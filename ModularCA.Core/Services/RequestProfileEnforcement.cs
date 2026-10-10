using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Helpers;
using ModularCA.Core.Models;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Models.Csr;
using ModularCA.Shared.Models.RequestProfiles;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using System.Text.Json;

namespace ModularCA.Core.Services;

/// <summary>
/// Holds a certificate request to the request profile it was made under, at each step: when
/// it is submitted through the console or its API, when it is approved, and when it is issued.
/// The enrollment protocols check their requests on arrival through
/// <see cref="RequestProfileValidationService"/>; this is the same rule set, applied without
/// rewriting the names, so it can be asked again at any later step.
/// </summary>
/// <param name="db">The application database.</param>
/// <param name="profiles">Resolves a request profile with its inheritance applied.</param>
public sealed class RequestProfileEnforcement(ModularCADbContext db, IProfileResolutionService profiles)
{
    private static readonly Dictionary<string, DerObjectIdentifier> FieldOids = new(StringComparer.OrdinalIgnoreCase)
    {
        ["CN"] = X509Name.CN,
        ["O"] = X509Name.O,
        ["OU"] = X509Name.OU,
        ["C"] = X509Name.C,
        ["ST"] = X509Name.ST,
        ["L"] = X509Name.L,
        ["E"] = X509Name.EmailAddress,
        ["SERIALNUMBER"] = X509Name.SerialNumber,
        ["DC"] = X509Name.DC,
        ["UID"] = X509Name.UID,
        ["T"] = X509Name.T,
        ["STREET"] = X509Name.Street,
    };

    /// <summary>
    /// Checks a request submitted through the console or its API before it is stored, and
    /// returns the subject fields the profile supplies: each field it fixes, and each field it
    /// gives a default for that the request left out. The caller adds them to the request. The
    /// request profile must exist and, when it is bound to a CA, be bound to the CA of
    /// <paramref name="signingProfileId"/>; the certificate profile must be one the request
    /// profile names (<see cref="RequestProfileCertProfiles.DesignatedIds"/>); and the names,
    /// with the supplied fields in place, must satisfy the profile's rules. A request profile
    /// that names no certificate profile takes any for an operator and none for a self-service
    /// requester. Throws <see cref="ConfigurationValidationException"/>
    /// (<see cref="ErrorCodes.RequestProfileRefused"/>) otherwise.
    /// </summary>
    /// <param name="requestProfileId">The request profile the request is made under.</param>
    /// <param name="certProfileId">The certificate profile the request names.</param>
    /// <param name="signingProfileId">The signing profile the request names.</param>
    /// <param name="selfService">True for a requester's own request, false for an operator's.</param>
    /// <param name="subject">The subject fields as the certificate would carry them, before the profile's own values.</param>
    /// <param name="sans">The subject alternative names, each as <c>TYPE:value</c>.</param>
    public async Task<Dictionary<string, string>> SettleSubmissionAsync(
        Guid requestProfileId, Guid certProfileId, Guid signingProfileId, bool selfService,
        IReadOnlyList<KeyValuePair<string, string>> subject, IReadOnlyList<string> sans)
    {
        var profile = await LoadAsync(requestProfileId)
            ?? throw new ConfigurationValidationException("The request profile does not exist.", ErrorCodes.RequestProfileRefused);

        var boundCaId = await db.RequestProfiles.AsNoTracking()
            .Where(p => p.Id == requestProfileId)
            .Select(p => p.CertificateAuthorityId)
            .FirstOrDefaultAsync();
        if (boundCaId != null)
        {
            var issuerId = await db.SigningProfiles.AsNoTracking()
                .Where(sp => sp.Id == signingProfileId)
                .Select(sp => sp.IssuerId)
                .FirstOrDefaultAsync();
            var caId = issuerId == null ? (Guid?)null : await db.CertificateAuthorities.AsNoTracking()
                .Where(ca => ca.CertificateId == issuerId)
                .Select(ca => (Guid?)ca.Id)
                .FirstOrDefaultAsync();
            if (caId != boundCaId)
                throw Refused(profile, "it belongs to another CA than the signing profile issues from");
        }

        var designated = RequestProfileCertProfiles.DesignatedIds(profile.DefaultCertProfileId, profile.AllowedCertProfileIds);
        if (designated.Count == 0 && selfService)
            throw Refused(profile, "it names no certificate profile, so it cannot be used for a self-service request until an administrator sets one");
        if (designated.Count > 0 && !designated.Contains(certProfileId))
        {
            var names = await db.CertProfiles.AsNoTracking()
                .Where(cp => designated.Contains(cp.Id))
                .OrderBy(cp => cp.Name)
                .Select(cp => cp.Name)
                .ToListAsync();
            throw Refused(profile, $"the certificate profile is not one it allows. Allowed: {(names.Count > 0 ? string.Join(", ", names) : "(none that still exist)")}");
        }

        var (settled, supplied) = Settle(profile, subject);
        if (WhyNamesRefused(profile, settled, sans) is string why)
            throw Refused(profile, why);
        return supplied;
    }

    /// <summary>
    /// <see cref="SettleSubmissionAsync"/> for a request whose key the CA generates: the subject
    /// is the fields the caller typed. Returns the subject to build the CSR from, with the
    /// profile's own values in place.
    /// </summary>
    public async Task<Dictionary<string, string>> SettleKeyRequestAsync(
        Guid requestProfileId, Guid certProfileId, Guid signingProfileId, bool selfService,
        IReadOnlyDictionary<string, string> subject, IEnumerable<SanOverride>? sans)
    {
        var supplied = await SettleSubmissionAsync(requestProfileId, certProfileId, signingProfileId, selfService,
            subject.ToList(), SanStrings(sans));
        var settled = new Dictionary<string, string>(subject, StringComparer.OrdinalIgnoreCase);
        foreach (var (field, value) in supplied)
        {
            foreach (var key in settled.Keys.Where(k => Canonical(k) == field).ToList())
                settled.Remove(key);
            settled[field] = value;
        }
        return settled;
    }

    /// <summary>
    /// <see cref="SettleSubmissionAsync"/> for an uploaded CSR: the names are the CSR's with the
    /// caller's overrides applied, as issuance will apply them. Returns the subject overrides
    /// to store: the caller's, with the profile's own values added. A CSR that cannot be read is
    /// left to the upload, which refuses it.
    /// </summary>
    public async Task<Dictionary<string, string>?> SettleUploadAsync(
        Guid requestProfileId, Guid certProfileId, Guid signingProfileId, bool selfService,
        string csrPem, Dictionary<string, string>? subjectOverrides, List<SanOverride>? sanOverrides)
    {
        X509Name subject;
        List<string> csrSans;
        try
        {
            using var reader = new StringReader(csrPem);
            if (new PemReader(reader).ReadObject() is not Pkcs10CertificationRequest csr)
                return subjectOverrides;
            csrSans = CertificateUtil.ParseCsr(csrPem).SubjectAlternativeNames ?? [];
            var asStored = new CertRequestEntity { SubjectAlternativeNames = JsonSerializer.Serialize(csrSans) };
            subject = CertificateIssuanceService.ApplySubjectOverrides(
                CertificateBuilderService.SubjectOf(csr, asStored),
                subjectOverrides is { Count: > 0 } ? JsonSerializer.Serialize(subjectOverrides) : null);
        }
        catch (Exception e) when (e is IOException or FormatException or ArgumentException or InvalidOperationException)
        {
            return subjectOverrides;
        }

        var sans = sanOverrides is { Count: > 0 } ? SanStrings(sanOverrides) : csrSans;
        var supplied = await SettleSubmissionAsync(requestProfileId, certProfileId, signingProfileId, selfService, FieldsOf(subject), sans);
        if (supplied.Count == 0)
            return subjectOverrides;
        var overrides = new Dictionary<string, string>(subjectOverrides ?? [], StringComparer.OrdinalIgnoreCase);
        foreach (var (field, value) in supplied)
        {
            foreach (var key in overrides.Keys.Where(k => Canonical(k) == field).ToList())
                overrides.Remove(key);
            overrides[field] = value;
        }
        return overrides;
    }

    /// <summary>
    /// <see cref="SettleSubmissionAsync"/> for a request made from a subject DN string. Returns
    /// the subject DN to build the CSR from, with the profile's own values in place.
    /// </summary>
    public async Task<string> SettleSubjectNameAsync(
        Guid requestProfileId, Guid certProfileId, Guid signingProfileId, bool selfService,
        string subjectName, IReadOnlyList<string>? sans)
    {
        X509Name subject;
        try
        {
            subject = new X509Name(subjectName);
        }
        catch (Exception e) when (e is ArgumentException or InvalidOperationException or FormatException)
        {
            throw new InvalidRequestException($"The subject '{subjectName}' is not a distinguished name.");
        }
        var supplied = await SettleSubmissionAsync(requestProfileId, certProfileId, signingProfileId, selfService, FieldsOf(subject), sans ?? []);
        return supplied.Count == 0
            ? subjectName
            : CertificateIssuanceService.ApplySubjectOverrides(subject, JsonSerializer.Serialize(supplied)).ToString();
    }

    private static List<string> SanStrings(IEnumerable<SanOverride>? sans)
        => (sans ?? [])
            .Where(s => !string.IsNullOrWhiteSpace(s.Value))
            .Select(s => SanOverrideJson.Format(s.Type ?? string.Empty, s.Value))
            .ToList();

    /// <summary>
    /// The subject overrides an enrollment protocol's request needs for its certificate to carry
    /// what the profile settled when the request arrived: each field the profile fixes or gives
    /// a default for, and the common name of <paramref name="settledSubject"/> when the subject
    /// issuance would build has none. Issuance builds the subject from the CSR, so without these
    /// the profile's values were checked and then left out of the certificate. Null when nothing is
    /// needed, or when the request holds no PKCS#10 CSR (CMP, whose subject is the stored one).
    /// </summary>
    /// <param name="profile">The effective request profile.</param>
    /// <param name="csrPem">The request's CSR.</param>
    /// <param name="sansJson">The request's SANs, as stored.</param>
    /// <param name="settledSubject">The subject the protocol's own validation settled on, as stored on the request.</param>
    public static string? ProtocolSubjectOverrides(EffectiveRequestProfile profile, string? csrPem, string? sansJson, string? settledSubject)
    {
        if (string.IsNullOrWhiteSpace(csrPem) || csrPem.Contains(CmpPublicKeyMarker, StringComparison.Ordinal))
            return null;
        var commonName = RequestProfileValidationService.ParseSubjectDn(settledSubject ?? string.Empty).GetValueOrDefault("CN");
        List<KeyValuePair<string, string>> fields;
        try
        {
            using var reader = new StringReader(csrPem);
            if (new PemReader(reader).ReadObject() is not Pkcs10CertificationRequest csr)
                return null;
            fields = FieldsOf(CertificateBuilderService.SubjectOf(csr, new CertRequestEntity { SubjectAlternativeNames = sansJson }));
        }
        catch (Exception e) when (e is IOException or FormatException or ArgumentException or InvalidOperationException)
        {
            return null;
        }

        var (settled, supplied) = Settle(profile, fields);
        if (!string.IsNullOrEmpty(commonName) && !settled.Any(f => Canonical(f.Key) == "CN"))
            supplied["CN"] = commonName;
        return supplied.Count == 0 ? null : JsonSerializer.Serialize(supplied);
    }

    /// <summary>The marker of a CMP request, which stores a public key where the others store a CSR.</summary>
    private const string CmpPublicKeyMarker = "-----CMP-PUBKEY-----";

    /// <summary>
    /// Why the stored request <paramref name="request"/> no longer satisfies the request profile
    /// it was made under, or null when it does, when it was made under none, or when its names
    /// cannot be read here (issuance reads them again and decides). The names are the ones the
    /// certificate would carry: the request's own with its overrides applied.
    /// </summary>
    public async Task<string?> WhyRefusedAsync(CertRequestEntity request)
    {
        if (request.RequestProfileId is not Guid profileId)
            return null;
        X509Name subject;
        try
        {
            subject = CertificateIssuanceService.ApplySubjectOverrides(StoredSubject(request), request.SubjectOverrides);
        }
        catch (Exception e) when (e is ArgumentException or InvalidOperationException or IOException or FormatException)
        {
            return null;
        }
        return await WhyRefusedAsync(profileId, subject,
            CertificateIssuanceService.ApplySanOverrides(request.SubjectAlternativeNames, request.SanOverrides));
    }

    /// <summary>
    /// Refuses, at issuance, a request whose final names do not satisfy the request profile it
    /// was made under (<see cref="ConfigurationValidationException"/>,
    /// <see cref="ErrorCodes.RequestProfileRefused"/>). A request made under no profile passes.
    /// </summary>
    /// <param name="request">The request being issued.</param>
    /// <param name="subject">The subject the certificate will carry, overrides applied.</param>
    /// <param name="sansJson">The subject alternative names it will carry, as a JSON array of <c>TYPE:value</c>.</param>
    public async Task EnsureSatisfiedAsync(CertRequestEntity request, X509Name subject, string? sansJson)
    {
        if (request.RequestProfileId is not Guid profileId)
            return;
        if (await WhyRefusedAsync(profileId, subject, sansJson) is string why)
            throw new ConfigurationValidationException(why, ErrorCodes.RequestProfileRefused);
    }

    private async Task<string?> WhyRefusedAsync(Guid profileId, X509Name subject, string? sansJson)
    {
        var profile = await LoadAsync(profileId);
        if (profile == null)
            return "The request profile this request was made under no longer exists.";
        return WhyNamesRefused(profile, FieldsOf(subject), ReadSans(sansJson)) is string why
            ? Message(profile, why)
            : null;
    }

    private async Task<EffectiveRequestProfile?> LoadAsync(Guid requestProfileId)
    {
        try
        {
            return await profiles.ResolveRequestProfileAsync(requestProfileId);
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    private static string Message(EffectiveRequestProfile profile, string why)
        => $"The request profile '{profile.Name}' does not permit this request: {why}.";

    private static ConfigurationValidationException Refused(EffectiveRequestProfile profile, string why)
        => new(Message(profile, why), ErrorCodes.RequestProfileRefused);

    /// <summary>The subject a stored request asks for, before overrides: its CSR's, or its recorded subject when it holds no CSR.</summary>
    private static X509Name StoredSubject(CertRequestEntity request)
    {
        if (!string.IsNullOrWhiteSpace(request.CSR) && !request.CSR.Contains(CmpPublicKeyMarker, StringComparison.Ordinal))
        {
            using var reader = new StringReader(request.CSR);
            if (new PemReader(reader).ReadObject() is Pkcs10CertificationRequest csr)
                return CertificateBuilderService.SubjectOf(csr, request);
        }
        return new X509Name(request.Subject ?? string.Empty);
    }

    /// <summary>The fields of <paramref name="subject"/> in order, each named as a request profile rule names it; a field with no such name is named by its OID.</summary>
    public static List<KeyValuePair<string, string>> FieldsOf(X509Name subject)
    {
        var oids = subject.GetOidList();
        var values = subject.GetValueList();
        var fields = new List<KeyValuePair<string, string>>(oids.Count);
        for (var i = 0; i < oids.Count; i++)
        {
            var name = FieldOids.FirstOrDefault(f => f.Value.Equals(oids[i])).Key ?? oids[i].Id;
            fields.Add(new(name, values[i] ?? string.Empty));
        }
        return fields;
    }

    /// <summary>The field name a rule or a request uses, as rules are stored: upper case, emailAddress as E.</summary>
    private static string Canonical(string? field)
    {
        var upper = (field ?? string.Empty).Trim().ToUpperInvariant();
        return upper is "EMAILADDRESS" or "EMAIL" ? "E" : upper;
    }

    private static List<SubjectDnFieldRule> RulesOf(EffectiveRequestProfile profile)
        => JsonSerializer.Deserialize<List<SubjectDnFieldRule>>(
            string.IsNullOrWhiteSpace(profile.SubjectDnRules) ? "[]" : profile.SubjectDnRules, SafeJsonOptions.Stored) ?? [];

    private static List<string> ReadSans(string? sansJson)
        => string.IsNullOrWhiteSpace(sansJson)
            ? []
            : JsonSerializer.Deserialize<List<string>>(sansJson, SafeJsonOptions.Default) ?? [];

    /// <summary>
    /// <paramref name="subject"/> with the profile's own values in place: a field the profile
    /// fixes carries the fixed value once, and a field it gives a default for carries the
    /// default when the request left it out. Also returns just those supplied fields.
    /// </summary>
    internal static (List<KeyValuePair<string, string>> Settled, Dictionary<string, string> Supplied) Settle(
        EffectiveRequestProfile profile, IReadOnlyList<KeyValuePair<string, string>> subject)
    {
        var settled = subject.Where(f => !string.IsNullOrWhiteSpace(f.Value)).ToList();
        var supplied = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rule in RulesOf(profile))
        {
            var field = Canonical(rule.Field);
            if (!string.IsNullOrEmpty(rule.FixedValue))
            {
                var present = settled.Where(f => Canonical(f.Key) == field).ToList();
                if (present.Count > 0 && present.All(f => f.Value == rule.FixedValue))
                    continue;
                settled.RemoveAll(f => Canonical(f.Key) == field);
                settled.Add(new(field, rule.FixedValue));
                supplied[field] = rule.FixedValue;
            }
            else if (!string.IsNullOrEmpty(rule.DefaultValue) && !settled.Any(f => Canonical(f.Key) == field))
            {
                settled.Add(new(field, rule.DefaultValue));
                supplied[field] = rule.DefaultValue;
            }
        }
        return (settled, supplied);
    }

    /// <summary>
    /// Why the names do not satisfy the profile's rules, or null when they do. Nothing is
    /// rewritten: a field the profile fixes must carry exactly the fixed value, a required field
    /// must be present, a forbidden one absent, and every value must match its field's pattern
    /// and length. The subject alternative names are checked as the protocols check them.
    /// </summary>
    internal static string? WhyNamesRefused(
        EffectiveRequestProfile profile, IReadOnlyList<KeyValuePair<string, string>> subject, IReadOnlyList<string> sans)
    {
        foreach (var rule in RulesOf(profile))
        {
            var field = Canonical(rule.Field);
            var values = subject.Where(f => Canonical(f.Key) == field && !string.IsNullOrEmpty(f.Value)).Select(f => f.Value).ToList();

            if (!string.IsNullOrEmpty(rule.FixedValue))
            {
                if (values.Count == 0 || values.Any(v => v != rule.FixedValue))
                    return $"subject field '{rule.Field}' must be '{rule.FixedValue}'";
            }
            else if (RequestProfileRules.IsRequired(rule.Requirement))
            {
                if (values.Count == 0)
                    return $"subject field '{rule.Field}' is required";
            }
            else if (RequestProfileRules.IsForbidden(rule.Requirement) && values.Count > 0)
            {
                return $"subject field '{rule.Field}' is not allowed";
            }

            foreach (var value in values)
            {
                if (!string.IsNullOrEmpty(rule.Regex) && !ProfileRegex.IsMatch(value, rule.Regex))
                    return $"subject field '{rule.Field}' value '{value}' does not match the pattern '{rule.Regex}'";
                if (rule.MaxLength.HasValue && value.Length > rule.MaxLength.Value)
                    return $"subject field '{rule.Field}' is longer than {rule.MaxLength} characters";
            }
        }

        var sanRules = RequestProfileValidationService.ReadSanRules(profile.SanRules);
        if (sanRules == null)
            return null;
        if (sans.Count == 0)
            return sanRules.Required ? "at least one subject alternative name is required" : null;
        return RequestProfileValidationService.ValidateSans(sans.ToList(), sanRules)?.TrimEnd('.');
    }
}
