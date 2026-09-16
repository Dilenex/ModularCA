using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace ModularCA.Core.Services.Msae;

/// <summary>
/// Answers a Windows client's policy query: which templates a CA offers, what they contain, and
/// where to enroll.
/// </summary>
public interface IXcepPolicyService
{
    /// <summary>
    /// Builds the policy set for <paramref name="caLabel"/> (or the default CA) as seen by
    /// <paramref name="caller"/>, whose enrollment permission is reported in the result.
    /// </summary>
    /// <exception cref="MsaeEnrollmentException">MSAE is not enabled on the CA.</exception>
    Task<XcepMessages.PolicySet> GetPoliciesAsync(string? caLabel, MsaeCaller caller);

    /// <summary>The policy set as seen by a caller that signed in with a username.</summary>
    Task<XcepMessages.PolicySet> GetPoliciesAsync(string? caLabel, string callerUsername)
        => GetPoliciesAsync(caLabel, MsaeCaller.Credential(callerUsername));
}

/// <summary>
/// Projects ModularCA's certificate templates and profiles into the MS-XCEP policy model.
/// </summary>
/// <remarks>
/// <para>
/// A template is offered to Windows when it is enabled and carries an MSAE OID; everything else
/// on the CA is invisible to a Windows client. What the client learns about each template comes
/// from the certificate profile the template points at, resolved through inheritance the same
/// way issuance resolves it, so the policy a client sees is the policy the CA will enforce:
/// validity from the profile's maximum, the smallest permitted RSA key as the minimum, and the
/// key usage and extended key usage the certificate will carry, encoded as the extensions the
/// client copies into its CSR.
/// </para>
/// <para>
/// Only RSA templates are offered in this phase. XCEP describes elliptic-curve keys through a
/// schema-3 template with a named-curve algorithm reference, and the profiles here express curves
/// differently enough that the mapping deserves its own change. A template whose profile permits
/// no RSA key is skipped with a warning rather than advertised with a key the CA would refuse.
/// </para>
/// <para>
/// Subjects are marked as supplied by the enrollee. Building the subject from the caller's
/// directory identity is Kerberos work (a later phase); until then the request profile is the
/// naming policy, applied at enrollment.
/// </para>
/// </remarks>
public class XcepPolicyService(
    ModularCADbContext db,
    ICaResolverService caResolver,
    IEnrollmentPrincipalAuthorizer principalAuthorizer,
    IProfileResolutionService profileResolution,
    IssuanceValidationService validation,
    SystemConfig config,
    ILogger<XcepPolicyService> logger) : IXcepPolicyService
{
    /// <summary>How long a client keeps the policy before asking again. Matches the AD CS default.</summary>
    public const int NextUpdateHours = 8;

    /// <summary>Renewal window as a fraction of validity: Windows renews inside the last fifth.</summary>
    private const double RenewalFraction = 0.2;

    private const string Sha256Oid = "2.16.840.1.101.3.4.2.1";
    private const string RsaOid = "1.2.840.113549.1.1.1";
    private const string KeyUsageOid = "2.5.29.15";
    private const string ExtendedKeyUsageOid = "2.5.29.37";
    private const string ApplicationPoliciesOid = "1.3.6.1.4.1.311.21.10";

    /// <summary>The policy set as seen by a caller that signed in with a username.</summary>
    public Task<XcepMessages.PolicySet> GetPoliciesAsync(string? caLabel, string callerUsername)
        => GetPoliciesAsync(caLabel, MsaeCaller.Credential(callerUsername));

    /// <inheritdoc />
    public async Task<XcepMessages.PolicySet> GetPoliciesAsync(string? caLabel, MsaeCaller caller)
    {
        ArgumentNullException.ThrowIfNull(caller);

        ResolvedCaContext context;
        try
        {
            context = await caResolver.ResolveAsync(caLabel, MsaeEnrollmentService.Protocol);
        }
        catch (InvalidOperationException ex)
        {
            throw new MsaeEnrollmentException(ex.Message);
        }
        var ca = context.Ca;

        var caCertificate = await db.Certificates.AsNoTracking()
            .FirstOrDefaultAsync(c => c.CertificateId == ca.CertificateId)
            ?? throw new InvalidOperationException($"CA '{ca.Label}' has no certificate row.");
        var caDer = CertificateUtil.ParseFromPem(caCertificate.Pem).GetEncoded();

        var mayEnroll = await principalAuthorizer.MayEnrollAsync(caller.ActingAsUsername, ca.Id);
        var cesUri = $"{config.Https.GetPublicHttpsBaseUrl()}/msae/{ca.Label}/ces";
        const int caReference = 0;
        // The engine authenticates to CES the way the policy tells it to. A caller that arrived
        // with a ticket keeps using it; a username caller is told to send its UsernameToken.
        var cesAuth = caller.Kerberos != null ? XcepMessages.AuthKerberos : XcepMessages.AuthUsernamePassword;
        var cas = new[] { new XcepMessages.PolicyCa(caReference, cesUri, caDer, mayEnroll, cesAuth) };

        var offered = await db.CertificateTemplates.AsNoTracking()
            .Include(t => t.SigningProfile)
            .Where(t => t.CaId == ca.Id && t.IsEnabled && t.MsaeTemplateOid != null)
            .OrderBy(t => t.Name)
            .ToListAsync();

        var templates = new List<XcepMessages.PolicyTemplate>();
        foreach (var template in offered)
        {
            var policy = await ProjectAsync(template, mayEnroll, caReference, identityBuilt: caller.Kerberos != null);
            if (policy != null) templates.Add(policy);
        }

        return new XcepMessages.PolicySet(ca.Id, $"{ca.Name} (ModularCA)", NextUpdateHours, cas, templates);
    }

    private async Task<XcepMessages.PolicyTemplate?> ProjectAsync(CertificateTemplateEntity template, bool mayEnroll, int caReference, bool identityBuilt)
    {
        var profile = await profileResolution.ResolveCertProfileAsync(template.CertProfileId);

        var algorithms = ReadList(profile.AllowedKeyAlgorithms);
        if (algorithms.Count > 0 && !algorithms.Any(a => a.Equals("RSA", StringComparison.OrdinalIgnoreCase)))
        {
            logger.LogWarning(
                "Template {Template} is offered to Windows but its certificate profile permits no RSA key; skipped. "
                + "Elliptic-curve templates are not advertised over MSAE yet.", template.Name);
            return null;
        }

        var validity = Iso8601ParserUtil.ParseIso8601(profile.ValidityPeriodMax ?? "P1Y");
        var validitySeconds = (long)validity.TotalSeconds;
        var renewalSeconds = Math.Max(1, (long)(validitySeconds * RenewalFraction));

        var extensions = new List<XcepMessages.PolicyExtension>();

        var keyUsageNames = validation.SetupAllowedStandardOids(profile.KeyUsages);
        if (keyUsageNames.Count > 0)
        {
            var bits = KeyUsageFriendlyNames.ParseMany(keyUsageNames);
            if (bits != 0)
                extensions.Add(new XcepMessages.PolicyExtension(KeyUsageOid, "Key Usage", true, new KeyUsage(bits).GetDerEncoded()));
        }

        var ekuOids = validation.SetupAllowedExtendedOids(profile.ExtendedKeyUsages, template.SigningProfile.AllowedEKUs);
        if (ekuOids.Count > 0)
        {
            var oids = ekuOids.Select(o => new DerObjectIdentifier(o)).ToArray<Asn1Encodable>();
            extensions.Add(new XcepMessages.PolicyExtension(ExtendedKeyUsageOid, "Enhanced Key Usage", false,
                new DerSequence(oids).GetDerEncoded()));
            // Windows reads the same OIDs from its own Application Policies extension; a template
            // that carries EKU without it leaves the client's "intended purposes" empty.
            var policies = ekuOids.Select(o => (Asn1Encodable)new DerSequence(new DerObjectIdentifier(o))).ToArray();
            extensions.Add(new XcepMessages.PolicyExtension(ApplicationPoliciesOid, "Application Policies", false,
                new DerSequence(policies).GetDerEncoded()));
        }

        // The client puts this in its CSR; the enrollment side resolves the template by it.
        extensions.Add(new XcepMessages.PolicyExtension(MsaeCsrTemplate.TemplateInfoOid, "Certificate Template Information", false,
            new DerSequence(
                new DerObjectIdentifier(template.MsaeTemplateOid!),
                new DerInteger(template.MsaeMajorVersion),
                new DerInteger(template.MsaeMinorVersion)).GetDerEncoded()));

        return new XcepMessages.PolicyTemplate(
            Name: template.Name,
            Oid: template.MsaeTemplateOid!,
            MajorVersion: template.MsaeMajorVersion,
            MinorVersion: template.MsaeMinorVersion,
            ValiditySeconds: validitySeconds,
            RenewalSeconds: renewalSeconds,
            Enroll: mayEnroll,
            // Autoenrollment has no subject to give, so it is offered only when the CA builds
            // the subject from the caller's Kerberos identity.
            AutoEnroll: identityBuilt,
            CaBuiltSubject: identityBuilt,
            MinimalKeyLength: MinimalRsaKeyLength(profile.AllowedKeySizes),
            MachineType: template.MsaeMachineType,
            ExportableKey: false,
            HashAlgorithmOid: Sha256Oid,
            HashAlgorithmName: "sha256",
            PublicKeyAlgorithmOid: RsaOid,
            PublicKeyAlgorithmName: "RSA",
            Extensions: extensions,
            CaReferenceIds: [caReference]);
    }

    /// <summary>The smallest RSA size the profile permits, or 2048 when it names none.</summary>
    internal static int MinimalRsaKeyLength(string allowedKeySizesJson)
    {
        var sizes = ReadList(allowedKeySizesJson)
            .Select(s => int.TryParse(s, out var n) ? n : 0)
            .Where(n => n >= 1024)
            .ToList();
        return sizes.Count == 0 ? 2048 : sizes.Min();
    }

    private static List<string> ReadList(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return [];
        try
        {
            return JsonSerializer.Deserialize<List<string>>(json, SafeJsonOptions.Default) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }
}
