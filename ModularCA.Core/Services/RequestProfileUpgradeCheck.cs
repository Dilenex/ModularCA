using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Models;
using ModularCA.Core.Services.Acme;
using ModularCA.Shared.Entities;
using Org.BouncyCastle.Asn1.X509;

namespace ModularCA.Core.Services;

/// <summary>A certificate an enrollment protocol issued, as the upgrade check replays it.</summary>
/// <param name="Protocol">The protocol, as a CA's protocol configuration names it: ACME, EST, SCEP, CMP or MSAE.</param>
/// <param name="CaLabel">The label of the CA it was issued from.</param>
/// <param name="RequestProfileId">The request profile that protocol uses on that CA now; null when it uses none.</param>
/// <param name="Subject">The subject its request recorded.</param>
/// <param name="SubjectAlternativeNames">The subject alternative names its request recorded, a JSON array of <c>TYPE:value</c> strings.</param>
/// <param name="IssuedAt">When the protocol last recorded it.</param>
public sealed record ProtocolIssuance(
    string Protocol, string CaLabel, Guid? RequestProfileId, string? Subject, string? SubjectAlternativeNames, DateTime IssuedAt);

/// <summary>
/// What <c>--upgrade-check</c> says about the request profiles the enrollment protocols use. From
/// 0.4.2 the subject alternative name rules of a request profile apply as stored (the seeded
/// profiles' rules were not read before, so every profile allowed DNS and IP names and required
/// none), and issuance checks the names again. The check replays the certificates each protocol
/// issued in the last <see cref="Days"/> days against the request profile that protocol uses on
/// its CA now, with the same rules issuance applies, and lists the ones whose next request would
/// be refused. It informs only and never refuses.
/// </summary>
public static class RequestProfileUpgradeCheck
{
    /// <summary>The heading of the note in the report.</summary>
    public const string NoteName = "Request profiles";

    /// <summary>How far back the check looks for certificates the protocols issued.</summary>
    public const int Days = 90;

    /// <summary>How many refused certificates the note shows for each protocol, CA and profile.</summary>
    private const int ExamplesPerGroup = 3;

    /// <summary>
    /// The note, or null when no certificate a protocol issued in the window was made under a
    /// request profile. Lists, by protocol, CA and request profile, how many certificates would be
    /// refused and why, with a few examples; says so when none would be.
    /// </summary>
    /// <param name="profiles">Every request profile, so that inheritance resolves as issuance resolves it.</param>
    /// <param name="issued">The certificates the protocols issued in the window, one per certificate.</param>
    public static string? Note(IReadOnlyList<RequestProfileEntity> profiles, IReadOnlyList<ProtocolIssuance> issued)
    {
        ArgumentNullException.ThrowIfNull(profiles);
        ArgumentNullException.ThrowIfNull(issued);
        var rows = profiles.GroupBy(p => p.Id).ToDictionary(g => g.Key, g => g.First());
        var resolver = ProfileResolutionService.ForLoadedRows(NullLogger<ProfileResolutionService>.Instance);

        var checkedCount = 0;
        var refused = new List<(ProtocolIssuance Issuance, string Profile, string Why)>();
        foreach (var issuance in issued)
        {
            if (issuance.RequestProfileId is not Guid id || !rows.TryGetValue(id, out var row))
                continue;
            var parent = row.InheritsFromId is Guid parentId && rows.TryGetValue(parentId, out var found) ? found : null;
            var profile = resolver.ResolveLoaded(row, parent);
            checkedCount++;
            if (WhyRefused(profile, issuance) is string why)
                refused.Add((issuance, profile.Name, why));
        }
        if (checkedCount == 0)
            return null;

        var opening = $"{checkedCount} certificate(s) issued through enrollment protocols in the last {Days} days were checked against the "
            + "request profile each protocol uses on its CA now, with the rules issuance applies from this release";
        if (refused.Count == 0)
            return opening + "; none would be refused.";

        var lines = new List<string> { $"{opening}. {refused.Count} would be refused if requested again:" };
        foreach (var group in refused
            .GroupBy(r => (r.Issuance.Protocol, r.Issuance.CaLabel, r.Profile))
            .OrderBy(g => g.Key.Protocol, StringComparer.Ordinal)
            .ThenBy(g => g.Key.CaLabel, StringComparer.Ordinal)
            .ThenBy(g => g.Key.Profile, StringComparer.Ordinal))
        {
            var latest = group.Max(r => r.Issuance.IssuedAt);
            lines.Add($"  {group.Key.Protocol} on '{group.Key.CaLabel}', request profile '{group.Key.Profile}': "
                + $"{group.Count()} certificate(s), the latest issued {latest:yyyy-MM-dd}");
            foreach (var (issuance, _, why) in group.OrderByDescending(r => r.Issuance.IssuedAt).Take(ExamplesPerGroup))
                lines.Add($"    '{Describe(issuance)}': {why}");
            if (group.Count() > ExamplesPerGroup)
                lines.Add($"    and {group.Count() - ExamplesPerGroup} more");
        }
        lines.Add("Before this release the subject alternative name rules of the seeded request profiles were not read, so every profile allowed "
            + "DNS and IP names and required none. A refusal stops the next request, not a certificate already issued: change the client or the "
            + "request profile before these certificates are due to be renewed.");
        return string.Join(Environment.NewLine, lines);
    }

    /// <summary>
    /// Why a request with <paramref name="issuance"/>'s names would be refused under
    /// <paramref name="profile"/>, or null when it would not. The names are settled as a protocol
    /// request settles them (the profile's fixed and default values supplied, and for ACME the
    /// first DNS name as common name where the profile requires one and the request has none),
    /// then checked as issuance checks them.
    /// </summary>
    /// <param name="profile">The effective request profile.</param>
    /// <param name="issuance">The certificate whose request is replayed.</param>
    internal static string? WhyRefused(EffectiveRequestProfile profile, ProtocolIssuance issuance)
    {
        List<KeyValuePair<string, string>> fields;
        List<string> sans;
        try
        {
            fields = string.IsNullOrWhiteSpace(issuance.Subject)
                ? []
                : RequestProfileEnforcement.FieldsOf(new X509Name(issuance.Subject));
            sans = RequestProfileEnforcement.ReadSans(issuance.SubjectAlternativeNames);
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException or InvalidOperationException or JsonException)
        {
            return "its recorded names cannot be read, so it cannot be checked";
        }

        if (string.Equals(issuance.Protocol, "ACME", StringComparison.OrdinalIgnoreCase)
            && !fields.Any(f => string.Equals(f.Key, "CN", StringComparison.OrdinalIgnoreCase))
            && RequestProfileEnforcement.Requires(profile, "CN")
            && AcmeOrderService.CommonNameFromSans(sans) is string commonName)
        {
            fields.Insert(0, new("CN", commonName));
        }

        var (settled, _) = RequestProfileEnforcement.Settle(profile, fields);
        return RequestProfileEnforcement.WhyNamesRefused(profile, settled, sans);
    }

    /// <summary>The certificate as the note names it: its subject, or its first SAN when the subject is empty.</summary>
    private static string Describe(ProtocolIssuance issuance)
    {
        if (!string.IsNullOrWhiteSpace(issuance.Subject))
            return issuance.Subject;
        try
        {
            return RequestProfileEnforcement.ReadSans(issuance.SubjectAlternativeNames).FirstOrDefault() ?? "(no names)";
        }
        catch (JsonException)
        {
            return "(no names)";
        }
    }
}
