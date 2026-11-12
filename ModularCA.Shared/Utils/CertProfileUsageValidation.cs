using System.Text.Json;

namespace ModularCA.Shared.Utils;

/// <summary>
/// Decides whether the usages a certificate profile asks for are ones this deployment's OID
/// catalog can resolve. <c>CertProfileService</c> runs it on profile create and update and
/// refuses what it cannot resolve (400, <c>MCA-PRF-002</c>).
/// </summary>
/// <remarks>
/// <para>
/// A usage field arrives in one of two forms, and both are read (<see cref="ParseField"/>): a
/// JSON array of strings, which is how a profile is stored and returned, and a comma-separated
/// list, which is what the console sends and the service turns into the JSON array.
/// </para>
/// <para>
/// It accepts every spelling the issuance path resolves, and no usage it would drop.
/// <c>IssuanceValidationService</c> resolves a profile's usages against the catalog by OID or by
/// friendly name, ignoring case and separators, and omits whatever does not resolve from the
/// certificate (with a warning in the log), refusing to issue only when nothing is left. So an
/// OID or a name with no catalog row never reached a certificate; it is refused here, where the
/// profile is written. A custom extended key usage is accepted in dotted form exactly when the
/// catalog has a row for it, which is also when it is issued.
/// </para>
/// <para>
/// It was the core of <c>CreateCertProfileValidator</c>, a FluentValidation class that never ran,
/// because nothing wired validation into the MVC pipeline. That class was removed in 0.4.4: it
/// split the usage fields on commas only, and it also demanded a maximum validity, which an
/// inheriting profile leaves empty, so wiring it would have refused profiles the console saves
/// today.
/// </para>
/// <para>
/// The rule lived as two hardcoded string arrays inside the API's FluentValidation class: eight
/// key usages and seven extended key usages. Anything else was refused however the catalog was
/// configured, which put a fixed ceiling on what the CA could be told to issue — no Kerberos KDC
/// authentication and therefore no domain controller certificate, none of the PIV usages, no EFS,
/// no document signing — and made adding a catalog row pointless, because this list was the real
/// gate.
/// </para>
/// <para>
/// It sits here rather than in the validator so the decision can be tested directly, and so
/// resolution runs through <see cref="UsageCatalogResolver"/>, the same comparison
/// <c>IssuanceValidationService</c> uses. A profile accepted here is one issuance can resolve;
/// hand-synchronised copies of that comparison are how a bootstrapped root CA once ended up with
/// no KeyUsage extension at all.
/// </para>
/// </remarks>
public static class CertProfileUsageValidation
{
    /// <summary>
    /// <c>anyExtendedKeyUsage</c>. Barred from subscriber certificates by RFC 5280 §4.2.1.12 and
    /// CA/B Forum BR §7.1.2.2, and thrown on by <c>IssuanceValidationService</c> — so it is
    /// refused here regardless of the catalog, rather than producing a profile that fails at first
    /// use.
    /// </summary>
    public const string AnyExtendedKeyUsageOid = "2.5.29.37.0";

    /// <summary>Outcome of checking one profile field against the catalog.</summary>
    /// <param name="IsValid">True when every entry resolved and none was forbidden.</param>
    /// <param name="Unknown">Entries the catalog could not resolve, in the order supplied.</param>
    /// <param name="ContainsForbidden">True when the field named <c>anyExtendedKeyUsage</c>.</param>
    public readonly record struct UsageCheck(
        bool IsValid,
        IReadOnlyList<string> Unknown,
        bool ContainsForbidden);

    /// <summary>Splits a comma-separated profile field into trimmed, non-empty entries.</summary>
    public static IReadOnlyList<string> Split(string? input) =>
        (input ?? string.Empty)
            .Split(',', StringSplitOptions.RemoveEmptyEntries)
            .Select(x => x.Trim())
            .Where(x => x.Length > 0)
            .ToList();

    /// <summary>
    /// Reads a usage field in either form a profile request carries it: a JSON array of strings
    /// (the stored form), or, when the text is not one, a comma-separated list (what the console
    /// sends). The same two readings <c>CertProfileService</c> makes when it stores the field.
    /// Entries are trimmed; blank and null entries are left out, as issuance ignores them. Null,
    /// blank and a JSON <c>null</c> are an empty list.
    /// </summary>
    /// <param name="input">The field as sent or stored.</param>
    public static IReadOnlyList<string> ParseField(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return [];
        try
        {
            return (JsonSerializer.Deserialize<List<string?>>(input) ?? [])
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Select(x => x!.Trim())
                .ToList();
        }
        catch (JsonException)
        {
            return Split(input);
        }
    }

    /// <summary>
    /// Checks a profile's standard key usages (<see cref="ParseField"/>) against the catalog's
    /// Standard rows. An entry passes when the catalog resolves it by friendly name or OID
    /// (<see cref="UsageCatalogResolver.Resolve"/>), which covers every spelling issuance resolves.
    /// </summary>
    /// <param name="input">The field as sent: a JSON array or a comma-separated list.</param>
    /// <param name="standardCatalog">The catalog's Standard rows.</param>
    /// <param name="stored">
    /// The field as the profile already stores it, on an update; its entries are not checked
    /// again, so a profile written before this check can still be edited. Null on a create.
    /// </param>
    public static UsageCheck CheckKeyUsages(
        string? input, IEnumerable<(string? Oid, string? FriendlyName)> standardCatalog, string? stored = null)
    {
        var lookup = UsageCatalogResolver.BuildLookup(standardCatalog, e => e.FriendlyName ?? string.Empty);
        var kept = Kept(stored);
        var unknown = ParseField(input)
            .Where(x => !kept.Contains(x))
            .Where(x => UsageCatalogResolver.Resolve(lookup, x) == null)
            .Distinct(StringComparer.Ordinal)
            .ToList();
        return new UsageCheck(unknown.Count == 0, unknown, false);
    }

    /// <summary>
    /// Checks a profile's extended key usages (<see cref="ParseField"/>) against the catalog's
    /// Extended rows. Entries may be spelled as an OID or as the catalog's friendly name; both are
    /// forms a profile is allowed to store, so both are accepted. A custom OID passes when the
    /// catalog has a row for it. <c>anyExtendedKeyUsage</c> is refused whatever the catalog says,
    /// by its OID or by a name that resolves to it.
    /// </summary>
    /// <param name="input">The field as sent: a JSON array or a comma-separated list.</param>
    /// <param name="extendedCatalog">The catalog's Extended rows.</param>
    /// <param name="stored">
    /// The field as the profile already stores it, on an update; its entries are not checked
    /// again. Null on a create.
    /// </param>
    public static UsageCheck CheckExtendedKeyUsages(
        string? input, IEnumerable<(string? Oid, string? FriendlyName)> extendedCatalog, string? stored = null)
    {
        var lookup = UsageCatalogResolver.BuildLookup(extendedCatalog, e => e.Oid ?? string.Empty);
        var kept = Kept(stored);

        var entries = ParseField(input).Where(x => !kept.Contains(x)).ToList();
        bool Forbidden(string x) =>
            string.Equals(x, AnyExtendedKeyUsageOid, StringComparison.Ordinal)
            || string.Equals(UsageCatalogResolver.Resolve(lookup, x), AnyExtendedKeyUsageOid, StringComparison.Ordinal);
        var forbidden = entries.Any(Forbidden);

        var unknown = entries
            .Where(x => !Forbidden(x))
            .Where(x => UsageCatalogResolver.Resolve(lookup, x) == null)
            .Distinct(StringComparer.Ordinal)
            .ToList();

        return new UsageCheck(unknown.Count == 0 && !forbidden, unknown, forbidden);
    }

    /// <summary>The entries of a stored field, compared without regard to case.</summary>
    /// <param name="stored">The stored field, or null.</param>
    private static HashSet<string> Kept(string? stored) => new(ParseField(stored), StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Builds the operator-facing message for a failed check. It names what could not be resolved
    /// and where to fix it, rather than reciting a fixed allow-list — the old message listed seven
    /// names and gave no hint that the answer was "add it to the catalog".
    /// </summary>
    public static string DescribeFailure(string field, UsageCheck check)
    {
        if (check.ContainsForbidden)
        {
            return $"{field} contains anyExtendedKeyUsage ({AnyExtendedKeyUsageOid}), which is " +
                   "forbidden in subscriber certificates (RFC 5280 4.2.1.12).";
        }

        return check.Unknown.Count switch
        {
            0 => $"{field} must be a list of usages from the OID catalog.",
            1 => $"{field} contains {check.Unknown[0]}, which is not in the OID catalog. " +
                 "Add it under Admin → OID Options, or use an existing OID or friendly name.",
            _ => $"{field} contains {string.Join(", ", check.Unknown)}, which are not in the OID catalog. " +
                 "Add them under Admin → OID Options, or use an existing OID or friendly name.",
        };
    }
}
