namespace ModularCA.Shared.Utils;

/// <summary>
/// Decides whether the usages a certificate profile asks for are ones this deployment's OID
/// catalog can resolve — the question the profile validator asks on create and update.
/// </summary>
/// <remarks>
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
    /// Checks a comma-separated list of standard key usages against the catalog's Standard rows.
    /// </summary>
    public static UsageCheck CheckKeyUsages(
        string? input, IEnumerable<(string? Oid, string? FriendlyName)> standardCatalog)
    {
        var lookup = UsageCatalogResolver.BuildLookup(standardCatalog, e => e.FriendlyName ?? string.Empty);
        var unknown = Split(input)
            .Where(x => UsageCatalogResolver.Resolve(lookup, x) == null)
            .ToList();
        return new UsageCheck(unknown.Count == 0, unknown, false);
    }

    /// <summary>
    /// Checks a comma-separated list of extended key usages against the catalog's Extended rows.
    /// Entries may be spelled as an OID or as the catalog's friendly name; both are forms a
    /// profile is allowed to store, so both must be accepted.
    /// </summary>
    public static UsageCheck CheckExtendedKeyUsages(
        string? input, IEnumerable<(string? Oid, string? FriendlyName)> extendedCatalog)
    {
        var lookup = UsageCatalogResolver.BuildLookup(extendedCatalog, e => e.Oid ?? string.Empty);

        var entries = Split(input);
        var forbidden = entries.Any(x => string.Equals(x, AnyExtendedKeyUsageOid, StringComparison.Ordinal));

        var unknown = entries
            .Where(x => !string.Equals(x, AnyExtendedKeyUsageOid, StringComparison.Ordinal))
            .Where(x => UsageCatalogResolver.Resolve(lookup, x) == null)
            .ToList();

        return new UsageCheck(unknown.Count == 0 && !forbidden, unknown, forbidden);
    }

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

        return check.Unknown.Count == 0
            ? $"{field} must be a comma-separated list of usages from the OID catalog."
            : $"{field} contains {string.Join(", ", check.Unknown)}, which are not in the OID catalog. " +
              "Add them under Admin → OID Options, or use an existing OID or friendly name.";
    }
}
