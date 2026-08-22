namespace ModularCA.Shared.Utils;

/// <summary>
/// The single place that decides whether two spellings name the same X.509 key usage, and the
/// single place that resolves a spelling against the OIDOptions catalog.
/// <para>
/// The same usage reaches this codebase under at least three spellings depending on who wrote it:
/// the bootstrap seeder passes display names ("Digital Signature", "Key Certificate Signing"), the
/// OIDOptions catalog stores camelCase ("digitalSignature", "keyCertSign"), and profiles may hold
/// a bare OID. An exact string comparison between any two of those matches nothing.
/// </para>
/// <para>
/// This type exists because that comparison had been reimplemented three times — in
/// <c>IssuanceValidationService</c>, in <c>KeyUsageFriendlyNames</c>, and in the admin UI — each
/// carrying a comment claiming to match the others. A fourth copy in
/// <c>BootstrapProfileSeeder</c> did an ordinal <c>HashSet.Contains</c> instead, and was missed
/// when the runtime copies were fixed. The consequence was severe and silent: with no
/// <c>config/OIDSeed.yaml</c> present the catalog falls back to camelCase defaults, the seeder's
/// display names matched nothing, every lookup returned an empty list, and the certificate
/// builder skips the extension entirely when the list is empty — so a freshly bootstrapped root
/// CA was issued with no KeyUsage and no ExtendedKeyUsage extension at all, violating RFC 5280
/// 4.2.1.3 for a certificate that signs certificates and CRLs. Every seeded profile inherited the
/// same empty lists.
/// </para>
/// <para>
/// Resolution is deliberately lossy-tolerant on input and exact on output: callers get back the
/// catalog's own canonical spelling, so downstream consumers never see the caller's variant.
/// </para>
/// </summary>
public static class UsageCatalogResolver
{
    /// <summary>
    /// Collapses a usage identifier to a comparison key: lowercase, every non-alphanumeric
    /// character removed. "Server Auth", "serverAuth" and "server_auth" all reduce to
    /// <c>serverauth</c>.
    /// </summary>
    public static string Normalize(string? value)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;
        Span<char> buffer = stackalloc char[value.Length];
        var len = 0;
        foreach (var ch in value)
            if (char.IsLetterOrDigit(ch))
                buffer[len++] = char.ToLowerInvariant(ch);
        return new string(buffer[..len]);
    }

    /// <summary>
    /// Word-level synonyms that normalization alone cannot bridge.
    /// <para>
    /// Stripping case and separators makes "Digital Signature" and "digitalSignature" agree, but
    /// several usages are spelled with genuinely different WORDS across the two vocabularies —
    /// "Key Certificate Signing" versus "keyCertSign", "OCSP Signer" versus "OCSPSigning". Those
    /// need an explicit mapping, and omitting it is not a cosmetic gap: these are exactly the
    /// usages a CA certificate depends on, so a miss here is what leaves a root without
    /// keyCertSign.
    /// </para>
    /// <para>
    /// Keys and values are already-normalized forms. Both the catalog entry and the query are put
    /// through this, so the two meet at the same canonical key regardless of which side uses
    /// which spelling.
    /// </para>
    /// </summary>
    private static readonly Dictionary<string, string> Synonyms = new(StringComparer.Ordinal)
    {
        // Standard key usages
        ["keycertificatesigning"] = "keycertsign",
        ["certificatesigning"] = "keycertsign",
        ["crlsigning"] = "crlsign",
        ["certificaterevocationlistsigning"] = "crlsign",
        ["nonrepudiation"] = "nonrepudiation",
        ["contentcommitment"] = "nonrepudiation",   // RFC 5280 renamed this bit

        // Extended key usages
        ["serverauthentication"] = "serverauth",
        ["clientauthentication"] = "clientauth",
        ["ocspsigner"] = "ocspsigning",
        ["ocspsign"] = "ocspsigning",
        ["smartcardlogin"] = "smartcardlogon",
    };

    /// <summary>
    /// Normalizes and then folds word-level synonyms, producing the key both sides compare on.
    /// </summary>
    public static string Canonicalize(string? value)
    {
        var normalized = Normalize(value);
        return Synonyms.TryGetValue(normalized, out var canonical) ? canonical : normalized;
    }

    /// <summary>
    /// Builds a lookup from every accepted spelling of a catalog entry to the value the caller
    /// wants back.
    /// </summary>
    /// <param name="entries">Catalog rows as (OID, FriendlyName) pairs.</param>
    /// <param name="resultSelector">
    /// Chooses what a match returns — the friendly name for KeyUsage (the certificate builder
    /// parses friendly names) or the OID for ExtendedKeyUsage (the builder emits OIDs).
    /// </param>
    public static Dictionary<string, string> BuildLookup(
        IEnumerable<(string? Oid, string? FriendlyName)> entries,
        Func<(string? Oid, string? FriendlyName), string> resultSelector)
    {
        var lookup = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in entries)
        {
            if (string.IsNullOrWhiteSpace(entry.FriendlyName)) continue;
            var result = resultSelector(entry);
            if (string.IsNullOrWhiteSpace(result)) continue;

            lookup[entry.FriendlyName] = result;
            lookup[Normalize(entry.FriendlyName)] = result;
            lookup[Canonicalize(entry.FriendlyName)] = result;
            if (!string.IsNullOrWhiteSpace(entry.Oid))
                lookup[entry.Oid] = result;
        }
        return lookup;
    }

    /// <summary>
    /// Resolves one caller-supplied spelling against a lookup from <see cref="BuildLookup"/>.
    /// Returns <c>null</c> when the usage is not in the catalog — callers decide whether that is
    /// a drop-with-warning or a hard failure.
    /// </summary>
    public static string? Resolve(Dictionary<string, string> lookup, string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        if (lookup.TryGetValue(raw.Trim(), out var direct)) return direct;
        if (lookup.TryGetValue(Normalize(raw), out var viaNorm)) return viaNorm;
        return lookup.TryGetValue(Canonicalize(raw), out var viaSynonym) ? viaSynonym : null;
    }
}
