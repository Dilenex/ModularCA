using System.Text.Json;

namespace ModularCA.Shared.Utils
{
    /// <summary>
    /// Turns a stored key-usage list into BouncyCastle key-usage bit flags.
    /// <para>
    /// This used to split the input on commas, lowercase it, and match against nine hard-coded
    /// spaced display names, mapping anything unrecognised to 0. Two things were wrong with that.
    /// The stored value is a JSON array, not CSV — splitting <c>["Digital Signature","Key
    /// Encipherment"]</c> on commas yields the tokens <c>["Digital Signature"</c> and <c>"Key
    /// Encipherment"]</c>, which match nothing. And the vocabulary was one of five hand-maintained
    /// copies, so it did not recognise the catalog's camelCase spellings either.
    /// </para>
    /// <para>
    /// Both failures produced the same result: <c>flags == 0</c>, and the caller
    /// (<c>CsrService</c>) then wrote a CRITICAL KeyUsage extension with no bits set — a CSR
    /// asserting that its key may do nothing. Export one to an external CA and the returned
    /// certificate is unusable. Internal issuance masked it because the certificate builder
    /// re-derives usages separately.
    /// </para>
    /// <para>
    /// Parsing is now delegated to <see cref="KeyUsageFriendlyNames"/>, the single vocabulary, and
    /// an unrecognised name throws rather than silently dropping a bit.
    /// </para>
    /// </summary>
    public static class X509KeyUsageUtil
    {
        /// <summary>
        /// Parses a JSON array (or, for legacy rows, a comma-separated list) of key-usage names
        /// and returns the combined BouncyCastle flags.
        /// <para>
        /// The returned value is usable with both <c>Org.BouncyCastle.Asn1.X509.KeyUsage</c> and
        /// <c>Org.BouncyCastle.X509.X509KeyUsage</c> — the bit constants are identical.
        /// </para>
        /// </summary>
        /// <exception cref="System.InvalidOperationException">
        /// Thrown when a name is not a recognised key usage. Failing closed matters here: the
        /// alternative is a certificate that silently lacks a usage the profile asked for.
        /// </exception>
        public static int ParseKeyUsages(string usageList)
        {
            var names = ParseNames(usageList);
            return names.Count == 0 ? 0 : KeyUsageFriendlyNames.ParseMany(names);
        }

        /// <summary>
        /// Reads the stored representation. JSON array is the current format; the comma-separated
        /// fallback covers rows written before profiles moved to JSON.
        /// </summary>
        private static List<string> ParseNames(string usageList)
        {
            if (string.IsNullOrWhiteSpace(usageList))
                return new List<string>();

            var trimmed = usageList.Trim();
            if (trimmed.StartsWith('['))
            {
                try
                {
                    var parsed = JsonSerializer.Deserialize<List<string>>(trimmed, SafeJsonOptions.Default);
                    if (parsed != null)
                        return parsed.Where(n => !string.IsNullOrWhiteSpace(n)).ToList();
                }
                catch (JsonException)
                {
                    // Fall through to the CSV reading below rather than throwing on a malformed
                    // blob — the name parser will still reject anything it does not recognise.
                }
            }

            return trimmed
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToList();
        }
    }
}
