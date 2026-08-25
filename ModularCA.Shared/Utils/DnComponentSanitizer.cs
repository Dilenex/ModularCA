using System.Net.Mail;

namespace ModularCA.Shared.Utils
{
    /// <summary>
    /// Sanitizes subject DN component values (CN, O, OU, …) and DNS / wildcard names
    /// before they are baked into a certificate. Blocks control characters, BIDI
    /// overrides, unpaired surrogates, and enforces CA/B Forum BR length caps.
    /// Shared between the CertificateBuilderService, CertificateIssuanceService,
    /// and CMP subject ingestion paths so no override surface can bypass the filter.
    /// </summary>
    public static class DnComponentSanitizer
    {
        /// <summary>Maximum CN length per CA/B Forum BR §7.1.4.1 (64 chars).</summary>
        public const int CommonNameMaxLength = 64;

        /// <summary>Maximum O / OU length per CA/B Forum BR (128 chars).</summary>
        public const int OrganizationMaxLength = 128;

        /// <summary>Generic RDN value cap applied when no field-specific limit is provided.</summary>
        public const int DefaultMaxLength = 128;

        /// <summary>
        /// Validates a single RDN value. Rejects control characters (U+0000–U+001F,
        /// U+007F), BIDI overrides (U+202A–U+202E, U+2066–U+2069), unpaired surrogates,
        /// null-embedding, and enforces <paramref name="maxLength"/>. Returns the
        /// (trimmed) value on success, throws <see cref="InvalidOperationException"/>
        /// on violation so issuance aborts with a clear error.
        /// </summary>
        /// <param name="fieldName">Human-readable RDN name used in error messages (e.g. "CN").</param>
        /// <param name="value">The raw value to sanitize.</param>
        /// <param name="maxLength">Maximum allowed length in characters.</param>
        /// <returns>The sanitized (trimmed) value.</returns>
        public static string Sanitize(string fieldName, string value, int maxLength = DefaultMaxLength)
        {
            if (value == null)
                throw new InvalidOperationException($"Subject DN field '{fieldName}' is null.");

            // Trim whitespace first — BR length checks apply to the trimmed form.
            var trimmed = value.Trim();

            if (trimmed.Length == 0)
                throw new InvalidOperationException($"Subject DN field '{fieldName}' is empty after trimming.");

            if (trimmed.Length > maxLength)
                throw new InvalidOperationException(
                    $"Subject DN field '{fieldName}' exceeds maximum length ({trimmed.Length} > {maxLength}).");

            for (int i = 0; i < trimmed.Length; i++)
            {
                char c = trimmed[i];

                // Control characters (C0 + DEL)
                if (c < 0x20 || c == 0x7F)
                    throw new InvalidOperationException(
                        $"Subject DN field '{fieldName}' contains control character U+{(int)c:X4}.");

                // BIDI override characters — these are used in display-spoofing attacks.
                // U+202A LRE, U+202B RLE, U+202C PDF, U+202D LRO, U+202E RLO
                // U+2066 LRI, U+2067 RLI, U+2068 FSI, U+2069 PDI
                if ((c >= 0x202A && c <= 0x202E) || (c >= 0x2066 && c <= 0x2069))
                    throw new InvalidOperationException(
                        $"Subject DN field '{fieldName}' contains BIDI override character U+{(int)c:X4}.");

                // Unpaired surrogates — a lone high surrogate without its low partner
                // or vice versa is not a valid Unicode scalar value.
                if (char.IsHighSurrogate(c))
                {
                    if (i + 1 >= trimmed.Length || !char.IsLowSurrogate(trimmed[i + 1]))
                        throw new InvalidOperationException(
                            $"Subject DN field '{fieldName}' contains unpaired high surrogate at index {i}.");
                    i++; // Skip the low surrogate we just validated
                }
                else if (char.IsLowSurrogate(c))
                {
                    throw new InvalidOperationException(
                        $"Subject DN field '{fieldName}' contains unpaired low surrogate at index {i}.");
                }
            }

            return trimmed;
        }

        /// <summary>
        /// Returns the BR-recommended maximum length for the given friendly field name
        /// (CN → 64, O/OU → 128, everything else → <see cref="DefaultMaxLength"/>).
        /// </summary>
        /// <param name="fieldName">Field name such as "CN", "O", "OU".</param>
        /// <returns>Maximum allowed length in characters.</returns>
        public static int GetMaxLength(string fieldName)
        {
            return fieldName.Trim().ToUpperInvariant() switch
            {
                "CN" => CommonNameMaxLength,
                "O" or "OU" => OrganizationMaxLength,
                _ => DefaultMaxLength
            };
        }

        /// <summary>
        /// Validates a DNS name or wildcard DNS name for use in a SAN entry.
        /// Enforces CA/B Forum BR §7.1.4.2.1 wildcard rules when a wildcard is present:
        /// at most one <c>*</c>, only as the leftmost label, with at least two additional
        /// labels. The <paramref name="allowWildcards"/> flag (sourced from the cert
        /// profile's <c>AllowWildcard</c> column) gates whether wildcards are permitted
        /// at all — when false, any DNS name containing <c>*</c> is rejected outright.
        /// Default is <c>true</c> so callers that don't have a profile context
        /// (e.g. NameConstraints subtree parsing) behave unchanged.
        /// </summary>
        /// <param name="dns">The candidate DNS name.</param>
        /// <param name="allowWildcards">When <c>false</c>, reject any wildcard DNS name with a clear error.</param>
        /// <exception cref="InvalidOperationException">Thrown when the DNS name is malformed, violates wildcard structural rules, or contains a wildcard while <paramref name="allowWildcards"/> is false.</exception>
        public static void ValidateDnsName(string dns, bool allowWildcards = true)
        {
            if (string.IsNullOrWhiteSpace(dns))
                throw new InvalidOperationException("DNS SAN value is empty.");

            var trimmed = dns.Trim();

            if (trimmed.Length > 253)
                throw new InvalidOperationException($"DNS SAN '{trimmed}' exceeds 253 characters.");

            // Reject embedded whitespace and control chars up front.
            foreach (var c in trimmed)
            {
                if (c < 0x20 || c == 0x7F)
                    throw new InvalidOperationException($"DNS SAN '{trimmed}' contains control character.");
            }

            if (trimmed.Contains('*'))
            {
                if (!allowWildcards)
                    throw new InvalidOperationException(
                        $"DNS SAN '{trimmed}' contains a wildcard, but the resolved cert profile does not allow wildcards. Enable 'AllowWildcard' on the profile to permit this.");

                var labels = trimmed.Split('.');
                // Wildcards must be the leftmost label only.
                if (labels[0] != "*")
                    throw new InvalidOperationException(
                        $"Wildcard '*' must be the leftmost label in '{trimmed}' (no partial or interior wildcards).");
                // Only one wildcard allowed.
                for (int i = 1; i < labels.Length; i++)
                {
                    if (labels[i].Contains('*'))
                        throw new InvalidOperationException(
                            $"DNS SAN '{trimmed}' contains a wildcard outside the leftmost label.");
                }
                // Must have at least two additional labels (e.g. *.example.com → 3 labels).
                if (labels.Length < 3)
                    throw new InvalidOperationException(
                        $"Wildcard DNS SAN '{trimmed}' must contain at least two labels beneath the wildcard (e.g. *.example.com).");

                // And the rest must actually be a host name. This branch used to check only
                // wildcard PLACEMENT and label count, never syntax, while the non-wildcard
                // branch below runs Uri.CheckHostName — so on any profile with AllowWildcard
                // enabled, `*.exa mple.com` and `*.ev!l.com` were accepted and encoded verbatim
                // into a dNSName SAN. Only control characters and total length were rejected.
                if (Uri.CheckHostName(string.Join('.', labels.Skip(1))) != UriHostNameType.Dns)
                    throw new InvalidOperationException(
                        $"DNS SAN '{trimmed}' is not a valid wildcard DNS name.");
            }
            else
            {
                // Plain DNS name — use framework validator to sanity-check host-name form.
                if (Uri.CheckHostName(trimmed) != UriHostNameType.Dns)
                    throw new InvalidOperationException($"DNS SAN '{trimmed}' is not a valid DNS name.");
            }
        }

        /// <summary>
        /// Validates an RFC 822 email address for use in a SAN entry by
        /// delegating to <see cref="MailAddress"/>. Returns on success, throws on failure.
        /// </summary>
        public static void ValidateEmail(string email)
        {
            try
            {
                _ = new MailAddress(email);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Email SAN '{email}' is not a valid RFC 822 address: {ex.Message}");
            }
        }

        /// <summary>
        /// Validates a URI SAN value by parsing it into an absolute <see cref="Uri"/>.
        /// </summary>
        public static void ValidateUri(string uri)
        {
            if (!Uri.TryCreate(uri, UriKind.Absolute, out _))
                throw new InvalidOperationException($"URI SAN '{uri}' is not a valid absolute URI.");
        }
    }
}
