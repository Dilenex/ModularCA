using Org.BouncyCastle.Asn1.X509;

namespace ModularCA.Shared.Utils
{
    /// <summary>
    /// Shared helper for translating cert-profile friendly-name strings (e.g.
    /// "Digital Signature", "Key Certificate Signing") into <see cref="KeyUsage"/>
    /// bit flags. Centralizes what used to be two near-identical copies of the same
    /// map in <c>CertificateBuilderService</c> and <c>IssuanceValidationService</c>.
    /// <para>
    /// Fails closed on unknown names: the caller receives an <see cref="InvalidOperationException"/>
    /// instead of a silent <c>-1</c>. That way a typo in a profile's KeyUsages JSON
    /// (e.g. "Digital Signatur") aborts issuance rather than quietly shipping a cert
    /// with a missing usage bit.
    /// </para>
    /// </summary>
    public static class KeyUsageFriendlyNames
    {
        /// <summary>
        /// Parses a single friendly-name string into its BouncyCastle
        /// <see cref="KeyUsage"/> bit flag.
        /// </summary>
        /// <param name="name">
        /// Friendly name (case-insensitive, trimmed). Accepted values:
        /// "Digital Signature", "Non Repudiation", "Key Encipherment",
        /// "Data Encipherment", "Key Agreement", "Key Certificate Signing",
        /// "CRL Signing", "Encipher Only", "Decipher Only".
        /// </param>
        /// <returns>The <see cref="KeyUsage"/> bit flag.</returns>
        /// <exception cref="InvalidOperationException">
        /// Thrown when <paramref name="name"/> does not match any known friendly
        /// name. Issuance must abort so the profile author notices the typo.
        /// </exception>
        public static int Parse(string name)
        {
            // Three vocabularies for the same nine bits exist in this system and all three reach
            // here depending on who wrote the profile:
            //
            //   this map's display form   "Digital Signature"  "Key Certificate Signing"  "CRL Signing"
            //   OIDOptions.FriendlyName   "digitalSignature"   "keyCertSign"              "crlSign"
            //   the admin UI's old label  "Digital Signature"  "Key Cert Sign"            "CRL Sign"
            //
            // Most collapse onto the same key once case and separators are removed, but KeyCertSign
            // and CrlSign genuinely differ in WORDS ("keycertsign" vs "keycertificatesigning"), so
            // they need explicit aliases. Accepting every spelling here is what lets the catalog,
            // the UI and the seeder disagree without aborting issuance.
            return Normalize(name) switch
            {
                "digitalsignature" => KeyUsage.DigitalSignature,
                "nonrepudiation" => KeyUsage.NonRepudiation,
                "keyencipherment" => KeyUsage.KeyEncipherment,
                "dataencipherment" => KeyUsage.DataEncipherment,
                "keyagreement" => KeyUsage.KeyAgreement,
                "keycertificatesigning" or "keycertsign" => KeyUsage.KeyCertSign,
                "crlsigning" or "crlsign" => KeyUsage.CrlSign,
                "encipheronly" => KeyUsage.EncipherOnly,
                "decipheronly" => KeyUsage.DecipherOnly,
                _ => throw new InvalidOperationException(
                    $"Unknown key usage friendly name: '{name}'. " +
                    "Expected one of: 'Digital Signature', 'Non Repudiation', 'Key Encipherment', " +
                    "'Data Encipherment', 'Key Agreement', 'Key Certificate Signing', 'CRL Signing', " +
                    "'Encipher Only', 'Decipher Only' (the camelCase OIDOptions spellings such as " +
                    "'digitalSignature' and 'keyCertSign' are accepted too).")
            };
        }

        /// <summary>
        /// Collapses a usage name to a comparison key. Delegates to
        /// <see cref="UsageCatalogResolver.Normalize"/> — this used to be a private copy carrying
        /// a comment claiming it "matches" the copies in IssuanceValidationService and the admin
        /// UI. Three hand-synchronized copies is how the Bootstrap seeder came to be left behind
        /// when the runtime ones were fixed, so there is now exactly one.
        /// </summary>
        private static string Normalize(string name) => UsageCatalogResolver.Normalize(name);

        /// <summary>
        /// Combines a list of friendly names into a single OR-ed <see cref="KeyUsage"/>
        /// bit mask. Returns <c>0</c> when the list is empty.
        /// </summary>
        /// <param name="names">List of friendly names.</param>
        /// <returns>Bitwise-OR of every parsed <see cref="KeyUsage"/> bit.</returns>
        /// <exception cref="InvalidOperationException">
        /// Thrown when any entry in <paramref name="names"/> is unrecognized.
        /// </exception>
        public static int ParseMany(IEnumerable<string> names)
        {
            int flags = 0;
            foreach (var name in names)
            {
                flags |= Parse(name);
            }
            return flags;
        }
    }
}
