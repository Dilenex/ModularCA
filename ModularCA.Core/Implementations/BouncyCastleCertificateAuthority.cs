using ModularCA.Shared.Models;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using System.Security.Cryptography;
using System.Text;

namespace ModularCA.Core.Implementations
{
    /// <summary>
    /// BouncyCastle-based helper for creating self-signed CA certificates during bootstrap.
    /// Only the static <see cref="CreateSelfSignedCACertificate"/> factory is currently in use;
    /// runtime certificate issuance is handled by <c>ICertificateIssuanceService</c>.
    /// </summary>
    public static class BouncyCastleCertificateAuthority
    {
        /// <summary>
        /// Create a self-signed CA certificate and return the DER bytes and generated private key.
        /// This is a convenience factory so callers don't need a separate SelfSign implementation.
        /// </summary>
        public static (byte[] Certificate, AsymmetricKeyParameter PrivateKey) CreateSelfSignedCACertificate(CertificateRequestModel request)
        {
            var subjectKeyPair = GenerateKeyPair(request.KeyAlgorithm, request.KeySize);

            // Generate 128-bit random serial number (CA/BF BR §7.1 requires ≥64 bits from CSPRNG)
            var serialBytes = new byte[16];
            RandomNumberGenerator.Fill(serialBytes);
            serialBytes[0] &= 0x7F; // Ensure positive (MSB = 0)
            var serial = new BigInteger(1, serialBytes);
            var notBefore = request.NotBefore;
            var notAfter = request.NotAfter;

            var subjectDN = new X509Name(BuildSubject(request));
            var issuerDN = subjectDN;

            var certGen = new X509V3CertificateGenerator();
            certGen.SetSerialNumber(serial);
            certGen.SetIssuerDN(issuerDN);
            // See CertificateValidityUtil.AsUtc: BouncyCastle treats an Unspecified DateTime as
            // local and shifts it by the host's UTC offset.
            certGen.SetNotBefore(CertificateValidityUtil.AsUtc(notBefore));
            certGen.SetNotAfter(CertificateValidityUtil.AsUtc(notAfter));
            certGen.SetSubjectDN(subjectDN);
            certGen.SetPublicKey(subjectKeyPair.Public);

            // Basic Constraints (CA flag)
            certGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(request.IsCA));

            // Subject Key Identifier — required so issued certs can reference this CA via AKI
            var subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(subjectKeyPair.Public);
            certGen.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
                X509ExtensionUtilities.CreateSubjectKeyIdentifier(subjectPublicKeyInfo));

            // Authority Key Identifier — self-signed, so AKI = own SKI
            certGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
                X509ExtensionUtilities.CreateAuthorityKeyIdentifier(subjectPublicKeyInfo));

            // Key Usage
            //
            // Delegates to KeyUsageFriendlyNames, which accepts every vocabulary in use and
            // THROWS on an unrecognised name. The local parser this replaces understood only the
            // spaced display form ("digital signature") and mapped anything else to 0. Once the
            // bootstrap seeder was fixed to resolve usages against the OIDOptions catalog it
            // started returning the catalog's camelCase spelling ("digitalSignature"), which that
            // parser silently scored as zero for every entry — so the root CA was issued with a
            // CRITICAL KeyUsage extension containing no bits at all, asserting that the CA key may
            // do nothing. Failing loudly is the only safe behaviour for this particular extension.
            var flags = request.KeyUsages.Any() ? KeyUsageFriendlyNames.ParseMany(request.KeyUsages) : 0;
            if (request.KeyUsages.Any() && flags == 0)
                throw new InvalidOperationException(
                    "Key usages were requested but resolved to no KeyUsage bits: "
                    + string.Join(", ", request.KeyUsages)
                    + ". Refusing to emit an empty critical KeyUsage extension.");

            // A CA key signs certificates and CRLs. It never enciphers a key or performs key
            // agreement, and RFC 5480 §3 forbids keyEncipherment outright for id-ecPublicKey
            // (RFC 8410 §5 likewise for Ed25519) — which is what the default install used,
            // so the bootstrap root asserted a bit its own key type cannot carry.
            //
            // The caller's list is fixed now, but this is the layer that decides what ends up
            // inside the signature, and a certificate's extensions cannot be corrected after
            // issuance. Refuse rather than quietly strip, so a reintroduction is a failed
            // bootstrap and not a non-compliant root nobody notices for a year.
            CaCertificateRules.EnsureKeyUsagesPermitted(request.IsCA, flags, request.KeyUsages);

            // keyCertSign and cRLSign are mandatory on a cA=TRUE certificate (RFC 5280
            // §4.2.1.3). Applied here as well as on the runtime path, because a CA request
            // that simply omits them previously produced a root with no KeyUsage extension
            // at all — the guard above sat inside `if (request.KeyUsages.Any())`, so an empty
            // list skipped every check rather than failing any of them.
            flags = CaCertificateRules.ApplyRequiredKeyUsages(request.IsCA, flags, out _);

            if (flags != 0)
                certGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(flags));

            // Extended Key Usage
            //
            // An EKU on a CA constrains every certificate beneath it (RFC 5280 §4.2.1.12), so a
            // root carrying serverAuth/clientAuth/codeSigning/emailProtection/timeStamping/OCSP
            // makes a smartcardLogon or kdcAuthentication leaf fail EKU-nesting in Windows
            // CryptoAPI with CERT_E_WRONG_USAGE. CA/B BR §7.1.2.1.2 forbids extKeyUsage on a root
            // outright. The bootstrap paths passed exactly that six-entry list into the root's own
            // request, which is what this rejects.
            //
            // What the CA is permitted to ISSUE is a separate question, carried by the signing
            // profile's AllowedEKUs, and is unaffected.
            CaCertificateRules.EnsureNoExtendedKeyUsage(request.IsCA, request.ExtendedKeyUsages);

            if (request.ExtendedKeyUsages.Any())
            {
                var usages = request.ExtendedKeyUsages.Select(u => new DerObjectIdentifier(u)).ToList();
                certGen.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(usages));
            }

            // Subject Alternative Name
            if (request.SubjectAlternativeNames.Any())
            {
                var altNames = request.SubjectAlternativeNames
                    .Select(name => name.Contains(":") ? name : $"DNS:{name}")
                    .Select(GeneralNameFactory)
                    .ToArray();

                var subjectAltNames = new DerSequence(altNames);
                certGen.AddExtension(X509Extensions.SubjectAlternativeName, false, subjectAltNames);
            }

            // Sign certificate with generated private key
            var signer = new Asn1SignatureFactory(
                KeyAlgorithmPolicy.ResolveSignatureAlgorithm(request.KeyAlgorithm, request.KeySize),
                subjectKeyPair.Private,
                new SecureRandom());
            var cert = certGen.Generate(signer);

            return (cert.GetEncoded(), subjectKeyPair.Private);
        }

        // ========== Helpers ==========

        /// <summary>
        /// Delegates to <see cref="KeyAlgorithmPolicy.GenerateKeyPair(string, int)"/> so the key
        /// generation allowlist (RSA 2048/3072/4096/7680/8192, ECDSA P-256/384/521, Ed25519/Ed448, ML-DSA,
        /// SLH-DSA) is enforced here as a defense-in-depth layer. Any other algorithm or size
        /// throws <see cref="ArgumentException"/>.
        /// </summary>
        private static AsymmetricCipherKeyPair GenerateKeyPair(string algorithm, int keySize)
            => KeyAlgorithmPolicy.GenerateKeyPair(algorithm, keySize);

        /// <summary>
        /// Builds an RFC 2253-ish subject DN string from the fields on <paramref name="req"/>.
        /// </summary>
        private static string BuildSubject(CertificateRequestModel req)
        {
            var sb = new StringBuilder();
            if (!string.IsNullOrWhiteSpace(req.CommonName)) sb.Append($"CN={req.CommonName}, ");
            if (!string.IsNullOrWhiteSpace(req.Organization)) sb.Append($"O={req.Organization}, ");
            if (!string.IsNullOrWhiteSpace(req.OrganizationalUnit)) sb.Append($"OU={req.OrganizationalUnit}, ");
            if (!string.IsNullOrWhiteSpace(req.Locality)) sb.Append($"L={req.Locality}, ");
            if (!string.IsNullOrWhiteSpace(req.State)) sb.Append($"ST={req.State}, ");
            if (!string.IsNullOrWhiteSpace(req.Country)) sb.Append($"C={req.Country}, ");
            return sb.ToString().TrimEnd(',', ' ');
        }


        /// <summary>
        /// Parses a "type:value" SAN string (e.g. "DNS:example.com", "IP:10.0.0.1") into a BouncyCastle
        /// <see cref="GeneralName"/>.
        /// </summary>
        /// <remarks>
        /// Unknown prefixes used to fall back to <c>DnsName</c>, which is worse than it sounds: a
        /// "UPN:alice@example.test" entry became a DNS SAN containing that text, and a typo like
        /// "DSN:host" became a DNS name silently rather than being reported. A SAN the caller did
        /// not ask for is a wrong identity in a signed certificate, so unknown types are refused.
        /// This mirrors <c>CertificateBuilderService</c>, which is the runtime path.
        /// </remarks>
        private static GeneralName GeneralNameFactory(string name)
        {
            var parts = name.Split(':', 2);
            if (parts.Length < 2)
                throw new InvalidOperationException(
                    $"SAN entry '{name}' is missing a TYPE:value prefix (expected DNS:, IP:, URI:, EMAIL:, UPN:).");

            return SanGeneralNames.Build(parts[0], parts[1].Trim());
        }
    }
}
