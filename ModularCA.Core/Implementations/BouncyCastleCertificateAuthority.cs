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
            certGen.SetNotBefore(notBefore);
            certGen.SetNotAfter(notAfter);
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
            if (request.KeyUsages.Any())
            {
                var flags = KeyUsageFriendlyNames.ParseMany(request.KeyUsages);
                if (flags == 0)
                    throw new InvalidOperationException(
                        "Key usages were requested but resolved to no KeyUsage bits: "
                        + string.Join(", ", request.KeyUsages)
                        + ". Refusing to emit an empty critical KeyUsage extension.");
                certGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(flags));
            }

            // Extended Key Usage
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
        /// <see cref="GeneralName"/>. Falls back to DNS for unknown prefixes.
        /// </summary>
        private static GeneralName GeneralNameFactory(string name)
        {
            var parts = name.Split(':', 2);
            return parts[0].ToLower() switch
            {
                "dns" => new GeneralName(GeneralName.DnsName, parts[1]),
                "ip" => new GeneralName(GeneralName.IPAddress, parts[1]),
                _ => new GeneralName(GeneralName.DnsName, parts[1])
            };
        }
    }
}
