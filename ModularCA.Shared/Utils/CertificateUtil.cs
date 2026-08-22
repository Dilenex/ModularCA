using ModularCA.Shared.Models;
using ModularCA.Shared.Models.Csr;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;


namespace ModularCA.Shared.Utils;

public static class CertificateUtil
{
    // === Export to PEM ===
    public static string ExportCertificateToPem(X509Certificate cert)
    {
        using var sw = new StringWriter();
        var pemWriter = new PemWriter(sw);
        pemWriter.WriteObject(cert);
        return sw.ToString();
    }

    public static string ExportPrivateKeyToPem(AsymmetricKeyParameter privateKey)
    {
        using var sw = new StringWriter();
        var pemWriter = new PemWriter(sw);
        pemWriter.WriteObject(privateKey);
        return sw.ToString();
    }

    // === Parse Certificate ===
    public static CertificateInfoModel ParseCertificate(X509Certificate cert)
    {
        var info = new CertificateInfoModel
        {
            SubjectDN = cert.SubjectDN.ToString(),
            Issuer = cert.IssuerDN.ToString(),
            SerialNumber = FormatSerialNumber(cert.SerialNumber),
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter,
            Thumbprints = GetThumbprints(cert)
        };

        // Basic Constraints
        var bc = cert.GetExtensionValue(X509Extensions.BasicConstraints);
        if (bc != null)
        {
            var constraints = BasicConstraints.GetInstance(X509ExtensionUtilities.FromExtensionValue(bc));
            info.IsCA = constraints.IsCA();
        }

        // Key Usage
        var kuExt = cert.GetExtensionValue(X509Extensions.KeyUsage);
        if (kuExt != null)
        {
            var keyUsage = KeyUsage.GetInstance(X509ExtensionUtilities.FromExtensionValue(kuExt));
            var usages = new[]
            {
                (KeyUsage.DigitalSignature, "DigitalSignature"),
                (KeyUsage.NonRepudiation, "NonRepudiation"),
                (KeyUsage.KeyEncipherment, "KeyEncipherment"),
                (KeyUsage.DataEncipherment, "DataEncipherment"),
                (KeyUsage.KeyAgreement, "KeyAgreement"),
                (KeyUsage.KeyCertSign, "KeyCertSign"),
                (KeyUsage.CrlSign, "CrlSign")
            };

            foreach (var (flag, name) in usages)
                if ((keyUsage.IntValue & flag) != 0)
                    info.KeyUsages.Add(name);
        }

        // Extended Key Usage
        var ekuExt = cert.GetExtensionValue(X509Extensions.ExtendedKeyUsage);
        if (ekuExt != null)
        {
            var eku = ExtendedKeyUsage.GetInstance(X509ExtensionUtilities.FromExtensionValue(ekuExt));
            info.ExtendedKeyUsages = eku.GetAllUsages().Cast<DerObjectIdentifier>().Select(x => x.Id).ToList();
        }

        // SAN
        var sanExt = cert.GetExtensionValue(X509Extensions.SubjectAlternativeName);
        if (sanExt != null)
        {
            var san = Asn1Sequence.GetInstance(X509ExtensionUtilities.FromExtensionValue(sanExt));
            foreach (Asn1Encodable entry in san)
            {
                var gn = GeneralName.GetInstance(entry);
                var val = gn.TagNo == GeneralName.IPAddress && gn.Name is Org.BouncyCastle.Asn1.DerOctetString ipOct
                    ? new System.Net.IPAddress(ipOct.GetOctets()).ToString()
                    : gn.Name.ToString() ?? "";
                info.SubjectAlternativeNames.Add($"{GeneralNameTypeName(gn.TagNo)}:{val}");
            }
        }

        // Key Algorithm & Size — mirrors the CSR parser so cert detail/list views
        // surface the same algorithm names. Previously left blank, which is why
        // public/admin cert views showed an empty algorithm field.
        var pubKey = cert.GetPublicKey();
        info.KeyAlgorithm = pubKey switch
        {
            Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters => "RSA",
            Org.BouncyCastle.Crypto.Parameters.ECKeyParameters => "ECDSA",
            Org.BouncyCastle.Crypto.Parameters.DsaPublicKeyParameters => "DSA",
            Org.BouncyCastle.Crypto.Parameters.Ed25519PublicKeyParameters => "Ed25519",
            Org.BouncyCastle.Crypto.Parameters.Ed448PublicKeyParameters => "Ed448",
            Org.BouncyCastle.Crypto.Parameters.MLDsaPublicKeyParameters mlDsa => mlDsa.Parameters.Name,
            Org.BouncyCastle.Crypto.Parameters.SlhDsaPublicKeyParameters slhDsa => slhDsa.Parameters.Name,
            _ => "Unknown"
        };

        if (pubKey is Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters rsa)
            info.KeySize = rsa.Modulus.BitLength.ToString();
        else if (pubKey is Org.BouncyCastle.Crypto.Parameters.ECKeyParameters ec)
            info.KeySize = MapEcCurveOidToName(ec.PublicKeyParamSet?.Id ?? "EC");

        // Signature Algorithm
        info.SignatureAlgorithm = MapSignatureAlgorithmOidToName(cert.SigAlgOid);

        return info;
    }

    private static string GeneralNameTypeName(int tag)
    {
        return tag switch
        {
            GeneralName.DnsName => "DNS",
            GeneralName.IPAddress => "IP",
            GeneralName.Rfc822Name => "Email",
            _ => "Other"
        };
    }

    // === Thumbprint Calculation ===
    public static string GetThumbprints(X509Certificate cert)
    {
        byte[] certBytes = cert.GetEncoded();
        byte[] sha1 = SHA1.HashData(certBytes);
        byte[] sha256 = SHA256.HashData(certBytes);

        var dict = new Dictionary<string, string>
        {
            { "SHA 1", BitConverter.ToString(sha1).Replace("-", "").ToUpperInvariant() },
            { "SHA 256", BitConverter.ToString(sha256).Replace("-", "").ToUpperInvariant() }
        };
        return JsonSerializer.Serialize(dict);
    }

    // === Format Helpers ===
    public static bool IsPemFormat(string input)
    {
        return input.Contains("-----BEGIN CERTIFICATE-----");
    }

    public static X509Certificate ParseFromPem(string pem)
    {
        using var sr = new StringReader(pem);
        var pemReader = new PemReader(sr);
        return pemReader.ReadObject() as X509Certificate
            ?? throw new InvalidOperationException("Invalid PEM certificate.");
    }

    public static string ConvertDerToPem(byte[] der, string label)
    {
        var base64 = Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks);
        return $"-----BEGIN {label}-----\n{base64}\n-----END {label}-----\n";
    }

    public class ParsedCsrInfo
    {
        public string SubjectName { get; set; } = string.Empty;
        public List<string> SubjectAlternativeNames { get; set; } = new();
        public string KeyAlgorithm { get; set; } = string.Empty;
        public string SignatureAlgorithm { get; set; } = string.Empty;
        public string KeySize { get; set; } = string.Empty;

        /// <summary>
        /// DER-encoded SubjectPublicKeyInfo so the SCEP GetCertInitial
        /// handler can hash it and verify the polling client proved possession of the
        /// same key that signed the original PKCSReq.
        /// </summary>
        public byte[]? PublicKeyDer { get; set; }
    }

    /// <summary>
    /// Parses a PEM-encoded CSR and returns a structured response with individual subject DN
    /// components, typed SAN entries, key info, requested extensions, and signature validation.
    /// Handles both PKCS#10 PEM and Base64-encoded DER formats.
    /// </summary>
    public static Models.Csr.ParseCsrResponse ParseCsrDetailed(string pem)
    {
        var response = new Models.Csr.ParseCsrResponse();
        var errors = new List<string>();

        Pkcs10CertificationRequest csr;
        try
        {
            // Try PEM first
            using var sr = new StringReader(pem);
            var pemReader = new PemReader(sr);
            var obj = pemReader.ReadObject();
            if (obj is Pkcs10CertificationRequest pemCsr)
            {
                csr = pemCsr;
            }
            else
            {
                // Try raw Base64 DER
                var derBytes = Convert.FromBase64String(pem.Trim());
                csr = new Pkcs10CertificationRequest(derBytes);
            }
        }
        catch (Exception ex)
        {
            response.Valid = false;
            response.ValidationErrors.Add($"Failed to parse CSR: {ex.Message}");
            return response;
        }

        var info = csr.GetCertificationRequestInfo();

        // Subject DN — extract individual RDN components
        var subject = info.Subject;
        var rdnOidToName = new Dictionary<string, string>
        {
            { X509Name.CN.Id, "CN" },
            { X509Name.O.Id, "O" },
            { X509Name.OU.Id, "OU" },
            { X509Name.L.Id, "L" },
            { X509Name.ST.Id, "ST" },
            { X509Name.C.Id, "C" },
            { X509Name.DC.Id, "DC" },
            { X509Name.EmailAddress.Id, "Email" },
            { X509Name.SerialNumber.Id, "SERIALNUMBER" },
            { X509Name.T.Id, "T" },
            { X509Name.Street.Id, "STREET" },
        };

        var oids = subject.GetOidList();
        var values = subject.GetValueList();
        for (int i = 0; i < oids.Count; i++)
        {
            var oid = ((DerObjectIdentifier)oids[i]).Id;
            var val = values[i]?.ToString() ?? "";
            var fieldName = rdnOidToName.TryGetValue(oid, out var name) ? name : oid;
            response.Subject[fieldName] = val;
        }

        // Key Algorithm & Size
        var pubKey = PublicKeyFactory.CreateKey(info.SubjectPublicKeyInfo);
        response.KeyAlgorithm = pubKey switch
        {
            Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters => "RSA",
            Org.BouncyCastle.Crypto.Parameters.ECKeyParameters => "ECDSA",
            Org.BouncyCastle.Crypto.Parameters.DsaPublicKeyParameters => "DSA",
            Org.BouncyCastle.Crypto.Parameters.Ed25519PublicKeyParameters => "Ed25519",
            Org.BouncyCastle.Crypto.Parameters.Ed448PublicKeyParameters => "Ed448",
            Org.BouncyCastle.Crypto.Parameters.MLDsaPublicKeyParameters mlDsa => mlDsa.Parameters.Name,
            Org.BouncyCastle.Crypto.Parameters.SlhDsaPublicKeyParameters slhDsa => slhDsa.Parameters.Name,
            _ => "Unknown"
        };

        if (pubKey is Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters rsa)
            response.KeySize = rsa.Modulus.BitLength.ToString();
        else if (pubKey is Org.BouncyCastle.Crypto.Parameters.ECKeyParameters ec)
            response.KeySize = MapEcCurveOidToName(ec.PublicKeyParamSet?.Id ?? "EC");

        // Signature Algorithm
        response.SignatureAlgorithm = MapSignatureAlgorithmOidToName(csr.SignatureAlgorithm.Algorithm.Id);

        // Parse extensions from attributes
        var attrs = info.Attributes;
        if (attrs != null)
        foreach (var attrObj in attrs)
        {
            var attr = Org.BouncyCastle.Asn1.X509.AttributeX509.GetInstance(attrObj);
            if (attr.AttrValues == null || attr.AttrValues.Count == 0) continue;
            if (attr.AttrType.Equals(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest))
            {
                var extensions = X509Extensions.GetInstance(attr.AttrValues[0]);

                // SANs
                var sanExt = extensions.GetExtension(X509Extensions.SubjectAlternativeName);
                if (sanExt != null)
                {
                    var sanSeq = Asn1Sequence.GetInstance(sanExt.GetParsedValue());
                    foreach (Asn1Encodable entry in sanSeq)
                    {
                        var gn = GeneralName.GetInstance(entry);
                        var sanType = gn.TagNo switch
                        {
                            GeneralName.DnsName => "DNS",
                            GeneralName.IPAddress => "IP",
                            GeneralName.Rfc822Name => "Email",
                            GeneralName.UniformResourceIdentifier => "URI",
                            _ => "Other"
                        };
                        var sanValue = gn.Name.ToString() ?? "";
                        // IP addresses come as ASN.1 octet strings — convert to dotted notation
                        if (sanType == "IP" && gn.Name is Org.BouncyCastle.Asn1.DerOctetString octets)
                        {
                            var ipBytes = octets.GetOctets();
                            sanValue = new System.Net.IPAddress(ipBytes).ToString();
                        }
                        response.Sans.Add(new Models.Csr.SanEntry
                        {
                            Type = sanType,
                            Value = sanValue
                        });
                    }
                }

                // Key Usage
                var kuExt = extensions.GetExtension(X509Extensions.KeyUsage);
                if (kuExt != null)
                {
                    var keyUsage = KeyUsage.GetInstance(kuExt.GetParsedValue());
                    var usages = new[]
                    {
                        (KeyUsage.DigitalSignature, "digitalSignature"),
                        (KeyUsage.NonRepudiation, "nonRepudiation"),
                        (KeyUsage.KeyEncipherment, "keyEncipherment"),
                        (KeyUsage.DataEncipherment, "dataEncipherment"),
                        (KeyUsage.KeyAgreement, "keyAgreement"),
                        (KeyUsage.KeyCertSign, "keyCertSign"),
                        (KeyUsage.CrlSign, "crlSign"),
                    };
                    foreach (var (flag, flagName) in usages)
                        if ((keyUsage.IntValue & flag) != 0)
                            response.RequestedExtensions.KeyUsage.Add(flagName);
                }

                // Extended Key Usage
                var ekuExt = extensions.GetExtension(X509Extensions.ExtendedKeyUsage);
                if (ekuExt != null)
                {
                    var eku = ExtendedKeyUsage.GetInstance(ekuExt.GetParsedValue());
                    foreach (DerObjectIdentifier ekuOid in eku.GetAllUsages())
                        response.RequestedExtensions.ExtendedKeyUsage.Add(ekuOid.Id);
                }
            }
        }

        // Verify CSR signature
        try
        {
            response.Valid = csr.Verify();
        }
        catch
        {
            response.Valid = false;
            errors.Add("CSR signature verification failed");
        }

        response.ValidationErrors = errors;
        return response;
    }

    public static ParsedCsrInfo ParseCsr(string pem)
    {
        using var sr = new StringReader(pem);
        var pemReader = new PemReader(sr);
        var csr = pemReader.ReadObject() as Pkcs10CertificationRequest
            ?? throw new InvalidOperationException("Invalid PEM CSR.");

        var info = csr.GetCertificationRequestInfo();

        // Subject
        var subject = info.Subject.ToString();

        // Key Algorithm & Size
        var pubKey = PublicKeyFactory.CreateKey(info.SubjectPublicKeyInfo);
        string keyAlgorithm = pubKey switch
        {
            Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters => "RSA",
            Org.BouncyCastle.Crypto.Parameters.ECKeyParameters => "ECDSA",
            Org.BouncyCastle.Crypto.Parameters.DsaPublicKeyParameters => "DSA",
            Org.BouncyCastle.Crypto.Parameters.Ed25519PublicKeyParameters => "Ed25519",
            Org.BouncyCastle.Crypto.Parameters.Ed448PublicKeyParameters => "Ed448",
            Org.BouncyCastle.Crypto.Parameters.MLDsaPublicKeyParameters mlDsa => mlDsa.Parameters.Name,
            Org.BouncyCastle.Crypto.Parameters.SlhDsaPublicKeyParameters slhDsa => slhDsa.Parameters.Name,
            _ => "Unknown"
        };
        string keySize = "";
        if (pubKey is Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters rsa)
            keySize = rsa.Modulus.BitLength.ToString();
        else if (pubKey is Org.BouncyCastle.Crypto.Parameters.ECKeyParameters ec)
            keySize = MapEcCurveOidToName(ec.PublicKeyParamSet?.Id ?? "EC");

        // Signature Algorithm
        string sigAlg = MapSignatureAlgorithmOidToName(csr.SignatureAlgorithm.Algorithm.Id);

        // SANs
        var altNames = new List<string>();
        var attrs = info.Attributes;
        if (attrs != null)
        foreach (var attrObj in attrs)
        {
            var attr = Org.BouncyCastle.Asn1.X509.AttributeX509.GetInstance(attrObj);
            if (attr.AttrValues == null || attr.AttrValues.Count == 0) continue;
            if (attr.AttrType.Equals(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest))
            {
                var extensions = X509Extensions.GetInstance(attr.AttrValues[0]);
                var sanExt = extensions.GetExtension(X509Extensions.SubjectAlternativeName);
                if (sanExt != null)
                {
                    var sanSeq = Asn1Sequence.GetInstance(sanExt.GetParsedValue());
                    foreach (Asn1Encodable entry in sanSeq)
                    {
                        var gn = GeneralName.GetInstance(entry);
                        var gnVal = gn.TagNo == GeneralName.IPAddress && gn.Name is Org.BouncyCastle.Asn1.DerOctetString ipO
                            ? new System.Net.IPAddress(ipO.GetOctets()).ToString()
                            : gn.Name.ToString() ?? "";
                        altNames.Add($"{GeneralNameTypeNameForCsr(gn.TagNo)}:{gnVal}");
                    }
                }
            }
        }

        return new ParsedCsrInfo
        {
            SubjectName = subject,
            SubjectAlternativeNames = altNames,
            KeyAlgorithm = keyAlgorithm,
            SignatureAlgorithm = sigAlg,
            KeySize = keySize,
            PublicKeyDer = info.SubjectPublicKeyInfo?.GetDerEncoded()
        };
    }

    private static readonly Dictionary<string, string> EcCurveOidToName = new()
    {
        { "1.2.840.10045.3.1.7", "P-256" },
        { "1.3.132.0.34", "P-384" },
        { "1.3.132.0.35", "P-521" },
    };

    private static string MapEcCurveOidToName(string oidOrName)
    {
        return EcCurveOidToName.TryGetValue(oidOrName, out var name) ? name : oidOrName;
    }

    private static readonly Dictionary<string, string> SignatureAlgorithmOidToName = new()
    {
        { "1.2.840.113549.1.1.5", "SHA1withRSA" },
        { "1.2.840.113549.1.1.11", "SHA256withRSA" },
        { "1.2.840.113549.1.1.12", "SHA384withRSA" },
        { "1.2.840.113549.1.1.13", "SHA512withRSA" },
        { "1.2.840.113549.1.1.10", "SHA256withRSAandMGF1" }, // id-RSASSA-PSS (params determine actual hash)
        { "1.2.840.10045.4.3.2", "SHA256withECDSA" },
        { "1.2.840.10045.4.3.3", "SHA384withECDSA" },
        { "1.2.840.10045.4.3.4", "SHA512withECDSA" },
        { "1.2.840.10040.4.3", "SHA1withDSA" },
        { "1.3.101.112", "Ed25519" },
        { "1.3.101.113", "Ed448" },
        { "2.16.840.1.101.3.4.3.17", "ML-DSA-44" },
        { "2.16.840.1.101.3.4.3.18", "ML-DSA-65" },
        { "2.16.840.1.101.3.4.3.19", "ML-DSA-87" },
        // SLH-DSA (SPHINCS+) — FIPS 205 OIDs (NIST PQC)
        { "2.16.840.1.101.3.4.3.20", "SLH-DSA-SHA2-128S" },
        { "2.16.840.1.101.3.4.3.21", "SLH-DSA-SHA2-128F" },
        { "2.16.840.1.101.3.4.3.22", "SLH-DSA-SHA2-192S" },
        { "2.16.840.1.101.3.4.3.23", "SLH-DSA-SHA2-192F" },
        { "2.16.840.1.101.3.4.3.24", "SLH-DSA-SHA2-256S" },
        { "2.16.840.1.101.3.4.3.25", "SLH-DSA-SHA2-256F" },
        { "2.16.840.1.101.3.4.3.26", "SLH-DSA-SHAKE-128S" },
        { "2.16.840.1.101.3.4.3.27", "SLH-DSA-SHAKE-128F" },
        { "2.16.840.1.101.3.4.3.28", "SLH-DSA-SHAKE-192S" },
        { "2.16.840.1.101.3.4.3.29", "SLH-DSA-SHAKE-192F" },
        { "2.16.840.1.101.3.4.3.30", "SLH-DSA-SHAKE-256S" },
        { "2.16.840.1.101.3.4.3.31", "SLH-DSA-SHAKE-256F" },
    };

    private static string MapSignatureAlgorithmOidToName(string oidOrName)
    {
        return SignatureAlgorithmOidToName.TryGetValue(oidOrName, out var name) ? name : oidOrName;
    }

    // Helper to avoid ambiguous call
    private static string GeneralNameTypeNameForCsr(int tag)
    {
        return tag switch
        {
            GeneralName.DnsName => "DNS",
            GeneralName.IPAddress => "IP",
            GeneralName.Rfc822Name => "Email",
            _ => "Other"
        };

    }

    public static CreateCsrRequest CreateCsrRequestFromCsrPem(
    string pem,
    Guid certificateProfileId,
    Guid signingProfileId)
    {
        var parsed = ParseCsr(pem);

        return new CreateCsrRequest
        {
            SubjectName = parsed.SubjectName,
            SubjectAlternativeNames = parsed.SubjectAlternativeNames,
            KeyAlgorithm = parsed.KeyAlgorithm,
            SignatureAlgorithm = parsed.SignatureAlgorithm,
            KeySize = parsed.KeySize,
            CertificateProfileId = certificateProfileId,
            SigningProfileId = signingProfileId
        };
    }

    public static byte[] ParseCrlFromPem(string pem)
    {
        using var sr = new StringReader(pem);
        var pemReader = new PemReader(sr);
        var crl = pemReader.ReadObject() as X509Crl
            ?? throw new InvalidOperationException("Invalid PEM CRL.");
        return crl.GetEncoded();
    }

    public static string ParseCnFromPem(string pem)
    {
        var certByte = ParseCertificate(ParseFromPem(pem));
        var cnPart = certByte.SubjectDN.Split(',')[0].Trim();
        return cnPart.StartsWith("CN=", StringComparison.OrdinalIgnoreCase) ? cnPart.Substring(3).Trim() : cnPart;
    }

    public static string ParseCnFromDer(byte[] der)
    {
        var cert = new X509Certificate(der);
        var cnPart = cert.SubjectDN.ToString().Split(',')[0].Trim();
        return cnPart.StartsWith("CN=", StringComparison.OrdinalIgnoreCase) ? cnPart.Substring(3).Trim() : cnPart;
    }

    /// <summary>
    /// Normalizes a BouncyCastle SigAlgName for use with Asn1SignatureFactory.
    /// X509Certificate.SigAlgName may return "SHA-256withECDSA" but the factory
    /// needs "SHA256withECDSA" (no hyphens in the hash prefix).
    /// Post-quantum algorithm names (ML-DSA-*, SLH-DSA-*) are preserved as-is
    /// because their hyphens are part of the canonical name.
    /// </summary>
    public static string NormalizeSigAlgName(string sigAlgName)
    {
        if (string.IsNullOrEmpty(sigAlgName))
            return sigAlgName;

        var upper = sigAlgName.ToUpperInvariant();
        // PQC and EdDSA algorithms use hyphens in their canonical names — return as-is
        if (upper.StartsWith("ML-DSA") || upper.StartsWith("SLH-DSA") ||
            upper == "ED25519" || upper == "ED448")
            return sigAlgName;

        // Traditional algorithms: strip hyphens from hash prefix (SHA-256 -> SHA256)
        return sigAlgName.Replace("-", "");
    }

    /// <summary>
    /// Extracts the challengePassword attribute from a PEM-encoded PKCS#10 CSR, if present.
    /// </summary>
    public static string? ExtractChallengePassword(string pem)
    {
        using var sr = new StringReader(pem);
        var pemReader = new PemReader(sr);
        var csr = pemReader.ReadObject() as Pkcs10CertificationRequest;
        if (csr == null) return null;

        var info = csr.GetCertificationRequestInfo();
        if (info.Attributes == null) return null;
        foreach (var attrObj in info.Attributes)
        {
            var attr = Org.BouncyCastle.Asn1.X509.AttributeX509.GetInstance(attrObj);
            if (attr.AttrType.Equals(PkcsObjectIdentifiers.Pkcs9AtChallengePassword))
            {
                var values = attr.AttrValues;
                if (values.Count > 0)
                {
                    var val = values[0];
                    if (val is DerUtf8String utf8) return utf8.GetString();
                    if (val is DerPrintableString ps) return ps.GetString();
                    if (val is DerIA5String ia5) return ia5.GetString();
                    return val.ToString();
                }
            }
        }
        return null;
    }

    // NormalizeSigAlgName is defined above with PQC-aware logic

    /// <summary>
    /// Maps a signature algorithm name (e.g. "SHA-256withECDSA") to its digest OID
    /// (e.g. "2.16.840.1.101.3.4.2.1" for SHA-256). Used by TSA where the
    /// TimeStampTokenGenerator requires a digest OID, not a signature algorithm.
    /// </summary>
    public static string GetDigestOidFromSigAlg(string sigAlgName)
    {
        var normalized = sigAlgName.Replace("-", "").ToUpperInvariant();

        if (normalized.StartsWith("SHA512"))
            return "2.16.840.1.101.3.4.2.3"; // SHA-512
        if (normalized.StartsWith("SHA384"))
            return "2.16.840.1.101.3.4.2.2"; // SHA-384
        if (normalized.StartsWith("SHA256"))
            return "2.16.840.1.101.3.4.2.1"; // SHA-256
        if (normalized.StartsWith("SHA1"))
            return "1.3.14.3.2.26";           // SHA-1

        // Ed25519/Ed448 and PQC algorithms don't have a separate digest — default to SHA-256
        return "2.16.840.1.101.3.4.2.1";
    }

    /// <summary>
    /// Formats a BouncyCastle BigInteger serial number as uppercase hex string.
    /// This is the industry standard representation (RFC 5280, OCSP, CRL, ACME).
    /// </summary>
    public static string FormatSerialNumber(Org.BouncyCastle.Math.BigInteger serial) =>
        serial.ToString(16).ToUpperInvariant();

    /// <summary>
    /// Converts any serial-number spelling into the exact form
    /// <see cref="FormatSerialNumber"/> produces, which is what the Certificates table stores.
    /// <para>
    /// The two representations disagree whenever the leading nibble is zero.
    /// <c>BigInteger.ToString(16)</c> emits minimal hex, so a serial beginning <c>0x0A…</c> is
    /// stored as <c>"A1B2…"</c>; .NET's <c>X509Certificate2.SerialNumber</c> renders the DER
    /// integer octets at fixed width and yields <c>"0A1B2…"</c>. Comparing the two directly is a
    /// silent miss on roughly one serial in sixteen — and where the comparison is a revocation
    /// check, a miss means the check passes. EST re-enrollment did exactly that, so a revoked
    /// client certificate could renew itself.
    /// </para>
    /// <para>
    /// Separators (colons, dashes, spaces) that some tools emit are stripped too, so an
    /// operator-pasted serial resolves the same way.
    /// </para>
    /// </summary>
    public static string NormalizeSerialForLookup(string? serial)
    {
        if (string.IsNullOrWhiteSpace(serial))
            return string.Empty;

        var cleaned = serial.Replace(":", "").Replace("-", "").Replace(" ", "").ToUpperInvariant();
        var trimmed = cleaned.TrimStart('0');

        // An all-zero serial trims to nothing; BigInteger renders zero as "0", so match that
        // rather than returning an empty string that would match every row or none.
        return trimmed.Length > 0 ? trimmed : "0";
    }

    /// <summary>
    /// Parses all common X.509v3 extensions from a PEM-encoded certificate and returns
    /// a structured model containing Basic Constraints, Key Usage, Extended Key Usage,
    /// SANs, AIA (OCSP + CA Issuer URLs), CDP, SKI, AKI, and Certificate Policies.
    /// </summary>
    public static CertificateExtensionsModel ParseCertificateExtensions(string pem)
    {
        var cert = ParseFromPem(pem);
        return ParseCertificateExtensions(cert);
    }

    /// <summary>
    /// Parses all common X.509v3 extensions from a BouncyCastle X509Certificate and returns
    /// a structured model containing Basic Constraints, Key Usage, Extended Key Usage,
    /// SANs, AIA (OCSP + CA Issuer URLs), CDP, SKI, AKI, and Certificate Policies.
    /// </summary>
    public static CertificateExtensionsModel ParseCertificateExtensions(X509Certificate cert)
    {
        var result = new CertificateExtensionsModel();

        // Basic Constraints
        var bcExt = cert.GetExtensionValue(X509Extensions.BasicConstraints);
        if (bcExt != null)
        {
            var constraints = BasicConstraints.GetInstance(X509ExtensionUtilities.FromExtensionValue(bcExt));
            result.BasicConstraints = new BasicConstraintsInfo
            {
                IsCA = constraints.IsCA(),
                PathLength = constraints.PathLenConstraint?.IntValueExact
            };
        }

        // Key Usage
        var kuExt = cert.GetExtensionValue(X509Extensions.KeyUsage);
        if (kuExt != null)
        {
            var keyUsage = KeyUsage.GetInstance(X509ExtensionUtilities.FromExtensionValue(kuExt));
            var usages = new[]
            {
                (KeyUsage.DigitalSignature, "DigitalSignature"),
                (KeyUsage.NonRepudiation, "NonRepudiation"),
                (KeyUsage.KeyEncipherment, "KeyEncipherment"),
                (KeyUsage.DataEncipherment, "DataEncipherment"),
                (KeyUsage.KeyAgreement, "KeyAgreement"),
                (KeyUsage.KeyCertSign, "KeyCertSign"),
                (KeyUsage.CrlSign, "CrlSign"),
                (KeyUsage.EncipherOnly, "EncipherOnly"),
                (KeyUsage.DecipherOnly, "DecipherOnly"),
            };
            foreach (var (flag, name) in usages)
                if ((keyUsage.IntValue & flag) != 0)
                    result.KeyUsage.Add(name);
        }

        // Extended Key Usage
        var ekuExt = cert.GetExtensionValue(X509Extensions.ExtendedKeyUsage);
        if (ekuExt != null)
        {
            var eku = ExtendedKeyUsage.GetInstance(X509ExtensionUtilities.FromExtensionValue(ekuExt));
            foreach (DerObjectIdentifier oid in eku.GetAllUsages())
                result.ExtendedKeyUsage.Add(MapEkuOidToName(oid.Id));
        }

        // Subject Alternative Names
        var sanExt = cert.GetExtensionValue(X509Extensions.SubjectAlternativeName);
        if (sanExt != null)
        {
            var san = Asn1Sequence.GetInstance(X509ExtensionUtilities.FromExtensionValue(sanExt));
            foreach (Asn1Encodable entry in san)
            {
                var gn = GeneralName.GetInstance(entry);
                var val = gn.TagNo == GeneralName.IPAddress && gn.Name is DerOctetString ipOct
                    ? new IPAddress(ipOct.GetOctets()).ToString()
                    : gn.Name.ToString() ?? "";
                result.SubjectAlternativeNames.Add($"{GeneralNameTypeName(gn.TagNo)}:{val}");
            }
        }

        // Authority Information Access
        var aiaExt = cert.GetExtensionValue(X509Extensions.AuthorityInfoAccess);
        if (aiaExt != null)
        {
            var aia = AuthorityInformationAccess.GetInstance(X509ExtensionUtilities.FromExtensionValue(aiaExt));
            var aiaInfo = new AuthorityInfoAccessInfo();
            foreach (var desc in aia.GetAccessDescriptions())
            {
                var location = desc.AccessLocation;
                if (location.TagNo != GeneralName.UniformResourceIdentifier)
                    continue;
                var url = location.Name.ToString() ?? "";
                if (desc.AccessMethod.Equals(AccessDescription.IdADOcsp))
                    aiaInfo.OcspUrls.Add(url);
                else if (desc.AccessMethod.Equals(AccessDescription.IdADCAIssuers))
                    aiaInfo.CaIssuerUrls.Add(url);
            }
            if (aiaInfo.OcspUrls.Count > 0 || aiaInfo.CaIssuerUrls.Count > 0)
                result.AuthorityInformationAccess = aiaInfo;
        }

        // CRL Distribution Points
        var cdpExt = cert.GetExtensionValue(X509Extensions.CrlDistributionPoints);
        if (cdpExt != null)
        {
            var cdp = CrlDistPoint.GetInstance(X509ExtensionUtilities.FromExtensionValue(cdpExt));
            foreach (var dp in cdp.GetDistributionPoints())
            {
                var dpName = dp.DistributionPointName;
                if (dpName?.Type == DistributionPointName.FullName)
                {
                    var names = GeneralNames.GetInstance(dpName.Name);
                    foreach (var gn in names.GetNames())
                    {
                        if (gn.TagNo == GeneralName.UniformResourceIdentifier)
                            result.CrlDistributionPoints.Add(gn.Name.ToString() ?? "");
                    }
                }
            }
        }

        // Subject Key Identifier
        var skiExt = cert.GetExtensionValue(X509Extensions.SubjectKeyIdentifier);
        if (skiExt != null)
        {
            var ski = SubjectKeyIdentifier.GetInstance(X509ExtensionUtilities.FromExtensionValue(skiExt));
            result.SubjectKeyIdentifier = FormatHexBytes(ski.GetKeyIdentifier());
        }

        // Authority Key Identifier
        var akiExt = cert.GetExtensionValue(X509Extensions.AuthorityKeyIdentifier);
        if (akiExt != null)
        {
            var aki = AuthorityKeyIdentifier.GetInstance(X509ExtensionUtilities.FromExtensionValue(akiExt));
            var keyId = aki.GetKeyIdentifier();
            if (keyId != null)
                result.AuthorityKeyIdentifier = FormatHexBytes(keyId);
        }

        // Certificate Policies
        var cpExt = cert.GetExtensionValue(X509Extensions.CertificatePolicies);
        if (cpExt != null)
        {
            var policies = Asn1Sequence.GetInstance(X509ExtensionUtilities.FromExtensionValue(cpExt));
            foreach (Asn1Encodable policyEntry in policies)
            {
                var policyInfo = PolicyInformation.GetInstance(policyEntry);
                result.CertificatePolicies.Add(policyInfo.PolicyIdentifier.Id);
            }
        }

        return result;
    }

    /// <summary>
    /// Maps well-known Extended Key Usage OIDs to human-readable names.
    /// Falls back to the raw OID string for unrecognized values.
    /// </summary>
    private static string MapEkuOidToName(string oid)
    {
        return oid switch
        {
            "1.3.6.1.5.5.7.3.1" => "ServerAuth",
            "1.3.6.1.5.5.7.3.2" => "ClientAuth",
            "1.3.6.1.5.5.7.3.3" => "CodeSigning",
            "1.3.6.1.5.5.7.3.4" => "EmailProtection",
            "1.3.6.1.5.5.7.3.8" => "TimeStamping",
            "1.3.6.1.5.5.7.3.9" => "OCSPSigning",
            "1.3.6.1.4.1.311.10.3.12" => "DocumentSigning",
            "1.3.6.1.5.5.7.3.17" => "CMSContentProtection",
            "2.16.840.1.113730.4.1" => "NetscapeServerGatedCrypto",
            _ => oid
        };
    }

    /// <summary>
    /// Formats a byte array as a colon-separated uppercase hex string (e.g. "AB:CD:EF").
    /// </summary>
    private static string FormatHexBytes(byte[] bytes)
    {
        return BitConverter.ToString(bytes).Replace("-", ":").ToUpperInvariant();
    }
}

