using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Core.Implementations;
using ModularCA.Keystore.Crypto;
using ModularCA.Keystore.Services;
using ModularCA.Keystore.Utils;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Models;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using System.Security.Cryptography;
using System.Text.Json;
using ModularCA.Auth.Utils;

namespace ModularCA.Bootstrap;

/// <summary>
/// Creates certificate requests, self-signed certificates, CA entities, CRL schedules,
/// TSA certificates, and Web TLS certificates during the bootstrap process.
/// </summary>
public static class BootstrapCertCreator
{
    /// <summary>
    /// Builds a <see cref="CertificateRequestModel"/> for a CA certificate with the given subject fields,
    /// algorithm, key size, validity window, and key-usage OIDs.
    /// </summary>
    public static CertificateRequestModel CreateCertificateRequest(string commonName, string organization, string organizationalUnit,
        string locality, string state, string country, string keyAlgorithm, int keySize, DateTime notBefore,
        DateTime notAfter, Guid signingProfileId, string[] standardKeyUsage, string[] extendedKeyUsage, ModularCADbContext db)
    {
        var standardKeyUsages = BootstrapProfileSeeder.SetupAllowedStandardOids(standardKeyUsage, db);
        var extendedKeyUsages = BootstrapProfileSeeder.SetupAllowedExtendedOids(extendedKeyUsage, db);

        var certRequestModel = new CertificateRequestModel
        {
            CommonName = commonName,
            Organization = organization,
            OrganizationalUnit = organizationalUnit,
            Locality = locality,
            State = state,
            Country = country,
            KeyAlgorithm = keyAlgorithm,
            KeySize = keySize,
            NotBefore = notBefore,
            NotAfter = notAfter,
            SigningProfileId = signingProfileId,
            IsCA = true,
            KeyUsages = standardKeyUsages,
            ExtendedKeyUsages = extendedKeyUsages
        };

        Console.WriteLine($"✓ Certificate request '{certRequestModel.CommonName}' created and ready for self-signing.");
        return certRequestModel;
    }

    /// <summary>
    /// Generates a self-signed certificate from the given request model using BouncyCastle.
    /// Returns the signed certificate, private key, and DER-encoded private key bytes.
    /// </summary>
    public static (Org.BouncyCastle.X509.X509Certificate caCert, AsymmetricKeyParameter privKey, byte[] privKeyDer) CreateSelfSignedCertificate(CertificateRequestModel certRequest)
    {
        var (certBytes, privKey) = BouncyCastleCertificateAuthority.CreateSelfSignedCACertificate(certRequest);
        var caCert = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(certBytes);
        var privateKeyDer = PrivateKeyInfoFactory
            .CreatePrivateKeyInfo(privKey)
            .ToAsn1Object()
            .GetDerEncoded();
        Console.WriteLine($"✓ Self-signed certificate '{caCert.SubjectDN}' created.");
        return (caCert, privKey, privateKeyDer);
    }

    /// <summary>
    /// Computes SHA-1 and SHA-256 thumbprints for the given certificate
    /// and returns them as a JSON-serialized dictionary.
    /// </summary>
    public static string GetCertThumbprints(Org.BouncyCastle.X509.X509Certificate cert)
    {
        byte[] sha1hash = SHA1.HashData(cert.GetEncoded());
        string sha1thumbprint = BitConverter.ToString(sha1hash).Replace("-", "").ToUpperInvariant();
        Console.WriteLine("SHA 1 Thumbprint: " + sha1thumbprint);
        byte[] sha256hash = SHA256.HashData(cert.GetEncoded());
        string sha256thumbprint = BitConverter.ToString(sha256hash).Replace("-", "").ToUpperInvariant();
        Console.WriteLine("SHA 256 Thumbprint: " + sha256thumbprint);
        var thumbprintDict = new Dictionary<string, string>
        {
            { "SHA 1", sha1thumbprint },
            { "SHA 256", sha256thumbprint }
        };
        return JsonSerializer.Serialize(thumbprintDict);
    }

    /// <summary>
    /// Stores a signed certificate (with its encrypted private key) in the database.
    /// The private key is AES-encrypted and the AES key is wrapped using the certificate's public key.
    /// For non-RSA keys, the wrap key is derived via HKDF-SHA256(ikm: passphrase, salt: random, info: publicKeyDER).
    /// </summary>
    public static CertificateEntity CreateCertificateEntry(ModularCADbContext db, string certPem, Org.BouncyCastle.X509.X509Certificate caCert, byte[] privateKeyDer, string standardOidsJson, string extendedOidsJson, CertProfileEntity certProfile, SigningProfileEntity signingProfile, byte[]? passphrase = null, Guid? issuerCertificateId = null)
    {

        var thumbprints = GetCertThumbprints(caCert);
        string publicKeyPem = certPem;

        var random = new SecureRandom();
        var aesKey = new byte[32];
        var iv = new byte[16];
        random.NextBytes(aesKey);
        random.NextBytes(iv);

        var cipher = CipherUtilities.GetCipher("AES/CBC/PKCS7Padding");
        cipher.Init(true, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("AES", aesKey), iv));
        var encryptedPrivateKey = cipher.DoFinal(privateKeyDer);

        var publicKey = caCert.GetPublicKey();
        byte[] encryptedAesKey;
        if (publicKey is RsaKeyParameters rsaPubKey)
        {
            // Wrap with RSA-OAEP-SHA256/MGF1-SHA256 to match KeyEncryptionUtil and avoid
            // the deprecated SHA-1 defaults baked into OaepEncoding(RsaEngine).
            var engine = new OaepEncoding(new RsaEngine(), new Org.BouncyCastle.Crypto.Digests.Sha256Digest(), new Org.BouncyCastle.Crypto.Digests.Sha256Digest(), null);
            engine.Init(true, rsaPubKey);
            encryptedAesKey = engine.ProcessBlock(aesKey, 0, aesKey.Length);
        }
        else
        {
            if (passphrase == null || passphrase.Length == 0)
                throw new ArgumentException("Passphrase is required for non-RSA key wrapping during bootstrap.", nameof(passphrase));

            var pubKeyDer = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey).GetDerEncoded();

            // Derive wrap key via HKDF-SHA256 with random salt and public key DER as info
            var hkdfSalt = new byte[32];
            RandomNumberGenerator.Fill(hkdfSalt);

            var wrapKey = System.Security.Cryptography.HKDF.DeriveKey(
                System.Security.Cryptography.HashAlgorithmName.SHA256,
                passphrase,
                32,
                hkdfSalt,
                pubKeyDer);

            var (wNonce, wCiphertext, wTag) = AesGcmEncryptor.Encrypt(aesKey, wrapKey);
            // Format: [32-byte HKDF salt][12-byte nonce][ciphertext][16-byte tag]
            encryptedAesKey = hkdfSalt.Concat(wNonce).Concat(wCiphertext).Concat(wTag).ToArray();
        }

        var emptyJson = new List<string>();

        var certEntity = new CertificateEntity
        {
            Pem = publicKeyPem,
            NotBefore = caCert.NotBefore,
            NotAfter = caCert.NotAfter,


            Issuer = caCert.IssuerDN.ToString(),
            SubjectDN = caCert.SubjectDN.ToString(),
            SerialNumber = CertificateUtil.FormatSerialNumber(caCert.SerialNumber),
            Thumbprints = thumbprints,
            KeyUsagesJson = standardOidsJson,
            EncryptedPrivateKey = encryptedPrivateKey,
            AesKeyEncryptionIv = iv,
            EncryptedAesForPrivateKey = encryptedAesKey,
            ExtendedKeyUsagesJson = extendedOidsJson,
            SubjectAlternativeNamesJson = JsonSerializer.Serialize(emptyJson),
            CertProfileId = certProfile.Id,
            CertProfile = certProfile,
            SigningProfileId = signingProfile.Id,
            SigningProfile = signingProfile,
            RawCertificate = caCert.GetEncoded(),

            IsCA = true
        };

        db.Certificates.Add(certEntity);
        db.SaveChanges();

        // Populate the IssuerCertificateId FK. For self-signed
        // roots (where the caller passes no issuer), point at the row we just saved.
        // For child rows (e.g. the system signing CA issued by the root), the caller
        // provides the parent's CertificateId.
        certEntity.IssuerCertificateId = issuerCertificateId ?? certEntity.CertificateId;
        db.SaveChanges();

        return certEntity;
    }

    /// <summary>
    /// Retrieves a certificate entity from the database by its subject distinguished name.
    /// Throws if not found.
    /// </summary>
    public static CertificateEntity GetCertificateFromDb(ModularCADbContext db, string certName)
    {
        var cert = db.Certificates
            .FirstOrDefault(c => c.SubjectDN == certName);
        return cert ?? throw new InvalidOperationException($"Certificate '{certName}' not found.");
    }

    /// <summary>
    /// Retrieves a certificate authority entity from the database by the linked certificate ID.
    /// Throws if not found.
    /// </summary>
    public static CertificateAuthorityEntity GetCertificateAuthorityFromDb(ModularCADbContext db, Guid certificateId)
    {
        var ca = db.CertificateAuthorities
            .FirstOrDefault(c => c.CertificateId == certificateId);
        return ca ?? throw new InvalidOperationException($"Certificate Authority for certificate '{certificateId}' not found.");
    }

    /// <summary>
    /// Creates a certificate authority entity in the database, linked to the given certificate.
    /// Supports root, intermediate, and issuing CA types. A null <paramref name="spaceId"/>
    /// creates an instance CA, such as the system signing CA. A label (ignoring case) or name that
    /// another CA of the instance already has throws
    /// <see cref="ModularCA.Shared.Errors.ConfigurationValidationException"/> naming both, rather
    /// than failing on the unique index, as does a label derived from the CA's name that
    /// <see cref="EnsureRootLabelUsable"/> refuses. An explicit <paramref name="label"/> may be reserved.
    /// A CA created as the default clears the default on every other CA.
    /// </summary>
    public static void CreateCertificateAuthority(ModularCADbContext db, CertificateEntity caCertificateEntity,
        string type = "Root", bool isDefault = false, string? label = null, Guid? parentCaId = null, Guid? spaceId = null)
    {
        var caName = CertificateUtil.ParseCnFromPem(caCertificateEntity.Pem);
        var caType = type;
        if (label == null)
            EnsureRootLabelUsable(caName);
        var caLabel = label ?? LabelFor(caName);
        var lowered = caLabel.ToLowerInvariant();
        var clash = db.CertificateAuthorities.IgnoreQueryFilters()
            .Where(c => (c.Label != null && c.Label.ToLower() == lowered) || c.Name == caName)
            .Select(c => new { c.Name, c.Label })
            .FirstOrDefault();
        if (clash != null)
            throw new ModularCA.Shared.Errors.ConfigurationValidationException(
                $"Bootstrap cannot create CA '{caName}' (label '{caLabel}'): CA '{clash.Name}' (label '{clash.Label}') already has that "
                + "name or label, and both are unique across the instance. Choose another root CA common name.");

        var caEntity = new CertificateAuthorityEntity
        {
            Name = caName,
            Certificate = caCertificateEntity,
            CertificateId = caCertificateEntity.CertificateId,
            Type = caType,
            IsEnabled = true,
            IsDefault = isDefault,
            Label = caLabel,
            ParentCaId = parentCaId,
            SpaceId = spaceId,
        };
        if (isDefault)
            foreach (var other in db.CertificateAuthorities.Where(c => c.IsDefault).ToList())
                other.IsDefault = false;
        db.CertificateAuthorities.Add(caEntity);
        db.SaveChanges();
        Console.WriteLine($"✓ Certificate Authority '{caEntity.Name}' added (Type={caType}, Label={caEntity.Label}, IsDefault={caEntity.IsDefault}).");
    }

    /// <summary>
    /// The system signing CA's common name, which is also its CA name.
    /// </summary>
    public const string SystemSigningCaName = "ModularCA System Signing CA";

    /// <summary>The system signing CA's label.</summary>
    public const string SystemSigningCaLabel = "system-signing-ca";

    /// <summary>
    /// Throws <see cref="ModularCA.Shared.Errors.ConfigurationValidationException"/> when the root CA
    /// common name <paramref name="commonName"/> would give an invalid label, or one with a reserved
    /// prefix (system- / space- / org-), under <see cref="ModularCA.Core.Services.CaLabelRules"/>. Called
    /// before any setup work so the operator can pick another name while nothing is built yet.
    /// </summary>
    public static void EnsureRootLabelUsable(string commonName)
    {
        var label = LabelFor(commonName.Trim());
        try
        {
            ModularCA.Core.Services.CaLabelRules.Validate(label, allowReserved: false);
        }
        catch (ArgumentException ex)
        {
            throw new ModularCA.Shared.Errors.ConfigurationValidationException(
                $"The root CA common name '{commonName}' gives the CA label '{label}', which cannot be used: {ex.Message} "
                + "The label is the path of the CA's CRL, OCSP and AIA URLs; choose another common name.");
        }
    }

    /// <summary>
    /// Throws <see cref="ModularCA.Shared.Errors.InvalidRequestException"/> when an entry of the
    /// setup Web TLS certificate's <paramref name="sans"/> is not <c>DNS:name</c> or
    /// <c>IP:address</c>. The certificate is issued on first start from these entries, by a CSR
    /// builder that encodes only those two types and skipped any other, so an Email, URI or
    /// untyped entry used to vanish from the certificate. Blank entries carry no name and are
    /// ignored. Called before any setup work, on the wizard and the CLI path.
    /// </summary>
    public static void EnsureWebTlsSansSupported(IEnumerable<string>? sans)
    {
        foreach (var raw in sans ?? [])
        {
            if (string.IsNullOrWhiteSpace(raw))
                continue;
            var entry = raw.Trim();
            var colon = entry.IndexOf(':');
            var type = colon > 0 ? entry[..colon].Trim().ToUpperInvariant() : null;
            var value = colon > 0 ? entry[(colon + 1)..].Trim() : string.Empty;
            string? problem = type switch
            {
                null => "has no type; write it as DNS:name or IP:address",
                "DNS" or "IP" when value.Length == 0 => "has no value",
                "IP" when !System.Net.IPAddress.TryParse(value, out _) => $"'{value}' is not an IP address",
                "DNS" or "IP" => null,
                _ => $"has type '{type}', which the Web TLS certificate cannot carry; only DNS and IP names are supported",
            };
            if (problem != null)
                throw new ModularCA.Shared.Errors.InvalidRequestException(
                    $"Web TLS certificate SAN '{entry}' {problem}.", ModularCA.Shared.Errors.ErrorCodes.RequestInvalid);
        }
    }

    /// <summary>
    /// Converts a CA name into a URL-safe label (lowercase, hyphens, no special chars), as
    /// bootstrap labels the root CA.
    /// </summary>
    public static string LabelFor(string name) =>
        new string(name.ToLowerInvariant()
            .Replace(' ', '-')
            .Where(c => char.IsLetterOrDigit(c) || c == '-')
            .ToArray())
        .Trim('-');

    /// <summary>
    /// Creates a CRL schedule entity for the given CA certificate with default settings
    /// (30-minute interval, 1-hour overlap, non-delta).
    /// </summary>
    public static void CreateCrlSchedule(ModularCADbContext db, CertificateEntity caCertificate)
    {
        var caName = CertificateUtil.ParseCnFromPem(caCertificate.Pem);
        var crlSchedule = new CrlConfigurationEntity
        {
            Name = $"CRL Schedule - {caName}",
            Description = $"Default CRL schedule for {caName}",
            IssuerDN = caCertificate.SubjectDN,
            UpdateInterval = "*/30 * * * *",
            OverlapPeriod = TimeSpan.FromHours(1),
            IsDelta = false,
            LastGenerated = DateTime.UtcNow,
            CaCertificate = caCertificate,
            CaCertificateId = caCertificate.CertificateId,

        };
        db.CrlConfigurations.Add(crlSchedule);
        db.SaveChanges();
        Console.WriteLine($"✓ CRL schedule '{crlSchedule.Name}' added to database.");
    }

    /// <summary>
    /// Signs a TSA certificate with the CA key. Called early in bootstrap so the cert
    /// and key can be added to the keystore files before they are written.
    /// Caps <c>notAfter</c> at the parent CA's <c>notAfter</c> so the TSA leaf
    /// never outlives its issuer. Extracts the parent CN via the OID list
    /// rather than string-parsing SubjectDN.ToString().
    /// </summary>
    public static Org.BouncyCastle.X509.X509Certificate SignTsaCertificate(
        AsymmetricCipherKeyPair tsaKeyPair,
        Org.BouncyCastle.X509.X509Certificate caCert,
        AsymmetricKeyParameter caPrivKey)
    {
        // Generate 128-bit random serial number (CA/BF BR §7.1 requires ≥64 bits from CSPRNG)
        var serialBytes = new byte[16];
        RandomNumberGenerator.Fill(serialBytes);
        serialBytes[0] &= 0x7F; // Ensure positive (MSB = 0)
        var serial = new BigInteger(1, serialBytes);

        // Extract CN from the OID list rather than string-parsing ToString().
        var parentCn = "TSA";
        var parentOids = caCert.SubjectDN.GetOidList();
        var parentValues = caCert.SubjectDN.GetValueList();
        for (int i = 0; i < parentOids.Count; i++)
        {
            if (parentOids[i] is Org.BouncyCastle.Asn1.DerObjectIdentifier oid && oid.Equals(X509Name.CN))
            {
                parentCn = parentValues[i]?.ToString() ?? "TSA";
                break;
            }
        }
        var subjectDN = new X509Name($"CN={parentCn} TSA");

        // Cap TSA validity at the parent CA's notAfter.
        var notBefore = CertificateValidityUtil.DefaultNotBefore();
        var requested = notBefore.AddYears(10);
        var notAfter = requested > caCert.NotAfter ? caCert.NotAfter : requested;
        if (notAfter <= notBefore) notAfter = caCert.NotAfter;

        var certGen = new X509V3CertificateGenerator();
        certGen.SetSerialNumber(serial);
        certGen.SetIssuerDN(caCert.SubjectDN);
        certGen.SetSubjectDN(subjectDN);
        certGen.SetNotBefore(notBefore);
        certGen.SetNotAfter(notAfter);
        certGen.SetPublicKey(tsaKeyPair.Public);

        certGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));

        var leafPubKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(tsaKeyPair.Public);
        certGen.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
            X509ExtensionUtilities.CreateSubjectKeyIdentifier(leafPubKeyInfo));

        var caPubKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(caCert.GetPublicKey());
        certGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(caPubKeyInfo));

        certGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature));

        // Extended Key Usage: id-kp-timeStamping — MUST be critical per RFC 3161 §2.3
        certGen.AddExtension(X509Extensions.ExtendedKeyUsage, true,
            new ExtendedKeyUsage(new[] { KeyPurposeID.id_kp_timeStamping }));

        var sigAlg = CertificateUtil.NormalizeSigAlgName(KeyAlgorithmPolicy.ResolveSignatureAlgorithmForKey(caPrivKey));
        var signer = new Asn1SignatureFactory(sigAlg, caPrivKey, new SecureRandom());
        return certGen.Generate(signer);
    }

    /// <summary>
    /// Stores the pre-signed TSA certificate in the database and links it to the CA entity
    /// via <see cref="CertificateAuthorityEntity.TsaCertificateId"/>.
    /// </summary>
    public static void StoreTsaCertificate(
        Org.BouncyCastle.X509.X509Certificate tsaCert,
        AsymmetricCipherKeyPair tsaKeyPair,
        ModularCADbContext db,
        SigningProfileEntity signingProfile,
        CertProfileEntity certProfile,
        CertificateAuthorityEntity caEntity)
    {
        var certEntity = StoreInfrastructureCertificate(tsaCert, tsaKeyPair, db, signingProfile,
            "TSA Certificate Profile", caEntity, "1.3.6.1.5.5.7.3.8", "TSA");

        caEntity.TsaCertificateId = certEntity.CertificateId;
        db.SaveChanges();

        Console.WriteLine($"✓ TSA signer certificate issued (CN={tsaCert.SubjectDN}, SN={certEntity.SerialNumber})");
    }

    /// <summary>
    /// Signs a delegated OCSP responder certificate using the given CA key pair.
    /// The cert has id-kp-OCSPSigning EKU, id-pkix-ocsp-nocheck extension, and validity
    /// capped at the parent CA's notAfter (same pattern as TSA certs).
    /// </summary>
    public static Org.BouncyCastle.X509.X509Certificate SignOcspResponderCertificate(
        AsymmetricCipherKeyPair ocspKeyPair,
        Org.BouncyCastle.X509.X509Certificate caCert,
        AsymmetricKeyParameter caPrivKey)
    {
        var serialBytes = new byte[16];
        RandomNumberGenerator.Fill(serialBytes);
        serialBytes[0] &= 0x7F;
        var serial = new BigInteger(1, serialBytes);

        var parentCn = "OCSP Responder";
        var parentOids = caCert.SubjectDN.GetOidList();
        var parentValues = caCert.SubjectDN.GetValueList();
        for (int i = 0; i < parentOids.Count; i++)
        {
            if (parentOids[i] is Org.BouncyCastle.Asn1.DerObjectIdentifier oid && oid.Equals(X509Name.CN))
            {
                parentCn = parentValues[i]?.ToString() ?? "OCSP Responder";
                break;
            }
        }
        var subjectDN = new X509Name($"CN={parentCn} OCSP Responder");

        var notBefore = CertificateValidityUtil.DefaultNotBefore();
        var requested = notBefore.AddYears(10);
        var notAfter = requested > caCert.NotAfter ? caCert.NotAfter : requested;
        if (notAfter <= notBefore) notAfter = caCert.NotAfter;

        var certGen = new X509V3CertificateGenerator();
        certGen.SetSerialNumber(serial);
        certGen.SetIssuerDN(caCert.SubjectDN);
        certGen.SetSubjectDN(subjectDN);
        certGen.SetNotBefore(notBefore);
        certGen.SetNotAfter(notAfter);
        certGen.SetPublicKey(ocspKeyPair.Public);

        certGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));

        var leafPubKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(ocspKeyPair.Public);
        certGen.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
            X509ExtensionUtilities.CreateSubjectKeyIdentifier(leafPubKeyInfo));

        var caPubKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(caCert.GetPublicKey());
        certGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(caPubKeyInfo));

        certGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature));

        // ExtendedKeyUsage: id-kp-OCSPSigning (RFC 6960 §4.2.2.2)
        certGen.AddExtension(X509Extensions.ExtendedKeyUsage, false,
            new ExtendedKeyUsage(new[] { KeyPurposeID.id_kp_OCSPSigning }));

        // id-pkix-ocsp-nocheck (RFC 6960 §4.2.2.2.1)
        certGen.AddExtension(
            new Org.BouncyCastle.Asn1.DerObjectIdentifier("1.3.6.1.5.5.7.48.1.5"),
            false,
            Org.BouncyCastle.Asn1.DerNull.Instance);

        var sigAlg = CertificateUtil.NormalizeSigAlgName(KeyAlgorithmPolicy.ResolveSignatureAlgorithmForKey(caPrivKey));
        var signer = new Asn1SignatureFactory(sigAlg, caPrivKey, new SecureRandom());
        return certGen.Generate(signer);
    }

    /// <summary>
    /// Stores the pre-signed OCSP responder certificate in the database and links it to the CA
    /// entity via <see cref="CertificateAuthorityEntity.OcspResponderCertificateId"/>.
    /// </summary>
    public static void StoreOcspResponderCertificate(
        Org.BouncyCastle.X509.X509Certificate ocspCert,
        AsymmetricCipherKeyPair ocspKeyPair,
        ModularCADbContext db,
        SigningProfileEntity signingProfile,
        CertProfileEntity certProfile,
        CertificateAuthorityEntity caEntity)
    {
        var certEntity = StoreInfrastructureCertificate(ocspCert, ocspKeyPair, db, signingProfile,
            "OCSP Responder Certificate Profile", caEntity, "1.3.6.1.5.5.7.3.9", "OCSP Responder");

        caEntity.OcspResponderCertificateId = certEntity.CertificateId;
        db.SaveChanges();

        Console.WriteLine($"✓ OCSP responder certificate issued (CN={ocspCert.SubjectDN}, SN={certEntity.SerialNumber})");
    }

    /// <summary>
    /// Shared helper for storing an infrastructure certificate (TSA or OCSP) in the database.
    /// Creates the CertificateEntity, a CertRequestEntity for audit trail with IsInfrastructureCert=true,
    /// and links them together.
    /// </summary>
    private static CertificateEntity StoreInfrastructureCertificate(
        Org.BouncyCastle.X509.X509Certificate cert,
        AsymmetricCipherKeyPair keyPair,
        ModularCADbContext db,
        SigningProfileEntity signingProfile,
        string infraCertProfileName,
        CertificateAuthorityEntity caEntity,
        string ekuOid,
        string certType)
    {
        byte[] sha1hash = SHA1.HashData(cert.GetEncoded());
        byte[] sha256hash = SHA256.HashData(cert.GetEncoded());
        var thumbprints = JsonSerializer.Serialize(new Dictionary<string, string>
        {
            { "SHA 1", BitConverter.ToString(sha1hash).Replace("-", "").ToUpperInvariant() },
            { "SHA 256", BitConverter.ToString(sha256hash).Replace("-", "").ToUpperInvariant() }
        });

        // Look up the infrastructure cert profile (seeded by SeedInfrastructureCertProfiles)
        var infraProfile = db.CertProfiles.FirstOrDefault(cp => cp.Name == infraCertProfileName);

        var certPem = CertificateUtil.ExportCertificateToPem(cert);
        var certEntity = new CertificateEntity
        {
            SerialNumber = CertificateUtil.FormatSerialNumber(cert.SerialNumber),
            SubjectDN = cert.SubjectDN.ToString(),
            Pem = certPem,
            Issuer = cert.IssuerDN.ToString(),
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter,
            Thumbprints = thumbprints,
            IsCA = false,
            Revoked = false,
            RevocationReason = string.Empty,
            CertProfileId = infraProfile?.Id,
            SigningProfileId = signingProfile.Id,
            SubjectAlternativeNamesJson = "[]",
            KeyUsagesJson = JsonSerializer.Serialize(new[] { "Digital Signature" }),
            ExtendedKeyUsagesJson = JsonSerializer.Serialize(new[] { ekuOid }),
            RawCertificate = cert.GetEncoded(),
            IssuerCertificateId = caEntity.CertificateId,
        };
        db.Certificates.Add(certEntity);
        db.SaveChanges();

        // Build a PKCS#10 CSR for the audit trail
        var sigAlgName = KeyAlgorithmPolicy.ResolveSignatureAlgorithmForKey(keyPair.Private);
        var csr = new Pkcs10CertificationRequest(
            sigAlgName, cert.SubjectDN, keyPair.Public, null, keyPair.Private);
        string csrPem;
        using (var sw = new StringWriter())
        {
            var pemWriter = new Org.BouncyCastle.OpenSsl.PemWriter(sw);
            pemWriter.WriteObject(csr);
            csrPem = sw.ToString();
        }

        var keySizeStr = KeyAlgorithmPolicy.FormatKeySizeForProfile(
            KeyAlgorithmPolicy.DetectKeyAlgorithm(keyPair.Public),
            KeyAlgorithmPolicy.DetectKeySize(keyPair.Public));

        var csrEntity = new CertRequestEntity
        {
            Subject = cert.SubjectDN.ToString(),
            SubjectAlternativeNames = "[]",
            CSR = csrPem,
            KeyAlgorithm = KeyAlgorithmPolicy.DetectKeyAlgorithm(keyPair.Public),
            KeySize = keySizeStr,
            SignatureAlgorithm = sigAlgName,
            SubmittedAt = DateTime.UtcNow,
            Status = "Issued",
            IsInfrastructureCert = true,
            CertProfileId = infraProfile?.Id,
            SigningProfileId = signingProfile.Id,
            IssuedCertificateId = certEntity.CertificateId,
        };
        db.CertificateRequests.Add(csrEntity);
        db.SaveChanges();

        return certEntity;
    }

    // NOTE: CreateWebTlsCertificate has been removed. Web TLS certificates are now issued
    // through the standard CSR pipeline by WebTlsProvisioningService (Stage 2 bootstrap)
    // on first runtime start after setup.
}
