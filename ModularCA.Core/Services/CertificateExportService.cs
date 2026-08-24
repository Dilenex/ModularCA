using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using ModularCA.Core.Helpers;

namespace ModularCA.Core.Services;

/// <summary>
/// Exports certificates in various formats (PFX, PEM) with optional private key and chain inclusion.
/// </summary>
public interface ICertificateExportService
{
    Task<byte[]?> ExportPfxAsync(string serial, string password, bool includeChain = true);
    Task<string?> ExportPemWithKeyAsync(string serial);
}

public class CertificateExportService : ICertificateExportService
{
    private readonly ModularCADbContext _db;
    private readonly IKeystoreCertificates _keystore;
    private readonly IKeyWrappingPassphraseProvider _passphraseProvider;

    /// <summary>
    /// Initializes a new instance of <see cref="CertificateExportService"/>.
    /// </summary>
    public CertificateExportService(ModularCADbContext db, IKeystoreCertificates keystore, IKeyWrappingPassphraseProvider passphraseProvider)
    {
        _db = db;
        _keystore = keystore;
        _passphraseProvider = passphraseProvider;
    }

    public async Task<byte[]?> ExportPfxAsync(string serial, string password, bool includeChain = true)
    {
        var certEntity = await _db.Certificates
            .Include(c => c.SigningProfile)
            .ResolveBySerialOrNullAsync(serial);

        if (certEntity == null) return null;

        var cert = CertificateUtil.ParseFromPem(certEntity.Pem);

        // Decrypt private key if available
        AsymmetricKeyParameter? privKey = null;
        if (certEntity.HasExportablePrivateKey())
        {
            privKey = DecryptPrivateKey(certEntity);
        }

        if (privKey == null) return null;

        // Build cert chain — include direct issuer always, exclude root only when intermediates exist
        var certEntries = new List<X509CertificateEntry> { new(cert) };
        if (includeChain && certEntity.SigningProfile?.IssuerId != null)
        {
            var visited = new HashSet<Guid>();
            var issuerId = certEntity.SigningProfile.IssuerId;

            // Determine if the direct issuer is root
            var directIssuerCa = await _db.CertificateAuthorities
                .AsNoTracking()
                .FirstOrDefaultAsync(ca => ca.CertificateId == issuerId);
            var directIssuerIsRoot = directIssuerCa?.ParentCaId == null;

            while (issuerId.HasValue && visited.Add(issuerId.Value))
            {
                var issuerEntity = await _db.Certificates
                    .Include(c => c.SigningProfile)
                    .FirstOrDefaultAsync(c => c.CertificateId == issuerId.Value);
                if (issuerEntity == null) break;

                var issuerCa = await _db.CertificateAuthorities
                    .AsNoTracking()
                    .FirstOrDefaultAsync(ca => ca.CertificateId == issuerId.Value);

                // Skip root when intermediates exist; include when it's the direct issuer
                if (issuerCa?.ParentCaId == null && !directIssuerIsRoot)
                    break;

                certEntries.Add(new X509CertificateEntry(CertificateUtil.ParseFromPem(issuerEntity.Pem)));

                if (issuerCa?.ParentCaId == null)
                    break; // Root was direct issuer and was included; stop

                issuerId = issuerEntity.SigningProfile?.IssuerId;
            }
        }

        var pfxStore = new Pkcs12StoreBuilder().Build();
        pfxStore.SetKeyEntry("certificate",
            new AsymmetricKeyEntry(privKey),
            certEntries.ToArray());

        using var ms = new MemoryStream();
        pfxStore.Save(ms, password.ToCharArray(), new SecureRandom());
        return ms.ToArray();
    }

    public async Task<string?> ExportPemWithKeyAsync(string serial)
    {
        var certEntity = await _db.Certificates
            .ResolveBySerialOrNullAsync(serial);

        if (certEntity?.EncryptedPrivateKey == null || certEntity.AesKeyEncryptionIv == null || certEntity.EncryptedAesForPrivateKey == null)
            return null;

        var privKey = DecryptPrivateKey(certEntity);
        if (privKey == null) return null;

        var keyPem = CertificateUtil.ExportPrivateKeyToPem(privKey);
        return certEntity.Pem + "\n" + keyPem;
    }

    /// <summary>
    /// Decrypts a certificate's private key using the CA certificate that originally encrypted it.
    /// Uses <see cref="CertificateEntity.EncryptionCertSerialNumber"/> for precise lookup;
    /// falls back to a name-based "System" search for certificates issued before this field existed.
    /// </summary>
    private AsymmetricKeyParameter? DecryptPrivateKey(ModularCA.Shared.Entities.CertificateEntity certEntity)
    {
        if (certEntity.EncryptedPrivateKey == null || certEntity.AesKeyEncryptionIv == null || certEntity.EncryptedAesForPrivateKey == null)
            return null;

        X509Certificate? encryptionCa = null;

        // Prefer serial-based lookup when the encryption cert serial is recorded
        if (!string.IsNullOrEmpty(certEntity.EncryptionCertSerialNumber))
        {
            encryptionCa = _keystore.GetTrustedAuthorities()
                .FirstOrDefault(ca => CertificateUtil.FormatSerialNumber(ca.SerialNumber) == certEntity.EncryptionCertSerialNumber);
        }

        // Backward compatibility: fall back to name-based lookup for older certificates
        encryptionCa ??= _keystore.GetTrustedAuthorities()
            .FirstOrDefault(ca => ca.SubjectDN.ToString().Contains("System", StringComparison.OrdinalIgnoreCase));

        if (encryptionCa == null) return null;

        var keyHandle = _keystore.GetPrivateKeyFor(encryptionCa);
        if (keyHandle == null || !keyHandle.CanExport) return null;

        // Zero the DER buffer immediately after PrivateKeyFactory.CreateKey has
        // consumed it. The AsymmetricKeyParameter still holds the scalar via BC internals,
        // but at least the raw DER copy we materialised for the constructor call is gone.
        var encryptorDer = keyHandle.ExportPrivateKeyDer();
        AsymmetricKeyParameter encryptorPrivKey;
        try
        {
            encryptorPrivKey = PrivateKeyFactory.CreateKey(encryptorDer);
        }
        finally
        {
            if (encryptorDer != null)
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(encryptorDer);
        }

        return KeyEncryptionUtil.DecryptPrivateKey(
            certEntity.EncryptedAesForPrivateKey,
            certEntity.AesKeyEncryptionIv,
            certEntity.EncryptedPrivateKey,
            encryptorPrivKey,
            encryptionCa.GetPublicKey(),
            _passphraseProvider.GetPassphrase());
    }
}
