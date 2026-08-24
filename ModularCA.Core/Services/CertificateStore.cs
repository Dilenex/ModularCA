using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Shared.Utils;
using System.Text.Json;
using ModularCA.Core.Helpers;

namespace ModularCA.Core.Services;

/// <summary>
/// Database-backed certificate store for persisting issued certificates and their metadata.
/// </summary>
public class CertificateStore(ModularCADbContext dbContext) : ICertificateStore
{
    private readonly ModularCADbContext _dbContext = dbContext;

    public async Task SaveCertificateAsync(
        byte[] certificateBytes,
        CertificateInfoModel info,
        byte[]? encryptedPrivateKey = null)
    {
        var entity = new CertificateEntity
        {
            SerialNumber = info.SerialNumber,
            SubjectDN = info.SubjectDN,
            Pem = info.Pem,
            Issuer = info.Issuer,
            NotBefore = info.NotBefore,
            NotAfter = info.NotAfter,
            Thumbprints = info.Thumbprints,
            IsCA = info.IsCA,


            Revoked = info.Revoked,
            RevocationReason = info.RevocationReason,
            RevocationDate = info.RevocationDate,
            CertProfileId = info.CertProfileId,
            SigningProfileId = info.SigningProfileId,
            SubjectAlternativeNamesJson = JsonSerializer.Serialize(info.SubjectAlternativeNames),
            KeyUsagesJson = JsonSerializer.Serialize(info.KeyUsages),
            ExtendedKeyUsagesJson = JsonSerializer.Serialize(info.ExtendedKeyUsages),
            RawCertificate = certificateBytes,
            AesKeyEncryptionIv = info.Iv,
            EncryptedAesForPrivateKey = info.EncryptedAesKey,
            EncryptedPrivateKey = info.EncryptedPrivateKey,
            EncryptionCertSerialNumber = info.EncryptionCertSerialNumber,
            // Persist the issuing-CA FK when the issuance
            // path supplies it so CRL generation can skip the DN-based fallback
            // lookup for new rows. Legacy / self-signed rows leave this null
            // and fall back to the defence-in-depth resolver in CrlService.
            IssuerCertificateId = info.IssuerCertificateId,
        };

        _dbContext.Certificates.Add(entity);

        // DO NOT set entity.CertificateAuthority here. CertificateEntity has NO own foreign key to
        // CertificateAuthority — its only CertificateAuthority relationship is the 1:1 whose foreign
        // key lives on the CA side (CertificateAuthorityEntity.CertificateId, via
        // [ForeignKey("CertificateId")] on CertificateAuthorityEntity.Certificate). Assigning this
        // navigation therefore makes EF write CA.CertificateId = thisCert.CertificateId, which CLOBBERS
        // the CA's pointer to its OWN identity certificate. Concretely, issuing a CA's TSA/OCSP infra
        // cert (which has IssuerCertificateId = that CA's cert) would repoint the CA at the infra cert,
        // orphaning the real CA cert and its signing profile (IssuerId no longer == CA.CertificateId) —
        // the exact corruption that produced "Parent CA signing profile not found".
        //
        // The issuing CA is already recorded in IssuerCertificateId above, and
        // CertificateAccessEvaluator.ResolveCertScope resolves a cert's CA scope from that. So this
        // assignment was both semantically wrong (the navigation means "the CA this cert IS the identity
        // cert of", not "the CA that issued it") and unnecessary.

        await _dbContext.SaveChangesAsync();
    }

    public async Task<CertificateInfoModel?> GetCertificateInfoAsync(string serialNumber)
    {
        var entity = await _dbContext.Certificates
            .AsNoTracking()
            .ResolveBySerialOrNullAsync(serialNumber);

        if (entity == null) return null;

        return new CertificateInfoModel
        {
            Pem = entity.Pem,
            CertificateId = entity.CertificateId,
            SerialNumber = entity.SerialNumber,
            SubjectDN = entity.SubjectDN,
            Issuer = entity.Issuer,
            NotBefore = entity.NotBefore,
            NotAfter = entity.NotAfter,
            Thumbprints = entity.Thumbprints,
            IsCA = entity.IsCA,
            HasPrivateKey = entity.HasExportablePrivateKey(),


            Revoked = entity.Revoked,
            RevocationReason = entity.RevocationReason ?? string.Empty,
            RevocationDate = entity.RevocationDate,
            SigningProfileId = entity.SigningProfileId ?? Guid.Empty,
            SubjectAlternativeNames = string.IsNullOrWhiteSpace(entity.SubjectAlternativeNamesJson)
    ? new List<string>()
    : JsonSerializer.Deserialize<List<string>>(entity.SubjectAlternativeNamesJson)!,

            KeyUsages = string.IsNullOrWhiteSpace(entity.KeyUsagesJson)
    ? new List<string>()
    : JsonSerializer.Deserialize<List<string>>(entity.KeyUsagesJson)!,

            ExtendedKeyUsages = string.IsNullOrWhiteSpace(entity.ExtendedKeyUsagesJson)
    ? new List<string>()
    : JsonSerializer.Deserialize<List<string>>(entity.ExtendedKeyUsagesJson)!,

        };
    }

    public async Task<IEnumerable<CertificateInfoModel>> ListAsync()
    {
        var entities = await _dbContext.Certificates.AsNoTracking().ToListAsync();

        return entities.Select(c =>
        {
            var model = new CertificateInfoModel
            {
                CertificateId = c.CertificateId,
                SerialNumber = c.SerialNumber,
                SubjectDN = c.SubjectDN,
                Issuer = c.Issuer,
                NotBefore = c.NotBefore,
                NotAfter = c.NotAfter,
                Thumbprints = c.Thumbprints,
                IsCA = c.IsCA,
                HasPrivateKey = c.HasExportablePrivateKey(),


                Revoked = c.Revoked,
                RevocationReason = c.RevocationReason ?? string.Empty,
                RevocationDate = c.RevocationDate,
                SigningProfileId = c.SigningProfileId ?? Guid.Empty,
                SubjectAlternativeNames = string.IsNullOrWhiteSpace(c.SubjectAlternativeNamesJson)
                    ? new List<string>()
                    : JsonSerializer.Deserialize<List<string>>(c.SubjectAlternativeNamesJson)!,
                KeyUsages = string.IsNullOrWhiteSpace(c.KeyUsagesJson)
                    ? new List<string>()
                    : JsonSerializer.Deserialize<List<string>>(c.KeyUsagesJson)!,
                ExtendedKeyUsages = string.IsNullOrWhiteSpace(c.ExtendedKeyUsagesJson)
                    ? new List<string>()
                    : JsonSerializer.Deserialize<List<string>>(c.ExtendedKeyUsagesJson)!,
            };
            // Extract key algorithm and size from the certificate
            try
            {
                var cert = CertificateUtil.ParseFromPem(c.Pem);
                var pubKey = cert.GetPublicKey();
                if (pubKey is Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters rsa)
                {
                    model.KeyAlgorithm = "RSA";
                    model.KeySize = rsa.Modulus.BitLength.ToString();
                }
                else if (pubKey is Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters ec)
                {
                    model.KeyAlgorithm = "ECDSA";
                    model.KeySize = ec.Parameters.Curve.FieldSize.ToString();
                }
                else if (pubKey is Org.BouncyCastle.Crypto.Parameters.Ed25519PublicKeyParameters)
                {
                    model.KeyAlgorithm = "Ed25519";
                    model.KeySize = "256";
                }
                else if (pubKey is Org.BouncyCastle.Crypto.Parameters.Ed448PublicKeyParameters)
                {
                    model.KeyAlgorithm = "Ed448";
                    model.KeySize = "456";
                }
                else
                {
                    model.KeyAlgorithm = pubKey.GetType().Name.Replace("PublicKeyParameters", "");
                }
                model.SignatureAlgorithm = cert.SigAlgName;
            }
            catch { /* parsing failed — leave as empty */ }
            return model;
        });
    }

    public async Task<CertificateInfoModel?> GetCertificateBySerialNumberAsync(string serialNumber)
    {
        var entity = await _dbContext.Certificates
            .AsNoTracking()
            .ResolveBySerialOrNullAsync(serialNumber);
        if (entity == null) return null;
        return new CertificateInfoModel
        {
            Pem = entity.Pem,
            CertificateId = entity.CertificateId,
            SerialNumber = entity.SerialNumber,
            SubjectDN = entity.SubjectDN,
            Issuer = entity.Issuer,
            NotBefore = entity.NotBefore,
            NotAfter = entity.NotAfter,
            Thumbprints = entity.Thumbprints,
            IsCA = entity.IsCA,
            HasPrivateKey = entity.HasExportablePrivateKey(),


            Revoked = entity.Revoked,
            RevocationReason = entity.RevocationReason ?? string.Empty,
            RevocationDate = entity.RevocationDate,
            SigningProfileId = entity.SigningProfileId ?? Guid.Empty,
        };
    }

    public async Task<List<CertificateInfoModel>> GetAllCertificatesAsync()
    {
        var entities = await _dbContext.Certificates.AsNoTracking().ToListAsync();

        return entities.Select(c => new CertificateInfoModel
        {
            CertificateId = c.CertificateId,
            SerialNumber = c.SerialNumber,
            SubjectDN = c.SubjectDN,
            Issuer = c.Issuer,
            NotBefore = c.NotBefore,
            NotAfter = c.NotAfter,
            Thumbprints = c.Thumbprints,
            IsCA = c.IsCA,
            HasPrivateKey = c.HasExportablePrivateKey(),
            Revoked = c.Revoked,
            RevocationReason = c.RevocationReason ?? string.Empty,
            RevocationDate = c.RevocationDate,
            SigningProfileId = c.SigningProfileId ?? Guid.Empty,
            SubjectAlternativeNames = string.IsNullOrWhiteSpace(c.SubjectAlternativeNamesJson)
    ? new List<string>()
    : JsonSerializer.Deserialize<List<string>>(c.SubjectAlternativeNamesJson)!,

            KeyUsages = string.IsNullOrWhiteSpace(c.KeyUsagesJson)
    ? new List<string>()
    : JsonSerializer.Deserialize<List<string>>(c.KeyUsagesJson)!,

            ExtendedKeyUsages = string.IsNullOrWhiteSpace(c.ExtendedKeyUsagesJson)
    ? new List<string>()
    : JsonSerializer.Deserialize<List<string>>(c.ExtendedKeyUsagesJson)!,

        }).ToList();
    }

    public async Task RevokeCertificateAsync(string serialNumber, string reason)
    {
        var entity = await _dbContext.Certificates.ResolveBySerialOrNullAsync(serialNumber);

        if (entity == null)
            throw new InvalidOperationException("Certificate not found.");

        entity.Revoked = true;
        entity.RevocationReason = reason;

        await _dbContext.SaveChangesAsync();
    }

    public async Task<CertificateInfoModel?> GetCertificateByIdAsync(Guid id)
    {
        var entity = await _dbContext.Certificates.FindAsync(id);
        if (entity == null)
            return null;

        return new CertificateInfoModel
        {
            Pem = entity.Pem,
            CertificateId = entity.CertificateId,
            SerialNumber = entity.SerialNumber,
            SubjectDN = entity.SubjectDN,
            Issuer = entity.Issuer,
            NotBefore = entity.NotBefore,
            NotAfter = entity.NotAfter,
            Thumbprints = entity.Thumbprints,
            IsCA = entity.IsCA,
            HasPrivateKey = entity.HasExportablePrivateKey(),


            Revoked = entity.Revoked,
            RevocationReason = entity.RevocationReason ?? string.Empty,
            RevocationDate = entity.RevocationDate,
            SigningProfileId = entity.SigningProfileId ?? Guid.Empty,
        };
    }

    public async Task<byte[]?> GetRawCertificateAsync(string serialNumber)
    {
        // Resolved as a whole row rather than a projection so the serial's uniqueness can be
        // checked; RawCertificate is the only column read afterwards.
        var entity = (await _dbContext.Certificates
            .AsNoTracking()
            .ResolveBySerialOrNullAsync(serialNumber))?.RawCertificate;

        return entity;
    }
}
