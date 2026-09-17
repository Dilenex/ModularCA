using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Signing;
using ModularCA.Shared.Utils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;
using System.Security.Cryptography;

namespace ModularCA.Core.Services;

/// <summary>
/// RFC 3161-compliant timestamping service that signs timestamp requests using a dedicated TSA
/// certificate. The TSA key stays with the signer: the service holds a <see cref="KeyRef"/> to
/// the TSA certificate and a context naming the CA that owns it, and the signer holds the key
/// to timestamp tokens for that CA only.
/// </summary>
public class TimestampService : ITimestampService
{
    private readonly ModularCADbContext _db;
    private readonly ILogger<TimestampService> _logger;
    private readonly ISigningService _signer;

    /// <summary>The caller identity the TSA signs under; the signer audits it with every decision.</summary>
    private const string SignerCaller = nameof(TimestampService);

    private static readonly HashSet<string> AcceptedAlgorithms = new()
    {
        TspAlgorithms.Sha256,
        TspAlgorithms.Sha384,
        TspAlgorithms.Sha512,
        TspAlgorithms.Sha1,
    };

    private static readonly string TsaPolicyOid = "1.2.3.4.1";

    /// <summary>Constructs the service over the database and the signer that holds the TSA key.</summary>
    public TimestampService(ModularCADbContext db, ILogger<TimestampService> logger, ISigningService signer)
    {
        _db = db;
        _logger = logger;
        _signer = signer ?? throw new ArgumentNullException(nameof(signer));
    }

    public async Task<byte[]> ProcessTimestampRequestAsync(byte[] tsqBytes, string? caLabel = null)
    {
        TimeStampRequest tsRequest;
        try
        {
            tsRequest = new TimeStampRequest(tsqBytes);
        }
        catch (Exception)
        {
            return BuildRejection("Invalid timestamp request encoding");
        }

        var hashAlgOid = tsRequest.MessageImprintAlgOid;
        if (!AcceptedAlgorithms.Contains(hashAlgOid))
        {
            return BuildRejection($"Hash algorithm {hashAlgOid} not supported");
        }

        var (tsaCert, tsaKey, signingContext) = await ResolveTsaSignerAsync(caLabel);
        if (tsaCert == null || tsaKey == null || signingContext == null)
        {
            return BuildRejection("No TSA signer available");
        }

        try
        {
            // Generate 128-bit random serial number (CA/BF BR §7.1 requires ≥64 bits from CSPRNG)
            var serialBytes = new byte[16];
            RandomNumberGenerator.Fill(serialBytes);
            serialBytes[0] &= 0x7F; // Ensure positive (MSB = 0)
            var serialNumber = new BigInteger(1, serialBytes);

            // The same token the key-based generator produced: the SignerInfo signed with
            // "<digest>with<key type>", an ESSCertID over SHA-1 naming the TSA certificate, no
            // issuer-serial. Only the signature now comes from the signer.
            var sigAlg = SignatureAlgorithm.FromName(ResolveTokenSignatureAlgorithm(tsaCert));
            var signatureFactory = new SigningServiceSignatureFactory(_signer, tsaKey, sigAlg, signingContext);
            var signerInfoGenerator = new SignerInfoGeneratorBuilder().Build(signatureFactory, tsaCert);
            var tokenGen = new TimeStampTokenGenerator(
                signerInfoGenerator,
                Asn1DigestFactory.Get(OiwObjectIdentifiers.IdSha1),
                new DerObjectIdentifier(TsaPolicyOid),
                isIssuerSerialIncluded: false);

            var respGen = new TimeStampResponseGenerator(tokenGen, TspAlgorithms.Allowed);
            var tsResponse = respGen.Generate(tsRequest, serialNumber, DateTime.UtcNow);

            _logger.LogInformation("TSA: timestamp token generated (serial={Serial}, hashAlg={HashAlg})",
                serialNumber.ToString(16), hashAlgOid);

            return tsResponse.GetEncoded();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "TSA: failed to generate timestamp token");
            return BuildRejection("Internal TSA error");
        }
    }

    /// <summary>
    /// The algorithm the token is signed with, as the key-based generator chose it: the digest
    /// of the algorithm the TSA certificate was signed with, paired with the TSA key's own type.
    /// Keys with no separate digest (EdDSA, ML-DSA, SLH-DSA) sign with their own algorithm name.
    /// </summary>
    private static string ResolveTokenSignatureAlgorithm(X509Certificate tsaCert)
    {
        var publicKey = tsaCert.GetPublicKey();
        var digest = CertificateUtil.GetDigestOidFromSigAlg(tsaCert.SigAlgName) switch
        {
            "2.16.840.1.101.3.4.2.3" => "SHA512",
            "2.16.840.1.101.3.4.2.2" => "SHA384",
            "1.3.14.3.2.26" => "SHA1",
            _ => "SHA256",
        };
        return publicKey switch
        {
            RsaKeyParameters => digest + "withRSA",
            ECPublicKeyParameters => digest + "withECDSA",
            _ => KeyAlgorithmPolicy.ResolveSignatureAlgorithmForKey(publicKey),
        };
    }

    /// <summary>
    /// Resolves the TSA certificate of the addressed CA together with the reference the signer
    /// knows its key by and the context holding that key to the CA. Whether the key is present
    /// is asked of the signer here, so a TSA certificate without its key is reported as it was
    /// when the keystore was consulted directly.
    /// </summary>
    private async Task<(X509Certificate? cert, KeyRef? key, SigningContext? context)> ResolveTsaSignerAsync(string? caLabel)
    {
        var caEntity = caLabel != null
            ? await _db.CertificateAuthorities.FirstOrDefaultAsync(ca => ca.Label == caLabel && ca.IsEnabled)
            : await _db.CertificateAuthorities.FirstOrDefaultAsync(ca => ca.IsDefault && ca.IsEnabled);

        if (caEntity == null) return (null, null, null);

        // Use dedicated TSA signer cert if available (has critical id-kp-timeStamping EKU per RFC 3161)
        if (caEntity.TsaCertificateId != null)
        {
            var tsaCertEntity = await _db.Certificates.FindAsync(caEntity.TsaCertificateId);
            if (tsaCertEntity != null)
            {
                var tsaCert = CertificateUtil.ParseFromPem(tsaCertEntity.Pem);
                var context = SigningContext.ForCa(SignerCaller, SigningPurpose.Tsa, caEntity.Id, caEntity.TenantId);
                var held = await _signer.ListKeysAsync(context);
                var tsaKey = held.FirstOrDefault(k => k.Key.CertificateId == tsaCertEntity.CertificateId);
                if (tsaKey != null)
                {
                    if (tsaKey.Backend == SignerHealth.Pkcs11Backend)
                    {
                        // The token is built from a SignerInfoGenerator over the signer, which
                        // could sign on-device; keep the refusal the node made before until an
                        // HSM-backed TSA has been proven end to end.
                        _logger.LogWarning("TSA: HSM-backed TSA keys not yet supported for timestamping");
                        return (null, null, null);
                    }
                    return (tsaCert, tsaKey.Key, context);
                }
                _logger.LogWarning("TSA: dedicated TSA cert found but private key not available in keystore");
            }
        }

        _logger.LogWarning("TSA: no dedicated TSA signer certificate configured. " +
            "Re-run bootstrap to generate one, or issue a cert with critical id-kp-timeStamping EKU.");
        return (null, null, null);
    }

    private static byte[] BuildRejection(string statusString)
    {
        try
        {
            var respGen = new TimeStampResponseGenerator(null, TspAlgorithms.Allowed);
            var resp = respGen.GenerateFailResponse(
                Org.BouncyCastle.Asn1.Cmp.PkiStatus.Rejection,
                Org.BouncyCastle.Asn1.Cmp.PkiFailureInfo.SystemFailure,
                statusString);
            return resp.GetEncoded();
        }
        catch
        {
            return Array.Empty<byte>();
        }
    }

}
