using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Signing;
using ModularCA.Shared.Utils;
using ModularCA.Core.Helpers;

namespace ModularCA.Core.Services;

/// <summary>
/// How an export request ended: with a PKCS#12, or with one of the reasons it could not.
/// </summary>
public enum CertificateExportOutcome
{
    /// <summary>The PKCS#12 was produced.</summary>
    Exported,

    /// <summary>No certificate has that serial.</summary>
    NotFound,

    /// <summary>
    /// The certificate exists but the CA holds no key for it. Since re-download ended, a key the
    /// CA generates is delivered once, with the request that carries it, and is not kept.
    /// </summary>
    KeyNotHeld,

    /// <summary>The signer refused the export; the detail carries its reason.</summary>
    Refused,
}

/// <summary>
/// The result of <see cref="ICertificateExportService.ExportPfxAsync"/>: the PKCS#12 when
/// <see cref="Outcome"/> is <see cref="CertificateExportOutcome.Exported"/>, otherwise a
/// sentence the caller can show for why not.
/// </summary>
/// <param name="Outcome">How the export ended.</param>
/// <param name="Pkcs12">The PKCS#12 bytes, when exported.</param>
/// <param name="Detail">Why the export did not happen, for the caller to relay.</param>
public sealed record CertificateExport(CertificateExportOutcome Outcome, byte[]? Pkcs12 = null, string? Detail = null)
{
    /// <summary>The sentence a holder sees when the CA never kept their key.</summary>
    public const string KeyNotHeldDetail =
        "The private key for this certificate was delivered once, in the download that carried the request, and is not kept by the CA.";
}

/// <summary>
/// Exports a certificate together with a private key the CA still holds for it, as PKCS#12.
/// </summary>
public interface ICertificateExportService
{
    /// <summary>
    /// Exports the certificate with serial <paramref name="serial"/> and its stored private
    /// key as PKCS#12 under <paramref name="password"/>, through the signer, on behalf of
    /// <paramref name="caller"/>. With <paramref name="includeChain"/> the issuing chain rides
    /// beside the certificate: the direct issuer always, the root only when it is the direct issuer.
    /// </summary>
    Task<CertificateExport> ExportPfxAsync(string serial, string password, string caller, bool includeChain = true);
}

/// <summary>
/// The export path for the keys the CA stored before re-download ended. The service resolves
/// the certificate, decides the chain, and asks the signer for the PKCS#12 under an
/// <see cref="SigningPurpose.Export"/> context naming the caller; it never sees the key. A
/// certificate issued since carries no stored key, and the service says so rather than
/// reporting the certificate missing.
/// </summary>
public class CertificateExportService : ICertificateExportService
{
    private readonly ModularCADbContext _db;
    private readonly ISigningService _signer;

    /// <summary>
    /// Initializes a new instance of <see cref="CertificateExportService"/>.
    /// </summary>
    public CertificateExportService(ModularCADbContext db, ISigningService signer)
    {
        _db = db;
        _signer = signer;
    }

    /// <inheritdoc />
    public async Task<CertificateExport> ExportPfxAsync(string serial, string password, string caller, bool includeChain = true)
    {
        var certEntity = await _db.Certificates
            .Include(c => c.SigningProfile)
            .ResolveBySerialOrNullAsync(serial);

        if (certEntity == null)
            return new CertificateExport(CertificateExportOutcome.NotFound, Detail: "Certificate not found.");

        if (!certEntity.HasExportablePrivateKey())
            return new CertificateExport(CertificateExportOutcome.KeyNotHeld, Detail: CertificateExport.KeyNotHeldDetail);

        var (chain, caId, tenantId) = await ResolveChainAsync(certEntity, includeChain);
        var context = new SigningContext(caller, SigningPurpose.Export, tenantId, caId);
        try
        {
            var pkcs12 = await _signer.ExportKeyAsync(
                new KeyRef(certEntity.CertificateId),
                new ExportWrap(ExportWrap.Pkcs12, password, chain),
                context);
            return new CertificateExport(CertificateExportOutcome.Exported, pkcs12);
        }
        catch (SigningRefusedException ex) when (ex.Reason == SigningRefusalReason.UnknownKey)
        {
            return new CertificateExport(CertificateExportOutcome.KeyNotHeld, Detail: CertificateExport.KeyNotHeldDetail);
        }
        catch (SigningRefusedException ex)
        {
            return new CertificateExport(CertificateExportOutcome.Refused, Detail: ex.Message);
        }
    }

    /// <summary>
    /// Walks the issuer chain from the certificate's signing profile: the direct issuer is
    /// always included, and the root only when it is the direct issuer, so a PKCS#12 carries
    /// what a client needs to present and not the trust anchor it should already hold. Also
    /// returns the issuing CA and its tenant for the export context.
    /// </summary>
    private async Task<(List<byte[]> Chain, Guid? CaId, Guid? TenantId)> ResolveChainAsync(CertificateEntity certEntity, bool includeChain)
    {
        var chain = new List<byte[]>();
        Guid? caId = null;
        Guid? tenantId = null;
        var issuerId = certEntity.SigningProfile?.IssuerId;
        if (issuerId == null)
            return (chain, caId, tenantId);

        var directIssuerCa = await _db.CertificateAuthorities
            .AsNoTracking()
            .FirstOrDefaultAsync(ca => ca.CertificateId == issuerId);
        caId = directIssuerCa?.Id;
        tenantId = directIssuerCa?.TenantId;
        if (!includeChain)
            return (chain, caId, tenantId);

        var directIssuerIsRoot = directIssuerCa?.ParentCaId == null;
        var visited = new HashSet<Guid>();
        while (issuerId.HasValue && visited.Add(issuerId.Value))
        {
            var issuerEntity = await _db.Certificates
                .Include(c => c.SigningProfile)
                .AsNoTracking()
                .FirstOrDefaultAsync(c => c.CertificateId == issuerId.Value);
            if (issuerEntity == null) break;

            var issuerCa = await _db.CertificateAuthorities
                .AsNoTracking()
                .FirstOrDefaultAsync(ca => ca.CertificateId == issuerId.Value);

            // Skip the root when intermediates exist; include it when it is the direct issuer.
            if (issuerCa?.ParentCaId == null && !directIssuerIsRoot)
                break;

            chain.Add(CertificateUtil.ParseFromPem(issuerEntity.Pem).GetEncoded());

            if (issuerCa?.ParentCaId == null)
                break;

            issuerId = issuerEntity.SigningProfile?.IssuerId;
        }
        return (chain, caId, tenantId);
    }
}
