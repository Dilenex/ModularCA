using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.API.Filters;
using ModularCA.API.Startup;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Revocation;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Revocation of what a CA's database does not hold
/// (<c>docs/architecture/rollback-continuity.md</c>, section 5): recording a serial as revoked
/// with no certificate row (a tombstone), and adopting a certificate supplied from outside.
/// Every action needs <c>cert.revoke</c> on the CA in the route, checked on that CA and no
/// other; the two mutations also need step-up for that CA and are audited, like any revocation.
/// </summary>
[ApiController]
[Route("api/v1/admin/authorities/{caId:guid}")]
[Authorize]
[NodeRole(ProcessRole.Control)]
public class AdminRevokedSerialController(
    RevokedSerialService revokedSerials,
    ModularCADbContext db,
    ICurrentUserService currentUser,
    IAuditService audit,
    ISecurityAlertService alerts) : ControllerBase
{
    /// <summary>
    /// Lists the serials recorded as revoked for the CA with no certificate row, newest first,
    /// each with its reason, dates, note, who recorded it and until when the CRL lists it.
    /// </summary>
    [HttpGet("revoked-serials")]
    [RequireCaCapability(Capabilities.CertRevoke, CaTarget.Ca, "caId")]
    public async Task<IActionResult> List(Guid caId)
    {
        var now = DateTime.UtcNow;
        var rows = await revokedSerials.ListAsync(caId, HttpContext.RequestAborted);
        return Ok(rows.Select(t => new
        {
            t.Id,
            t.SerialNumber,
            t.IssuerDN,
            Reason = t.RevocationReason,
            t.RevocationDate,
            t.InvalidityDate,
            t.ListedUntil,
            OnCrl = t.ListedUntil > now,
            t.Note,
            RecordedBy = t.CreatedByUsername,
        }));
    }

    /// <summary>
    /// Records a serial as revoked for the CA with no certificate row. The CA's CRL is
    /// regenerated to list it, and OCSP answers for it with the recorded date and reason. The
    /// entry stays on the CRL until the longest validity the CA's profiles allow has passed.
    /// Refused with 409 when the CA holds a certificate with that serial (revoke the certificate)
    /// or the serial is already recorded; 400 for a serial that is not hexadecimal, a hold, or a
    /// missing note. A refusal is audited with <c>success=false</c>.
    /// </summary>
    [HttpPost("revoked-serials")]
    [ModularCA.Shared.Modes.ModeGate(ModularCA.Shared.Modes.ModeOperation.Restriction)]
    [RequireCaCapability(Capabilities.CertRevoke, CaTarget.Ca, "caId")]
    [RequireStepUp(StepUpOps.RevokeSerial, "caId")]
    public async Task<IActionResult> Record(Guid caId, [FromBody] RecordRevokedSerialRequest request)
    {
        await currentUser.EnsureLoadedAsync();
        if (currentUser.User == null) return Unauthorized();
        var spaceId = await SpaceOfAsync(caId);

        TombstoneResult result;
        try
        {
            result = await revokedSerials.RecordTombstoneAsync(caId, request.SerialNumber, request.Reason, request.InvalidityDate,
                request.Note, currentUser.User.Id, currentUser.User.Username, HttpContext.RequestAborted);
        }
        catch (Exception ex)
        {
            await TryAuditFailureAsync(AuditActionType.RevokedSerialRecorded, "RevokedSerial", request.SerialNumber,
                new { request.SerialNumber, request.Reason }, ex, caId, spaceId);
            throw;
        }

        var t = result.Tombstone;
        await audit.LogAsync(AuditActionType.RevokedSerialRecorded, currentUser.User.Id, currentUser.User.Username,
            "RevokedSerial", t.SerialNumber,
            new { t.SerialNumber, t.IssuerDN, Reason = t.RevocationReason, t.InvalidityDate, t.ListedUntil, t.Note, result.CrlNumber },
            HttpContext.Connection.RemoteIpAddress?.ToString(), certificateAuthorityId: caId, spaceId: spaceId);
        _ = alerts.RaiseAlertAsync("CertificateRevoked", AlertSeverity.Critical,
            $"Serial {t.SerialNumber} recorded as revoked without a certificate by {currentUser.User.Username}",
            new { t.SerialNumber, CertificateAuthorityId = caId, Reason = t.RevocationReason });

        return Ok(new
        {
            message = "Serial recorded as revoked.",
            id = t.Id,
            serialNumber = t.SerialNumber,
            reason = t.RevocationReason,
            revocationDate = t.RevocationDate,
            listedUntil = t.ListedUntil,
            crlNumber = result.CrlNumber,
        });
    }

    /// <summary>
    /// Adopts a certificate supplied from outside as a certificate row of the CA, once its issuer
    /// name is the CA's and its signature verifies under the key of the CA's current certificate.
    /// The row is marked as adopted, with no profile and no known requester, and can be revoked
    /// like any other; <c>revokeReason</c> revokes it in the same step. A tombstone recorded for
    /// its serial becomes the row's revocation and is removed. 400 for a certificate that cannot
    /// be read, names another issuer, does not verify, or is a CA certificate; 409 when the CA
    /// already holds that serial. A refusal is audited with <c>success=false</c>.
    /// </summary>
    [HttpPost("adopted-certificates")]
    [ModularCA.Shared.Modes.ModeGate(ModularCA.Shared.Modes.ModeOperation.Fact)]
    [RequireCaCapability(Capabilities.CertRevoke, CaTarget.Ca, "caId")]
    [RequireStepUp(StepUpOps.AdoptCertificate, "caId")]
    public async Task<IActionResult> Adopt(Guid caId, [FromBody] AdoptCertificateRequest request)
    {
        await currentUser.EnsureLoadedAsync();
        if (currentUser.User == null) return Unauthorized();
        var spaceId = await SpaceOfAsync(caId);

        AdoptionResult result;
        try
        {
            result = await revokedSerials.AdoptCertificateAsync(caId, request.Certificate, request.Note, request.RevokeReason,
                request.InvalidityDate, currentUser.User.Username, HttpContext.RequestAborted);
        }
        catch (Exception ex)
        {
            await TryAuditFailureAsync(AuditActionType.CertificateAdopted, "Certificate", null,
                new { request.RevokeReason }, ex, caId, spaceId);
            throw;
        }

        var c = result.Certificate;
        await audit.LogAsync(AuditActionType.CertificateAdopted, currentUser.User.Id, currentUser.User.Username,
            "Certificate", c.CertificateId.ToString(),
            new { c.SerialNumber, c.SubjectDN, c.NotBefore, c.NotAfter, Note = c.AdoptionNote, result.Revoked, result.FromTombstone },
            HttpContext.Connection.RemoteIpAddress?.ToString(), certificateAuthorityId: caId, spaceId: spaceId);
        if (result.Revoked)
        {
            await audit.LogAsync(AuditActionType.CertificateRevoked, currentUser.User.Id, currentUser.User.Username,
                "Certificate", c.CertificateId.ToString(),
                new { Reason = c.RevocationReason, Adopted = true, result.FromTombstone },
                HttpContext.Connection.RemoteIpAddress?.ToString(), certificateAuthorityId: caId, spaceId: spaceId);
            _ = alerts.RaiseAlertAsync("CertificateRevoked", AlertSeverity.Critical,
                $"Certificate {c.CertificateId} adopted and revoked by {currentUser.User.Username}",
                new { c.CertificateId, Reason = c.RevocationReason });
        }

        return Ok(new
        {
            message = result.Revoked ? "Certificate adopted and revoked." : "Certificate adopted.",
            certificateId = c.CertificateId,
            serialNumber = c.SerialNumber,
            subjectDN = c.SubjectDN,
            notAfter = c.NotAfter,
            revoked = result.Revoked,
            reason = c.RevocationReason,
            fromTombstone = result.FromTombstone,
            crlNumber = result.CrlNumber,
        });
    }

    private Task<Guid?> SpaceOfAsync(Guid caId)
        => db.CertificateAuthorities.AsNoTracking().Where(c => c.Id == caId).Select(c => c.SpaceId).FirstOrDefaultAsync();

    /// <summary>
    /// Audits a refused or failed attempt under the action it would have been, with
    /// <c>success=false</c>. A failure to write it is swallowed so it cannot hide the refusal
    /// the caller is about to get.
    /// </summary>
    private async Task TryAuditFailureAsync(string action, string targetType, string? targetId, object details, Exception ex, Guid caId, Guid? spaceId)
    {
        try
        {
            await audit.LogAsync(action, currentUser.User?.Id, currentUser.User?.Username, targetType, targetId, details,
                HttpContext.Connection.RemoteIpAddress?.ToString(), success: false, errorMessage: ex.Message,
                certificateAuthorityId: caId, spaceId: spaceId);
        }
        catch
        {
            // The refusal itself reaches the caller.
        }
    }
}
