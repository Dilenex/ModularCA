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
    ISecurityAlertService alerts,
    ModularCA.Shared.Signing.ISigningService signer) : ControllerBase
{
    /// <summary>
    /// Lists every serial the signer found missing from the last full CRL it was offered for the
    /// CA and therefore refused to sign: serials that the newest CRL in the signer's journal
    /// lists as revoked, that the database now leaves out, and that nothing excuses (the serial
    /// was not on hold, and it is not shown to be expired). That is what a database taken back
    /// in time leaves: the revocations made in the lost time. Each entry is in the form
    /// <c>POST revoked-serials</c> takes (<c>serialNumber</c>, <c>reason</c>), with the date the
    /// journaled CRL gives; recording them there, or revoking the certificates where the
    /// database still has them, lets the next CRL be signed.
    /// </summary>
    /// <remarks>
    /// The list is the signer's, as of the last CRL it refused (<c>refusedAtUtc</c>). It is
    /// empty, with <c>refused</c> false, when no refusal stands: the signer has signed a full
    /// CRL for the CA since, never refused one, or has restarted since it did, in which case
    /// the CA's next CRL generation brings the list back if it still holds.
    /// </remarks>
    [HttpGet("revoked-serials/missing-from-crl")]
    [RequireCaCapability(Capabilities.CertRevoke, CaTarget.Ca, "caId")]
    public async Task<IActionResult> MissingFromCrl(Guid caId)
    {
        var missing = await signer.JournalMissingRevocationsAsync(caId, HttpContext.RequestAborted);
        // Which of them the CA still has the certificate for: those are revoked on the certificate's own page.
        IReadOnlySet<string> held = new HashSet<string>();
        if (missing is { Serials.Count: > 0 } && revokedSerials != null)
            held = await revokedSerials.HeldAsync(caId, missing.Serials.Select(s => s.Serial).ToList(), HttpContext.RequestAborted);
        return Ok(new
        {
            caId,
            refused = missing != null,
            refusedAtUtc = missing?.RefusedAtUtc,
            journaledCrlNumber = missing?.JournaledCrlNumber,
            count = missing?.Serials.Count ?? 0,
            consolePath = MissingFromCrlConsolePath(caId),
            serials = (missing?.Serials ?? []).Select(s => new
            {
                serialNumber = s.Serial,
                reason = Enum.IsDefined(typeof(RevocationReason), s.Reason) ? ((RevocationReason)s.Reason).ToString() : RevocationReason.Unspecified.ToString(),
                reasonCode = s.Reason,
                revocationDate = s.RevokedAtUtc,
                certificateHeld = held.Contains(s.Serial),
            }),
        });
    }

    /// <summary>
    /// The page of the console that lists the serials missing from a refused CRL of CA
    /// <paramref name="caId"/> and offers to revoke them: the CA's own page, at the section
    /// "Certificates This CA Does Not Hold". A path on this instance, for a link from elsewhere.
    /// </summary>
    public static string MissingFromCrlConsolePath(Guid caId) => $"/admin/authorities/manage/{caId:D}#missing-from-crl";

    /// <summary>
    /// Records several serials as revoked for the CA with no certificate row, under one note and
    /// one step-up, and regenerates the CA's CRL once: the "revoke a serial number alone" action
    /// for every serial a refused CRL left out. Each serial is recorded, audited and alerted as
    /// <see cref="Record"/> does one. A serial the CA holds a certificate for, one already
    /// recorded, and one that is not a serial are answered in <c>refused</c> with the reason and
    /// do not stop the others; 400 for a missing note.
    /// </summary>
    [HttpPost("revoked-serials/bulk")]
    [ModularCA.Shared.Modes.ModeGate(ModularCA.Shared.Modes.ModeOperation.Restriction)]
    [RequireCaCapability(Capabilities.CertRevoke, CaTarget.Ca, "caId")]
    [RequireStepUp(StepUpOps.RevokeSerial, "caId")]
    public async Task<IActionResult> RecordMany(Guid caId, [FromBody] RecordRevokedSerialsRequest request)
    {
        await currentUser.EnsureLoadedAsync();
        if (currentUser.User == null) return Unauthorized();
        var spaceId = await SpaceOfAsync(caId);

        IReadOnlyList<RevokedSerialService.TombstoneOutcome> outcomes;
        long? crlNumber;
        try
        {
            (outcomes, crlNumber) = await revokedSerials.RecordTombstonesAsync(caId,
                request.Serials.Select(s => (s.SerialNumber, s.Reason)).ToList(), request.Note,
                currentUser.User.Id, currentUser.User.Username, HttpContext.RequestAborted);
        }
        catch (Exception ex)
        {
            await TryAuditFailureAsync(AuditActionType.RevokedSerialRecorded, "RevokedSerial", null, new { Count = request.Serials.Count }, ex, caId, spaceId);
            throw;
        }

        foreach (var outcome in outcomes)
        {
            if (outcome.Tombstone is { } t)
                await audit.LogAsync(AuditActionType.RevokedSerialRecorded, currentUser.User.Id, currentUser.User.Username,
                    "RevokedSerial", t.SerialNumber,
                    new { t.SerialNumber, t.IssuerDN, Reason = t.RevocationReason, t.InvalidityDate, t.ListedUntil, t.Note, CrlNumber = crlNumber, Bulk = true },
                    HttpContext.Connection.RemoteIpAddress?.ToString(), certificateAuthorityId: caId, spaceId: spaceId);
            else
                await audit.LogAsync(AuditActionType.RevokedSerialRecorded, currentUser.User.Id, currentUser.User.Username,
                    "RevokedSerial", outcome.SerialNumber, new { outcome.SerialNumber, Bulk = true },
                    HttpContext.Connection.RemoteIpAddress?.ToString(), success: false, errorMessage: outcome.Refusal,
                    certificateAuthorityId: caId, spaceId: spaceId);
        }
        var recorded = outcomes.Where(o => o.Tombstone != null).ToList();
        if (recorded.Count > 0)
            _ = alerts.RaiseAlertAsync("CertificateRevoked", AlertSeverity.Critical,
                $"{recorded.Count} serial(s) recorded as revoked without a certificate by {currentUser.User.Username}",
                new { CertificateAuthorityId = caId, Count = recorded.Count });

        return Ok(new
        {
            message = $"{recorded.Count} serial(s) recorded as revoked.",
            recorded = recorded.Select(o => new { serialNumber = o.Tombstone!.SerialNumber, reason = o.Tombstone.RevocationReason, listedUntil = o.Tombstone.ListedUntil }),
            refused = outcomes.Where(o => o.Tombstone == null).Select(o => new { serialNumber = o.SerialNumber, reason = o.Refusal }),
            crlNumber,
        });
    }

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
