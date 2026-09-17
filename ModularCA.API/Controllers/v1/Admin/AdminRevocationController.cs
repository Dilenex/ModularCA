using ModularCA.Shared.Authorization;
using ModularCA.Auth.Authorization;
using ModularCA.API.Filters;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.EntityFrameworkCore;
using ModularCA.API.Controllers.v1.Auth;
using ModularCA.Auth.Interfaces;
using ModularCA.Database;
using ModularCA.Shared.Enums;
using ModularCA.Core.Services;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Revocation;
using ModularCA.Core.Helpers;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for revoking certificates and placing/removing certificate holds.
/// All endpoints require step-up MFA verification. KC-06: CA certificate revocation is
/// ceremony-gated when the tenant's <c>RequireKeyCeremony</c> flag is set.
/// </summary>
[ApiController]
[Route("api/v1/admin/certificates")]
[Authorize]
[NodeRole(ProcessRole.Control)]
public class AdminRevocationController(
    ICertificateRevocationService revocationService,
    ICurrentUserService currentUser,
    IAuditService auditService,
    IDistributedCache cache,
    ISecurityAlertService alertService,
    ModularCADbContext dbContext,
    IKeyCeremonyService ceremonySvc
) : ControllerBase
{
    private readonly ICertificateRevocationService _revocationService = revocationService;
    private readonly ICurrentUserService _currentUser = currentUser;
    private readonly IAuditService _audit = auditService;
    private readonly IDistributedCache _cache = cache;
    private readonly ISecurityAlertService _alertService = alertService;
    private readonly ModularCADbContext _dbContext = dbContext;
    private readonly IKeyCeremonyService _ceremonySvc = ceremonySvc;

    /// <summary>
    /// Revokes a certificate by its ID. Requires step-up MFA verification.
    /// KC-06: when the certificate is a CA cert and the tenant requires key ceremonies,
    /// a <c>RevokeCa</c> ceremony is created instead of performing immediate revocation.
    /// Audit findings #32: emits the success-path action type with <c>success=false</c> when
    /// the underlying revocation service throws, so SIEM can correlate failed attempts.
    /// </summary>
    [HttpPost("{certId:guid}/revoke")]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> RevokeByCertId(Guid certId, [FromBody] RevokeCertificateRequestByCertId request, [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
    {
        // The {certId} route segment was declared but never bound, so every one of these
        // actions operated on request.CertificateId from the BODY. That is an authorization
        // split: CaGroupAuthorizationHandler resolves the CA to authorize against from the
        // ROUTE's certId (see ResolveCaFromCertIdAsync), so an operator holding rights on one CA
        // could pass one of its certificates in the path to satisfy the policy and a different
        // CA's certificate in the body to act on. The tenant fence below checks the body id, so
        // this never crossed a tenant — but within one it crossed CAs freely.
        //
        // The route is the resource identity; a body field must not be able to redirect it.
        if (request.CertificateId != Guid.Empty && request.CertificateId != certId)
            return BadRequest(new { error = "Certificate id in the request body does not match the URL." });

        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null) return Unauthorized();

        // KC-06: CA cert revocation uses RevokeCa step-up op; leaf certs use RevokeCert.
        var cert = await _dbContext.Certificates.AsNoTracking()
            .FirstOrDefaultAsync(c => c.CertificateId == certId);
        if (cert == null) return NotFound(new { error = "Certificate not found." });

        var stepUpOp = cert.IsCA ? StepUpOps.RevokeCa : StepUpOps.RevokeCert;
        if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, stepUpOp, certId.ToString()))
            return StatusCode(403, new { error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.", requiresStepUp = true });

        var fence = await EnforceTenantFenceForCertAsync(certId, null);
        if (fence != null) return fence;

        // KC-06: if the cert is a CA cert, check if the tenant requires a ceremony.
        if (cert.IsCA)
        {
            var ceremonyResult = await TryCreateRevokeCaCeremonyAsync(cert, request.Reason);
            if (ceremonyResult != null) return ceremonyResult;
        }

        Shared.Interfaces.RevocationResult result;
        try
        {
            result = await _revocationService.RevokeCertificateAsync(
                certId, null, request.Reason, request.InvalidityDate);
        }
        catch (Exception ex)
        {
            // Audit findings #32: failed revocation attempts must be auditable. CA-cert
            // revocation uses a different action type than leaf-cert revocation so the
            // failure record matches the success-path emission on the corresponding cert
            // class (see CertificateRevocationService.cs for the success-path mapping).
            await TryAuditRevocationFailureAsync(cert, certId, null, request.Reason, ex);
            throw;
        }
        var caInfoById = await ResolveCaFromCertIdAsync(certId);
        await _audit.LogAsync(AuditActionType.CertificateRevoked, _currentUser.User?.Id, _currentUser.User?.Username,
            "Certificate", certId.ToString(), new { request.Reason },
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            certificateAuthorityId: caInfoById?.CaId, tenantId: caInfoById?.TenantId);
        _ = _alertService.RaiseAlertAsync("CertificateRevoked", AlertSeverity.Critical, $"Certificate {certId} revoked by {_currentUser.User?.Username}", new { CertificateId = certId, request.Reason });
        return Ok(new
        {
            message = "Certificate revoked.",
            certificateId = result.CertificateId,
            serialNumber = result.SerialNumber,
            newStatus = result.NewStatus,
            reason = result.Reason?.ToString(),
            crlNumber = result.CrlNumber,
            effectiveAt = result.EffectiveAt,
        });
    }

    /// <summary>
    /// Revokes a certificate by its serial number. Requires step-up MFA verification.
    /// KC-06: when the certificate is a CA cert and the tenant requires key ceremonies,
    /// a <c>RevokeCa</c> ceremony is created instead of performing immediate revocation.
    /// Audit findings #32: emits <see cref="AuditActionType.CertificateRevoked"/> with
    /// <c>success=false</c> when the revocation service throws so SIEM can correlate
    /// failed revocation attempts.
    /// </summary>
    [HttpPost("serial/{serial}/revoke")]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> RevokeByCertSerial(string serial, [FromBody] RevokeCertificateRequestByCertSerial request, [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
    {
        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null) return Unauthorized();

        // The {serial} route segment was declared but never bound, so the body's SerialNumber
        // governed entirely: a request to /serial/AAAA/revoke carrying BBBB acted on BBBB while
        // every access log, proxy trace and metric recorded AAAA. Step-up is validated against the
        // body value too, so this was never an authorization bypass — but on a CA, an audit trail
        // that names the wrong certificate is its own problem. Bind it and require agreement.
        if (!string.IsNullOrWhiteSpace(serial)
            && !string.Equals(serial, request.SerialNumber, StringComparison.OrdinalIgnoreCase))
            return BadRequest(new { error = "Serial number in the URL does not match the request body." });

        // Resolve the target ONCE, then key every subsequent step off the primary key.
        //
        // This method used to look the serial up four separate times — here, inside the tenant
        // fence, inside the revocation service, and again for audit attribution. Because a serial
        // is unique only per issuer (the unique index is (SerialNumber, Issuer)), those were four
        // independent "give me any row with this serial" queries with no defined ordering, and
        // nothing guaranteed they agreed. A serial present under two issuers could therefore have
        // the step-up requirement and the tenant check evaluated against one certificate while the
        // revocation landed on the other — a confused deputy across the tenant boundary, not just
        // a cosmetically wrong row.
        var (cert, resolveError) = await ResolveUniqueCertBySerialAsync(request.SerialNumber);
        if (resolveError != null) return resolveError;

        // KC-06: CA cert revocation uses RevokeCa step-up op; leaf certs use RevokeCert.
        var stepUpOp = cert!.IsCA ? StepUpOps.RevokeCa : StepUpOps.RevokeCert;
        if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, stepUpOp, request.SerialNumber))
            return StatusCode(403, new { error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.", requiresStepUp = true });

        var fence = await EnforceTenantFenceForCertAsync(cert.CertificateId, null);
        if (fence != null) return fence;

        // KC-06: if the cert is a CA cert, check if the tenant requires a ceremony.
        if (cert.IsCA)
        {
            var ceremonyResult = await TryCreateRevokeCaCeremonyAsync(cert, request.Reason);
            if (ceremonyResult != null) return ceremonyResult;
        }

        Shared.Interfaces.RevocationResult result;
        try
        {
            // Pass the resolved ID, not the serial, so the service acts on the exact row this
            // request authorized rather than re-resolving and possibly selecting a different one.
            result = await _revocationService.RevokeCertificateAsync(
                cert.CertificateId, null, request.Reason, request.InvalidityDate);
        }
        catch (Exception ex)
        {
            await TryAuditRevocationFailureAsync(cert, cert.CertificateId, request.SerialNumber, request.Reason, ex);
            throw;
        }
        var caInfoBySn = await ResolveCaFromCertIdAsync(cert.CertificateId);
        await _audit.LogAsync(AuditActionType.CertificateRevoked, _currentUser.User?.Id, _currentUser.User?.Username,
            "Certificate", request.SerialNumber, new { request.Reason },
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            certificateAuthorityId: caInfoBySn?.CaId, tenantId: caInfoBySn?.TenantId);
        _ = _alertService.RaiseAlertAsync("CertificateRevoked", AlertSeverity.Critical, $"Certificate {request.SerialNumber} revoked by {_currentUser.User?.Username}", new { request.SerialNumber, request.Reason });
        return Ok(new
        {
            message = "Certificate revoked.",
            certificateId = result.CertificateId,
            serialNumber = result.SerialNumber,
            newStatus = result.NewStatus,
            reason = result.Reason?.ToString(),
            crlNumber = result.CrlNumber,
            effectiveAt = result.EffectiveAt,
        });
    }

    /// <summary>
    /// Bulk-revokes several LEAF certificates by serial with a single shared reason, authorized by ONE
    /// step-up token (<see cref="StepUpOps.RevokeCert"/>, batch-scoped / no target). CA certificates are
    /// skipped (status <c>skipped_ca</c>) because they use the RevokeCa op and may be ceremony-gated —
    /// they must be revoked individually. Already-revoked / not-found / cross-tenant entries are skipped
    /// too. Never aborts the batch on one failure; returns a per-serial summary.
    /// </summary>
    [HttpPost("bulk-revoke")]
    [Authorize]
    [RequireCaCapability(Capabilities.CertRevoke, CaTarget.Serials, "request.SerialNumbers")]
    public async Task<IActionResult> BulkRevoke([FromBody] BulkRevokeRequest request, [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
    {
        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null) return Unauthorized();

        if (request.SerialNumbers == null || request.SerialNumbers.Count == 0)
            return BadRequest(new { error = "At least one serial number is required." });

        // ONE RevokeCert token (no target) authorizes the whole leaf-cert batch.
        if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, StepUpOps.RevokeCert))
            return StatusCode(403, new { error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.", requiresStepUp = true });

        var results = new List<object>();
        int revoked = 0, skipped = 0, failed = 0;

        foreach (var serial in request.SerialNumbers.Where(s => !string.IsNullOrWhiteSpace(s)).Distinct())
        {
            // Same resolve-once rule as the single-serial path. An ambiguous serial is reported
            // per-entry as "ambiguous" and skipped rather than aborting the batch — the operator
            // can re-submit that one by certificate ID.
            var resolution = await _dbContext.Certificates.AsNoTracking().ResolveBySerialAsync(serial);
            if (resolution.Outcome == SerialResolution.NotFound) { results.Add(new { serialNumber = serial, status = "not_found" }); skipped++; continue; }
            if (resolution.Outcome == SerialResolution.Ambiguous) { results.Add(new { serialNumber = serial, status = "ambiguous" }); skipped++; continue; }

            var cert = resolution.Certificate!;
            if (cert.IsCA) { results.Add(new { serialNumber = serial, status = "skipped_ca" }); skipped++; continue; }
            if (cert.Revoked) { results.Add(new { serialNumber = serial, status = "already_revoked" }); skipped++; continue; }

            var fence = await EnforceTenantFenceForCertAsync(cert.CertificateId, null);
            if (fence != null) { results.Add(new { serialNumber = serial, status = "denied" }); skipped++; continue; }

            try
            {
                await _revocationService.RevokeCertificateAsync(cert.CertificateId, null, request.Reason, request.InvalidityDate);
                var caInfo = await ResolveCaFromCertIdAsync(cert.CertificateId);
                await _audit.LogAsync(AuditActionType.CertificateRevoked, _currentUser.User?.Id, _currentUser.User?.Username,
                    "Certificate", serial, new { request.Reason, Bulk = true },
                    HttpContext.Connection.RemoteIpAddress?.ToString(),
                    certificateAuthorityId: caInfo?.CaId, tenantId: caInfo?.TenantId);
                results.Add(new { serialNumber = serial, status = "revoked" });
                revoked++;
            }
            catch (Exception ex)
            {
                await TryAuditRevocationFailureAsync(cert, null, serial, request.Reason, ex);
                results.Add(new { serialNumber = serial, status = "failed" });
                failed++;
            }
        }

        if (revoked > 0)
            _ = _alertService.RaiseAlertAsync("CertificateRevoked", AlertSeverity.Critical,
                $"{revoked} certificate(s) bulk-revoked by {_currentUser.User?.Username}", new { Count = revoked, request.Reason });

        return Ok(new { revoked, skipped, failed, results });
    }

    /// <summary>
    /// Places a certificate on hold by its ID. Requires step-up MFA verification.
    /// Audit findings #32: emits <see cref="AuditActionType.CertificateHeld"/> with
    /// <c>success=false</c> when the hold service call throws.
    /// </summary>
    [HttpPost("{certId:guid}/hold")]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> HoldByCertId(Guid certId, [FromBody] HoldCertificateRequestByCertId request, [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
    {
        // The {certId} route segment was declared but never bound, so every one of these
        // actions operated on request.CertificateId from the BODY. That is an authorization
        // split: CaGroupAuthorizationHandler resolves the CA to authorize against from the
        // ROUTE's certId (see ResolveCaFromCertIdAsync), so an operator holding rights on one CA
        // could pass one of its certificates in the path to satisfy the policy and a different
        // CA's certificate in the body to act on. The tenant fence below checks the body id, so
        // this never crossed a tenant — but within one it crossed CAs freely.
        //
        // The route is the resource identity; a body field must not be able to redirect it.
        if (request.CertificateId != Guid.Empty && request.CertificateId != certId)
            return BadRequest(new { error = "Certificate id in the request body does not match the URL." });

        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null) return Unauthorized();
        if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, StepUpOps.HoldCert, certId.ToString()))
            return StatusCode(403, new { error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.", requiresStepUp = true });

        var fence = await EnforceTenantFenceForCertAsync(certId, null);
        if (fence != null) return fence;

        Shared.Interfaces.RevocationResult holdResult;
        try
        {
            holdResult = await _revocationService.HoldCertificateAsync(certId, null);
        }
        catch (Exception ex)
        {
            await TryAuditHoldFailureAsync(AuditActionType.CertificateHeld, certId, null, ex);
            throw;
        }
        var caInfoHoldId = await ResolveCaFromCertIdAsync(certId);
        await _audit.LogAsync(AuditActionType.CertificateHeld, _currentUser.User?.Id, _currentUser.User?.Username,
            "Certificate", certId.ToString(),
            sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString(),
            certificateAuthorityId: caInfoHoldId?.CaId, tenantId: caInfoHoldId?.TenantId);
        _ = _alertService.RaiseAlertAsync("CertificateHold", AlertSeverity.Critical, $"Certificate {certId} placed on hold by {_currentUser.User?.Username}", new { CertificateId = certId });
        return Ok(new
        {
            message = "Certificate placed on hold.",
            certificateId = holdResult.CertificateId,
            serialNumber = holdResult.SerialNumber,
            newStatus = holdResult.NewStatus,
            crlNumber = holdResult.CrlNumber,
            effectiveAt = holdResult.EffectiveAt,
        });
    }

    /// <summary>
    /// Places a certificate on hold by its serial number. Requires step-up MFA verification.
    /// Audit findings #32: emits <see cref="AuditActionType.CertificateHeld"/> with
    /// <c>success=false</c> when the hold service call throws.
    /// </summary>
    [HttpPost("serial/{serial}/hold")]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> HoldByCertSerial(string serial, [FromBody] HoldCertificateRequestByCertSerial request, [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
    {
        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null) return Unauthorized();
        // Route/body agreement — see RevokeByCertSerial for why the {serial} segment is bound.
        if (!string.IsNullOrWhiteSpace(serial)
            && !string.Equals(serial, request.SerialNumber, StringComparison.OrdinalIgnoreCase))
            return BadRequest(new { error = "Serial number in the URL does not match the request body." });

        if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, StepUpOps.HoldCert, request.SerialNumber))
            return StatusCode(403, new { error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.", requiresStepUp = true });

        // Resolve once, then key off the primary key — see RevokeByCertSerial for why a serial
        // is not a safe identifier to re-resolve at each step.
        var (holdCert, holdResolveError) = await ResolveUniqueCertBySerialAsync(request.SerialNumber);
        if (holdResolveError != null) return holdResolveError;

        var fence = await EnforceTenantFenceForCertAsync(holdCert!.CertificateId, null);
        if (fence != null) return fence;

        Shared.Interfaces.RevocationResult holdSnResult;
        try
        {
            holdSnResult = await _revocationService.HoldCertificateAsync(holdCert.CertificateId, null);
        }
        catch (Exception ex)
        {
            await TryAuditHoldFailureAsync(AuditActionType.CertificateHeld, holdCert.CertificateId, request.SerialNumber, ex);
            throw;
        }
        var caInfoHoldSn = await ResolveCaFromCertIdAsync(holdCert.CertificateId);
        await _audit.LogAsync(AuditActionType.CertificateHeld, _currentUser.User?.Id, _currentUser.User?.Username,
            "Certificate", request.SerialNumber,
            sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString(),
            certificateAuthorityId: caInfoHoldSn?.CaId, tenantId: caInfoHoldSn?.TenantId);
        _ = _alertService.RaiseAlertAsync("CertificateHold", AlertSeverity.Critical, $"Certificate {request.SerialNumber} placed on hold by {_currentUser.User?.Username}", new { request.SerialNumber });
        return Ok(new
        {
            message = "Certificate placed on hold.",
            certificateId = holdSnResult.CertificateId,
            serialNumber = holdSnResult.SerialNumber,
            newStatus = holdSnResult.NewStatus,
            crlNumber = holdSnResult.CrlNumber,
            effectiveAt = holdSnResult.EffectiveAt,
        });
    }

    /// <summary>
    /// Removes a certificate from hold by its ID. Requires step-up MFA verification.
    /// Audit findings #32: emits <see cref="AuditActionType.CertificateUnheld"/> with
    /// <c>success=false</c> when the unhold service call throws.
    /// </summary>
    [HttpPost("{certId:guid}/unhold")]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> UnholdByCertId(Guid certId, [FromBody] HoldCertificateRequestByCertId request, [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
    {
        // The {certId} route segment was declared but never bound, so every one of these
        // actions operated on request.CertificateId from the BODY. That is an authorization
        // split: CaGroupAuthorizationHandler resolves the CA to authorize against from the
        // ROUTE's certId (see ResolveCaFromCertIdAsync), so an operator holding rights on one CA
        // could pass one of its certificates in the path to satisfy the policy and a different
        // CA's certificate in the body to act on. The tenant fence below checks the body id, so
        // this never crossed a tenant — but within one it crossed CAs freely.
        //
        // The route is the resource identity; a body field must not be able to redirect it.
        if (request.CertificateId != Guid.Empty && request.CertificateId != certId)
            return BadRequest(new { error = "Certificate id in the request body does not match the URL." });

        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null) return Unauthorized();
        if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, StepUpOps.UnholdCert, certId.ToString()))
            return StatusCode(403, new { error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.", requiresStepUp = true });

        var fence = await EnforceTenantFenceForCertAsync(certId, null);
        if (fence != null) return fence;

        Shared.Interfaces.RevocationResult unholdResult;
        try
        {
            unholdResult = await _revocationService.UnholdCertificateAsync(certId, null);
        }
        catch (Exception ex)
        {
            await TryAuditHoldFailureAsync(AuditActionType.CertificateUnheld, certId, null, ex);
            throw;
        }
        var caInfoUnholdId = await ResolveCaFromCertIdAsync(certId);
        await _audit.LogAsync(AuditActionType.CertificateUnheld, _currentUser.User?.Id, _currentUser.User?.Username,
            "Certificate", certId.ToString(),
            sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString(),
            certificateAuthorityId: caInfoUnholdId?.CaId, tenantId: caInfoUnholdId?.TenantId);
        return Ok(new
        {
            message = "Certificate reinstated from hold.",
            certificateId = unholdResult.CertificateId,
            serialNumber = unholdResult.SerialNumber,
            newStatus = unholdResult.NewStatus,
            crlNumber = unholdResult.CrlNumber,
            effectiveAt = unholdResult.EffectiveAt,
        });
    }

    /// <summary>
    /// Removes a certificate from hold by its serial number. Requires step-up MFA verification.
    /// Audit findings #32: emits <see cref="AuditActionType.CertificateUnheld"/> with
    /// <c>success=false</c> when the unhold service call throws.
    /// </summary>
    [HttpPost("serial/{serial}/unhold")]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> UnholdByCertSerial(string serial, [FromBody] HoldCertificateRequestByCertSerial request, [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
    {
        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null) return Unauthorized();
        // Route/body agreement — see RevokeByCertSerial for why the {serial} segment is bound.
        if (!string.IsNullOrWhiteSpace(serial)
            && !string.Equals(serial, request.SerialNumber, StringComparison.OrdinalIgnoreCase))
            return BadRequest(new { error = "Serial number in the URL does not match the request body." });

        if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, StepUpOps.UnholdCert, request.SerialNumber))
            return StatusCode(403, new { error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.", requiresStepUp = true });

        // Resolve once, then key off the primary key — see RevokeByCertSerial for the rationale.
        var (unholdCert, unholdResolveError) = await ResolveUniqueCertBySerialAsync(request.SerialNumber);
        if (unholdResolveError != null) return unholdResolveError;

        var fence = await EnforceTenantFenceForCertAsync(unholdCert!.CertificateId, null);
        if (fence != null) return fence;

        Shared.Interfaces.RevocationResult unholdSnResult;
        try
        {
            unholdSnResult = await _revocationService.UnholdCertificateAsync(unholdCert.CertificateId, null);
        }
        catch (Exception ex)
        {
            await TryAuditHoldFailureAsync(AuditActionType.CertificateUnheld, unholdCert.CertificateId, request.SerialNumber, ex);
            throw;
        }
        var caInfoUnholdSn = await ResolveCaFromCertIdAsync(unholdCert.CertificateId);
        await _audit.LogAsync(AuditActionType.CertificateUnheld, _currentUser.User?.Id, _currentUser.User?.Username,
            "Certificate", request.SerialNumber,
            sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString(),
            certificateAuthorityId: caInfoUnholdSn?.CaId, tenantId: caInfoUnholdSn?.TenantId);
        return Ok(new
        {
            message = "Certificate reinstated from hold.",
            certificateId = unholdSnResult.CertificateId,
            serialNumber = unholdSnResult.SerialNumber,
            newStatus = unholdSnResult.NewStatus,
            crlNumber = unholdSnResult.CrlNumber,
            effectiveAt = unholdSnResult.EffectiveAt,
        });
    }

    /// <summary>
    /// KC-06: checks whether a CA certificate revocation requires a key ceremony. If the CA's
    /// tenant has <c>RequireKeyCeremony</c> set, creates a <c>RevokeCa</c> ceremony and returns
    /// an <see cref="IActionResult"/> with the ceremony details. Returns null if no ceremony is
    /// required, allowing the caller to proceed with direct revocation.
    /// </summary>
    private async Task<IActionResult?> TryCreateRevokeCaCeremonyAsync(
        Shared.Entities.CertificateEntity cert, RevocationReason reason)
    {
        // Find the CA entity that owns this certificate.
        var ca = await _dbContext.CertificateAuthorities
            .Include(c => c.Tenant)
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.CertificateId == cert.CertificateId);

        if (ca?.Tenant == null)
            return null; // No CA linkage — allow direct revocation.

        if (!ca.Tenant.RequireKeyCeremony)
            return null; // Tenant does not require ceremonies.

        // Create a RevokeCa ceremony.
        // camelCase so the stored blob matches the casing of the API envelope it is embedded in.
        var parametersJson = JsonSerializer.Serialize(new
        {
            CertificateId = cert.CertificateId,
            SerialNumber = cert.SerialNumber,
            Reason = reason.ToString(),
            TenantId = ca.TenantId,
        }, ModularCA.Shared.Utils.SafeJsonOptions.Stored);

        var ceremony = await _ceremonySvc.InitiateAsync(
            "RevokeCa",
            $"Revoke CA certificate {cert.SerialNumber} ({ca.Name})",
            ca.Id.ToString(),
            _currentUser.User!.Id,
            _currentUser.User.Username ?? string.Empty,
            parametersJson);

        await _audit.LogAsync(
            AuditActionType.KeyCeremonyInitiated,
            _currentUser.User.Id, _currentUser.User.Username,
            "KeyCeremony", ceremony.Id.ToString(),
            new { ceremony.OperationType, CertificateId = cert.CertificateId, cert.SerialNumber },
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            certificateAuthorityId: ca.Id, tenantId: ca.TenantId);

        _ = _alertService.RaiseAlertAsync(
            "KeyCeremonyInitiated", AlertSeverity.Critical,
            $"CA revocation ceremony created for {ca.Name} by {_currentUser.User.Username}",
            new { CeremonyId = ceremony.Id, CertificateId = cert.CertificateId, cert.SerialNumber });

        return Ok(new
        {
            message = "CA certificate revocation requires a key ceremony. A ceremony has been created.",
            requiresCeremony = true,
            ceremonyId = ceremony.Id,
            ceremony.Status,
            ceremony.RequiredApprovals,
            ceremony.CurrentApprovals,
            certificateId = cert.CertificateId,
            serialNumber = cert.SerialNumber,
            caName = ca.Name,
        });
    }

    /// <summary>
    /// Enforces tenant isolation for certificate operations. Resolves the certificate's CA
    /// tenant via the signing profile linkage and checks that the caller has access to that
    /// tenant. System admins bypass the check. Returns null on allow, NotFound on deny.
    /// </summary>
    private async Task<IActionResult?> EnforceTenantFenceForCertAsync(Guid? certId, string? serial)
    {
        if (HttpContext.Items["IsSystemAdmin"] is true) return null;

        Shared.Entities.CertificateEntity? cert = null;
        if (certId.HasValue)
        {
            cert = await _dbContext.Certificates.AsNoTracking().FirstOrDefaultAsync(c => c.CertificateId == certId.Value);
        }
        else if (!string.IsNullOrWhiteSpace(serial))
        {
            // Ambiguity denies. This method is the tenant isolation boundary, so resolving an
            // ambiguous serial to an arbitrary row could authorize against a certificate in a
            // tenant the caller can reach while the operation targets one they cannot.
            cert = await _dbContext.Certificates.AsNoTracking().ResolveBySerialOrNullAsync(serial);
            if (cert == null)
                return NotFound();
        }
        if (cert == null)
            return NotFound();

        if (cert.SigningProfileId == null) return NotFound();
        var config = await _dbContext.CaProtocolConfigs
            .Include(pc => pc.Ca)
            .AsNoTracking()
            .FirstOrDefaultAsync(pc => pc.SigningProfileId == cert.SigningProfileId);
        if (config?.Ca == null) return NotFound();

        var tenantIds = HttpContext.Items["AccessibleTenantIds"] as HashSet<Guid>;
        if (tenantIds == null || !tenantIds.Contains(config.Ca.TenantId))
            return NotFound();
        return null;
    }

    /// <summary>
    /// Resolves a serial number to exactly one certificate, or returns the error response to send.
    /// <para>
    /// X.509 scopes serial uniqueness to the issuer, and the schema follows suit — the unique
    /// index on <c>Certificates</c> is <c>(SerialNumber, Issuer)</c>. A serial is therefore a
    /// lookup key only when it happens to be unambiguous, and the caller has no way to know that
    /// without asking. Returning HTTP 409 on ambiguity keeps the operator in control: revoking
    /// the wrong certificate is unrecoverable, so "tell me which one" is the only safe answer.
    /// </para>
    /// </summary>
    /// <returns>
    /// The single matching certificate and a null error, or a null certificate and the
    /// <see cref="IActionResult"/> to return (404 when nothing matches, 409 when several do).
    /// </returns>
    private async Task<(Shared.Entities.CertificateEntity? Cert, IActionResult? Error)> ResolveUniqueCertBySerialAsync(string? serial)
    {
        if (string.IsNullOrWhiteSpace(serial))
            return (null, BadRequest(new { error = "A serial number is required." }));

        var resolution = await _dbContext.Certificates.AsNoTracking().ResolveBySerialAsync(serial);

        if (resolution.Outcome == SerialResolution.NotFound)
            return (null, NotFound(new { error = "Certificate not found." }));

        if (resolution.Outcome == SerialResolution.Ambiguous)
            return (null, Conflict(new
            {
                error = $"Serial number '{serial}' matches more than one certificate. "
                      + "Serial numbers are unique only within an issuer — retry using the certificate ID.",
                ambiguousSerial = serial
            }));

        return (resolution.Certificate, null);
    }

    /// <summary>
    /// Resolves the CA ID and tenant ID from a certificate ID via its signing profile linkage.
    /// </summary>
    private async Task<(Guid CaId, Guid TenantId)?> ResolveCaFromCertIdAsync(Guid certId)
    {
        var cert = await _dbContext.Certificates.AsNoTracking().FirstOrDefaultAsync(c => c.CertificateId == certId);
        if (cert?.SigningProfileId == null) return null;
        var config = await _dbContext.CaProtocolConfigs
            .Include(pc => pc.Ca)
            .AsNoTracking()
            .FirstOrDefaultAsync(pc => pc.SigningProfileId == cert.SigningProfileId);
        if (config?.Ca == null) return null;
        return (config.Ca.Id, config.Ca.TenantId);
    }

    /// <summary>
    /// Resolves the CA ID and tenant ID from a certificate serial number via its signing profile linkage.
    /// </summary>
    private async Task<(Guid CaId, Guid TenantId)?> ResolveCaFromSerialAsync(string serial)
    {
        var cert = await _dbContext.Certificates.AsNoTracking().ResolveBySerialOrNullAsync(serial);
        if (cert?.SigningProfileId == null) return null;
        var config = await _dbContext.CaProtocolConfigs
            .Include(pc => pc.Ca)
            .AsNoTracking()
            .FirstOrDefaultAsync(pc => pc.SigningProfileId == cert.SigningProfileId);
        if (config?.Ca == null) return null;
        return (config.Ca.Id, config.Ca.TenantId);
    }

    /// <summary>
    /// Audit findings #32: helper that emits a <see cref="AuditActionType.CertificateRevoked"/>
    /// audit record with <c>success=false</c> when the revocation service throws. The emission
    /// is wrapped in its own try/catch so an audit-store failure does not shadow the original
    /// service error the caller is about to rethrow.
    /// </summary>
    private async Task TryAuditRevocationFailureAsync(
        Shared.Entities.CertificateEntity cert,
        Guid? certificateId,
        string? serial,
        RevocationReason reason,
        Exception ex)
    {
        try
        {
            var caInfo = certificateId.HasValue
                ? await ResolveCaFromCertIdAsync(certificateId.Value)
                : (serial != null ? await ResolveCaFromSerialAsync(serial) : null);

            var targetId = certificateId?.ToString() ?? serial ?? cert.CertificateId.ToString();

            await _audit.LogAsync(
                AuditActionType.CertificateRevoked,
                _currentUser.User?.Id, _currentUser.User?.Username,
                "Certificate", targetId,
                new { Reason = reason, IsCA = cert.IsCA, cert.SerialNumber },
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                success: false,
                errorMessage: ex.Message,
                certificateAuthorityId: caInfo?.CaId,
                tenantId: caInfo?.TenantId);
        }
        catch
        {
            // Swallow — original error is what the user needs.
        }
    }

    /// <summary>
    /// Audit findings #32: helper that emits a hold/unhold failure audit record. Picks the
    /// matching action type (<see cref="AuditActionType.CertificateHeld"/> or
    /// <see cref="AuditActionType.CertificateUnheld"/>) so SIEM can align failures with the
    /// success-path emissions on the same endpoints.
    /// </summary>
    private async Task TryAuditHoldFailureAsync(
        string actionType,
        Guid? certificateId,
        string? serial,
        Exception ex)
    {
        try
        {
            var caInfo = certificateId.HasValue
                ? await ResolveCaFromCertIdAsync(certificateId.Value)
                : (serial != null ? await ResolveCaFromSerialAsync(serial) : null);

            var targetId = certificateId?.ToString() ?? serial ?? string.Empty;

            await _audit.LogAsync(
                actionType,
                _currentUser.User?.Id, _currentUser.User?.Username,
                "Certificate", targetId,
                sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString(),
                success: false,
                errorMessage: ex.Message,
                certificateAuthorityId: caInfo?.CaId,
                tenantId: caInfo?.TenantId);
        }
        catch
        {
            // Swallow — original error is what the user needs.
        }
    }
}
