using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Authorization;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for querying audit logs across the main and protocol audit databases.
/// Supports CA-scoped filtering and group-based access control.
/// </summary>
[ApiController]
[Route("api/v1/admin/audit")]
[Authorize(Policy = "CaAuditor")]
public class AdminAuditController : ControllerBase
{
    private readonly AuditDbContext? _auditDb;
    private readonly ModularCADbContext _mainDb;
    private readonly ICaGroupAuthorizationService _authService;
    private readonly ICurrentUserService _currentUser;
    private readonly AuditHashChainService? _hashChain;

    /// <summary>
    /// Initializes the audit controller with both audit and main DB contexts plus authorization services.
    /// </summary>
    public AdminAuditController(
        ModularCADbContext mainDb,
        ICaGroupAuthorizationService authService,
        ICurrentUserService currentUser,
        AuditDbContext? auditDb = null,
        AuditHashChainService? hashChain = null)
    {
        _mainDb = mainDb;
        _authService = authService;
        _currentUser = currentUser;
        _auditDb = auditDb;
        _hashChain = hashChain;
    }

    /// <summary>
    /// Returns paginated general audit log entries, optionally filtered by date range, action type, actor, and CA.
    /// System admins/auditors see all logs. CA-scoped auditors only see logs for their assigned CAs.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> GetAuditLogs(
        [FromQuery] DateTime? from,
        [FromQuery] DateTime? to,
        [FromQuery] string? actionType,
        [FromQuery] string? actorUsername,
        [FromQuery] Guid? caId,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 50)
    {
        if (_auditDb == null)
            return StatusCode(503, new { error = "Audit database is not configured" });

        var query = _auditDb.AuditLogs.AsQueryable();

        if (from.HasValue)
            query = query.Where(a => a.Timestamp >= from.Value);
        if (to.HasValue)
            query = query.Where(a => a.Timestamp <= to.Value);
        if (!string.IsNullOrWhiteSpace(actionType))
            query = query.Where(a => a.ActionType == actionType);
        if (!string.IsNullOrWhiteSpace(actorUsername))
            query = query.Where(a => a.ActorUsername == actorUsername);

        // Filter by specific CA if requested
        if (caId.HasValue)
            query = query.Where(a => a.CertificateAuthorityId == caId.Value);

        // Apply group-based access filtering
        var userId = _currentUser.UserId;
        if (userId.HasValue)
        {
            var isSystemLevel = await _authService.HasSystemCapabilityAsync(userId.Value, Capabilities.AuditView);
            if (!isSystemLevel)
            {
                var accessibleCaIds = await _authService.GetAccessibleCaIdsAsync(userId.Value, Capabilities.AuditView);
                query = query.Where(a => a.CertificateAuthorityId != null && accessibleCaIds.Contains(a.CertificateAuthorityId.Value));
            }
        }

        var total = await query.CountAsync();
        var items = await query
            .OrderByDescending(a => a.Timestamp)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(a => new
            {
                a.Id,
                a.Timestamp,
                a.ActorUserId,
                a.ActorUsername,
                a.ActionType,
                a.TargetEntityType,
                a.TargetEntityId,
                a.Success,
                a.ErrorMessage,
                a.SourceIp,
                a.DetailsJson
            })
            .ToListAsync();

        var totalPages = (int)Math.Ceiling((double)total / pageSize);
        return Ok(new { total, totalPages, page, pageSize, items });
    }

    /// <summary>
    /// Returns a single audit log entry by ID. Applies the same
    /// CA-scope filter as <see cref="GetAuditLogs"/>. A CA-scoped auditor can only see
    /// entries whose <c>CertificateAuthorityId</c> is in their accessible CA set;
    /// system-wide entries (null <c>CertificateAuthorityId</c>) are rejected with 404.
    /// Returning 404 on mismatch (instead of 403) avoids leaking row existence to
    /// callers enumerating GUIDs.
    /// </summary>
    [HttpGet("{id:guid}")]
    public async Task<IActionResult> GetAuditLogById(Guid id)
    {
        if (_auditDb == null)
            return StatusCode(503, new { error = "Audit database is not configured" });

        var entry = await _auditDb.AuditLogs.FindAsync(id);
        if (entry == null)
            return NotFound();

        // CA-scope check. System-level auditors see everything; CA-
        // scoped auditors only see rows for their accessible CAs, and never system-wide
        // rows (null CertificateAuthorityId). Mismatches return 404 so audit GUIDs can
        // not be used as an existence oracle.
        var userId = _currentUser.UserId;
        if (userId.HasValue)
        {
            var isSystemLevel = await _authService.HasSystemCapabilityAsync(userId.Value, Capabilities.AuditView);
            if (!isSystemLevel)
            {
                if (entry.CertificateAuthorityId == null)
                    return NotFound();

                var accessibleCaIds = await _authService.GetAccessibleCaIdsAsync(userId.Value, Capabilities.AuditView);
                if (!accessibleCaIds.Contains(entry.CertificateAuthorityId.Value))
                    return NotFound();
            }
        }

        return Ok(entry);
    }

    /// <summary>
    /// Shared by-id lookup for the protocol/network audit tables. Mirrors the CA-label access
    /// scoping used by the list endpoints: system-level auditors see everything; CA-scoped auditors
    /// only see entries whose <c>CaLabel</c> is in their accessible set, and never null-label
    /// (system-wide) rows. Mismatches return 404 so audit ids can't be used as an existence oracle.
    /// </summary>
    private async Task<IActionResult> GetProtocolAuditByIdAsync<T>(
        DbSet<T>? set, Guid id, Func<T, string?> caLabel) where T : class
    {
        if (_auditDb == null || set == null)
            return StatusCode(503, new { error = "Audit database is not configured" });

        var entry = await set.FindAsync(id);
        if (entry == null)
            return NotFound();

        var userId = _currentUser.UserId;
        if (userId.HasValue)
        {
            var isSystemLevel = await _authService.HasSystemCapabilityAsync(userId.Value, Capabilities.AuditView);
            if (!isSystemLevel)
            {
                var label = caLabel(entry);
                if (label == null)
                    return NotFound();

                var accessibleCaIds = await _authService.GetAccessibleCaIdsAsync(userId.Value, Capabilities.AuditView);
                var accessibleLabels = await _mainDb.CertificateAuthorities
                    .Where(ca => accessibleCaIds.Contains(ca.Id))
                    .Select(ca => ca.Label)
                    .ToListAsync();
                if (!accessibleLabels.Contains(label))
                    return NotFound();
            }
        }

        return Ok(entry);
    }

    /// <summary>Returns a single EST audit entry by ID, CA-scope filtered like the list endpoint.</summary>
    [HttpGet("est/{id:guid}")]
    public Task<IActionResult> GetEstAuditById(Guid id) =>
        GetProtocolAuditByIdAsync(_auditDb?.AuditEst, id, a => a.CaLabel);

    /// <summary>Returns a single SCEP audit entry by ID, CA-scope filtered like the list endpoint.</summary>
    [HttpGet("scep/{id:guid}")]
    public Task<IActionResult> GetScepAuditById(Guid id) =>
        GetProtocolAuditByIdAsync(_auditDb?.AuditScep, id, a => a.CaLabel);

    /// <summary>Returns a single CMP audit entry by ID, CA-scope filtered like the list endpoint.</summary>
    [HttpGet("cmp/{id:guid}")]
    public Task<IActionResult> GetCmpAuditById(Guid id) =>
        GetProtocolAuditByIdAsync(_auditDb?.AuditCmp, id, a => a.CaLabel);

    /// <summary>Returns a single ACME audit entry by ID, CA-scope filtered like the list endpoint.</summary>
    [HttpGet("acme/{id:guid}")]
    public Task<IActionResult> GetAcmeAuditById(Guid id) =>
        GetProtocolAuditByIdAsync(_auditDb?.AuditAcme, id, a => a.CaLabel);

    /// <summary>Returns a single MSAE audit entry by ID, CA-scope filtered like the list endpoint.</summary>
    [HttpGet("msae/{id:guid}")]
    public Task<IActionResult> GetMsaeAuditById(Guid id) =>
        GetProtocolAuditByIdAsync(_auditDb?.AuditMsae, id, a => a.CaLabel);

    /// <summary>Returns a single network audit entry by ID, CA-scope filtered like the list endpoint.</summary>
    [HttpGet("network/{id:guid}")]
    public Task<IActionResult> GetNetworkAuditById(Guid id) =>
        GetProtocolAuditByIdAsync(_auditDb?.AuditNetwork, id, a => a.CaLabel);

    /// <summary>
    /// Returns paginated EST audit entries, optionally filtered by date range and CA.
    /// Non-system users only see logs for CAs they have auditor-level access to.
    /// </summary>
    [HttpGet("est")]
    public async Task<IActionResult> GetEstAudit(
        [FromQuery] DateTime? from, [FromQuery] DateTime? to,
        [FromQuery] Guid? caId,
        [FromQuery] int page = 1, [FromQuery] int pageSize = 50)
    {
        if (_auditDb == null)
            return StatusCode(503, new { error = "Audit database is not configured" });

        var query = _auditDb.AuditEst.AsQueryable();
        if (from.HasValue) query = query.Where(a => a.Timestamp >= from.Value);
        if (to.HasValue) query = query.Where(a => a.Timestamp <= to.Value);

        // Resolve caId to caLabel for filtering
        var filterLabel = await ResolveCaLabelAsync(caId);
        if (filterLabel != null)
            query = query.Where(a => a.CaLabel == filterLabel);

        query = await ApplyCaLabelAccessFilterAsync(query, a => a.CaLabel);

        var total = await query.CountAsync();
        var items = await query.OrderByDescending(a => a.Timestamp)
            .Skip((page - 1) * pageSize).Take(pageSize).ToListAsync();
        var totalPages = (int)Math.Ceiling((double)total / pageSize);
        return Ok(new { total, totalPages, page, pageSize, items });
    }

    /// <summary>
    /// Returns paginated MSAE (Windows autoenrollment) audit entries, optionally filtered by date
    /// range and CA. Non-system users only see logs for CAs they have auditor-level access to.
    /// </summary>
    [HttpGet("msae")]
    public async Task<IActionResult> GetMsaeAudit(
        [FromQuery] DateTime? from, [FromQuery] DateTime? to,
        [FromQuery] Guid? caId,
        [FromQuery] int page = 1, [FromQuery] int pageSize = 50)
    {
        if (_auditDb == null)
            return StatusCode(503, new { error = "Audit database is not configured" });

        var query = _auditDb.AuditMsae.AsQueryable();
        if (from.HasValue) query = query.Where(a => a.Timestamp >= from.Value);
        if (to.HasValue) query = query.Where(a => a.Timestamp <= to.Value);

        var filterLabel = await ResolveCaLabelAsync(caId);
        if (filterLabel != null)
            query = query.Where(a => a.CaLabel == filterLabel);

        query = await ApplyCaLabelAccessFilterAsync(query, a => a.CaLabel);

        var total = await query.CountAsync();
        var items = await query.OrderByDescending(a => a.Timestamp)
            .Skip((page - 1) * pageSize).Take(pageSize).ToListAsync();
        var totalPages = (int)Math.Ceiling((double)total / pageSize);
        return Ok(new { total, totalPages, page, pageSize, items });
    }

    /// <summary>
    /// Returns paginated SCEP audit entries, optionally filtered by date range and CA.
    /// Non-system users only see logs for CAs they have auditor-level access to.
    /// </summary>
    [HttpGet("scep")]
    public async Task<IActionResult> GetScepAudit(
        [FromQuery] DateTime? from, [FromQuery] DateTime? to,
        [FromQuery] Guid? caId,
        [FromQuery] int page = 1, [FromQuery] int pageSize = 50)
    {
        if (_auditDb == null)
            return StatusCode(503, new { error = "Audit database is not configured" });

        var query = _auditDb.AuditScep.AsQueryable();
        if (from.HasValue) query = query.Where(a => a.Timestamp >= from.Value);
        if (to.HasValue) query = query.Where(a => a.Timestamp <= to.Value);

        var filterLabel = await ResolveCaLabelAsync(caId);
        if (filterLabel != null)
            query = query.Where(a => a.CaLabel == filterLabel);

        query = await ApplyCaLabelAccessFilterAsync(query, a => a.CaLabel);

        var total = await query.CountAsync();
        var items = await query.OrderByDescending(a => a.Timestamp)
            .Skip((page - 1) * pageSize).Take(pageSize).ToListAsync();
        var totalPages = (int)Math.Ceiling((double)total / pageSize);
        return Ok(new { total, totalPages, page, pageSize, items });
    }

    /// <summary>
    /// Returns paginated CMP audit entries, optionally filtered by date range and CA.
    /// Non-system users only see logs for CAs they have auditor-level access to.
    /// </summary>
    [HttpGet("cmp")]
    public async Task<IActionResult> GetCmpAudit(
        [FromQuery] DateTime? from, [FromQuery] DateTime? to,
        [FromQuery] Guid? caId,
        [FromQuery] int page = 1, [FromQuery] int pageSize = 50)
    {
        if (_auditDb == null)
            return StatusCode(503, new { error = "Audit database is not configured" });

        var query = _auditDb.AuditCmp.AsQueryable();
        if (from.HasValue) query = query.Where(a => a.Timestamp >= from.Value);
        if (to.HasValue) query = query.Where(a => a.Timestamp <= to.Value);

        var filterLabel = await ResolveCaLabelAsync(caId);
        if (filterLabel != null)
            query = query.Where(a => a.CaLabel == filterLabel);

        query = await ApplyCaLabelAccessFilterAsync(query, a => a.CaLabel);

        var total = await query.CountAsync();
        var items = await query.OrderByDescending(a => a.Timestamp)
            .Skip((page - 1) * pageSize).Take(pageSize).ToListAsync();
        var totalPages = (int)Math.Ceiling((double)total / pageSize);
        return Ok(new { total, totalPages, page, pageSize, items });
    }

    /// <summary>
    /// Returns paginated ACME audit entries, optionally filtered by date range and CA.
    /// Non-system users only see logs for CAs they have auditor-level access to.
    /// </summary>
    [HttpGet("acme")]
    public async Task<IActionResult> GetAcmeAudit(
        [FromQuery] DateTime? from, [FromQuery] DateTime? to,
        [FromQuery] Guid? caId,
        [FromQuery] int page = 1, [FromQuery] int pageSize = 50)
    {
        if (_auditDb == null)
            return StatusCode(503, new { error = "Audit database is not configured" });

        var query = _auditDb.AuditAcme.AsQueryable();
        if (from.HasValue) query = query.Where(a => a.Timestamp >= from.Value);
        if (to.HasValue) query = query.Where(a => a.Timestamp <= to.Value);

        var filterLabel = await ResolveCaLabelAsync(caId);
        if (filterLabel != null)
            query = query.Where(a => a.CaLabel == filterLabel);

        query = await ApplyCaLabelAccessFilterAsync(query, a => a.CaLabel);

        var total = await query.CountAsync();
        var items = await query.OrderByDescending(a => a.Timestamp)
            .Skip((page - 1) * pageSize).Take(pageSize).ToListAsync();
        var totalPages = (int)Math.Ceiling((double)total / pageSize);
        return Ok(new { total, totalPages, page, pageSize, items });
    }

    /// <summary>
    /// Returns paginated network audit entries (IP whitelist 403 rejections), optionally filtered by date range, source IP, and CA.
    /// Non-system users only see logs for CAs they have auditor-level access to.
    /// </summary>
    [HttpGet("network")]
    public async Task<IActionResult> GetNetworkAudit(
        [FromQuery] DateTime? from, [FromQuery] DateTime? to,
        [FromQuery] string? sourceIp,
        [FromQuery] Guid? caId,
        [FromQuery] int page = 1, [FromQuery] int pageSize = 50)
    {
        if (_auditDb == null)
            return StatusCode(503, new { error = "Audit database is not configured" });

        var query = _auditDb.AuditNetwork.AsQueryable();
        if (from.HasValue) query = query.Where(a => a.Timestamp >= from.Value);
        if (to.HasValue) query = query.Where(a => a.Timestamp <= to.Value);
        if (!string.IsNullOrWhiteSpace(sourceIp)) query = query.Where(a => a.SourceIp == sourceIp);

        var filterLabel = await ResolveCaLabelAsync(caId);
        if (filterLabel != null)
            query = query.Where(a => a.CaLabel == filterLabel);

        query = await ApplyCaLabelAccessFilterAsync(query, a => a.CaLabel);

        var total = await query.CountAsync();
        var items = await query.OrderByDescending(a => a.Timestamp)
            .Skip((page - 1) * pageSize).Take(pageSize).ToListAsync();
        var totalPages = (int)Math.Ceiling((double)total / pageSize);
        return Ok(new { total, totalPages, page, pageSize, items });
    }

    /// <summary>
    /// Resolves a CA ID (GUID) to its label string from the main database.
    /// Returns null if caId is null or the CA is not found.
    /// </summary>
    private async Task<string?> ResolveCaLabelAsync(Guid? caId)
    {
        if (!caId.HasValue)
            return null;
        var ca = await _mainDb.CertificateAuthorities.FindAsync(caId.Value);
        return ca?.Label;
    }

    /// <summary>
    /// Applies group-based access filtering to a protocol audit query that has a CaLabel property.
    /// System-level auditors see all logs. CA-scoped auditors only see logs for CAs they can access.
    /// Logs with null CaLabel (system-wide events) are only visible to system-level users.
    /// </summary>
    private async Task<IQueryable<T>> ApplyCaLabelAccessFilterAsync<T>(
        IQueryable<T> query,
        System.Linq.Expressions.Expression<Func<T, string?>> caLabelSelector)
    {
        var userId = _currentUser.UserId;
        if (!userId.HasValue)
            return query;

        var isSystemLevel = await _authService.HasSystemCapabilityAsync(userId.Value, Capabilities.AuditView);
        if (isSystemLevel)
            return query;

        // Get accessible CA labels from the main DB
        var accessibleCaIds = await _authService.GetAccessibleCaIdsAsync(userId.Value, Capabilities.AuditView);
        var accessibleLabels = await _mainDb.CertificateAuthorities
            .Where(ca => accessibleCaIds.Contains(ca.Id))
            .Select(ca => ca.Label)
            .ToListAsync();

        // Build: a => accessibleLabels.Contains(a.CaLabel)
        // Null CaLabel (system-wide events) are excluded for non-system users
        var parameter = caLabelSelector.Parameters[0];
        var memberAccess = caLabelSelector.Body;

        var containsMethod = typeof(List<string?>).GetMethod("Contains", new[] { typeof(string) })!;
        var containsCall = System.Linq.Expressions.Expression.Call(
            System.Linq.Expressions.Expression.Constant(accessibleLabels),
            containsMethod,
            memberAccess);

        var lambda = System.Linq.Expressions.Expression.Lambda<Func<T, bool>>(containsCall, parameter);
        return query.Where(lambda);
    }

    /// <summary>
    /// Verifies the integrity of the audit hash chain for a given tenant.
    /// Walks records sequentially, recomputes hashes, and reports any broken links.
    /// </summary>
    [HttpGet("verify")]
    [Authorize(Policy = "SystemAdmin")]
    public async Task<IActionResult> VerifyHashChain(
        [FromQuery] Guid? tenantId,
        [FromQuery] int limit = 10000)
    {
        if (_auditDb == null)
            return BadRequest(new { error = "Audit database is not configured." });
        if (_hashChain == null)
            return BadRequest(new { error = "Hash chain service is not available." });

        var result = await _hashChain.VerifyAsync(_auditDb, tenantId, Math.Min(limit, 100000));
        return Ok(new
        {
            result.TenantId,
            result.RecordsVerified,
            BreakCount = result.Breaks.Count,
            result.Breaks,
            result.FirstRecord,
            result.LastRecord,
            Integrity = result.Breaks.Count == 0 ? "Valid" : "TAMPERED"
        });
    }
}
