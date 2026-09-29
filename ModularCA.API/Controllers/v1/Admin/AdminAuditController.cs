using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for querying audit logs across the main and protocol audit databases.
/// Supports CA-scoped filtering and group-based access control.
/// </summary>
[ApiController]
[Route("api/v1/admin/audit")]
[Authorize(Policy = "CaAuditor")]
[NodeRole(ProcessRole.Control)]
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
    /// Returns paginated general audit log entries, optionally filtered by date range, action type, actor, CA,
    /// target, and tenant (its CAs, the tenant itself and its groups, or records stamped with it before 0.4.0).
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
        [FromQuery] int pageSize = 50,
        [FromQuery] Guid? tenantId = null,
        [FromQuery] string? sort = null,
        [FromQuery] string? targetEntityType = null,
        [FromQuery] string? targetEntityId = null)
    {
        if (_auditDb == null)
            return StatusCode(503, new { error = "Audit database is not configured" });

        var query = _auditDb.AuditLogs.AsQueryable();

        // One entity's activity: the record drawers' Audit tab asks by target.
        if (!string.IsNullOrWhiteSpace(targetEntityType))
            query = query.Where(a => a.TargetEntityType == targetEntityType);
        if (!string.IsNullOrWhiteSpace(targetEntityId))
            query = query.Where(a => a.TargetEntityId == targetEntityId);

        // The console's tenant scope: rows stamped with that tenant (records before 0.4.0), or
        // (new records carry no tenant) about one of its CAs, the tenant itself, or one of its
        // groups. A group deleted outright is no longer known to be the tenant's.
        if (tenantId.HasValue)
        {
            var tenantCaIds = await _mainDb.CertificateAuthorities.IgnoreQueryFilters().AsNoTracking()
                .Where(ca => ca.TenantId == tenantId.Value)
                .Select(ca => ca.Id)
                .ToListAsync();
            var tenantGroupIds = (await _mainDb.CaGroups.IgnoreQueryFilters().AsNoTracking()
                    .Where(g => g.TenantId == tenantId.Value)
                    .Select(g => g.Id)
                    .ToListAsync())
                .Select(id => id.ToString()).ToList();
            var tenantKey = tenantId.Value.ToString();
            query = query.Where(a => a.TenantId == tenantId.Value
                || (a.CertificateAuthorityId != null && tenantCaIds.Contains(a.CertificateAuthorityId.Value))
                || (a.TargetEntityType == "Tenant" && a.TargetEntityId == tenantKey)
                || (a.TargetEntityType == "CaGroup" && a.TargetEntityId != null && tenantGroupIds.Contains(a.TargetEntityId)));
        }

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
        // sort: timestamp (default, newest first), actionType, actorUsername, success.
        var parsedSort = ModularCA.Core.ListSort.Parse(sort, "timestamp", "actionType", "actorUsername", "success");
        IOrderedQueryable<Shared.Entities.AuditLogEntity> ordered = parsedSort switch
        {
            ("actionType", false) => query.OrderBy(a => a.ActionType).ThenByDescending(a => a.Timestamp),
            ("actionType", true) => query.OrderByDescending(a => a.ActionType).ThenByDescending(a => a.Timestamp),
            ("actorUsername", false) => query.OrderBy(a => a.ActorUsername).ThenByDescending(a => a.Timestamp),
            ("actorUsername", true) => query.OrderByDescending(a => a.ActorUsername).ThenByDescending(a => a.Timestamp),
            ("success", false) => query.OrderBy(a => a.Success).ThenByDescending(a => a.Timestamp),
            ("success", true) => query.OrderByDescending(a => a.Success).ThenByDescending(a => a.Timestamp),
            ("timestamp", false) => query.OrderBy(a => a.Timestamp),
            _ => query.OrderByDescending(a => a.Timestamp),
        };
        var items = await ordered
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
    /// Verifies the integrity of one audit hash chain: the instance chain with no
    /// <paramref name="tenantId"/>, else that tenant's retired chain, whose sealed tail is also
    /// checked against the instance chain's succession record.
    /// Walks records sequentially, recomputes hashes, and reports any broken links. A run that
    /// stopped at <paramref name="limit"/> before the end of the chain reports
    /// <c>PartiallyChecked</c> and the count it did not examine, never <c>Valid</c>.
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

        return Ok(await VerifyChainAsync(tenantId, Math.Min(limit, 100000)));
    }

    /// <summary>
    /// Lists every audit chain with its verification: the live instance chain, then each retired
    /// per-tenant chain (sealed in 0.4.0) with the state of its tail. The retired chains are those
    /// with records and those a succession record names, so one deleted outright still reports.
    /// </summary>
    [HttpGet("verify/chains")]
    [Authorize(Policy = "SystemAdmin")]
    public async Task<IActionResult> VerifyAllChains([FromQuery] int limit = 10000)
    {
        if (_auditDb == null)
            return BadRequest(new { error = "Audit database is not configured." });
        if (_hashChain == null)
            return BadRequest(new { error = "Hash chain service is not available." });

        var retired = await _hashChain.ListRetiredChainsAsync(_auditDb);
        var names = await _mainDb.Tenants.IgnoreQueryFilters().AsNoTracking()
            .Where(t => retired.Contains(t.Id))
            .ToDictionaryAsync(t => t.Id, t => t.Name);

        var chains = new List<object> { await VerifyChainAsync(null, Math.Min(limit, 100000)) };
        foreach (var t in retired.OrderBy(t => names.GetValueOrDefault(t) ?? t.ToString()))
            chains.Add(await VerifyChainAsync(t, Math.Min(limit, 100000), names.GetValueOrDefault(t), listedAsRetired: true));
        return Ok(chains);
    }

    /// <summary>
    /// The verification report for one chain, with <c>Chain</c> ("instance" or "retired") and,
    /// for a retired chain, the state of its sealed tail. A chain <paramref name="listedAsRetired"/>
    /// with no records left is broken: retention always leaves its prune marker behind.
    /// </summary>
    private async Task<object> VerifyChainAsync(Guid? tenantId, int limit, string? tenantName = null, bool listedAsRetired = false)
    {
        var result = await _hashChain!.VerifyAsync(_auditDb!, tenantId, limit);
        var tail = tenantId is Guid t ? await _hashChain.CheckRetiredChainAsync(_auditDb!, t) : null;
        if (listedAsRetired && tail != null && result.TotalRecords == 0 && tail.State is not (RetiredChainState.TailMissing or RetiredChainState.TailAltered))
            tail = tail with { State = RetiredChainState.TailMissing, Issue = "The instance chain names this chain as retired, but none of its records remain." };
        var tailBroken = tail is { State: RetiredChainState.TailMissing or RetiredChainState.TailAltered };

        // Unverifiable is its own answer, and conflating it with tampered is what made this
        // endpoint useless: records written before the canonical form was versioned hashed a
        // timestamp at a precision the column does not keep, so they cannot be recomputed. Calling
        // that TAMPERED puts every deployment permanently in the alarm state, which is exactly how
        // a real tamper goes unnoticed.
        var integrity = result.Breaks.Count > 0 || tailBroken
            ? "TAMPERED"
            : result.Truncated ? "PartiallyChecked"
            : result.UnverifiableRecords > 0 ? "PartiallyVerifiable" : "Valid";

        return new
        {
            Chain = tenantId == null ? "instance" : "retired",
            TenantName = tenantName,
            result.Sealed,
            TailState = tail?.State.ToString(),
            TailIssue = tail?.Issue,
            result.TenantId,
            result.RecordsVerified,
            result.UnverifiableRecords,
            result.TotalRecords,
            result.Truncated,
            RecordsNotExamined = Math.Max(0, result.TotalRecords - result.RecordsVerified - result.UnverifiableRecords),
            result.Epochs,
            result.Pruned,
            result.VerifiableSince,
            BreakCount = result.Breaks.Count,
            result.Breaks,
            result.FirstRecord,
            result.LastRecord,
            Integrity = integrity,
            UnverifiableReason = result.UnverifiableRecords > 0
                ? "Written before the audit hash was versioned; the timestamp they were hashed from "
                  + "carried more precision than the column stores, so the hash cannot be reproduced. "
                  + "Their chain links are still checked."
                : null
        };
    }

    /// <summary>
    /// Begins a new epoch of the instance audit chain. A tenant's chain is retired and sealed from
    /// 0.4.0 on, so restarting one is refused (409): a record after its seal is a break.
    /// <para>
    /// Every record after the marker verifies fully and the report says so from one moment. The
    /// marker is itself an audited record naming the caller and the reason, hashed and chained
    /// forward, and the verify report counts restarts — so this is a visible act, not a way to
    /// make something disappear. Records before it keep their link checks.
    /// </para>
    /// </summary>
    [HttpPost("verify/restart")]
    [Authorize(Policy = "SystemAdmin")]
    public async Task<IActionResult> RestartHashChain(
        [FromQuery] Guid? tenantId,
        [FromBody] RestartChainRequest? request)
    {
        if (_auditDb == null)
            return BadRequest(new { error = "Audit database is not configured." });
        if (_hashChain == null)
            return BadRequest(new { error = "Hash chain service is not available." });
        if (tenantId != null)
            return Conflict(new { error = "Per-tenant audit chains are retired and sealed; only the instance chain (no tenantId) can be restarted." });

        var reason = string.IsNullOrWhiteSpace(request?.Reason) ? "Restarted by an administrator." : request!.Reason.Trim();
        if (reason.Length > 500)
            return BadRequest(new { error = "Reason must be 500 characters or fewer." });

        var sub = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        var actorId = Guid.TryParse(sub, out var parsed) ? parsed : (Guid?)null;
        var actorName = User.Identity?.Name ?? sub ?? "unknown";

        var marker = await _hashChain.RestartChainAsync(_auditDb, tenantId, actorId, actorName, reason);
        return Ok(new
        {
            marker.Id,
            marker.Timestamp,
            marker.TenantId,
            Message = "A new chain epoch begins at this record. Everything after it verifies fully.",
        });
    }

    /// <summary>Body of a chain restart request.</summary>
    public sealed class RestartChainRequest
    {
        /// <summary>Why the chain is being restarted; recorded in the marker.</summary>
        public string? Reason { get; set; }
    }
}
