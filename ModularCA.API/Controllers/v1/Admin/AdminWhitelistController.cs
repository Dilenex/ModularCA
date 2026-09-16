using ModularCA.Shared.Authorization;
using ModularCA.Auth.Authorization;
using ModularCA.API.Filters;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using ModularCA.API.Controllers.v1.Auth;
using ModularCA.Auth.Interfaces;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Utils;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for managing IP whitelist rules stored in the <c>Whitelists</c>
/// table. Whitelists are the source of truth for per-scope IP allow-lists evaluated
/// by <c>IpWhitelistMiddleware</c>. Mutating operations (create / update / delete)
/// require a step-up MFA token via the <c>X-MFA-Token</c> header. System-default
/// rules (seeded by bootstrap) cannot be deleted — only their CIDR contents or
/// enabled flag can be edited — so the service always retains a baseline policy.
/// </summary>
[ApiController]
[Route("api/v1/admin/whitelists")]
[Authorize]
public class AdminWhitelistController(
    IWhitelistService whitelistService,
    IDistributedCache cache,
    ICurrentUserService currentUser,
    IAuditService audit,
    ModularCADbContext db,
    ILogger<AdminWhitelistController> logger) : ControllerBase
{
    private readonly IWhitelistService _whitelistService = whitelistService;
    private readonly IDistributedCache _cache = cache;
    private readonly ICurrentUserService _currentUser = currentUser;
    private readonly IAuditService _audit = audit;
    private readonly ModularCADbContext _db = db;
    private readonly ILogger<AdminWhitelistController> _logger = logger;

    /// <summary>
    /// Lists every whitelist row, ordered for admin UI display. No step-up MFA is
    /// required for read operations — callers still need the <c>CaOperator</c>
    /// policy to reach the endpoint.
    /// </summary>
    /// <param name="ct">Cancellation token propagated from the HTTP request.</param>
    /// <returns>200 OK with the full list of <see cref="WhitelistResponse"/>.</returns>
    [HttpGet]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> GetAll(CancellationToken ct)
    {
        var all = await _whitelistService.GetAllAsync(ct);
        return Ok(all.Select(ToResponse).ToList());
    }

    /// <summary>
    /// Fetches a single whitelist rule by its primary key. Returns 404 if no row
    /// with the supplied identifier exists.
    /// </summary>
    /// <param name="id">The whitelist rule identifier.</param>
    /// <param name="ct">Cancellation token propagated from the HTTP request.</param>
    /// <returns>200 OK with the <see cref="WhitelistResponse"/>, or 404 Not Found.</returns>
    [HttpGet("{id:guid}")]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> GetById(Guid id, CancellationToken ct)
    {
        var entity = await _whitelistService.GetByIdAsync(id, ct);
        if (entity == null)
            return NotFound(new { error = "Whitelist not found" });
        return Ok(ToResponse(entity));
    }

    /// <summary>
    /// Creates a new whitelist rule. Requires a step-up MFA token for the
    /// <c>create-whitelist</c> operation. The request is validated for scope-shape
    /// consistency (e.g. <c>Protocol</c> scope requires both <c>CertificateAuthorityId</c>
    /// and <c>Protocol</c>) and every CIDR must parse cleanly via
    /// <see cref="CidrMatcher.ParseNetworks(IEnumerable{string})"/>. Conflicts with
    /// the unique <c>(Scope, CertificateAuthorityId, Protocol)</c> index are
    /// surfaced as 409 with a fixed, sanitised error body — Audit Item #24: the
    /// underlying <see cref="DbUpdateException"/> inner message is logged via
    /// <see cref="ILogger"/> for operator diagnostics but never returned to the
    /// caller, since EF/MySQL inner messages can leak FK / constraint / index names
    /// and occasionally connection metadata into admin browser history.
    /// </summary>
    /// <param name="request">The create request body.</param>
    /// <param name="mfaToken">Step-up MFA token from the <c>X-MFA-Token</c> header.</param>
    /// <param name="ct">Cancellation token propagated from the HTTP request.</param>
    /// <returns>201 Created with the new row, 400 on validation failure, 403 when
    /// step-up is required, 409 on uniqueness conflict.</returns>
    [HttpPost]
    [Authorize]
    [RequireCaCapability(Capabilities.CertRevoke, CaTarget.Ca, "request.CertificateAuthorityId")]
    public async Task<IActionResult> Create(
        [FromBody] CreateWhitelistRequest request,
        [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null,
        CancellationToken ct = default)
    {
        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null) return Unauthorized();

        if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, StepUpOps.CreateWhitelist, null))
            return StatusCode(403, new { error = "MFA re-verification required. Call /auth/mfa/verify-stepup first.", requiresStepUp = true });

        if (request == null)
            return BadRequest(new { error = "Request body is required." });

        if (string.IsNullOrWhiteSpace(request.Name))
            return BadRequest(new { error = "Name is required." });

        if (request.Cidrs == null || request.Cidrs.Count == 0)
            return BadRequest(new { error = "At least one CIDR entry is required." });

        var scopeShapeError = ValidateScopeShape(request.Scope, request.CertificateAuthorityId, request.Protocol);
        if (scopeShapeError != null)
            return BadRequest(new { error = scopeShapeError });

        var cidrError = ValidateCidrs(request.Cidrs);
        if (cidrError != null)
            return BadRequest(new { error = cidrError });

        var now = DateTime.UtcNow;
        var entity = new WhitelistEntity
        {
            Id = Guid.NewGuid(),
            Name = request.Name.Trim(),
            Description = request.Description,
            Scope = request.Scope,
            CertificateAuthorityId = request.CertificateAuthorityId,
            Protocol = request.Protocol,
            IsEnabled = request.IsEnabled,
            IsSystemDefault = false,
            CreatedAt = now,
            UpdatedAt = now,
            CidrList = request.Cidrs,
        };

        try
        {
            entity = await _whitelistService.CreateAsync(entity, ct);
        }
        catch (DbUpdateException ex)
        {
            // Audit Item #24: do NOT echo the EF/MySQL inner exception to the admin
            // browser. Inner messages frequently leak FK / constraint / index names and
            // occasionally connection metadata that ends up in admin browser history.
            // Operators get the original detail via the structured log entry below.
            _logger.LogWarning(
                ex,
                "AdminWhitelistController.Create: DbUpdateException creating whitelist '{Name}' (Scope={Scope}, CaId={CaId}, Protocol={Protocol})",
                entity.Name, entity.Scope, entity.CertificateAuthorityId, entity.Protocol);
            return Conflict(new
            {
                error = "Constraint violation. Check that the whitelist name is unique and the IP CIDRs are valid.",
            });
        }

        await _audit.LogAsync(
            AuditActionType.WhitelistCreated,
            _currentUser.User?.Id,
            _currentUser.User?.Username,
            targetEntityType: "Whitelist",
            targetEntityId: entity.Id.ToString(),
            details: new { entity.Scope, entity.Name, CidrCount = entity.CidrList.Count },
            sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString());

        return Created($"/api/v1/admin/whitelists/{entity.Id}", ToResponse(entity));
    }

    /// <summary>
    /// Updates mutable fields on an existing whitelist rule. Requires a step-up
    /// MFA token for the <c>update-whitelist</c> operation, scoped to the target
    /// rule identifier. Only fields present on the request body are modified — all
    /// others retain their current value. System-default rules can be edited via
    /// this endpoint (but not deleted).
    /// </summary>
    /// <param name="id">The whitelist rule identifier.</param>
    /// <param name="request">The update request body.</param>
    /// <param name="mfaToken">Step-up MFA token from the <c>X-MFA-Token</c> header.</param>
    /// <param name="ct">Cancellation token propagated from the HTTP request.</param>
    /// <returns>200 OK with the updated row, 400 on validation failure, 403 when
    /// step-up is required, 404 if the rule does not exist.</returns>
    [HttpPut("{id:guid}")]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> Update(
        Guid id,
        [FromBody] UpdateWhitelistRequest request,
        [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null,
        CancellationToken ct = default)
    {
        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null) return Unauthorized();

        if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, StepUpOps.UpdateWhitelist, id.ToString()))
            return StatusCode(403, new { error = "MFA re-verification required. Call /auth/mfa/verify-stepup first.", requiresStepUp = true });

        if (request == null)
            return BadRequest(new { error = "Request body is required." });

        var existing = await _whitelistService.GetByIdAsync(id, ct);
        if (existing == null)
            return NotFound(new { error = "Whitelist not found" });

        if (request.Name != null)
        {
            if (string.IsNullOrWhiteSpace(request.Name))
                return BadRequest(new { error = "Name cannot be empty." });
            existing.Name = request.Name.Trim();
        }

        if (request.Description != null)
            existing.Description = request.Description;

        if (request.Cidrs != null)
        {
            if (request.Cidrs.Count == 0)
                return BadRequest(new { error = "At least one CIDR entry is required." });

            var cidrError = ValidateCidrs(request.Cidrs);
            if (cidrError != null)
                return BadRequest(new { error = cidrError });

            existing.CidrList = request.Cidrs;
        }

        if (request.IsEnabled.HasValue)
            existing.IsEnabled = request.IsEnabled.Value;

        existing.UpdatedAt = DateTime.UtcNow;

        var updated = await _whitelistService.UpdateAsync(id, existing, ct);
        if (updated == null)
            return NotFound(new { error = "Whitelist not found" });

        await _audit.LogAsync(
            AuditActionType.WhitelistUpdated,
            _currentUser.User?.Id,
            _currentUser.User?.Username,
            targetEntityType: "Whitelist",
            targetEntityId: updated.Id.ToString(),
            details: new { updated.Scope, updated.Name, CidrCount = updated.CidrList.Count, updated.IsEnabled },
            sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(ToResponse(updated));
    }

    /// <summary>
    /// Deletes a whitelist rule. Requires a step-up MFA token for the
    /// <c>delete-whitelist</c> operation, scoped to the target rule identifier.
    /// System-default rules cannot be deleted — the endpoint returns 409 and
    /// instructs the operator to disable or edit instead.
    /// </summary>
    /// <param name="id">The whitelist rule identifier.</param>
    /// <param name="mfaToken">Step-up MFA token from the <c>X-MFA-Token</c> header.</param>
    /// <param name="ct">Cancellation token propagated from the HTTP request.</param>
    /// <returns>204 No Content on success, 403 when step-up is required, 404 if
    /// the rule does not exist, 409 if the rule is a system default.</returns>
    [HttpDelete("{id:guid}")]
    [Authorize(Policy = "CaOperator")]
    public async Task<IActionResult> Delete(
        Guid id,
        [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null,
        CancellationToken ct = default)
    {
        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null) return Unauthorized();

        if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, StepUpOps.DeleteWhitelist, id.ToString()))
            return StatusCode(403, new { error = "MFA re-verification required. Call /auth/mfa/verify-stepup first.", requiresStepUp = true });

        // Peek at the row first so we can distinguish "system default" from "not found"
        // after the service refuses to delete. GetByIdAsync reads directly from the DB.
        var existing = await _whitelistService.GetByIdAsync(id, ct);

        var deleted = await _whitelistService.DeleteAsync(id, ct);
        if (!deleted)
        {
            if (existing == null)
                return NotFound(new { error = "Whitelist not found" });

            if (existing.IsSystemDefault)
                return Conflict(new { error = "System-default whitelists cannot be deleted. Disable or edit them instead." });

            // The service refused for some other reason — surface a generic 409.
            return Conflict(new { error = "Whitelist could not be deleted." });
        }

        await _audit.LogAsync(
            AuditActionType.WhitelistDeleted,
            _currentUser.User?.Id,
            _currentUser.User?.Username,
            targetEntityType: "Whitelist",
            targetEntityId: id.ToString(),
            details: existing == null
                ? null
                : new { existing.Scope, existing.Name, CidrCount = existing.CidrList.Count },
            sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString());

        return NoContent();
    }

    /// <summary>
    /// Bulk-deletes whitelist rules under a <b>single</b> step-up MFA authorization. The token is
    /// validated once for the <c>delete-whitelist</c> operation with no specific target, so the
    /// admin UI prompts for MFA only once for the whole batch (per-row deletes would each require
    /// their own target-scoped token). System-default rules in the list are skipped, not deleted.
    /// </summary>
    /// <param name="request">The list of whitelist ids to delete.</param>
    /// <param name="mfaToken">Step-up MFA token from the <c>X-MFA-Token</c> header.</param>
    /// <param name="ct">Cancellation token propagated from the HTTP request.</param>
    /// <returns>200 OK with a per-outcome summary, 400 on empty list, 403 when step-up is required.</returns>
    [HttpPost("bulk-delete")]
    [Authorize]
    [RequireCaCapability(Capabilities.CertRevoke, CaTarget.Whitelists, "request.Ids")]
    public async Task<IActionResult> BulkDelete(
        [FromBody] BulkDeleteWhitelistRequest request,
        [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null,
        CancellationToken ct = default)
    {
        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null) return Unauthorized();

        // One token covers the batch — validated for the operation with a null target.
        if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, StepUpOps.DeleteWhitelist, null))
            return StatusCode(403, new { error = "MFA re-verification required. Call /auth/mfa/verify-stepup first.", requiresStepUp = true });

        if (request?.Ids == null || request.Ids.Count == 0)
            return BadRequest(new { error = "At least one id is required." });

        int deleted = 0, skipped = 0, notFound = 0;
        foreach (var id in request.Ids.Distinct())
        {
            var existing = await _whitelistService.GetByIdAsync(id, ct);
            if (existing == null) { notFound++; continue; }
            if (existing.IsSystemDefault) { skipped++; continue; } // system defaults can't be deleted

            if (!await _whitelistService.DeleteAsync(id, ct)) { skipped++; continue; }
            deleted++;

            await _audit.LogAsync(
                AuditActionType.WhitelistDeleted,
                _currentUser.User?.Id,
                _currentUser.User?.Username,
                targetEntityType: "Whitelist",
                targetEntityId: id.ToString(),
                details: new { existing.Scope, existing.Name, CidrCount = existing.CidrList.Count },
                sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString());
        }

        return Ok(new { deleted, skipped, notFound });
    }

    /// <summary>
    /// Bulk enable/disable of whitelist rules under a <b>single</b> step-up MFA authorization. The
    /// token is validated once for the <c>update-whitelist</c> operation with no specific target, so
    /// the admin UI prompts only once for the whole batch. Rules already in the requested state are
    /// left untouched (counted as no-ops, not re-written).
    /// </summary>
    /// <param name="request">The ids to update and the target enabled flag.</param>
    /// <param name="mfaToken">Step-up MFA token from the <c>X-MFA-Token</c> header.</param>
    /// <param name="ct">Cancellation token propagated from the HTTP request.</param>
    /// <returns>200 OK with a per-outcome summary, 400 on empty list, 403 when step-up is required.</returns>
    [HttpPost("bulk-set-enabled")]
    [Authorize]
    [RequireCaCapability(Capabilities.CertRevoke, CaTarget.Whitelists, "request.Ids")]
    public async Task<IActionResult> BulkSetEnabled(
        [FromBody] BulkSetEnabledWhitelistRequest request,
        [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null,
        CancellationToken ct = default)
    {
        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null) return Unauthorized();

        // One token covers the batch — validated for the operation with a null target.
        if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, StepUpOps.UpdateWhitelist, null))
            return StatusCode(403, new { error = "MFA re-verification required. Call /auth/mfa/verify-stepup first.", requiresStepUp = true });

        if (request?.Ids == null || request.Ids.Count == 0)
            return BadRequest(new { error = "At least one id is required." });

        int updated = 0, unchanged = 0, notFound = 0;
        foreach (var id in request.Ids.Distinct())
        {
            var existing = await _whitelistService.GetByIdAsync(id, ct);
            if (existing == null) { notFound++; continue; }
            if (existing.IsEnabled == request.Enabled) { unchanged++; continue; }

            existing.IsEnabled = request.Enabled;
            existing.UpdatedAt = DateTime.UtcNow;
            if (await _whitelistService.UpdateAsync(id, existing, ct) == null) { notFound++; continue; }
            updated++;

            await _audit.LogAsync(
                AuditActionType.WhitelistUpdated,
                _currentUser.User?.Id,
                _currentUser.User?.Username,
                targetEntityType: "Whitelist",
                targetEntityId: id.ToString(),
                details: new { existing.Scope, existing.Name, existing.IsEnabled },
                sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString());
        }

        return Ok(new { updated, unchanged, notFound });
    }

    /// <summary>
    /// Maps a persistent <see cref="WhitelistEntity"/> onto the flat
    /// <see cref="WhitelistResponse"/> DTO returned to the admin UI. The JSON
    /// <c>Cidrs</c> column is decoded via <see cref="WhitelistEntity.CidrList"/>
    /// so API consumers never see the raw serialized form.
    /// </summary>
    private static WhitelistResponse ToResponse(WhitelistEntity e) => new()
    {
        Id = e.Id,
        Name = e.Name,
        Description = e.Description,
        Scope = e.Scope,
        CertificateAuthorityId = e.CertificateAuthorityId,
        Protocol = e.Protocol,
        Cidrs = e.CidrList,
        IsEnabled = e.IsEnabled,
        IsSystemDefault = e.IsSystemDefault,
        CreatedAt = e.CreatedAt,
        UpdatedAt = e.UpdatedAt,
    };

    /// <summary>
    /// Validates the shape of a scope / CA / protocol triple.
    /// <list type="bullet">
    /// <item><description><c>Protocol</c> requires a protocol string. <c>CertificateAuthorityId</c>
    /// is optional — when null, the rule applies globally to that protocol regardless of CA.</description></item>
    /// <item><description><c>Ca</c> requires a CA and must not include a protocol.</description></item>
    /// <item><description><c>System</c>, <c>Setup</c>, <c>Auth</c>, <c>Api</c>, <c>ShortUrl</c>,
    /// and <c>Admin</c> must have both fields null.</description></item>
    /// </list>
    /// Returns a human-readable error string on failure or null when the shape is valid.
    /// </summary>
    private static string? ValidateScopeShape(WhitelistScope scope, Guid? caId, string? protocol)
    {
        switch (scope)
        {
            case WhitelistScope.Protocol:
                // CaId is optional — null means "global per-protocol rule across all CAs".
                if (string.IsNullOrWhiteSpace(protocol))
                    return "Scope=Protocol requires Protocol.";
                return null;

            case WhitelistScope.Ca:
                if (!caId.HasValue)
                    return "Scope=Ca requires CertificateAuthorityId.";
                if (!string.IsNullOrWhiteSpace(protocol))
                    return "Scope=Ca must not include Protocol.";
                return null;

            case WhitelistScope.System:
            case WhitelistScope.Setup:
            case WhitelistScope.Auth:
            case WhitelistScope.Api:
            case WhitelistScope.ShortUrl:
            case WhitelistScope.Admin:
                if (caId.HasValue)
                    return $"Scope={scope} must not include CertificateAuthorityId.";
                if (!string.IsNullOrWhiteSpace(protocol))
                    return $"Scope={scope} must not include Protocol.";
                return null;

            default:
                return $"Unknown scope: {scope}.";
        }
    }

    /// <summary>
    /// Validates a list of operator-supplied CIDR strings by feeding them through
    /// <see cref="CidrMatcher.ParseNetworks(IEnumerable{string})"/>. The parser
    /// silently skips malformed entries, so a count mismatch between the input
    /// list and the parsed networks identifies the invalid offenders. Returns a
    /// human-readable error string on failure or null when every CIDR parses.
    /// </summary>
    private static string? ValidateCidrs(List<string> cidrs)
    {
        var trimmed = cidrs.Select(c => c?.Trim() ?? string.Empty).ToList();
        if (trimmed.Any(string.IsNullOrWhiteSpace))
            return "CIDR entries must not be empty or whitespace.";

        var parsed = CidrMatcher.ParseNetworks(trimmed);
        if (parsed.Count != trimmed.Count)
        {
            // Find the specific offenders by re-parsing one-at-a-time so the
            // operator sees exactly which entry is bad, not just a count.
            var invalid = trimmed
                .Where(c => CidrMatcher.ParseNetworks(new[] { c }).Count == 0)
                .ToList();
            return $"Invalid CIDR entries: {string.Join(", ", invalid)}";
        }
        return null;
    }
}

/// <summary>
/// Flat DTO returned by <see cref="AdminWhitelistController"/> read endpoints. Maps
/// directly to <see cref="WhitelistEntity"/> with the JSON CIDR column decoded into
/// a plain list.
/// </summary>
public class WhitelistResponse
{
    /// <summary>Primary key of the whitelist rule.</summary>
    public Guid Id { get; set; }

    /// <summary>Operator-facing label shown in the admin UI.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Optional free-text description of the rule's intent.</summary>
    public string? Description { get; set; }

    /// <summary>Which bucket of gated paths this rule applies to. Serialized as the enum
    /// name (e.g., "System", "Setup", "Protocol") via the global <c>JsonStringEnumConverter</c>
    /// registered in <c>StartModularCA.cs</c> so the admin UI can bind a string-valued
    /// select element to it directly, instead of receiving an opaque integer.</summary>
    public WhitelistScope Scope { get; set; }

    /// <summary>Target CA identifier for <c>Ca</c> / <c>Protocol</c> scoped rules, else null.</summary>
    public Guid? CertificateAuthorityId { get; set; }

    /// <summary>Protocol identifier for <c>Protocol</c> scoped rules, else null.</summary>
    public string? Protocol { get; set; }

    /// <summary>Parsed list of CIDR ranges. Empty list denotes an explicit block-all.</summary>
    public List<string> Cidrs { get; set; } = new();

    /// <summary>Master toggle — false means the rule is ignored entirely.</summary>
    public bool IsEnabled { get; set; }

    /// <summary>True for rows inserted by the bootstrap seeder. These cannot be deleted.</summary>
    public bool IsSystemDefault { get; set; }

    /// <summary>UTC timestamp of the row's initial insert.</summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>UTC timestamp of the row's last mutation.</summary>
    public DateTime UpdatedAt { get; set; }
}

/// <summary>
/// Request body for <c>POST /api/v1/admin/whitelists</c>. Every new row is inserted
/// with <c>IsSystemDefault = false</c>; only the bootstrap seeder creates
/// system-default rows.
/// </summary>
public class CreateWhitelistRequest
{
    /// <summary>Operator-facing label for the new rule. Required, non-empty.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Optional free-text description.</summary>
    public string? Description { get; set; }

    /// <summary>The scope bucket this rule applies to. Accepted as the enum name
    /// (e.g., "System", "Setup", "Protocol") via the global <c>JsonStringEnumConverter</c>
    /// registered in <c>StartModularCA.cs</c> — the admin UI sends a string from its select
    /// element.</summary>
    public WhitelistScope Scope { get; set; }

    /// <summary>Target CA for <c>Ca</c> / <c>Protocol</c> scoped rules.</summary>
    public Guid? CertificateAuthorityId { get; set; }

    /// <summary>Protocol identifier for <c>Protocol</c> scoped rules.</summary>
    public string? Protocol { get; set; }

    /// <summary>List of CIDR ranges; required and must contain at least one entry.</summary>
    public List<string> Cidrs { get; set; } = new();

    /// <summary>Whether the new rule is active on insert. Defaults to true.</summary>
    public bool IsEnabled { get; set; } = true;
}

/// <summary>
/// Request body for <c>PUT /api/v1/admin/whitelists/{id}</c>. Every field is
/// optional — only fields present on the request are mutated, which gives the
/// admin UI an ergonomic patch-style interface without a separate PATCH verb.
/// <c>Scope</c>, <c>CertificateAuthorityId</c>, and <c>Protocol</c> are intentionally
/// immutable via this endpoint: changing them would violate the unique composite
/// index, so operators must delete and recreate instead.
/// </summary>
public class UpdateWhitelistRequest
{
    /// <summary>New operator-facing label, or null to leave unchanged.</summary>
    public string? Name { get; set; }

    /// <summary>New description, or null to leave unchanged.</summary>
    public string? Description { get; set; }

    /// <summary>New CIDR list, or null to leave unchanged. An empty list is rejected.</summary>
    public List<string>? Cidrs { get; set; }

    /// <summary>New enabled flag, or null to leave unchanged.</summary>
    public bool? IsEnabled { get; set; }
}

/// <summary>
/// Request body for <c>POST /api/v1/admin/whitelists/bulk-delete</c>. Carries the ids to delete
/// under one step-up authorization. System-default ids are skipped server-side.
/// </summary>
public class BulkDeleteWhitelistRequest
{
    /// <summary>The whitelist rule ids to delete.</summary>
    public List<Guid> Ids { get; set; } = new();
}

/// <summary>
/// Request body for <c>POST /api/v1/admin/whitelists/bulk-set-enabled</c>. Carries the ids to
/// toggle and the target enabled state, applied under one step-up authorization.
/// </summary>
public class BulkSetEnabledWhitelistRequest
{
    /// <summary>The whitelist rule ids to update.</summary>
    public List<Guid> Ids { get; set; } = new();

    /// <summary>Target enabled state to apply to every listed rule.</summary>
    public bool Enabled { get; set; }
}
