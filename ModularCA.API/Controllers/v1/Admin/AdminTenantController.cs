using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using ModularCA.API.Controllers.v1.Auth;
using ModularCA.API.Filters;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Bootstrap;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Licensing;
using Serilog;
using System.Text.RegularExpressions;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for managing tenants. Tenants provide organizational isolation by
/// grouping certificate authorities and their associated groups under a single entity.
/// All endpoints require the SystemAdmin policy.
/// </summary>
[ApiController]
[Route("api/v1/admin/tenants")]
[Authorize(Policy = "SystemAdmin")]
[NodeRole(ProcessRole.Control)]
public partial class AdminTenantController(
    ModularCADbContext db,
    ICurrentUserService currentUser,
    IAuditService audit,
    IDistributedCache cache,
    ICaGroupAuthorizationService groupAuth,
    ITenantPolicyChangeService tenantPolicyChangeService,
    IControlledUserCeremonyService controlledUserSvc,
    IEntitlementService entitlements) : ControllerBase
{
    private readonly ModularCADbContext _db = db;
    private readonly IEntitlementService _entitlements = entitlements;
    private readonly ICurrentUserService _currentUser = currentUser;
    private readonly IAuditService _audit = audit;
    private readonly IDistributedCache _cache = cache;
    private readonly ICaGroupAuthorizationService _groupAuth = groupAuth;
    private readonly ITenantPolicyChangeService _tenantPolicyChangeService = tenantPolicyChangeService;
    private readonly IControlledUserCeremonyService _controlledUserSvc = controlledUserSvc;

    /// <summary>
    /// Lists all tenants with summary counts for CAs, users, and certificates.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        var tenants = await _db.Tenants
            .AsNoTracking()
            .OrderBy(t => t.Name)
            .ToListAsync();

        var tenantIds = tenants.Select(t => t.Id).ToList();

        // CA counts per tenant
        var caCounts = await _db.CertificateAuthorities
            .Where(ca => tenantIds.Contains(ca.TenantId))
            .GroupBy(ca => ca.TenantId)
            .Select(g => new { TenantId = g.Key, Count = g.Count() })
            .ToDictionaryAsync(x => x.TenantId, x => x.Count);

        // Distinct user counts per tenant (via group memberships)
        var userCounts = await _db.CaGroupMembers
            .Where(gm => tenantIds.Contains(gm.Group.TenantId))
            .GroupBy(gm => gm.Group.TenantId)
            .Select(g => new { TenantId = g.Key, Count = g.Select(gm => gm.UserId).Distinct().Count() })
            .ToDictionaryAsync(x => x.TenantId, x => x.Count);

        return Ok(tenants.Select(t => new
        {
            t.Id,
            t.Name,
            t.Slug,
            t.Description,
            t.IsEnabled,
            t.CreatedAt,
            t.MaxCertificateAuthorities,
            t.MaxCertificatesTotal,
            t.MaxUsers,
            t.MaxValidityDays,
            t.ValidityCeilingBehavior,
            t.RequireKeyCeremony,
            t.CeremonyRequiredApprovals,
            CaCount = caCounts.GetValueOrDefault(t.Id, 0),
            UserCount = userCounts.GetValueOrDefault(t.Id, 0)
        }));
    }

    /// <summary>
    /// Returns detailed information about a tenant including CA count, user count, and certificate count.
    /// </summary>
    [HttpGet("{id:guid}")]
    public async Task<IActionResult> GetById(Guid id)
    {
        var tenant = await _db.Tenants
            .AsNoTracking()
            .FirstOrDefaultAsync(t => t.Id == id);

        if (tenant == null)
            return NotFound(new { error = $"Tenant with ID {id} not found" });

        var caCount = await _db.CertificateAuthorities
            .CountAsync(ca => ca.TenantId == id);

        var userCount = await _db.CaGroupMembers
            .Where(gm => gm.Group.TenantId == id)
            .Select(gm => gm.UserId)
            .Distinct()
            .CountAsync();

        var certCount = await _db.Certificates
            .Where(c => c.CertificateAuthority != null && c.CertificateAuthority.TenantId == id)
            .CountAsync();

        return Ok(new
        {
            tenant.Id,
            tenant.Name,
            tenant.Slug,
            tenant.Description,
            tenant.IsEnabled,
            tenant.CreatedAt,
            tenant.MaxCertificateAuthorities,
            tenant.MaxCertificatesTotal,
            tenant.MaxUsers,
            tenant.MaxValidityDays,
            tenant.ValidityCeilingBehavior,
            tenant.RequireKeyCeremony,
            tenant.CeremonyRequiredApprovals,
            CaCount = caCount,
            UserCount = userCount,
            CertificateCount = certCount
        });
    }

    /// <summary>
    /// Creates a new tenant. The slug is auto-generated from the name if not provided.
    /// </summary>
    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreateTenantRequest request)
    {
        await _currentUser.EnsureLoadedAsync();

        if (string.IsNullOrWhiteSpace(request.Name))
            return BadRequest(new { error = "Tenant name is required" });

        var slug = string.IsNullOrWhiteSpace(request.Slug)
            ? GenerateSlug(request.Name)
            : GenerateSlug(request.Slug);

        var nameExists = await _db.Tenants.AnyAsync(t => t.Name == request.Name.Trim());
        if (nameExists)
            return Conflict(new { error = $"A tenant with name '{request.Name.Trim()}' already exists" });

        var slugExists = await _db.Tenants.AnyAsync(t => t.Slug == slug);
        if (slugExists)
            return Conflict(new { error = $"A tenant with slug '{slug}' already exists" });

        // Licence gate. Placed after the shape and uniqueness checks so a malformed request is
        // still reported as malformed rather than as a licensing problem — telling an operator
        // to buy something when they actually typed a duplicate name would be a poor trade.
        var refusal = TenantCreationGate.Evaluate(
            _entitlements, await _db.Tenants.CountAsync());
        if (refusal is not null)
        {
            // Audited before it is thrown. A refused attempt to exceed a licence limit is the
            // event a commercial dispute later turns on, so it is recorded whether or not the
            // operator ever reads the message.
            await _audit.LogAsync(
                AuditActionType.TenantCreated,
                _currentUser.User?.Id, _currentUser.User?.Username,
                "Tenant", request.Name.Trim(),
                new { Success = false, Refusal = refusal.Code, Error = refusal.Message },
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                success: false,
                errorMessage: refusal.Message);

            throw refusal;
        }

        var tenant = new TenantEntity
        {
            Name = request.Name.Trim(),
            Slug = slug,
            Description = request.Description,
            IsEnabled = true,
            MaxCertificateAuthorities = request.MaxCertificateAuthorities ?? 0,
            MaxCertificatesTotal = request.MaxCertificatesTotal ?? 0,
            MaxUsers = request.MaxUsers ?? 0,
            MaxValidityDays = request.MaxValidityDays ?? 0,
            // Shorten unless the caller asks otherwise: a new tenant behaves exactly as every
            // tenant did before this setting existed.
            ValidityCeilingBehavior = request.ValidityCeilingBehavior ?? ValidityCeilingBehavior.Shorten
        };

        _db.Tenants.Add(tenant);
        await _db.SaveChangesAsync();

        // === Auto-generate tenant-level permission groups ===
        var tenantRoles = new[]
        {
            ("Administrator", "admin", "Admin", Capabilities.AdministratorTemplate),
            ("Operator", "operator", "Operator", Capabilities.OperatorTemplate),
            ("Auditor", "auditor", "Auditor", Capabilities.AuditorTemplate),
            ("Requester", "user", "User", Capabilities.RequesterTemplate)
        };

        foreach (var (templateName, suffix, displaySuffix, _) in tenantRoles)
        {
            var groupName = $"org-{tenant.Slug}-{suffix}";
            if (!await _db.CaGroups.AnyAsync(g => g.Name == groupName))
            {
                var newGroup = new CaGroupEntity
                {
                    Name = groupName,
                    DisplayName = $"Org {tenant.Name} {displaySuffix}",
                    CertificateAuthorityId = null, // Tenant-wide, not CA-specific
                    TemplateName = templateName,
                    IsSystemGroup = false,
                    IsAutoGenerated = true,
                    TenantId = tenant.Id,
                    RequiredQuorum = 1,
                };
                _db.CaGroups.Add(newGroup);
                await _db.SaveChangesAsync();

                BootstrapProfileSeeder.AssignBuiltInRoleToGroup(_db, newGroup, templateName);
            }
        }

        await _audit.LogAsync(AuditActionType.TenantCreated, _currentUser.User?.Id, _currentUser.User?.Username,
            "Tenant", tenant.Id.ToString(),
            new { tenant.Name, tenant.Slug },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return CreatedAtAction(nameof(GetById), new { id = tenant.Id }, new
        {
            tenant.Id,
            tenant.Name,
            tenant.Slug,
            tenant.Description,
            tenant.IsEnabled,
            tenant.CreatedAt,
            tenant.MaxCertificateAuthorities,
            tenant.MaxCertificatesTotal,
            tenant.MaxUsers,
            tenant.MaxValidityDays,
            tenant.ValidityCeilingBehavior,
            tenant.RequireKeyCeremony,
            tenant.CeremonyRequiredApprovals
        });
    }

    /// <summary>
    /// Updates a tenant's name, description, or quota settings.
    /// Disabling RequireKeyCeremony (true to false) requires step-up MFA verification
    /// to prevent accidental or malicious removal of ceremony protections.
    /// </summary>
    [HttpPut("{id:guid}")]
    public async Task<IActionResult> Update(
        Guid id,
        [FromBody] UpdateTenantRequest request,
        [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
    {
        await _currentUser.EnsureLoadedAsync();

        var tenant = await _db.Tenants.FindAsync(id);
        if (tenant == null)
            return NotFound(new { error = $"Tenant with ID {id} not found" });

        // Toggling a tenant's enabled state (e.g. re-enabling a disabled tenant) is a
        // high-impact action — require step-up MFA. Quota-only edits (no IsEnabled in the
        // request) are unaffected.
        if (request.IsEnabled.HasValue && request.IsEnabled.Value != tenant.IsEnabled)
        {
            var op = request.IsEnabled.Value ? StepUpOps.EnableTenant : StepUpOps.DisableTenant;
            if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, op))
                return StatusCode(403, new
                {
                    error = "MFA re-verification required to change a tenant's enabled state. Call /api/v1/auth/mfa/verify-stepup first.",
                    requiresStepUp = true
                });
        }

        // Compute proposed security-policy values: null if the request is not carrying a
        // change (missing or equal to current). The policy-change service treats null as
        // "not changing" on both the IsDowngrade check and the ceremony snapshot.
        bool? proposedRequireKeyCeremony =
            request.RequireKeyCeremony.HasValue && request.RequireKeyCeremony.Value != tenant.RequireKeyCeremony
                ? request.RequireKeyCeremony
                : null;
        int? proposedCeremonyRequiredApprovals = null;
        if (request.CeremonyRequiredApprovals.HasValue)
        {
            var normalized = Math.Max(1, request.CeremonyRequiredApprovals.Value);
            if (normalized != tenant.CeremonyRequiredApprovals)
                proposedCeremonyRequiredApprovals = normalized;
        }

        // ANY change to the key-ceremony policy fields is routed through a TenantPolicyChange ceremony
        // unless the caller is a system-SUPER (who may apply it directly). Unchanged values fall
        // through to the direct-write path. (Mirrors the combined settings endpoint.)
        var keyCeremonyChanged = proposedRequireKeyCeremony.HasValue || proposedCeremonyRequiredApprovals.HasValue;
        bool callerIsSuper = _currentUser.User != null && await _controlledUserSvc.IsSuperAsync(_currentUser.User.Id);
        var gateThroughCeremony = keyCeremonyChanged && !callerIsSuper;

        // KC-07: Disabling ceremony requirement requires step-up MFA. Only enforced on
        // the direct-write path (system-super); the ceremony path has its
        // own multi-party quorum check and does not require step-up MFA at initiation.
        if (!gateThroughCeremony
            && request.RequireKeyCeremony.HasValue
            && tenant.RequireKeyCeremony
            && !request.RequireKeyCeremony.Value)
        {
            if (!await MfaStepUpController.ValidateStepUpTokenAsync(
                    _cache, User, mfaToken, StepUpOps.DisableCeremonyRequirement))
                return StatusCode(403, new
                {
                    error = "MFA re-verification required to disable key ceremony requirement. Call /api/v1/auth/mfa/verify-stepup first.",
                    requiresStepUp = true
                });
        }

        if (request.Name != null)
        {
            var nameExists = await _db.Tenants.AnyAsync(t => t.Name == request.Name.Trim() && t.Id != id);
            if (nameExists)
                return Conflict(new { error = $"A tenant with name '{request.Name.Trim()}' already exists" });
            tenant.Name = request.Name.Trim();
        }

        if (request.Slug != null)
        {
            var slug = GenerateSlug(request.Slug);
            var slugExists = await _db.Tenants.AnyAsync(t => t.Slug == slug && t.Id != id);
            if (slugExists)
                return Conflict(new { error = $"A tenant with slug '{slug}' already exists" });
            tenant.Slug = slug;
        }

        if (request.Description != null)
            tenant.Description = request.Description;
        if (request.MaxCertificateAuthorities.HasValue)
            tenant.MaxCertificateAuthorities = request.MaxCertificateAuthorities.Value;
        if (request.MaxCertificatesTotal.HasValue)
            tenant.MaxCertificatesTotal = request.MaxCertificatesTotal.Value;
        if (request.MaxUsers.HasValue)
            tenant.MaxUsers = request.MaxUsers.Value;
        if (request.MaxValidityDays.HasValue)
        {
            // Negative is rejected rather than coerced: 0 already means unlimited, so there is no
            // reading of -1 that the caller could have meant and every reading is a bug worth
            // hearing about at the boundary instead of at issuance.
            if (request.MaxValidityDays.Value < 0)
                return BadRequest(new { error = "MaxValidityDays must be 0 (unlimited) or a positive number of days." });
            tenant.MaxValidityDays = request.MaxValidityDays.Value;
        }
        if (request.ValidityCeilingBehavior.HasValue)
            tenant.ValidityCeilingBehavior = request.ValidityCeilingBehavior.Value;
        if (request.IsEnabled.HasValue)
            tenant.IsEnabled = request.IsEnabled.Value;

        var ceremonyWasRequired = tenant.RequireKeyCeremony;

        // Security-policy fields: applied inline only on the direct-write path (super, or no change).
        // When gating, they stay unchanged here and are applied when the ceremony executes.
        if (!gateThroughCeremony)
        {
            if (request.RequireKeyCeremony.HasValue)
                tenant.RequireKeyCeremony = request.RequireKeyCeremony.Value;
            if (request.CeremonyRequiredApprovals.HasValue)
                tenant.CeremonyRequiredApprovals = Math.Max(1, request.CeremonyRequiredApprovals.Value);
        }

        await _db.SaveChangesAsync();

        // Audit specifically when ceremony requirement is disabled inline
        if (ceremonyWasRequired && !tenant.RequireKeyCeremony)
        {
            await _audit.LogAsync(AuditActionType.TenantUpdated, _currentUser.User?.Id, _currentUser.User?.Username,
                "Tenant", tenant.Id.ToString(),
                new { tenant.Name, tenant.Slug, CeremonyRequirementDisabled = true, DisabledBy = _currentUser.User?.Username },
                HttpContext.Connection.RemoteIpAddress?.ToString());
        }
        else
        {
            await _audit.LogAsync(AuditActionType.TenantUpdated, _currentUser.User?.Id, _currentUser.User?.Username,
                "Tenant", tenant.Id.ToString(),
                new { tenant.Name, tenant.Slug },
                HttpContext.Connection.RemoteIpAddress?.ToString());
        }

        // If we gated a key-ceremony change behind a ceremony, open it now and return 202
        // alongside the (already-persisted) non-gated field updates.
        if (gateThroughCeremony)
        {
            if (_currentUser.User == null)
                return Unauthorized();

            Guid ceremonyId;
            try
            {
                ceremonyId = await _tenantPolicyChangeService.InitiateChangeAsync(
                    tenant.Id,
                    proposedRequireKeyCeremony,
                    proposedCeremonyRequiredApprovals,
                    _currentUser.User.Id,
                    _currentUser.User.Username);
            }
            catch (InvalidOperationException ex) when (ex.Message.Contains("already pending", StringComparison.OrdinalIgnoreCase))
            {
                return Conflict(new
                {
                    error = "A tenant policy-change ceremony is already pending for this tenant. Resolve or cancel it before opening a new one."
                });
            }

            Log.Warning(
                "Tenant policy downgrade requires ceremony: tenant={TenantId} initiator={Initiator} ceremonyId={CeremonyId}",
                tenant.Id,
                _currentUser.User.Username,
                ceremonyId);

            return Accepted(new
            {
                ceremonyId,
                message = "Policy change requires ceremony approval. Approve via /api/v1/admin/ceremonies/{id}/approve.",
                tenant = new
                {
                    tenant.Id,
                    tenant.Name,
                    tenant.Slug,
                    tenant.Description,
                    tenant.IsEnabled,
                    tenant.CreatedAt,
                    tenant.MaxCertificateAuthorities,
                    tenant.MaxCertificatesTotal,
                    tenant.MaxUsers,
                    tenant.MaxValidityDays,
                    tenant.ValidityCeilingBehavior,
                    tenant.RequireKeyCeremony,
                    tenant.CeremonyRequiredApprovals
                }
            });
        }

        return Ok(new
        {
            tenant.Id,
            tenant.Name,
            tenant.Slug,
            tenant.Description,
            tenant.IsEnabled,
            tenant.CreatedAt,
            tenant.MaxCertificateAuthorities,
            tenant.MaxCertificatesTotal,
            tenant.MaxUsers,
            tenant.MaxValidityDays,
            tenant.ValidityCeilingBehavior,
            tenant.RequireKeyCeremony,
            tenant.CeremonyRequiredApprovals
        });
    }

    /// <summary>
    /// Combined, atomic update of a tenant's editable settings as a single sub-resource:
    /// org-level ceilings, per-CA issuance quotas, and the tenant + per-CA controlled-user approval
    /// quorums. Backs the tenant detail page's unified Save. Because any of these fields is considered
    /// sensitive, the whole save is gated by ONE step-up MFA token (<see cref="StepUpOps.UpdateTenantSettings"/>),
    /// so editing several fields prompts the operator exactly once. A key-ceremony downgrade by a
    /// non-system-super caller is still routed through a tenant policy-change ceremony (202), mirroring
    /// <see cref="Update"/>. PUT replaces the settings representation with the supplied desired state.
    /// </summary>
    [HttpPut("{id:guid}/settings")]
    [RequireStepUp(StepUpOps.UpdateTenantSettings, "id")]
    public async Task<IActionResult> UpdateSettings(Guid id, [FromBody] UpdateTenantSettingsRequest request)
    {
        await _currentUser.EnsureLoadedAsync();

        var tenant = await _db.Tenants.FindAsync(id);
        if (tenant == null)
            return NotFound(new { error = $"Tenant with ID {id} not found" });

        // ── key-ceremony (security-policy) downgrade gating — mirrors Update ──
        bool? proposedRequireKeyCeremony =
            request.RequireKeyCeremony.HasValue && request.RequireKeyCeremony.Value != tenant.RequireKeyCeremony
                ? request.RequireKeyCeremony
                : null;
        int? proposedCeremonyRequiredApprovals = null;
        if (request.CeremonyRequiredApprovals.HasValue)
        {
            var normalized = Math.Max(1, request.CeremonyRequiredApprovals.Value);
            if (normalized != tenant.CeremonyRequiredApprovals)
                proposedCeremonyRequiredApprovals = normalized;
        }

        var keyCeremonyChanged = proposedRequireKeyCeremony.HasValue || proposedCeremonyRequiredApprovals.HasValue;

        // Only a system-SUPER may change ceremony/quorum thresholds directly. A regular system/CA admin
        // routes ANY such change (up or down) through a TenantPolicyChange ceremony. The single
        // UpdateTenantSettings step-up token (validated by the filter) covers the direct-write path.
        bool callerIsSuper = _currentUser.User != null && await _controlledUserSvc.IsSuperAsync(_currentUser.User.Id);

        // ── validate user-approval quorums up-front (tenant is the ceiling for its CAs) ──
        if (request.ApplyUserQuorums)
        {
            if (request.UserQuorum is int tq && tq < 1)
                return BadRequest(new { error = "Tenant quorum must be at least 1, or null to inherit." });

            var tenantQuorumEffective = Math.Max(1, request.UserQuorum ?? 1);
            foreach (var cq in request.CaQuorums)
            {
                if (cq.Quorum is int q)
                {
                    if (q < 1)
                        return BadRequest(new { error = "A CA quorum must be at least 1, or null to inherit." });
                    if (q > tenantQuorumEffective)
                        return BadRequest(new { error = $"A CA's quorum can't exceed its tenant's ({tenantQuorumEffective}). Use {tenantQuorumEffective} or lower, or clear it to inherit." });
                }
            }
        }

        // ── load + validate the CA quota groups we'll touch ──
        var groupIds = request.CaQuotas.Select(c => c.GroupId).ToList();
        var groups = await _db.CaGroups.Include(g => g.Grants)
            .Where(g => groupIds.Contains(g.Id)).ToListAsync();
        foreach (var qd in request.CaQuotas)
        {
            var group = groups.FirstOrDefault(g => g.Id == qd.GroupId);
            if (group == null)
                return NotFound(new { error = $"Group {qd.GroupId} not found." });
            if (group.TemplateName != "Administrator" && !group.Grants.Any(gr => gr.Capability == Capabilities.CaManage))
                return BadRequest(new { error = "Quotas can only be configured on admin-level groups." });
            if (qd.MaxCertificates < 0 || qd.MaxPendingRequests < 0)
                return BadRequest(new { error = "Quota values must be 0 (unlimited) or a positive integer." });
        }

        // ── per-CA user-quorum targets, scoped to this tenant ──
        var caIds = request.CaQuorums.Select(c => c.CaId).ToList();
        var cas = request.ApplyUserQuorums
            ? await _db.CertificateAuthorities.Where(c => c.TenantId == id && caIds.Contains(c.Id)).ToListAsync()
            : new List<CertificateAuthorityEntity>();

        // ── compute which ceremony/quorum thresholds actually change (these are ceremony-gated) ──
        bool userQuorumChanged = request.ApplyUserQuorums && request.UserQuorum != tenant.UserCeremonyRequiredApprovals;
        var caQuorumChanges = new List<ModularCA.Shared.Models.CaUserQuorumChange>();
        if (request.ApplyUserQuorums)
        {
            foreach (var ca in cas)
            {
                var proposedQ = request.CaQuorums.First(c => c.CaId == ca.Id).Quorum;
                if (proposedQ != ca.UserCeremonyRequiredApprovals)
                    caQuorumChanges.Add(new ModularCA.Shared.Models.CaUserQuorumChange { CaId = ca.Id, ProposedQuorum = proposedQ });
            }
        }
        var gateThroughCeremony = (keyCeremonyChanged || userQuorumChanged || caQuorumChanges.Count > 0) && !callerIsSuper;

        // ── apply: non-gated tenant fields (always — resource limits, not security thresholds) ──
        if (request.Description != null) tenant.Description = request.Description;
        if (request.MaxCertificateAuthorities.HasValue) tenant.MaxCertificateAuthorities = request.MaxCertificateAuthorities.Value;
        if (request.MaxCertificatesTotal.HasValue) tenant.MaxCertificatesTotal = request.MaxCertificatesTotal.Value;
        if (request.MaxUsers.HasValue) tenant.MaxUsers = request.MaxUsers.Value;
        // MaxValidityDays was missing here from the day the tenant ceiling landed, so the tenant
        // detail page — whose one Save posts to this sub-resource, not to PUT /tenants/{id} — sent
        // the field and had it silently dropped. The only way to set a tenant ceiling was the raw
        // API. Same negative guard as Update: 0 already means unlimited, so a negative value has no
        // reading the caller could have intended.
        if (request.MaxValidityDays.HasValue)
        {
            if (request.MaxValidityDays.Value < 0)
                return BadRequest(new { error = "MaxValidityDays must be 0 (unlimited) or a positive number of days." });
            tenant.MaxValidityDays = request.MaxValidityDays.Value;
        }
        // Not ceremony-gated. Refuse is the *stricter* of the two behaviours — it issues fewer
        // certificates, not more — and it cannot reach the enrollment protocols or the renewal
        // jobs, so turning it on cannot take a fleet offline. Gating it would put a quorum in front
        // of tightening a policy, which is the wrong way round.
        if (request.ValidityCeilingBehavior.HasValue)
            tenant.ValidityCeilingBehavior = request.ValidityCeilingBehavior.Value;

        var ceremonyWasRequired = tenant.RequireKeyCeremony;

        // ── apply: ceremony/quorum thresholds INLINE only when NOT gating (super, or nothing changed).
        // When gating, these stay unchanged here and are applied later when the ceremony executes. ──
        if (!gateThroughCeremony)
        {
            if (request.RequireKeyCeremony.HasValue) tenant.RequireKeyCeremony = request.RequireKeyCeremony.Value;
            if (request.CeremonyRequiredApprovals.HasValue) tenant.CeremonyRequiredApprovals = Math.Max(1, request.CeremonyRequiredApprovals.Value);
            if (request.ApplyUserQuorums)
            {
                tenant.UserCeremonyRequiredApprovals = request.UserQuorum;
                foreach (var ca in cas)
                    ca.UserCeremonyRequiredApprovals = request.CaQuorums.First(c => c.CaId == ca.Id).Quorum;
            }
        }

        // ── apply: per-CA issuance quotas (not a security threshold — always applied) ──
        foreach (var group in groups)
        {
            var qd = request.CaQuotas.First(c => c.GroupId == group.Id);
            group.MaxCertificates = qd.MaxCertificates;
            group.MaxPendingRequests = qd.MaxPendingRequests;
        }

        await _db.SaveChangesAsync();

        await _audit.LogAsync(AuditActionType.TenantUpdated, _currentUser.User?.Id, _currentUser.User?.Username,
            "Tenant", tenant.Id.ToString(),
            new
            {
                tenant.Name,
                SettingsBatch = true,
                GatedThroughCeremony = gateThroughCeremony,
                CeremonyRequirementDisabled = !gateThroughCeremony && ceremonyWasRequired && !tenant.RequireKeyCeremony,
                QuotasUpdated = request.CaQuotas.Count,
            },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        // ── ceremony-gated path: open ONE bundled ceremony for all the threshold changes, return 202
        // alongside the (already-persisted) non-gated changes. ──
        if (gateThroughCeremony)
        {
            if (_currentUser.User == null)
                return Unauthorized();

            Guid ceremonyId;
            try
            {
                ceremonyId = await _tenantPolicyChangeService.InitiateChangeAsync(
                    tenant.Id,
                    proposedRequireKeyCeremony,
                    proposedCeremonyRequiredApprovals,
                    _currentUser.User.Id,
                    _currentUser.User.Username,
                    userQuorumIncluded: userQuorumChanged,
                    proposedUserQuorum: userQuorumChanged ? request.UserQuorum : null,
                    caUserQuorums: caQuorumChanges);
            }
            catch (InvalidOperationException ex) when (ex.Message.Contains("already pending", StringComparison.OrdinalIgnoreCase))
            {
                return Conflict(new
                {
                    error = "A tenant policy-change ceremony is already pending for this tenant. Resolve or cancel it before opening a new one."
                });
            }

            Log.Warning(
                "Tenant settings save gated ceremony/quorum changes behind a ceremony: tenant={TenantId} initiator={Initiator} ceremonyId={CeremonyId}",
                tenant.Id, _currentUser.User.Username, ceremonyId);

            return Accepted(new
            {
                ceremonyId,
                message = "Changing ceremony or quorum thresholds requires ceremony approval. Approve via /api/v1/admin/ceremonies/{id}/approve.",
                settings = TenantSettingsRepresentation(tenant),
            });
        }

        return Ok(TenantSettingsRepresentation(tenant));
    }

    /// <summary>The canonical settings representation returned by the settings sub-resource.</summary>
    private static object TenantSettingsRepresentation(TenantEntity t) => new
    {
        t.Id,
        t.Name,
        t.Description,
        t.MaxCertificateAuthorities,
        t.MaxCertificatesTotal,
        t.MaxUsers,
        t.RequireKeyCeremony,
        t.CeremonyRequiredApprovals,
        UserQuorum = t.UserCeremonyRequiredApprovals,
    };

    /// <summary>
    /// Disables a tenant (soft delete). The tenant and its CAs remain in the database
    /// but are marked as disabled. Does not delete any data. Requires step-up MFA.
    /// </summary>
    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Disable(
        Guid id,
        [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
    {
        await _currentUser.EnsureLoadedAsync();

        var tenant = await _db.Tenants.FindAsync(id);
        if (tenant == null)
            return NotFound(new { error = $"Tenant with ID {id} not found" });

        if (!tenant.IsEnabled)
            return BadRequest(new { error = "Tenant is already disabled" });

        // Disabling a tenant is a high-impact action — require step-up MFA re-verification.
        if (!await MfaStepUpController.ValidateStepUpTokenAsync(
                _cache, User, mfaToken, StepUpOps.DisableTenant))
            return StatusCode(403, new
            {
                error = "MFA re-verification required to disable a tenant. Call /api/v1/auth/mfa/verify-stepup first.",
                requiresStepUp = true
            });

        tenant.IsEnabled = false;
        await _db.SaveChangesAsync();

        await _audit.LogAsync(AuditActionType.TenantDisabled, _currentUser.User?.Id, _currentUser.User?.Username,
            "Tenant", tenant.Id.ToString(),
            new { tenant.Name, tenant.Slug },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new { message = $"Tenant '{tenant.Name}' has been disabled" });
    }

    /// <summary>
    /// Generates a URL-safe slug from the given input string by lowercasing,
    /// replacing spaces and non-alphanumeric characters with hyphens, and trimming.
    /// </summary>
    private static string GenerateSlug(string input)
    {
        var slug = input.Trim().ToLowerInvariant();
        slug = SlugCleanupRegex().Replace(slug, "-");
        slug = SlugCollapseRegex().Replace(slug, "-");
        return slug.Trim('-');
    }

    [GeneratedRegex(@"[^a-z0-9\-]")]
    private static partial Regex SlugCleanupRegex();

    [GeneratedRegex(@"-{2,}")]
    private static partial Regex SlugCollapseRegex();
}

/// <summary>
/// Request body for creating a new tenant.
/// </summary>
public class CreateTenantRequest
{
    /// <summary>Human-readable tenant name. Must be unique.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Optional URL-safe slug. Auto-generated from name if not provided.</summary>
    public string? Slug { get; set; }

    /// <summary>Optional description of the tenant.</summary>
    public string? Description { get; set; }

    /// <summary>Maximum CAs allowed. 0 = unlimited.</summary>
    public int? MaxCertificateAuthorities { get; set; }

    /// <summary>Maximum total certificates. 0 = unlimited.</summary>
    public int? MaxCertificatesTotal { get; set; }

    /// <summary>Maximum users. 0 = unlimited.</summary>
    public int? MaxUsers { get; set; }

    /// <summary>
    /// Longest validity, in days, a leaf certificate issued by this tenant's CAs may carry.
    /// 0 = unlimited. Exceeding it shortens the certificate and raises MCA-ISS-004 rather than
    /// refusing issuance; see TenantEntity.MaxValidityDays.
    /// </summary>
    public int? MaxValidityDays { get; set; }

    /// <summary>
    /// What to do when a request exceeds <see cref="MaxValidityDays"/>: <c>Shorten</c> (the
    /// default, and the behaviour the ceiling shipped with) or <c>Refuse</c>. Refuse governs
    /// interactive and admin issuance only — ACME, EST, SCEP, CMP and the renewal jobs always
    /// shorten, because the enrolling client can neither see the tenant ceiling nor change its
    /// own request. See TenantEntity.ValidityCeilingBehavior.
    /// </summary>
    public ValidityCeilingBehavior? ValidityCeilingBehavior { get; set; }
}

/// <summary>
/// Request body for updating a tenant. All fields are optional; only provided fields are updated.
/// </summary>
public class UpdateTenantRequest
{
    /// <summary>New tenant name.</summary>
    public string? Name { get; set; }

    /// <summary>New URL-safe slug.</summary>
    public string? Slug { get; set; }

    /// <summary>New description.</summary>
    public string? Description { get; set; }

    /// <summary>New maximum CAs allowed. 0 = unlimited.</summary>
    public int? MaxCertificateAuthorities { get; set; }

    /// <summary>New maximum total certificates. 0 = unlimited.</summary>
    public int? MaxCertificatesTotal { get; set; }

    /// <summary>New maximum users. 0 = unlimited.</summary>
    public int? MaxUsers { get; set; }

    /// <summary>
    /// Longest validity, in days, a leaf certificate issued by this tenant's CAs may carry.
    /// 0 = unlimited. Exceeding it shortens the certificate and raises MCA-ISS-004 rather than
    /// refusing issuance; see TenantEntity.MaxValidityDays.
    /// </summary>
    public int? MaxValidityDays { get; set; }

    /// <summary>
    /// What to do when a request exceeds <see cref="MaxValidityDays"/>: <c>Shorten</c> (the
    /// default, and the behaviour the ceiling shipped with) or <c>Refuse</c>. Refuse governs
    /// interactive and admin issuance only — ACME, EST, SCEP, CMP and the renewal jobs always
    /// shorten, because the enrolling client can neither see the tenant ceiling nor change its
    /// own request. See TenantEntity.ValidityCeilingBehavior.
    /// </summary>
    public ValidityCeilingBehavior? ValidityCeilingBehavior { get; set; }

    /// <summary>Enable or disable the tenant. Used to re-enable a previously disabled tenant.</summary>
    public bool? IsEnabled { get; set; }

    /// <summary>Whether CA creation in this tenant requires a key ceremony approval workflow.</summary>
    public bool? RequireKeyCeremony { get; set; }

    /// <summary>
    /// Number of approvals required for key ceremonies in this tenant. Values are clamped
    /// to a minimum of 1 at write time (<c>Math.Max(1, value)</c>). The initiator is never
    /// counted toward this total, so a value of 1 still requires one approver other than
    /// the person who started the ceremony.
    /// </summary>
    public int? CeremonyRequiredApprovals { get; set; }
}

/// <summary>
/// Request body for the combined tenant-settings sub-resource (<c>PUT tenants/{id}/settings</c>).
/// Carries the full desired state the tenant detail page edits in one Save: ceilings, key-ceremony
/// policy, per-CA issuance quotas, and tenant/CA user-approval quorums.
/// </summary>
public class UpdateTenantSettingsRequest
{
    /// <summary>New description.</summary>
    public string? Description { get; set; }

    /// <summary>New maximum CAs allowed. 0 = unlimited.</summary>
    public int? MaxCertificateAuthorities { get; set; }

    /// <summary>New maximum total certificates. 0 = unlimited.</summary>
    public int? MaxCertificatesTotal { get; set; }

    /// <summary>New maximum users. 0 = unlimited.</summary>
    public int? MaxUsers { get; set; }

    /// <summary>
    /// Longest validity, in days, a leaf certificate issued by this tenant's CAs may carry.
    /// 0 = unlimited. Absent from this request type until now, which meant the tenant detail
    /// page's Save posted the field and the server dropped it — see the apply block in
    /// <c>UpdateSettings</c>.
    /// </summary>
    public int? MaxValidityDays { get; set; }

    /// <summary>
    /// What to do when a request exceeds <see cref="MaxValidityDays"/>: <c>Shorten</c> (the
    /// default, and the behaviour the ceiling shipped with) or <c>Refuse</c>. Refuse governs
    /// interactive and admin issuance only — ACME, EST, SCEP, CMP and the renewal jobs always
    /// shorten, because the enrolling client can neither see the tenant ceiling nor change its
    /// own request. See TenantEntity.ValidityCeilingBehavior.
    /// </summary>
    public ValidityCeilingBehavior? ValidityCeilingBehavior { get; set; }

    /// <summary>Whether CA creation in this tenant requires a key ceremony.</summary>
    public bool? RequireKeyCeremony { get; set; }

    /// <summary>Number of approvals required for key ceremonies (clamped to a minimum of 1).</summary>
    public int? CeremonyRequiredApprovals { get; set; }

    /// <summary>
    /// When true, the tenant + per-CA user-approval quorum overrides are applied (clearing the
    /// tenant override when <see cref="UserQuorum"/> is null). When false they are left untouched —
    /// so a client that couldn't load the quorum tree never accidentally clears it.
    /// </summary>
    public bool ApplyUserQuorums { get; set; }

    /// <summary>Tenant user-approval quorum override; null = inherit the System quorum.</summary>
    public int? UserQuorum { get; set; }

    /// <summary>Per-CA user-approval quorum overrides for this tenant's CAs.</summary>
    public List<CaQuorumItem> CaQuorums { get; set; } = new();

    /// <summary>Per-CA issuance quota updates, keyed by the CA admin group id.</summary>
    public List<CaQuotaItem> CaQuotas { get; set; } = new();
}

/// <summary>A per-CA user-approval quorum override; null <see cref="Quorum"/> inherits the tenant.</summary>
public class CaQuorumItem
{
    /// <summary>The certificate authority id.</summary>
    public Guid CaId { get; set; }

    /// <summary>The override, or null to inherit the tenant quorum.</summary>
    public int? Quorum { get; set; }
}

/// <summary>A per-CA issuance quota update, addressed by the CA admin group id.</summary>
public class CaQuotaItem
{
    /// <summary>The CA admin group id the quota is configured on.</summary>
    public Guid GroupId { get; set; }

    /// <summary>Maximum active certificates. 0 = unlimited.</summary>
    public int MaxCertificates { get; set; }

    /// <summary>Maximum pending CSRs. 0 = unlimited.</summary>
    public int MaxPendingRequests { get; set; }
}
