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
using ModularCA.Shared.Errors;
using ModularCA.Shared.Licensing;
using ModularCA.Shared.Models.Config;
using Serilog;
using System.Text.RegularExpressions;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for managing spaces. A space groups certificate authorities and their groups
/// so their administration can be delegated within the instance.
/// All endpoints require the SystemAdmin policy.
/// </summary>
[ApiController]
[Route("api/v1/admin/spaces")]
[Authorize(Policy = "SystemAdmin")]
[NodeRole(ProcessRole.Control)]
public partial class AdminSpaceController(
    ModularCADbContext db,
    ICurrentUserService currentUser,
    IAuditService audit,
    IDistributedCache cache,
    ICaGroupAuthorizationService groupAuth,
    ISpacePolicyChangeService spacePolicyChangeService,
    IControlledUserCeremonyService controlledUserSvc,
    IEntitlementService entitlements) : ControllerBase
{
    private readonly ModularCADbContext _db = db;
    private readonly IEntitlementService _entitlements = entitlements;
    private readonly ICurrentUserService _currentUser = currentUser;
    private readonly IAuditService _audit = audit;
    private readonly IDistributedCache _cache = cache;
    private readonly ICaGroupAuthorizationService _groupAuth = groupAuth;
    private readonly ISpacePolicyChangeService _spacePolicyChangeService = spacePolicyChangeService;
    private readonly IControlledUserCeremonyService _controlledUserSvc = controlledUserSvc;

    /// <summary>
    /// Lists all spaces with summary counts for CAs, users, and certificates.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        var spaces = await _db.Spaces
            .AsNoTracking()
            .OrderBy(t => t.Name)
            .ToListAsync();

        var spaceIds = spaces.Select(t => t.Id).ToList();

        // CA counts per space
        var caCounts = await _db.CertificateAuthorities
            .Where(ca => ca.SpaceId != null && spaceIds.Contains(ca.SpaceId.Value))
            .GroupBy(ca => ca.SpaceId!.Value)
            .Select(g => new { SpaceId = g.Key, Count = g.Count() })
            .ToDictionaryAsync(x => x.SpaceId, x => x.Count);

        // Distinct user counts per space (via group memberships)
        var userCounts = await _db.CaGroupMembers
            .Where(gm => gm.Group.SpaceId != null && spaceIds.Contains(gm.Group.SpaceId.Value))
            .GroupBy(gm => gm.Group.SpaceId!.Value)
            .Select(g => new { SpaceId = g.Key, Count = g.Select(gm => gm.UserId).Distinct().Count() })
            .ToDictionaryAsync(x => x.SpaceId, x => x.Count);

        return Ok(spaces.Select(t => new
        {
            t.Id,
            t.Name,
            t.Slug,
            t.Description,
            t.IsEnabled,
            t.CreatedAt,
            t.MaxValidityDays,
            t.ValidityCeilingBehavior,
            t.RequireKeyCeremony,
            t.CeremonyRequiredApprovals,
            CaCount = caCounts.GetValueOrDefault(t.Id, 0),
            UserCount = userCounts.GetValueOrDefault(t.Id, 0)
        }));
    }

    /// <summary>
    /// Returns detailed information about a space including CA count, user count, and certificate count.
    /// </summary>
    [HttpGet("{id:guid}")]
    public async Task<IActionResult> GetById(Guid id)
    {
        var space = await _db.Spaces
            .AsNoTracking()
            .FirstOrDefaultAsync(t => t.Id == id);

        if (space == null)
            return NotFound(new { error = $"Space with ID {id} not found" });

        var caCount = await _db.CertificateAuthorities
            .CountAsync(ca => ca.SpaceId == id);

        var userCount = await _db.CaGroupMembers
            .Where(gm => gm.Group.SpaceId == id)
            .Select(gm => gm.UserId)
            .Distinct()
            .CountAsync();

        var certCount = await _db.Certificates
            .Where(c => c.CertificateAuthority != null && c.CertificateAuthority.SpaceId == id)
            .CountAsync();

        return Ok(new
        {
            space.Id,
            space.Name,
            space.Slug,
            space.Description,
            space.IsEnabled,
            space.CreatedAt,
            space.MaxValidityDays,
            space.ValidityCeilingBehavior,
            space.RequireKeyCeremony,
            space.CeremonyRequiredApprovals,
            CaCount = caCount,
            UserCount = userCount,
            CertificateCount = certCount
        });
    }

    /// <summary>
    /// Creates a new space. The slug is auto-generated from the name if not provided. Creation
    /// always succeeds; from the fifth space, without a licence carrying the multi-space feature,
    /// the response's <c>recommendation</c> says a licence is recommended
    /// (<see cref="SpaceCreationGate"/>). The slug <c>system</c> is reserved for instance CAs' groups.
    /// </summary>
    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreateSpaceRequest request)
    {
        await _currentUser.EnsureLoadedAsync();

        if (string.IsNullOrWhiteSpace(request.Name))
            return BadRequest(new { error = "Space name is required" });

        var slug = string.IsNullOrWhiteSpace(request.Slug)
            ? GenerateSlug(request.Name)
            : GenerateSlug(request.Slug);

        if (slug == ReservedInstanceSlug)
            return BadRequest(new { error = $"The slug '{ReservedInstanceSlug}' is reserved: instance CAs' groups are named with it." });

        var nameExists = await _db.Spaces.AnyAsync(t => t.Name == request.Name.Trim());
        if (nameExists)
            return Conflict(new { error = $"A space with name '{request.Name.Trim()}' already exists" });

        var slugExists = await _db.Spaces.AnyAsync(t => t.Slug == slug);
        if (slugExists)
            return Conflict(new { error = $"A space with slug '{slug}' already exists" });

        var recommendation = SpaceCreationGate.Recommendation(_entitlements, await _db.Spaces.CountAsync());

        var space = new SpaceEntity
        {
            Name = request.Name.Trim(),
            Slug = slug,
            Description = request.Description,
            IsEnabled = true,
            MaxValidityDays = request.MaxValidityDays ?? 0,
            // Shorten unless the caller asks otherwise: a new space behaves exactly as every
            // space did before this setting existed.
            ValidityCeilingBehavior = request.ValidityCeilingBehavior ?? ValidityCeilingBehavior.Shorten
        };

        _db.Spaces.Add(space);
        await _db.SaveChangesAsync();

        // === Auto-generate space-level permission groups ===
        var spaceRoles = new[]
        {
            ("Administrator", "admin", "Admin", Capabilities.AdministratorTemplate),
            ("Operator", "operator", "Operator", Capabilities.OperatorTemplate),
            ("Auditor", "auditor", "Auditor", Capabilities.AuditorTemplate),
            ("Requester", "user", "User", Capabilities.RequesterTemplate)
        };

        foreach (var (templateName, suffix, displaySuffix, _) in spaceRoles)
        {
            var groupName = $"space-{space.Slug}-{suffix}";
            if (!await _db.CaGroups.AnyAsync(g => g.Name == groupName))
            {
                var newGroup = new CaGroupEntity
                {
                    Name = groupName,
                    DisplayName = $"Space {space.Name} {displaySuffix}",
                    CertificateAuthorityId = null, // Space-wide, not CA-specific
                    TemplateName = templateName,
                    IsSystemGroup = false,
                    IsAutoGenerated = true,
                    SpaceId = space.Id,
                    RequiredQuorum = 1,
                };
                _db.CaGroups.Add(newGroup);
                await _db.SaveChangesAsync();

                BootstrapProfileSeeder.AssignBuiltInRoleToGroup(_db, newGroup, templateName);
            }
        }

        await _audit.LogAsync(AuditActionType.SpaceCreated, _currentUser.User?.Id, _currentUser.User?.Username,
            "Space", space.Id.ToString(),
            new { space.Name, space.Slug, LicenceRecommended = recommendation != null },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return CreatedAtAction(nameof(GetById), new { id = space.Id }, new
        {
            space.Id,
            space.Name,
            space.Slug,
            space.Description,
            space.IsEnabled,
            space.CreatedAt,
            space.MaxValidityDays,
            space.ValidityCeilingBehavior,
            space.RequireKeyCeremony,
            space.CeremonyRequiredApprovals,
            Recommendation = recommendation,
        });
    }

    /// <summary>
    /// Updates a space's name, description, validity ceiling or ceremony policy (space quotas were removed in 0.4.0).
    /// Disabling RequireKeyCeremony (true to false) requires step-up MFA verification
    /// to prevent accidental or malicious removal of ceremony protections. A change that needs a
    /// policy-change ceremony nobody else could approve is refused with 409 before anything is saved.
    /// </summary>
    [HttpPut("{id:guid}")]
    public async Task<IActionResult> Update(
        Guid id,
        [FromBody] UpdateSpaceRequest request,
        [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
    {
        await _currentUser.EnsureLoadedAsync();

        var space = await _db.Spaces.FindAsync(id);
        if (space == null)
            return NotFound(new { error = $"Space with ID {id} not found" });

        // Toggling a space's enabled state (e.g. re-enabling a disabled space) is a
        // high-impact action — require step-up MFA. Other edits (no IsEnabled in the
        // request) are unaffected.
        if (request.IsEnabled.HasValue && request.IsEnabled.Value != space.IsEnabled)
        {
            var op = request.IsEnabled.Value ? StepUpOps.EnableSpace : StepUpOps.DisableSpace;
            if (!await MfaStepUpController.ValidateStepUpTokenAsync(_cache, User, mfaToken, op))
                return StatusCode(403, new
                {
                    error = "MFA re-verification required to change a space's enabled state. Call /api/v1/auth/mfa/verify-stepup first.",
                    requiresStepUp = true
                });
        }

        // Compute proposed security-policy values: null if the request is not carrying a
        // change (missing or equal to current). The policy-change service treats null as
        // "not changing" on both the IsDowngrade check and the ceremony snapshot.
        bool? proposedRequireKeyCeremony =
            request.RequireKeyCeremony.HasValue && request.RequireKeyCeremony.Value != space.RequireKeyCeremony
                ? request.RequireKeyCeremony
                : null;
        int? proposedCeremonyRequiredApprovals = null;
        if (request.CeremonyRequiredApprovals.HasValue)
        {
            var normalized = Math.Max(1, request.CeremonyRequiredApprovals.Value);
            if (normalized != space.CeremonyRequiredApprovals)
                proposedCeremonyRequiredApprovals = normalized;
        }

        // ANY change to the key-ceremony policy fields is routed through a SpacePolicyChange ceremony
        // unless the caller is a system-SUPER (who may apply it directly). Unchanged values fall
        // through to the direct-write path. (Mirrors the combined settings endpoint.)
        var keyCeremonyChanged = proposedRequireKeyCeremony.HasValue || proposedCeremonyRequiredApprovals.HasValue;
        bool callerIsSuper = _currentUser.User != null && await _controlledUserSvc.IsSuperAsync(_currentUser.User.Id);
        var gateThroughCeremony = keyCeremonyChanged && !callerIsSuper;

        // Before anything is saved: a ceremony nobody else could approve is refused (409).
        if (gateThroughCeremony && _currentUser.User != null)
            await _spacePolicyChangeService.EnsureChangeApprovableAsync(space.Id, _currentUser.User.Id);

        // KC-07: Disabling ceremony requirement requires step-up MFA. Only enforced on
        // the direct-write path (system-super); the ceremony path has its
        // own multi-party quorum check and does not require step-up MFA at initiation.
        if (!gateThroughCeremony
            && request.RequireKeyCeremony.HasValue
            && space.RequireKeyCeremony
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
            var nameExists = await _db.Spaces.AnyAsync(t => t.Name == request.Name.Trim() && t.Id != id);
            if (nameExists)
                return Conflict(new { error = $"A space with name '{request.Name.Trim()}' already exists" });
            space.Name = request.Name.Trim();
        }

        if (request.Slug != null)
        {
            var slug = GenerateSlug(request.Slug);
            if (slug == ReservedInstanceSlug)
                return BadRequest(new { error = $"The slug '{ReservedInstanceSlug}' is reserved: instance CAs' groups are named with it." });
            var slugExists = await _db.Spaces.AnyAsync(t => t.Slug == slug && t.Id != id);
            if (slugExists)
                return Conflict(new { error = $"A space with slug '{slug}' already exists" });
            space.Slug = slug;
        }

        if (request.Description != null)
            space.Description = request.Description;
        if (request.MaxValidityDays.HasValue)
        {
            // Negative is rejected rather than coerced: 0 already means unlimited, so there is no
            // reading of -1 that the caller could have meant and every reading is a bug worth
            // hearing about at the boundary instead of at issuance.
            if (request.MaxValidityDays.Value < 0)
                return BadRequest(new { error = "MaxValidityDays must be 0 (unlimited) or a positive number of days." });
            space.MaxValidityDays = request.MaxValidityDays.Value;
        }
        if (request.ValidityCeilingBehavior.HasValue)
            space.ValidityCeilingBehavior = request.ValidityCeilingBehavior.Value;
        if (request.IsEnabled.HasValue)
            space.IsEnabled = request.IsEnabled.Value;

        var ceremonyWasRequired = space.RequireKeyCeremony;

        // Security-policy fields: applied inline only on the direct-write path (super, or no change).
        // When gating, they stay unchanged here and are applied when the ceremony executes.
        if (!gateThroughCeremony)
        {
            if (request.RequireKeyCeremony.HasValue)
                space.RequireKeyCeremony = request.RequireKeyCeremony.Value;
            if (request.CeremonyRequiredApprovals.HasValue)
                space.CeremonyRequiredApprovals = Math.Max(1, request.CeremonyRequiredApprovals.Value);
        }

        await _db.SaveChangesAsync();

        // Audit specifically when ceremony requirement is disabled inline
        if (ceremonyWasRequired && !space.RequireKeyCeremony)
        {
            await _audit.LogAsync(AuditActionType.SpaceUpdated, _currentUser.User?.Id, _currentUser.User?.Username,
                "Space", space.Id.ToString(),
                new { space.Name, space.Slug, CeremonyRequirementDisabled = true, DisabledBy = _currentUser.User?.Username },
                HttpContext.Connection.RemoteIpAddress?.ToString());
        }
        else
        {
            await _audit.LogAsync(AuditActionType.SpaceUpdated, _currentUser.User?.Id, _currentUser.User?.Username,
                "Space", space.Id.ToString(),
                new { space.Name, space.Slug },
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
                ceremonyId = await _spacePolicyChangeService.InitiateChangeAsync(
                    space.Id,
                    proposedRequireKeyCeremony,
                    proposedCeremonyRequiredApprovals,
                    _currentUser.User.Id,
                    _currentUser.User.Username);
            }
            catch (InvalidOperationException ex) when (ex.Message.Contains("already pending", StringComparison.OrdinalIgnoreCase))
            {
                return Conflict(new
                {
                    error = "A space policy-change ceremony is already pending for this space. Resolve or cancel it before opening a new one."
                });
            }

            Log.Warning(
                "Space policy downgrade requires ceremony: space={SpaceId} initiator={Initiator} ceremonyId={CeremonyId}",
                space.Id,
                _currentUser.User.Username,
                ceremonyId);

            return Accepted(new
            {
                ceremonyId,
                message = "Policy change requires ceremony approval. Approve via /api/v1/admin/ceremonies/{id}/approve.",
                space = new
                {
                    space.Id,
                    space.Name,
                    space.Slug,
                    space.Description,
                    space.IsEnabled,
                    space.CreatedAt,
                    space.MaxValidityDays,
                    space.ValidityCeilingBehavior,
                    space.RequireKeyCeremony,
                    space.CeremonyRequiredApprovals
                }
            });
        }

        return Ok(new
        {
            space.Id,
            space.Name,
            space.Slug,
            space.Description,
            space.IsEnabled,
            space.CreatedAt,
            space.MaxValidityDays,
            space.ValidityCeilingBehavior,
            space.RequireKeyCeremony,
            space.CeremonyRequiredApprovals
        });
    }

    /// <summary>
    /// Combined, atomic update of a space's editable settings as a single sub-resource:
    /// the validity ceiling, per-CA issuance quotas, and the space + per-CA controlled-user approval
    /// quorums. Backs the space detail page's unified Save. Because any of these fields is considered
    /// sensitive, the whole save is gated by ONE step-up MFA token (<see cref="StepUpOps.UpdateSpaceSettings"/>),
    /// so editing several fields prompts the operator exactly once. A key-ceremony downgrade by a
    /// non-system-super caller is still routed through a space policy-change ceremony (202), mirroring
    /// <see cref="Update"/>, and refused with 409 before anything is saved when nobody else could
    /// approve that ceremony. PUT replaces the settings representation with the supplied desired state.
    /// </summary>
    [HttpPut("{id:guid}/settings")]
    [RequireStepUp(StepUpOps.UpdateSpaceSettings, "id")]
    public async Task<IActionResult> UpdateSettings(Guid id, [FromBody] UpdateSpaceSettingsRequest request)
    {
        await _currentUser.EnsureLoadedAsync();

        var space = await _db.Spaces.FindAsync(id);
        if (space == null)
            return NotFound(new { error = $"Space with ID {id} not found" });

        // ── key-ceremony (security-policy) downgrade gating — mirrors Update ──
        bool? proposedRequireKeyCeremony =
            request.RequireKeyCeremony.HasValue && request.RequireKeyCeremony.Value != space.RequireKeyCeremony
                ? request.RequireKeyCeremony
                : null;
        int? proposedCeremonyRequiredApprovals = null;
        if (request.CeremonyRequiredApprovals.HasValue)
        {
            var normalized = Math.Max(1, request.CeremonyRequiredApprovals.Value);
            if (normalized != space.CeremonyRequiredApprovals)
                proposedCeremonyRequiredApprovals = normalized;
        }

        var keyCeremonyChanged = proposedRequireKeyCeremony.HasValue || proposedCeremonyRequiredApprovals.HasValue;

        // Only a system-SUPER may change ceremony/quorum thresholds directly. A regular system/CA admin
        // routes ANY such change (up or down) through a SpacePolicyChange ceremony. The single
        // UpdateSpaceSettings step-up token (validated by the filter) covers the direct-write path.
        bool callerIsSuper = _currentUser.User != null && await _controlledUserSvc.IsSuperAsync(_currentUser.User.Id);

        // ── validate user-approval quorums up-front (space is the ceiling for its CAs) ──
        if (request.ApplyUserQuorums)
        {
            if (request.UserQuorum is int tq && tq < 1)
                return BadRequest(new { error = "Space quorum must be at least 1, or null to inherit." });

            var spaceQuorumEffective = Math.Max(1, request.UserQuorum ?? 1);
            foreach (var cq in request.CaQuorums)
            {
                if (cq.Quorum is int q)
                {
                    if (q < 1)
                        return BadRequest(new { error = "A CA quorum must be at least 1, or null to inherit." });
                    if (q > spaceQuorumEffective)
                        return BadRequest(new { error = $"A CA's quorum can't exceed its space's ({spaceQuorumEffective}). Use {spaceQuorumEffective} or lower, or clear it to inherit." });
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

        // ── per-CA user-quorum targets, scoped to this space ──
        var caIds = request.CaQuorums.Select(c => c.CaId).ToList();
        var cas = request.ApplyUserQuorums
            ? await _db.CertificateAuthorities.Where(c => c.SpaceId == id && caIds.Contains(c.Id)).ToListAsync()
            : new List<CertificateAuthorityEntity>();

        // ── compute which ceremony/quorum thresholds actually change (these are ceremony-gated) ──
        bool userQuorumChanged = request.ApplyUserQuorums && request.UserQuorum != space.UserCeremonyRequiredApprovals;
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

        // Before anything is saved: a ceremony nobody else could approve is refused (409).
        if (gateThroughCeremony && _currentUser.User != null)
            await _spacePolicyChangeService.EnsureChangeApprovableAsync(space.Id, _currentUser.User.Id);

        // ── apply: non-gated space fields (always — not security thresholds) ──
        if (request.Description != null) space.Description = request.Description;
        // MaxValidityDays was missing here from the day the space ceiling landed, so the space
        // detail page — whose one Save posts to this sub-resource, not to the space PUT — sent
        // the field and had it silently dropped. The only way to set a space ceiling was the raw
        // API. Same negative guard as Update: 0 already means unlimited, so a negative value has no
        // reading the caller could have intended.
        if (request.MaxValidityDays.HasValue)
        {
            if (request.MaxValidityDays.Value < 0)
                return BadRequest(new { error = "MaxValidityDays must be 0 (unlimited) or a positive number of days." });
            space.MaxValidityDays = request.MaxValidityDays.Value;
        }
        // Not ceremony-gated. Refuse is the *stricter* of the two behaviours — it issues fewer
        // certificates, not more — and it cannot reach the enrollment protocols or the renewal
        // jobs, so turning it on cannot take a fleet offline. Gating it would put a quorum in front
        // of tightening a policy, which is the wrong way round.
        if (request.ValidityCeilingBehavior.HasValue)
            space.ValidityCeilingBehavior = request.ValidityCeilingBehavior.Value;

        var ceremonyWasRequired = space.RequireKeyCeremony;

        // ── apply: ceremony/quorum thresholds INLINE only when NOT gating (super, or nothing changed).
        // When gating, these stay unchanged here and are applied later when the ceremony executes. ──
        if (!gateThroughCeremony)
        {
            if (request.RequireKeyCeremony.HasValue) space.RequireKeyCeremony = request.RequireKeyCeremony.Value;
            if (request.CeremonyRequiredApprovals.HasValue) space.CeremonyRequiredApprovals = Math.Max(1, request.CeremonyRequiredApprovals.Value);
            if (request.ApplyUserQuorums)
            {
                space.UserCeremonyRequiredApprovals = request.UserQuorum;
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

        await _audit.LogAsync(AuditActionType.SpaceUpdated, _currentUser.User?.Id, _currentUser.User?.Username,
            "Space", space.Id.ToString(),
            new
            {
                space.Name,
                SettingsBatch = true,
                GatedThroughCeremony = gateThroughCeremony,
                CeremonyRequirementDisabled = !gateThroughCeremony && ceremonyWasRequired && !space.RequireKeyCeremony,
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
                ceremonyId = await _spacePolicyChangeService.InitiateChangeAsync(
                    space.Id,
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
                    error = "A space policy-change ceremony is already pending for this space. Resolve or cancel it before opening a new one."
                });
            }

            Log.Warning(
                "Space settings save gated ceremony/quorum changes behind a ceremony: space={SpaceId} initiator={Initiator} ceremonyId={CeremonyId}",
                space.Id, _currentUser.User.Username, ceremonyId);

            return Accepted(new
            {
                ceremonyId,
                message = "Changing ceremony or quorum thresholds requires ceremony approval. Approve via /api/v1/admin/ceremonies/{id}/approve.",
                settings = SpaceSettingsRepresentation(space),
            });
        }

        return Ok(SpaceSettingsRepresentation(space));
    }

    /// <summary>The canonical settings representation returned by the settings sub-resource.</summary>
    private static object SpaceSettingsRepresentation(SpaceEntity t) => new
    {
        t.Id,
        t.Name,
        t.Description,
        t.RequireKeyCeremony,
        t.CeremonyRequiredApprovals,
        UserQuorum = t.UserCeremonyRequiredApprovals,
    };

    /// <summary>
    /// Disables a space (soft delete). The space and its CAs remain in the database
    /// but are marked as disabled. Does not delete any data. Requires step-up MFA.
    /// </summary>
    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Disable(
        Guid id,
        [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
    {
        await _currentUser.EnsureLoadedAsync();

        var space = await _db.Spaces.FindAsync(id);
        if (space == null)
            return NotFound(new { error = $"Space with ID {id} not found" });

        if (!space.IsEnabled)
            return BadRequest(new { error = "Space is already disabled" });

        // Disabling a space is a high-impact action — require step-up MFA re-verification.
        if (!await MfaStepUpController.ValidateStepUpTokenAsync(
                _cache, User, mfaToken, StepUpOps.DisableSpace))
            return StatusCode(403, new
            {
                error = "MFA re-verification required to disable a space. Call /api/v1/auth/mfa/verify-stepup first.",
                requiresStepUp = true
            });

        space.IsEnabled = false;
        await _db.SaveChangesAsync();

        await _audit.LogAsync(AuditActionType.SpaceDisabled, _currentUser.User?.Id, _currentUser.User?.Username,
            "Space", space.Id.ToString(),
            new { space.Name, space.Slug },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new { message = $"Space '{space.Name}' has been disabled" });
    }

    /// <summary>
    /// The slug instance CAs' groups carry (<c>system_&lt;label&gt;_&lt;role&gt;</c>), which no
    /// space may take, or its CA groups would collide with theirs.
    /// </summary>
    private const string ReservedInstanceSlug = "system";

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
/// Request body for creating a new space.
/// </summary>
public class CreateSpaceRequest
{
    /// <summary>Human-readable space name. Must be unique.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Optional URL-safe slug. Auto-generated from name if not provided.</summary>
    public string? Slug { get; set; }

    /// <summary>Optional description of the space.</summary>
    public string? Description { get; set; }

    /// <summary>
    /// Longest validity, in days, a leaf certificate issued by this space's CAs may carry.
    /// 0 = unlimited. Exceeding it shortens the certificate and raises MCA-ISS-004 rather than
    /// refusing issuance; see SpaceEntity.MaxValidityDays.
    /// </summary>
    public int? MaxValidityDays { get; set; }

    /// <summary>
    /// What to do when a request exceeds <see cref="MaxValidityDays"/>: <c>Shorten</c> (the
    /// default, and the behaviour the ceiling shipped with) or <c>Refuse</c>. Refuse governs
    /// interactive and admin issuance only — ACME, EST, SCEP, CMP and the renewal jobs always
    /// shorten, because the enrolling client can neither see the space ceiling nor change its
    /// own request. See SpaceEntity.ValidityCeilingBehavior.
    /// </summary>
    public ValidityCeilingBehavior? ValidityCeilingBehavior { get; set; }
}

/// <summary>
/// Request body for updating a space. All fields are optional; only provided fields are updated.
/// </summary>
public class UpdateSpaceRequest
{
    /// <summary>New space name.</summary>
    public string? Name { get; set; }

    /// <summary>New URL-safe slug.</summary>
    public string? Slug { get; set; }

    /// <summary>New description.</summary>
    public string? Description { get; set; }

    /// <summary>
    /// Longest validity, in days, a leaf certificate issued by this space's CAs may carry.
    /// 0 = unlimited. Exceeding it shortens the certificate and raises MCA-ISS-004 rather than
    /// refusing issuance; see SpaceEntity.MaxValidityDays.
    /// </summary>
    public int? MaxValidityDays { get; set; }

    /// <summary>
    /// What to do when a request exceeds <see cref="MaxValidityDays"/>: <c>Shorten</c> (the
    /// default, and the behaviour the ceiling shipped with) or <c>Refuse</c>. Refuse governs
    /// interactive and admin issuance only — ACME, EST, SCEP, CMP and the renewal jobs always
    /// shorten, because the enrolling client can neither see the space ceiling nor change its
    /// own request. See SpaceEntity.ValidityCeilingBehavior.
    /// </summary>
    public ValidityCeilingBehavior? ValidityCeilingBehavior { get; set; }

    /// <summary>Enable or disable the space. Used to re-enable a previously disabled space.</summary>
    public bool? IsEnabled { get; set; }

    /// <summary>Whether CA creation in this space requires a key ceremony approval workflow.</summary>
    public bool? RequireKeyCeremony { get; set; }

    /// <summary>
    /// Number of approvals required for key ceremonies in this space. Values are clamped
    /// to a minimum of 1 at write time (<c>Math.Max(1, value)</c>). The initiator is never
    /// counted toward this total, so a value of 1 still requires one approver other than
    /// the person who started the ceremony.
    /// </summary>
    public int? CeremonyRequiredApprovals { get; set; }
}

/// <summary>
/// Request body for the combined space-settings sub-resource (<c>PUT spaces/{id}/settings</c>).
/// Carries the full desired state the space detail page edits in one Save: ceilings, key-ceremony
/// policy, per-CA issuance quotas, and space/CA user-approval quorums.
/// </summary>
public class UpdateSpaceSettingsRequest
{
    /// <summary>New description.</summary>
    public string? Description { get; set; }

    /// <summary>
    /// Longest validity, in days, a leaf certificate issued by this space's CAs may carry.
    /// 0 = unlimited. Absent from this request type until now, which meant the space detail
    /// page's Save posted the field and the server dropped it — see the apply block in
    /// <c>UpdateSettings</c>.
    /// </summary>
    public int? MaxValidityDays { get; set; }

    /// <summary>
    /// What to do when a request exceeds <see cref="MaxValidityDays"/>: <c>Shorten</c> (the
    /// default, and the behaviour the ceiling shipped with) or <c>Refuse</c>. Refuse governs
    /// interactive and admin issuance only — ACME, EST, SCEP, CMP and the renewal jobs always
    /// shorten, because the enrolling client can neither see the space ceiling nor change its
    /// own request. See SpaceEntity.ValidityCeilingBehavior.
    /// </summary>
    public ValidityCeilingBehavior? ValidityCeilingBehavior { get; set; }

    /// <summary>Whether CA creation in this space requires a key ceremony.</summary>
    public bool? RequireKeyCeremony { get; set; }

    /// <summary>Number of approvals required for key ceremonies (clamped to a minimum of 1).</summary>
    public int? CeremonyRequiredApprovals { get; set; }

    /// <summary>
    /// When true, the space + per-CA user-approval quorum overrides are applied (clearing the
    /// space override when <see cref="UserQuorum"/> is null). When false they are left untouched —
    /// so a client that couldn't load the quorum tree never accidentally clears it.
    /// </summary>
    public bool ApplyUserQuorums { get; set; }

    /// <summary>Space user-approval quorum override; null = inherit the System quorum.</summary>
    public int? UserQuorum { get; set; }

    /// <summary>Per-CA user-approval quorum overrides for this space's CAs.</summary>
    public List<CaQuorumItem> CaQuorums { get; set; } = new();

    /// <summary>Per-CA issuance quota updates, keyed by the CA admin group id.</summary>
    public List<CaQuotaItem> CaQuotas { get; set; } = new();
}

/// <summary>A per-CA user-approval quorum override; null <see cref="Quorum"/> inherits the space.</summary>
public class CaQuorumItem
{
    /// <summary>The certificate authority id.</summary>
    public Guid CaId { get; set; }

    /// <summary>The override, or null to inherit the space quorum.</summary>
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
