using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;
using ModularCA.API.Controllers.v1.Auth;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using Microsoft.EntityFrameworkCore;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Models;
using Serilog;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using System.ComponentModel.DataAnnotations;
using ModularCA.Shared.Models.Revocation;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for managing key ceremony workflows. Key ceremonies enforce multi-party
/// approval (quorum) for catastrophic CA operations such as root CA creation and CA revocation.
/// Self-approval is forbidden and the ceremony audit trail is permanent.
/// Scoped to space: CA admins see ceremonies for their space(s); system admins see all.
/// </summary>
[ApiController]
[Route("api/v1/admin/ceremonies")]
[Authorize]
[NodeRole(ProcessRole.Control)]
public class AdminKeyCeremonyController : ControllerBase
{
    private readonly IKeyCeremonyService _ceremonySvc;
    private readonly ICurrentUserService _currentUser;
    private readonly IAuditService _audit;
    private readonly IDistributedCache _cache;
    private readonly ISecurityAlertService _alertService;
    private readonly CaCreationService _caCreation;
    private readonly ModularCA.Database.ModularCADbContext _db;
    private readonly ICaGroupAuthorizationService _groupAuth;
    private readonly ISshCaService _sshCaService;
    private readonly ICertificateRevocationService _revocationSvc;
    private readonly ISpacePolicyChangeService _spacePolicyChangeSvc;
    private readonly ModularCA.Auth.Authorization.IControlledUserCeremonyService _controlledUserSvc;

    /// <summary>
    /// Initializes a new instance of <see cref="AdminKeyCeremonyController"/>.
    /// </summary>
    public AdminKeyCeremonyController(
        IKeyCeremonyService ceremonySvc,
        ICurrentUserService currentUser,
        IAuditService audit,
        IDistributedCache cache,
        ISecurityAlertService alertService,
        CaCreationService caCreation,
        ModularCA.Database.ModularCADbContext db,
        ICaGroupAuthorizationService groupAuth,
        ISshCaService sshCaService,
        ICertificateRevocationService revocationSvc,
        ISpacePolicyChangeService spacePolicyChangeSvc,
        ModularCA.Auth.Authorization.IControlledUserCeremonyService controlledUserSvc)
    {
        _ceremonySvc = ceremonySvc;
        _currentUser = currentUser;
        _audit = audit;
        _cache = cache;
        _alertService = alertService;
        _caCreation = caCreation;
        _db = db;
        _groupAuth = groupAuth;
        _sshCaService = sshCaService;
        _revocationSvc = revocationSvc;
        _spacePolicyChangeSvc = spacePolicyChangeSvc;
        _controlledUserSvc = controlledUserSvc;
    }

    /// <summary>
    /// Initiates a new key ceremony for CA creation (<c>CreateRootCA</c> or <c>CreateIntermediateCA</c>).
    /// Requires step-up MFA verification. Operation types with their own initiation path
    /// (controlled-user changes, space policy changes, CA revocation, SSH CAs) are refused with 400:
    /// those paths classify, validate and scope the ceremony, which this generic body cannot.
    /// The parameters name the CA's scope explicitly: a space id, or scope "instance" (400 otherwise).
    /// The label, name and CA certificate profile are checked now (<see cref="RefuseCaCreationParametersAsync"/>),
    /// so a ceremony that could never execute is not put to the approvers. A control character in
    /// the description, target id or a parameter text field is refused with 400. A ceremony too
    /// few other accounts could approve is refused with 409 and nothing is opened
    /// (<see cref="ModularCA.API.Services.CeremonyRefusalResponse"/>).
    /// </summary>
    [HttpPost]
    [Authorize]
    public async Task<IActionResult> Initiate(
        [FromBody] InitiateCeremonyRequest request,
        [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
    {
        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null) return Unauthorized();

        if (!await MfaStepUpController.ValidateStepUpTokenAsync(
                _cache, User, mfaToken, StepUpOps.InitiateCeremony))
            return StatusCode(403, new
            {
                error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.",
                requiresStepUp = true
            });

        if (string.IsNullOrWhiteSpace(request.OperationType))
            return BadRequest(new { error = "OperationType is required." });
        if (!GenericOperationTypes.Contains(request.OperationType))
            return BadRequest(new { error = $"Operation type '{request.OperationType}' cannot be initiated here; use its dedicated endpoint." });
        if (request.Parameters == null)
            return BadRequest(new { error = "Parameters are required for a CA-creation ceremony." });
        if (KeyCeremonyParameters.ScopeError(request.Parameters.SpaceId, request.Parameters.Scope) is string scopeError)
            return BadRequest(new { error = scopeError });
        if (ModularCA.Shared.Utils.DnComponentSanitizer.HasControlCharacter(request.Description)
            || ModularCA.Shared.Utils.DnComponentSanitizer.HasControlCharacter(request.TargetEntityId))
            return BadRequest(new { error = "Description and TargetEntityId must not contain control characters." });

        // The space and parent are in the body, so the route policy cannot scope this action;
        // the same rules as direct CA creation apply (see CaCreationAccess). Other operation
        // types need ca.manage space-wide for the ceremony's space.
        if (!await MayInitiateAsync(request.OperationType, request.Parameters, _currentUser.User.Id))
        {
            Log.Warning("Authorization denied for user {UserId} ({Username}) initiating ceremony {OperationType} in space {SpaceId}",
                _currentUser.User.Id, _currentUser.User.Username, request.OperationType, request.Parameters?.SpaceId);
            return StatusCode(403, new { error = "You need ca.manage for the ceremony's space, and for the parent CA when it belongs to another space." });
        }

        if (await RefuseCaCreationParametersAsync(_caCreation, request.Parameters) is { } refused)
            return refused;

        try
        {
            var parametersJson = request.Parameters != null
                ? JsonSerializer.Serialize(request.Parameters)
                : "{}";

            var ceremony = await _ceremonySvc.InitiateAsync(
                request.OperationType,
                request.Description ?? string.Empty,
                request.TargetEntityId ?? string.Empty,
                _currentUser.User.Id,
                _currentUser.User.Username ?? string.Empty,
                parametersJson);

            _ = _alertService.RaiseAlertAsync(
                "KeyCeremonyInitiated",
                AlertSeverity.Warning,
                $"Key ceremony '{request.OperationType}' initiated by {_currentUser.User.Username}",
                new { CeremonyId = ceremony.Id, request.OperationType, request.TargetEntityId });

            return Ok(new
            {
                ceremony.Id,
                ceremony.OperationType,
                ceremony.Description,
                ceremony.TargetEntityId,
                ceremony.RequiredApprovals,
                ceremony.CurrentApprovals,
                ceremony.Status,
                ceremony.CreatedAt,
                ceremony.ExpiresAt,
                message = ceremony.Status == "Approved"
                    ? "Ceremony auto-approved (quorum = 1). Ready for execution."
                    : $"Ceremony created. {ceremony.RequiredApprovals} approval(s) required."
            });
        }
        catch (ModularCA.Shared.Errors.CeremonyQuorumUnreachableException ex)
        {
            return Conflict(await ModularCA.API.Services.CeremonyRefusalResponse.BuildAsync(HttpContext, ex));
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to create key ceremony");
            return StatusCode(500, new { error = "An unexpected error occurred while creating the key ceremony. Please try again." });
        }
    }

    /// <summary>
    /// Null when CA-creation parameters would pass the checks execution applies, else the response
    /// to send now, before anyone approves: 400 for a control character in a text field, an
    /// invalid or reserved label, or a name constraint <see cref="ModularCA.Shared.Utils.NameConstraintRules"/> refuses,
    /// 409 for a label or name another CA has, 404 for a CA certificate profile outside the new
    /// CA's scope.
    /// </summary>
    internal static async Task<IActionResult?> RefuseCaCreationParametersAsync(CaCreationService caCreation, KeyCeremonyParameters parameters)
    {
        if (parameters.ControlCharacterError() is string controlError)
            return new BadRequestObjectResult(new { error = controlError });
        if ((ModularCA.Shared.Utils.NameConstraintRules.ListError(parameters.NameConstraintsPermitted, nameof(parameters.NameConstraintsPermitted))
            ?? ModularCA.Shared.Utils.NameConstraintRules.ListError(parameters.NameConstraintsExcluded, nameof(parameters.NameConstraintsExcluded))) is string ncError)
            return new BadRequestObjectResult(new { error = ncError });
        try
        {
            await caCreation.EnsureNamingAsync(parameters.SubjectCN, parameters.Label);
            if (parameters.ParentCaId is Guid parentCaId)
                await caCreation.EnsureCaCertProfileAdmittedAsync(parameters.CertProfileId, parentCaId, parameters.SpaceId);
            return null;
        }
        catch (ArgumentException ex)
        {
            return new BadRequestObjectResult(new { error = ex.Message });
        }
        catch (ModularCA.Shared.Errors.ResourceConflictException ex)
        {
            return new ConflictObjectResult(new { error = ex.Message, code = ex.Code });
        }
        catch (ModularCA.Shared.Errors.ResourceNotFoundException ex)
        {
            return new NotFoundObjectResult(new { error = ex.Message, code = ex.Code });
        }
    }

    /// <summary>The operation types the generic <see cref="Initiate"/> accepts.</summary>
    private static readonly HashSet<string> GenericOperationTypes = new(StringComparer.Ordinal) { "CreateRootCA", "CreateIntermediateCA" };

    /// <summary>
    /// Lists key ceremonies scoped by space. System admins see all ceremonies; system-wide
    /// <c>ca.manage</c> holders see every other ceremony, and space-level CA admins those of their
    /// space(s). Controlled-user ceremonies are shown only to a system admin, their initiator, and
    /// whoever holds a tier that could approve them (see <c>CanAccessCeremonyAsync</c>), all under
    /// the worn badge. Each row carries <c>canApprove</c> for the caller and, for a controlled-user
    /// ceremony they may not approve, the reason (<c>approvalRefusal</c>). Authorization is per ceremony, so the route carries plain <c>[Authorize]</c>: a CA-scoped
    /// policy cannot resolve a CA here.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> List([FromQuery] string? status = null)
    {
        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null) return Unauthorized();

        // Expire stale ceremonies before listing
        await _ceremonySvc.ExpireStaleCeremoniesAsync();

        List<KeyCeremonyEntity> ceremonies;

        if (await _groupAuth.IsSystemAdminAsync(_currentUser.User.Id))
        {
            ceremonies = new List<KeyCeremonyEntity>();
            foreach (var c in await _ceremonySvc.ListAsync(status))
                if (!IsControlledUserChange(c) || await CanAccessCeremonyAsync(c))
                    ceremonies.Add(c);
        }
        else if (await _groupAuth.HasSystemCapabilityAsync(_currentUser.User.Id, Capabilities.CaManage))
        {
            ceremonies = new List<KeyCeremonyEntity>();
            foreach (var c in await _ceremonySvc.ListAsync(status))
                if (!IsControlledUserChange(c) || await CanAccessCeremonyAsync(c))
                    ceremonies.Add(c);
        }
        else
        {
            var spaceIds = await GetUserCeremonySpaceIdsAsync(_currentUser.User.Id);
            var tiers = await _controlledUserSvc.GetActorTiersAsync(_currentUser.User.Id);
            var tierSpaceIds = tiers.Where(t => t.SpaceId != null).Select(t => t.SpaceId!.Value);
            var candidateSpaces = spaceIds.Union(tierSpaceIds).ToList();
            // Instance ceremonies (no space) are candidates for a caller with instance scope or a
            // tier on an instance CA; CanAccessCeremonyAsync decides each one.
            var includeInstance = (ModularCA.Auth.Authorization.SpaceFence.From(HttpContext)?.Allows(null) ?? false) || tiers.Any(t => t.SpaceId == null);
            if (candidateSpaces.Count == 0 && !includeInstance)
                return Ok(Array.Empty<object>());

            var fullSpaces = spaceIds.ToHashSet();
            ceremonies = new List<KeyCeremonyEntity>();
            foreach (var c in await _ceremonySvc.ListBySpacesAsync(candidateSpaces, status, includeInstance))
                if ((!IsControlledUserChange(c) && c.SpaceId is Guid ct && fullSpaces.Contains(ct)) || await CanAccessCeremonyAsync(c))
                    ceremonies.Add(c);
        }

        var viewerId = _currentUser.User.Id;
        var approvalMap = new Dictionary<Guid, (bool CanApprove, string? Refusal)>();
        foreach (var c in ceremonies)
        {
            approvalMap[c.Id] = await ComputeCanApproveAsync(c, viewerId);
        }

        var result = ceremonies.Select(c => new
        {
            c.Id,
            c.OperationType,
            CeremonyType = (c.CeremonyType ?? ModularCA.Shared.Enums.CeremonyType.CaCreation).ToString(),
            c.Description,
            c.TargetEntityId,
            c.InitiatedByUserId,
            c.InitiatedByUsername,
            c.RequiredApprovals,
            c.CurrentApprovals,
            c.Status,
            c.CreatedAt,
            c.ExpiresAt,
            c.ExecutedAt,
            c.ApprovalsJson,
            CanApprove = approvalMap[c.Id].CanApprove,
            ApprovalRefusal = approvalMap[c.Id].Refusal,
        });

        return Ok(result);
    }

    /// <summary>
    /// Retrieves full detail for a single key ceremony, including the approval records, and for a
    /// controlled-user ceremony the named scope of its affected tier (<c>tierScope</c>) and why the
    /// caller may not approve it (<c>approvalRefusal</c>), if so. A pending ceremony also reports
    /// whether it can still reach its quorum (<c>quorumReachable</c>), from the approvals it still
    /// needs (<c>approvalsStillNeeded</c>) and the accounts that could still give one
    /// (<c>eligibleApprovers</c>, see <see cref="CeremonyQuorumGuard"/>); all three are null otherwise.
    /// Enforces space-level access: only system admins or space-level CA admins can view.
    /// </summary>
    [HttpGet("{id:guid}")]
    public async Task<IActionResult> GetById(Guid id)
    {
        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null) return Unauthorized();

        var ceremony = await _ceremonySvc.GetByIdAsync(id);
        if (ceremony == null)
            return NotFound(new { error = "Ceremony not found." });

        if (!await CanAccessCeremonyAsync(ceremony))
            return StatusCode(403, new { error = "You do not have access to this ceremony." });

        var approval = await ComputeCanApproveAsync(ceremony, _currentUser.User.Id);
        var reach = ceremony.Status == "Pending" ? await new CeremonyQuorumGuard(_db).AssessPendingAsync(ceremony) : null;
        return Ok(new
        {
            ceremony.Id,
            ceremony.OperationType,
            CeremonyType = (ceremony.CeremonyType ?? ModularCA.Shared.Enums.CeremonyType.CaCreation).ToString(),
            ceremony.Description,
            ceremony.TargetEntityId,
            ceremony.InitiatedByUserId,
            ceremony.InitiatedByUsername,
            ceremony.RequiredApprovals,
            ceremony.CurrentApprovals,
            ceremony.Status,
            ceremony.CreatedAt,
            ceremony.ExpiresAt,
            ceremony.ExecutedAt,
            ceremony.ParametersJson,
            ceremony.ApprovalsJson,
            CanApprove = approval.CanApprove,
            ApprovalRefusal = approval.Refusal,
            QuorumReachable = reach?.Reachable,
            ApprovalsStillNeeded = reach?.RequiredApprovals,
            EligibleApprovers = reach?.EligibleApprovers,
            TierScope = IsControlledUserChange(ceremony) && _controlledUserSvc.DescribeCeremony(ceremony).Minted is { } minted
                ? await _controlledUserSvc.DescribeScopeAsync(minted)
                : null,
        });
    }

    /// <summary>
    /// Reports whether a key ceremony the caller opened in a scope could be approved: the scope's
    /// requirement and quorum, and how many accounts other than the caller could approve
    /// (<c>eligibleApprovers</c>, see <see cref="CeremonyQuorumGuard"/>). The scope is the space
    /// in the route, or the instance without one. The console reads it to warn before the
    /// requirement is turned on where nobody else could approve. Needs <c>ca.manage</c> across
    /// the scope (403 otherwise); an unknown space is 404.
    /// </summary>
    [HttpGet("approvers")]
    [HttpGet("approvers/{spaceId:guid}")]
    public async Task<IActionResult> Approvers([FromRoute] Guid? spaceId = null)
    {
        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null) return Unauthorized();
        var userId = _currentUser.User.Id;
        if (!await _groupAuth.IsSystemAdminAsync(userId)
            && !await _groupAuth.HasScopeCapabilityAsync(userId, spaceId, Capabilities.CaManage))
            return StatusCode(403, new { error = "You need ca.manage for this scope." });

        var policy = await new ModularCA.Database.EffectivePolicyResolver(_db).ResolveAsync(spaceId);
        if (!policy.Found)
            return NotFound(new { error = $"Space '{spaceId}' not found." });

        // Any CA operation: they share one approval rule.
        var eligible = await new CeremonyQuorumGuard(_db).EligibleApproversAsync("CreateIntermediateCA", spaceId, null, userId);
        var required = Math.Max(1, policy.CeremonyRequiredApprovals);
        return Ok(new
        {
            scope = spaceId == null ? "instance" : "space",
            spaceId,
            requireKeyCeremony = policy.RequireKeyCeremony,
            requiredApprovals = required,
            eligibleApprovers = eligible.Count,
            reachable = eligible.Count >= required,
        });
    }

    /// <summary>
    /// Whether <paramref name="viewerId"/> may approve <paramref name="ceremony"/> right now:
    /// pending, not the initiator, has ceremony access, and no refusal reason, which is returned
    /// as <c>Refusal</c>: for ControlledUserChange, <see cref="IControlledUserCeremonyService.ApprovalRefusalAsync"/>
    /// (an approving tier, and not a resetter of a promoted account's credentials); for a policy
    /// change, <see cref="PolicyApprovalRefusalAsync"/> (admin rank at its scope).
    /// Single source of approver eligibility for the UI.
    /// </summary>
    private async Task<(bool CanApprove, string? Refusal)> ComputeCanApproveAsync(ModularCA.Shared.Entities.KeyCeremonyEntity ceremony, Guid viewerId)
    {
        if (ceremony.Status != "Pending") return (false, null);
        if (ceremony.InitiatedByUserId == viewerId) return (false, null);
        if (!await CanAccessCeremonyAsync(ceremony)) return (false, null);
        if (ceremony.OperationType == "ControlledUserChange"
            && await _controlledUserSvc.ApprovalRefusalAsync(viewerId, ceremony) is { } refusal)
            return (false, refusal);
        if (await PolicyApprovalRefusalAsync(ceremony, viewerId) is { } policyRefusal)
            return (false, policyRefusal);
        return (true, null);
    }

    /// <summary>
    /// Why <paramref name="userId"/> may not approve a policy-change ceremony, or null when they
    /// may or the ceremony is of another type. A SpacePolicyChange needs a space administrator
    /// (<c>system.manage</c> space-wide in its space) and an InstancePolicyChange a system
    /// administrator: the change sets the ceremony requirement and quorums every operator is held
    /// to, so an operator of that scope may see it but not approve or reject it. The initiator never
    /// counts, which <see cref="IKeyCeremonyService.ApproveAsync"/> enforces for every ceremony.
    /// <paramref name="verb"/> names the decision in the refusal ("approve" or "reject").
    /// </summary>
    private async Task<string?> PolicyApprovalRefusalAsync(KeyCeremonyEntity ceremony, Guid userId, string verb = "approve")
    {
        if (ceremony.OperationType is not (nameof(CeremonyType.SpacePolicyChange) or nameof(CeremonyType.InstancePolicyChange)))
            return null;
        if (await _groupAuth.HasScopeCapabilityAsync(userId, ceremony.SpaceId, Capabilities.SystemManage))
            return null;
        return ceremony.SpaceId == null
            ? $"Only a system administrator can {verb} a change to the instance's policy."
            : $"Only an administrator of this space can {verb} a change to its policy.";
    }

    /// <summary>
    /// Approves a pending key ceremony. Requires step-up MFA verification.
    /// Self-approval is forbidden: the initiator cannot approve their own ceremony. A controlled-user
    /// ceremony the caller may not approve is 403 with the reason: no approving tier, or, for a
    /// promotion, a recent reset by the caller of the credentials of an account it promotes. A
    /// policy-change ceremony needs admin rank at its scope (403 for an operator of that scope).
    /// When approvals reach the quorum threshold, the ceremony transitions to Approved status.
    /// </summary>
    [HttpPost("{id:guid}/approve")]
    public async Task<IActionResult> Approve(
        Guid id,
        [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
    {
        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null) return Unauthorized();

        var approveCeremony = await _ceremonySvc.GetByIdAsync(id);
        if (approveCeremony == null) return NotFound(new { error = "Ceremony not found." });
        if (!await CanAccessCeremonyAsync(approveCeremony))
            return StatusCode(403, new { error = "You do not have access to this ceremony." });

        // Initiator self-approval is blocked separately by the ceremony service.
        if (approveCeremony.OperationType == "ControlledUserChange"
            && await _controlledUserSvc.ApprovalRefusalAsync(_currentUser.User.Id, approveCeremony) is { } refusal)
            return StatusCode(403, new { error = refusal });
        if (await PolicyApprovalRefusalAsync(approveCeremony, _currentUser.User.Id) is { } policyRefusal)
            return StatusCode(403, new { error = policyRefusal });

        if (!await MfaStepUpController.ValidateStepUpTokenAsync(
                _cache, User, mfaToken, StepUpOps.ApproveCeremony, id.ToString()))
            return StatusCode(403, new
            {
                error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.",
                requiresStepUp = true
            });

        try
        {
            var ceremony = await _ceremonySvc.ApproveAsync(
                id,
                _currentUser.User.Id,
                _currentUser.User.Username ?? string.Empty);

            return Ok(new
            {
                ceremony.Id,
                ceremony.CurrentApprovals,
                ceremony.RequiredApprovals,
                ceremony.Status,
                message = ceremony.Status == "Approved"
                    ? "Quorum reached. Ceremony is approved and ready for execution."
                    : $"Approval recorded. {ceremony.RequiredApprovals - ceremony.CurrentApprovals} more approval(s) needed."
            });
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
        catch (UnauthorizedAccessException ex)
        {
            return StatusCode(403, new { error = ex.Message });
        }
    }

    /// <summary>
    /// Rejects a pending key ceremony, immediately setting its status to Rejected.
    /// Now step-up gated so an attacker with a hijacked admin
    /// session cannot silently reject legitimate ceremonies as a DOS against the
    /// key-rotation workflow. A controlled-user ceremony can be rejected only by a system admin or
    /// by someone holding a tier that could approve it, including one barred from approving it as
    /// a resetter, and never by the user it changes. A policy-change ceremony is rejected under the
    /// approval rule, <see cref="PolicyApprovalRefusalAsync"/> (403 for an operator of its scope),
    /// except by its initiator, who may withdraw it.
    /// </summary>
    [HttpPost("{id:guid}/reject")]
    public async Task<IActionResult> Reject(Guid id, [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
    {
        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null) return Unauthorized();

        var rejectCeremony = await _ceremonySvc.GetByIdAsync(id);
        if (rejectCeremony == null) return NotFound(new { error = "Ceremony not found." });
        if (!await CanAccessCeremonyAsync(rejectCeremony))
            return StatusCode(403, new { error = "You do not have access to this ceremony." });
        if (rejectCeremony.InitiatedByUserId != _currentUser.User.Id
            && await PolicyApprovalRefusalAsync(rejectCeremony, _currentUser.User.Id, "reject") is { } policyRefusal)
            return StatusCode(403, new { error = policyRefusal });
        if (IsControlledUserChange(rejectCeremony))
        {
            var userId = _currentUser.User.Id;
            if (_controlledUserSvc.DescribeCeremony(rejectCeremony).TargetUserId == userId)
                return StatusCode(403, new { error = "You cannot reject a change to your own privileges." });
            if (!await _groupAuth.IsSystemAdminAsync(userId) && !await _controlledUserSvc.HoldsApprovingTierAsync(userId, rejectCeremony))
                return StatusCode(403, new { error = "You are not eligible to reject this controlled-user change: your role doesn't cover the affected privilege tier." });
        }

        if (!await MfaStepUpController.ValidateStepUpTokenAsync(
                _cache, User, mfaToken, StepUpOps.RejectCeremony, id.ToString()))
            return StatusCode(403, new
            {
                error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.",
                requiresStepUp = true
            });

        try
        {
            var ceremony = await _ceremonySvc.RejectAsync(
                id,
                _currentUser.User.Id,
                _currentUser.User.Username ?? string.Empty);

            return Ok(new
            {
                ceremony.Id,
                ceremony.Status,
                message = "Ceremony rejected."
            });
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }

    /// <summary>
    /// Cancels a pending key ceremony. Only the original initiator may cancel.
    /// Step-up gated to block session-hijack cancellations of
    /// in-progress ceremonies.
    /// </summary>
    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Cancel(Guid id, [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
    {
        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null) return Unauthorized();

        var cancelCeremony = await _ceremonySvc.GetByIdAsync(id);
        if (cancelCeremony == null) return NotFound(new { error = "Ceremony not found." });
        if (!await CanAccessCeremonyAsync(cancelCeremony))
            return StatusCode(403, new { error = "You do not have access to this ceremony." });

        if (!await MfaStepUpController.ValidateStepUpTokenAsync(
                _cache, User, mfaToken, StepUpOps.CancelCeremony, id.ToString()))
            return StatusCode(403, new
            {
                error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.",
                requiresStepUp = true
            });

        try
        {
            var ceremony = await _ceremonySvc.CancelAsync(id, _currentUser.User.Id);

            return Ok(new
            {
                ceremony.Id,
                ceremony.Status,
                message = "Ceremony cancelled."
            });
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
        catch (UnauthorizedAccessException ex)
        {
            return StatusCode(403, new { error = ex.Message });
        }
    }

    /// <summary>
    /// Executes an approved key ceremony, triggering the actual CA creation.
    /// Only the initiator or an approver may execute. Parameters are locked from initiation.
    /// A label or name another CA took meanwhile is 409, an invalid or reserved label 400, and a
    /// CA certificate profile outside the new CA's scope 404. A controlled-user password reset
    /// returns the temporary password it generates (<c>temporaryPassword</c>) in this response only,
    /// to the caller who executes it; it is not stored, audited or shown again.
    /// Requires step-up MFA verification.
    /// </summary>
    [HttpPost("{id:guid}/execute")]
    public async Task<IActionResult> Execute(Guid id, [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
    {
        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null) return Unauthorized();

        var ceremony = await _ceremonySvc.GetByIdAsync(id);
        if (ceremony == null)
            return NotFound(new { error = "Ceremony not found." });
        if (!await CanAccessCeremonyAsync(ceremony))
            return StatusCode(403, new { error = "You do not have access to this ceremony." });
        if (IsControlledUserChange(ceremony) && !await MayExecuteControlledUserChangeAsync(ceremony))
            return StatusCode(403, new { error = "You no longer hold a role that covers the affected privilege tier." });

        if (!await MfaStepUpController.ValidateStepUpTokenAsync(
                _cache, User, mfaToken, StepUpOps.ExecuteCeremony, id.ToString()))
            return StatusCode(403, new { error = "MFA re-verification required.", requiresStepUp = true });

        if (ceremony.Status != "Approved")
            return Conflict(new { error = $"Ceremony is '{ceremony.Status}', not 'Approved'. Only approved ceremonies can be executed." });

        // One execution at a time per ceremony, then re-read the status under the lock: a second
        // execute that raced the first finds it Executed and gets 409 instead of running it twice.
        await using var executionLock = await _ceremonySvc.TryAcquireExecutionLockAsync(id);
        if (executionLock == null)
            return Conflict(new { error = "This ceremony is being executed by another request." });
        ceremony = await _ceremonySvc.GetByIdAsync(id);
        if (ceremony == null)
            return NotFound(new { error = "Ceremony not found." });
        if (ceremony.Status != "Approved")
            return Conflict(new { error = $"Ceremony is '{ceremony.Status}', not 'Approved'. Only approved ceremonies can be executed." });

        // Verify the caller is the initiator or an approver
        var userId = _currentUser.User.Id;
        var isInitiator = ceremony.InitiatedByUserId == userId;
        var approvalRecords = new List<ApprovalRecord>();
        if (!string.IsNullOrEmpty(ceremony.ApprovalsJson))
        {
            try
            {
                approvalRecords = JsonSerializer.Deserialize<List<ApprovalRecord>>(
                    ceremony.ApprovalsJson,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? new();
            }
            catch (JsonException ex)
            {
                // Corrupt ApprovalsJson is a ceremony data-integrity
                // incident — fail loud and audit. Silently treating the ceremony as having zero
                // approvers would (a) produce an unhelpful 403 for the caller, (b) leave the
                // ceremony stuck with no diagnostic, and (c) mask possible tampering of a
                // high-value quorum-protected row. Operators must intervene.
                Log.Error(ex,
                    "KeyCeremony {CeremonyId}: ApprovalsJson is corrupt and cannot be deserialized; failing execute with 500 so an operator can inspect.",
                    id);
                await _audit.LogAsync(
                    AuditActionType.KeyCeremonyRejected,
                    _currentUser.User.Id, _currentUser.User.Username,
                    "KeyCeremony", id.ToString(),
                    new { CeremonyId = id, Reason = "ApprovalsJson corrupt — cannot deserialize", Error = ex.Message });
                return StatusCode(500, new
                {
                    error = "Ceremony approvals record is corrupt and cannot be parsed. Operator intervention required.",
                    ceremonyId = id
                });
            }
        }
        var isApprover = approvalRecords.Any(a => a.UserId == userId);
        if (!isInitiator && !isApprover)
            return StatusCode(403, new { error = "Only the initiator or an approver can execute this ceremony." });

        // Deserialize locked parameters. ONLY the X.509 CA-creation operations
        // (CreateRootCA / CreateIntermediateCA) use the generic KeyCeremonyParameters shape and
        // fall through to the common "CA created" tail below. SSH, revoke, space-policy, and
        // controlled-user ceremonies carry their own parameter shapes and deserialize them inside
        // their own branch. We must NOT force the generic deserialize for those: e.g. an ed25519
        // SSH CA serializes KeySize as null, which cannot bind to KeyCeremonyParameters.KeySize
        // (a non-nullable int) and would throw here — returning a misleading "Failed to deserialize
        // ceremony parameters" 400 before the SSH branch ever runs.
        ModularCA.Shared.Models.KeyCeremonyParameters? parameters = null;
        var usesGenericCaParameters =
            ceremony.OperationType is "CreateRootCA" or "CreateIntermediateCA";
        if (usesGenericCaParameters)
        {
            if (string.IsNullOrEmpty(ceremony.ParametersJson))
                return BadRequest(new { error = "Ceremony has no parameters to execute." });
            try
            {
                parameters = CeremonyParametersJson.Read<ModularCA.Shared.Models.KeyCeremonyParameters>(ceremony.ParametersJson);
            }
            catch
            {
                return BadRequest(new { error = "Failed to deserialize ceremony parameters." });
            }
            if (parameters == null)
                return BadRequest(new { error = "Ceremony has no parameters to execute." });
        }

        try
        {
            ModularCA.Shared.Entities.CertificateAuthorityEntity newCa;

            if (ceremony.OperationType == "CreateRootCA")
            {
                if (parameters == null)
                    return BadRequest(new { error = "Ceremony has no parameters to execute." });
                newCa = await _caCreation.CreateRootAsync(
                    parameters.SubjectCN, parameters.SubjectO, parameters.SubjectOU,
                    parameters.SubjectL, parameters.SubjectST, parameters.SubjectC,
                    parameters.KeyAlgorithm, parameters.KeySize, parameters.ValidityYears,
                    parameters.Label, parameters.SpaceId,
                    publicBaseUrl: parameters.PublicBaseUrl,
                    nameConstraintsPermittedJson: parameters.NameConstraintsPermitted is { Count: > 0 }
                        ? JsonSerializer.Serialize(parameters.NameConstraintsPermitted) : null,
                    nameConstraintsExcludedJson: parameters.NameConstraintsExcluded is { Count: > 0 }
                        ? JsonSerializer.Serialize(parameters.NameConstraintsExcluded) : null,
                    ceremonyId: ceremony.Id);
            }
            else if (ceremony.OperationType == "CreateIntermediateCA")
            {
                if (parameters == null)
                    return BadRequest(new { error = "Ceremony has no parameters to execute." });
                if (parameters.ParentCaId == null)
                    return BadRequest(new { error = "Parent CA ID is required for intermediate CA creation." });

                var parentCa = await _db.CertificateAuthorities
                    .Include(ca => ca.Certificate)
                    .FirstOrDefaultAsync(ca => ca.Id == parameters.ParentCaId.Value && ca.IsEnabled);
                if (parentCa?.Certificate == null)
                    return BadRequest(new { error = "Parent CA not found or disabled." });

                newCa = await _caCreation.CreateIntermediateAsync(
                    parentCa, parentCa.Certificate,
                    parameters.SubjectCN, parameters.SubjectO, parameters.SubjectOU,
                    parameters.SubjectL, parameters.SubjectST, parameters.SubjectC,
                    parameters.KeyAlgorithm, parameters.KeySize, parameters.ValidityYears,
                    parameters.Label, parameters.SpaceId,
                    publicBaseUrl: parameters.PublicBaseUrl,
                    certProfileId: parameters.CertProfileId,
                    nameConstraintsPermittedJson: parameters.NameConstraintsPermitted is { Count: > 0 }
                        ? JsonSerializer.Serialize(parameters.NameConstraintsPermitted) : null,
                    nameConstraintsExcludedJson: parameters.NameConstraintsExcluded is { Count: > 0 }
                        ? JsonSerializer.Serialize(parameters.NameConstraintsExcluded) : null,
                    ceremonyId: ceremony.Id);
            }
            else if (ceremony.OperationType == "CreateSshCa")
            {
                var sshParams = CeremonyParametersJson.Read<SshKeyCeremonyParameters>(ceremony.ParametersJson);
                if (sshParams == null)
                    return BadRequest(new { error = "Failed to deserialize SSH CA ceremony parameters." });

                var newKey = await _sshCaService.GenerateKeyPairAsync(
                    sshParams.Name, sshParams.KeyType,
                    sshParams.IsUserCa, sshParams.IsHostCa,
                    sshParams.MaxValidityHours, sshParams.KeySize);

                await _ceremonySvc.MarkExecutedAsync(id);

                await _audit.LogAsync(
                    AuditActionType.KeyCeremonyExecuted,
                    _currentUser.User.Id, _currentUser.User.Username,
                    "KeyCeremony", id.ToString(),
                    new { CeremonyId = id, ceremony.OperationType, NewSshCaKeyId = newKey.Id, NewSshCaKeyName = newKey.Name });

                return Ok(new { ceremony.Id, Status = "Executed",
                    NewSshCaKey = new { newKey.Id, newKey.Name, newKey.KeyType },
                    message = $"SSH CA '{newKey.Name}' created successfully." });
            }
            else if (ceremony.OperationType == "DeleteSshCa")
            {
                var sshParams = CeremonyParametersJson.Read<SshKeyCeremonyParameters>(ceremony.ParametersJson);
                if (sshParams?.SshCaKeyId == null)
                    return BadRequest(new { error = "SSH CA key ID missing from ceremony parameters." });

                await _sshCaService.DisableAsync(sshParams.SshCaKeyId.Value);

                await _ceremonySvc.MarkExecutedAsync(id);

                await _audit.LogAsync(
                    AuditActionType.KeyCeremonyExecuted,
                    _currentUser.User.Id, _currentUser.User.Username,
                    "KeyCeremony", id.ToString(),
                    new { CeremonyId = id, ceremony.OperationType, DisabledSshCaKeyId = sshParams.SshCaKeyId, sshParams.Name });

                return Ok(new { ceremony.Id, Status = "Executed",
                    message = $"SSH CA '{sshParams.Name}' disabled. All certificates revoked." });
            }
            else if (ceremony.OperationType == "RevokeCa")
            {
                // KC-06: execute the ceremony-gated CA certificate revocation.
                var revokeParams = CeremonyParametersJson.Read<RevokeCaCeremonyParameters>(ceremony.ParametersJson);
                if (revokeParams == null || revokeParams.CertificateId == Guid.Empty)
                    return BadRequest(new { error = "Certificate ID missing from RevokeCa ceremony parameters." });

                if (!Enum.TryParse<RevocationReason>(revokeParams.Reason, true, out var reason))
                    reason = RevocationReason.Unspecified;

                var revokeResult = await _revocationSvc.RevokeCertificateAsync(
                    revokeParams.CertificateId, null, reason);

                await _ceremonySvc.MarkExecutedAsync(id);

                await _audit.LogAsync(
                    AuditActionType.KeyCeremonyExecuted,
                    _currentUser.User.Id, _currentUser.User.Username,
                    "KeyCeremony", id.ToString(),
                    new { CeremonyId = id, ceremony.OperationType, revokeParams.CertificateId, revokeParams.SerialNumber, Reason = reason.ToString() });

                return Ok(new
                {
                    ceremony.Id,
                    Status = "Executed",
                    message = $"CA certificate {revokeParams.SerialNumber} revoked via ceremony.",
                    certificateId = revokeResult.CertificateId,
                    serialNumber = revokeResult.SerialNumber,
                    newStatus = revokeResult.NewStatus,
                    reason = revokeResult.Reason?.ToString(),
                    crlNumber = revokeResult.CrlNumber,
                });
            }
            else if (ceremony.OperationType is nameof(CeremonyType.SpacePolicyChange) or nameof(CeremonyType.InstancePolicyChange))
            {
                // Apply the ceremony-gated scope policy change via the dedicated service (the
                // instance's goes to the security policy row), then mark executed + emit a distinct
                // audit entry carrying the before/after diff so operators can easily filter policy
                // changes out of the broader ceremony stream.
                var result = await _spacePolicyChangeSvc.ApplyApprovedChangeAsync(ceremony.Id);

                await _ceremonySvc.MarkExecutedAsync(id);
                var isInstance = result.SpaceId == null;
                if (isInstance)
                    HttpContext.RequestServices.GetService<ISecurityPolicyService>()?.InvalidateCache();

                await _audit.LogAsync(
                    isInstance ? AuditActionType.InstancePolicyChangeApplied : AuditActionType.SpacePolicyChangeApplied,
                    _currentUser.User.Id,
                    _currentUser.User.Username,
                    isInstance ? "SecurityPolicy" : "Space",
                    result.SpaceId?.ToString() ?? "instance",
                    new
                    {
                        CeremonyId = ceremony.Id,
                        SpaceId = result.SpaceId,
                        Before = new
                        {
                            RequireKeyCeremony = result.BeforeRequireKeyCeremony,
                            CeremonyRequiredApprovals = result.BeforeCeremonyRequiredApprovals,
                        },
                        After = new
                        {
                            RequireKeyCeremony = result.AfterRequireKeyCeremony,
                            CeremonyRequiredApprovals = result.AfterCeremonyRequiredApprovals,
                        },
                    });

                return Ok(new
                {
                    ceremony.Id,
                    Status = "Executed",
                    message = isInstance ? "Instance policy change applied." : "Space policy change applied.",
                    result,
                });
            }
            else if (ceremony.OperationType == "ControlledUserChange")
            {
                // The service marks the ceremony Executed in the same transaction as the change.
                var result = await _controlledUserSvc.ApplyApprovedAsync(ceremony.Id);

                await _audit.LogAsync(
                    AuditActionType.KeyCeremonyExecuted,
                    _currentUser.User.Id, _currentUser.User.Username,
                    "KeyCeremony", id.ToString(),
                    new { CeremonyId = id, ceremony.OperationType, result.TargetUserId });

                await _audit.LogAsync(
                    AuditActionType.ControlledUserChangeApplied,
                    _currentUser.User.Id,
                    _currentUser.User.Username,
                    "User",
                    result.TargetUserId.ToString(),
                    new
                    {
                        CeremonyId = ceremony.Id,
                        result.ChangeType,
                        result.TargetUserId,
                        result.Capability,
                        result.SpaceId,
                        result.CertificateAuthorityId,
                    });

                await ModularCA.API.Middleware.TokenRevocationMiddleware.InvalidateUserStampCacheAsync(_cache, result.TargetUserId);
                await AuditAccountChangeAsync(result, ceremony.Id);

                if (result.TemporaryPassword != null)
                    Response.Headers.CacheControl = "no-store";
                return Ok(new
                {
                    ceremony.Id,
                    Status = "Executed",
                    message = result.TemporaryPassword != null
                        ? "Password reset. The temporary password is shown only in this response."
                        : "Controlled-user change applied.",
                    result,
                    temporaryPassword = result.TemporaryPassword,
                });
            }
            else
            {
                return BadRequest(new { error = $"Unsupported operation type: {ceremony.OperationType}" });
            }

            // Mark ceremony as executed
            await _ceremonySvc.MarkExecutedAsync(id);

            await _audit.LogAsync(
                AuditActionType.KeyCeremonyExecuted,
                _currentUser.User.Id,
                _currentUser.User.Username,
                "KeyCeremony",
                id.ToString(),
                new { CeremonyId = id, ceremony.OperationType, NewCaId = newCa.Id, NewCaName = newCa.Name });

            return Ok(new
            {
                ceremony.Id,
                Status = "Executed",
                NewCa = new { newCa.Id, newCa.Name, newCa.Label, newCa.Type },
                message = $"{ceremony.OperationType} executed successfully. CA '{newCa.Name}' created."
            });
        }
        catch (CeremonyNotExecutableException ex)
        {
            return Conflict(new { error = ex.Message, status = ex.Status });
        }
        catch (ControlledUserChangeRefusedException ex)
        {
            // A last-dominator refusal leaves the ceremony Approved, so it is not a rejection.
            await _audit.LogAsync(
                ex.CeremonyExpired ? AuditActionType.KeyCeremonyExpired : AuditActionType.ControlledUserChangeRefused,
                _currentUser.User.Id, _currentUser.User.Username,
                "KeyCeremony", id.ToString(),
                new { CeremonyId = id, ceremony.OperationType, Reason = ex.Message, RefusedAtExecute = true });
            return Conflict(new { error = ex.Message, ceremonyExpired = ex.CeremonyExpired });
        }
        catch (ModularCA.Shared.Errors.ResourceConflictException ex)
        {
            return Conflict(new { error = ex.Message, code = ex.Code });
        }
        catch (ModularCA.Shared.Errors.ResourceNotFoundException ex)
        {
            return NotFound(new { error = ex.Message, code = ex.Code });
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to execute key ceremony");
            return StatusCode(500, new { error = "An unexpected error occurred while executing the key ceremony. Please try again." });
        }
    }

    /// <summary>
    /// The spaces whose ceremonies the caller may see: those where they hold <c>ca.manage</c>
    /// space-wide, from any grant source. A system-scoped holder is handled by the caller.
    /// </summary>
    private Task<List<Guid>> GetUserCeremonySpaceIdsAsync(Guid userId)
        => _groupAuth.GetSpaceIdsWithCapabilityAsync(userId, Capabilities.CaManage);

    /// <summary>
    /// Checks if the current user can access the given ceremony, all under the worn badge. A
    /// controlled-user ceremony is open to a system admin, its initiator, and anyone whose tier could
    /// approve it (which excludes its target), barred from approving or not, so a CA admin reaches the changes on their CA and a
    /// space-wide <c>ca.manage</c> holder does not see changes above their rank. Its target gets no
    /// access as such: a pending demotion or deletion must not tip off the account it removes. Any
    /// other ceremony is open to a system admin or a holder of <c>ca.manage</c> space-wide in its
    /// space, or at system scope for an instance ceremony (no space).
    /// </summary>
    private async Task<bool> CanAccessCeremonyAsync(KeyCeremonyEntity ceremony)
    {
        var userId = _currentUser.User!.Id;
        if (IsControlledUserChange(ceremony)
            && _controlledUserSvc.DescribeCeremony(ceremony).TargetUserId == userId)
            return false;

        if (await _groupAuth.IsSystemAdminAsync(userId))
            return true;

        if (IsControlledUserChange(ceremony))
            return ceremony.InitiatedByUserId == userId || await _controlledUserSvc.HoldsApprovingTierAsync(userId, ceremony);

        // An instance ceremony (no space) is open to ca.manage at system scope, as the System
        // space's were.
        return await _groupAuth.HasScopeCapabilityAsync(userId, ceremony.SpaceId, Capabilities.CaManage);
    }

    /// <summary>
    /// Writes the audit rows and raises the alerts the direct account endpoints do, for an account
    /// change (password reset, MFA reset, identity update) applied by a controlled-user ceremony.
    /// Nothing written carries the temporary password.
    /// </summary>
    private async Task AuditAccountChangeAsync(ControlledUserChangeResult result, Guid ceremonyId)
    {
        var user = _currentUser.User!;
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
        var target = result.TargetUserId;
        switch (result.ChangeType)
        {
            case "ResetPassword":
                await _audit.LogAsync(AuditActionType.UserPasswordReset, user.Id, user.Username, "User", target.ToString(),
                    new { CeremonyId = ceremonyId }, ip);
                _ = _alertService.RaiseAlertAsync("AdminPasswordReset", AlertSeverity.Warning,
                    $"Password reset for user {target} by {user.Username} (ceremony {ceremonyId})", new { TargetUserId = target, CeremonyId = ceremonyId });
                break;
            case "ResetMfa":
                await _audit.LogAsync(AuditActionType.UserUpdated, user.Id, user.Username, "User", target.ToString(),
                    new { Action = "MfaReset", CeremonyId = ceremonyId }, ip);
                _ = _alertService.RaiseAlertAsync("UserMfaReset", AlertSeverity.Critical,
                    $"MFA reset for user {target} by {user.Username} (ceremony {ceremonyId})", new { TargetUserId = target, CeremonyId = ceremonyId });
                break;
            case "UpdateIdentity":
                await _audit.LogAsync(AuditActionType.UserUpdated, user.Id, user.Username, "User", target.ToString(),
                    new { Action = "UpdateIdentity", CeremonyId = ceremonyId }, ip);
                break;
        }
    }

    /// <summary>True for a ceremony that gates a controlled user's privileges.</summary>
    private static bool IsControlledUserChange(KeyCeremonyEntity ceremony)
        => ceremony.OperationType == "ControlledUserChange";

    /// <summary>
    /// Whether the current user may execute a controlled-user ceremony with the rights they wear now:
    /// a system admin, someone eligible to approve it, or its initiator while still holding a tier
    /// that dominates the change. Being the initiator alone is not enough under a narrowing badge.
    /// </summary>
    private async Task<bool> MayExecuteControlledUserChangeAsync(KeyCeremonyEntity ceremony)
    {
        var userId = _currentUser.User!.Id;
        if (await _groupAuth.IsSystemAdminAsync(userId) || await _controlledUserSvc.CanApproveAsync(userId, ceremony))
            return true;
        return ceremony.InitiatedByUserId == userId
            && _controlledUserSvc.DescribeCeremony(ceremony).Minted is { } minted
            && await _controlledUserSvc.CanInitiateAsync(userId, minted);
    }

    /// <summary>
    /// Whether the caller may start a ceremony of this type with these parameters. CA creation
    /// follows <see cref="CaCreationAccess"/>; anything else needs <c>ca.manage</c> across the
    /// scope named in the parameters: space-wide for a space, at system scope for the instance
    /// (no space).
    /// </summary>
    private async Task<bool> MayInitiateAsync(string operationType, KeyCeremonyParameters? parameters, Guid userId)
    {
        if (await _groupAuth.IsSystemAdminAsync(userId))
            return true;
        if (parameters == null)
            return false;

        if (string.Equals(operationType, "CreateRootCA", StringComparison.OrdinalIgnoreCase))
            return await CaCreationAccess.MayCreateRootAsync(_groupAuth, userId, parameters.SpaceId);
        if (string.Equals(operationType, "CreateIntermediateCA", StringComparison.OrdinalIgnoreCase))
            return parameters.ParentCaId is Guid parent
                && await CaCreationAccess.MayCreateIntermediateAsync(_groupAuth, _db, userId, parameters.SpaceId, parent);

        return await _groupAuth.HasScopeCapabilityAsync(userId, parameters.SpaceId, Capabilities.CaManage);
    }
}

/// <summary>
/// Request body for initiating a new key ceremony.
/// </summary>
public class InitiateCeremonyRequest
{
    /// <summary>The type of operation (e.g., CreateRootCA, CreateIntermediateCA, RevokeCA).</summary>
    [Required, MaxLength(100)]
    public string OperationType { get; set; } = string.Empty;

    /// <summary>Human-readable description of the ceremony's purpose.</summary>
    [MaxLength(1000)]
    public string? Description { get; set; }

    /// <summary>The ID of the target entity (e.g., CA ID). Empty for new entity creation.</summary>
    [MaxLength(500)]
    public string? TargetEntityId { get; set; }

    /// <summary>
    /// Structured CA creation parameters. Serialized to JSON and locked at initiation time.
    /// Approvers review these parameters; they cannot be modified after initiation.
    /// </summary>
    public ModularCA.Shared.Models.KeyCeremonyParameters? Parameters { get; set; }
}
