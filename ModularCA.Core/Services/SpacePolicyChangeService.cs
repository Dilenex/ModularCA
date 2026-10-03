using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Shared.Utils;

namespace ModularCA.Core.Services;

/// <summary>
/// Orchestrates ceremony-gated changes of a scope's security policy fields
/// (<c>RequireKeyCeremony</c>, <c>CeremonyRequiredApprovals</c> and the user quorums). A space's
/// changes open a <see cref="CeremonyType.SpacePolicyChange"/> ceremony on its space row; the
/// instance's (a null space) open an <see cref="CeremonyType.InstancePolicyChange"/> ceremony on
/// the <see cref="SecurityPolicyEntity"/> row. Direct writes by a system-super bypass this service.
/// </summary>
public class SpacePolicyChangeService(
    ModularCADbContext db,
    IKeyCeremonyService keyCeremonyService,
    ILogger<SpacePolicyChangeService> logger) : ISpacePolicyChangeService
{
    /// <inheritdoc />
    public bool IsDowngrade(
        bool currentRequireKeyCeremony,
        int currentCeremonyRequiredApprovals,
        bool? proposedRequireKeyCeremony,
        int? proposedCeremonyRequiredApprovals)
    {
        var requireKeyCeremonyDowngrade =
            proposedRequireKeyCeremony.HasValue
            && currentRequireKeyCeremony
            && !proposedRequireKeyCeremony.Value;

        var approvalsDowngrade =
            proposedCeremonyRequiredApprovals.HasValue
            && proposedCeremonyRequiredApprovals.Value < currentCeremonyRequiredApprovals;

        return requireKeyCeremonyDowngrade || approvalsDowngrade;
    }

    /// <inheritdoc />
    public async Task<Guid> InitiateChangeAsync(
        Guid? spaceId,
        bool? proposedRequireKeyCeremony,
        int? proposedCeremonyRequiredApprovals,
        Guid initiatorUserId,
        string initiatorUsername,
        bool userQuorumIncluded = false,
        int? proposedUserQuorum = null,
        IReadOnlyList<CaUserQuorumChange>? caUserQuorums = null)
    {
        var isInstance = spaceId == null;
        var ceremonyType = isInstance ? CeremonyType.InstancePolicyChange : CeremonyType.SpacePolicyChange;

        bool currentRequire;
        int currentApprovals;
        int? currentUserQuorum;
        string scopeName;
        string targetEntityId;
        if (spaceId is Guid tid)
        {
            var space = await db.Spaces.FindAsync(tid)
                ?? throw new InvalidOperationException($"Space {tid} not found.");
            (currentRequire, currentApprovals, currentUserQuorum) =
                (space.RequireKeyCeremony, space.CeremonyRequiredApprovals, space.UserCeremonyRequiredApprovals);
            scopeName = $"space '{space.Name}'";
            targetEntityId = tid.ToString();
        }
        else
        {
            var policy = await db.SecurityPolicies.FirstOrDefaultAsync()
                ?? throw new InvalidOperationException("No security policy is configured for the instance.");
            (currentRequire, currentApprovals, currentUserQuorum) =
                (policy.RequireKeyCeremony, policy.CeremonyRequiredApprovals, policy.UserCeremonyRequiredApprovals);
            scopeName = "the instance";
            targetEntityId = policy.Id.ToString();
        }

        // Concurrency guard: only one pending policy-change ceremony per scope at a time.
        var alreadyPending = await db.KeyCeremonies.AnyAsync(k =>
            k.SpaceId == spaceId
            && k.CeremonyType == ceremonyType
            && k.Status == "Pending");

        if (alreadyPending)
        {
            throw new InvalidOperationException(
                $"A policy-change ceremony is already pending for {scopeName}. " +
                "Cancel or approve it before starting another.");
        }

        // Snapshot each CA's current quorum for the drift guard (only the scope's CAs the change touches).
        var caChanges = new List<CaUserQuorumChange>();
        if (caUserQuorums is { Count: > 0 })
        {
            var caIds = caUserQuorums.Select(c => c.CaId).ToList();
            var cas = await db.CertificateAuthorities.Where(c => caIds.Contains(c.Id) && c.SpaceId == spaceId).ToListAsync();
            foreach (var c in caUserQuorums)
            {
                var ca = cas.FirstOrDefault(x => x.Id == c.CaId);
                if (ca == null) continue; // CA vanished between request and initiate, or is outside the scope — drop it.
                caChanges.Add(new CaUserQuorumChange
                {
                    CaId = c.CaId,
                    CurrentQuorum = ca.UserCeremonyRequiredApprovals,
                    ProposedQuorum = c.ProposedQuorum,
                });
            }
        }

        var parameters = new SpacePolicyChangeCeremonyParameters
        {
            SpaceId = spaceId,
            CurrentRequireKeyCeremony = currentRequire,
            CurrentCeremonyRequiredApprovals = currentApprovals,
            ProposedRequireKeyCeremony = proposedRequireKeyCeremony,
            ProposedCeremonyRequiredApprovals = proposedCeremonyRequiredApprovals,
            UserQuorumIncluded = userQuorumIncluded,
            CurrentUserQuorum = currentUserQuorum,
            ProposedUserQuorum = proposedUserQuorum,
            CaUserQuorums = caChanges,
        };

        // camelCase so the stored blob matches the casing of the API envelope it is embedded in.
        var parametersJson = JsonSerializer.Serialize(parameters, SafeJsonOptions.Stored);

        var description = $"Change {scopeName} ceremony / quorum policy";

        // No quorumOverride: KeyCeremonyService.ResolveQuorumAsync reads the scope's current
        // CeremonyRequiredApprovals for both policy-change operation types.
        var ceremony = await keyCeremonyService.InitiateAsync(
            operationType: ceremonyType.ToString(),
            description: description,
            targetEntityId: targetEntityId,
            initiatorUserId: initiatorUserId,
            initiatorUsername: initiatorUsername,
            parametersJson: parametersJson);

        // The base InitiateAsync doesn't know the policy-change enum values — stamp it here.
        var tracked = await db.KeyCeremonies.FindAsync(ceremony.Id)
            ?? throw new InvalidOperationException(
                $"Newly-created ceremony {ceremony.Id} could not be re-loaded for CeremonyType stamp.");

        tracked.CeremonyType = ceremonyType;
        tracked.SpaceId = spaceId;
        await db.SaveChangesAsync();

        logger.LogInformation(
            "Initiated {CeremonyType} ceremony {CeremonyId} for {Scope} (initiator {InitiatorUserId}).",
            ceremonyType, tracked.Id, scopeName, initiatorUserId);

        return tracked.Id;
    }

    /// <inheritdoc />
    public async Task<SpacePolicyChangeAppliedResult> ApplyApprovedChangeAsync(Guid ceremonyId)
    {
        var ceremony = await db.KeyCeremonies.FindAsync(ceremonyId)
            ?? throw new InvalidOperationException($"Ceremony {ceremonyId} not found.");

        if (ceremony.Status != "Approved")
        {
            throw new InvalidOperationException(
                $"Ceremony must be in Approved status to apply (current: {ceremony.Status}).");
        }

        SpacePolicyChangeCeremonyParameters? parameters;
        try
        {
            parameters = CeremonyParametersJson.Read<SpacePolicyChangeCeremonyParameters>(ceremony.ParametersJson);
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException(
                $"Ceremony {ceremonyId} parameters could not be deserialized as SpacePolicyChangeCeremonyParameters.",
                ex);
        }

        if (parameters is null)
        {
            throw new InvalidOperationException(
                $"Ceremony {ceremonyId} parameters deserialized to null.");
        }

        // The ceremony's type and its parameters must name the same scope, so a space ceremony
        // can never be applied to the instance or the other way round.
        var isInstance = ceremony.CeremonyType == CeremonyType.InstancePolicyChange;
        if (isInstance != (parameters.SpaceId == null))
            throw new InvalidOperationException(
                $"Ceremony {ceremonyId} is a {ceremony.CeremonyType} ceremony but its parameters name {(parameters.SpaceId == null ? "the instance" : $"space {parameters.SpaceId}")}.");

        SpaceEntity? space = null;
        SecurityPolicyEntity? policy = null;
        if (parameters.SpaceId is Guid tid)
            space = await db.Spaces.FindAsync(tid)
                ?? throw new InvalidOperationException($"Space {tid} referenced by ceremony {ceremonyId} not found.");
        else
            policy = await db.SecurityPolicies.FirstOrDefaultAsync()
                ?? throw new InvalidOperationException($"No security policy is configured; ceremony {ceremonyId} cannot be applied.");

        var beforeRequire = space?.RequireKeyCeremony ?? policy!.RequireKeyCeremony;
        var beforeApprovals = space?.CeremonyRequiredApprovals ?? policy!.CeremonyRequiredApprovals;
        var beforeUserQuorum = space != null ? space.UserCeremonyRequiredApprovals : policy!.UserCeremonyRequiredApprovals;

        // State-drift guard — if the scope moved since the ceremony was opened, abort.
        if (beforeRequire != parameters.CurrentRequireKeyCeremony
            || beforeApprovals != parameters.CurrentCeremonyRequiredApprovals
            || (parameters.UserQuorumIncluded && beforeUserQuorum != parameters.CurrentUserQuorum))
        {
            throw new InvalidOperationException(
                "Policy has changed since ceremony was initiated; aborting to prevent an unintended change.");
        }

        // Load + drift-check the CAs this ceremony touches before mutating any of them.
        var caChanges = parameters.CaUserQuorums ?? new List<CaUserQuorumChange>();
        List<CertificateAuthorityEntity> cas = new();
        if (caChanges.Count > 0)
        {
            var caIds = caChanges.Select(c => c.CaId).ToList();
            cas = await db.CertificateAuthorities.Where(c => caIds.Contains(c.Id)).ToListAsync();
            foreach (var c in caChanges)
            {
                var ca = cas.FirstOrDefault(x => x.Id == c.CaId);
                if (ca == null)
                    throw new InvalidOperationException($"CA {c.CaId} referenced by ceremony {ceremonyId} not found; aborting.");
                if (ca.SpaceId != parameters.SpaceId)
                    throw new InvalidOperationException($"CA {c.CaId} is outside the scope of ceremony {ceremonyId}; aborting.");
                if (ca.UserCeremonyRequiredApprovals != c.CurrentQuorum)
                    throw new InvalidOperationException("A CA quorum has changed since the ceremony was initiated; aborting to prevent an unintended change.");
            }
        }

        bool afterRequire;
        int afterApprovals;
        if (space != null)
        {
            if (parameters.ProposedRequireKeyCeremony.HasValue)
                space.RequireKeyCeremony = parameters.ProposedRequireKeyCeremony.Value;
            if (parameters.ProposedCeremonyRequiredApprovals.HasValue)
                space.CeremonyRequiredApprovals = parameters.ProposedCeremonyRequiredApprovals.Value;
            if (parameters.UserQuorumIncluded)
                space.UserCeremonyRequiredApprovals = parameters.ProposedUserQuorum;
            (afterRequire, afterApprovals) = (space.RequireKeyCeremony, space.CeremonyRequiredApprovals);
        }
        else
        {
            if (parameters.ProposedRequireKeyCeremony.HasValue)
                policy!.RequireKeyCeremony = parameters.ProposedRequireKeyCeremony.Value;
            if (parameters.ProposedCeremonyRequiredApprovals.HasValue)
                policy!.CeremonyRequiredApprovals = parameters.ProposedCeremonyRequiredApprovals.Value;
            if (parameters.UserQuorumIncluded)
                policy!.UserCeremonyRequiredApprovals = parameters.ProposedUserQuorum;
            policy!.UpdatedAt = DateTime.UtcNow;
            (afterRequire, afterApprovals) = (policy.RequireKeyCeremony, policy.CeremonyRequiredApprovals);
        }

        foreach (var c in caChanges)
        {
            var ca = cas.First(x => x.Id == c.CaId);
            ca.UserCeremonyRequiredApprovals = c.ProposedQuorum;
        }

        await db.SaveChangesAsync();

        logger.LogInformation(
            "Applied {CeremonyType} ceremony {CeremonyId} to {Scope}: " +
            "RequireKeyCeremony {BeforeRequire}->{AfterRequire}, CeremonyRequiredApprovals {BeforeApprovals}->{AfterApprovals}, " +
            "UserQuorumChanged={UserQuorumChanged}, CaQuorumsChanged={CaQuorumsChanged}.",
            ceremony.CeremonyType,
            ceremonyId,
            space?.Id.ToString() ?? "instance",
            beforeRequire,
            afterRequire,
            beforeApprovals,
            afterApprovals,
            parameters.UserQuorumIncluded,
            caChanges.Count);

        return new SpacePolicyChangeAppliedResult(
            parameters.SpaceId,
            beforeRequire,
            beforeApprovals,
            afterRequire,
            afterApprovals);
    }
}
