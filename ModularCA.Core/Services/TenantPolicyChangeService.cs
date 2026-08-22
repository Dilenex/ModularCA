using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Shared.Utils;

namespace ModularCA.Core.Services;

/// <summary>
/// Orchestrates ceremony-gated downgrades of tenant security policy fields
/// (<c>RequireKeyCeremony</c> and <c>CeremonyRequiredApprovals</c>). Non-system-super
/// tenant admins route downgrades through this service which opens a
/// <see cref="CeremonyType.TenantPolicyChange"/> ceremony. Upgrades bypass this service
/// entirely and are applied directly by the admin controller.
/// </summary>
public class TenantPolicyChangeService(
    ModularCADbContext db,
    IKeyCeremonyService keyCeremonyService,
    ILogger<TenantPolicyChangeService> logger) : ITenantPolicyChangeService
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
        Guid tenantId,
        bool? proposedRequireKeyCeremony,
        int? proposedCeremonyRequiredApprovals,
        Guid initiatorUserId,
        string initiatorUsername,
        bool userQuorumIncluded = false,
        int? proposedUserQuorum = null,
        IReadOnlyList<CaUserQuorumChange>? caUserQuorums = null)
    {
        var tenant = await db.Tenants.FindAsync(tenantId)
            ?? throw new InvalidOperationException($"Tenant {tenantId} not found.");

        // Concurrency guard: only one pending policy-change ceremony per tenant at a time.
        var alreadyPending = await db.KeyCeremonies.AnyAsync(k =>
            k.TenantId == tenantId
            && k.CeremonyType == CeremonyType.TenantPolicyChange
            && k.Status == "Pending");

        if (alreadyPending)
        {
            throw new InvalidOperationException(
                "A tenant policy-change ceremony is already pending for this tenant. " +
                "Cancel or approve it before starting another.");
        }

        // Snapshot each CA's current quorum for the drift guard (only the CAs the change touches).
        var caChanges = new List<CaUserQuorumChange>();
        if (caUserQuorums is { Count: > 0 })
        {
            var caIds = caUserQuorums.Select(c => c.CaId).ToList();
            var cas = await db.CertificateAuthorities.Where(c => caIds.Contains(c.Id)).ToListAsync();
            foreach (var c in caUserQuorums)
            {
                var ca = cas.FirstOrDefault(x => x.Id == c.CaId);
                if (ca == null) continue; // CA vanished between request and initiate — drop it.
                caChanges.Add(new CaUserQuorumChange
                {
                    CaId = c.CaId,
                    CurrentQuorum = ca.UserCeremonyRequiredApprovals,
                    ProposedQuorum = c.ProposedQuorum,
                });
            }
        }

        var parameters = new TenantPolicyChangeCeremonyParameters
        {
            TenantId = tenantId,
            CurrentRequireKeyCeremony = tenant.RequireKeyCeremony,
            CurrentCeremonyRequiredApprovals = tenant.CeremonyRequiredApprovals,
            ProposedRequireKeyCeremony = proposedRequireKeyCeremony,
            ProposedCeremonyRequiredApprovals = proposedCeremonyRequiredApprovals,
            UserQuorumIncluded = userQuorumIncluded,
            CurrentUserQuorum = tenant.UserCeremonyRequiredApprovals,
            ProposedUserQuorum = proposedUserQuorum,
            CaUserQuorums = caChanges,
        };

        // camelCase so the stored blob matches the casing of the API envelope it is embedded in.
        var parametersJson = JsonSerializer.Serialize(parameters, SafeJsonOptions.Stored);

        var description = $"Change tenant '{tenant.Name}' ceremony / quorum policy";

        // Do not pass a quorumOverride — KeyCeremonyService.ResolveQuorumAsync (P2b patch)
        // reads the tenant's current CeremonyRequiredApprovals for TenantPolicyChange.
        var ceremony = await keyCeremonyService.InitiateAsync(
            operationType: "TenantPolicyChange",
            description: description,
            targetEntityId: tenantId.ToString(),
            initiatorUserId: initiatorUserId,
            initiatorUsername: initiatorUsername,
            parametersJson: parametersJson);

        // The base InitiateAsync doesn't know about the TenantPolicyChange enum value — stamp it here.
        var tracked = await db.KeyCeremonies.FindAsync(ceremony.Id)
            ?? throw new InvalidOperationException(
                $"Newly-created ceremony {ceremony.Id} could not be re-loaded for CeremonyType stamp.");

        tracked.CeremonyType = CeremonyType.TenantPolicyChange;
        await db.SaveChangesAsync();

        logger.LogInformation(
            "Initiated TenantPolicyChange ceremony {CeremonyId} for tenant {TenantId} (initiator {InitiatorUserId}).",
            tracked.Id, tenantId, initiatorUserId);

        return tracked.Id;
    }

    /// <inheritdoc />
    public async Task<TenantPolicyChangeAppliedResult> ApplyApprovedChangeAsync(Guid ceremonyId)
    {
        var ceremony = await db.KeyCeremonies.FindAsync(ceremonyId)
            ?? throw new InvalidOperationException($"Ceremony {ceremonyId} not found.");

        if (ceremony.Status != "Approved")
        {
            throw new InvalidOperationException(
                $"Ceremony must be in Approved status to apply (current: {ceremony.Status}).");
        }

        TenantPolicyChangeCeremonyParameters? parameters;
        try
        {
            parameters = JsonSerializer.Deserialize<TenantPolicyChangeCeremonyParameters>(
                ceremony.ParametersJson,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException(
                $"Ceremony {ceremonyId} parameters could not be deserialized as TenantPolicyChangeCeremonyParameters.",
                ex);
        }

        if (parameters is null)
        {
            throw new InvalidOperationException(
                $"Ceremony {ceremonyId} parameters deserialized to null.");
        }

        var tenant = await db.Tenants.FindAsync(parameters.TenantId)
            ?? throw new InvalidOperationException(
                $"Tenant {parameters.TenantId} referenced by ceremony {ceremonyId} not found.");

        // State-drift guard — if the tenant row moved since the ceremony was opened, abort.
        if (tenant.RequireKeyCeremony != parameters.CurrentRequireKeyCeremony
            || tenant.CeremonyRequiredApprovals != parameters.CurrentCeremonyRequiredApprovals
            || (parameters.UserQuorumIncluded && tenant.UserCeremonyRequiredApprovals != parameters.CurrentUserQuorum))
        {
            throw new InvalidOperationException(
                "Tenant policy has changed since ceremony was initiated; aborting to prevent an unintended change.");
        }

        // Load + drift-check the CAs this ceremony touches before mutating any of them.
        var caChanges = parameters.CaUserQuorums ?? new List<CaUserQuorumChange>();
        List<Shared.Entities.CertificateAuthorityEntity> cas = new();
        if (caChanges.Count > 0)
        {
            var caIds = caChanges.Select(c => c.CaId).ToList();
            cas = await db.CertificateAuthorities.Where(c => caIds.Contains(c.Id)).ToListAsync();
            foreach (var c in caChanges)
            {
                var ca = cas.FirstOrDefault(x => x.Id == c.CaId);
                if (ca == null)
                    throw new InvalidOperationException($"CA {c.CaId} referenced by ceremony {ceremonyId} not found; aborting.");
                if (ca.UserCeremonyRequiredApprovals != c.CurrentQuorum)
                    throw new InvalidOperationException("A CA quorum has changed since the ceremony was initiated; aborting to prevent an unintended change.");
            }
        }

        var beforeRequire = tenant.RequireKeyCeremony;
        var beforeApprovals = tenant.CeremonyRequiredApprovals;

        if (parameters.ProposedRequireKeyCeremony.HasValue)
            tenant.RequireKeyCeremony = parameters.ProposedRequireKeyCeremony.Value;

        if (parameters.ProposedCeremonyRequiredApprovals.HasValue)
            tenant.CeremonyRequiredApprovals = parameters.ProposedCeremonyRequiredApprovals.Value;

        if (parameters.UserQuorumIncluded)
            tenant.UserCeremonyRequiredApprovals = parameters.ProposedUserQuorum;

        foreach (var c in caChanges)
        {
            var ca = cas.First(x => x.Id == c.CaId);
            ca.UserCeremonyRequiredApprovals = c.ProposedQuorum;
        }

        await db.SaveChangesAsync();

        logger.LogInformation(
            "Applied TenantPolicyChange ceremony {CeremonyId} to tenant {TenantId}: " +
            "RequireKeyCeremony {BeforeRequire}->{AfterRequire}, CeremonyRequiredApprovals {BeforeApprovals}->{AfterApprovals}, " +
            "UserQuorumChanged={UserQuorumChanged}, CaQuorumsChanged={CaQuorumsChanged}.",
            ceremonyId,
            tenant.Id,
            beforeRequire,
            tenant.RequireKeyCeremony,
            beforeApprovals,
            tenant.CeremonyRequiredApprovals,
            parameters.UserQuorumIncluded,
            caChanges.Count);

        return new TenantPolicyChangeAppliedResult(
            tenant.Id,
            beforeRequire,
            beforeApprovals,
            tenant.RequireKeyCeremony,
            tenant.CeremonyRequiredApprovals);
    }
}
