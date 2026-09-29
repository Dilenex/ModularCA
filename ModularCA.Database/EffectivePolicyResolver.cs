using Microsoft.EntityFrameworkCore;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;

namespace ModularCA.Database;

/// <summary>
/// The CA policy that governs one scope. Scopes are independent: the instance's values govern
/// instance CAs (a null tenant) and a space's values govern that space's CAs. Nothing merges.
/// </summary>
/// <param name="TenantId">The space the policy belongs to, or null for the instance.</param>
/// <param name="Scope">"instance", or the space's name, for diagnostics.</param>
/// <param name="Found">
/// False when <paramref name="TenantId"/> names no space. The values are then the strict
/// defaults, and a caller that must verify a waiver refuses instead.
/// </param>
/// <param name="IsEnabled">Whether the scope may issue. The instance is always enabled.</param>
/// <param name="RequireKeyCeremony">Whether creating, revoking or deleting a CA needs a ceremony.</param>
/// <param name="CeremonyRequiredApprovals">Approvals a key ceremony needs.</param>
/// <param name="MaxValidityDays">Longest leaf validity in days; 0 is unlimited.</param>
/// <param name="ValidityCeilingBehavior">What happens above <paramref name="MaxValidityDays"/>.</param>
/// <param name="UserCeremonyRequiredApprovals">The scope's CA-level user quorum; null means 1.</param>
public sealed record EffectivePolicy(
    Guid? TenantId,
    string Scope,
    bool Found,
    bool IsEnabled,
    bool RequireKeyCeremony,
    int CeremonyRequiredApprovals,
    int MaxValidityDays,
    ValidityCeilingBehavior ValidityCeilingBehavior,
    int? UserCeremonyRequiredApprovals)
{
    /// <summary>The name used in diagnostics for the instance scope.</summary>
    public const string InstanceScope = "instance";

    /// <summary>"the instance", or "tenant '&lt;name&gt;'", for messages.</summary>
    public string Describe() => TenantId == null ? "the instance" : $"tenant '{Scope}'";

    /// <summary>The instance's policy from its <see cref="SecurityPolicyEntity"/> row, or the entity defaults when there is none.</summary>
    public static EffectivePolicy ForInstance(SecurityPolicyEntity? policy)
    {
        policy ??= new SecurityPolicyEntity();
        return new EffectivePolicy(null, InstanceScope, true, true, policy.RequireKeyCeremony,
            policy.CeremonyRequiredApprovals, policy.MaxValidityDays, policy.ValidityCeilingBehavior,
            policy.UserCeremonyRequiredApprovals);
    }

    /// <summary>A space's policy from its tenant row.</summary>
    public static EffectivePolicy ForSpace(TenantEntity tenant) =>
        new(tenant.Id, tenant.Name, true, tenant.IsEnabled, tenant.RequireKeyCeremony,
            tenant.CeremonyRequiredApprovals, tenant.MaxValidityDays, tenant.ValidityCeilingBehavior,
            tenant.UserCeremonyRequiredApprovals);

    /// <summary>The strict policy reported for a tenant id that names no space.</summary>
    public static EffectivePolicy Unknown(Guid tenantId)
    {
        var strict = new TenantEntity();
        return new EffectivePolicy(tenantId, tenantId.ToString(), false, false, true,
            strict.CeremonyRequiredApprovals, strict.MaxValidityDays, strict.ValidityCeilingBehavior, null);
    }
}

/// <summary>
/// Resolves the CA policy of a scope. Every reader of RequireKeyCeremony, the key-ceremony
/// quorum, the validity ceiling or the CA-level user quorum goes through it, so a null tenant
/// always means the instance's policy and never "no policy".
/// </summary>
public interface IEffectivePolicyResolver
{
    /// <summary>
    /// The policy of <paramref name="tenantId"/>: the instance's for null, the space's otherwise,
    /// and <see cref="EffectivePolicy.Unknown"/> for an id that names no live space. The
    /// caller's query filters do not hide a space's policy; soft deletion does.
    /// </summary>
    Task<EffectivePolicy> ResolveAsync(Guid? tenantId, CancellationToken cancellationToken = default);

    /// <summary>
    /// The policy of the CA <paramref name="caId"/>'s scope, or null when no such live CA
    /// exists. The caller's query filters do not hide the CA.
    /// </summary>
    Task<EffectivePolicy?> ResolveForCaAsync(Guid caId, CancellationToken cancellationToken = default);
}

/// <summary>EF implementation of <see cref="IEffectivePolicyResolver"/>.</summary>
public sealed class EffectivePolicyResolver(ModularCADbContext db) : IEffectivePolicyResolver
{
    /// <inheritdoc />
    public async Task<EffectivePolicy> ResolveAsync(Guid? tenantId, CancellationToken cancellationToken = default)
    {
        if (tenantId is not Guid id)
            return EffectivePolicy.ForInstance(await db.SecurityPolicies.AsNoTracking().FirstOrDefaultAsync(cancellationToken));

        var tenant = await db.Tenants.IgnoreQueryFilters().AsNoTracking().FirstOrDefaultAsync(t => t.Id == id && !t.IsDeleted, cancellationToken);
        return tenant == null ? EffectivePolicy.Unknown(id) : EffectivePolicy.ForSpace(tenant);
    }

    /// <inheritdoc />
    public async Task<EffectivePolicy?> ResolveForCaAsync(Guid caId, CancellationToken cancellationToken = default)
    {
        var ca = await db.CertificateAuthorities.IgnoreQueryFilters().AsNoTracking()
            .Where(c => c.Id == caId && !c.IsDeleted)
            .Select(c => new { c.TenantId })
            .FirstOrDefaultAsync(cancellationToken);
        return ca == null ? null : await ResolveAsync(ca.TenantId, cancellationToken);
    }
}
