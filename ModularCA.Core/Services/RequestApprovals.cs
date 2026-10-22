using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Entities;

namespace ModularCA.Core.Services;

/// <summary>
/// How many approvals a certificate request needs, and whether its requester may approve it
/// alone under <see cref="SecurityPolicyEntity.AllowSystemSuperSelfApproval"/>.
/// </summary>
public static class RequestApprovals
{
    /// <summary>
    /// The approvals <paramref name="request"/> needs: the count of the request profile it was made
    /// under, at least 1. A request made under none (older than the column) falls back to the trace
    /// that was used for every request: signing profile, then the protocol configuration that names
    /// it, then that configuration's request profile. 1 when nothing says otherwise.
    /// </summary>
    /// <param name="db">The application database.</param>
    /// <param name="profiles">Resolves a request profile with its inheritance applied.</param>
    /// <param name="request">The request.</param>
    public static async Task<int> RequiredCountAsync(ModularCADbContext db, IProfileResolutionService profiles, CertRequestEntity request)
    {
        if (request.RequestProfileId is Guid ownProfileId)
        {
            try { return Math.Max(1, (await profiles.ResolveRequestProfileAsync(ownProfileId)).RequiredApprovalCount); }
            catch (InvalidOperationException) { return 1; }
        }
        if (request.SigningProfileId is Guid signingProfileId)
        {
            var count = await db.CaProtocolConfigs.AsNoTracking()
                .Where(pc => pc.SigningProfileId == signingProfileId && pc.RequestProfileId != null)
                .Select(pc => (int?)pc.RequestProfile!.RequiredApprovalCount)
                .FirstOrDefaultAsync();
            if (count is int required)
                return Math.Max(1, required);
        }
        return 1;
    }

    /// <summary>
    /// Whether <paramref name="userId"/> may approve requests they made themselves: the security
    /// policy allows it (<see cref="SecurityPolicyEntity.AllowSystemSuperSelfApproval"/>) and they
    /// belong to the system-super group. Such an approval completes the request whatever its count,
    /// since on a single-administrator instance nobody else could add to it.
    /// </summary>
    /// <param name="db">The application database.</param>
    /// <param name="policy">The security policy.</param>
    /// <param name="userId">The requester.</param>
    public static async Task<bool> MaySelfApproveAsync(ModularCADbContext db, SecurityPolicyEntity policy, Guid userId)
        => policy.AllowSystemSuperSelfApproval
            && await db.CaGroupMembers.AnyAsync(gm => gm.UserId == userId && gm.Group.IsSystemTierSuper);

    /// <summary>Whether <paramref name="request"/> was approved by its own requester.</summary>
    /// <param name="request">The request.</param>
    /// <param name="approverId">The approver.</param>
    public static bool IsSelfApproval(CertRequestEntity request, Guid approverId)
        => request.RequestorUserId is Guid requester && requester == approverId;
}
