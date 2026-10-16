using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;

namespace ModularCA.Auth.Authorization;

/// <summary>
/// Who could approve a certificate request: the active accounts that pass the Approve endpoint's
/// checks on the request's CA (<see cref="Capabilities.CertRevoke"/>) and on its certificate and
/// signing profiles (<see cref="Capabilities.ProfileUse"/>), other than the requester and anyone
/// who has already approved it.
/// </summary>
/// <param name="RequiredCount">The approvals the request needs (<see cref="RequestApprovals.RequiredCountAsync"/>).</param>
/// <param name="ApprovalCount">The approvals it has.</param>
/// <param name="OthersWhoCanApprove">The accounts, other than the requester, that could still add one.</param>
/// <param name="RequesterMaySelfApprove">Whether the requester's own approval would complete it (<see cref="RequestApprovals.MaySelfApproveAsync"/>).</param>
public sealed record ApprovalOutlook(int RequiredCount, int ApprovalCount, int OthersWhoCanApprove, bool RequesterMaySelfApprove)
{
    /// <summary>Whether the people who can approve it are enough to complete it.</summary>
    public bool CanComplete => RequesterMaySelfApprove || ApprovalCount + OthersWhoCanApprove >= RequiredCount;
}

/// <summary>Works out an <see cref="ApprovalOutlook"/>.</summary>
public static class RequestApprovers
{
    /// <summary>
    /// The outlook of a request routed through <paramref name="signingProfileId"/> under
    /// <paramref name="certProfileId"/>, made by <paramref name="requesterId"/>.
    /// </summary>
    /// <param name="db">The application database.</param>
    /// <param name="auth">The capability checks the Approve endpoint makes.</param>
    /// <param name="policy">The security policy, for self-approval.</param>
    /// <param name="requiredCount">The approvals the request needs.</param>
    /// <param name="signingProfileId">The signing profile the request names.</param>
    /// <param name="certProfileId">The certificate profile the request names.</param>
    /// <param name="requesterId">The requester, or null for a request no account made.</param>
    /// <param name="approvedBy">The accounts that have approved it already.</param>
    public static async Task<ApprovalOutlook> OutlookAsync(
        ModularCADbContext db, ICaGroupAuthorizationService auth, SecurityPolicyEntity policy, int requiredCount,
        Guid? signingProfileId, Guid? certProfileId, Guid? requesterId, IReadOnlyCollection<Guid> approvedBy)
    {
        var caId = await CaOfAsync(db, signingProfileId);
        var others = 0;
        var requesterCanAct = false;
        if (caId is Guid ca)
        {
            var candidates = await db.Users.AsNoTracking()
                .Where(u => u.IsActive && !u.IsDeleted && !u.IsServiceIdentity)
                .Where(u => db.CaGroupMembers.Any(m => m.UserId == u.Id) || db.UserCapabilityGrants.Any(g => g.UserId == u.Id))
                .Select(u => u.Id)
                .ToListAsync();
            foreach (var userId in candidates)
            {
                if (userId != requesterId && approvedBy.Contains(userId))
                    continue;
                if (!await CanApproveAsync(auth, userId, ca, signingProfileId, certProfileId))
                    continue;
                if (userId == requesterId)
                    requesterCanAct = true;
                else
                    others++;
            }
        }
        var selfApproves = requesterCanAct && requesterId is Guid requester
            && !approvedBy.Contains(requester)
            && await RequestApprovals.MaySelfApproveAsync(db, policy, requester);
        return new ApprovalOutlook(requiredCount, approvedBy.Count, others, selfApproves);
    }

    private static async Task<bool> CanApproveAsync(ICaGroupAuthorizationService auth, Guid userId, Guid caId, Guid? signingProfileId, Guid? certProfileId)
        => await auth.HasCaCapabilityAsync(userId, caId, Capabilities.CertRevoke)
            && (certProfileId is not Guid cp || await auth.HasResourceCapabilityAsync(userId, Capabilities.ProfileUse, "CertProfile", cp))
            && (signingProfileId is not Guid sp || await auth.HasResourceCapabilityAsync(userId, Capabilities.ProfileUse, "SigningProfile", sp));

    private static async Task<Guid?> CaOfAsync(ModularCADbContext db, Guid? signingProfileId)
    {
        if (signingProfileId is not Guid id)
            return null;
        var issuerId = await db.SigningProfiles.AsNoTracking().Where(sp => sp.Id == id).Select(sp => sp.IssuerId).FirstOrDefaultAsync();
        return issuerId == null
            ? null
            : await db.CertificateAuthorities.AsNoTracking().Where(ca => ca.CertificateId == issuerId).Select(ca => (Guid?)ca.Id).FirstOrDefaultAsync();
    }
}
