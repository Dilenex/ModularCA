using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Shared.Errors;

namespace ModularCA.API.Services;

/// <summary>
/// The 409 body for a ceremony that was not opened because it could never reach its quorum
/// (<see cref="CeremonyQuorumUnreachableException"/>). One shape for every initiation path:
/// <c>RequestValidationMiddleware</c> sends it for an exception that propagates, and an action
/// that catches the exception itself returns the same body.
/// </summary>
public static class CeremonyRefusalResponse
{
    /// <summary>
    /// Builds the body: the problem fields (<c>detail</c>, <c>code</c>, <c>remediation</c>), the
    /// counts, the scope whose requirement switch applies (<c>requirementScope</c> "instance" or
    /// "space" with <c>spaceId</c> and <c>spaceName</c>, or null when none does), and
    /// <c>canDisableRequirement</c>: true only when a switch applies and the caller is a system
    /// super-administrator under the badge they wear, who may turn it off directly.
    /// </summary>
    public static async Task<object> BuildAsync(HttpContext context, CeremonyQuorumUnreachableException ex, string? correlationId = null)
    {
        var canDisable = false;
        if (ex.RequirementScope != null)
        {
            try
            {
                var userId = context.RequestServices.GetService<ICurrentUserService>()?.UserId;
                var controlled = context.RequestServices.GetService<IControlledUserCeremonyService>();
                if (userId is Guid id && controlled != null)
                    canDisable = await controlled.IsSuperAsync(id);
            }
            catch (Exception)
            {
                canDisable = false;
            }
        }

        return new
        {
            type = "https://tools.ietf.org/html/rfc7231#section-6.5.8",
            title = ex.Title,
            status = ex.Status,
            detail = ex.Message,
            code = ex.Code,
            remediation = ex.RemediationFor(canDisable),
            operationType = ex.OperationType,
            requiredApprovals = ex.RequiredApprovals,
            eligibleApprovers = ex.EligibleApprovers,
            requirementScope = ex.RequirementScope,
            spaceId = ex.SpaceId,
            spaceName = ex.SpaceName,
            canDisableRequirement = canDisable,
            correlationId,
        };
    }
}
