using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;

namespace ModularCA.Auth.Authorization;

/// <summary>
/// "Signed in and holds <see cref="RequiredCapability"/> at some scope": at system scope, across
/// some space, or on some CA. It is a gate, not a decision. It exists for the write routes whose
/// target is a user account, which belongs to no CA: the route can never name the CA a CA-scoped
/// policy would check, so the action itself decides against the target (which scopes the account
/// holds anything in, and whether the caller holds the capability on every one of them).
/// </summary>
/// <remarks>
/// Use it only on an action that makes that decision for itself. On any other write it would be
/// the cross-CA downgrade that <see cref="CaGroupAuthorizationHandler"/> refuses: a caller who
/// holds the capability on one small CA would pass for a target anywhere.
/// </remarks>
public sealed class AnyScopeCapabilityRequirement(string requiredCapability) : IAuthorizationRequirement
{
    /// <summary>The capability the caller must hold at some scope.</summary>
    public string RequiredCapability { get; } = requiredCapability;
}

/// <summary>
/// Evaluates <see cref="AnyScopeCapabilityRequirement"/>. Separate from
/// <see cref="CaGroupAuthorizationHandler"/> on purpose: that handler's refusal of a CA-scoped
/// write with no resolvable CA stays unconditional, and only a policy that names this
/// requirement gets the "held somewhere" rule.
/// </summary>
public sealed class AnyScopeCapabilityAuthorizationHandler(ICaGroupAuthorizationService authService)
    : AuthorizationHandler<AnyScopeCapabilityRequirement>
{
    /// <summary>
    /// Succeeds when the authenticated user holds the capability at system scope (or is a system
    /// admin), space-wide in at least one space, or on at least one CA, under the badge they wear.
    /// </summary>
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, AnyScopeCapabilityRequirement requirement)
    {
        var sub = context.User?.FindFirst(ClaimTypes.NameIdentifier)?.Value
               ?? context.User?.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
        if (!Guid.TryParse(sub, out var userId))
            return;

        if (await UserAdministrationAccess.HoldsAtSomeScopeAsync(authService, userId, requirement.RequiredCapability))
            context.Succeed(requirement);
    }
}
