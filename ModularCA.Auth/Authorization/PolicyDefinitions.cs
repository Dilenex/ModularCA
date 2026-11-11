using Microsoft.AspNetCore.Authorization;
using ModularCA.Shared.Authorization;

namespace ModularCA.Auth.Authorization;

/// <summary>
/// The named capability policies, defined once for the API and the tests that evaluate endpoints
/// through the real policy set. A system-only policy is met only at system scope; a CA-scoped one
/// on the CA the handler resolves from the route, or on any CA when the route names none (reads
/// only; a write that names no CA is refused below system scope). <see cref="HeldAtSomeScope"/>
/// holds the gates of the user-administration routes, which decide inside the action.
/// </summary>
public static class PolicyDefinitions
{
    /// <summary>Policy name → the capability it demands and whether only system scope meets it.</summary>
    public static readonly IReadOnlyDictionary<string, (string Capability, bool SystemOnly)> All =
        new Dictionary<string, (string, bool)>(StringComparer.Ordinal)
        {
            ["SystemAdmin"] = (Capabilities.SystemManage, true),
            ["SystemOperator"] = (Capabilities.CaManage, true),
            ["SystemAuditor"] = (Capabilities.AuditView, true),
            ["CaAdmin"] = (Capabilities.CaManage, false),
            ["CaOperator"] = (Capabilities.CertRevoke, false),
            ["CaAuditor"] = (Capabilities.CertView, false),
            // The directory of a scope: who its users are and what groups it has. Not CaAuditor:
            // a requester holds cert.view to see certificates, and has no business reading the
            // list of accounts, their e-mail addresses, last sign-in and memberships.
            ["CaDirectoryViewer"] = (Capabilities.GroupView, false),
            ["CaUser"] = (Capabilities.CertRequest, false),
            // Resetting an account's second factor stays a system matter: with a password reset
            // it is a complete takeover of the account, so no scoped administrator gets both.
            ["SystemUserAdministrator"] = (Capabilities.UserManage, true),
        };

    /// <summary>
    /// Policy name → the capability it demands at SOME scope (system, a space, or a CA):
    /// <see cref="AnyScopeCapabilityRequirement"/>. These are gates for the user-administration
    /// routes only. A user account belongs to no CA, so their routes can never name one, and a
    /// CA-scoped policy from <see cref="All"/> refuses every such write below system scope. The
    /// gate lets a scoped administrator reach the action; the action then decides against the
    /// target account (<see cref="UserAdministrationAccess"/> for account changes,
    /// <see cref="GroupAssignmentAccess"/> for memberships), and refuses what the caller's own
    /// scope does not cover. Do not put one on an action that does not make that decision.
    /// <para>
    /// The capabilities are <c>user.manage</c> and <c>group.manage</c>, not <c>ca.manage</c>: the
    /// Administrator role holds them and the Operator role does not, so an operator stays out of
    /// user administration.
    /// </para>
    /// </summary>
    public static readonly IReadOnlyDictionary<string, string> HeldAtSomeScope =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["UserAdministrator"] = Capabilities.UserManage,
            ["GroupMembershipAdministrator"] = Capabilities.GroupManage,
        };

    /// <summary>Adds every policy of <see cref="All"/> and <see cref="HeldAtSomeScope"/> to <paramref name="options"/>.</summary>
    public static void AddTo(AuthorizationOptions options)
    {
        foreach (var (name, (capability, systemOnly)) in All)
            options.AddPolicy(name, policy => policy.Requirements.Add(new CaGroupRequirement(capability, isSystemOnly: systemOnly)));
        foreach (var (name, capability) in HeldAtSomeScope)
            options.AddPolicy(name, policy => policy.Requirements.Add(new AnyScopeCapabilityRequirement(capability)));
    }
}
