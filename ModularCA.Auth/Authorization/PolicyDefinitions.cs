using Microsoft.AspNetCore.Authorization;
using ModularCA.Shared.Authorization;

namespace ModularCA.Auth.Authorization;

/// <summary>
/// The named capability policies, defined once for the API and the tests that evaluate endpoints
/// through the real policy set. A system-only policy is met only at system scope; a CA-scoped one
/// on the CA the handler resolves from the route, or on any CA when the route names none.
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
            ["CaUser"] = (Capabilities.CertRequest, false),
        };

    /// <summary>Adds every policy of <see cref="All"/> to <paramref name="options"/>.</summary>
    public static void AddTo(AuthorizationOptions options)
    {
        foreach (var (name, (capability, systemOnly)) in All)
            options.AddPolicy(name, policy => policy.Requirements.Add(new CaGroupRequirement(capability, isSystemOnly: systemOnly)));
    }
}
