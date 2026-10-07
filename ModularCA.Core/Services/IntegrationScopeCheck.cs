using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;

namespace ModularCA.Core.Services;

/// <summary>
/// Warns about an integration API key fenced to a space that does not exist. Such a key reaches no
/// CA and fails every request without saying why; the usual cause is a key scoped to
/// the system tenant, which 0.4.0 folded into the instance.
/// </summary>
public static class IntegrationScopeCheck
{
    /// <summary>The integration keys whose <c>SpaceId</c> is set, by their config key name, with the value.</summary>
    public static IReadOnlyList<(string Key, string Value)> Configured(SystemConfig config) =>
        new[] { ("IntegrationApi.SpaceId", config.IntegrationApi?.SpaceId), ("CertManager.SpaceId", config.CertManager?.SpaceId) }
            .Where(k => !string.IsNullOrWhiteSpace(k.Item2))
            .Select(k => (k.Item1, k.Item2!.Trim()))
            .ToList();

    /// <summary>
    /// One warning per configured <c>SpaceId</c> that names no existing space (a soft-deleted one
    /// included) or is neither a space id nor <c>instance</c>, naming the key; empty when none does.
    /// </summary>
    public static async Task<IReadOnlyList<string>> WarningsAsync(ModularCADbContext db, SystemConfig config, CancellationToken ct = default)
    {
        var warnings = new List<string>();
        foreach (var (key, value) in Configured(config))
        {
            var scope = IntegrationSpaceScope.Parse(value);
            if (scope.Kind == IntegrationScopeKind.Invalid)
                warnings.Add($"{key} is '{value}', which is neither a space id nor '{IntegrationSpaceScope.InstanceValue}': the key reaches no CA, "
                    + $"so every request it makes is refused or finds nothing. Set it to a space's id, to '{IntegrationSpaceScope.InstanceValue}' "
                    + "for the instance's CAs only, or remove it for every CA.");
            else if (scope.Kind == IntegrationScopeKind.Space && !await db.Spaces.AsNoTracking().AnyAsync(s => s.Id == scope.SpaceId, ct))
                warnings.Add($"{key} names space {scope.SpaceId}, which does not exist: the key reaches no CA, so every request it makes "
                    + $"is refused or finds nothing. If it named the system tenant before 0.4.0, set it to '{IntegrationSpaceScope.InstanceValue}' "
                    + "for the instance's CAs; otherwise set it to an existing space's id, or remove it for every CA.");
        }
        return warnings;
    }
}
