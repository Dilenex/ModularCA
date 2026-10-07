using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Authorization;
using ModularCA.Core.Services;
using ModularCA.Tests.Auth;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Which groups an LDAP mapping may target. The rule (<see cref="LdapGroupSyncService.IsRefusedMappingTarget"/>)
/// is shared with the console's group picker through ldap-mapping-cases.json, and the console learns
/// whether a group is controlled from GET /admin/groups, which classifies every group in one pass
/// (<see cref="ControlledTierResolver.ClassifyGroupsAsync"/>); that must agree with the per-group
/// classification validation and sync use.
/// </summary>
public class LdapMappingTargetTests
{
    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "ModularCA.sln")))
            dir = dir.Parent;
        Assert.NotNull(dir);
        return dir!.FullName;
    }

    public static IEnumerable<object[]> TargetCases()
    {
        var path = Path.Combine(RepoRoot(), "tests", "modularca.web.tests", "src", "adminui", "ldap-mapping-cases.json");
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        return doc.RootElement.GetProperty("targets").EnumerateArray().Select(e => new object[]
        {
            e.GetProperty("isSystemGroup").GetBoolean(), e.GetProperty("isSystemTierSuper").GetBoolean(),
            e.GetProperty("isControlled").GetBoolean(), e.GetProperty("refused").GetBoolean(),
        }).ToList();
    }

    [Theory, MemberData(nameof(TargetCases))]
    public void Refuses_system_and_controlled_targets_as_the_console_does(bool isSystemGroup, bool isSystemTierSuper, bool isControlled, bool refused)
        => Assert.Equal(refused, LdapGroupSyncService.IsRefusedMappingTarget(isSystemGroup, isSystemTierSuper, isControlled));

    [Fact]
    public async Task Classifying_all_groups_at_once_matches_classifying_each()
    {
        var w = new ControlledUserWorld();
        var groups = await w.Db.CaGroups.AsNoTracking().ToListAsync();
        Assert.NotEmpty(groups);

        var batch = await ControlledTierResolver.ClassifyGroupsAsync(w.Db, groups);

        foreach (var g in groups)
            Assert.Equal(await ControlledTierResolver.ClassifyGroupAsync(w.Db, g), batch[g.Id]);
        Assert.Contains(batch.Values, t => t != null);
        Assert.Contains(batch.Values, t => t == null);
    }
}
