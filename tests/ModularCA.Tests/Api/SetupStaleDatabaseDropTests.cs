using ModularCA.Tests.Roles;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// The setup wizard's stale-database recovery dropped the audit database with the application
/// database every time, though a command-line reset keeps audit history unless told otherwise
/// (<c>--wipe-audit</c>). It now drops the audit database only when asked.
/// </summary>
public class SetupStaleDatabaseDropTests
{
    private static IReadOnlyList<string> DatabasesToDrop(string? app, string? audit, bool wipeAudit)
        => (IReadOnlyList<string>)ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.SetupController")
            .GetMethod("DatabasesToDrop")!.Invoke(null, [app, audit, wipeAudit])!;

    [Fact]
    public void The_audit_database_is_kept_by_default()
    {
        Assert.Equal(["modularca"], DatabasesToDrop("modularca", "modularca-audit", wipeAudit: false));

        var body = Activator.CreateInstance(ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.SetupDropDatabasesRequest"))!;
        Assert.False((bool)body.GetType().GetProperty("WipeAudit")!.GetValue(body)!);
    }

    [Fact]
    public void Asked_to_wipe_it_drops_both()
        => Assert.Equal(["modularca", "modularca-audit"], DatabasesToDrop("modularca", "modularca-audit", wipeAudit: true));

    [Fact]
    public void Blank_and_repeated_names_are_skipped()
    {
        Assert.Equal(["modularca-audit"], DatabasesToDrop(" ", "modularca-audit", wipeAudit: true));
        Assert.Equal(["modularca"], DatabasesToDrop("modularca", "modularca", wipeAudit: true));
        Assert.Empty(DatabasesToDrop(null, "modularca-audit", wipeAudit: false));
    }
}
