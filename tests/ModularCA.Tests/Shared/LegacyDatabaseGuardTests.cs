using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using Xunit;

namespace ModularCA.Tests.Shared;

/// <summary>
/// Pins the refusal that stands between this build and a MariaDB database.
/// <para>
/// The failure this guards against is not a crash, it is a destructive success: pointed at the
/// MariaDB instance a 0.3.0 deployment is using, an unguarded build would connect and begin
/// applying an <c>InitialCreate</c> migration over a live certificate authority. The guard has
/// to fire before any connection is opened, and it has to say what the operator should have
/// done instead — so these tests assert on the message as well as on the refusal.
/// </para>
/// </summary>
public class LegacyDatabaseGuardTests
{
    private static DbConfig Config(int appPort, int auditPort) => new()
    {
        App = new DbInstance { Host = "db.example.com", Port = appPort, Database = "modularca-app" },
        Audit = new DbInstance { Host = "db.example.com", Port = auditPort, Database = "modularca-audit" },
    };

    [Fact]
    public void Accepts_A_PostgreSQL_Configuration()
    {
        LegacyDatabaseGuard.EnsureNotMySql(Config(5432, 5432));
    }

    [Fact]
    public void Accepts_A_NonDefault_Port()
    {
        // The check must not become "anything unusual is MySQL": operators run PostgreSQL on
        // whatever port they like, and refusing one of those would be a false refusal with a
        // very confusing message.
        LegacyDatabaseGuard.EnsureNotMySql(Config(6432, 6432));
    }

    [Fact]
    public void Refuses_When_The_App_Database_Is_On_3306()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => LegacyDatabaseGuard.EnsureNotMySql(Config(3306, 5432)));
        Assert.Contains("DB.App", ex.Message);
        Assert.Contains("docs/architecture/postgresql-migration.md", ex.Message);
    }

    [Fact]
    public void Refuses_When_Only_The_Audit_Database_Is_On_3306()
    {
        // A half-migrated configuration is exactly the state a partial upgrade leaves behind,
        // and it is the one most likely to be missed by a check that only looked at the app DB.
        var ex = Assert.Throws<InvalidOperationException>(() => LegacyDatabaseGuard.EnsureNotMySql(Config(5432, 3306)));
        Assert.Contains("DB.Audit", ex.Message);
    }

    [Fact]
    public void Refusal_Names_Both_Databases_When_Both_Are_Legacy()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => LegacyDatabaseGuard.EnsureNotMySql(Config(3306, 3306)));
        Assert.Contains("DB.App", ex.Message);
        Assert.Contains("DB.Audit", ex.Message);
    }

    [Fact]
    public void Refusal_Describes_The_Three_Step_Upgrade_Path()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => LegacyDatabaseGuard.EnsureNotMySql(Config(3306, 3306)));
        Assert.Contains("0.3.0", ex.Message);
        Assert.Contains("migration helper", ex.Message);
    }

    [Theory]
    [InlineData("Server=db;Uid=root;Pwd=secret;Database=modularca-app")]
    [InlineData("Server=db;Port=3306;User ID=root;Password=secret")]
    [InlineData("Server=db;User ID=root;Password=secret;SslMode=Preferred")]
    public void Refuses_A_MySqlConnector_Connection_String(string connectionString)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => LegacyDatabaseGuard.EnsureNotMySql(connectionString));
        Assert.Contains("docs/architecture/postgresql-migration.md", ex.Message);
    }

    [Theory]
    [InlineData("Host=db;Port=5432;Username=modularca_app;Password=secret;Database=modularca-app")]
    [InlineData("")]
    [InlineData(null)]
    public void Accepts_A_Npgsql_Connection_String_Or_None(string? connectionString)
    {
        LegacyDatabaseGuard.EnsureNotMySql(connectionString);
    }
}
