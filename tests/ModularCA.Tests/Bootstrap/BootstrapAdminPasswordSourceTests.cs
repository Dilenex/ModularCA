using System.Reflection;
using ModularCA.Auth.Services;
using ModularCA.Bootstrap;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Utils;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Bootstrap;

/// <summary>
/// Every path that creates an install's first administrator gives it the password source Local,
/// so break-glass password sign-in never depends on the directory: not during an LDAP outage, and
/// not in direct-bind mode, where an unknown user and a refused bind look the same.
/// </summary>
public class BootstrapAdminPasswordSourceTests
{
    private const string Password = "Initial-Admin-Passw0rd!xyz";

    /// <summary>A database holding the two system groups the first administrator joins.</summary>
    private static ModularCADbContext Seeded()
    {
        var db = InMemoryDbContextFactory.Create();
        db.CaGroups.AddRange(
            new CaGroupEntity { Name = "system-super", DisplayName = "system-super", IsSystemGroup = true, IsSystemTierSuper = true },
            new CaGroupEntity { Name = "system-admin", DisplayName = "system-admin", IsSystemGroup = true });
        db.SaveChanges();
        return db;
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void The_headless_bootstrap_administrator_is_local(bool byClaim)
    {
        using var db = Seeded();
        var configDir = Directory.CreateTempSubdirectory("mca-admin-source-").FullName;
        try
        {
            var administration = new YamlBootstrapLoader.AdministrationConfig
            {
                ClaimTokenSha256 = byClaim ? AccountClaims.HashHex(AccountClaims.NewToken()) : null,
            };

            BootstrapProfileSeeder.CreateInitialUser(db, configDir, administration, TextWriter.Null);

            Assert.Equal(PasswordSource.Local, Assert.Single(db.Users).PasswordSource);
        }
        finally
        {
            Directory.Delete(configDir, recursive: true);
        }
    }

    [Theory]
    [InlineData("CreateInitialUserWithUsername")]
    [InlineData("CreateInitialUserWithPassword")]
    public void The_setup_wizard_administrator_is_local(string method)
    {
        using var db = Seeded();
        var create = typeof(BootstrapService).GetMethod(method, BindingFlags.NonPublic | BindingFlags.Static)!;

        create.Invoke(null, method == "CreateInitialUserWithPassword"
            ? new object?[] { db, "admin", Password, "admin@example.test" }
            : new object?[] { db, "admin", "admin@example.test" });

        var admin = Assert.Single(db.Users);
        Assert.Equal("admin", admin.Username);
        Assert.Equal(PasswordSource.Local, admin.PasswordSource);
    }
}
