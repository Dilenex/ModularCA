using Microsoft.EntityFrameworkCore;
using ModularCA.Bootstrap;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Errors;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Bootstrap;

/// <summary>
/// Bootstrap creates the first space, named after the organisation, idempotently and with no
/// system space, and refuses a database that already holds a different space.
/// </summary>
public class BootstrapFirstSpaceTests
{
    [Fact]
    public void Bootstrap_creates_one_space_and_no_system_space_idempotently()
    {
        var name = $"bootstrap-{Guid.NewGuid():N}";
        using (var db = InMemoryDbContextFactory.Create(name))
        {
            var space = BootstrapModularCA.EnsureBootstrapSpaces(db, "Acme Corp", null);
            Assert.Equal("acme-corp", space.Slug);
        }

        using (var db = InMemoryDbContextFactory.Create(name))
        {
            var groupsBefore = db.CaGroups.Count();
            var space = BootstrapModularCA.EnsureBootstrapSpaces(db, "Acme Corp", null);
            Assert.Equal(1, db.Spaces.IgnoreQueryFilters().Count());
            Assert.Equal(groupsBefore, db.CaGroups.Count());
            Assert.Equal(4, groupsBefore);
            Assert.DoesNotContain(db.CaGroups, g => g.Name.StartsWith("org-system-"));
            Assert.Equal("acme-corp", space.Slug);
        }
    }

    [Fact]
    public void Bootstrap_system_groups_and_instance_ca_groups_have_no_space()
    {
        using var db = InMemoryDbContextFactory.Create();
        BootstrapProfileSeeder.SeedBuiltInRoles(db);
        BootstrapProfileSeeder.CreateSystemGroups(db);
        var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "System Signing CA", Label = "system-signing-ca", SpaceId = null };
        db.CertificateAuthorities.Add(ca);
        db.SaveChanges();
        BootstrapProfileSeeder.CreateCaGroups(db, ca, null);

        Assert.All(db.CaGroups.ToList(), g => Assert.Null(g.SpaceId));
        Assert.Contains(db.CaGroups, g => g.Name == "system_system-signing-ca_admin" && g.CertificateAuthorityId == ca.Id);
        Assert.Equal(4, db.CaGroups.Count(g => g.IsSystemGroup));
    }

    [Fact]
    public void Bootstrap_never_creates_a_second_space()
    {
        using var db = InMemoryDbContextFactory.Create();
        db.Spaces.Add(new SpaceEntity { Name = "Existing", Slug = "existing", IsEnabled = true });
        db.SaveChanges();

        var ex = Assert.Throws<ConfigurationValidationException>(
            () => BootstrapModularCA.EnsureBootstrapSpaces(db, "Other Org", null));
        Assert.Equal(ErrorCodes.BootstrapDatabaseNotEmpty, ex.Code);
        Assert.Contains("Existing", ex.Message);
        Assert.Contains("Other Org", ex.Message);
        Assert.DoesNotContain("AllowMultipleOrganizations", ex.Remediation);
        Assert.Equal(1, db.Spaces.IgnoreQueryFilters().Count());
    }

    [Fact]
    public void A_disabled_space_still_blocks_bootstrap()
    {
        using var db = InMemoryDbContextFactory.Create();
        db.Spaces.Add(new SpaceEntity { Name = "Dormant", Slug = "dormant", IsEnabled = false });
        db.SaveChanges();

        var ex = Assert.Throws<ConfigurationValidationException>(
            () => BootstrapModularCA.EnsureBootstrapSpaces(db, "Other Org", null));
        Assert.Equal(ErrorCodes.BootstrapDatabaseNotEmpty, ex.Code);
        Assert.Contains("(disabled)", ex.Message);
    }

    [Fact]
    public void The_control_role_no_longer_counts_organisations_at_startup()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !dir.EnumerateFiles("ModularCA.sln").Any())
            dir = dir.Parent;
        Assert.NotNull(dir);
        var startup = File.ReadAllText(Path.Combine(dir!.FullName, "ModularCA.API", "StartModularCA.cs"));

        Assert.DoesNotContain("AllowMultipleOrganizations", startup);
        Assert.DoesNotContain("SingleOrganization", startup);
    }
}
