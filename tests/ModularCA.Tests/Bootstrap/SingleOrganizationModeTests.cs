using Microsoft.EntityFrameworkCore;
using ModularCA.Bootstrap;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Licensing;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Bootstrap;

/// <summary>
/// Single-organisation mode: a second organisation tenant is refused unless
/// <c>Features.AllowMultipleOrganizations</c> is set, and bootstrap creates the first
/// organisation, idempotently, and no system tenant.
/// </summary>
public class SingleOrganizationModeTests
{
    [Fact]
    public void The_flag_is_off_by_default()
    {
        Assert.False(new SystemConfig().Features.AllowMultipleOrganizations);
    }

    [Fact]
    public void A_second_organisation_is_refused_with_its_code()
    {
        var refusal = TenantCreationGate.EvaluateOrganizationMode(allowMultipleOrganizations: false, existingOrganizationCount: 1);
        Assert.NotNull(refusal);
        Assert.Equal(ErrorCodes.MultipleOrganizationsDisabled, refusal.Code);
        Assert.Equal(400, refusal.Status);
        Assert.Contains("Features.AllowMultipleOrganizations", refusal.Remediation);
    }

    [Fact]
    public void The_first_organisation_is_allowed()
    {
        Assert.Null(TenantCreationGate.EvaluateOrganizationMode(allowMultipleOrganizations: false, existingOrganizationCount: 0));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(7)]
    public void The_flag_allows_further_organisations(int existing)
    {
        Assert.Null(TenantCreationGate.EvaluateOrganizationMode(allowMultipleOrganizations: true, existingOrganizationCount: existing));
    }

    [Fact]
    public void Bootstrap_creates_one_organisation_and_no_system_tenant_idempotently()
    {
        var name = $"bootstrap-{Guid.NewGuid():N}";
        using (var db = InMemoryDbContextFactory.Create(name))
        {
            var org = BootstrapModularCA.EnsureBootstrapTenants(db, "Acme Corp", null);
            Assert.Equal("acme-corp", org.Slug);
        }

        using (var db = InMemoryDbContextFactory.Create(name))
        {
            var groupsBefore = db.CaGroups.Count();
            var org = BootstrapModularCA.EnsureBootstrapTenants(db, "Acme Corp", null);
            Assert.Equal(1, db.Tenants.IgnoreQueryFilters().Count());
            Assert.Equal(groupsBefore, db.CaGroups.Count());
            Assert.Equal(4, groupsBefore);
            Assert.DoesNotContain(db.CaGroups, g => g.Name.StartsWith("org-system-"));
            Assert.Equal("acme-corp", org.Slug);
        }
    }

    [Fact]
    public void Bootstrap_system_groups_and_instance_ca_groups_have_no_tenant()
    {
        using var db = InMemoryDbContextFactory.Create();
        BootstrapProfileSeeder.SeedBuiltInRoles(db);
        BootstrapProfileSeeder.CreateSystemGroups(db);
        var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "System Signing CA", Label = "system-signing-ca", TenantId = null };
        db.CertificateAuthorities.Add(ca);
        db.SaveChanges();
        BootstrapProfileSeeder.CreateCaGroups(db, ca, null);

        Assert.All(db.CaGroups.ToList(), g => Assert.Null(g.TenantId));
        Assert.Contains(db.CaGroups, g => g.Name == "system_system-signing-ca_admin" && g.CertificateAuthorityId == ca.Id);
        Assert.Equal(4, db.CaGroups.Count(g => g.IsSystemGroup));
    }

    [Fact]
    public void Bootstrap_never_creates_a_second_organisation()
    {
        using var db = InMemoryDbContextFactory.Create();
        db.Tenants.Add(new TenantEntity { Name = "Existing", Slug = "existing", IsEnabled = true });
        db.SaveChanges();

        var ex = Assert.Throws<ConfigurationValidationException>(
            () => BootstrapModularCA.EnsureBootstrapTenants(db, "Other Org", null));
        Assert.Equal(ErrorCodes.BootstrapDatabaseNotEmpty, ex.Code);
        Assert.Contains("Existing", ex.Message);
        Assert.Contains("Other Org", ex.Message);
        Assert.DoesNotContain("AllowMultipleOrganizations", ex.Remediation);
        Assert.Equal(1, db.Tenants.IgnoreQueryFilters().Count());
    }

    [Fact]
    public void A_disabled_organisation_still_blocks_bootstrap()
    {
        using var db = InMemoryDbContextFactory.Create();
        db.Tenants.Add(new TenantEntity { Name = "Dormant", Slug = "dormant", IsEnabled = false });
        db.SaveChanges();

        var ex = Assert.Throws<ConfigurationValidationException>(
            () => BootstrapModularCA.EnsureBootstrapTenants(db, "Other Org", null));
        Assert.Equal(ErrorCodes.BootstrapDatabaseNotEmpty, ex.Code);
        Assert.Contains("(disabled)", ex.Message);
    }

    [Fact]
    public void A_disabled_organisation_still_counts_for_single_organisation_mode()
    {
        var refusal = TenantCreationGate.EvaluateOrganizationMode(false, 1, "Dormant", blockingOrganizationDisabled: true);
        Assert.NotNull(refusal);
        Assert.Contains("Dormant", refusal.Message);
        Assert.Contains("disabled", refusal.Message);
        Assert.Contains("Stop the service", refusal.Remediation);
    }

    [Fact]
    public void Startup_warns_when_the_instance_already_holds_several_organisations()
    {
        var warning = TenantCreationGate.SingleOrganizationStartupWarning(false, [("Acme", true), ("Dormant", false)]);

        Assert.NotNull(warning);
        Assert.Contains("holds 2 organisations", warning);
        Assert.Contains("'Acme'", warning);
        Assert.Contains("'Dormant' (disabled)", warning);
        Assert.Contains(ErrorCodes.MultipleOrganizationsDisabled, warning);
        Assert.Contains("Features.AllowMultipleOrganizations: true", warning);
    }

    [Fact]
    public void Startup_is_silent_for_one_organisation_or_with_the_flag_on()
    {
        Assert.Null(TenantCreationGate.SingleOrganizationStartupWarning(false, []));
        Assert.Null(TenantCreationGate.SingleOrganizationStartupWarning(false, [("Acme", true)]));
        Assert.Null(TenantCreationGate.SingleOrganizationStartupWarning(true, [("Acme", true), ("Beta", true)]));
    }

    [Fact]
    public void The_control_role_logs_the_single_organisation_warning_at_startup()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !dir.EnumerateFiles("ModularCA.sln").Any())
            dir = dir.Parent;
        Assert.NotNull(dir);
        var startup = File.ReadAllText(Path.Combine(dir!.FullName, "ModularCA.API", "StartModularCA.cs"));

        var call = startup.IndexOf("TenantCreationGate.SingleOrganizationStartupWarning(", StringComparison.Ordinal);
        Assert.True(call > 0, "StartModularCA no longer computes the single-organisation startup warning.");
        var guard = startup.LastIndexOf("if (!isSetupMode && controlActive && !config.Features.AllowMultipleOrganizations)", call, StringComparison.Ordinal);
        Assert.True(guard > 0 && call - guard < 1500, "The warning must run for the control role outside setup mode.");
        Assert.Contains("Log.Warning(\"{SingleOrganizationWarning}\", organisationWarning)", startup[call..(call + 800)]);
    }
}
