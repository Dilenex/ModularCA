using System.Reflection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// An integration key's <c>SpaceId</c> since the system tenant was folded into the instance:
/// <c>instance</c> fences it to the instance's CAs, a space that does not exist is named at start,
/// the upgrade check refuses a key scoped to the system tenant, and cert-manager refuses a signing
/// profile whose CA it cannot establish rather than letting it through.
/// </summary>
public class IntegrationSpaceScopeTests
{
    private static readonly Guid Space = Guid.Parse("5c4b3a29-1807-4f6e-9d5c-4b3a29180706");
    private static readonly Guid SystemTenant = Guid.Parse("00000000-0000-0000-0000-000000000001");

    [Fact]
    public async Task A_SpaceId_naming_no_space_or_neither_a_space_nor_instance_is_warned_about_by_key()
    {
        using var db = InMemoryDbContextFactory.Create();
        db.Spaces.Add(new SpaceEntity { Id = Space, Name = "Acme", Slug = "acme" });
        await db.SaveChangesAsync();

        var config = new SystemConfig();
        config.IntegrationApi.SpaceId = SystemTenant.ToString();
        config.CertManager.SpaceId = "instanse";
        var warnings = await IntegrationScopeCheck.WarningsAsync(db, config);

        Assert.Equal(2, warnings.Count);
        Assert.Contains(warnings, w => w.StartsWith("IntegrationApi.SpaceId names space " + SystemTenant, StringComparison.Ordinal) && w.Contains("'instance'"));
        Assert.Contains(warnings, w => w.StartsWith("CertManager.SpaceId is 'instanse'", StringComparison.Ordinal));

        config.IntegrationApi.SpaceId = Space.ToString();
        config.CertManager.SpaceId = "instance";
        Assert.Empty(await IntegrationScopeCheck.WarningsAsync(db, config));
        config.IntegrationApi.SpaceId = null;
        config.CertManager.SpaceId = " ";
        Assert.Empty(await IntegrationScopeCheck.WarningsAsync(db, config));
    }

    [Fact]
    public void The_upgrade_check_refuses_a_key_scoped_to_the_system_tenant_and_says_to_set_it_to_instance()
    {
        var refusals = SystemTenantScopeRefusals(
            [("IntegrationApi.SpaceId", SystemTenant.ToString().ToUpperInvariant()), ("CertManager.SpaceId", Space.ToString())],
            [SystemTenant], [Space]);

        var (key, message, toSystem) = Assert.Single(refusals);
        Assert.Equal("IntegrationApi.SpaceId", key);
        Assert.True(toSystem);
        Assert.Contains("IntegrationApi.TenantId", message);
        Assert.Contains("Set IntegrationApi.SpaceId to 'instance'", message);
        Assert.Empty(SystemTenantScopeRefusals([("CertManager.SpaceId", "instance")], [SystemTenant], [Space]));
    }

    /// <summary>
    /// Review 2: after the fold there is no system tenant to compare with, as on an enrollment host
    /// checked after the control host upgraded. A GUID that names no existing space is refused with
    /// the same remedy; the instance and an existing space are not.
    /// </summary>
    [Fact]
    public void After_the_fold_the_upgrade_check_refuses_a_key_scoped_to_no_existing_space()
    {
        var refusals = SystemTenantScopeRefusals(
            [("IntegrationApi.SpaceId", SystemTenant.ToString()), ("CertManager.SpaceId", Space.ToString())], [], [Space]);

        var (key, message, toSystem) = Assert.Single(refusals);
        Assert.Equal("IntegrationApi.SpaceId", key);
        Assert.False(toSystem);
        Assert.Contains("names no existing space", message);
        Assert.Contains("set IntegrationApi.SpaceId to 'instance'", message);
        Assert.Contains("an existing space's id", message);
        Assert.Empty(SystemTenantScopeRefusals([("CertManager.SpaceId", "instance"), ("IntegrationApi.SpaceId", Space.ToString())], [], [Space]));
        Assert.Single(SystemTenantScopeRefusals([("CertManager.SpaceId", Guid.NewGuid().ToString())], [SystemTenant], [Space]));
    }

    [Theory]
    [InlineData(null, "space", true)]
    [InlineData("instance", "instance", true)]
    [InlineData("instance", "space", false)]
    [InlineData("instance", "none", false)]
    [InlineData("instance", "no-issuer", false)]
    [InlineData("space", "space", true)]
    [InlineData("space", "instance", false)]
    [InlineData("space", "none", false)]
    [InlineData("bogus", "instance", false)]
    [InlineData(null, "none", true)]
    public async Task Cert_manager_signs_only_inside_its_scope_and_refuses_a_CA_it_cannot_resolve(string? scope, string ca, bool allowed)
    {
        using var db = InMemoryDbContextFactory.Create();
        var instanceCa = new CertificateAuthorityEntity { Name = "Instance CA", Label = "inst", CertificateId = Guid.NewGuid() };
        var spaceCa = new CertificateAuthorityEntity { Name = "Space CA", Label = "acme", CertificateId = Guid.NewGuid(), SpaceId = Space };
        db.CertificateAuthorities.AddRange(instanceCa, spaceCa);
        await db.SaveChangesAsync();
        var profile = new SigningProfileEntity
        {
            Name = "p",
            IssuerId = ca switch { "instance" => instanceCa.CertificateId, "space" => spaceCa.CertificateId, "none" => Guid.NewGuid(), _ => null },
        };

        var config = new SystemConfig();
        config.CertManager.SpaceId = scope == "space" ? Space.ToString() : scope;
        var type = ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Integration.CertManagerController");
        var logger = typeof(NullLogger<>).MakeGenericType(type).GetField("Instance")!.GetValue(null);
        var controller = Activator.CreateInstance(type, db, null, config, null, logger)!;
        var check = (Task<IActionResult?>)type.GetMethod("VerifySigningProfileSpaceAsync", BindingFlags.NonPublic | BindingFlags.Instance)!
            .Invoke(controller, [profile])!;

        var result = await check;
        if (allowed)
            Assert.Null(result);
        else
            Assert.Equal(403, Assert.IsType<ObjectResult>(result).StatusCode);
    }

    [Theory]
    [InlineData(null, new[] { "acme", "inst" })]
    [InlineData("instance", new[] { "inst" })]
    [InlineData("space", new[] { "acme" })]
    [InlineData("bogus", new string[0])]
    public async Task The_integration_API_lists_only_the_CAs_inside_its_scope(string? scope, string[] labels)
    {
        using var db = InMemoryDbContextFactory.Create();
        db.CertificateAuthorities.AddRange(
            new CertificateAuthorityEntity { Name = "Instance CA", Label = "inst" },
            new CertificateAuthorityEntity { Name = "Space CA", Label = "acme", SpaceId = Space });
        await db.SaveChangesAsync();
        var config = new SystemConfig();
        config.IntegrationApi.SpaceId = scope == "space" ? Space.ToString() : scope;
        var type = ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Integration.InfraController");
        var controller = Activator.CreateInstance(type, null, null, null, null, null, null, null, db, config)!;

        var list = await (Task<IActionResult>)type.GetMethod("ListAuthorities")!.Invoke(controller, null)!;

        var ok = Assert.IsType<OkObjectResult>(list);
        using var json = System.Text.Json.JsonDocument.Parse(System.Text.Json.JsonSerializer.Serialize(ok.Value));
        Assert.Equal(labels, json.RootElement.EnumerateArray().Select(e => e.GetProperty("Label").GetString()).OrderBy(l => l).ToArray());
    }

    /// <summary>Calls <c>SchemaStartup.FoldedScopeRefusals</c>.</summary>
    private static IReadOnlyList<(string Key, string Message, bool ToSystemTenant)> SystemTenantScopeRefusals(
        IReadOnlyList<(string Key, string Value)> scopes, IReadOnlyCollection<Guid> systemTenants, IReadOnlyCollection<Guid> spaces) =>
        (IReadOnlyList<(string Key, string Message, bool ToSystemTenant)>)ApiAssembly.TypeNamed("ModularCA.API.Startup.SchemaStartup")
            .GetMethod("FoldedScopeRefusals", BindingFlags.NonPublic | BindingFlags.Static)!
            .Invoke(null, [scopes, systemTenants, spaces])!;
}
