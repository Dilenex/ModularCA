using System.Reflection;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.Auth.Interfaces;
using ModularCA.Bootstrap;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// Drives the real <c>AdminTenantController.Create</c> (loaded from the API build output) to pin
/// the single-organisation wiring: the flag read from config, the count taken without the tenant
/// filter, the order of the checks, and the audit record written before the refusal is thrown.
/// </summary>
public sealed class SingleOrganizationEndpointTests
{
    private const string ControllerType = "ModularCA.API.Controllers.v1.Admin.AdminTenantController";
    private const string RequestType = "ModularCA.API.Controllers.v1.Admin.CreateTenantRequest";

    private sealed class Admin : ICurrentUserService
    {
        public Guid? UserId { get; } = Guid.NewGuid();
        public UserEntity? User => new() { Id = UserId!.Value, Username = "sysadmin" };
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync() => Task.CompletedTask;
    }

    private sealed class World
    {
        public ModularCADbContext Db { get; } = InMemoryDbContextFactory.Create();
        public RecordingAuditService Audit { get; } = new();

        public World(params TenantEntity[] tenants)
        {
            BootstrapProfileSeeder.SeedBuiltInRoles(Db);
            Db.Tenants.Add(new TenantEntity { Name = "System", Slug = "system", IsSystemTenant = true, CanBeDeleted = false });
            Db.Tenants.AddRange(tenants);
            Db.SaveChanges();
        }

        public int Tenants => Db.Tenants.IgnoreQueryFilters().Count();

        public async Task<IActionResult> CreateAsync(string name, bool allowMultipleOrganizations)
        {
            var config = new SystemConfig();
            config.Features.AllowMultipleOrganizations = allowMultipleOrganizations;
            var controller = Activator.CreateInstance(ApiAssembly.TypeNamed(ControllerType),
                Db, new Admin(), Audit, null, null, null, null, new EntitlementService(null), config)!;
            controller.GetType().GetProperty("ControllerContext", BindingFlags.Instance | BindingFlags.Public)!
                .SetValue(controller, new ControllerContext
                {
                    HttpContext = new DefaultHttpContext
                    {
                        User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", Guid.NewGuid().ToString())], "test")),
                    },
                });
            var request = Activator.CreateInstance(ApiAssembly.TypeNamed(RequestType))!;
            request.GetType().GetProperty("Name")!.SetValue(request, name);
            return await (Task<IActionResult>)controller.GetType().GetMethod("Create")!.Invoke(controller, [request])!;
        }

        public IReadOnlyList<(string Action, string? TargetId, object? Details)> Refusals(string code) =>
            Audit.Entries.Where(e => e.Action == AuditActionType.TenantCreated
                && e.Details?.GetType().GetProperty("Refusal")?.GetValue(e.Details) as string == code).ToList();
    }

    private static TenantEntity Org(string name, bool enabled = true, bool deleted = false) =>
        new() { Name = name, Slug = name.ToLowerInvariant(), IsEnabled = enabled, IsDeleted = deleted };

    private static int? Status(IActionResult result) => result switch
    {
        ObjectResult o => o.StatusCode ?? 200,
        StatusCodeResult s => s.StatusCode,
        _ => null,
    };

    [Fact]
    public async Task A_second_organisation_is_refused_with_CFG_017_and_the_refusal_is_audited_first()
    {
        var world = new World(Org("Acme"));

        var ex = await Assert.ThrowsAsync<ConfigurationValidationException>(() => world.CreateAsync("Globex", allowMultipleOrganizations: false));

        Assert.Equal(ErrorCodes.MultipleOrganizationsDisabled, ex.Code);
        Assert.Equal("MCA-CFG-017", ex.Code);
        Assert.Equal(400, ex.Status);
        Assert.Contains("'Acme'", ex.Message);
        Assert.Equal(2, world.Tenants);
        var audited = Assert.Single(world.Refusals("MCA-CFG-017"));
        Assert.Equal("Globex", audited.TargetId);
        Assert.Single(world.Audit.Entries);
    }

    [Fact]
    public async Task The_flag_allows_the_second_organisation()
    {
        var world = new World(Org("Acme"));

        var result = await world.CreateAsync("Globex", allowMultipleOrganizations: true);

        Assert.Equal(201, Status(result));
        Assert.Equal(3, world.Tenants);
        Assert.Empty(world.Refusals("MCA-CFG-017"));
    }

    [Fact]
    public async Task The_first_organisation_is_created_with_the_flag_off()
    {
        var world = new World();

        var result = await world.CreateAsync("Acme", allowMultipleOrganizations: false);

        Assert.Equal(201, Status(result));
        Assert.Equal(1, world.Db.Tenants.IgnoreQueryFilters().Count(t => !t.IsSystemTenant));
    }

    [Fact]
    public async Task A_soft_deleted_organisation_does_not_count()
    {
        var world = new World(Org("Gone", deleted: true));

        var result = await world.CreateAsync("Acme", allowMultipleOrganizations: false);

        Assert.Equal(201, Status(result));
    }

    [Fact]
    public async Task A_disabled_organisation_counts_and_is_named_as_disabled()
    {
        var world = new World(Org("Dormant", enabled: false));

        var ex = await Assert.ThrowsAsync<ConfigurationValidationException>(() => world.CreateAsync("Acme", allowMultipleOrganizations: false));

        Assert.Equal("MCA-CFG-017", ex.Code);
        Assert.Contains("'Dormant'", ex.Message);
        Assert.Contains("disabled", ex.Message);
        Assert.Equal(2, world.Tenants);
    }

    [Fact]
    public async Task At_the_free_edition_ceiling_the_configuration_refusal_comes_before_the_licence()
    {
        var world = new World(Org("One"), Org("Two"), Org("Three"), Org("Four"), Org("Five"));

        var ex = await Assert.ThrowsAsync<ConfigurationValidationException>(() => world.CreateAsync("Six", allowMultipleOrganizations: false));

        Assert.Equal("MCA-CFG-017", ex.Code);
        Assert.DoesNotContain(world.Audit.Entries, e => (e.Details?.GetType().GetProperty("Refusal")?.GetValue(e.Details) as string ?? "").StartsWith("MCA-LIC", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_duplicate_name_is_a_conflict_not_a_configuration_refusal()
    {
        var world = new World(Org("Acme"));

        var result = await world.CreateAsync("Acme", allowMultipleOrganizations: false);

        Assert.Equal(409, Status(result));
        Assert.Empty(world.Audit.Entries);
    }
}
