using System.Reflection;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.Auth.Interfaces;
using ModularCA.Bootstrap;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// Drives the real <c>AdminSpaceController.Create</c> (loaded from the API build output) to pin
/// that spaces are not counted, limited or licensed: creating a space always succeeds, at any
/// number of spaces, and neither the response nor the audit record carries a license hint.
/// </summary>
public sealed class SpaceCreationEndpointTests
{
    private const string ControllerType = "ModularCA.API.Controllers.v1.Admin.AdminSpaceController";
    private const string RequestType = "ModularCA.API.Controllers.v1.Admin.CreateSpaceRequest";

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

        public World(params SpaceEntity[] spaces)
        {
            BootstrapProfileSeeder.SeedBuiltInRoles(Db);
            Db.Spaces.AddRange(spaces);
            Db.SaveChanges();
        }

        public int Spaces => Db.Spaces.IgnoreQueryFilters().Count();

        public async Task<IActionResult> CreateAsync(string name)
        {
            var controller = Activator.CreateInstance(ApiAssembly.TypeNamed(ControllerType),
                Db, new Admin(), Audit, null, null, null, null)!;
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
    }

    private static SpaceEntity Space(string name, bool enabled = true, bool deleted = false) =>
        new() { Name = name, Slug = name.ToLowerInvariant(), IsEnabled = enabled, IsDeleted = deleted };

    private static int? Status(IActionResult result) => result switch
    {
        ObjectResult o => o.StatusCode ?? 200,
        StatusCodeResult s => s.StatusCode,
        _ => null,
    };

    /// <summary>The members of an anonymous response or audit-details object, by name.</summary>
    private static string[] Members(object value) =>
        value.GetType().GetProperties().Select(p => p.Name).ToArray();

    /// <summary>Fails when the create response or the audit record says anything about a license.</summary>
    private static void AssertNoLicenseHint(IActionResult result, RecordingAuditService audit)
    {
        var body = ((ObjectResult)result).Value!;
        Assert.DoesNotContain(Members(body), m => m.Contains("Recommend", StringComparison.OrdinalIgnoreCase)
            || m.Contains("Licen", StringComparison.OrdinalIgnoreCase));
        var json = System.Text.Json.JsonSerializer.Serialize(body);
        Assert.DoesNotContain("licen", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("recommend", json, StringComparison.OrdinalIgnoreCase);

        var details = audit.Entries[^1].Details!;
        Assert.Equal(["Name", "Slug"], Members(details));
    }

    [Fact]
    public async Task A_second_space_is_created_and_audited_as_a_space()
    {
        var world = new World(Space("Acme"));

        var result = await world.CreateAsync("Globex");

        Assert.Equal(201, Status(result));
        Assert.Equal(2, world.Spaces);
        AssertNoLicenseHint(result, world.Audit);
        var created = Assert.Single(world.Audit.Entries);
        Assert.Equal(AuditActionType.SpaceCreated, created.Action);
    }

    [Fact]
    public async Task The_fifth_space_is_created_with_no_license_hint()
    {
        var world = new World(Space("One"), Space("Two"), Space("Three"), Space("Four", enabled: false));

        var result = await world.CreateAsync("Five");

        Assert.Equal(201, Status(result));
        Assert.Equal(5, world.Spaces);
        AssertNoLicenseHint(result, world.Audit);
    }

    [Fact]
    public async Task Creating_many_spaces_never_returns_a_license_hint()
    {
        var world = new World();

        for (var i = 1; i <= 25; i++)
        {
            var result = await world.CreateAsync($"Space{i:00}");

            Assert.Equal(201, Status(result));
            Assert.Equal(i, world.Spaces);
            AssertNoLicenseHint(result, world.Audit);
        }
    }

    [Fact]
    public void The_controller_takes_no_entitlement_service()
    {
        // Nothing about creating a space depends on a license, so nothing license-shaped is injected.
        var parameters = ApiAssembly.TypeNamed(ControllerType).GetConstructors().Single().GetParameters();

        Assert.DoesNotContain(parameters, p => p.ParameterType == typeof(IEntitlementService));
    }

    [Fact]
    public async Task The_slug_system_is_reserved_for_the_instance()
    {
        var world = new World();

        var result = await world.CreateAsync("System");

        Assert.Equal(400, Status(result));
        Assert.Equal(0, world.Spaces);
    }

    [Fact]
    public async Task A_duplicate_name_is_a_conflict()
    {
        var world = new World(Space("Acme"));

        var result = await world.CreateAsync("Acme");

        Assert.Equal(409, Status(result));
        Assert.Empty(world.Audit.Entries);
    }
}
