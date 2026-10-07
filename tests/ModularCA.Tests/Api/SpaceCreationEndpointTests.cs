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
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Licensing;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// Drives the real <c>AdminSpaceController.Create</c> (loaded from the API build output) to pin
/// the soft cap: creating a space always succeeds, and from the fifth space without a licence
/// carrying the multi-space feature the response recommends one.
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

    /// <summary>A licence that carries the multi-space feature.</summary>
    private sealed class MultiSpaceLicence : IEntitlementService
    {
        private readonly EntitlementService _free = new(null);
        public bool IsEntitled(string featureKey) => featureKey == FeatureKeys.MultiTenancy;
        public bool IsAvailable(string featureKey) => featureKey == FeatureKeys.MultiTenancy;
        public EntitlementDenial? Explain(string featureKey) => featureKey == FeatureKeys.MultiTenancy ? null : _free.Explain(featureKey);
        public int? GetLimit(string limitName) => null;
        public LicenseLoadResult License => _free.License;
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

        public async Task<IActionResult> CreateAsync(string name, IEntitlementService? entitlements = null)
        {
            var controller = Activator.CreateInstance(ApiAssembly.TypeNamed(ControllerType),
                Db, new Admin(), Audit, null, null, null, null, entitlements ?? new EntitlementService(null))!;
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

    private static string? Recommendation(IActionResult result)
    {
        var body = ((ObjectResult)result).Value!;
        return body.GetType().GetProperty("Recommendation")!.GetValue(body) as string;
    }

    [Fact]
    public async Task A_second_space_is_created_and_audited_as_a_space()
    {
        var world = new World(Space("Acme"));

        var result = await world.CreateAsync("Globex");

        Assert.Equal(201, Status(result));
        Assert.Equal(2, world.Spaces);
        Assert.Null(Recommendation(result));
        var created = Assert.Single(world.Audit.Entries);
        Assert.Equal(AuditActionType.SpaceCreated, created.Action);
    }

    [Fact]
    public async Task The_fourth_space_carries_no_recommendation()
    {
        var world = new World(Space("One"), Space("Two"), Space("Three"));

        var result = await world.CreateAsync("Four");

        Assert.Equal(201, Status(result));
        Assert.Null(Recommendation(result));
    }

    [Fact]
    public async Task The_fifth_space_is_created_with_a_licence_recommendation()
    {
        var world = new World(Space("One"), Space("Two"), Space("Three"), Space("Four", enabled: false));

        var result = await world.CreateAsync("Five");

        Assert.Equal(201, Status(result));
        Assert.Equal(5, world.Spaces);
        Assert.Equal("A licence is recommended for more than four spaces.", Recommendation(result));
        var details = Assert.Single(world.Audit.Entries).Details!;
        Assert.Equal(true, details.GetType().GetProperty("LicenceRecommended")!.GetValue(details));
    }

    [Fact]
    public async Task A_licence_carrying_the_multi_space_feature_suppresses_the_recommendation()
    {
        var world = new World(Space("One"), Space("Two"), Space("Three"), Space("Four"), Space("Five"));

        var result = await world.CreateAsync("Six", new MultiSpaceLicence());

        Assert.Equal(201, Status(result));
        Assert.Null(Recommendation(result));
    }

    [Fact]
    public async Task A_soft_deleted_space_does_not_count()
    {
        var world = new World(Space("One"), Space("Two"), Space("Three"), Space("Gone", deleted: true));

        var result = await world.CreateAsync("Four");

        Assert.Equal(201, Status(result));
        Assert.Null(Recommendation(result));
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

    [Fact]
    public void The_recommendation_follows_the_licence_not_a_refusal()
    {
        var free = new EntitlementService(null);
        Assert.Null(SpaceCreationGate.Recommendation(free, SpaceCreationGate.SpacesWithoutLicence - 1));
        Assert.Equal(SpaceCreationGate.LicenceRecommendation, SpaceCreationGate.Recommendation(free, SpaceCreationGate.SpacesWithoutLicence));
        Assert.Null(SpaceCreationGate.Recommendation(new MultiSpaceLicence(), 40));
    }
}
