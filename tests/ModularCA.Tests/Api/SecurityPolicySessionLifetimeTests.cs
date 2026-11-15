using System.Reflection;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// The maximum session lifetime an administrator saves through
/// <c>PUT /api/v1/admin/security-policy</c>: stored in hours; days, the unit before 0.4.5, are
/// still accepted from a client that has not caught up and mean the same length.
/// </summary>
public sealed class SecurityPolicySessionLifetimeTests
{
    private const string Ns = "ModularCA.API.Controllers.v1.Admin.";

    private sealed class CurrentUserStub(Guid id) : ICurrentUserService
    {
        public Guid? UserId => id;
        public UserEntity? User { get; } = new UserEntity { Id = id, Username = $"user-{id:N}" };
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync() => Task.CompletedTask;
    }

    /// <summary>Saves <paramref name="props"/> over a policy row of <paramref name="storedHours"/> and returns what is then stored.</summary>
    private static async Task<int> SaveAsync(int storedHours, params (string Name, object? Value)[] props)
    {
        var db = InMemoryDbContextFactory.Create();
        db.SecurityPolicies.Add(new SecurityPolicyEntity { MaxSessionLifetimeHours = storedHours });
        db.SaveChanges();
        var actor = Guid.NewGuid();
        IDistributedCache cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var controller = Activator.CreateInstance(ApiAssembly.TypeNamed(Ns + "AdminSecurityPolicyController"),
            db, InstanceCeremonyEndpointTests.Fake<ModularCA.Shared.Interfaces.ISecurityPolicyService>.Create(),
            new RecordingAuditService(), new CurrentUserStub(actor),
            InstanceCeremonyEndpointTests.Fake<ModularCA.Auth.Authorization.IControlledUserCeremonyService>.Create(),
            InstanceCeremonyEndpointTests.Fake<ModularCA.Auth.Authorization.ICaGroupAuthorizationService>.Create(),
            InstanceCeremonyEndpointTests.Fake<ISpacePolicyChangeService>.Create(), cache)!;
        var http = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("sub", actor.ToString()) }, "test")),
        };
        http.Items["IsSystemAdmin"] = true;
        controller.GetType().GetProperty("ControllerContext", BindingFlags.Instance | BindingFlags.Public)!
            .SetValue(controller, new ControllerContext { HttpContext = http });

        var requestType = ApiAssembly.TypeNamed(Ns + "SecurityPolicyUpdateRequest");
        var request = Activator.CreateInstance(requestType)!;
        foreach (var (name, value) in props)
            requestType.GetProperty(name)!.SetValue(request, value);
        var token = Guid.NewGuid().ToString("N");
        cache.SetString($"mfa-stepup:{actor}:{StepUpOps.UpdateConfig}", token);
        Assert.IsType<OkObjectResult>(await (Task<IActionResult>)controller.GetType().GetMethod("Update")!.Invoke(controller, [request, token])!);

        db.ChangeTracker.Clear();
        return (await db.SecurityPolicies.AsNoTracking().SingleAsync()).MaxSessionLifetimeHours;
    }

    [Theory]
    [InlineData(12)]
    [InlineData(1)]
    [InlineData(0)]     // no maximum
    [InlineData(336)]
    public async Task Hours_are_stored_as_sent(int hours)
    {
        Assert.Equal(hours, await SaveAsync(336, ("MaxSessionLifetimeHours", (int?)hours)));
    }

    [Fact]
    public async Task Days_from_an_older_client_are_stored_as_the_same_length_in_hours()
    {
        Assert.Equal(7 * 24, await SaveAsync(336, ("MaxSessionLifetimeDays", (int?)7)));
        Assert.Equal(0, await SaveAsync(336, ("MaxSessionLifetimeDays", (int?)0)));
    }

    [Fact]
    public async Task Hours_win_when_both_are_sent_and_a_save_of_other_fields_changes_neither()
    {
        Assert.Equal(12, await SaveAsync(336, ("MaxSessionLifetimeHours", (int?)12), ("MaxSessionLifetimeDays", (int?)14)));
        Assert.Equal(336, await SaveAsync(336, ("LockoutMinutes", (int?)20)));
        Assert.Equal(336, await SaveAsync(336, ("MaxSessionLifetimeHours", (int?)-1)));
    }
}
