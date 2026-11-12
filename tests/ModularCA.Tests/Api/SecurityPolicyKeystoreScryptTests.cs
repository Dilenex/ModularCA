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
/// The keystore scrypt cost an administrator saves through <c>PUT /api/v1/admin/security-policy</c>.
/// A value scrypt cannot use is refused with 400 and nothing is saved; the console's save, which
/// sends the stored values back unchanged, is not held to the new rules for values it did not change.
/// </summary>
public sealed class SecurityPolicyKeystoreScryptTests
{
    private const string Ns = "ModularCA.API.Controllers.v1.Admin.";

    private sealed class CurrentUserStub(Guid id) : ICurrentUserService
    {
        public Guid? UserId => id;
        public UserEntity? User { get; } = new UserEntity { Id = id, Username = $"user-{id:N}" };
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync() => Task.CompletedTask;
    }

    private sealed class Harness
    {
        public required ModularCADbContext Db { get; init; }
        public required RecordingAuditService Audit { get; init; }
        public required Func<(string Name, object? Value)[], Task<IActionResult>> Put { get; init; }
    }

    /// <summary>A security policy controller over a fresh database whose policy row is <paramref name="policy"/>.</summary>
    private static Harness Create(SecurityPolicyEntity policy)
    {
        var db = InMemoryDbContextFactory.Create();
        db.SecurityPolicies.Add(policy);
        db.SaveChanges();
        var actor = Guid.NewGuid();
        IDistributedCache cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var audit = new RecordingAuditService();
        var controller = Activator.CreateInstance(ApiAssembly.TypeNamed(Ns + "AdminSecurityPolicyController"),
            db, InstanceCeremonyEndpointTests.Fake<ModularCA.Shared.Interfaces.ISecurityPolicyService>.Create(),
            audit, new CurrentUserStub(actor),
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
        var update = controller.GetType().GetMethod("Update")!;

        return new Harness
        {
            Db = db,
            Audit = audit,
            Put = async props =>
            {
                var requestType = ApiAssembly.TypeNamed(Ns + "SecurityPolicyUpdateRequest");
                var request = Activator.CreateInstance(requestType)!;
                foreach (var (name, value) in props)
                    requestType.GetProperty(name)!.SetValue(request, value);
                var token = Guid.NewGuid().ToString("N");
                cache.SetString($"mfa-stepup:{actor}:{StepUpOps.UpdateConfig}", token);
                return await (Task<IActionResult>)update.Invoke(controller, [request, token])!;
            },
        };
    }

    private static async Task<SecurityPolicyEntity> StoredAsync(Harness h)
    {
        h.Db.ChangeTracker.Clear();
        return await h.Db.SecurityPolicies.AsNoTracking().SingleAsync();
    }

    [Theory]
    [InlineData(30000)]
    [InlineData(65535)]
    [InlineData(1000000)]
    public async Task An_n_that_is_not_a_power_of_two_is_refused_and_nothing_is_saved(int n)
    {
        var h = Create(new SecurityPolicyEntity { LoginBanner = "before" });

        var result = await h.Put([("KeystoreScryptN", (int?)n), ("LoginBanner", "after")]);

        var bad = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Contains("KeystoreScryptN", System.Text.Json.JsonSerializer.Serialize(bad.Value));
        var stored = await StoredAsync(h);
        Assert.Equal(65536, stored.KeystoreScryptN);
        Assert.Equal("before", stored.LoginBanner);
        Assert.Empty(h.Audit.Entries);
    }

    [Theory]
    [InlineData(1 << 14)]
    [InlineData(1 << 17)]
    [InlineData(1 << 20)]
    public async Task A_power_of_two_n_in_range_is_saved(int n)
    {
        var h = Create(new SecurityPolicyEntity());

        Assert.IsType<OkObjectResult>(await h.Put([("KeystoreScryptN", (int?)n)]));

        Assert.Equal(n, (await StoredAsync(h)).KeystoreScryptN);
    }

    [Theory]
    [InlineData(1 << 13, 8, 1)]
    [InlineData(1 << 21, 8, 1)]
    [InlineData(1 << 16, 0, 1)]
    [InlineData(1 << 16, 33, 1)]
    [InlineData(1 << 16, 8, 0)]
    [InlineData(1 << 16, 8, 17)]
    public async Task A_cost_outside_the_ranges_is_refused_rather_than_clamped(int n, int r, int p)
    {
        var h = Create(new SecurityPolicyEntity());

        var result = await h.Put([("KeystoreScryptN", (int?)n), ("KeystoreScryptR", (int?)r), ("KeystoreScryptP", (int?)p)]);

        Assert.IsType<BadRequestObjectResult>(result);
        var stored = await StoredAsync(h);
        Assert.Equal((65536, 8, 1), (stored.KeystoreScryptN, stored.KeystoreScryptR, stored.KeystoreScryptP));
    }

    /// <summary>
    /// The console's Settings page sends the whole policy back. A value stored before these
    /// checks, sent back unchanged, does not block the save of the fields that did change.
    /// </summary>
    [Fact]
    public async Task A_stored_value_sent_back_unchanged_does_not_block_the_save()
    {
        var h = Create(new SecurityPolicyEntity { KeystoreScryptN = 30000, LoginBanner = "before" });

        var result = await h.Put([("KeystoreScryptN", (int?)30000), ("KeystoreScryptR", (int?)8), ("KeystoreScryptP", (int?)1), ("LoginBanner", "after")]);

        Assert.IsType<OkObjectResult>(result);
        var stored = await StoredAsync(h);
        Assert.Equal("after", stored.LoginBanner);
        Assert.Equal(30000, stored.KeystoreScryptN);
    }

    [Fact]
    public async Task A_stored_bad_n_can_be_corrected()
    {
        var h = Create(new SecurityPolicyEntity { KeystoreScryptN = 30000 });

        Assert.IsType<OkObjectResult>(await h.Put([("KeystoreScryptN", (int?)32768)]));

        Assert.Equal(32768, (await StoredAsync(h)).KeystoreScryptN);
    }

    /// <summary>
    /// One derivation takes about 128 · N · r bytes. Each value was in its range before, so
    /// N = 2^20 with r = 32, which needs 4 GiB, was saved.
    /// </summary>
    [Theory]
    [InlineData(1 << 20, 16)]
    [InlineData(1 << 20, 32)]
    [InlineData(1 << 19, 32)]
    public async Task A_cost_that_needs_more_than_one_gibibyte_is_refused_and_nothing_is_saved(int n, int r)
    {
        var h = Create(new SecurityPolicyEntity());

        var result = await h.Put([("KeystoreScryptN", (int?)n), ("KeystoreScryptR", (int?)r)]);

        var bad = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Contains("MiB", System.Text.Json.JsonSerializer.Serialize(bad.Value));
        var stored = await StoredAsync(h);
        Assert.Equal((65536, 8), (stored.KeystoreScryptN, stored.KeystoreScryptR));
        Assert.Empty(h.Audit.Entries);
    }

    /// <summary>Raising r alone counts against the stored N.</summary>
    [Fact]
    public async Task Raising_r_alone_is_checked_against_the_stored_n()
    {
        var h = Create(new SecurityPolicyEntity { KeystoreScryptN = 1 << 20 });

        Assert.IsType<BadRequestObjectResult>(await h.Put([("KeystoreScryptR", (int?)16)]));
        Assert.Equal(8, (await StoredAsync(h)).KeystoreScryptR);
    }

    [Theory]
    [InlineData(1 << 20, 8)]
    [InlineData(1 << 19, 16)]
    [InlineData(1 << 17, 8)]
    public async Task A_cost_of_at_most_one_gibibyte_is_saved(int n, int r)
    {
        var h = Create(new SecurityPolicyEntity());

        Assert.IsType<OkObjectResult>(await h.Put([("KeystoreScryptN", (int?)n), ("KeystoreScryptR", (int?)r)]));

        var stored = await StoredAsync(h);
        Assert.Equal((n, r), (stored.KeystoreScryptN, stored.KeystoreScryptR));
    }

    /// <summary>
    /// An install that saved a cost above the ceiling before it existed keeps it: the console's
    /// save sends it back unchanged and is not refused for it.
    /// </summary>
    [Fact]
    public async Task A_stored_cost_above_the_ceiling_sent_back_unchanged_does_not_block_the_save()
    {
        var h = Create(new SecurityPolicyEntity { KeystoreScryptN = 1 << 20, KeystoreScryptR = 32, LoginBanner = "before" });

        var result = await h.Put([("KeystoreScryptN", (int?)(1 << 20)), ("KeystoreScryptR", (int?)32), ("KeystoreScryptP", (int?)1), ("LoginBanner", "after")]);

        Assert.IsType<OkObjectResult>(result);
        var stored = await StoredAsync(h);
        Assert.Equal("after", stored.LoginBanner);
        Assert.Equal((1 << 20, 32), (stored.KeystoreScryptN, stored.KeystoreScryptR));
    }
}
