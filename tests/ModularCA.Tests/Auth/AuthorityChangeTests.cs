using System.Security.Claims;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Services;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Tests.Roles;
using Xunit;

namespace ModularCA.Tests.Auth;

/// <summary>
/// What a signed-in account can still do after its authority changes, whichever code changed it.
/// An access token carries no authority: the resolver (<see cref="CaGroupAuthorizationService"/>)
/// reads group memberships, grants and role assignments from the database on every request, so a
/// membership or grant taken away is gone on the account's next request, with the token it
/// already holds. That is why the paths that change membership without touching the security
/// stamp (the group administration endpoints, controlled-user ceremonies, LDAP group sync, service
/// identities, deleting a group, space or CA) leave nothing usable behind. The token's
/// <c>ghash</c> claim only makes the client fetch a new token, so the group names the console
/// shows catch up: the middleware answers 401 once it reads the account again, at most 30 seconds
/// later. The source scan holds the premise: nothing decides access from a token's claims.
/// </summary>
public sealed class AuthorityChangeTests
{
    private sealed class World : IDisposable
    {
        private readonly Microsoft.Data.Sqlite.SqliteConnection _connection = new("DataSource=:memory:");
        public Guid UserId { get; } = Guid.NewGuid();
        public Guid GroupId { get; } = Guid.NewGuid();
        public Guid GrantId { get; } = Guid.NewGuid();
        public IDistributedCache Cache { get; } = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));

        /// <summary>The <c>ghash</c> an access token issued while the account was in the group carries.</summary>
        public string GhashAsMember { get; }

        public World()
        {
            _connection.Open();
            using var db = Db();
            db.Database.EnsureCreated();
            var group = new CaGroupEntity { Id = GroupId, Name = "system-admin", DisplayName = "System administrators", IsSystemGroup = true };
            db.Users.Add(new UserEntity { Id = UserId, Username = "rita", Email = "rita@example.test", IsActive = true, SecurityStamp = "s" });
            db.CaGroups.Add(group);
            db.CapabilityGrants.Add(new CapabilityGrantEntity { Id = GrantId, GroupId = GroupId, Capability = Capabilities.CertRevoke });
            db.CaGroupMembers.Add(new CaGroupMemberEntity { GroupId = GroupId, UserId = UserId });
            db.SaveChanges();
            GhashAsMember = JwtTokenService.ComputeGroupHash([group]);
        }

        public ModularCADbContext Db() =>
            new(new DbContextOptionsBuilder<ModularCADbContext>().UseSqlite(_connection).Options);

        public void Dispose() => _connection.Dispose();

        public void Change(Action<ModularCADbContext> change)
        {
            using var db = Db();
            change(db);
            db.SaveChanges();
        }

        public string Stamp()
        {
            using var db = Db();
            return db.Users.AsNoTracking().Single(u => u.Id == UserId).SecurityStamp;
        }

        /// <summary>Whether the account may revoke certificates system-wide, asked as a request would.</summary>
        public async Task<bool> MayRevokeAsync()
        {
            using var db = Db();
            return await CaGroupAuthorizationService.ForAnotherAccount(db).HasSystemCapabilityAsync(UserId, Capabilities.CertRevoke);
        }

        /// <summary>
        /// Presents the access token issued while the account was in the group to the real
        /// <c>TokenRevocationMiddleware</c> and returns the status it answers (200 when let through).
        /// </summary>
        public async Task<int> OldAccessTokenStatusAsync()
        {
            var type = ApiAssembly.TypeNamed("ModularCA.API.Middleware.TokenRevocationMiddleware");
            RequestDelegate next = _ => Task.CompletedTask;
            var middleware = Activator.CreateInstance(type, next, Cache)!;
            await using var services = new ServiceCollection().AddScoped(_ => Db()).BuildServiceProvider();
            var http = new DefaultHttpContext
            {
                RequestServices = services,
                User = new ClaimsPrincipal(new ClaimsIdentity(
                    [new Claim("sub", UserId.ToString()), new Claim("stamp", "s"), new Claim("ghash", GhashAsMember), new Claim("groups", "system-admin")], "test")),
            };
            await (Task)type.GetMethod("InvokeAsync")!.Invoke(middleware, [http])!;
            return http.Response.StatusCode;
        }

        public void DropCachedStamp() => Cache.Remove($"user-stamp:{UserId:N}");
    }

    /// <summary>
    /// A membership removed the way every path outside <c>UserManagementService</c> removes one (the
    /// row is deleted; the stamp is not touched): the authority is gone on the next request even
    /// while the middleware's cached entry still lets the old token through, and the old token is
    /// refused once that entry is read again.
    /// </summary>
    [Fact]
    public async Task A_membership_removed_without_a_stamp_rotation_takes_the_authority_away_at_once()
    {
        using var w = new World();
        Assert.True(await w.MayRevokeAsync());
        Assert.Equal(200, await w.OldAccessTokenStatusAsync());

        w.Change(db => db.CaGroupMembers.Remove(db.CaGroupMembers.Single(m => m.UserId == w.UserId)));

        Assert.Equal("s", w.Stamp());
        // The old token still passes the middleware for up to 30 seconds, and carries nothing.
        Assert.Equal(200, await w.OldAccessTokenStatusAsync());
        Assert.False(await w.MayRevokeAsync());

        // Read again, the account's groups no longer match the token's ghash: refresh.
        w.DropCachedStamp();
        Assert.Equal(401, await w.OldAccessTokenStatusAsync());
    }

    /// <summary>Deleting the group (its members and grants go with it) does the same.</summary>
    [Fact]
    public async Task Deleting_the_group_takes_the_authority_away_at_once()
    {
        using var w = new World();

        w.Change(db => db.CaGroups.Remove(db.CaGroups.Include(g => g.Members).Include(g => g.Grants).Single(g => g.Id == w.GroupId)));

        Assert.False(await w.MayRevokeAsync());
        w.DropCachedStamp();
        Assert.Equal(401, await w.OldAccessTokenStatusAsync());
    }

    /// <summary>
    /// A grant taken from a group leaves the members' group list, and so the token's ghash, as it
    /// was: the token stays valid, and what it can do shrinks on the next request all the same.
    /// </summary>
    [Fact]
    public async Task A_grant_taken_from_a_group_is_gone_at_once_though_the_token_stays_valid()
    {
        using var w = new World();

        w.Change(db => db.CapabilityGrants.Remove(db.CapabilityGrants.Single(g => g.Id == w.GrantId)));

        Assert.False(await w.MayRevokeAsync());
        w.DropCachedStamp();
        Assert.Equal(200, await w.OldAccessTokenStatusAsync());
    }

    /// <summary>
    /// The premise of the tests above, read from the product sources: nothing reads the token's
    /// <c>groups</c> claim, and no policy or attribute decides by role or claim. The claim is
    /// written for the console to display; a decision made from it would outlive a membership
    /// change until the token was replaced.
    /// </summary>
    [Fact]
    public void No_product_code_decides_access_from_a_tokens_claims()
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "ModularCA.sln")))
            root = root.Parent;
        Assert.NotNull(root);

        var sep = Path.DirectorySeparatorChar;
        var claimDecision = new Regex(@"(?:FindFirst|FindAll|FindFirstValue|HasClaim)\(\s*""groups""|\bIsInRole\(|\bRequireRole\(|\bRequireClaim\(|\[Authorize\([^\]]*\bRoles\s*=");
        var found = new List<string>();
        var scanned = 0;
        foreach (var project in Directory.EnumerateDirectories(root!.FullName, "ModularCA.*"))
        {
            foreach (var file in Directory.EnumerateFiles(project, "*.cs", SearchOption.AllDirectories))
            {
                if (file.Contains($"{sep}obj{sep}") || file.Contains($"{sep}bin{sep}"))
                    continue;
                scanned++;
                var lines = File.ReadAllLines(file);
                for (var i = 0; i < lines.Length; i++)
                {
                    if (!lines[i].TrimStart().StartsWith("//", StringComparison.Ordinal) && claimDecision.IsMatch(lines[i]))
                        found.Add($"{Path.GetRelativePath(root.FullName, file)}:{i + 1}: {lines[i].Trim()}");
                }
            }
        }

        Assert.True(scanned > 100, "The scan found too few source files.");
        Assert.True(found.Count == 0,
            "Access decided from a token claim. Authority is read from the database on every request (CaGroupAuthorizationService), "
            + "which is what makes a group or grant change take effect at once; a decision made from the token would keep the old "
            + "authority until the token is replaced. Ask the authorization service instead:\n" + string.Join("\n", found));
    }
}
