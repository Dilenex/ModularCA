using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Auth.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Models.Management;
using Xunit;

namespace ModularCA.Tests.Auth;

/// <summary>
/// Covers the uniqueness checks in <see cref="UserManagementService.UpdateUser"/>.
/// <para>
/// Both checks asked "does any user hold this username / email?" without excluding the user
/// being updated. A PUT carrying the account's own current values therefore matched the account
/// itself and returned false, which <c>AdminUserManagerController</c> maps to
/// <c>404 "User with ID {id} not found."</c>
/// </para>
/// <para>
/// That method holds the only assignment of <see cref="UserEntity.IsActive"/> from a request in
/// the solution, so the practical effect was that an administrator could not disable an account:
/// the account stayed enabled, the security stamp was never rotated, and outstanding refresh
/// tokens were never revoked. It succeeded only when the username <em>and</em> the email were
/// both changed in the same request.
/// </para>
/// <para>
/// These tests exercise the real service against a real <see cref="ModularCADbContext"/>, so
/// removing the <c>u.Id != userId</c> exclusion fails them.
/// </para>
/// </summary>
public class UserUpdateSelfCollisionTests
{
    /// <summary>Tenant filter off; this suite is about uniqueness, not tenancy.</summary>
    private sealed class NoTenantContext : ITenantContext
    {
        public bool HasContext => true;
        public bool IsSystemAdmin => true;
        public IReadOnlySet<Guid> AccessibleTenantIds => new HashSet<Guid>();
        public Guid? UserId => null;
        public void Set(Guid? userId, IReadOnlySet<Guid> accessibleTenantIds, bool isSystemAdmin) { }
    }

    private static ModularCADbContext BuildContext(string dbName)
    {
        var options = new DbContextOptionsBuilder<ModularCADbContext>()
            .UseInMemoryDatabase(dbName)
            .ConfigureWarnings(w => w.Ignore(
                Microsoft.EntityFrameworkCore.Diagnostics.InMemoryEventId.TransactionIgnoredWarning))
            .Options;
        return new ModularCADbContext(options, new NoTenantContext());
    }

    private static UserManagementService BuildService(ModularCADbContext db)
        => new(db, NullLogger<UserManagementService>.Instance, new SystemConfig(), null!, null!);

    private static UserEntity SeedUser(ModularCADbContext db, string username, string email)
    {
        var user = new UserEntity
        {
            Id = Guid.NewGuid(),
            Username = username,
            Email = email,
            PasswordHash = "stub",
            IsActive = true,
        };
        db.Users.Add(user);
        db.SaveChanges();
        return user;
    }

    /// <summary>
    /// The regression itself: disabling an account while echoing back its own username and email
    /// — exactly what the admin UI sends — must succeed.
    /// </summary>
    [Fact]
    public async Task Disabling_a_user_succeeds_when_the_request_echoes_their_own_username_and_email()
    {
        using var db = BuildContext(nameof(Disabling_a_user_succeeds_when_the_request_echoes_their_own_username_and_email));
        var user = SeedUser(db, "compromised", "compromised@example.test");

        var ok = await BuildService(db).UpdateUser(user.Id, new UpdateUserRequest
        {
            Username = user.Username,
            Email = user.Email,
            IsActive = false,
        });

        Assert.True(ok);
        Assert.False(db.Users.Single(u => u.Id == user.Id).IsActive);
    }

    /// <summary>
    /// The consequences that were skipped along with the update: an account being disabled must
    /// have its security stamp rotated and its refresh tokens revoked, or outstanding JWTs stay
    /// valid for the rest of their TTL.
    /// </summary>
    [Fact]
    public async Task Disabling_a_user_rotates_the_security_stamp_and_revokes_refresh_tokens()
    {
        using var db = BuildContext(nameof(Disabling_a_user_rotates_the_security_stamp_and_revokes_refresh_tokens));
        var user = SeedUser(db, "revoked", "revoked@example.test");
        var originalStamp = user.SecurityStamp;

        db.Set<RefreshTokenEntity>().Add(new RefreshTokenEntity
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            Token = "stub-refresh-token",
            IsRevoked = false,
        });
        db.SaveChanges();

        var ok = await BuildService(db).UpdateUser(user.Id, new UpdateUserRequest
        {
            Username = user.Username,
            Email = user.Email,
            IsActive = false,
        });

        Assert.True(ok);
        Assert.NotEqual(originalStamp, db.Users.Single(u => u.Id == user.Id).SecurityStamp);
        Assert.All(db.Set<RefreshTokenEntity>().Where(t => t.UserId == user.Id), t => Assert.True(t.IsRevoked));
    }

    /// <summary>
    /// The check still has to do its job. Guards against "fixing" the above by deleting the
    /// uniqueness test outright.
    /// </summary>
    [Fact]
    public async Task Taking_another_users_username_is_still_rejected()
    {
        using var db = BuildContext(nameof(Taking_another_users_username_is_still_rejected));
        var target = SeedUser(db, "alice", "alice@example.test");
        SeedUser(db, "bob", "bob@example.test");

        var ok = await BuildService(db).UpdateUser(target.Id, new UpdateUserRequest
        {
            Username = "bob",
            Email = target.Email,
        });

        Assert.False(ok);
        Assert.Equal("alice", db.Users.Single(u => u.Id == target.Id).Username);
    }

    /// <summary>As above, for the email check, which is a separate statement.</summary>
    [Fact]
    public async Task Taking_another_users_email_is_still_rejected()
    {
        using var db = BuildContext(nameof(Taking_another_users_email_is_still_rejected));
        var target = SeedUser(db, "carol", "carol@example.test");
        SeedUser(db, "dave", "dave@example.test");

        var ok = await BuildService(db).UpdateUser(target.Id, new UpdateUserRequest
        {
            Username = target.Username,
            Email = "dave@example.test",
        });

        Assert.False(ok);
        Assert.Equal("carol@example.test", db.Users.Single(u => u.Id == target.Id).Email);
    }

    /// <summary>
    /// A partial PUT omits the fields it does not change. A null username or email means "leave
    /// unchanged" and must not be treated as a value to check for collisions.
    /// </summary>
    [Fact]
    public async Task A_partial_update_omitting_username_and_email_succeeds()
    {
        using var db = BuildContext(nameof(A_partial_update_omitting_username_and_email_succeeds));
        var user = SeedUser(db, "erin", "erin@example.test");

        var ok = await BuildService(db).UpdateUser(user.Id, new UpdateUserRequest { IsActive = false });

        Assert.True(ok);
        var updated = db.Users.Single(u => u.Id == user.Id);
        Assert.False(updated.IsActive);
        Assert.Equal("erin", updated.Username);
        Assert.Equal("erin@example.test", updated.Email);
    }
}
