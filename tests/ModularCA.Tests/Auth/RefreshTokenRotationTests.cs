using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using ModularCA.Auth.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using Xunit;

namespace ModularCA.Tests.Auth;

/// <summary>
/// Refresh rotation revokes the presented token with a conditional UPDATE, so of two requests that
/// both read the same live token only one rotates it; the other is treated as reuse and the family
/// is revoked. SQLite rather than the in-memory provider, which cannot execute ExecuteUpdate.
/// </summary>
public sealed class RefreshTokenRotationTests : IDisposable
{
    private readonly SqliteConnection _connection = new("DataSource=:memory:");

    public RefreshTokenRotationTests()
    {
        _connection.Open();
        using var db = Context();
        db.Database.EnsureCreated();
    }

    public void Dispose() => _connection.Dispose();

    private ModularCADbContext Context() =>
        new(new DbContextOptionsBuilder<ModularCADbContext>().UseSqlite(_connection).Options);

    private static RefreshTokenEntity Token(Guid userId, Guid family) => new()
    {
        UserId = userId,
        Token = Guid.NewGuid().ToString("N"),
        ExpiresAt = DateTime.UtcNow.AddDays(1),
        FamilyId = family,
        FamilyCreatedAt = DateTime.UtcNow,
    };

    private (Guid UserId, Guid Family, RefreshTokenEntity Presented) Seed()
    {
        using var db = Context();
        var user = new UserEntity { Username = "alice", PasswordHash = "x", IsActive = true };
        db.Users.Add(user);
        var family = Guid.NewGuid();
        var presented = Token(user.Id, family);
        db.RefreshTokens.Add(presented);
        db.SaveChanges();
        return (user.Id, family, presented);
    }

    [Fact]
    public async Task A_live_token_rotates_once_and_links_its_successor()
    {
        var (userId, family, presented) = Seed();
        var successor = Token(userId, family);

        await using (var db = Context())
            Assert.True(await RefreshTokenRotation.RotateAsync(db, presented.Id, family, successor, DateTime.UtcNow));

        await using var read = Context();
        var old = await read.RefreshTokens.SingleAsync(t => t.Id == presented.Id);
        Assert.True(old.IsRevoked);
        Assert.Equal(successor.Token, old.ReplacedByToken);
        Assert.False((await read.RefreshTokens.SingleAsync(t => t.Id == successor.Id)).IsRevoked);
    }

    [Fact]
    public async Task The_loser_of_a_concurrent_rotation_is_reuse_and_revokes_the_family()
    {
        var (userId, family, presented) = Seed();

        // Both requests loaded the token while it was live; the first to write wins.
        await using var first = Context();
        await using var second = Context();
        Assert.False((await first.RefreshTokens.SingleAsync(t => t.Id == presented.Id)).IsRevoked);
        Assert.False((await second.RefreshTokens.SingleAsync(t => t.Id == presented.Id)).IsRevoked);

        var winner = Token(userId, family);
        var loser = Token(userId, family);
        Assert.True(await RefreshTokenRotation.RotateAsync(first, presented.Id, family, winner, DateTime.UtcNow));
        Assert.False(await RefreshTokenRotation.RotateAsync(second, presented.Id, family, loser, DateTime.UtcNow));

        await using var read = Context();
        Assert.False(await read.RefreshTokens.AnyAsync(t => t.Id == loser.Id));
        Assert.True((await read.RefreshTokens.SingleAsync(t => t.Id == winner.Id)).IsRevoked);
        Assert.Equal(winner.Token, (await read.RefreshTokens.SingleAsync(t => t.Id == presented.Id)).ReplacedByToken);
        Assert.False(await read.RefreshTokens.AnyAsync(t => t.FamilyId == family && !t.IsRevoked));
    }
}
