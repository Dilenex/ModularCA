using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Helpers;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Tests.TestUtils;
using Npgsql;
using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// <see cref="UserSessionTermination.EndAllSessionsSetBasedAsync"/> against a real PostgreSQL
/// database migrated to the latest migration: on its own it commits the rotated stamp, the
/// caller's other changes and the revocation together; inside a transaction the caller holds it
/// commits nothing itself, so the caller's rollback undoes all of it. Opt-in through
/// <c>MODULARCA_TEST_PG</c>.
/// </summary>
[Trait("Category", "PostgreSQL")]
[Trait(TestTier.Name, TestTier.Slow)]
[Collection(PostgresLane.Four)]
public class PostgresSessionTerminationTests
{
    private const string ServerVariable = "MODULARCA_TEST_PG";

    [RequiresEnvironmentFact(ServerVariable)]
    public Task The_set_based_form_commits_alone_and_joins_a_transaction_the_caller_holds_on_postgres() =>
        OnPostgresAsync(async db =>
        {
            var userId = Guid.NewGuid();
            var otherId = Guid.NewGuid();
            db.Users.Add(new UserEntity { Id = userId, Username = "maya", Email = "maya@example.test", IsActive = true, SecurityStamp = "s" });
            db.Users.Add(new UserEntity { Id = otherId, Username = "noor", Email = "noor@example.test", IsActive = true, SecurityStamp = "o" });
            db.RefreshTokens.Add(new RefreshTokenEntity { Id = Guid.NewGuid(), UserId = userId, Token = "a", ExpiresAt = DateTime.UtcNow.AddDays(1) });
            db.RefreshTokens.Add(new RefreshTokenEntity { Id = Guid.NewGuid(), UserId = userId, Token = "b", ExpiresAt = DateTime.UtcNow.AddDays(1) });
            db.RefreshTokens.Add(new RefreshTokenEntity { Id = Guid.NewGuid(), UserId = otherId, Token = "c", ExpiresAt = DateTime.UtcNow.AddDays(1) });
            await db.SaveChangesAsync();

            async Task<(string Stamp, string FirstName, int Live)> StateAsync()
            {
                db.ChangeTracker.Clear();
                var user = await db.Users.AsNoTracking().SingleAsync(u => u.Id == userId);
                return (user.SecurityStamp, user.FirstName, await db.RefreshTokens.CountAsync(t => t.UserId == userId && !t.IsRevoked));
            }

            // Inside the caller's transaction, rolled back: nothing happened.
            await using (var tx = await db.Database.BeginTransactionAsync())
            {
                var user = await db.Users.SingleAsync(u => u.Id == userId);
                user.FirstName = "Rolled back";
                var ended = await UserSessionTermination.EndAllSessionsSetBasedAsync(db, user, DateTime.UtcNow);
                Assert.Equal(2, ended.RefreshTokensRevoked);
                Assert.Same(tx, db.Database.CurrentTransaction);
                await tx.RollbackAsync();
            }
            Assert.Equal(("s", string.Empty, 2), await StateAsync());

            // On its own: one transaction, committed here, carrying the caller's other change.
            var revokedAt = DateTime.UtcNow;
            var tracked = await db.Users.SingleAsync(u => u.Id == userId);
            tracked.FirstName = "Maya";
            var result = await UserSessionTermination.EndAllSessionsSetBasedAsync(db, tracked, revokedAt);
            Assert.Null(db.Database.CurrentTransaction);
            Assert.Equal(new EndedSessions(userId, "maya", 2), result);

            var after = await StateAsync();
            Assert.NotEqual("s", after.Stamp);
            Assert.Equal(("Maya", 0), (after.FirstName, after.Live));
            Assert.All(await db.RefreshTokens.AsNoTracking().Where(t => t.UserId == userId).ToListAsync(), t => Assert.NotNull(t.RevokedAt));
            Assert.False((await db.RefreshTokens.AsNoTracking().SingleAsync(t => t.UserId == otherId)).IsRevoked);
            Assert.Equal("o", (await db.Users.AsNoTracking().SingleAsync(u => u.Id == otherId)).SecurityStamp);
        });

    private static async Task OnPostgresAsync(Func<ModularCADbContext, Task> scenario)
    {
        var server = Environment.GetEnvironmentVariable(ServerVariable)!;
        var name = await PostgresTestDatabase.CreateMigratedAsync(server, "modularca_sess");
        try
        {
            var connection = new NpgsqlConnectionStringBuilder(server) { Database = name, Pooling = false }.ConnectionString;
            await using var db = new ModularCADbContext(new DbContextOptionsBuilder<ModularCADbContext>().UseNpgsql(connection).Options);
            await scenario(db);
        }
        finally
        {
            NpgsqlConnection.ClearAllPools();
            await ExecAsync(server, $"DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)");
        }
    }

    private static async Task ExecAsync(string server, string sql)
    {
        await using var connection = new NpgsqlConnection(server);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        await command.ExecuteNonQueryAsync();
    }
}
