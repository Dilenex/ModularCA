using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services.Continuity;
using ModularCA.Shared.Enums;
using ModularCA.Tests.TestUtils;
using Xunit;
using static ModularCA.Tests.Database.PostgresCaFixture;

namespace ModularCA.Tests.Database;

/// <summary>
/// The published-CRL check on a real PostgreSQL database, with a CRL the service really signed
/// standing in for what a directory gave back: the comparison, the floor and the event inside
/// one locked transaction. Opt-in through <c>MODULARCA_TEST_PG</c>.
/// </summary>
[Trait("Category", "PostgreSQL")]
[Trait(TestTier.Name, TestTier.Slow)]
[Collection(PostgresLane.Four)]
public class PostgresPublishedCrlCheckTests
{
    [RequiresEnvironmentFact(ServerVariable)]
    public Task A_published_crl_ahead_of_the_database_raises_the_counters_and_the_next_crl_is_numbered_above_it()
        => WithDatabaseAsync("modularca_published", async connection =>
        {
            await using var db = Open(connection);
            var ca = await SeedCaAsync(db, "published-ca");
            var crls = Crls(db, connection, ca.Material);
            var audit = new RecordingAuditService();

            // The lost timeline published CRLs 1 and 2; then the database went back to before both.
            await crls.GenerateCrlAsync(ca.CaCertificateId);
            var published = new PublishedCrl(ca.CaCertificateId, "test directory", PemToDer(await crls.GenerateCrlAsync(ca.CaCertificateId)));
            db.ChangeTracker.Clear();
            db.Crls.RemoveRange(await db.Crls.ToListAsync());
            (await db.CrlConfigurations.SingleAsync()).LastCrlNumber = 0;
            await db.SaveChangesAsync();

            var now = DateTimeOffset.UtcNow;
            var ahead = Assert.Single(await InstanceContinuity.CheckPublishedCrlsAsync(db, null, audit, [published], now, NullLogger.Instance));

            Assert.Equal(2, ahead.PublishedNumber);
            Assert.Equal(0, ahead.DatabaseNumber);
            db.ChangeTracker.Clear();
            Assert.Equal(now.ToUnixTimeSeconds(), (await db.CrlConfigurations.AsNoTracking().SingleAsync()).LastCrlNumber);
            Assert.Equal(ContinuityEventKind.PublishedCrlAhead, (await db.InstanceContinuityEvents.AsNoTracking().SingleAsync()).Kind);
            Assert.Equal(AuditActionType.InstanceIncarnationChanged, Assert.Single(audit.Entries).Action);
            Assert.True(CrlNumberOf(ParseCrl(await crls.GenerateCrlAsync(ca.CaCertificateId))) > ahead.PublishedNumber);

            // The same CRL read back at the next start proves nothing new.
            db.ChangeTracker.Clear();
            Assert.Empty(await InstanceContinuity.CheckPublishedCrlsAsync(db, null, audit, [published], DateTimeOffset.UtcNow, NullLogger.Instance));
            Assert.Single(await db.InstanceContinuityEvents.AsNoTracking().ToListAsync());
        });
}
