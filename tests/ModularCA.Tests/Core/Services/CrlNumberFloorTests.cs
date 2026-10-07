using ModularCA.Core.Services;
using ModularCA.Shared.Entities;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// A restore must not make a CA reuse CRL numbers it published after the backup (RFC 5280
/// §5.2.3). The restored counters are raised to a time-derived floor, full and delta alike, so
/// the shared sequence continues above anything published since.
/// </summary>
public class CrlNumberFloorTests
{
    /// <summary>The allocation <see cref="CrlService"/> makes for full and delta CRLs alike.</summary>
    private static long NextCrlNumber(CrlConfigurationEntity config, IEnumerable<long> issuerRows)
        => Math.Max(config.LastCrlNumber, issuerRows.DefaultIfEmpty(0L).Max()) + 1;

    private static CrlConfigurationEntity Config(bool isDelta, long last) => new()
    {
        Name = isDelta ? "delta" : "full",
        IsDelta = isDelta,
        IssuerDN = "CN=Issuing CA",
        CaCertificateId = Guid.NewGuid(),
        UpdateInterval = "0 * * * *",
        LastCrlNumber = last,
    };

    [Fact]
    public async Task After_a_restore_the_next_full_and_delta_crl_numbers_exceed_everything_published_since_the_backup()
    {
        var restoredAt = new DateTimeOffset(2026, 10, 5, 12, 0, 0, TimeSpan.Zero);
        using var db = InMemoryDbContextFactory.Create();
        // The backup was taken after full CRL 40 and delta 41. After it, the CA went on to publish
        // up to 9,000 more numbers before the disaster; the restored database knows none of them.
        var full = Config(isDelta: false, last: 40);
        var delta = Config(isDelta: true, last: 41);
        db.CrlConfigurations.AddRange(full, delta);
        await db.SaveChangesAsync();
        var restoredRows = new long[] { 40, 41 };
        const long publishedSinceBackup = 9041;

        var raised = await CrlNumberFloor.ApplyAsync(db, CrlNumberFloor.FloorAt(restoredAt));

        Assert.Equal(2, raised.Count);
        Assert.True(NextCrlNumber(full, restoredRows) > publishedSinceBackup);
        Assert.True(NextCrlNumber(delta, restoredRows) > publishedSinceBackup);
        // One sequence: full and delta stand at the same floor, so neither can overtake the
        // other's numbers or the delta's base reference.
        Assert.Equal(full.LastCrlNumber, delta.LastCrlNumber);
        Assert.Equal(restoredAt.ToUnixTimeSeconds(), full.LastCrlNumber);
    }

    [Fact]
    public async Task The_floor_never_lowers_a_counter_already_above_it()
    {
        using var db = InMemoryDbContextFactory.Create();
        var ahead = Config(isDelta: false, last: 5_000_000_000);
        db.CrlConfigurations.Add(ahead);
        await db.SaveChangesAsync();

        var raised = await CrlNumberFloor.ApplyAsync(db, CrlNumberFloor.FloorAt(DateTimeOffset.UtcNow));

        Assert.Empty(raised);
        Assert.Equal(5_000_000_000, ahead.LastCrlNumber);
    }

    [Fact]
    public async Task After_a_restore_every_crl_configuration_is_due_whether_or_not_its_counter_moved()
    {
        using var db = InMemoryDbContextFactory.Create();
        var behind = Config(isDelta: false, last: 40);
        var ahead = Config(isDelta: true, last: 5_000_000_000);
        behind.NextUpdateUtc = ahead.NextUpdateUtc = DateTime.UtcNow.AddDays(1);
        db.CrlConfigurations.AddRange(behind, ahead);
        await db.SaveChangesAsync();

        await CrlNumberFloor.ApplyAsync(db, CrlNumberFloor.FloorAt(DateTimeOffset.UtcNow));

        db.ChangeTracker.Clear();
        Assert.All(db.CrlConfigurations, c => Assert.True(c.NextUpdateUtc < DateTime.UtcNow));
    }

    [Fact]
    public async Task A_second_restore_later_lands_above_a_ca_that_has_published_since_the_first()
    {
        using var db = InMemoryDbContextFactory.Create();
        var full = Config(isDelta: false, last: 0);
        db.CrlConfigurations.Add(full);
        await db.SaveChangesAsync();
        var first = new DateTimeOffset(2026, 10, 5, 12, 0, 0, TimeSpan.Zero);
        await CrlNumberFloor.ApplyAsync(db, CrlNumberFloor.FloorAt(first));

        // A CRL every minute for a week after the first restore, then a restore of the backup
        // taken just before that week began.
        var publishedSince = full.LastCrlNumber + 7 * 24 * 60;
        full.LastCrlNumber = CrlNumberFloor.FloorAt(first);
        await db.SaveChangesAsync();
        await CrlNumberFloor.ApplyAsync(db, CrlNumberFloor.FloorAt(first.AddDays(7)));

        Assert.True(NextCrlNumber(full, Array.Empty<long>()) > publishedSince);
    }
}
