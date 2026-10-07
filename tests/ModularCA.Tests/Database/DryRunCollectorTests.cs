using ModularCA.Database;
using Npgsql;
using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// The dry run's collect mode without a server: what <see cref="DryRunCollector"/> does after each
/// kind of failure, how <see cref="SchemaVersionGate.DryRunFailedMessage"/> and
/// <see cref="SchemaVersionGate.DryRunSummary"/> report what it collected, and that nothing short
/// of every command running passes.
/// </summary>
public class DryRunCollectorTests
{
    private const string Retire = "20260928221118_RetireTenantHostnames";
    private const string Unique = "20261002063527_InstanceUniqueCaNames";
    private const string Rename = "20261003072435_RenameTenantToSpace";

    private static PostgresException Pg(string sqlState, string message) => new(message, "ERROR", "ERROR", sqlState);

    [Fact]
    public void A_refusal_is_recorded_and_the_run_continues_and_later_ones_are_also_found()
    {
        var collector = new DryRunCollector();

        Assert.Equal(DryRunAction.Continue, collector.Failed(Retire, 1, 3, null, Pg("P0001", "hostnames remain")));
        Assert.Equal(DryRunAction.Continue, collector.Failed(Unique, 1, 22, "P1", Pg("P0001", "labels shared")));
        Assert.Equal(DryRunAction.Continue, collector.Failed(Unique, 2, 22, "P2", Pg("P0001", "labels shared up to case")));

        Assert.Equal(
            [new DryRunRefusal(Retire, null, "hostnames remain", false), new DryRunRefusal(Unique, "P1", "labels shared", true),
             new DryRunRefusal(Unique, "P2", "labels shared up to case", true)],
            collector.Refusals);
        Assert.Empty(collector.Skipped);
    }

    [Fact]
    public void Another_error_after_a_refusal_in_the_same_migration_skips_the_rest_of_it()
    {
        var collector = new DryRunCollector();
        collector.Failed(Unique, 1, 22, "P1", Pg("P0001", "labels shared"));
        var duplicate = Pg("23505", "could not create unique index");

        Assert.Equal(DryRunAction.SkipMigration, collector.Failed(Unique, 7, 22, null, duplicate));

        var skip = Assert.Single(collector.Skipped);
        Assert.Equal((Unique, 7, 22), (skip.Migration, skip.Command, skip.Commands));
        Assert.Same(duplicate, skip.Error);
    }

    /// <summary>
    /// With no refusal before it, after a refusal only in an earlier migration, or when it is a lock
    /// timeout, a deadlock or a statement timeout, which no refusal causes, an error stops the run.
    /// </summary>
    [Theory]
    [InlineData("42704", null)]
    [InlineData("23505", Unique)]
    [InlineData("55P03", Rename)]
    [InlineData("40P01", Rename)]
    [InlineData("57014", Rename)]
    public void Any_other_error_stops_the_run(string sqlState, string? refusedIn)
    {
        var collector = new DryRunCollector();
        if (refusedIn is not null)
            collector.Failed(refusedIn, 1, 22, "P1", Pg("P0001", "refused"));

        Assert.Equal(DryRunAction.Stop, collector.Failed(Rename, 25, 40, null, Pg(sqlState, "no")));
        Assert.Empty(collector.Skipped);
    }

    [Fact]
    public void An_error_that_is_not_from_postgres_is_never_a_refusal()
    {
        Assert.False(DryRunCollector.IsRefusal(new InvalidOperationException("P0001")));
        Assert.True(DryRunCollector.IsRefusal(new InvalidOperationException("wrapped", Pg("P0001", "x"))));
        Assert.Equal(DryRunAction.Stop, new DryRunCollector().Failed(Retire, 1, 3, null, new InvalidOperationException("table c exists")));
    }

    [Fact]
    public void Only_a_run_where_every_command_ran_passes()
    {
        DryRunResult Run(string? migration = null, Exception? error = null, bool notRehearsable = false) =>
            new([Retire], [], migration, error, notRehearsable);

        Assert.True(Run().Passed);
        Assert.False(Run().Stopped);
        Assert.False((Run() with { Refusals = [new DryRunRefusal(Retire, null, "x", false)] }).Passed);
        Assert.False((Run() with { Skipped = [new DryRunSkip(Retire, 2, 3, Pg("42P01", "x"))] }).Passed);
        Assert.False(Run(Retire, Pg("42P01", "x")).Passed);
        Assert.False(Run(Retire, notRehearsable: true).Passed);
        Assert.True(Run(Retire, notRehearsable: true).Stopped);
    }

    [Fact]
    public void The_message_lists_every_refusal_verbatim_numbered_with_later_ones_also_found()
    {
        var result = new DryRunResult([Retire, Unique, Rename], [], Rename, Pg("42P01", "relation \"IX_CertificateAuthorities_TenantId\" does not exist"), false)
        {
            Refusals =
            [
                new DryRunRefusal(Retire, null, "This instance has 1 tenant hostname(s), which 0.4.0 no longer serves.", false),
                new DryRunRefusal(Unique, "P1", "This instance has 1 CA label(s) used by more than one CA: acme-root (Acme), acme-root (instance).", true),
            ],
            Skipped = [new DryRunSkip(Unique, 7, 22, Pg("23505", "could not create unique index \"IX_CertificateAuthorities_LabelLower\""))],
            Command = 25,
            Commands = 40,
        };

        var lines = SchemaVersionGate.DryRunFailedMessage("application", result).Split(Environment.NewLine);

        Assert.Equal("The dry run of the application database found 2 refusal(s); fix each, then check again:", lines[0]);
        Assert.Equal($"  1 of 2: migration {Retire} refuses: This instance has 1 tenant hostname(s), which 0.4.0 no longer serves.", lines[1]);
        Assert.Equal($"  2 of 2, also found: migration {Unique} (P1) refuses: This instance has 1 CA label(s) used by more than one CA: "
            + "acme-root (Acme), acme-root (instance).", lines[2]);
        Assert.StartsWith($"  Skipped: the rest of migration {Unique}, from command 7 of 22, which failed after its refusal above "
            + "(PostgresException 23505: could not create unique index", lines[3]);
        Assert.EndsWith("Those steps depend on fixing that refusal; they are checked once it is fixed.", lines[3]);
        Assert.Equal($"  Stopped: migration {Rename} failed at command 25 of 40 (PostgresException 42P01: relation "
            + "\"IX_CertificateAuthorities_TenantId\" does not exist), which may follow from the steps skipped above. "
            + "The checks after this point could not run.", lines[4]);
        Assert.StartsWith("\"Also found\" refusals came after an earlier refusal", lines[5]);
        Assert.Equal($"The dry run ran the pending migrations ({Retire}, {Unique}, {Rename}) in one transaction and rolled it back; "
            + "nothing was applied to this database.", lines[6]);
        Assert.Equal(7, lines.Length);

        Assert.Equal($"migrations {Retire}, {Unique} refuse; then migration {Rename} fails, and the checks after it could not run",
            SchemaVersionGate.DryRunSummary(result));
    }

    [Fact]
    public void A_single_refusal_that_ran_to_the_end_has_no_also_found_and_no_stop()
    {
        var result = new DryRunResult([Rename], [], null, null, false)
        {
            Refusals = [new DryRunRefusal(Rename, "6", "RenameTenantToSpace left a tenant key.", false)],
        };

        var message = SchemaVersionGate.DryRunFailedMessage("application", result, scope: "either database");

        Assert.Contains($"  1 of 1: migration {Rename} (step 6) refuses: RenameTenantToSpace left a tenant key.", message);
        Assert.DoesNotContain("also found", message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("could not run", message);
        Assert.EndsWith("nothing was applied to either database.", message);
        Assert.Equal($"migration {Rename} refuses", SchemaVersionGate.DryRunSummary(result));
    }

    [Fact]
    public void An_error_with_no_refusal_is_one_paragraph_that_says_the_checks_after_it_could_not_run()
    {
        var result = new DryRunResult([Rename], [], Rename, Pg("42P07", "relation \"c\" already exists"), false) { Command = 3, Commands = 40 };

        var message = SchemaVersionGate.DryRunFailedMessage("application", result);

        Assert.Equal($"The dry run of the application database failed at migration {Rename}, command 3 of 40: PostgresException 42P07: "
            + "relation \"c\" already exists. The checks after this point could not run. The dry run ran the pending migrations "
            + $"({Rename}) in one transaction and rolled it back; nothing was applied to this database.", message);
        Assert.Equal($"migration {Rename} fails", SchemaVersionGate.DryRunSummary(result));

        var before = new DryRunResult([], [], null, Pg("55P03", "lock timeout"), false);
        Assert.StartsWith("The dry run of the application database failed before any migration ran:", SchemaVersionGate.DryRunFailedMessage("application", before));
        Assert.Equal("dry run failed", SchemaVersionGate.DryRunSummary(before));
    }

    [Fact]
    public void A_migration_that_cannot_be_rehearsed_after_a_refusal_is_listed_as_the_stop()
    {
        var result = new DryRunResult([Retire, Rename], [], Rename, null, true)
        {
            Refusals = [new DryRunRefusal(Retire, null, "hostnames remain", false)],
        };

        var message = SchemaVersionGate.DryRunFailedMessage("application", result);

        Assert.Contains($"  Stopped: migration {Rename} runs a statement outside a transaction, so the dry run cannot rehearse it", message);
        Assert.Contains("The checks after this point could not run.", message);
        Assert.Equal($"migration {Retire} refuses; then migration {Rename} cannot be rehearsed, and the checks after it could not run",
            SchemaVersionGate.DryRunSummary(result));
    }

    [Fact]
    public void Check_labels_go_to_the_raising_commands_in_order_or_nowhere_when_they_do_not_match()
    {
        var fail = MigrationPreconditions.BuildSql("true", "no");
        string[] commands = ["ALTER TABLE x", fail, "UPDATE y", fail, fail, "INSERT INTO \"__EFMigrationsHistory\""];
        Assert.Equal(["P1", "P2", "6"], MigrationCheckLabels.Labels["20261003072435_RenameTenantToSpace"]);

        Assert.Equal([null, "P1", null, "P2", "6", null], MigrationCheckLabels.ForCommands("20261003072435_RenameTenantToSpace", commands));
        Assert.All(MigrationCheckLabels.ForCommands("20261003072435_RenameTenantToSpace", commands[..4]), Assert.Null);
        Assert.All(MigrationCheckLabels.ForCommands("20990101000000_Unlabelled", commands), Assert.Null);
    }
}
