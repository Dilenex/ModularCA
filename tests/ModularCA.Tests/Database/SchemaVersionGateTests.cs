using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// The startup schema rule (<see cref="SchemaVersionGate"/>): the verdict for every presence,
/// role and history, the failure wording, the migration precondition helper, and the frozen
/// baselines. None of these need a database.
/// </summary>
public class SchemaVersionGateTests
{
    private static readonly string[] Known = ["001_A", "002_B", "003_C"];

    [Fact]
    public void A_database_with_every_known_migration_is_current_for_every_role()
    {
        var state = new SchemaState(Known, Known);
        Assert.Equal(SchemaVerdict.Current, SchemaVersionGate.Evaluate(state, appliesMigrations: true));
        Assert.Equal(SchemaVerdict.Current, SchemaVersionGate.Evaluate(state, appliesMigrations: false));
    }

    [Fact]
    public void The_control_role_applies_what_is_pending()
    {
        var state = new SchemaState(["001_A"], Known);
        Assert.Equal(SchemaVerdict.ApplyPending, SchemaVersionGate.Evaluate(state, appliesMigrations: true));
        Assert.Equal(["002_B", "003_C"], state.Pending);
    }

    [Fact]
    public void Other_roles_refuse_pending_migrations_and_name_the_control_role()
    {
        var state = new SchemaState(["001_A"], Known);
        var verdict = SchemaVersionGate.Evaluate(state, appliesMigrations: false);
        Assert.Equal(SchemaVerdict.PendingForControlRole, verdict);
        var message = SchemaVersionGate.RefusalMessage(verdict, state, "application");
        Assert.NotNull(message);
        Assert.Contains("002_B", message);
        Assert.Contains("control role first", message);
    }

    [Fact]
    public void Other_roles_do_not_refuse_a_database_that_was_never_bootstrapped()
    {
        var state = new SchemaState([], Known);
        var verdict = SchemaVersionGate.Evaluate(state, appliesMigrations: false);
        Assert.Equal(SchemaVerdict.Unbootstrapped, verdict);
        Assert.Null(SchemaVersionGate.RefusalMessage(verdict, state, "application"));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Every_role_refuses_a_schema_newer_than_the_build(bool appliesMigrations)
    {
        var state = new SchemaState([.. Known, "004_Future"], Known);
        var verdict = SchemaVersionGate.Evaluate(state, appliesMigrations);
        Assert.Equal(SchemaVerdict.NewerThanBuild, verdict);
        var message = SchemaVersionGate.RefusalMessage(verdict, state, "audit");
        Assert.NotNull(message);
        Assert.Contains("004_Future", message);
        Assert.Contains("pre-upgrade dump", message);
    }

    [Theory]
    [InlineData(DatabasePresence.Missing, true)]
    [InlineData(DatabasePresence.Missing, false)]
    [InlineData(DatabasePresence.Empty, true)]
    [InlineData(DatabasePresence.Empty, false)]
    public void A_missing_or_empty_database_is_left_to_bootstrap_by_every_role(DatabasePresence presence, bool appliesMigrations)
    {
        var state = new SchemaState([], Known) { Presence = presence };
        var verdict = SchemaVersionGate.Evaluate(state, appliesMigrations);
        Assert.Equal(SchemaVerdict.Unbootstrapped, verdict);
        Assert.Null(SchemaVersionGate.RefusalMessage(verdict, state, "application"));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Every_role_refuses_tables_without_a_history(bool appliesMigrations)
    {
        var state = new SchemaState([], Known) { Presence = DatabasePresence.Unmanaged };
        var verdict = SchemaVersionGate.Evaluate(state, appliesMigrations);
        Assert.Equal(SchemaVerdict.Unmanaged, verdict);
        var message = SchemaVersionGate.RefusalMessage(verdict, state, "audit");
        Assert.NotNull(message);
        Assert.Contains("audit database", message);
        Assert.Contains("no migration history", message);
        Assert.Contains("Restore the pre-upgrade dump", message);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void A_newer_schema_is_refused_even_when_migrations_are_also_pending(bool appliesMigrations)
    {
        var state = new SchemaState(["001_A", "004_Future"], Known);
        Assert.Equal(["002_B", "003_C"], state.Pending);
        Assert.Equal(SchemaVerdict.NewerThanBuild, SchemaVersionGate.Evaluate(state, appliesMigrations));
    }

    [Fact]
    public void Presence_defaults_from_what_is_applied()
    {
        Assert.Equal(DatabasePresence.Managed, new SchemaState(["001_A"], Known).Presence);
        Assert.Equal(DatabasePresence.Empty, new SchemaState([], Known).Presence);
    }

    [Fact]
    public void A_failed_migration_message_names_the_migration_and_the_restore()
    {
        var error = new InvalidOperationException("outer", new Exception("precondition failed: two organisations"));
        var message = SchemaVersionGate.MigrationFailedMessage("application", "20261001000000_Fold", error);
        Assert.Contains("20261001000000_Fold", message);
        Assert.Contains("precondition failed: two organisations", message);
        Assert.Contains("pre-upgrade dump", message);
        Assert.Contains("rolled back", message);
        Assert.Contains("Committed in this run: none.", message);
    }

    [Fact]
    public void A_failed_migration_message_gives_the_sqlstate_and_what_this_run_committed()
    {
        var error = new Npgsql.PostgresException("canceling statement due to lock timeout", "ERROR", "ERROR", "55P03");
        var failure = new MigrationFailure("003_C", error, ["001_A", "002_B"], LeavesNonTransactionalStatements: false);
        var message = SchemaVersionGate.MigrationFailedMessage("audit", failure);
        Assert.Contains("Migration 003_C of the audit database failed", message);
        Assert.Contains("55P03", message);
        Assert.Contains("lock timeout", message);
        Assert.Contains("It ran in its own transaction and was rolled back.", message);
        Assert.Contains("Committed in this run: 001_A, 002_B.", message);
    }

    [Fact]
    public void A_failed_migration_with_statements_outside_a_transaction_says_they_stay_applied()
    {
        var error = new Npgsql.NpgsqlException("Exception while reading from stream", new TimeoutException("Timeout during reading attempt"));
        var failure = new MigrationFailure("002_B", error, [], LeavesNonTransactionalStatements: true);
        var message = SchemaVersionGate.MigrationFailedMessage("application", failure, commandTimeoutSeconds: 3600);
        Assert.Contains("command timeout (3600 s)", message);
        Assert.Contains("stay applied", message);
        Assert.DoesNotContain("It ran in its own transaction and was rolled back", message);
        Assert.Contains("Committed in this run: none.", message);
    }

    [Fact]
    public void A_precondition_is_a_do_block_that_raises()
    {
        var sql = MigrationPreconditions.BuildSql(
            "(SELECT count(*) FROM \"Tenants\") > 2", "Tenant's count is 100% too high");
        Assert.Equal(
            "DO $$ BEGIN IF ((SELECT count(*) FROM \"Tenants\") > 2) THEN "
            + "RAISE EXCEPTION 'Tenant''s count is 100%% too high'; END IF; END $$;",
            sql);
    }

    [Fact]
    public void A_precondition_cannot_close_the_do_block_early()
    {
        Assert.Throws<ArgumentException>(() => MigrationPreconditions.BuildSql("$$ true", "x"));
    }

    [Fact]
    public void Main_model_matches_its_latest_migration()
    {
        using var db = new ModularCADbContextFactory().CreateDbContext([]);
        Assert.False(db.Database.HasPendingModelChanges(),
            "The ModularCADbContext model differs from its snapshot: add a migration with dotnet ef migrations add.");
    }

    [Fact]
    public void Audit_model_matches_its_latest_migration()
    {
        using var db = new AuditDbContextFactory().CreateDbContext([]);
        Assert.False(db.Database.HasPendingModelChanges(),
            "The AuditDbContext model differs from its snapshot: add a migration with dotnet ef migrations add.");
    }

    [Fact]
    public void The_baselines_are_still_the_first_migrations()
    {
        using var db = new ModularCADbContextFactory().CreateDbContext([]);
        using var audit = new AuditDbContextFactory().CreateDbContext([]);
        Assert.Equal(PostgresUpgradeHarnessTests.AppBaseline, db.Database.GetMigrations().First());
        Assert.Equal(PostgresUpgradeHarnessTests.AuditBaseline, audit.Database.GetMigrations().First());
    }
}
