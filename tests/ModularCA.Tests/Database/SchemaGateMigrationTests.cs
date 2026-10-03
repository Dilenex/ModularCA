using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using ModularCA.Database;
using ModularCA.Tests.Database.GateMigrations;
using Xunit;

namespace ModularCA.Tests.Database
{
    /// <summary>
    /// <see cref="SchemaVersionGate"/> with real pending migrations, on SQLite: a fresh apply, a
    /// failing migration, a merged-branch gap, and a gap whose second migration fails. The four
    /// hand-written migrations of <see cref="GateTestContext"/> live in this assembly.
    /// </summary>
    public sealed class SchemaGateMigrationTests : IDisposable
    {
        private const string A = "20990101000001_A";
        private const string B1 = "20990101000002_B1";
        private const string B2 = "20990101000003_B2";
        private const string C = "20990101000004_C";

        private readonly string _path = Path.Combine(Path.GetTempPath(), $"modularca-gate-{Guid.NewGuid():N}.db");

        /// <summary>Deletes the temporary database file.</summary>
        public void Dispose()
        {
            SqliteConnection.ClearAllPools();
            try { File.Delete(_path); } catch (IOException) { }
        }

        [Fact]
        public async Task A_missing_database_file_is_missing_and_left_to_bootstrap()
        {
            await using var db = Context();
            var state = await SchemaVersionGate.ReadAsync(db);
            Assert.Equal(DatabasePresence.Missing, state.Presence);
            Assert.Equal(SchemaVerdict.Unbootstrapped, SchemaVersionGate.Evaluate(state, appliesMigrations: true));
            Assert.False(File.Exists(_path));
        }

        [Fact]
        public async Task A_fresh_apply_ends_current_for_every_role()
        {
            Execute("SELECT 1");
            await using var db = Context();
            Assert.Equal(DatabasePresence.Empty, (await SchemaVersionGate.ReadAsync(db)).Presence);

            var failure = await SchemaVersionGate.ApplyAllForBootstrapAsync(db);

            Assert.Null(failure);
            var after = await SchemaVersionGate.ReadAsync(db);
            Assert.Equal([A, B1, B2, C], after.Applied);
            Assert.Equal(DatabasePresence.Managed, after.Presence);
            Assert.Equal(SchemaVerdict.Current, SchemaVersionGate.Evaluate(after, appliesMigrations: true));
            Assert.Equal(SchemaVerdict.Current, SchemaVersionGate.Evaluate(after, appliesMigrations: false));
        }

        [Fact]
        public async Task Bootstrap_applies_a_baseline_only_to_an_empty_database()
        {
            Execute("CREATE TABLE foreign_table (id INTEGER)");
            await using var db = Context();
            var state = await SchemaVersionGate.ReadAsync(db);
            Assert.Equal(DatabasePresence.Unmanaged, state.Presence);
            Assert.Equal(SchemaVerdict.Unmanaged, SchemaVersionGate.Evaluate(state, appliesMigrations: true));

            await Assert.ThrowsAsync<InvalidOperationException>(() => SchemaVersionGate.ApplyAllForBootstrapAsync(db));
            Assert.Empty(Tables().Where(t => t.StartsWith("__EFMigrations", StringComparison.Ordinal) && t != "__EFMigrationsLock"));
        }

        [Fact]
        public async Task A_failing_migration_is_named_and_what_ran_before_it_stays_committed()
        {
            Execute("SELECT 1");
            await ApplyUpToAsync(A);
            Execute("CREATE TABLE c (id INTEGER); INSERT INTO c VALUES (7);");

            await using var db = Context();
            var state = await SchemaVersionGate.ReadAsync(db);
            Assert.Equal([B1, B2, C], state.Pending);
            var failure = await SchemaVersionGate.ApplyPendingAsync(db, state);

            Assert.NotNull(failure);
            Assert.Equal(C, failure.Migration);
            Assert.Equal([B1, B2], failure.CommittedInThisRun);
            Assert.False(failure.LeavesNonTransactionalStatements);
            Assert.Equal([A, B1, B2], (await SchemaVersionGate.ReadAsync(db)).Applied);
            Assert.Equal(7L, Scalar("SELECT id FROM c"));

            var message = SchemaVersionGate.MigrationFailedMessage("application", failure);
            Assert.Contains($"Migration {C} of the application database failed", message);
            Assert.Contains($"Committed in this run: {B1}, {B2}.", message);
            Assert.Contains("was rolled back", message);
        }

        [Fact]
        public async Task A_merged_branch_gap_is_applied_without_reverting_the_newer_migration()
        {
            Execute("SELECT 1");
            await ApplyUpToAsync(A);
            Execute($"CREATE TABLE c (id INTEGER); INSERT INTO c VALUES (9); INSERT INTO \"__EFMigrationsHistory\" VALUES ('{C}', '10.0.12');");

            await using var db = Context();
            var state = await SchemaVersionGate.ReadAsync(db);
            Assert.Equal([B1, B2], state.Pending);
            Assert.Equal(SchemaVerdict.ApplyPending, SchemaVersionGate.Evaluate(state, appliesMigrations: true));

            var failure = await SchemaVersionGate.ApplyPendingAsync(db, state);

            Assert.Null(failure);
            var after = await SchemaVersionGate.ReadAsync(db);
            Assert.Equal(SchemaVerdict.Current, SchemaVersionGate.Evaluate(after, appliesMigrations: true));
            Assert.Contains(C, after.Applied);
            Assert.Equal(9L, Scalar("SELECT id FROM c"));
            Assert.DoesNotContain("c_down_ran", Tables());
        }

        [Fact]
        public async Task A_gap_whose_second_migration_fails_names_that_one_and_reports_the_first_as_committed()
        {
            Execute("SELECT 1");
            await ApplyUpToAsync(A);
            Execute($"CREATE TABLE c (id INTEGER); INSERT INTO \"__EFMigrationsHistory\" VALUES ('{C}', '10.0.12'); CREATE TABLE b2 (id INTEGER);");

            await using var db = Context();
            var state = await SchemaVersionGate.ReadAsync(db);
            var failure = await SchemaVersionGate.ApplyPendingAsync(db, state);

            Assert.NotNull(failure);
            Assert.Equal(B2, failure.Migration);
            Assert.Equal([B1], failure.CommittedInThisRun);
            Assert.True(failure.LeavesNonTransactionalStatements);
            var after = await SchemaVersionGate.ReadAsync(db);
            Assert.Contains(C, after.Applied);
            Assert.Contains(B1, after.Applied);
            Assert.DoesNotContain(B2, after.Applied);

            var message = SchemaVersionGate.MigrationFailedMessage("application", failure);
            Assert.Contains($"Migration {B2} ", message);
            Assert.Contains($"Committed in this run: {B1}.", message);
            Assert.Contains("stay applied", message);
        }

        [Fact]
        public async Task Applying_through_a_migration_leaves_the_later_ones_pending()
        {
            Execute("SELECT 1");
            await using var db = Context();

            Assert.Null(await SchemaVersionGate.ApplyPendingThroughAsync(db, await SchemaVersionGate.ReadAsync(db), B1));

            var state = await SchemaVersionGate.ReadAsync(db);
            Assert.Equal([A, B1], state.Applied);
            Assert.Equal([B2, C], state.Pending);
            Assert.Null(await SchemaVersionGate.ApplyPendingThroughAsync(db, state, C));
            Assert.Equal([A, B1, B2, C], (await SchemaVersionGate.ReadAsync(db)).Applied);
        }

        [Fact]
        public async Task Applying_through_an_older_or_unknown_migration_is_refused_and_never_reverts()
        {
            Execute("SELECT 1");
            await ApplyUpToAsync(C);
            await using var db = Context();
            var state = await SchemaVersionGate.ReadAsync(db);

            await Assert.ThrowsAsync<InvalidOperationException>(() => SchemaVersionGate.ApplyPendingThroughAsync(db, state, A));
            await Assert.ThrowsAsync<ArgumentException>(() => SchemaVersionGate.ApplyPendingThroughAsync(db, state, "20990101000099_NotAMigration"));
            Assert.Equal([A, B1, B2, C], (await SchemaVersionGate.ReadAsync(db)).Applied);
            Assert.DoesNotContain("c_down_ran", Tables());
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public async Task An_unknown_history_row_is_newer_than_the_build_for_every_role(bool appliesMigrations)
        {
            Execute("SELECT 1");
            await ApplyUpToAsync(A);
            Execute("INSERT INTO \"__EFMigrationsHistory\" VALUES ('20991231000000_Future', '10.0.12');");

            await using var db = Context();
            var state = await SchemaVersionGate.ReadAsync(db);
            Assert.Equal(["20991231000000_Future"], state.Unknown);
            Assert.Equal(SchemaVerdict.NewerThanBuild, SchemaVersionGate.Evaluate(state, appliesMigrations));
        }

        [Fact]
        public void Statements_run_outside_a_transaction_are_detected_per_migration()
        {
            using var db = Context();
            Assert.True(SchemaVersionGate.LeavesNonTransactionalStatements(db, B2));
            Assert.False(SchemaVersionGate.LeavesNonTransactionalStatements(db, B1));
            Assert.False(SchemaVersionGate.LeavesNonTransactionalStatements(db, "20990101000099_NotAMigration"));
        }

        /// <summary>A context on the temporary file, unpooled so the file can be deleted.</summary>
        private GateTestContext Context() =>
            new(new DbContextOptionsBuilder<GateTestContext>().UseSqlite($"Data Source={_path};Pooling=False").Options);

        /// <summary>Applies the test migrations up to <paramref name="target"/> with EF directly.</summary>
        private async Task ApplyUpToAsync(string target)
        {
            await using var db = Context();
            await db.GetService<IMigrator>().MigrateAsync(target);
        }

        /// <summary>Runs <paramref name="sql"/> on its own connection.</summary>
        private void Execute(string sql)
        {
            using var connection = new SqliteConnection($"Data Source={_path};Pooling=False");
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = sql;
            command.ExecuteNonQuery();
        }

        /// <summary>The first column of the first row of <paramref name="sql"/>.</summary>
        private object? Scalar(string sql)
        {
            using var connection = new SqliteConnection($"Data Source={_path};Pooling=False");
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = sql;
            return command.ExecuteScalar();
        }

        /// <summary>Every table in the file.</summary>
        private List<string> Tables()
        {
            using var connection = new SqliteConnection($"Data Source={_path};Pooling=False");
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT name FROM sqlite_master WHERE type = 'table'";
            using var reader = command.ExecuteReader();
            var names = new List<string>();
            while (reader.Read())
                names.Add(reader.GetString(0));
            return names;
        }
    }
}

namespace ModularCA.Tests.Database.GateMigrations
{
    /// <summary>An entity-less context whose only purpose is to carry the four test migrations.</summary>
    public sealed class GateTestContext(DbContextOptions<GateTestContext> options) : DbContext(options);

    /// <summary>The first migration: table <c>a</c>.</summary>
    [DbContext(typeof(GateTestContext))]
    [Migration("20990101000001_A")]
    public sealed class GateMigrationA : Migration
    {
        /// <summary>Creates table <c>a</c>.</summary>
        protected override void Up(MigrationBuilder migrationBuilder) => migrationBuilder.Sql("CREATE TABLE a (id INTEGER)");
    }

    /// <summary>The first migration of a merged branch: table <c>b1</c>.</summary>
    [DbContext(typeof(GateTestContext))]
    [Migration("20990101000002_B1")]
    public sealed class GateMigrationB1 : Migration
    {
        /// <summary>Creates table <c>b1</c>.</summary>
        protected override void Up(MigrationBuilder migrationBuilder) => migrationBuilder.Sql("CREATE TABLE b1 (id INTEGER)");
    }

    /// <summary>The second migration of a merged branch, run outside a transaction: table <c>b2</c>.</summary>
    [DbContext(typeof(GateTestContext))]
    [Migration("20990101000003_B2")]
    public sealed class GateMigrationB2 : Migration
    {
        /// <summary>Creates table <c>b2</c> with <c>suppressTransaction</c>.</summary>
        protected override void Up(MigrationBuilder migrationBuilder) =>
            migrationBuilder.Sql("CREATE TABLE b2 (id INTEGER)", suppressTransaction: true);
    }

    /// <summary>The newest migration: table <c>c</c>. Its <c>Down</c> leaves a marker, so a revert is visible.</summary>
    [DbContext(typeof(GateTestContext))]
    [Migration("20990101000004_C")]
    public sealed class GateMigrationC : Migration
    {
        /// <summary>Creates table <c>c</c>.</summary>
        protected override void Up(MigrationBuilder migrationBuilder) => migrationBuilder.Sql("CREATE TABLE c (id INTEGER)");

        /// <summary>Drops table <c>c</c> and leaves table <c>c_down_ran</c> behind.</summary>
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("DROP TABLE c");
            migrationBuilder.Sql("CREATE TABLE c_down_ran (id INTEGER)");
        }
    }
}
