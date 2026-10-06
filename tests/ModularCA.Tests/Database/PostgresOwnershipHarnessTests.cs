using System.Diagnostics;
using System.Reflection;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using ModularCA.Bootstrap;
using ModularCA.Database;
using ModularCA.Migrate;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Database.ProbeMigrations;
using Npgsql;
using Serilog.Events;
using Xunit;

namespace ModularCA.Tests.Database
{
    /// <summary>
    /// A <see cref="TheoryAttribute"/> that runs only when <paramref name="variable"/> is set, and is
    /// otherwise reported as skipped with the reason.
    /// </summary>
    public sealed class RequiresEnvironmentTheoryAttribute : TheoryAttribute
    {
        /// <summary>Skips the theory unless <paramref name="variable"/> is set.</summary>
        public RequiresEnvironmentTheoryAttribute(string variable)
        {
            if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(variable)))
                Skip = $"Opt-in: set {variable} to run.";
        }
    }

    /// <summary>
    /// A <see cref="TheoryAttribute"/> that runs only when <paramref name="variable"/> is set and
    /// <see cref="PostgresClientTools.Directory"/> finds <c>pg_dump</c> and <c>pg_restore</c>.
    /// </summary>
    public sealed class RequiresPostgresClientToolsTheoryAttribute : TheoryAttribute
    {
        /// <summary>Skips the theory unless <paramref name="variable"/> is set and the client tools are found.</summary>
        public RequiresPostgresClientToolsTheoryAttribute(string variable)
        {
            if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(variable)))
                Skip = $"Opt-in: set {variable} to run.";
            else if (PostgresClientTools.Directory is null)
                Skip = $"pg_dump and pg_restore were not found: set {PostgresClientTools.Variable} to PostgreSQL's bin folder, or put it on PATH.";
        }
    }

    /// <summary>
    /// Finds the folder holding <c>pg_dump</c> and <c>pg_restore</c> for the harness: the folder in
    /// <see cref="Variable"/>, else one on PATH, else the newest <c>C:\Program Files\PostgreSQL\*\bin</c>
    /// on Windows. The product itself only looks on PATH.
    /// </summary>
    internal static class PostgresClientTools
    {
        /// <summary>The optional environment variable naming PostgreSQL's bin folder.</summary>
        public const string Variable = "MODULARCA_TEST_PG_BIN";

        private static readonly Lazy<string?> Found = new(Locate);

        /// <summary>The folder holding both tools, or null when none does.</summary>
        public static string? Directory => Found.Value;

        /// <summary>Puts <see cref="Directory"/> first on this process's PATH, so the product's bare-name lookup finds the tools.</summary>
        public static void EnsureOnPath()
        {
            var dir = Directory ?? throw new InvalidOperationException("pg_dump and pg_restore were not found.");
            var path = Environment.GetEnvironmentVariable("PATH") ?? "";
            if (!path.Split(Path.PathSeparator).Contains(dir, StringComparer.OrdinalIgnoreCase))
                Environment.SetEnvironmentVariable("PATH", dir + Path.PathSeparator + path);
        }

        private static string? Locate()
        {
            var candidates = new List<string>();
            if (Environment.GetEnvironmentVariable(Variable) is { Length: > 0 } configured)
                candidates.Add(configured);
            candidates.AddRange((Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries));
            var installs = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "PostgreSQL");
            if (OperatingSystem.IsWindows() && System.IO.Directory.Exists(installs))
                candidates.AddRange(System.IO.Directory.GetDirectories(installs)
                    .OrderByDescending(d => int.TryParse(Path.GetFileName(d), out var major) ? major : -1)
                    .Select(d => Path.Combine(d, "bin")));
            var suffix = OperatingSystem.IsWindows() ? ".exe" : "";
            return candidates.FirstOrDefault(d =>
                File.Exists(Path.Combine(d, "pg_dump" + suffix)) && File.Exists(Path.Combine(d, "pg_restore" + suffix)));
        }
    }

    /// <summary>
    /// Opt-in ownership and startup-gate tests against a real PostgreSQL server
    /// (<c>MODULARCA_TEST_PG</c>, a superuser connection string). Each test builds throwaway roles
    /// and databases with a random suffix in one of three layouts and drops them afterwards:
    /// <c>migrated</c> (ModularCA.Migrate's <see cref="DestinationBuilder"/>), <c>fresh</c>
    /// (bootstrap's provisioning, schema and ownership check) and <c>legacy</c> (the 0.3.1
    /// bootstrap: baselines applied as the superuser, the application database handed to the app
    /// role, the old audit grants), optionally stopped at the frozen baselines. Test-only probe
    /// contexts with their own history tables carry migrations that alter <c>Users</c>, a table
    /// every stage of the schema has, run through <c>SchemaStartup.EnforceAllAsync</c> as the
    /// runtime roles.
    /// </summary>
    [Trait("Category", "PostgreSQL")]
    [Collection(SerilogCaptureCollection.Name)]
    public sealed class PostgresOwnershipHarnessTests
    {
        private const string ServerVariable = "MODULARCA_TEST_PG";

        private static string Server => Environment.GetEnvironmentVariable(ServerVariable)!;

        [RequiresEnvironmentTheory(ServerVariable)]
        [InlineData(OwnershipLayout.Migrated)]
        [InlineData(OwnershipLayout.Fresh)]
        public async Task A_migrated_or_fresh_layout_is_sound_and_every_role_starts(OwnershipLayout layout)
        {
            await using var f = await OwnershipFixture.CreateAsync(Server, layout);
            using var log = new CapturedSerilog();

            var app = await f.OwnershipAsync(DatabaseKind.Application);
            var audit = await f.OwnershipAsync(DatabaseKind.Audit);
            Assert.True(app.IsSound, SchemaOwnership.RefusalMessage(app, null));
            Assert.True(audit.IsSound, SchemaOwnership.RefusalMessage(audit, null));
            Assert.False(audit.CanBecomeDbOwner);
            Assert.False(audit.CanCreateSchema);
            Assert.Empty(SchemaOwnership.Warnings(app));
            Assert.Empty(SchemaOwnership.Warnings(audit));

            Assert.Null(await SchemaStartupApi.EnforceAllAsync(f.Targets(), true, new SchemaConfig { WaitSeconds = 1 }));
            Assert.Null(await SchemaStartupApi.EnforceAllAsync(f.Targets(), false, new SchemaConfig { WaitSeconds = 1 }));
            Assert.True(log.Has(LogEventLevel.Information, "Schema check passed"), Dump(log));
        }

        /// <summary>
        /// The migration tool's destination: rows written into the baselines as the app role, by the
        /// baseline's names as the copier writes them, then every later migration applied by
        /// <see cref="DestinationBuilder.ApplyUpgradeMigrationsAsync"/>. The copied system tenant is
        /// folded and a copied space CA keeps its tenant; read through the current model, which the
        /// schema now matches.
        /// </summary>
        [RequiresEnvironmentFact(ServerVariable)]
        public async Task The_migration_tool_takes_rows_copied_into_the_baselines_through_every_later_migration()
        {
            await using var f = await OwnershipFixture.CreateAsync(Server, OwnershipLayout.Migrated, atBaseline: true);
            Assert.Equal(1, await f.CountAsync(f.AppDatabase, "SELECT count(*) FROM public.\"__EFMigrationsHistory\""));
            Assert.Equal(1, await f.CountAsync(f.AuditDatabase, "SELECT count(*) FROM public.\"__EFMigrationsHistory\""));
            await f.ExecuteAsRuntimeAsync(f.App, PostgresUpgradeHarnessTests.Seed030Sql + PostgresUpgradeHarnessTests.SeedFoldSql);

            await f.Builder!.ApplyUpgradeMigrationsAsync(CancellationToken.None);

            Assert.Null(await SchemaStartupApi.EnforceAllAsync(f.Targets(), false, new SchemaConfig { WaitSeconds = 1 }));
            await using var app = new ModularCADbContext(new DbContextOptionsBuilder<ModularCADbContext>()
                .UseNpgsql(f.RuntimeConnectionString(f.App, f.AppDatabase)).Options);
            var cas = await app.CertificateAuthorities.IgnoreQueryFilters().AsNoTracking().ToDictionaryAsync(c => c.Id);
            Assert.Equal(PostgresUpgradeHarnessTests.OrgTenantId, cas[PostgresUpgradeHarnessTests.RootCaId].SpaceId);
            Assert.Equal(2, cas.Values.Count(c => c.SpaceId is null));
            Assert.Equal([PostgresUpgradeHarnessTests.OrgTenantId], await app.Spaces.IgnoreQueryFilters().Select(t => t.Id).ToListAsync());
        }

        /// <summary>
        /// A precondition that refuses the copied data fails the migration tool with the
        /// migration's own message, leaves the migrations before it committed, and the tool's
        /// rollback then removes both databases and all three roles.
        /// </summary>
        [RequiresEnvironmentFact(ServerVariable)]
        public async Task A_refusal_after_the_copy_fails_the_migration_tool_and_its_rollback_removes_the_destination()
        {
            await using var f = await OwnershipFixture.CreateAsync(Server, OwnershipLayout.Migrated, atBaseline: true);
            await f.ExecuteAsRuntimeAsync(f.App, PostgresUpgradeHarnessTests.Seed030Sql + PostgresUpgradeHarnessTests.SeedFoldSql
                + PostgresUpgradeHarnessTests.SeedSecurityPolicySql);

            var refused = await Assert.ThrowsAsync<MigrationFailedException>(() => f.Builder!.ApplyUpgradeMigrationsAsync(CancellationToken.None));

            Assert.Contains("_" + PostgresUpgradeHarnessTests.FoldSystemTenant, refused.Message);
            Assert.Contains("This instance has 2 SecurityPolicy rows", refused.Message);
            Assert.Equal(2, await f.CountAsync(f.AppDatabase, "SELECT count(*) FROM public.\"__EFMigrationsHistory\""));

            await DestinationBuilder.RollbackAsync(f.MigrateOptions!, _ => { }, CancellationToken.None);
            Assert.Equal(0, await f.CountAsync(null,
                $"SELECT count(*) FROM pg_catalog.pg_database WHERE datname IN ('{f.AppDatabase}','{f.AuditDatabase}')"));
            Assert.Equal(0, await f.CountAsync(null,
                $"SELECT count(*) FROM pg_catalog.pg_roles WHERE rolname IN ('{f.App.Username}','{f.Audit.Username}','{f.AuditOwner}')"));
        }

        [RequiresEnvironmentFact(ServerVariable)]
        public async Task A_legacy_layout_reports_every_object_is_refused_and_starts_after_one_idempotent_repair()
        {
            await using var f = await OwnershipFixture.CreateAsync(Server, OwnershipLayout.Legacy);
            using var log = new CapturedSerilog();

            var app = await f.OwnershipAsync(DatabaseKind.Application);
            var audit = await f.OwnershipAsync(DatabaseKind.Audit);
            var appTables = await f.CountAsync(f.AppDatabase, "SELECT count(*) FROM pg_catalog.pg_tables WHERE schemaname = 'public'");
            var auditTables = await f.CountAsync(f.AuditDatabase, "SELECT count(*) FROM pg_catalog.pg_tables WHERE schemaname = 'public'");
            Assert.Equal(appTables, app.NotOwned.Count(o => o.Kind == "r"));
            Assert.True(app.Unusable);
            Assert.All(app.NotOwned, o => Assert.False(o.Usable, $"{o.Object} is readable by the app role"));
            Assert.Equal(auditTables, audit.NotOwned.Count(o => o.Kind == "r"));
            Assert.False(audit.Unusable);

            var appHistory = await f.CountAsync(f.AppDatabase, "SELECT count(*) FROM public.\"__EFMigrationsHistory\"");
            var auditHistory = await f.CountAsync(f.AuditDatabase, "SELECT count(*) FROM public.\"__EFMigrationsHistory\"");
            Assert.Equal(3, await SchemaStartupApi.EnforceAllAsync(f.Targets(), true, new SchemaConfig { WaitSeconds = 1 }));
            Assert.True(log.Has(LogEventLevel.Fatal, "cannot even read"), Dump(log));
            Assert.True(log.Has(LogEventLevel.Fatal, "adopt-ownership.sql"), Dump(log));
            Assert.Equal(appHistory, await f.CountAsync(f.AppDatabase, "SELECT count(*) FROM public.\"__EFMigrationsHistory\""));
            Assert.Equal(auditHistory, await f.CountAsync(f.AuditDatabase, "SELECT count(*) FROM public.\"__EFMigrationsHistory\""));

            Assert.True(await f.RepairAsync(DatabaseKind.Application) > 0);
            Assert.True(await f.RepairAsync(DatabaseKind.Audit) > 0);
            Assert.True((await f.OwnershipAsync(DatabaseKind.Application)).IsSound);
            Assert.True((await f.OwnershipAsync(DatabaseKind.Audit)).IsSound);
            Assert.Null(await SchemaStartupApi.EnforceAllAsync(f.Targets(), true, new SchemaConfig { WaitSeconds = 1 }));

            Assert.Equal(0, await f.RepairAsync(DatabaseKind.Application));
            Assert.Equal(0, await f.RepairAsync(DatabaseKind.Audit));
        }

        [RequiresEnvironmentTheory(ServerVariable)]
        [InlineData(OwnershipLayout.Migrated)]
        [InlineData(OwnershipLayout.Fresh)]
        [InlineData(OwnershipLayout.Legacy)]
        public async Task A_migration_that_alters_existing_tables_runs_as_the_runtime_roles_only_where_they_own_them(OwnershipLayout layout)
        {
            await using var f = await OwnershipFixture.CreateAsync(Server, layout);
            using var log = new CapturedSerilog();
            await f.SeedProbeHistoryAsync(f.AppDatabase, AppProbeContext.History, f.App.Username);
            await f.SeedProbeHistoryAsync(f.AuditDatabase, AuditProbeContext.History, f.Audit.Username);
            SchemaStartupApi.UseContextFactory((kind, cs, timeout) => kind == DatabaseKind.Application
                ? new AppProbeContext(ProbeOptions.For<AppProbeContext>(cs, timeout, AppProbeContext.History))
                : new AuditProbeContext(ProbeOptions.For<AuditProbeContext>(cs, timeout, AuditProbeContext.History)));

            var exit = await SchemaStartupApi.EnforceAllAsync(f.Targets(), true, new SchemaConfig { WaitSeconds = 1 });

            if (layout == OwnershipLayout.Legacy)
            {
                Assert.Equal(3, exit);
                Assert.True(log.Has(LogEventLevel.Fatal, "Nothing was applied to either database"), Dump(log));
                Assert.Equal(1, await f.CountAsync(f.AppDatabase, $"SELECT count(*) FROM public.\"{AppProbeContext.History}\""));
                Assert.Equal(1, await f.CountAsync(f.AuditDatabase, $"SELECT count(*) FROM public.\"{AuditProbeContext.History}\""));
                Assert.Equal(0, await f.ColumnCountAsync(f.AppDatabase, "Users", "GateProbe"));

                await f.RepairAsync(DatabaseKind.Application);
                await f.RepairAsync(DatabaseKind.Audit);
                exit = await SchemaStartupApi.EnforceAllAsync(f.Targets(), true, new SchemaConfig { WaitSeconds = 1 });
            }

            Assert.True(exit is null, Dump(log));
            Assert.Equal(1, await f.ColumnCountAsync(f.AppDatabase, "Users", "GateProbe"));
            Assert.Equal(1, await f.ColumnCountAsync(f.AuditDatabase, "AuditLogs", "GateProbe"));
            Assert.Equal(2, await f.CountAsync(f.AppDatabase, $"SELECT count(*) FROM public.\"{AppProbeContext.History}\""));
            Assert.True((await f.OwnershipAsync(DatabaseKind.Application)).IsSound);
            Assert.True((await f.OwnershipAsync(DatabaseKind.Audit)).IsSound);
        }

        [RequiresEnvironmentTheory(ServerVariable)]
        [InlineData(OwnershipLayout.Migrated)]
        [InlineData(OwnershipLayout.Fresh)]
        [InlineData(OwnershipLayout.Legacy)]
        public async Task The_tenant_hostname_retirement_refuses_while_a_row_remains_then_applies_as_the_runtime_role(OwnershipLayout layout)
        {
            await using var f = await OwnershipFixture.CreateAsync(Server, layout, atBaseline: true);
            using var log = new CapturedSerilog();
            const string retire = "RetireTenantHostnames";
            var history = "SELECT count(*) FROM public.\"__EFMigrationsHistory\"";
            var tableExists = "SELECT count(*) FROM pg_catalog.pg_class WHERE relname = 'TenantHostnames' AND relnamespace = 'public'::regnamespace";

            if (layout == OwnershipLayout.Legacy)
            {
                await f.RepairAsync(DatabaseKind.Application);
                await f.RepairAsync(DatabaseKind.Audit);
            }
            Assert.Equal(1, await f.CountAsync(f.AppDatabase, history));
            Assert.Equal(1, await f.CountAsync(f.AppDatabase, tableExists));
            Assert.True((await f.OwnershipAsync(DatabaseKind.Application)).IsSound);

            await f.ExecuteAsRuntimeAsync(f.App, PostgresUpgradeHarnessTests.Seed030Sql + PostgresUpgradeHarnessTests.SeedTenantHostnameSql);
            Assert.Equal(3, await SchemaStartupApi.EnforceAllAsync(f.Targets(), true, new SchemaConfig { WaitSeconds = 1 }));
            Assert.True(Logged(log, "This instance has 1 tenant hostname(s)"), Dump(log));
            Assert.Equal(1, await f.CountAsync(f.AppDatabase, history));
            Assert.Equal(1, await f.CountAsync(f.AppDatabase, "SELECT count(*) FROM public.\"TenantHostnames\""));

            await f.ExecuteAsRuntimeAsync(f.App, "DELETE FROM \"TenantHostnames\"");
            var exit = await SchemaStartupApi.EnforceAllAsync(f.Targets(), true, new SchemaConfig { WaitSeconds = 1 });

            Assert.True(exit is null, Dump(log));
            Assert.Equal(0, await f.CountAsync(f.AppDatabase, tableExists));
            Assert.Equal(1, await f.CountAsync(f.AppDatabase, $"{history} WHERE \"MigrationId\" LIKE '%\\_{retire}'"));
            Assert.True((await f.OwnershipAsync(DatabaseKind.Application)).IsSound);
            Assert.Equal(1, await f.CountAsync(f.AppDatabase, "SELECT count(*) FROM public.\"Users\""));
            Assert.Equal(2, await f.CountAsync(f.AppDatabase, "SELECT count(*) FROM public.\"CaGroupMembers\""));
        }

        [RequiresEnvironmentFact(ServerVariable)]
        public async Task The_repair_refuses_what_is_not_its_to_change()
        {
            await using var f = await OwnershipFixture.CreateAsync(Server, OwnershipLayout.Fresh);
            var admin = new NpgsqlConnectionStringBuilder(Server).Username!;

            var stranger = f.ExtraDatabase("stranger");
            await f.ExecuteAsync(null, $"CREATE DATABASE {Q(stranger)} OWNER {Q(f.App.Username)}");
            await f.ExecuteAsync(stranger, "CREATE TABLE public.\"__EFMigrationsHistory\" (\"MigrationId\" varchar(150) PRIMARY KEY, \"ProductVersion\" varchar(32) NOT NULL)");
            var noBaseline = await Assert.ThrowsAsync<PostgresException>(() => f.RepairAsync(stranger, "app", f.App.Username));
            Assert.Contains("is not a ModularCA app database", noBaseline.MessageText);

            var notOwner = await Assert.ThrowsAsync<PostgresException>(() => f.RepairAsync(f.AppDatabase, "app", f.Audit.Username));
            Assert.Contains("does not own", notOwner.MessageText);

            await f.ExecuteAsync(null, $"GRANT {Q(f.AuditOwner)} TO {Q(f.Audit.Username)}");
            var couldDrop = await Assert.ThrowsAsync<PostgresException>(() => f.RepairAsync(f.AuditDatabase, "audit", f.Audit.Username));
            Assert.Contains("could drop the audit database", couldDrop.MessageText);
            await f.ExecuteAsync(null, $"REVOKE {Q(f.AuditOwner)} FROM {Q(f.Audit.Username)}");

            var superuser = await Assert.ThrowsAsync<PostgresException>(() => f.RepairAsync(f.AppDatabase, "app", admin));
            Assert.Contains("is not a plain login role", superuser.MessageText);

            var wrongKind = await Assert.ThrowsAsync<PostgresException>(() => f.RepairAsync(f.AppDatabase, "other", f.App.Username));
            Assert.Contains("kind must be app or audit", wrongKind.MessageText);
        }

        [RequiresEnvironmentTheory(ServerVariable)]
        [InlineData(OwnershipLayout.Migrated)]
        [InlineData(OwnershipLayout.Fresh)]
        public async Task The_audit_role_cannot_drop_its_database_or_step_outside_its_tables(OwnershipLayout layout)
        {
            await using var f = await OwnershipFixture.CreateAsync(Server, layout);

            await using (var maintenance = new NpgsqlConnection(f.RuntimeConnectionString(f.Audit, PostgresConnection.MaintenanceDatabase)))
            {
                await maintenance.OpenAsync();
                var drop = await Assert.ThrowsAsync<PostgresException>(() =>
                    new NpgsqlCommand($"DROP DATABASE {Q(f.AuditDatabase)}", maintenance).ExecuteNonQueryAsync());
                Assert.Equal("42501", drop.SqlState);
            }

            foreach (var sql in new[]
                     {
                         $"SET ROLE {Q(f.AuditOwner)}",
                         "CREATE EXTENSION IF NOT EXISTS citext",
                         "CREATE SCHEMA gate_probe",
                     })
            {
                await using var conn = new NpgsqlConnection(f.RuntimeConnectionString(f.Audit, f.AuditDatabase));
                await conn.OpenAsync();
                var ex = await Assert.ThrowsAsync<PostgresException>(() => new NpgsqlCommand(sql, conn).ExecuteNonQueryAsync());
                Assert.True(ex.SqlState == "42501", $"{sql}: {ex.SqlState} {ex.MessageText}");
            }
        }

        [RequiresEnvironmentFact(ServerVariable)]
        public async Task A_missing_database_is_left_to_bootstrap_and_never_created()
        {
            await using var f = await OwnershipFixture.CreateAsync(Server, OwnershipLayout.Fresh);
            var missing = f.ExtraDatabase("missing");
            var instance = f.Instance(missing, f.App.Username, f.App.Password);

            var exit = await SchemaStartupApi.EnforceAllAsync([("application", DatabaseKind.Application, instance)], true, new SchemaConfig { WaitSeconds = 1 });

            Assert.Null(exit);
            Assert.Equal(0, await f.CountAsync(null, $"SELECT count(*) FROM pg_catalog.pg_database WHERE datname = '{missing}'"));
        }

        [RequiresEnvironmentFact(ServerVariable)]
        public async Task An_empty_database_gets_no_table_from_the_runtime()
        {
            await using var f = await OwnershipFixture.CreateAsync(Server, OwnershipLayout.Fresh);
            var empty = f.ExtraDatabase("empty");
            await f.ExecuteAsync(null, $"CREATE DATABASE {Q(empty)} OWNER {Q(f.App.Username)} ENCODING 'UTF8' TEMPLATE template0");
            var instance = f.Instance(empty, f.App.Username, f.App.Password);

            var exit = await SchemaStartupApi.EnforceAllAsync([("application", DatabaseKind.Application, instance)], true, new SchemaConfig { WaitSeconds = 1 });

            Assert.Null(exit);
            Assert.Equal(0, await f.CountAsync(empty, "SELECT count(*) FROM pg_catalog.pg_class WHERE relnamespace = 'public'::regnamespace AND relkind IN ('r','p')"));
        }

        [RequiresEnvironmentFact(ServerVariable)]
        public async Task A_read_behind_the_migration_lock_reports_a_migration_in_progress_then_current_once_released()
        {
            await using var f = await OwnershipFixture.CreateAsync(Server, OwnershipLayout.Fresh);
            using var log = new CapturedSerilog();

            await using var holder = new NpgsqlConnection(f.AdminConnectionString(f.AppDatabase));
            await holder.OpenAsync();
            var tx = await holder.BeginTransactionAsync();
            await new NpgsqlCommand("LOCK TABLE public.\"__EFMigrationsHistory\" IN ACCESS EXCLUSIVE MODE", holder, tx).ExecuteNonQueryAsync();

            await using (var gate = GateReadContext(f.App))
            {
                var clock = Stopwatch.StartNew();
                var error = await Record.ExceptionAsync(() => SchemaVersionGate.ReadAsync(gate));
                Assert.NotNull(error);
                Assert.Equal(SchemaFailureKind.MigrationInProgress, SchemaFailure.Classify(error!));
                Assert.True(clock.Elapsed < TimeSpan.FromSeconds(10), $"took {clock.Elapsed}");
            }
            Assert.Equal(75, await SchemaStartupApi.EnforceAllAsync(
                [("application", DatabaseKind.Application, f.App)], false, new SchemaConfig { WaitSeconds = 1 }));
            Assert.True(Logged(log, "most likely by a migration in progress"), Dump(log));

            await tx.RollbackAsync();
            await using (var gate = GateReadContext(f.App))
            {
                var state = await SchemaVersionGate.ReadAsync(gate);
                Assert.Equal(SchemaVerdict.Current, SchemaVersionGate.Evaluate(state, appliesMigrations: false));
            }
        }

        [RequiresEnvironmentFact(ServerVariable)]
        public async Task A_migration_statement_longer_than_the_request_timeout_succeeds_on_the_migration_connection()
        {
            await using var f = await OwnershipFixture.CreateAsync(Server, OwnershipLayout.Fresh);
            using var log = new CapturedSerilog();
            await f.SeedProbeHistoryAsync(f.AppDatabase, SlowProbeContext.History, f.App.Username);
            SchemaStartupApi.UseContextFactory((_, cs, timeout) =>
                new SlowProbeContext(ProbeOptions.For<SlowProbeContext>(cs, timeout, SlowProbeContext.History)));
            var clock = Stopwatch.StartNew();

            var exit = await SchemaStartupApi.EnforceAllAsync([("application", DatabaseKind.Application, f.App)], true, new SchemaConfig());

            Assert.True(exit is null, Dump(log));
            Assert.True(clock.Elapsed >= TimeSpan.FromSeconds(35), $"took {clock.Elapsed}");
            Assert.Equal(2, await f.CountAsync(f.AppDatabase, $"SELECT count(*) FROM public.\"{SlowProbeContext.History}\""));
        }

        [RequiresEnvironmentFact(ServerVariable)]
        public async Task A_migration_with_a_statement_outside_a_transaction_is_not_rehearsed_and_the_start_stops_with_3_having_applied_nothing()
        {
            await using var f = await OwnershipFixture.CreateAsync(Server, OwnershipLayout.Fresh);
            using var log = new CapturedSerilog();
            await f.SeedProbeHistoryAsync(f.AppDatabase, NonTransactionalProbeContext.History, f.App.Username);
            SchemaStartupApi.UseContextFactory((_, cs, timeout) =>
                new NonTransactionalProbeContext(ProbeOptions.For<NonTransactionalProbeContext>(cs, timeout, NonTransactionalProbeContext.History)));

            var exit = await SchemaStartupApi.EnforceAllAsync([("application", DatabaseKind.Application, f.App)], true, new SchemaConfig { WaitSeconds = 1 });

            Assert.Equal(3, exit);
            Assert.True(log.Has(LogEventLevel.Fatal, "cannot rehearse it"), Dump(log));
            Assert.True(log.Has(LogEventLevel.Fatal, "defective"), Dump(log));
            Assert.Equal(1, await f.CountAsync(f.AppDatabase, $"SELECT count(*) FROM public.\"{NonTransactionalProbeContext.History}\""));
            Assert.Equal(0, await f.CountAsync(f.AppDatabase, "SELECT count(*) FROM pg_catalog.pg_class WHERE relname = 'gate_probe_nt'"));
        }

        [RequiresEnvironmentFact(ServerVariable)]
        public async Task A_migration_blocked_on_a_table_lock_exits_75_to_be_retried()
        {
            await using var f = await OwnershipFixture.CreateAsync(Server, OwnershipLayout.Fresh);
            using var log = new CapturedSerilog();
            await f.SeedProbeHistoryAsync(f.AppDatabase, AppProbeContext.History, f.App.Username);
            SchemaStartupApi.UseContextFactory((_, cs, timeout) =>
                new AppProbeContext(ProbeOptions.For<AppProbeContext>(cs, timeout, AppProbeContext.History)));

            await using var holder = new NpgsqlConnection(f.AdminConnectionString(f.AppDatabase));
            await holder.OpenAsync();
            await using var tx = await holder.BeginTransactionAsync();
            await new NpgsqlCommand("LOCK TABLE public.\"Users\" IN ACCESS EXCLUSIVE MODE", holder, tx).ExecuteNonQueryAsync();

            var exit = await SchemaStartupApi.EnforceAllAsync([("application", DatabaseKind.Application, f.App)], true,
                new SchemaConfig { WaitSeconds = 1, MigrationLockTimeoutSeconds = 1 });

            Assert.Equal(75, exit);
            Assert.True(log.Has(LogEventLevel.Fatal, "55P03"), Dump(log));
            await tx.RollbackAsync();
            Assert.Equal(0, await f.ColumnCountAsync(f.AppDatabase, "Users", "GateProbe"));
        }

        [RequiresEnvironmentFact(ServerVariable)]
        public async Task A_role_that_does_not_apply_migrations_waits_for_pending_ones_then_exits_75()
        {
            await using var f = await OwnershipFixture.CreateAsync(Server, OwnershipLayout.Fresh);
            using var log = new CapturedSerilog();
            await f.SeedProbeHistoryAsync(f.AppDatabase, AppProbeContext.History, f.App.Username);
            SchemaStartupApi.UseContextFactory((_, cs, timeout) =>
                new AppProbeContext(ProbeOptions.For<AppProbeContext>(cs, timeout, AppProbeContext.History)));

            var exit = await SchemaStartupApi.EnforceAllAsync([("application", DatabaseKind.Application, f.App)], false, new SchemaConfig { WaitSeconds = 1 });

            Assert.Equal(75, exit);
            Assert.True(Logged(log, "Only the control role applies migrations"), Dump(log));
            Assert.True(log.Has(LogEventLevel.Error, "Gave up after 1 s (Schema.WaitSeconds)"), Dump(log));
            Assert.Equal(0, await f.ColumnCountAsync(f.AppDatabase, "Users", "GateProbe"));
        }

        [RequiresEnvironmentFact(ServerVariable)]
        public async Task A_build_whose_model_differs_from_its_snapshot_stops_with_3_before_applying_anything()
        {
            await using var f = await OwnershipFixture.CreateAsync(Server, OwnershipLayout.Fresh);
            using var log = new CapturedSerilog();
            await f.SeedProbeHistoryAsync(f.AppDatabase, DriftProbeContext.History, f.App.Username);
            SchemaStartupApi.UseContextFactory((_, cs, timeout) =>
                new DriftProbeContext(ProbeOptions.For<DriftProbeContext>(cs, timeout, DriftProbeContext.History)));

            var exit = await SchemaStartupApi.EnforceAllAsync([("application", DatabaseKind.Application, f.App)], true, new SchemaConfig { WaitSeconds = 1 });

            Assert.Equal(3, exit);
            Assert.True(log.Has(LogEventLevel.Fatal, "differs from its latest migration"), Dump(log));
            Assert.Equal(1, await f.CountAsync(f.AppDatabase, $"SELECT count(*) FROM public.\"{DriftProbeContext.History}\""));
            Assert.Equal(0, await f.CountAsync(f.AppDatabase, "SELECT count(*) FROM pg_catalog.pg_class WHERE relname = 'gate_probe_drift'"));
        }

        [RequiresPostgresClientToolsTheory(ServerVariable)]
        [InlineData(OwnershipLayout.Migrated)]
        [InlineData(OwnershipLayout.Legacy)]
        public async Task A_backup_restores_as_the_runtime_roles(OwnershipLayout layout)
        {
            PostgresClientTools.EnsureOnPath();
            await using var f = await OwnershipFixture.CreateAsync(Server, layout, atBaseline: true);
            if (layout == OwnershipLayout.Legacy)
            {
                await f.ExecuteAsync(f.AppDatabase, PostgresUpgradeHarnessTests.Seed030Sql);
                await f.RepairAsync(DatabaseKind.Application);
                await f.RepairAsync(DatabaseKind.Audit);
            }
            else
            {
                await f.ExecuteAsRuntimeAsync(f.App, PostgresUpgradeHarnessTests.Seed030Sql);
            }

            foreach (var (kind, instance) in new[] { (DatabaseKind.Application, f.App), (DatabaseKind.Audit, f.Audit) })
            {
                var dump = Path.Combine(Path.GetTempPath(), $"modularca-harness-{Guid.NewGuid():N}.dump");
                var pgpass = BackupRestore.WritePgPassFile(instance.Host, instance.Port, instance.Database, instance.Username, instance.Password);
                try
                {
                    var (dumpExit, dumpErr) = await PgDumpAsync(instance, dump, pgpass);
                    Assert.True(dumpExit == 0, $"pg_dump exited {dumpExit}: {dumpErr}");
                    if (kind == DatabaseKind.Application)
                        await f.ExecuteAsRuntimeAsync(instance, "DELETE FROM \"CaGroupMembers\"");

                    var (exit, stderr) = await RestoreDumpFileAsync(pgpass, instance, dump, ensureCitext: kind == DatabaseKind.Application);

                    Assert.True(exit == 0, $"{kind} restore exited {exit}: {stderr}");
                    var report = await f.OwnershipAsync(kind);
                    Assert.True(report.IsSound, SchemaOwnership.RefusalMessage(report, null));
                    if (kind == DatabaseKind.Application)
                        Assert.Equal(2, await f.CountAsync(f.AppDatabase, "SELECT count(*) FROM \"CaGroupMembers\""));
                }
                finally
                {
                    foreach (var file in new[] { dump, dump + ".list", pgpass })
                        try { File.Delete(file); } catch (IOException) { }
                }
            }
            Assert.Null(await SchemaStartupApi.EnforceAllAsync(f.Targets(), true, new SchemaConfig { WaitSeconds = 1 }));
        }

        [RequiresEnvironmentFact(ServerVariable)]
        public async Task A_reset_whose_drop_fails_leaves_the_old_database_and_its_rows_in_place()
        {
            await using var f = await OwnershipFixture.CreateAsync(Server, OwnershipLayout.Fresh, atBaseline: true);
            await f.ExecuteAsRuntimeAsync(f.App, PostgresUpgradeHarnessTests.Seed030Sql);
            await f.ExecuteAsync(null, $"ALTER DATABASE {Q(f.AppDatabase)} IS_TEMPLATE true");
            try
            {
                await Assert.ThrowsAsync<PostgresException>(() =>
                    PostgresRoleLayout.ProvisionAsync(Server, f.Names, new ProvisioningMode(ResetApp: true, WipeAudit: false)));

                Assert.Equal(1, await f.CountAsync(null, $"SELECT count(*) FROM pg_catalog.pg_database WHERE datname = '{f.AppDatabase}'"));
                Assert.Equal(2, await f.CountAsync(f.AppDatabase, "SELECT count(*) FROM \"Tenants\""));
                await f.ExecuteAsRuntimeAsync(f.App, "SELECT 1");
                await f.ExecuteAsRuntimeAsync(f.Audit, "SELECT 1");
            }
            finally
            {
                await f.ExecuteAsync(null, $"ALTER DATABASE {Q(f.AppDatabase)} IS_TEMPLATE false");
            }
        }

        [RequiresEnvironmentFact(ServerVariable)]
        public async Task A_migration_blocked_on_a_table_lock_is_retried_in_process_and_applied_once_the_lock_is_released()
        {
            await using var f = await OwnershipFixture.CreateAsync(Server, OwnershipLayout.Fresh);
            using var log = new CapturedSerilog();
            await f.SeedProbeHistoryAsync(f.AppDatabase, AppProbeContext.History, f.App.Username);
            SchemaStartupApi.UseContextFactory((_, cs, timeout) =>
                new AppProbeContext(ProbeOptions.For<AppProbeContext>(cs, timeout, AppProbeContext.History)));

            await using var holder = new NpgsqlConnection(f.AdminConnectionString(f.AppDatabase));
            await holder.OpenAsync();
            var tx = await holder.BeginTransactionAsync();
            await new NpgsqlCommand("LOCK TABLE public.\"Users\" IN ACCESS EXCLUSIVE MODE", holder, tx).ExecuteNonQueryAsync();
            var release = Task.Run(async () =>
            {
                await Task.Delay(TimeSpan.FromSeconds(3));
                await tx.RollbackAsync();
            });

            var exit = await SchemaStartupApi.EnforceAllAsync([("application", DatabaseKind.Application, f.App)], true,
                new SchemaConfig { WaitSeconds = 60, MigrationLockTimeoutSeconds = 1 });
            await release;

            Assert.True(exit is null, Dump(log));
            Assert.True(log.Has(LogEventLevel.Warning, "55P03"), Dump(log));
            Assert.True(Logged(log, "retrying in"), Dump(log));
            Assert.Equal(1, await f.ColumnCountAsync(f.AppDatabase, "Users", "GateProbe"));
        }

        [RequiresEnvironmentFact(ServerVariable)]
        public async Task A_preserved_audit_database_whose_schema_public_the_superuser_still_owns_is_handed_to_its_owner_whatever_the_version()
        {
            await using var f = await OwnershipFixture.CreateAsync(Server, OwnershipLayout.Fresh);
            var admin = new NpgsqlConnectionStringBuilder(Server).Username!;
            await f.ExecuteAsync(f.AuditDatabase, $"ALTER SCHEMA public OWNER TO {Q(admin)}; GRANT CREATE ON SCHEMA public TO PUBLIC;");

            await PostgresRoleLayout.ProvisionAsync(Server, f.Names, new ProvisioningMode(ResetApp: true, WipeAudit: false));

            Assert.Equal(1, await f.CountAsync(f.AuditDatabase,
                $"SELECT count(*) FROM pg_catalog.pg_namespace WHERE nspname = 'public' AND nspowner = to_regrole('{Q(f.AuditOwner)}')"));
            Assert.Equal(0, await f.CountAsync(f.AuditDatabase,
                "SELECT count(*) FROM pg_catalog.pg_namespace n, aclexplode(n.nspacl) a WHERE n.nspname = 'public' AND a.grantee = 0 AND a.privilege_type = 'CREATE'"));
            Assert.Equal(0, await f.CountAsync(f.AppDatabase,
                "SELECT count(*) FROM pg_catalog.pg_namespace n, aclexplode(coalesce(n.nspacl, acldefault('n', n.nspowner))) a "
                + "WHERE n.nspname = 'public' AND a.grantee = 0 AND a.privilege_type = 'CREATE'"));
        }

        [RequiresEnvironmentFact(ServerVariable)]
        public async Task A_sqlroot_that_is_not_a_superuser_or_whose_password_is_wrong_is_refused_cleanly_before_any_read_of_the_audit_database()
        {
            await using var f = await OwnershipFixture.CreateAsync(Server, OwnershipLayout.Fresh);
            var role = f.Names.AppRole + "_nosu";
            var password = PostgresRoleLayout.GeneratePassword();
            await f.ExecuteAsync(null, $"CREATE ROLE {Q(role)} WITH LOGIN CREATEDB CREATEROLE PASSWORD '{password}'");
            try
            {
                var asRole = new NpgsqlConnectionStringBuilder(Server) { Username = role, Password = password }.ConnectionString;
                var refused = await Assert.ThrowsAsync<PostgresLayoutRefusedException>(() =>
                    PostgresRoleLayout.ProvisionAsync(asRole, f.Names with { AdminRole = role }, new ProvisioningMode(ResetApp: true, WipeAudit: false)));
                Assert.Contains($"SqlRoot '{role}' is not a PostgreSQL superuser", refused.Message);

                var wrong = new NpgsqlConnectionStringBuilder(Server) { Username = role, Password = password + "x", Pooling = false }.ConnectionString;
                var login = await Record.ExceptionAsync(async () =>
                {
                    await using var probe = new NpgsqlConnection(wrong);
                    await probe.OpenAsync();
                });
                if (login is PostgresException { SqlState: "28P01" })
                {
                    var badPassword = await Assert.ThrowsAsync<PostgresLayoutRefusedException>(() =>
                        PostgresRoleLayout.ProbeAsync(wrong, f.Names with { AdminRole = role }));
                    Assert.Contains("rejected the password", badPassword.Message);
                }
                await f.ExecuteAsRuntimeAsync(f.App, "SELECT 1");
            }
            finally
            {
                NpgsqlConnection.ClearAllPools();
                await f.ExecuteAsync(null, $"DROP ROLE IF EXISTS {Q(role)}");
            }
        }

        [RequiresEnvironmentFact(ServerVariable)]
        public async Task A_preserved_audit_database_the_takeover_cannot_complete_is_refused_before_any_ddl()
        {
            await using var f = await OwnershipFixture.CreateAsync(Server, OwnershipLayout.Fresh);
            var stranger = f.Names.AuditRole + "_stray";
            await f.ExecuteAsync(null, $"CREATE ROLE {Q(stranger)} NOLOGIN");
            try
            {
                await f.ExecuteAsync(f.AuditDatabase, $"CREATE TABLE public.gate_stray (id int); ALTER TABLE public.gate_stray OWNER TO {Q(stranger)};");
                var stray = await Assert.ThrowsAsync<PostgresLayoutRefusedException>(() =>
                    PostgresRoleLayout.ProvisionAsync(Server, f.Names, new ProvisioningMode(ResetApp: true, WipeAudit: false)));
                Assert.Contains("gate_stray", stray.Message);
                Assert.Contains(stranger, stray.Message);
                await f.ExecuteAsRuntimeAsync(f.App, "SELECT 1");
                await f.ExecuteAsync(f.AuditDatabase, "DROP TABLE public.gate_stray");

                await f.ExecuteAsync(f.AuditDatabase,
                    "UPDATE public.\"__EFMigrationsHistory\" SET \"MigrationId\" = '20260919181509_NotTheBaseline' "
                    + $"WHERE \"MigrationId\" = '{PostgresUpgradeHarnessTests.AuditBaseline}'");
                var noBaseline = await Assert.ThrowsAsync<PostgresLayoutRefusedException>(() =>
                    PostgresRoleLayout.ProvisionAsync(Server, f.Names, new ProvisioningMode(ResetApp: true, WipeAudit: false)));
                Assert.Contains(PostgresUpgradeHarnessTests.AuditBaseline, noBaseline.Message);
                await f.ExecuteAsRuntimeAsync(f.App, "SELECT 1");
            }
            finally
            {
                await f.ExecuteAsync(null, $"DROP ROLE IF EXISTS {Q(stranger)}");
            }
        }

        [RequiresEnvironmentFact(ServerVariable)]
        public async Task A_leftover_member_of_any_runtime_or_owner_role_is_warned_with_the_exact_revoke()
        {
            await using var f = await OwnershipFixture.CreateAsync(Server, OwnershipLayout.Fresh);
            var leftover = f.Names.AppRole + "_migrate";
            await f.ExecuteAsync(null, $"CREATE ROLE {Q(leftover)} LOGIN CREATEROLE; "
                + $"GRANT {Q(f.App.Username)}, {Q(f.Audit.Username)}, {Q(f.AuditOwner)} TO {Q(leftover)};");
            try
            {
                var app = SchemaOwnership.Warnings(await f.OwnershipAsync(DatabaseKind.Application));
                var audit = SchemaOwnership.Warnings(await f.OwnershipAsync(DatabaseKind.Audit));

                Assert.Contains(app, w => w.Contains($"REVOKE {Q(f.App.Username)} FROM {Q(leftover)};"));
                Assert.Contains(audit, w => w.Contains($"REVOKE {Q(f.Audit.Username)} FROM {Q(leftover)};"));
                Assert.Contains(audit, w => w.Contains($"REVOKE {Q(f.AuditOwner)} FROM {Q(leftover)};") && w.Contains("could drop it"));
                Assert.All(app.Concat(audit), w => Assert.Contains("NOLOGIN", w));
            }
            finally
            {
                await f.ExecuteAsync(null, $"DROP ROLE IF EXISTS {Q(leftover)}");
            }
        }

        /// <summary>A context on the gate-read connection the startup check uses, as <paramref name="instance"/>'s role.</summary>
        private static ModularCADbContext GateReadContext(DbInstance instance) =>
            new(new DbContextOptionsBuilder<ModularCADbContext>().UseNpgsql(SchemaStartupApi.GateReadConnectionString(instance)).Options);

        /// <summary>Dumps <paramref name="instance"/> in custom format with <c>pg_dump</c>, as its own role.</summary>
        private static async Task<(int Exit, string Stderr)> PgDumpAsync(DbInstance instance, string file, string pgpass)
        {
            var start = new ProcessStartInfo("pg_dump")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            foreach (var arg in new[] { "--host", instance.Host, "--port", instance.Port.ToString(), "--username", instance.Username,
                         "--no-password", "--format=custom", "--file", file, instance.Database })
                start.ArgumentList.Add(arg);
            start.Environment["PGPASSFILE"] = pgpass;
            using var process = Process.Start(start)!;
            var stderr = process.StandardError.ReadToEndAsync();
            await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();
            return (process.ExitCode, await stderr);
        }

        /// <summary>Calls the private <c>BackupRestore.RestoreDumpFileAsync</c>, the restore the product runs.</summary>
        private static async Task<(int ExitCode, string Stderr)> RestoreDumpFileAsync(string pgpass, DbInstance instance, string dump, bool ensureCitext)
        {
            var method = typeof(BackupRestore).GetMethod("RestoreDumpFileAsync", BindingFlags.NonPublic | BindingFlags.Static)!;
            return await (Task<(int, string)>)method.Invoke(null, [pgpass, instance, dump, ensureCitext, 600_000])!;
        }

        /// <summary>Whether any captured event, at any level, contains <paramref name="text"/>.</summary>
        private static bool Logged(CapturedSerilog log, string text) =>
            log.Events.Any(e => e.Text.Contains(text, StringComparison.Ordinal));

        /// <summary>Every captured event, for an assertion message.</summary>
        private static string Dump(CapturedSerilog log) =>
            string.Join(Environment.NewLine, log.Events.Select(e => $"{e.Level}: {e.Text}"));

        /// <summary>Quotes a PostgreSQL identifier.</summary>
        private static string Q(string identifier) => PostgresConnection.QuoteIdentifier(identifier);
    }

    /// <summary>The three ways a PostgreSQL install can have been laid out.</summary>
    public enum OwnershipLayout
    {
        /// <summary>ModularCA.Migrate's <see cref="DestinationBuilder"/>: production and staging.</summary>
        Migrated,

        /// <summary>0.4.0 bootstrap: provisioning, schema as the runtime roles, ownership check.</summary>
        Fresh,

        /// <summary>0.3.1 wizard or CLI bootstrap: baselines as the superuser, the old grants.</summary>
        Legacy,
    }

    /// <summary>
    /// Throwaway roles and databases with a random suffix in one <see cref="OwnershipLayout"/>, dropped with
    /// every role's grants on dispose. Administrative statements run as the superuser in
    /// <c>MODULARCA_TEST_PG</c>.
    /// </summary>
    internal sealed class OwnershipFixture : IAsyncDisposable
    {
        private static readonly Regex AdoptedCount = new(@"modularca: (\d+) object\(s\)", RegexOptions.CultureInvariant);

        private readonly string _server;
        private readonly List<string> _extraDatabases = [];

        /// <summary>Picks the names; creates nothing.</summary>
        private OwnershipFixture(string server)
        {
            _server = server;
            var suffix = Guid.NewGuid().ToString("N")[..10];
            var admin = new NpgsqlConnectionStringBuilder(server).Username ?? "postgres";
            Names = new PostgresLayoutNames(admin, $"mcat_app_{suffix}", $"mcat_audit_{suffix}", $"mcat-app-{suffix}", $"mcat-audit-{suffix}");
            App = Instance(Names.AppDatabase, Names.AppRole, "");
            Audit = Instance(Names.AuditDatabase, Names.AuditRole, "");
        }

        /// <summary>The layout names.</summary>
        public PostgresLayoutNames Names { get; }

        /// <summary>The application database as its runtime role.</summary>
        public DbInstance App { get; private set; }

        /// <summary>The audit database as its runtime role.</summary>
        public DbInstance Audit { get; private set; }

        /// <summary>The application database's name.</summary>
        public string AppDatabase => Names.AppDatabase;

        /// <summary>The audit database's name.</summary>
        public string AuditDatabase => Names.AuditDatabase;

        /// <summary>The NOLOGIN owner of the audit database in the migrated and fresh layouts.</summary>
        public string AuditOwner => Names.AuditOwnerRole;

        /// <summary>
        /// Builds the fixture in <paramref name="layout"/>; drops what it made when that fails. With
        /// <paramref name="atBaseline"/> both databases stop at the frozen baselines, as the 0.3.x
        /// schema a live upgrade starts from (the legacy layout always does).
        /// </summary>
        public static async Task<OwnershipFixture> CreateAsync(string server, OwnershipLayout layout, bool atBaseline = false)
        {
            var f = new OwnershipFixture(server);
            try
            {
                switch (layout)
                {
                    case OwnershipLayout.Migrated: await f.BuildMigratedAsync(atBaseline); break;
                    case OwnershipLayout.Fresh: await f.BuildFreshAsync(atBaseline); break;
                    default: await f.BuildLegacyAsync(); break;
                }
                return f;
            }
            catch
            {
                await f.DisposeAsync();
                throw;
            }
        }

        /// <summary>Both databases as startup-check targets, the application database first.</summary>
        public IReadOnlyList<(string Name, DatabaseKind Kind, DbInstance Instance)> Targets() =>
        [
            ("application", DatabaseKind.Application, App),
            ("audit", DatabaseKind.Audit, Audit),
        ];

        /// <summary>A further database name with this fixture's suffix, dropped on dispose.</summary>
        public string ExtraDatabase(string label)
        {
            var name = $"{Names.AppDatabase}-{label}";
            _extraDatabases.Add(name);
            return name;
        }

        /// <summary>A <c>db.yaml</c> instance on this server.</summary>
        public DbInstance Instance(string database, string role, string password)
        {
            var b = new NpgsqlConnectionStringBuilder(_server);
            return new DbInstance
            {
                Host = b.Host ?? "localhost", Port = b.Port, Database = database, Username = role, Password = password,
                SslMode = b.SslMode.ToString(),
            };
        }

        /// <summary>The superuser's unpooled connection string to <paramref name="database"/>, or to the server's own database when null.</summary>
        public string AdminConnectionString(string? database)
        {
            var b = new NpgsqlConnectionStringBuilder(_server) { Pooling = false };
            if (database is not null)
                b.Database = database;
            return b.ConnectionString;
        }

        /// <summary><paramref name="instance"/>'s role's unpooled connection string to <paramref name="database"/>.</summary>
        public string RuntimeConnectionString(DbInstance instance, string database) =>
            new NpgsqlConnectionStringBuilder(PostgresConnection.Build(instance)) { Database = database, Pooling = false }.ConnectionString;

        /// <summary>Runs <paramref name="sql"/> as the superuser.</summary>
        public async Task ExecuteAsync(string? database, string sql)
        {
            await using var conn = new NpgsqlConnection(AdminConnectionString(database));
            await conn.OpenAsync();
            await new NpgsqlCommand(sql, conn).ExecuteNonQueryAsync();
        }

        /// <summary>Runs <paramref name="sql"/> as <paramref name="instance"/>'s role in its database.</summary>
        public async Task ExecuteAsRuntimeAsync(DbInstance instance, string sql)
        {
            await using var conn = new NpgsqlConnection(RuntimeConnectionString(instance, instance.Database));
            await conn.OpenAsync();
            await new NpgsqlCommand(sql, conn).ExecuteNonQueryAsync();
        }

        /// <summary>The first column of the first row of <paramref name="sql"/>, as the superuser.</summary>
        public async Task<long> CountAsync(string? database, string sql)
        {
            await using var conn = new NpgsqlConnection(AdminConnectionString(database));
            await conn.OpenAsync();
            return Convert.ToInt64(await new NpgsqlCommand(sql, conn).ExecuteScalarAsync());
        }

        /// <summary>Whether <paramref name="table"/> in <paramref name="database"/> has <paramref name="column"/> (1) or not (0).</summary>
        public Task<long> ColumnCountAsync(string database, string table, string column) =>
            CountAsync(database, "SELECT count(*) FROM information_schema.columns WHERE table_schema = 'public' "
                + $"AND table_name = '{table}' AND column_name = '{column}'");

        /// <summary>The ownership report for one database, read as its runtime role.</summary>
        public async Task<OwnershipReport> OwnershipAsync(DatabaseKind kind)
        {
            var instance = kind == DatabaseKind.Application ? App : Audit;
            await using var conn = new NpgsqlConnection(RuntimeConnectionString(instance, instance.Database));
            return await SchemaOwnership.ProbeAsync(conn, kind);
        }

        /// <summary>
        /// Creates a probe context's history table as the superuser, records its base migration,
        /// and gives the table to <paramref name="owner"/>, so the probe's next migration is the
        /// only one pending.
        /// </summary>
        public async Task SeedProbeHistoryAsync(string database, string historyTable, string owner)
        {
            var h = PostgresConnection.QuoteIdentifier(historyTable);
            await ExecuteAsync(database,
                $"CREATE TABLE public.{h} (\"MigrationId\" character varying(150) NOT NULL PRIMARY KEY, \"ProductVersion\" character varying(32) NOT NULL); "
                + $"INSERT INTO public.{h} VALUES ('{ProbeBaseMigration.Id}', '10.0.12'); "
                + $"ALTER TABLE public.{h} OWNER TO {PostgresConnection.QuoteIdentifier(owner)};");
        }

        /// <summary>Runs the embedded repair block on this fixture's database of <paramref name="kind"/>; returns how many objects it moved.</summary>
        public Task<int> RepairAsync(DatabaseKind kind) => kind == DatabaseKind.Application
            ? RepairAsync(AppDatabase, "app", App.Username)
            : RepairAsync(AuditDatabase, "audit", Audit.Username);

        /// <summary>
        /// Runs the embedded repair block as the superuser, with <c>modularca.kind</c> and
        /// <c>modularca.target</c> bound as parameters, the way provisioning runs it. Returns the
        /// object count from its NOTICE.
        /// </summary>
        public async Task<int> RepairAsync(string database, string kind, string target)
        {
            var notices = new List<string>();
            await using var conn = new NpgsqlConnection(AdminConnectionString(database));
            conn.Notice += (_, e) => notices.Add(e.Notice.MessageText);
            await conn.OpenAsync();
            await using var cmd = new NpgsqlCommand(
                "SET lock_timeout = '10s'; SELECT set_config('modularca.kind', @kind, false), set_config('modularca.target', @target, false); "
                + SchemaOwnership.RepairBlock(), conn);
            cmd.Parameters.AddWithValue("kind", kind);
            cmd.Parameters.AddWithValue("target", target);
            await cmd.ExecuteNonQueryAsync();
            var match = notices.Select(n => AdoptedCount.Match(n)).FirstOrDefault(m => m.Success);
            Assert.True(match is not null, "The repair printed no count: " + string.Join(" | ", notices));
            return int.Parse(match!.Groups[1].Value);
        }

        /// <summary>The migration tool's options for this fixture's names, in the migrated layout.</summary>
        public MigrationOptions? MigrateOptions { get; private set; }

        /// <summary>The migration tool's builder, in the migrated layout.</summary>
        public DestinationBuilder? Builder { get; private set; }

        /// <summary>
        /// The layout ModularCA.Migrate builds, through <see cref="DestinationBuilder.BuildAsync"/>
        /// itself, then, unless <paramref name="atBaseline"/>, its
        /// <see cref="DestinationBuilder.ApplyUpgradeMigrationsAsync"/> as after a copy.
        /// </summary>
        private async Task BuildMigratedAsync(bool atBaseline)
        {
            var b = new NpgsqlConnectionStringBuilder(_server);
            MigrateOptions = new MigrationOptions
            {
                SourceHost = "unused", SourcePort = 3306, SourceUser = "unused", SourcePassword = "unused",
                SourceAppDatabase = "unused", SourceAuditDatabase = "unused",
                TargetHost = b.Host ?? "localhost", TargetPort = b.Port, TargetAdminUser = b.Username ?? "postgres",
                TargetAdminPassword = b.Password ?? "", TargetSslMode = b.SslMode.ToString(),
                TargetAppDatabase = Names.AppDatabase, TargetAuditDatabase = Names.AuditDatabase,
                TargetAppRole = Names.AppRole, TargetAuditRole = Names.AuditRole, TargetAuditOwnerRole = Names.AuditOwnerRole,
            };
            Builder = new DestinationBuilder(MigrateOptions, _ => { });
            await Builder.BuildAsync(CancellationToken.None);
            App = Instance(Names.AppDatabase, Names.AppRole, Builder.AppPassword);
            Audit = Instance(Names.AuditDatabase, Names.AuditRole, Builder.AuditPassword);
            if (!atBaseline)
                await Builder.ApplyUpgradeMigrationsAsync(CancellationToken.None);
        }

        /// <summary>
        /// The layout 0.4.0 bootstrap builds: provisioning, the schemas as the runtime roles, the
        /// ownership check. With <paramref name="atBaseline"/> the runtime roles apply only the
        /// frozen baselines, through the gate on migration connections.
        /// </summary>
        private async Task BuildFreshAsync(bool atBaseline)
        {
            var (appPassword, auditPassword) = await PostgresRoleLayout.ProvisionAsync(
                _server, Names, new ProvisioningMode(ResetApp: true, WipeAudit: false));
            App = Instance(Names.AppDatabase, Names.AppRole, appPassword);
            Audit = Instance(Names.AuditDatabase, Names.AuditRole, auditPassword);
            var databases = new ProvisionedDatabases(App, Audit);
            if (atBaseline)
            {
                await using (var app = MigrationConnection.CreateContext(DatabaseKind.Application, App, new SchemaConfig()))
                    await SchemaStages.ApplyBaselineAsync(app, PostgresRoleLayout.AppBaselineMigration, "application", CancellationToken.None);
                await using (var audit = MigrationConnection.CreateContext(DatabaseKind.Audit, Audit, new SchemaConfig()))
                    await SchemaStages.ApplyBaselineAsync(audit, PostgresRoleLayout.AuditBaselineMigration, "audit", CancellationToken.None);
            }
            else
            {
                await BootstrapDatabaseSetup.ApplySchemasAsync(databases, null);
            }
            await BootstrapDatabaseSetup.VerifyOwnershipAsync(databases, null);
        }

        /// <summary>
        /// The layout the 0.3.1 wizard and CLI bootstrap left: both baselines applied as the
        /// superuser, the application database then handed to the app role, and the audit role
        /// given CONNECT, CREATE on schema public and DML on every table instead of ownership.
        /// </summary>
        private async Task BuildLegacyAsync()
        {
            var appPassword = PostgresRoleLayout.GeneratePassword();
            var auditPassword = PostgresRoleLayout.GeneratePassword();
            var da = PostgresConnection.QuoteIdentifier(AppDatabase);
            var du = PostgresConnection.QuoteIdentifier(AuditDatabase);
            var a = PostgresConnection.QuoteIdentifier(Names.AppRole);
            var u = PostgresConnection.QuoteIdentifier(Names.AuditRole);

            await ExecuteAsync(null, $"CREATE ROLE {a} WITH LOGIN PASSWORD '{appPassword}'");
            await ExecuteAsync(null, $"CREATE ROLE {u} WITH LOGIN PASSWORD '{auditPassword}'");
            await ExecuteAsync(null, $"CREATE DATABASE {da} ENCODING 'UTF8' TEMPLATE template0");
            await ExecuteAsync(null, $"CREATE DATABASE {du} ENCODING 'UTF8' TEMPLATE template0");

            await using (var app = new ModularCADbContext(new DbContextOptionsBuilder<ModularCADbContext>().UseNpgsql(AdminConnectionString(AppDatabase)).Options))
                await app.GetService<IMigrator>().MigrateAsync(PostgresUpgradeHarnessTests.AppBaseline);
            await using (var audit = new AuditDbContext(new DbContextOptionsBuilder<AuditDbContext>().UseNpgsql(AdminConnectionString(AuditDatabase)).Options))
                await audit.GetService<IMigrator>().MigrateAsync(PostgresUpgradeHarnessTests.AuditBaseline);

            await ExecuteAsync(null, $"ALTER DATABASE {da} OWNER TO {a}");
            await ExecuteAsync(AuditDatabase,
                $"GRANT CONNECT ON DATABASE {du} TO {u}; "
                + $"GRANT USAGE, CREATE ON SCHEMA public TO {u}; "
                + $"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {u}; "
                + $"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {u}; "
                + $"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {u}; "
                + $"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {u};");

            App = Instance(AppDatabase, Names.AppRole, appPassword);
            Audit = Instance(AuditDatabase, Names.AuditRole, auditPassword);
        }

        /// <summary>Drops every database this fixture made, then each role's grants and the role itself.</summary>
        public async ValueTask DisposeAsync()
        {
            NpgsqlConnection.ClearAllPools();
            await using var conn = new NpgsqlConnection(AdminConnectionString(null));
            await conn.OpenAsync();
            foreach (var database in new[] { AppDatabase, AuditDatabase }.Concat(_extraDatabases))
            {
                var q = PostgresConnection.QuoteIdentifier(database);
                await TryAsync(conn, $"ALTER DATABASE {q} IS_TEMPLATE false");
                await TryAsync(conn, $"DROP DATABASE IF EXISTS {q} WITH (FORCE)");
            }
            foreach (var role in new[] { Names.AppRole, Names.AuditRole, Names.AuditOwnerRole })
            {
                var q = PostgresConnection.QuoteIdentifier(role);
                await TryAsync(conn, $"DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN EXECUTE 'DROP OWNED BY {q.Replace("'", "''")}'; END IF; END $$");
                await TryAsync(conn, $"DROP ROLE IF EXISTS {q}");
            }
        }

        /// <summary>Runs <paramref name="sql"/> and ignores a server error: clean-up must reach every step.</summary>
        private static async Task TryAsync(NpgsqlConnection conn, string sql)
        {
            try
            {
                await new NpgsqlCommand(sql, conn).ExecuteNonQueryAsync();
            }
            catch (PostgresException)
            {
            }
        }
    }

    /// <summary>Probe context options: Npgsql on <paramref name="connectionString"/> with its own history table.</summary>
    internal static class ProbeOptions
    {
        /// <summary>The options for probe context <typeparamref name="T"/>.</summary>
        public static DbContextOptions<T> For<T>(string connectionString, int commandTimeoutSeconds, string historyTable) where T : DbContext =>
            new DbContextOptionsBuilder<T>()
                .UseNpgsql(connectionString, o => o.CommandTimeout(commandTimeoutSeconds).MigrationsHistoryTable(historyTable))
                .Options;
    }
}

namespace ModularCA.Tests.Database.ProbeMigrations
{
    /// <summary>The base migration every probe context's seeded history records as applied.</summary>
    public static class ProbeBaseMigration
    {
        /// <summary>Its id, shared by every probe context.</summary>
        public const string Id = "20990201000001_ProbeBase";
    }

    /// <summary>Alters the application database's <c>Users</c> table, which every stage of the schema has, and indexes the new column.</summary>
    public sealed class AppProbeContext(DbContextOptions<AppProbeContext> options) : DbContext(options)
    {
        /// <summary>Its history table.</summary>
        public const string History = "__GateProbeHistory";
    }

    /// <summary>Alters the audit database's <c>AuditLogs</c> table and indexes the new column.</summary>
    public sealed class AuditProbeContext(DbContextOptions<AuditProbeContext> options) : DbContext(options)
    {
        /// <summary>Its history table.</summary>
        public const string History = "__GateProbeHistory";
    }

    /// <summary>Runs one statement longer than the request connections' 30 s timeout.</summary>
    public sealed class SlowProbeContext(DbContextOptions<SlowProbeContext> options) : DbContext(options)
    {
        /// <summary>Its history table.</summary>
        public const string History = "__GateProbeSlowHistory";
    }

    /// <summary>Runs a statement outside a transaction, then one that fails.</summary>
    public sealed class NonTransactionalProbeContext(DbContextOptions<NonTransactionalProbeContext> options) : DbContext(options)
    {
        /// <summary>Its history table.</summary>
        public const string History = "__GateProbeNtHistory";
    }

    /// <summary>Has an entity its migrations never create, so its model differs from its (absent) snapshot.</summary>
    public sealed class DriftProbeContext(DbContextOptions<DriftProbeContext> options) : DbContext(options)
    {
        /// <summary>Its history table.</summary>
        public const string History = "__GateProbeDriftHistory";

        /// <summary>The entity no migration creates.</summary>
        public DbSet<DriftProbeRow> Rows => Set<DriftProbeRow>();

        /// <summary>Maps <see cref="DriftProbeRow"/> to <c>gate_probe_rows</c>.</summary>
        protected override void OnModelCreating(ModelBuilder modelBuilder) =>
            modelBuilder.Entity<DriftProbeRow>().ToTable("gate_probe_rows");
    }

    /// <summary>The <see cref="DriftProbeContext"/> entity.</summary>
    public sealed class DriftProbeRow
    {
        /// <summary>Key.</summary>
        public int Id { get; set; }
    }

    /// <summary>No-op base, recorded by the seeded history.</summary>
    [DbContext(typeof(AppProbeContext))]
    [Migration(ProbeBaseMigration.Id)]
    public sealed class AppProbeBase : Migration
    {
        /// <summary>Does nothing.</summary>
        protected override void Up(MigrationBuilder migrationBuilder) => migrationBuilder.Sql("SELECT 1");
    }

    /// <summary>Adds and indexes <c>Users.GateProbe</c>, which only the table's owner may do.</summary>
    [DbContext(typeof(AppProbeContext))]
    [Migration("20990201000002_ProbeAlter")]
    public sealed class AppProbeAlter : Migration
    {
        /// <summary>ALTER TABLE and CREATE INDEX on an existing table.</summary>
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("ALTER TABLE public.\"Users\" ADD COLUMN \"GateProbe\" integer");
            migrationBuilder.Sql("CREATE INDEX \"IX_Users_GateProbe\" ON public.\"Users\" (\"GateProbe\")");
        }
    }

    /// <summary>No-op base, recorded by the seeded history.</summary>
    [DbContext(typeof(AuditProbeContext))]
    [Migration(ProbeBaseMigration.Id)]
    public sealed class AuditProbeBase : Migration
    {
        /// <summary>Does nothing.</summary>
        protected override void Up(MigrationBuilder migrationBuilder) => migrationBuilder.Sql("SELECT 1");
    }

    /// <summary>Adds and indexes <c>AuditLogs.GateProbe</c>, which only the table's owner may do.</summary>
    [DbContext(typeof(AuditProbeContext))]
    [Migration("20990201000002_ProbeAlter")]
    public sealed class AuditProbeAlter : Migration
    {
        /// <summary>ALTER TABLE and CREATE INDEX on an existing table.</summary>
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("ALTER TABLE public.\"AuditLogs\" ADD COLUMN \"GateProbe\" integer");
            migrationBuilder.Sql("CREATE INDEX \"IX_AuditLogs_GateProbe\" ON public.\"AuditLogs\" (\"GateProbe\")");
        }
    }

    /// <summary>No-op base, recorded by the seeded history.</summary>
    [DbContext(typeof(SlowProbeContext))]
    [Migration(ProbeBaseMigration.Id)]
    public sealed class SlowProbeBase : Migration
    {
        /// <summary>Does nothing.</summary>
        protected override void Up(MigrationBuilder migrationBuilder) => migrationBuilder.Sql("SELECT 1");
    }

    /// <summary>Sleeps 35 s, past the 30 s the request connections allow.</summary>
    [DbContext(typeof(SlowProbeContext))]
    [Migration("20990201000002_ProbeSleep")]
    public sealed class SlowProbeSleep : Migration
    {
        /// <summary>SELECT pg_sleep(35).</summary>
        protected override void Up(MigrationBuilder migrationBuilder) => migrationBuilder.Sql("SELECT pg_sleep(35)");
    }

    /// <summary>No-op base, recorded by the seeded history.</summary>
    [DbContext(typeof(NonTransactionalProbeContext))]
    [Migration(ProbeBaseMigration.Id)]
    public sealed class NonTransactionalProbeBase : Migration
    {
        /// <summary>Does nothing.</summary>
        protected override void Up(MigrationBuilder migrationBuilder) => migrationBuilder.Sql("SELECT 1");
    }

    /// <summary>Creates a table outside a transaction, then divides by zero.</summary>
    [DbContext(typeof(NonTransactionalProbeContext))]
    [Migration("20990201000002_ProbeNonTransactional")]
    public sealed class NonTransactionalProbeFail : Migration
    {
        /// <summary>A suppressed-transaction CREATE TABLE followed by a failing statement.</summary>
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("CREATE TABLE public.gate_probe_nt (id integer)", suppressTransaction: true);
            migrationBuilder.Sql("SELECT 1 / 0");
        }
    }

    /// <summary>No-op base, recorded by the seeded history.</summary>
    [DbContext(typeof(DriftProbeContext))]
    [Migration(ProbeBaseMigration.Id)]
    public sealed class DriftProbeBase : Migration
    {
        /// <summary>Does nothing.</summary>
        protected override void Up(MigrationBuilder migrationBuilder) => migrationBuilder.Sql("SELECT 1");
    }

    /// <summary>A migration that must never run, because the build is defective.</summary>
    [DbContext(typeof(DriftProbeContext))]
    [Migration("20990201000002_ProbeDrift")]
    public sealed class DriftProbeNext : Migration
    {
        /// <summary>Creates <c>gate_probe_drift</c>.</summary>
        protected override void Up(MigrationBuilder migrationBuilder) => migrationBuilder.Sql("CREATE TABLE public.gate_probe_drift (id integer)");
    }
}
