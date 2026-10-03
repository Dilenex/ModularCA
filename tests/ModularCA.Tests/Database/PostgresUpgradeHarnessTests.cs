using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Models;
using ModularCA.Shared.Models.Config;
using Npgsql;
using Xunit;
using F = ModularCA.Tests.Shared.CeremonyParametersFixtures;
using RenameMigration = ModularCA.Database.Migrations.RenameTenantToSpace;

namespace ModularCA.Tests.Database;

/// <summary>
/// A <see cref="FactAttribute"/> that runs only when <see cref="Variable"/> is set, and is
/// otherwise reported as skipped with the reason.
/// </summary>
public sealed class RequiresEnvironmentFactAttribute : FactAttribute
{
    /// <summary>The environment variable that must hold a value for the test to run.</summary>
    public string Variable { get; }

    /// <summary>Skips the test unless <paramref name="variable"/> is set.</summary>
    public RequiresEnvironmentFactAttribute(string variable)
    {
        Variable = variable;
        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(variable)))
            Skip = $"Opt-in: set {variable} to run.";
    }
}

/// <summary>
/// Opt-in upgrade tests against a real PostgreSQL server. Skipped unless an environment variable
/// names a server.
/// </summary>
/// <remarks>
/// <para>
/// <c>MODULARCA_TEST_PG</c> holds a connection string to a server where the user may create and
/// drop databases (the <c>Database</c> in it is only used to connect). The fresh-install test
/// creates two throwaway databases, applies the frozen baselines only, seeds the 0.3.x shape
/// with SQL written against the baseline schema (not through the current model, which later
/// migrations change), then applies the later migrations one stage at a time through the same
/// code the control role uses, checking each stage in SQL at that stage's migration. The
/// databases are dropped afterwards.
/// </para>
/// <para>
/// <c>MODULARCA_TEST_PG_REHEARSAL</c> holds a connection string to a copy of a real
/// application database, restored from a dump of staging. That test migrates the copy to latest
/// and checks that nothing was lost. It changes the database it is pointed at, so point it only
/// at a disposable restore. <c>MODULARCA_TEST_PG_REHEARSAL_AUDIT</c> optionally does the same
/// for the audit database. See docs/architecture/postgresql-migration.md.
/// </para>
/// </remarks>
[Trait("Category", "PostgreSQL")]
public class PostgresUpgradeHarnessTests
{
    /// <summary>The application context's frozen baseline, applied by production on 2026-09-19.</summary>
    public const string AppBaseline = "20260919181506_InitialCreate";

    /// <summary>The audit context's frozen baseline, applied by production on 2026-09-19.</summary>
    public const string AuditBaseline = "20260919181510_InitialAuditSchema";

    /// <summary>The name of the 0.4.0 S2 migration that retires tenant hostnames.</summary>
    public const string RetireTenantHostnames = "RetireTenantHostnames";

    /// <summary>The name of the 0.4.0 S3 migration that folds the system tenant into the instance.</summary>
    public const string FoldSystemTenant = "FoldSystemTenant";

    /// <summary>The 0.4.0 S4 migration's name, without its timestamp.</summary>
    public const string InstanceUniqueCaNames = "InstanceUniqueCaNames";

    /// <summary>The 0.4.0 S6 migration that renames tenant to space, without its timestamp.</summary>
    public const string RenameTenantToSpace = "RenameTenantToSpace";

    private const string ServerVariable = "MODULARCA_TEST_PG";
    private const string RehearsalVariable = "MODULARCA_TEST_PG_REHEARSAL";
    private const string RehearsalAuditVariable = "MODULARCA_TEST_PG_REHEARSAL_AUDIT";

    private static readonly Guid SystemTenant = Guid.Parse("00000000-0000-0000-0000-00000000a001");
    private static readonly Guid OrgTenant = Guid.Parse("00000000-0000-0000-0000-00000000a002");
    private static readonly Guid RootCa = Guid.Parse("00000000-0000-0000-0000-00000000b001");
    private static readonly Guid SystemGroup = Guid.Parse("00000000-0000-0000-0000-00000000c001");
    private static readonly Guid OrgAdminGroup = Guid.Parse("00000000-0000-0000-0000-00000000c002");
    private static readonly Guid CaAdminGroup = Guid.Parse("00000000-0000-0000-0000-00000000c003");
    private static readonly Guid Operator = Guid.Parse("00000000-0000-0000-0000-00000000d001");
    private static readonly Guid SysCa = Guid.Parse("00000000-0000-0000-0000-00000000b002");
    private static readonly Guid SshCa = Guid.Parse("00000000-0000-0000-0000-00000000b003");
    private static readonly Guid SysAdminGroup = Guid.Parse("00000000-0000-0000-0000-00000000c004");
    private static readonly Guid SysOperatorGroup = Guid.Parse("00000000-0000-0000-0000-00000000c005");
    private static readonly Guid SysAuditorGroup = Guid.Parse("00000000-0000-0000-0000-00000000c006");
    private static readonly Guid SysCaAdminGroup = Guid.Parse("00000000-0000-0000-0000-00000000c007");
    private static readonly Guid SshAdminGroup = Guid.Parse("00000000-0000-0000-0000-00000000c008");
    private static readonly Guid OrgSystemAdmin = Guid.Parse("00000000-0000-0000-0000-00000000c009");
    private static readonly Guid OrgSystemOperator = Guid.Parse("00000000-0000-0000-0000-00000000c00a");
    private static readonly Guid OrgSystemAuditor = Guid.Parse("00000000-0000-0000-0000-00000000c00b");
    private static readonly Guid OrgSystemUser = Guid.Parse("00000000-0000-0000-0000-00000000c00c");
    private static readonly Guid BuiltInRole = Guid.Parse("00000000-0000-0000-0000-00000000e001");
    private static readonly Guid CustomRole = Guid.Parse("00000000-0000-0000-0000-00000000e002");
    private static readonly Guid SysAdminRoleAssignment = Guid.Parse("00000000-0000-0000-0000-00000000e003");
    private static readonly Guid CaScopedGrant = Guid.Parse("00000000-0000-0000-0000-00000000e004");
    private static readonly Guid Realm = Guid.Parse("00000000-0000-0000-0000-00000000e005");
    private static readonly Guid BoundProfile = Guid.Parse("00000000-0000-0000-0000-00000000e006");
    private static readonly Guid Token = Guid.Parse("00000000-0000-0000-0000-00000000e007");
    private static readonly Guid ExecutedCeremony = Guid.Parse("00000000-0000-0000-0000-00000000e008");
    private static readonly Guid ServiceIdentity = Guid.Parse("00000000-0000-0000-0000-00000000d002");
    private static readonly Guid ForeignSigningProfile = Guid.Parse("00000000-0000-0000-0000-00000000e009");
    private static readonly Guid OrgOperatorGroup = Guid.Parse("00000000-0000-0000-0000-00000000c00d");
    private static readonly Guid OrgAuditorGroup = Guid.Parse("00000000-0000-0000-0000-00000000c00e");
    private static readonly Guid OrgUserGroup = Guid.Parse("00000000-0000-0000-0000-00000000c00f");
    private static readonly Guid MismatchedOrgGroup = Guid.Parse("00000000-0000-0000-0000-00000000c010");
    private static readonly Guid ControlledCeremony = Guid.Parse("00000000-0000-0000-0000-00000000f001");
    private static readonly Guid CaCeremony = Guid.Parse("00000000-0000-0000-0000-00000000f002");
    private static readonly Guid SshCeremony = Guid.Parse("00000000-0000-0000-0000-00000000f003");
    private static readonly Guid RevokeCeremony = Guid.Parse("00000000-0000-0000-0000-00000000f004");
    private static readonly Guid PolicyCeremony = Guid.Parse("00000000-0000-0000-0000-00000000f005");
    private static readonly Guid InstancePolicyCeremony = Guid.Parse("00000000-0000-0000-0000-00000000f006");
    private static readonly Guid QuorumCeremony = Guid.Parse("00000000-0000-0000-0000-00000000f007");
    private static readonly Guid BadCeremony = Guid.Parse("00000000-0000-0000-0000-00000000f008");
    private static readonly Guid NulCeremony = Guid.Parse("00000000-0000-0000-0000-00000000f009");
    private static readonly Guid NulSshCeremony = Guid.Parse("00000000-0000-0000-0000-00000000f00a");

    /// <summary>The seeded organisation tenant.</summary>
    internal static Guid OrgTenantId => OrgTenant;

    /// <summary>The seeded organisation's root CA.</summary>
    internal static Guid RootCaId => RootCa;

    /// <summary>A second, disabled organisation tenant, which <c>FoldSystemTenant</c>'s P2 refuses. Run after <see cref="Seed030Sql"/>.</summary>
    internal static string SeedSecondOrganisationSql =>
        "INSERT INTO \"Tenants\" (\"Id\",\"Name\",\"Slug\",\"IsEnabled\",\"IsSystemTenant\",\"CanBeDeleted\",\"CreatedAt\",\"MaxCertificateAuthorities\",\"MaxCertificatesTotal\",\"MaxUsers\",\"MaxValidityDays\",\"ValidityCeilingBehavior\",\"RequireKeyCeremony\",\"CeremonyRequiredApprovals\",\"IsDeleted\") "
        + "VALUES (gen_random_uuid(),'Globex','globex',false,false,true,now(),0,0,0,0,0,true,2,false);";

    /// <summary>
    /// The upgrade, one stage at a time: each stage's assertions run at that stage's migration, in
    /// SQL against that stage's names, so a later rename cannot break an earlier stage's checks.
    /// The audit database is seeded at its baseline with records hashed by the real
    /// <see cref="AuditHashChainService.ComputeHash"/>: the instance chain and two tenant chains,
    /// which the control role's start then seals. Before the S6 rename, open ceremonies in every
    /// stored shape and casing, the space's <c>org-*</c> groups and a signer audit row are added;
    /// after it, an LDAP mapping that still names an <c>org-*</c> group is synced.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public async Task Baseline_with_a_030_shape_migrates_stage_by_stage()
    {
        var server = Environment.GetEnvironmentVariable(ServerVariable)!;
        var suffix = Guid.NewGuid().ToString("N")[..12];
        var appName = $"modularca_upgrade_app_{suffix}";
        var auditName = $"modularca_upgrade_audit_{suffix}";

        await CreateDatabaseAsync(server, appName);
        await CreateDatabaseAsync(server, auditName);
        try
        {
            await using (var app = CreateApp(WithDatabase(server, appName)))
            {
                await app.GetService<IMigrator>().MigrateAsync(AppBaseline);
                Assert.Equal([AppBaseline], await app.Database.GetAppliedMigrationsAsync());

                await ExecAsync(app, Seed030Sql + SeedFoldSql);
                Assert.Equal(0, await ScalarAsync(app, "SELECT count(*) FROM \"TenantHostnames\""));
                Assert.Equal(12, await ScalarAsync(app, "SELECT count(*) FROM \"CaGroups\""));

                await MigrateThroughAsync(app, RetireTenantHostnames);
                Assert.Equal(0, await ScalarAsync(app, "SELECT count(*) FROM pg_catalog.pg_class WHERE relname = 'TenantHostnames'"));

                await MigrateThroughAsync(app, FoldSystemTenant);
                await AssertFoldedAsync(app);

                await MigrateThroughAsync(app, InstanceUniqueCaNames);
                await AssertInstanceUniqueAsync(app);

                await ExecAsync(app, SeedRenameSql);
                var before = await RowValuesAsync(app, renamed: false);
                await MigrateThroughAsync(app, RenameTenantToSpace);
                await AssertRenamedAsync(app, before);

                await MigrateToLatestAsync(app, "application");
                await AssertCatalogMatchesModelAsync(app);
                await AssertLegacyLdapMappingStillGrantsAsync(app);
            }

            await using (var audit = CreateAudit(WithDatabase(server, auditName)))
            {
                await audit.GetService<IMigrator>().MigrateAsync(AuditBaseline);
                Assert.Equal([AuditBaseline], await audit.Database.GetAppliedMigrationsAsync());
                await SeedAuditChainsAsync(audit);

                await MigrateToLatestAsync(audit, "audit");
                await AssertAuditChainsSealedAsync(audit);
            }
        }
        finally
        {
            NpgsqlConnection.ClearAllPools();
            await DropDatabaseAsync(server, appName);
            await DropDatabaseAsync(server, auditName);
        }
    }

    [RequiresEnvironmentFact(ServerVariable)]
    public async Task A_tenant_hostname_row_stops_the_upgrade_with_3_through_the_startup_gate_and_nothing_is_applied()
    {
        var server = Environment.GetEnvironmentVariable(ServerVariable)!;
        var suffix = Guid.NewGuid().ToString("N")[..12];
        var appName = $"modularca_upgrade_app_{suffix}";

        await CreateDatabaseAsync(server, appName);
        try
        {
            var connection = WithDatabase(server, appName);
            await using (var app = CreateApp(connection))
            {
                await app.GetService<IMigrator>().MigrateAsync(AppBaseline);
                await app.Database.ExecuteSqlRawAsync(Seed030Sql + SeedTenantHostnameSql);
            }

            using var log = new CapturedSerilog();
            var exit = await SchemaStartupApi.EnforceAllAsync(
                [("application", DatabaseKind.Application, Instance(connection))], true, new SchemaConfig { WaitSeconds = 1 });

            Assert.Equal(3, exit);
            Assert.True(log.Events.Any(e => e.Text.Contains("This instance has 1 tenant hostname(s)", StringComparison.Ordinal)),
                string.Join(Environment.NewLine, log.Events.Select(e => $"{e.Level}: {e.Text}")));
            await using (var app = CreateApp(connection))
            {
                Assert.Equal([AppBaseline], await app.Database.GetAppliedMigrationsAsync());
                Assert.Equal(1, await ScalarAsync(app, "SELECT count(*) FROM \"TenantHostnames\""));
            }
        }
        finally
        {
            NpgsqlConnection.ClearAllPools();
            await DropDatabaseAsync(server, appName);
        }
    }

    /// <summary>
    /// What the fold must leave, read in SQL at the fold's own stage: no system tenant and the
    /// column gone; every row that named it on the instance (a null tenant); the org-system-*
    /// groups, their grants and roles gone; the instance policy equal to the SYSTEM tenant's
    /// values (scopes are independent, nothing merged) and the organisation's unchanged; and
    /// RESTRICT on the tenant foreign keys.
    /// </summary>
    private static async Task AssertFoldedAsync(DbContext app)
    {
        Assert.Equal(1, await ScalarAsync(app, "SELECT count(*) FROM \"Tenants\""));
        Assert.Equal(0, await ScalarAsync(app, "SELECT count(*) FROM information_schema.columns WHERE table_name = 'Tenants' AND column_name = 'IsSystemTenant'"));
        Assert.Equal(1, await ScalarAsync(app,
            $"SELECT count(*) FROM \"Tenants\" WHERE \"Id\" = '{OrgTenant}' AND NOT \"RequireKeyCeremony\" AND \"CeremonyRequiredApprovals\" = 2 "
            + $"AND \"UserCeremonyRequiredApprovals\" IS NULL AND \"MaxValidityDays\" = 825 AND \"ValidityCeilingBehavior\" = {(int)ModularCA.Shared.Enums.ValidityCeilingBehavior.Refuse}"));

        Assert.Equal(1, await ScalarAsync(app, "SELECT count(*) FROM \"SecurityPolicy\""));
        Assert.Equal(1, await ScalarAsync(app,
            "SELECT count(*) FROM \"SecurityPolicy\" WHERE \"RequireKeyCeremony\" AND \"CeremonyRequiredApprovals\" = 3 "
            + $"AND \"UserCeremonyRequiredApprovals\" = 2 AND \"MaxValidityDays\" = 0 AND \"ValidityCeilingBehavior\" = {(int)ModularCA.Shared.Enums.ValidityCeilingBehavior.Shorten} "
            + "AND \"UserQuorum\" = 1"));

        Assert.Equal(1, await ScalarAsync(app, $"SELECT count(*) FROM \"CertificateAuthorities\" WHERE \"Id\" = '{RootCa}' AND \"TenantId\" = '{OrgTenant}'"));
        Assert.Equal(2, await ScalarAsync(app, $"SELECT count(*) FROM \"CertificateAuthorities\" WHERE \"Id\" IN ('{SysCa}','{SshCa}') AND \"TenantId\" IS NULL"));

        Assert.Equal(8, await ScalarAsync(app, "SELECT count(*) FROM \"CaGroups\""));
        Assert.Equal(6, await ScalarAsync(app,
            $"SELECT count(*) FROM \"CaGroups\" WHERE \"TenantId\" IS NULL AND \"Id\" IN ('{SystemGroup}','{SysAdminGroup}','{SysOperatorGroup}','{SysAuditorGroup}','{SysCaAdminGroup}','{SshAdminGroup}')"));
        Assert.Equal(2, await ScalarAsync(app, $"SELECT count(*) FROM \"CaGroups\" WHERE \"TenantId\" = '{OrgTenant}' AND \"Id\" IN ('{OrgAdminGroup}','{CaAdminGroup}')"));
        Assert.Equal(0, await ScalarAsync(app,
            $"SELECT count(*) FROM \"CaGroups\" WHERE \"Id\" IN ('{OrgSystemAdmin}','{OrgSystemOperator}','{OrgSystemAuditor}','{OrgSystemUser}')"));
        Assert.Equal(0, await ScalarAsync(app, $"SELECT count(*) FROM \"CapabilityGrants\" WHERE \"GroupId\" IN ('{OrgSystemAdmin}','{OrgSystemOperator}')"));
        Assert.Equal(0, await ScalarAsync(app, $"SELECT count(*) FROM \"RoleAssignments\" WHERE \"GroupId\" = '{OrgSystemAdmin}'"));
        Assert.Equal(1, await ScalarAsync(app, $"SELECT count(*) FROM \"CapabilityGrants\" WHERE \"GroupId\" = '{SysAdminGroup}'"));

        Assert.Equal(1, await ScalarAsync(app, $"SELECT count(*) FROM \"KerberosRealms\" WHERE \"Id\" = '{Realm}' AND \"TenantId\" IS NULL"));
        Assert.Equal(1, await ScalarAsync(app, $"SELECT count(*) FROM \"Roles\" WHERE \"Id\" = '{CustomRole}' AND \"TenantId\" IS NULL"));
        Assert.Equal(1, await ScalarAsync(app, $"SELECT count(*) FROM \"RoleAssignments\" WHERE \"Id\" = '{SysAdminRoleAssignment}' AND \"TenantId\" IS NULL"));
        Assert.Equal(1, await ScalarAsync(app,
            $"SELECT count(*) FROM \"UserCapabilityGrants\" WHERE \"Id\" = '{CaScopedGrant}' AND \"TenantId\" IS NULL AND \"CertificateAuthorityId\" = '{SysCa}'"));
        Assert.Equal(1, await ScalarAsync(app,
            $"SELECT count(*) FROM \"CertProfiles\" WHERE \"Id\" = '{BoundProfile}' AND \"TenantId\" IS NULL AND \"CertificateAuthorityId\" = '{SysCa}'"));
        Assert.Equal(1, await ScalarAsync(app, $"SELECT count(*) FROM \"EnrollmentTokens\" WHERE \"Id\" = '{Token}' AND \"TenantId\" IS NULL"));
        Assert.Equal(1, await ScalarAsync(app,
            $"SELECT count(*) FROM \"KeyCeremonies\" WHERE \"Id\" = '{ExecutedCeremony}' AND \"TenantId\" IS NULL AND strpos(\"ParametersJson\", '{SystemTenant}') > 0"));
        Assert.Equal(1, await ScalarAsync(app,
            $"SELECT count(*) FROM \"Users\" WHERE \"Id\" = '{ServiceIdentity}' AND \"ServiceScopeTenantId\" IS NULL AND \"ServiceScopeCaId\" = '{SysCa}'"));
        Assert.Equal(1, await ScalarAsync(app, $"SELECT count(*) FROM \"Users\" WHERE \"Id\" = '{Operator}'"));
        Assert.Equal(2, await ScalarAsync(app, $"SELECT count(*) FROM \"CaGroupMembers\" WHERE \"UserId\" = '{Operator}'"));

        foreach (var fk in new[] { "FK_CertificateAuthorities_Tenants_TenantId", "FK_KerberosRealms_Tenants_TenantId", "FK_Roles_Tenants_TenantId",
                     "FK_RoleAssignments_Tenants_TenantId", "FK_UserCapabilityGrants_Tenants_TenantId" })
            Assert.Equal(1, await ScalarAsync(app, $"SELECT count(*) FROM pg_catalog.pg_constraint WHERE conname = '{fk}' AND confdeltype = 'r'"));
    }

    /// <summary>
    /// What 0.4.0 S4 must leave, read in SQL at its own stage: plain unique indexes on CA Label and
    /// Name over all rows, the raw unique index on lower(Label), the non-unique TenantId index
    /// behind the foreign key, none of the four per-tenant and instance-only indexes, and no tenant
    /// quota columns. A space CA may not take an instance CA's label, nor a CA a deleted CA's name.
    /// </summary>
    private static async Task AssertInstanceUniqueAsync(DbContext app)
    {
        foreach (var index in new[] { "IX_CertificateAuthorities_Label", "IX_CertificateAuthorities_Name" })
            Assert.Equal(1, await ScalarAsync(app,
                $"SELECT count(*) FROM pg_catalog.pg_indexes WHERE indexname = '{index}' AND indexdef LIKE 'CREATE UNIQUE INDEX%' AND indexdef NOT LIKE '% WHERE %'"));
        Assert.Equal(1, await ScalarAsync(app,
            "SELECT count(*) FROM pg_catalog.pg_indexes WHERE indexname = 'IX_CertificateAuthorities_TenantId' AND indexdef NOT LIKE 'CREATE UNIQUE INDEX%'"));
        Assert.Equal(1, await ScalarAsync(app,
            "SELECT count(*) FROM pg_catalog.pg_indexes WHERE indexname = 'IX_CertificateAuthorities_LabelLower' AND indexdef LIKE 'CREATE UNIQUE INDEX%' AND indexdef LIKE '%lower(%'"));
        foreach (var index in new[] { "IX_CertificateAuthorities_TenantId_Label", "IX_CertificateAuthorities_TenantId_Name",
                     "IX_CertificateAuthorities_Label_Instance", "IX_CertificateAuthorities_Name_Instance" })
            Assert.Equal(0, await ScalarAsync(app, $"SELECT count(*) FROM pg_catalog.pg_indexes WHERE indexname = '{index}'"));
        Assert.Equal(0, await ScalarAsync(app,
            "SELECT count(*) FROM information_schema.columns WHERE table_name = 'Tenants' AND column_name IN ('MaxCertificateAuthorities','MaxCertificatesTotal','MaxUsers')"));

        var duplicate = await Assert.ThrowsAsync<PostgresException>(() => ExecAsync(app,
            "INSERT INTO \"CertificateAuthorities\" (\"Id\",\"Name\",\"Label\",\"IsDefault\",\"Type\",\"IsEnabled\",\"KeyStorageType\",\"IsSshCa\",\"TenantId\",\"IsDeleted\") "
            + $"VALUES (gen_random_uuid(),'Another','system-signing-ca',false,'Root',true,'Software',false,'{OrgTenant}',false)"));
        Assert.Equal(PostgresErrorCodes.UniqueViolation, duplicate.SqlState);

        await ExecAsync(app, $"UPDATE \"CertificateAuthorities\" SET \"IsDeleted\" = true WHERE \"Id\" = '{SshCa}'");
        var reused = await Assert.ThrowsAsync<PostgresException>(() => ExecAsync(app,
            "INSERT INTO \"CertificateAuthorities\" (\"Id\",\"Name\",\"Label\",\"IsDefault\",\"Type\",\"IsEnabled\",\"KeyStorageType\",\"IsSshCa\",\"TenantId\",\"IsDeleted\") "
            + "VALUES (gen_random_uuid(),'Ops SSH','ops-ssh-2',false,'SSH',true,'Software',true,NULL,false)"));
        Assert.Equal(PostgresErrorCodes.UniqueViolation, reused.SqlState);
    }

    /// <summary>The tables S6 renames a column of, the column, and the columns whose values S6 may change.</summary>
    private static readonly (string Table, string Column, string[] Changed)[] RenamedColumns =
    [
        ("CaGroups", "TenantId", ["Name", "DisplayName"]), ("CertProfiles", "TenantId", []), ("CertificateAuthorities", "TenantId", []),
        ("EnrollmentTokens", "TenantId", []), ("KerberosRealms", "TenantId", []), ("KeyCeremonies", "TenantId", ["ParametersJson", "OperationType"]),
        ("RoleAssignments", "TenantId", []), ("Roles", "TenantId", []), ("SignerAudit", "TenantId", []),
        ("UserCapabilityGrants", "TenantId", []), ("Users", "ServiceScopeTenantId", []),
    ];

    /// <summary>
    /// Every row of every table S6 touches, as jsonb text in a stable order, read before the rename
    /// with the old column given its new name, or after it as it is, so the two compare equal when
    /// no value moved. Columns S6 rewrites on purpose are left out; their checks are explicit.
    /// </summary>
    private static async Task<List<string>> RowValuesAsync(DbContext app, bool renamed)
    {
        var values = new List<string>();
        foreach (var (table, column, changed) in RenamedColumns)
        {
            var newColumn = column.Replace("Tenant", "Space", StringComparison.Ordinal);
            var except = string.Concat(changed.Select(c => $" - '{c}'"));
            var row = renamed
                ? $"(to_jsonb(t){except})"
                : $"((to_jsonb(t) - '{column}'{except}) || jsonb_build_object('{newColumn}', t.\"{column}\"))";
            values.Add(table + ": " + await TextAsync(app, $"SELECT coalesce(string_agg({row}::text, ' ; ' ORDER BY t.\"Id\"), '') FROM \"{table}\" t"));
        }
        values.Add("Spaces: " + await TextAsync(app,
            $"SELECT coalesce(string_agg(to_jsonb(t)::text, ' ; ' ORDER BY t.\"Id\"), '') FROM \"{(renamed ? "Spaces" : "Tenants")}\" t"));
        return values;
    }

    /// <summary>
    /// What 0.4.0 S6 must leave, read at its own stage: every value where it was under the new
    /// names; no catalog name or definition in <c>public</c> that says tenant; every stored
    /// ceremony read by the real classes with its space ids, equal to its 0.4.0 shape; no
    /// <c>TenantPolicyChange</c> left; the space's <c>org-*</c> groups renamed as new spaces name
    /// them, with their members, and nothing else renamed; old signer audit rows keeping their token.
    /// </summary>
    private static async Task AssertRenamedAsync(DbContext app, List<string> before)
    {
        Assert.Equal(before, await RowValuesAsync(app, renamed: true));

        Assert.Equal("", await TextAsync(app, """
            SELECT coalesce(string_agg(n, ', ' ORDER BY n), '') FROM (
                SELECT c.relname::text AS n FROM pg_catalog.pg_class c WHERE c.relnamespace = 'public'::regnamespace
                UNION ALL SELECT a.attname::text FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
                    WHERE c.relnamespace = 'public'::regnamespace AND a.attnum > 0 AND NOT a.attisdropped
                UNION ALL SELECT conname::text FROM pg_catalog.pg_constraint WHERE connamespace = 'public'::regnamespace
                UNION ALL SELECT pg_catalog.pg_get_constraintdef(oid) FROM pg_catalog.pg_constraint WHERE connamespace = 'public'::regnamespace
                UNION ALL SELECT indexdef FROM pg_catalog.pg_indexes WHERE schemaname = 'public'
                UNION ALL SELECT tgname::text FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid WHERE c.relnamespace = 'public'::regnamespace
                UNION ALL SELECT viewname::text FROM pg_catalog.pg_views WHERE schemaname = 'public'
                UNION ALL SELECT proname::text FROM pg_catalog.pg_proc WHERE pronamespace = 'public'::regnamespace
            ) x WHERE n ILIKE '%tenant%'
            """));
        Assert.Equal(0, await ScalarAsync(app, "SELECT count(*) FROM \"KeyCeremonies\" WHERE \"ParametersJson\" ILIKE '%tenantid%' OR \"OperationType\" ILIKE '%tenant%'"));
        Assert.Equal(2, await ScalarAsync(app, "SELECT count(*) FROM \"KeyCeremonies\" WHERE \"OperationType\" = 'SpacePolicyChange'"));

        async Task<string> Parameters(Guid id) => await TextAsync(app, $"SELECT \"ParametersJson\" FROM \"KeyCeremonies\" WHERE \"Id\" = '{id}'");
        foreach (var (id, current) in new[]
                 {
                     (ControlledCeremony, F.ControlledUserChange), (CaCeremony, F.KeyCeremony), (SshCeremony, F.SshKeyCeremony),
                     (RevokeCeremony, F.RevokeCa), (PolicyCeremony, F.SpacePolicyChange), (InstancePolicyCeremony, F.InstancePolicyChange),
                     (QuorumCeremony, F.CaUserQuorumChange),
                 })
            Assert.True(System.Text.Json.Nodes.JsonNode.DeepEquals(
                System.Text.Json.Nodes.JsonNode.Parse(await Parameters(id)), System.Text.Json.Nodes.JsonNode.Parse(current)), $"ceremony {id}");

        var controlled = CeremonyParametersJson.Read<ControlledUserChangeParameters>(await Parameters(ControlledCeremony))!;
        Assert.Equal((F.SpaceA, F.SpaceB), (controlled.SpaceId, controlled.MintedTierSpaceId));
        Assert.Equal(F.SpaceA, CeremonyParametersJson.Read<KeyCeremonyParameters>(await Parameters(CaCeremony))!.SpaceId);
        Assert.Equal(F.SpaceA, CeremonyParametersJson.Read<SshKeyCeremonyParameters>(await Parameters(SshCeremony))!.SpaceId);
        Assert.Equal(F.SpaceA, CeremonyParametersJson.ReadSpaceId(await Parameters(SshCeremony)));
        Assert.Equal(F.SpaceA, CeremonyParametersJson.Read<RevokeCaCeremonyParameters>(await Parameters(RevokeCeremony))!.SpaceId);
        Assert.Equal(F.SpaceA, CeremonyParametersJson.Read<SpacePolicyChangeCeremonyParameters>(await Parameters(PolicyCeremony))!.SpaceId);
        Assert.Equal(F.SpaceA, CeremonyParametersJson.Read<SpacePolicyChangeCeremonyParameters>(await Parameters(QuorumCeremony))!.SpaceId);
        var instance = CeremonyParametersJson.Read<SpacePolicyChangeCeremonyParameters>(await Parameters(InstancePolicyCeremony))!;
        Assert.Null(instance.SpaceId);
        Assert.Equal(F.InstanceCa, Assert.Single(instance.CaUserQuorums).CaId);
        Assert.Equal(SystemTenant, CeremonyParametersJson.ReadSpaceId(await Parameters(ExecutedCeremony)));

        Assert.Equal(
            "ca-acme-root-admin=CA acme-root Admin; org-globex-admin=Org Globex Admin; space-acme-admin=Space Acme Admin; "
            + "space-acme-auditor=Space Acme Auditor; space-acme-operator=Space Acme Operator; space-acme-user=Acme PKI users",
            await TextAsync(app, $"SELECT string_agg(\"Name\" || '=' || \"DisplayName\", '; ' ORDER BY \"Name\"::text COLLATE \"C\") FROM \"CaGroups\" WHERE \"SpaceId\" = '{OrgTenant}'"));
        Assert.Equal(1, await ScalarAsync(app, $"SELECT count(*) FROM \"CaGroups\" WHERE \"Id\" = '{OrgAdminGroup}' AND \"Name\" = 'space-acme-admin'"));
        Assert.Equal(1, await ScalarAsync(app, $"SELECT count(*) FROM \"CaGroupMembers\" WHERE \"GroupId\" = '{OrgAdminGroup}' AND \"UserId\" = '{Operator}'"));
        Assert.Equal(0, await ScalarAsync(app, "SELECT count(*) FROM \"CaGroups\" WHERE \"Name\" LIKE 'space-%' AND \"SpaceId\" IS NULL"));

        Assert.Equal(1, await ScalarAsync(app,
            $"SELECT count(*) FROM \"SignerAudit\" WHERE \"SpaceId\" = '{OrgTenant}' AND \"EffectiveScope\" = '{ModularCA.Shared.Entities.SignerAuditEntity.TenantScope}'"));
    }

    /// <summary>
    /// The model at this build's latest migration names exactly what the catalog has: every table,
    /// column, primary, unique, foreign and check constraint, and index. The raw
    /// <c>IX_CertificateAuthorities_LabelLower</c>, outside the model, is the only extra index.
    /// </summary>
    private static async Task AssertCatalogMatchesModelAsync(ModularCADbContext app)
    {
        var model = app.GetService<Microsoft.EntityFrameworkCore.Metadata.IDesignTimeModel>().Model.GetRelationalModel();
        var tables = model.Tables.ToList();
        Assert.Equal(tables.Select(t => t.Name).Order(StringComparer.Ordinal),
            await TextsAsync(app, "SELECT relname::text FROM pg_catalog.pg_class WHERE relnamespace = 'public'::regnamespace AND relkind IN ('r','p') AND relname <> '__EFMigrationsHistory'"));

        foreach (var table in tables)
            Assert.Equal(table.Columns.Select(c => c.Name).Where(n => n != "xmin").Order(StringComparer.Ordinal),
                await TextsAsync(app, $"SELECT attname::text FROM pg_catalog.pg_attribute WHERE attrelid = 'public.\"{table.Name}\"'::regclass AND attnum > 0 AND NOT attisdropped"));

        var keys = tables.SelectMany(t => t.UniqueConstraints.Select(u => u.Name)
            .Concat(t.PrimaryKey is { } pk ? [pk.Name] : [])
            .Concat(t.ForeignKeyConstraints.Select(f => f.Name))
            .Concat(t.CheckConstraints.Select(c => c.Name!))).Distinct().Order(StringComparer.Ordinal);
        Assert.Equal(keys, await TextsAsync(app,
            "SELECT conname::text FROM pg_catalog.pg_constraint WHERE connamespace = 'public'::regnamespace AND contype IN ('p','u','f','c') AND conrelid <> 'public.\"__EFMigrationsHistory\"'::regclass"));

        var indexes = tables.SelectMany(t => t.Indexes.Select(i => i.Name).Concat(t.UniqueConstraints.Select(u => u.Name)))
            .Append("IX_CertificateAuthorities_LabelLower").Distinct().Order(StringComparer.Ordinal);
        Assert.Equal(indexes, await TextsAsync(app,
            "SELECT indexname::text FROM pg_catalog.pg_indexes WHERE schemaname = 'public' AND tablename <> '__EFMigrationsHistory'"));
    }

    /// <summary>
    /// An LDAP mapping written before 0.4.0 names the space's old <c>org-acme-user</c> group, which
    /// the rename made <c>space-acme-user</c>: sync still grants it, and warns.
    /// </summary>
    private static async Task AssertLegacyLdapMappingStillGrantsAsync(ModularCADbContext app)
    {
        var config = new SystemConfig();
        config.LdapAuth.GroupToRoleMappings = """{"CN=PKI Users,DC=acme,DC=example":"org-acme-user"}""";
        var log = new ModularCA.Tests.Core.Services.LdapSpaceGroupRenameTests.CapturingLogger();
        LdapGroupSyncService.WarnedRenamedGroups.TryRemove("org-acme-user", out _);
        await new LdapGroupSyncService(app, config, null!, log).SyncUserGroupsAsync(Operator, ["CN=PKI Users,DC=acme,DC=example"]);

        Assert.Equal(1, await ScalarAsync(app, $"SELECT count(*) FROM \"CaGroupMembers\" WHERE \"GroupId\" = '{OrgUserGroup}' AND \"UserId\" = '{Operator}'"));
        Assert.Contains(log.Warnings, w => w.Contains("org-acme-user") && w.Contains("space-acme-user"));
    }

    public static TheoryData<string, string, string> RefusedRenames() => new()
    {
        { "P1 not JSON", BadCeremonySql("""{"tenantId": "6d1f3c2a-4b5e-4f60-8a71-0b2c3d4e5f60" """),
            $"The stored parameters of these key ceremonies could not be read as a JSON object with one tenant key each: {BadCeremony} (Executed). " },
        { "P1 not an object", BadCeremonySql("""["tenantId"]"""), $"one tenant key each: {BadCeremony} (Executed)." },
        { "P1 both keys", BadCeremonySql("""{"TenantId":"6d1f3c2a-4b5e-4f60-8a71-0b2c3d4e5f60","SpaceId":"7e2a4d3b-5c6f-4071-9b82-1c3d4e5f6071"}"""),
            $"one tenant key each: {BadCeremony} (Executed)." },
        { "P2 taken", $"""
            INSERT INTO "CaGroups" ("Id","Name","DisplayName","CertificateAuthorityId","TemplateName","IsSystemGroup","IsSystemTierSuper",
                "IsAutoGenerated","RequiredQuorum","MaxCertificates","MaxPendingRequests","CreatedAt","TenantId")
            VALUES (gen_random_uuid(),'space-acme-admin','Hand-made',NULL,NULL,false,false,false,1,0,0,now(),'{OrgTenant}');
            """, "This instance has 1 space group(s) that cannot take their 0.4.0 name: org-acme-admin -> space-acme-admin." },
        { "P2 too long", $"""
            INSERT INTO "Tenants" ("Id","Name","Slug","IsEnabled","IsSystemTenant","CanBeDeleted","CreatedAt","MaxCertificateAuthorities",
                "MaxCertificatesTotal","MaxUsers","MaxValidityDays","ValidityCeilingBehavior","RequireKeyCeremony","CeremonyRequiredApprovals","IsDeleted")
            VALUES ('00000000-0000-0000-0000-00000000a003','Long','{new string('l', 187)}',true,false,true,now(),0,0,0,0,0,true,2,true);
            INSERT INTO "CaGroups" ("Id","Name","DisplayName","CertificateAuthorityId","TemplateName","IsSystemGroup","IsSystemTierSuper",
                "IsAutoGenerated","RequiredQuorum","MaxCertificates","MaxPendingRequests","CreatedAt","TenantId")
            VALUES (gen_random_uuid(),'org-{new string('l', 187)}-operator','Org Long Operator',NULL,'Operator',false,false,true,1,0,0,now(),'00000000-0000-0000-0000-00000000a003');
            """, $"org-{new string('l', 187)}-operator -> space-{new string('l', 187)}-operator" },
    };

    /// <summary>An executed ceremony whose stored parameters are <paramref name="parametersJson"/>, at the baseline's names.</summary>
    private static string BadCeremonySql(string parametersJson) => $"""
        INSERT INTO "KeyCeremonies" ("Id","OperationType","Description","TargetEntityId","InitiatedByUserId","InitiatedByUsername",
            "RequiredApprovals","CurrentApprovals","Status","CreatedAt","ExpiresAt","ParametersJson","ApprovalsJson","TenantId")
        VALUES ('{BadCeremony}','RevokeCa','x','','{Operator}','operator',1,1,'Executed',now(),now(),'{parametersJson}','[]',NULL);
        """;

    /// <summary>
    /// Each S6 precondition refuses its own shape, names it, and rolls back: S6 is not recorded,
    /// the tables keep their tenant names and the groups their old ones.
    /// </summary>
    [RequiresEnvironmentTheory(ServerVariable)]
    [MemberData(nameof(RefusedRenames))]
    public async Task A_precondition_refuses_the_rename_and_nothing_of_it_is_applied(string precondition, string offendingSql, string expected)
    {
        var failure = await FoldAsync(Seed030Sql + SeedFoldSql + offendingSql, RenameTenantToSpace, async app =>
        {
            var applied = await app.Database.GetAppliedMigrationsAsync();
            Assert.DoesNotContain(applied, m => m.EndsWith("_" + RenameTenantToSpace, StringComparison.Ordinal));
            Assert.Contains(applied, m => m.EndsWith("_" + InstanceUniqueCaNames, StringComparison.Ordinal));
            Assert.Equal(1, await ScalarAsync(app, "SELECT count(*) FROM pg_catalog.pg_class WHERE relname = 'Tenants' AND relnamespace = 'public'::regnamespace"));
            Assert.Equal(0, await ScalarAsync(app, "SELECT count(*) FROM pg_catalog.pg_class WHERE relname = 'Spaces' AND relnamespace = 'public'::regnamespace"));
            Assert.Equal(1, await ScalarAsync(app, $"SELECT count(*) FROM \"CaGroups\" WHERE \"Id\" = '{OrgAdminGroup}' AND \"Name\" = 'org-acme-admin'"));
            Assert.Equal(1, await ScalarAsync(app, $"SELECT count(*) FROM \"KeyCeremonies\" WHERE \"Id\" = '{ExecutedCeremony}' AND \"ParametersJson\" LIKE '%\"tenantId\"%'"));
        });

        Assert.NotNull(failure);
        Assert.EndsWith("_" + RenameTenantToSpace, failure!.Migration, StringComparison.Ordinal);
        var raised = Assert.IsType<PostgresException>(failure.Error.GetBaseException());
        Assert.True(raised.MessageText.Contains(expected, StringComparison.Ordinal), $"{precondition}: {raised.MessageText}");
    }

    /// <summary>
    /// A closed ceremony whose stored names hold the JSON escape <c>\u0000</c>, which jsonb rejects,
    /// does not block the rename: each such escape becomes U+FFFD, here and in a ceremony naming no
    /// tenant, an escaped backslash before <c>u0000</c> is left alone, and the row reads.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public async Task A_nul_escape_in_stored_parameters_is_neutralised_and_the_rename_succeeds()
    {
        var identity = F.Legacy.ControlledUserChange.Replace(@"""Identity"":null", """
            "Identity":{"FirstName":"Bob\u0000\u0000","LastName":"O\\u0000Neil","DisplayName":"x\\\u0000y"}
            """, StringComparison.Ordinal);
        Assert.NotEqual(F.Legacy.ControlledUserChange, identity);
        const string ssh = """{"Name":"a\u0000b","KeyType":"ed25519"}""";
        var seed = $"""
            INSERT INTO "KeyCeremonies" ("Id","OperationType","Description","TargetEntityId","InitiatedByUserId","InitiatedByUsername",
                "RequiredApprovals","CurrentApprovals","Status","CreatedAt","ExpiresAt","ParametersJson","ApprovalsJson","TenantId")
            VALUES ('{NulCeremony}','ControlledUserChange','x','','{Operator}','operator',1,1,'Executed',now(),now(),'{identity}','[]','{OrgTenant}'),
                   ('{NulSshCeremony}','CreateSshCa','x','','{Operator}','operator',1,0,'Rejected',now(),now(),'{ssh}','[]',NULL);
            """;

        var failure = await FoldAsync(Seed030Sql + SeedFoldSql + seed, RenameTenantToSpace, async app =>
        {
            Assert.Contains(await app.Database.GetAppliedMigrationsAsync(), m => m.EndsWith("_" + RenameTenantToSpace, StringComparison.Ordinal));
            var fffd = (char)0xFFFD;
            var stored = await TextAsync(app,
                $"SELECT \"ParametersJson\" FROM \"KeyCeremonies\" WHERE \"Id\" = '{NulCeremony}' AND \"Status\" = 'Executed' AND (\"ParametersJson\"::jsonb ->> 'SpaceId') = '{F.SpaceA}'");
            var controlled = CeremonyParametersJson.Read<ControlledUserChangeParameters>(stored)!;
            Assert.Equal((F.SpaceA, F.SpaceB), (controlled.SpaceId, controlled.MintedTierSpaceId));
            Assert.Equal($"Bob{fffd}{fffd}", controlled.Identity!.FirstName);
            Assert.Equal(@"O\u0000Neil", controlled.Identity.LastName);
            Assert.Equal(@"x\" + fffd + "y", controlled.Identity.DisplayName);

            var other = await TextAsync(app, $"SELECT \"ParametersJson\" FROM \"KeyCeremonies\" WHERE \"Id\" = '{NulSshCeremony}' AND \"Status\" = 'Rejected'");
            Assert.Equal($"a{fffd}b", CeremonyParametersJson.Read<SshKeyCeremonyParameters>(other)!.Name);
            Assert.Equal(0, await ScalarAsync(app,
                $"SELECT count(*) FROM \"KeyCeremonies\" WHERE \"ParametersJson\" ~ '{RenameMigration.NulEscapePattern}'"));
        });
        Assert.Null(failure);
    }

    public static TheoryData<string, string, string> RefusedUniqueness() => new()
    {
        { "P1", $"UPDATE \"CertificateAuthorities\" SET \"Label\" = 'acme-root' WHERE \"Id\" = '{SshCa}';",
            "This instance has 1 CA label(s) used by more than one CA, counting soft-deleted CAs: acme-root (Acme), acme-root (instance)." },
        { "P1 deleted", "INSERT INTO \"CertificateAuthorities\" (\"Id\",\"Name\",\"Label\",\"IsDefault\",\"Type\",\"IsEnabled\",\"KeyStorageType\",\"IsSshCa\",\"TenantId\",\"IsDeleted\") "
            + $"VALUES (gen_random_uuid(),'Old Root','acme-root',false,'Root',false,'Software',false,'{SystemTenant}',true);",
            "acme-root (Acme), acme-root (instance, deleted)" },
        { "P2", $"UPDATE \"CertificateAuthorities\" SET \"Label\" = 'Acme-Root' WHERE \"Id\" = '{SshCa}';",
            "This instance has 1 CA label(s) that differ from another CA's label only in case, counting soft-deleted CAs: |acme-root (Acme)|Acme-Root (instance)" },
        { "P3", $"UPDATE \"CertificateAuthorities\" SET \"Name\" = 'Acme Root CA' WHERE \"Id\" = '{SshCa}';",
            "This instance has 1 CA name(s) used by more than one CA, counting soft-deleted CAs: Acme Root CA (Acme), Acme Root CA (instance)." },
        { "P4", SeedForeignProtocolConfigsSql,
            "This instance has 1 enabled protocol configuration(s) whose signing profile does not issue from the configuration's CA: acme-root EST uses 'Orphan Signing'. |point the protocol at that CA's own signing profile, or disable the protocol" },
        { "P5", SeedForeignTemplatesSql,
            "This instance has 1 enabled certificate template(s) whose signing profile does not issue from the template's CA: 'Workstation' on acme-root uses 'Orphan Signing'. |From 0.4.0 MSAE refuses such a template." },
    };

    /// <summary>
    /// Each S4 precondition refuses its own shape (P1-P3 counting soft-deleted CAs, P4 and P5 only
    /// enabled rows), names the offenders, and rolls back: S4 is not recorded and the old
    /// indexes and the quota columns are still there.
    /// </summary>
    [RequiresEnvironmentTheory(ServerVariable)]
    [MemberData(nameof(RefusedUniqueness))]
    public async Task A_precondition_refuses_the_upgrade_and_nothing_of_it_is_applied(string precondition, string offendingSql, string expected)
    {
        var failure = await FoldAsync(Seed030Sql + SeedFoldSql + offendingSql, InstanceUniqueCaNames, async app =>
        {
            Assert.DoesNotContain(await app.Database.GetAppliedMigrationsAsync(), m => m.EndsWith("_" + InstanceUniqueCaNames, StringComparison.Ordinal));
            Assert.Equal(1, await ScalarAsync(app, "SELECT count(*) FROM pg_catalog.pg_indexes WHERE indexname = 'IX_CertificateAuthorities_TenantId_Label'"));
            Assert.Equal(0, await ScalarAsync(app, "SELECT count(*) FROM pg_catalog.pg_indexes WHERE indexname = 'IX_CertificateAuthorities_Label'"));
            Assert.Equal(1, await ScalarAsync(app, "SELECT count(*) FROM information_schema.columns WHERE table_name = 'Tenants' AND column_name = 'MaxUsers'"));
        });

        Assert.NotNull(failure);
        Assert.EndsWith("_" + InstanceUniqueCaNames, failure!.Migration, StringComparison.Ordinal);
        var raised = Assert.IsType<PostgresException>(failure.Error.GetBaseException());
        foreach (var fragment in expected.Split('|'))
            Assert.True(raised.MessageText.Contains(fragment, StringComparison.Ordinal), $"{precondition}: {raised.MessageText}");
    }

    [RequiresEnvironmentFact(ServerVariable)]
    public async Task A_fresh_database_migrates_and_the_fold_changes_nothing()
    {
        var server = Environment.GetEnvironmentVariable(ServerVariable)!;
        var appName = $"modularca_upgrade_app_{Guid.NewGuid().ToString("N")[..12]}";
        await CreateDatabaseAsync(server, appName);
        try
        {
            await using var app = CreateApp(WithDatabase(server, appName));
            await MigrateThroughAsync(app, FoldSystemTenant);
            Assert.Equal(0, await ScalarAsync(app, "SELECT count(*) FROM \"Tenants\""));
            // Bootstrap seeds the policy with the wizard's values; the fold must not pre-empt it.
            Assert.Equal(0, await ScalarAsync(app, "SELECT count(*) FROM \"SecurityPolicy\""));
            await MigrateToLatestAsync(app, "application");
        }
        finally
        {
            NpgsqlConnection.ClearAllPools();
            await DropDatabaseAsync(server, appName);
        }
    }

    [RequiresEnvironmentFact(ServerVariable)]
    public async Task An_upgrade_without_a_security_policy_row_gets_one_with_the_system_tenants_values()
    {
        var failure = await FoldAsync(Seed030Sql, FoldSystemTenant, async app =>
        {
            var defaults = new ModularCA.Shared.Entities.SecurityPolicyEntity();
            Assert.Equal(1, await ScalarAsync(app, "SELECT count(*) FROM \"SecurityPolicy\""));
            Assert.Equal(1, await ScalarAsync(app,
                $"SELECT count(*) FROM \"SecurityPolicy\" WHERE \"MaxFailedLoginAttempts\" = {defaults.MaxFailedLoginAttempts} "
                + $"AND \"KeystoreScryptN\" = {defaults.KeystoreScryptN} AND \"UserQuorum\" = {defaults.UserQuorum} "
                + "AND \"RequireKeyCeremony\" AND \"CeremonyRequiredApprovals\" = 3 AND \"UserCeremonyRequiredApprovals\" = 2"));
        });
        Assert.Null(failure);
    }

    public static TheoryData<string, string, string> RefusedFolds() => new()
    {
        { "P1", $"INSERT INTO \"Tenants\" (\"Id\",\"Name\",\"Slug\",\"IsEnabled\",\"IsSystemTenant\",\"CanBeDeleted\",\"CreatedAt\",\"MaxCertificateAuthorities\",\"MaxCertificatesTotal\",\"MaxUsers\",\"MaxValidityDays\",\"ValidityCeilingBehavior\",\"RequireKeyCeremony\",\"CeremonyRequiredApprovals\",\"IsDeleted\") VALUES (gen_random_uuid(),'System 2','system-2',true,true,false,now(),0,0,0,0,0,true,2,true);",
            "This instance has 2 system tenant(s)" },
        { "P2", SeedSecondOrganisationSql, "This instance has 2 organisation tenants (Acme, Globex)" },
        { "P3", SeedSecurityPolicySql, "This instance has 2 SecurityPolicy rows" },
        { "P4", $"INSERT INTO \"KeyCeremonies\" (\"Id\",\"OperationType\",\"Description\",\"TargetEntityId\",\"InitiatedByUserId\",\"InitiatedByUsername\",\"RequiredApprovals\",\"CurrentApprovals\",\"Status\",\"CreatedAt\",\"ExpiresAt\",\"ParametersJson\",\"ApprovalsJson\",\"TenantId\") VALUES (gen_random_uuid(),'ControlledUserChange','x','','{Operator}','operator',1,0,'Pending',now(),now() + interval '1 day','{{\"MintedTierTenantId\":\"{SystemTenant.ToString().ToUpperInvariant()}\"}}','[]',NULL);",
            "This instance has 1 open ceremony(ies) that name the system tenant" },
        { "P5", $"INSERT INTO \"UserCapabilityGrants\" (\"Id\",\"UserId\",\"Capability\",\"TenantId\",\"GrantedAt\") VALUES (gen_random_uuid(),'{Operator}','system.manage','{SystemTenant}',now());",
            "This instance has 1 capability(ies) and 0 role assignment(s)" },
        { "P6", $"UPDATE \"Users\" SET \"ServiceScopeCaId\" = NULL WHERE \"Id\" = '{ServiceIdentity}';",
            "service identity(ies) scoped to the whole system tenant (svc-signing)" },
        { "P7", $"INSERT INTO \"CaGroupMembers\" (\"Id\",\"GroupId\",\"UserId\",\"AddedAt\") VALUES (gen_random_uuid(),'{OrgSystemAdmin}','{Operator}',now());",
            "have 1 member(s) and 0 access badge source(s)" },
        { "P8", $"UPDATE \"CaGroups\" SET \"TenantId\" = '{OrgTenant}' WHERE \"Id\" = '{SysCaAdminGroup}';",
            "system_system-signing-ca_admin" },
        { "P9", $"INSERT INTO \"CertProfiles\" (\"Id\",\"Name\",\"Description\",\"IsCaProfile\",\"KeyUsages\",\"ExtendedKeyUsages\",\"AllowedKeyAlgorithms\",\"AllowedKeySizes\",\"AllowedSignatureAlgorithms\",\"CreatedAt\",\"Revision\",\"UpdatedAt\",\"CanBeDeleted\",\"ProfileHash\",\"CtEnabled\",\"AllowWildcard\",\"InheritanceEnabled\",\"TenantId\") VALUES (gen_random_uuid(),'Loose System Profile','',false,'[]','[]','[]','[]','[]',now(),1,now(),true,'',false,false,false,'{SystemTenant}');",
            "certificate profile(s) on the system tenant that are bound to no CA (Loose System Profile)" },
    };

    /// <summary>
    /// Each precondition refuses its own shape, names it, and rolls back: the fold is not
    /// recorded and the system tenant is still there.
    /// </summary>
    [RequiresEnvironmentTheory(ServerVariable)]
    [MemberData(nameof(RefusedFolds))]
    public async Task A_precondition_refuses_the_fold_and_nothing_is_applied(string precondition, string offendingSql, string expected)
    {
        var failure = await FoldAsync(Seed030Sql + SeedFoldSql + offendingSql, FoldSystemTenant, async app =>
        {
            Assert.DoesNotContain(await app.Database.GetAppliedMigrationsAsync(), m => m.EndsWith("_" + FoldSystemTenant, StringComparison.Ordinal));
            Assert.Equal(1, await ScalarAsync(app, $"SELECT count(*) FROM \"Tenants\" WHERE \"Id\" = '{SystemTenant}'"));
            Assert.Equal(4, await ScalarAsync(app, "SELECT count(*) FROM \"CaGroups\" WHERE \"Name\" LIKE 'org-system-%'"));
        });

        Assert.NotNull(failure);
        Assert.EndsWith("_" + FoldSystemTenant, failure!.Migration, StringComparison.Ordinal);
        var raised = Assert.IsType<PostgresException>(failure.Error.GetBaseException());
        Assert.True(raised.MessageText.Contains(expected, StringComparison.Ordinal), $"{precondition}: {raised.MessageText}");
    }

    /// <summary>
    /// Applies the baseline, runs <paramref name="seedSql"/>, applies the later migrations through
    /// the one named <paramref name="through"/> with the control role's code, runs
    /// <paramref name="check"/> at that stage, and returns the failure, if any.
    /// </summary>
    private static async Task<MigrationFailure?> FoldAsync(string seedSql, string through, Func<ModularCADbContext, Task> check)
    {
        var server = Environment.GetEnvironmentVariable(ServerVariable)!;
        var appName = $"modularca_upgrade_app_{Guid.NewGuid().ToString("N")[..12]}";
        await CreateDatabaseAsync(server, appName);
        try
        {
            MigrationFailure? failure;
            await using (var app = CreateApp(WithDatabase(server, appName)))
            {
                await app.GetService<IMigrator>().MigrateAsync(AppBaseline);
                await ExecAsync(app, seedSql);
                failure = await SchemaVersionGate.ApplyPendingThroughAsync(app, await SchemaVersionGate.ReadAsync(app), MigrationId(app, through));
            }
            await using (var app = CreateApp(WithDatabase(server, appName)))
                await check(app);
            return failure;
        }
        finally
        {
            NpgsqlConnection.ClearAllPools();
            await DropDatabaseAsync(server, appName);
        }
    }

    [RequiresEnvironmentFact(RehearsalVariable)]
    public async Task A_restored_dump_migrates_to_latest_without_losing_rows()
    {
        await using var app = CreateApp(Environment.GetEnvironmentVariable(RehearsalVariable)!);
        var ownership = await SchemaOwnership.ProbeAsync(app.Database.GetDbConnection(), DatabaseKind.Application);
        Assert.True(ownership.IsSound,
            "The rehearsal copy does not reproduce staging's ownership; restore it with pg_restore --role=<service role> "
            + "and connect as the service role. " + SchemaOwnership.RefusalMessage(ownership, null));

        var before = await CountsAsync(app);
        await MigrateThroughAsync(app, InstanceUniqueCaNames);
        var after = await CountsAsync(app);

        // The fold removes the system tenant and its four org-system-* groups, and nothing else.
        Assert.Equal(before with { Tenants = before.Tenants - 1, Groups = before.Groups - 4 }, after);
        Assert.Equal(0, await ScalarAsync(app, "SELECT count(*) FROM information_schema.columns WHERE table_name = 'Tenants' AND column_name = 'IsSystemTenant'"));
        Assert.Equal(0, await ScalarAsync(app, "SELECT count(*) FROM \"CaGroups\" WHERE \"Name\" LIKE 'org-system-%'"));
        Assert.Equal(0, await ScalarAsync(app,
            "SELECT count(*) FROM information_schema.columns WHERE table_name = 'Tenants' AND column_name IN ('MaxCertificateAuthorities','MaxCertificatesTotal','MaxUsers')"));
        Assert.Equal(2, await ScalarAsync(app,
            "SELECT count(*) FROM pg_catalog.pg_indexes WHERE indexname IN ('IX_CertificateAuthorities_Label','IX_CertificateAuthorities_Name') AND indexdef LIKE 'CREATE UNIQUE INDEX%'"));
        await MigrateToLatestAsync(app, "application");

        var auditConnection = Environment.GetEnvironmentVariable(RehearsalAuditVariable);
        if (!string.IsNullOrWhiteSpace(auditConnection))
        {
            await using var audit = CreateAudit(auditConnection);
            var auditOwnership = await SchemaOwnership.ProbeAsync(audit.Database.GetDbConnection(), DatabaseKind.Audit);
            Assert.True(auditOwnership.IsSound, SchemaOwnership.RefusalMessage(auditOwnership, null));
            await MigrateToLatestAsync(audit, "audit");
        }
    }

    /// <summary>
    /// Brings <paramref name="db"/> to the latest migration through the control role's code path
    /// and asserts the schema is then current.
    /// </summary>
    private static async Task MigrateToLatestAsync(DbContext db, string name)
    {
        var state = await SchemaVersionGate.ReadAsync(db);
        Assert.Empty(state.Unknown);
        var failure = await SchemaVersionGate.ApplyPendingAsync(db, state);
        Assert.True(failure is null,
            failure is { } f ? SchemaVersionGate.MigrationFailedMessage(name, f.Migration, f.Error) : null);

        var after = await SchemaVersionGate.ReadAsync(db);
        Assert.Equal(SchemaVerdict.Current, SchemaVersionGate.Evaluate(after, appliesMigrations: false));
    }

    /// <summary>
    /// Applies the later migrations through the one named <paramref name="name"/> (no timestamp)
    /// with the control role's code, and asserts it is then the newest applied.
    /// </summary>
    private static async Task MigrateThroughAsync(DbContext db, string name)
    {
        var id = MigrationId(db, name);
        var state = await SchemaVersionGate.ReadAsync(db);
        Assert.Empty(state.Unknown);
        var failure = await SchemaVersionGate.ApplyPendingThroughAsync(db, state, id);
        Assert.True(failure is null,
            failure is { } f ? SchemaVersionGate.MigrationFailedMessage("application", f.Migration, f.Error) : null);
        Assert.Equal(id, (await SchemaVersionGate.ReadAsync(db)).Applied[^1]);
    }

    /// <summary>The full id of this build's migration named <paramref name="name"/>.</summary>
    private static string MigrationId(DbContext db, string name) =>
        Assert.Single(db.Database.GetMigrations(), m => m.EndsWith("_" + name, StringComparison.Ordinal));

    /// <summary>Row counts in SQL, so they read the same at any stage of the schema that still has these names.</summary>
    private static async Task<(long Tenants, long Cas, long Groups, long Users, long Members, long Certificates)> CountsAsync(DbContext db) => (
        await ScalarAsync(db, "SELECT count(*) FROM \"Tenants\""),
        await ScalarAsync(db, "SELECT count(*) FROM \"CertificateAuthorities\""),
        await ScalarAsync(db, "SELECT count(*) FROM \"CaGroups\""),
        await ScalarAsync(db, "SELECT count(*) FROM \"Users\""),
        await ScalarAsync(db, "SELECT count(*) FROM \"CaGroupMembers\""),
        await ScalarAsync(db, "SELECT count(*) FROM \"Certificates\""));

    /// <summary>A retired chain's tenant.</summary>
    private static readonly Guid[] AuditTenantChains = [OrgTenant, SystemTenant];

    /// <summary>
    /// Writes, in SQL against the baseline audit schema, three instance-chain records and two
    /// records on each of <see cref="AuditTenantChains"/>, each hashed by the real
    /// <see cref="AuditHashChainService.ComputeHash"/> and linked to the one before it.
    /// </summary>
    private static async Task SeedAuditChainsAsync(DbContext audit)
    {
        var start = new DateTime(2026, 9, 1, 8, 0, 0, DateTimeKind.Utc);
        var rows = new List<ModularCA.Shared.Entities.AuditLogEntity>();
        foreach (var (tenant, count) in new (Guid?, int)[] { (null, 3), (AuditTenantChains[0], 2), (AuditTenantChains[1], 2) })
        {
            string? previous = null;
            for (var i = 0; i < count; i++)
            {
                var row = new ModularCA.Shared.Entities.AuditLogEntity
                {
                    Id = Guid.NewGuid(),
                    Timestamp = start.AddMinutes(rows.Count).AddTicks(10 * (rows.Count + 1)),
                    ActorUserId = Operator,
                    ActorUsername = "operator",
                    ActionType = tenant is null ? "UserLogin" : "CertificateIssued",
                    TargetEntityType = tenant is null ? "User" : "Certificate",
                    TargetEntityId = Guid.NewGuid().ToString(),
                    DetailsJson = $$"""{"seq":{{i}}}""",
                    SourceIp = "192.0.2.10",
                    Success = true,
                    CertificateAuthorityId = tenant is null ? null : RootCa,
                    TenantId = tenant,
                    PreviousRecordHash = previous,
                    HashVersion = AuditHashChainService.CurrentHashVersion,
                };
                row.RecordHash = AuditHashChainService.ComputeHash(row, previous);
                previous = row.RecordHash;
                rows.Add(row);
            }
        }

        var connection = (NpgsqlConnection)audit.Database.GetDbConnection();
        await audit.Database.OpenConnectionAsync();
        try
        {
            foreach (var r in rows)
            {
                await using var command = new NpgsqlCommand(
                    "INSERT INTO \"AuditLogs\" (\"Id\",\"Timestamp\",\"ActorUserId\",\"ActorUsername\",\"ActionType\",\"TargetEntityType\",\"TargetEntityId\","
                    + "\"DetailsJson\",\"SourceIp\",\"Success\",\"ErrorMessage\",\"CertificateAuthorityId\",\"TenantId\",\"RecordHash\",\"HashVersion\",\"PreviousRecordHash\") "
                    + "VALUES (@id,@ts,@actor,@actorName,@action,@targetType,@targetId,@details,@ip,@success,@error,@ca,@tenant,@hash,@version,@previous)", connection);
                command.Parameters.AddWithValue("id", r.Id);
                command.Parameters.AddWithValue("ts", r.Timestamp);
                command.Parameters.AddWithValue("actor", (object?)r.ActorUserId ?? DBNull.Value);
                command.Parameters.AddWithValue("actorName", (object?)r.ActorUsername ?? DBNull.Value);
                command.Parameters.AddWithValue("action", r.ActionType);
                command.Parameters.AddWithValue("targetType", (object?)r.TargetEntityType ?? DBNull.Value);
                command.Parameters.AddWithValue("targetId", (object?)r.TargetEntityId ?? DBNull.Value);
                command.Parameters.AddWithValue("details", (object?)r.DetailsJson ?? DBNull.Value);
                command.Parameters.AddWithValue("ip", (object?)r.SourceIp ?? DBNull.Value);
                command.Parameters.AddWithValue("success", r.Success);
                command.Parameters.AddWithValue("error", DBNull.Value);
                command.Parameters.AddWithValue("ca", (object?)r.CertificateAuthorityId ?? DBNull.Value);
                command.Parameters.AddWithValue("tenant", (object?)r.TenantId ?? DBNull.Value);
                command.Parameters.AddWithValue("hash", r.RecordHash!);
                command.Parameters.AddWithValue("version", r.HashVersion!.Value);
                command.Parameters.AddWithValue("previous", (object?)r.PreviousRecordHash ?? DBNull.Value);
                await command.ExecuteNonQueryAsync();
            }
        }
        finally
        {
            await audit.Database.CloseConnectionAsync();
        }
    }

    /// <summary>
    /// Seals the retired chains as the control role's start does after the fold, then asserts
    /// every chain verifies with no break and each retired chain reports
    /// <see cref="RetiredChainState.Sealed"/>.
    /// </summary>
    private static async Task AssertAuditChainsSealedAsync(AuditDbContext audit)
    {
        var chains = new AuditHashChainService();
        Assert.Equal(AuditTenantChains.OrderBy(g => g), (await chains.SealRetiredChainsAsync(audit)).OrderBy(g => g));

        var instance = await chains.VerifyAsync(audit, null);
        Assert.Empty(instance.Breaks);
        Assert.Equal(3 + AuditTenantChains.Length, instance.RecordsVerified);
        foreach (var tenant in AuditTenantChains)
        {
            var retired = await chains.VerifyAsync(audit, tenant);
            Assert.Empty(retired.Breaks);
            Assert.True(retired.Sealed);
            Assert.Equal(3, retired.RecordsVerified);
            Assert.Equal(RetiredChainState.Sealed, (await chains.CheckRetiredChainAsync(audit, tenant)).State);
        }
    }

    /// <summary>
    /// Runs <paramref name="sql"/> as written, on the context's connection. Not through
    /// <c>ExecuteSqlRaw</c>, which reads braces (JSON in a seed) as format placeholders.
    /// </summary>
    internal static async Task ExecAsync(DbContext db, string sql)
    {
        var connection = db.Database.GetDbConnection();
        await db.Database.OpenConnectionAsync();
        try
        {
            await using var command = connection.CreateCommand();
            command.CommandText = sql;
            await command.ExecuteNonQueryAsync();
        }
        finally
        {
            await db.Database.CloseConnectionAsync();
        }
    }

    /// <summary>The first column of the first row of <paramref name="sql"/>, as text; empty for SQL null.</summary>
    private static async Task<string> TextAsync(DbContext db, string sql)
    {
        var connection = db.Database.GetDbConnection();
        await db.Database.OpenConnectionAsync();
        try
        {
            await using var command = connection.CreateCommand();
            command.CommandText = sql;
            return await command.ExecuteScalarAsync() is string text ? text : "";
        }
        finally
        {
            await db.Database.CloseConnectionAsync();
        }
    }

    /// <summary>The first column of every row of <paramref name="sql"/>, in ordinal order.</summary>
    private static async Task<List<string>> TextsAsync(DbContext db, string sql)
    {
        var connection = db.Database.GetDbConnection();
        await db.Database.OpenConnectionAsync();
        try
        {
            await using var command = connection.CreateCommand();
            command.CommandText = sql;
            var values = new List<string>();
            await using var reader = await command.ExecuteReaderAsync();
            while (await reader.ReadAsync())
                values.Add(reader.GetString(0));
            return values.Order(StringComparer.Ordinal).ToList();
        }
        finally
        {
            await db.Database.CloseConnectionAsync();
        }
    }

    /// <summary>The first column of the first row of <paramref name="sql"/>.</summary>
    internal static async Task<long> ScalarAsync(DbContext db, string sql)
    {
        var connection = db.Database.GetDbConnection();
        await db.Database.OpenConnectionAsync();
        try
        {
            await using var command = connection.CreateCommand();
            command.CommandText = sql;
            return Convert.ToInt64(await command.ExecuteScalarAsync());
        }
        finally
        {
            await db.Database.CloseConnectionAsync();
        }
    }

    /// <summary>A <c>db.yaml</c> instance for <paramref name="connectionString"/>.</summary>
    private static DbInstance Instance(string connectionString)
    {
        var b = new NpgsqlConnectionStringBuilder(connectionString);
        return new DbInstance
        {
            Host = b.Host ?? "localhost", Port = b.Port, Database = b.Database!, Username = b.Username ?? "postgres",
            Password = b.Password ?? "", SslMode = b.SslMode.ToString(),
        };
    }

    private static ModularCADbContext CreateApp(string connectionString) =>
        new(new DbContextOptionsBuilder<ModularCADbContext>().UseNpgsql(connectionString).Options);

    private static AuditDbContext CreateAudit(string connectionString) =>
        new(new DbContextOptionsBuilder<AuditDbContext>().UseNpgsql(connectionString).Options);

    private static string WithDatabase(string connectionString, string database) =>
        new NpgsqlConnectionStringBuilder(connectionString) { Database = database, Pooling = false }.ConnectionString;

    private static async Task CreateDatabaseAsync(string server, string name)
    {
        await using var connection = new NpgsqlConnection(server);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand($"CREATE DATABASE \"{name}\"", connection);
        await command.ExecuteNonQueryAsync();
    }

    private static async Task DropDatabaseAsync(string server, string name)
    {
        await using var connection = new NpgsqlConnection(server);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand($"DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)", connection);
        await command.ExecuteNonQueryAsync();
    }

    /// <summary>
    /// A 0.3.x instance as bootstrap leaves it, written against the baseline schema: the system
    /// tenant and one organisation tenant, a root CA in the organisation, a system group, a
    /// tenant-wide and a CA-scoped group, and one operator in two of them.
    /// </summary>
    internal static string Seed030Sql => $"""
        INSERT INTO "Tenants" ("Id","Name","Slug","Description","IsEnabled","IsSystemTenant","CanBeDeleted","CreatedAt",
            "MaxCertificateAuthorities","MaxCertificatesTotal","MaxUsers","MaxValidityDays","ValidityCeilingBehavior",
            "RequireKeyCeremony","CeremonyRequiredApprovals","UserCeremonyRequiredApprovals","IsDeleted")
        VALUES ('{SystemTenant}','System','system','Internal system tenant',true,true,false,now(),0,0,0,0,0,true,3,2,false),
               ('{OrgTenant}','Acme','acme','Primary tenant for Acme',true,false,false,now(),0,0,0,825,1,false,2,NULL,false);

        INSERT INTO "CertificateAuthorities" ("Id","Name","Label","IsDefault","Type","IsEnabled","KeyStorageType","IsSshCa","TenantId","IsDeleted")
        VALUES ('{RootCa}','Acme Root CA','acme-root',true,'Root',true,'Software',false,'{OrgTenant}',false);

        INSERT INTO "CaGroups" ("Id","Name","DisplayName","CertificateAuthorityId","TemplateName","IsSystemGroup","IsSystemTierSuper",
            "IsAutoGenerated","RequiredQuorum","MaxCertificates","MaxPendingRequests","CreatedAt","TenantId")
        VALUES ('{SystemGroup}','system-super','System Super',NULL,'Administrator',true,true,true,1,0,0,now(),'{SystemTenant}'),
               ('{OrgAdminGroup}','org-acme-admin','Org Acme Admin',NULL,'Administrator',false,false,true,1,0,0,now(),'{OrgTenant}'),
               ('{CaAdminGroup}','ca-acme-root-admin','CA acme-root Admin','{RootCa}','Administrator',false,false,true,1,0,0,now(),'{OrgTenant}');

        INSERT INTO "Users" ("Id","Username","Email","PasswordHash","PasswordNeverExpires","PasswordChangeOnNextLogon","FirstName",
            "LastName","IsActive","IsServiceIdentity","IsLocked","FailedLoginAttempts","CreatedAt","SecurityStamp","IsDeleted")
        VALUES ('{Operator}','operator','operator@acme.example','not-a-hash',false,false,'Op','Erator',true,false,false,0,now(),'stamp',false);

        INSERT INTO "CaGroupMembers" ("Id","GroupId","UserId","AddedAt")
        VALUES (gen_random_uuid(),'{OrgAdminGroup}','{Operator}',now()),
               (gen_random_uuid(),'{CaAdminGroup}','{Operator}',now());
        """;

    /// <summary>
    /// Everything the 0.4.0 S3 fold moves, on top of <see cref="Seed030Sql"/>: the security policy
    /// row, the system signing CA and an SSH CA with their groups, the other system groups with a
    /// group role, the four <c>org-system-*</c> groups with grants and a role but no members, a
    /// Kerberos realm and a custom role on the system tenant, a CA-scoped user grant, a CA-bound
    /// profile, an enrollment token, an executed ceremony whose parameters name the system tenant,
    /// and a CA-scoped service identity.
    /// </summary>
    internal static string SeedFoldSql => SeedSecurityPolicySql + $$"""

        INSERT INTO "CertificateAuthorities" ("Id","Name","Label","IsDefault","Type","IsEnabled","KeyStorageType","IsSshCa","TenantId","IsDeleted")
        VALUES ('{{SysCa}}','System Signing CA','system-signing-ca',false,'Root',true,'Software',false,'{{SystemTenant}}',false),
               ('{{SshCa}}','Ops SSH','ops-ssh',false,'SSH',true,'Software',true,'{{SystemTenant}}',false);

        INSERT INTO "CaGroups" ("Id","Name","DisplayName","CertificateAuthorityId","TemplateName","IsSystemGroup","IsSystemTierSuper",
            "IsAutoGenerated","RequiredQuorum","MaxCertificates","MaxPendingRequests","CreatedAt","TenantId")
        VALUES ('{{SysAdminGroup}}','system-admin','System Admin',NULL,'Administrator',true,false,true,1,0,0,now(),'{{SystemTenant}}'),
               ('{{SysOperatorGroup}}','system-operator','System Operator',NULL,'Operator',true,false,true,1,0,0,now(),'{{SystemTenant}}'),
               ('{{SysAuditorGroup}}','system-auditor','System Auditor',NULL,'Auditor',true,false,true,1,0,0,now(),'{{SystemTenant}}'),
               ('{{SysCaAdminGroup}}','system_system-signing-ca_admin','System Signing CA Admin','{{SysCa}}','Administrator',false,false,true,1,0,0,now(),'{{SystemTenant}}'),
               ('{{SshAdminGroup}}','ops-ssh-admin','Ops SSH Admin','{{SshCa}}','Administrator',false,false,true,1,0,0,now(),'{{SystemTenant}}'),
               ('{{OrgSystemAdmin}}','org-system-admin','Org System Admin',NULL,'Administrator',false,false,true,1,0,0,now(),'{{SystemTenant}}'),
               ('{{OrgSystemOperator}}','org-system-operator','Org System Operator',NULL,'Operator',false,false,true,1,0,0,now(),'{{SystemTenant}}'),
               ('{{OrgSystemAuditor}}','org-system-auditor','Org System Auditor',NULL,'Auditor',false,false,true,1,0,0,now(),'{{SystemTenant}}'),
               ('{{OrgSystemUser}}','org-system-user','Org System User',NULL,'Requester',false,false,true,1,0,0,now(),'{{SystemTenant}}');

        INSERT INTO "CapabilityGrants" ("Id","GroupId","Capability","GrantedAt")
        VALUES (gen_random_uuid(),'{{SysAdminGroup}}','system.manage',now()),
               (gen_random_uuid(),'{{OrgSystemAdmin}}','system.manage',now()),
               (gen_random_uuid(),'{{OrgSystemOperator}}','ca.manage',now());

        INSERT INTO "Roles" ("Id","Name","IsBuiltIn","CreatedAt","TenantId")
        VALUES ('{{BuiltInRole}}','Administrator',true,now(),NULL),
               ('{{CustomRole}}','Signing Custodian',false,now(),'{{SystemTenant}}');

        INSERT INTO "RoleAssignments" ("Id","RoleId","GroupId","TenantId","AssignedAt")
        VALUES ('{{SysAdminRoleAssignment}}','{{BuiltInRole}}','{{SysAdminGroup}}','{{SystemTenant}}',now()),
               (gen_random_uuid(),'{{BuiltInRole}}','{{OrgSystemAdmin}}','{{SystemTenant}}',now());

        INSERT INTO "UserCapabilityGrants" ("Id","UserId","Capability","TenantId","CertificateAuthorityId","GrantedAt")
        VALUES ('{{CaScopedGrant}}','{{Operator}}','ca.manage','{{SystemTenant}}','{{SysCa}}',now());

        INSERT INTO "KerberosRealms" ("Id","TenantId","Realm","DnsDomain","ServicePrincipal","EnrollmentUserId","AllowMachines","AllowUsers","IsEnabled","CreatedAt")
        VALUES ('{{Realm}}','{{SystemTenant}}','CORP.EXAMPLE','corp.example','HTTP/ca.example','{{Operator}}',true,true,true,now());

        INSERT INTO "CertProfiles" ("Id","Name","Description","IsCaProfile","KeyUsages","ExtendedKeyUsages","AllowedKeyAlgorithms",
            "AllowedKeySizes","AllowedSignatureAlgorithms","CreatedAt","Revision","UpdatedAt","CanBeDeleted","ProfileHash","CtEnabled",
            "AllowWildcard","InheritanceEnabled","TenantId","CertificateAuthorityId")
        VALUES ('{{BoundProfile}}','System Signing Leaf','bound to the signing CA',false,'[]','[]','[]','[]','[]',now(),1,now(),true,'',false,false,false,'{{SystemTenant}}','{{SysCa}}');

        INSERT INTO "EnrollmentTokens" ("Id","Token","CreatedByUserId","CreatedAt","ExpiresAt","MaxUses","UsesRemaining","IsRevoked","UsedForCmp","TenantId","CertificateAuthorityId")
        VALUES ('{{Token}}','token-hash','{{Operator}}',now(),now() + interval '1 day',1,1,false,false,'{{SystemTenant}}','{{SysCa}}');

        INSERT INTO "KeyCeremonies" ("Id","OperationType","Description","TargetEntityId","InitiatedByUserId","InitiatedByUsername",
            "RequiredApprovals","CurrentApprovals","Status","CreatedAt","ExpiresAt","ParametersJson","ApprovalsJson","TenantId")
        VALUES ('{{ExecutedCeremony}}','CreateRootCA','created long ago','','{{Operator}}','operator',2,2,'Executed',now(),now(),
            '{"tenantId":"{{SystemTenant}}"}','[]','{{SystemTenant}}');

        INSERT INTO "Users" ("Id","Username","Email","PasswordHash","PasswordNeverExpires","PasswordChangeOnNextLogon","FirstName",
            "LastName","IsActive","IsServiceIdentity","IsLocked","FailedLoginAttempts","CreatedAt","SecurityStamp","IsDeleted",
            "ServiceScopeTenantId","ServiceScopeCaId")
        VALUES ('{{ServiceIdentity}}','svc-signing','svc-signing@service-identity.invalid','',false,false,'','',true,true,false,0,now(),'stamp',false,
            '{{SystemTenant}}','{{SysCa}}');
        """;

    /// <summary>
    /// What the 0.4.0 S6 rename carries across, at the names of the stage before it: an open
    /// ceremony in every stored parameter shape, in the pre-0.4.0 casing each writer used (the
    /// legacy fixtures), the policy changes with operation type <c>TenantPolicyChange</c>; the
    /// space's other three <c>org-acme-*</c> groups, one display name in the long form and one
    /// customised, and a tenant-wide group whose name does not follow the space's slug; and a
    /// signer audit row with the old scope token. Run after <see cref="SeedFoldSql"/> at that stage.
    /// </summary>
    internal static string SeedRenameSql => $$"""
        INSERT INTO "KeyCeremonies" ("Id","OperationType","Description","TargetEntityId","InitiatedByUserId","InitiatedByUsername",
            "RequiredApprovals","CurrentApprovals","Status","CreatedAt","ExpiresAt","ParametersJson","ApprovalsJson","TenantId","CeremonyType")
        VALUES ('{{ControlledCeremony}}','ControlledUserChange','x','','{{Operator}}','operator',1,0,'Pending',now(),now() + interval '1 day','{{F.Legacy.ControlledUserChange}}','[]','{{OrgTenant}}',2),
               ('{{CaCeremony}}','CreateIntermediateCA','x','','{{Operator}}','operator',2,0,'Pending',now(),now() + interval '1 day','{{F.Legacy.KeyCeremony}}','[]','{{OrgTenant}}',0),
               ('{{SshCeremony}}','CreateSshCa','x','','{{Operator}}','operator',2,1,'Approved',now(),now() + interval '1 day','{{F.Legacy.SshKeyCeremony}}','[]','{{OrgTenant}}',0),
               ('{{RevokeCeremony}}','RevokeCa','x','{{RootCa}}','{{Operator}}','operator',2,0,'Pending',now(),now() + interval '1 day','{{F.Legacy.RevokeCa}}','[]','{{OrgTenant}}',0),
               ('{{PolicyCeremony}}','TenantPolicyChange','x','{{OrgTenant}}','{{Operator}}','operator',3,0,'Pending',now(),now() + interval '1 day','{{F.Legacy.TenantPolicyChange}}','[]','{{OrgTenant}}',1),
               ('{{InstancePolicyCeremony}}','InstancePolicyChange','x','instance','{{Operator}}','operator',3,0,'Pending',now(),now() + interval '1 day','{{F.Legacy.InstancePolicyChange}}','[]',NULL,3),
               ('{{QuorumCeremony}}','TenantPolicyChange','x','{{OrgTenant}}','{{Operator}}','operator',2,0,'Pending',now(),now() + interval '1 day','{{F.Legacy.CaUserQuorumChange}}','[]','{{OrgTenant}}',1);

        INSERT INTO "CaGroups" ("Id","Name","DisplayName","CertificateAuthorityId","TemplateName","IsSystemGroup","IsSystemTierSuper",
            "IsAutoGenerated","RequiredQuorum","MaxCertificates","MaxPendingRequests","CreatedAt","TenantId")
        VALUES ('{{OrgOperatorGroup}}','org-acme-operator','Org Acme Operator',NULL,'Operator',false,false,true,1,0,0,now(),'{{OrgTenant}}'),
               ('{{OrgAuditorGroup}}','org-acme-auditor','Organisation Acme Auditor',NULL,'Auditor',false,false,true,1,0,0,now(),'{{OrgTenant}}'),
               ('{{OrgUserGroup}}','org-acme-user','Acme PKI users',NULL,'Requester',false,false,true,1,0,0,now(),'{{OrgTenant}}'),
               ('{{MismatchedOrgGroup}}','org-globex-admin','Org Globex Admin',NULL,'Administrator',false,false,false,1,0,0,now(),'{{OrgTenant}}');

        INSERT INTO "SignerAudit" ("Id","At","Operation","Caller","Purpose","Outcome","CaId","TenantId","EffectiveScope")
        VALUES (gen_random_uuid(),now(),'Sign','control','Certificate','allowed','{{RootCa}}','{{OrgTenant}}','tenant');
        """;

    /// <summary>The one security policy row bootstrap seeds, at the entity's defaults.</summary>
    internal static string SeedSecurityPolicySql => """

        INSERT INTO "SecurityPolicy" ("Id","MaxFailedLoginAttempts","LockoutMinutes","SessionIdleTimeoutMinutes","MaxConcurrentSessions",
            "MaxSessionLifetimeDays","LoginResponseDelayMs","AllowSystemSuperSelfApproval","RequireMtlsOcspCheck","StepUpTokenTtlSeconds",
            "MfaSessionTtlSeconds","WebAuthnChallengeTtlSeconds","RequireWebAuthnUserVerification","StepUpFailureThreshold",
            "StepUpFailureWindowSeconds","AllowCaDirectSigning","RequireNoCheckExtension","RequireSignedRequests",
            "DefaultGoodResponseTtlMinutes","DefaultRevokedResponseTtlMinutes","MaxSingleRequestsPerRequest","KeystoreScryptN",
            "KeystoreScryptR","KeystoreScryptP","UserQuorum","UpdatedAt")
        VALUES (gen_random_uuid(),5,15,30,3,14,500,false,false,90,300,120,true,5,300,false,false,false,60,15,4,65536,8,1,1,now());
        """;

    /// <summary>A signing profile that issues from no CA.</summary>
    internal static string SeedOrphanSigningProfileSql => $"""

        INSERT INTO "SigningProfiles" ("Id","Name","Description","AllowedAlgorithms","AllowedEKUs","IsDefault","CreatedAt","Revision",
            "UpdatedAt","ExtendedKeyUsageCritical","InhibitAnyPolicy","InheritanceEnabled","IssuerId")
        VALUES ('{ForeignSigningProfile}','Orphan Signing','','[]','[]',false,now(),1,now(),false,false,false,NULL);
        """;

    /// <summary>
    /// An enabled EST and a disabled SCEP configuration of the root CA naming
    /// <see cref="SeedOrphanSigningProfileSql"/>'s profile: the enabled one is what the 0.4.0 S4
    /// migration's P4 refuses. Run after <see cref="Seed030Sql"/> and that seed.
    /// </summary>
    internal static string SeedForeignProtocolConfigsSql => SeedOrphanSigningProfileSql + $"""

        INSERT INTO "CaProtocolConfigs" ("Id","CaId","Protocol","IsEnabled","IsPublicVisible","SigningProfileId","CertProfileId",
            "EstRequireClientCert","EstHttpAuthEnabled","ScepChallengeRequired","CmpRequireSignature","AcmeRequireEab",
            "AcmeAllowPrivateAddressValidation","OcspSignResponses","MsaeAllowUsernameToken","MsaeAllowKerberos")
        VALUES (gen_random_uuid(),'{RootCa}','EST',true,true,'{ForeignSigningProfile}',NULL,false,false,false,false,false,false,false,false,false),
               (gen_random_uuid(),'{RootCa}','SCEP',false,true,'{ForeignSigningProfile}',NULL,false,false,false,false,false,false,false,false,false);
        """;

    /// <summary>
    /// An enabled and a disabled certificate template of the root CA naming
    /// <see cref="SeedOrphanSigningProfileSql"/>'s profile: the enabled one is what P5 refuses.
    /// Run after <see cref="SeedFoldSql"/>, whose bound profile they use.
    /// </summary>
    internal static string SeedForeignTemplatesSql => SeedOrphanSigningProfileSql + $"""

        INSERT INTO "CertificateTemplates" ("Id","Name","CaId","CertProfileId","SigningProfileId","IsEnabled","MsaeMajorVersion",
            "MsaeMinorVersion","MsaeMachineType","CreatedAt")
        VALUES (gen_random_uuid(),'Workstation','{RootCa}','{BoundProfile}','{ForeignSigningProfile}',true,100,0,true,now()),
               (gen_random_uuid(),'Retired','{RootCa}','{BoundProfile}','{ForeignSigningProfile}',false,100,0,true,now());
        """;

    /// <summary>
    /// One tenant hostname on the organisation tenant, issued by its root CA, with no certificate
    /// yet and routed nowhere: the row the 0.4.0 S2 migration refuses to drop. Run after
    /// <see cref="Seed030Sql"/>.
    /// </summary>
    internal static string SeedTenantHostnameSql => $"""

        INSERT INTO "TenantHostnames" ("Id","TenantId","Hostname","IssuingCaId","CertificateId","CreatedAt","Notes","NodeUpstream")
        VALUES (gen_random_uuid(),'{OrgTenant}','ca.acme.example','{RootCa}',NULL,now(),NULL,NULL);
        """;
}
