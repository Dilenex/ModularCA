using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using ModularCA.Database;
using ModularCA.Shared.Models.Config;
using Npgsql;
using Xunit;

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
/// migrations change), then applies every later migration through the same code the control
/// role uses and checks the result. The databases are dropped afterwards.
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

    [RequiresEnvironmentFact(ServerVariable)]
    public async Task Baseline_with_a_030_shape_migrates_to_latest()
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

                await MigrateToLatestAsync(app, "application");

                Assert.Equal(0, await ScalarAsync(app, "SELECT count(*) FROM pg_catalog.pg_class WHERE relname = 'TenantHostnames'"));
                Assert.Contains(await app.Database.GetAppliedMigrationsAsync(), m => m.EndsWith("_" + RetireTenantHostnames, StringComparison.Ordinal));
                Assert.Contains(await app.Database.GetAppliedMigrationsAsync(), m => m.EndsWith("_" + FoldSystemTenant, StringComparison.Ordinal));
                await AssertFoldedAsync(app);
            }

            await using (var audit = CreateAudit(WithDatabase(server, auditName)))
            {
                await audit.GetService<IMigrator>().MigrateAsync(AuditBaseline);
                Assert.Equal([AuditBaseline], await audit.Database.GetAppliedMigrationsAsync());
                await MigrateToLatestAsync(audit, "audit");
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
    /// What the fold must leave: no system tenant and the column gone; every row that named it on
    /// the instance (a null tenant); the org-system-* groups, their grants and roles gone; the
    /// instance policy equal to the SYSTEM tenant's values (scopes are independent, nothing merged)
    /// and the organisation's unchanged; RESTRICT on the tenant foreign keys; and the instance's own
    /// label and name uniqueness.
    /// </summary>
    private static async Task AssertFoldedAsync(ModularCADbContext app)
    {
        var tenants = await app.Tenants.IgnoreQueryFilters().AsNoTracking().ToListAsync();
        var org = Assert.Single(tenants);
        Assert.Equal(OrgTenant, org.Id);
        Assert.Equal(0, await ScalarAsync(app, "SELECT count(*) FROM information_schema.columns WHERE table_name = 'Tenants' AND column_name = 'IsSystemTenant'"));

        Assert.False(org.RequireKeyCeremony);
        Assert.Equal(2, org.CeremonyRequiredApprovals);
        Assert.Null(org.UserCeremonyRequiredApprovals);
        Assert.Equal(825, org.MaxValidityDays);
        Assert.Equal(ModularCA.Shared.Enums.ValidityCeilingBehavior.Refuse, org.ValidityCeilingBehavior);

        var policy = await app.SecurityPolicies.AsNoTracking().SingleAsync();
        Assert.True(policy.RequireKeyCeremony);
        Assert.Equal(3, policy.CeremonyRequiredApprovals);
        Assert.Equal(2, policy.UserCeremonyRequiredApprovals);
        Assert.Equal(0, policy.MaxValidityDays);
        Assert.Equal(ModularCA.Shared.Enums.ValidityCeilingBehavior.Shorten, policy.ValidityCeilingBehavior);
        Assert.Equal(1, policy.UserQuorum);

        var cas = await app.CertificateAuthorities.IgnoreQueryFilters().AsNoTracking().ToDictionaryAsync(c => c.Id);
        Assert.Equal(OrgTenant, cas[RootCa].TenantId);
        Assert.Null(cas[SysCa].TenantId);
        Assert.Null(cas[SshCa].TenantId);

        var groups = await app.CaGroups.IgnoreQueryFilters().AsNoTracking().ToDictionaryAsync(g => g.Id);
        Assert.Equal(8, groups.Count);
        foreach (var id in new[] { SystemGroup, SysAdminGroup, SysOperatorGroup, SysAuditorGroup, SysCaAdminGroup, SshAdminGroup })
            Assert.Null(groups[id].TenantId);
        Assert.Equal(OrgTenant, groups[OrgAdminGroup].TenantId);
        Assert.Equal(OrgTenant, groups[CaAdminGroup].TenantId);
        foreach (var id in new[] { OrgSystemAdmin, OrgSystemOperator, OrgSystemAuditor, OrgSystemUser })
            Assert.False(groups.ContainsKey(id));
        Assert.Equal(0, await ScalarAsync(app, $"SELECT count(*) FROM \"CapabilityGrants\" WHERE \"GroupId\" IN ('{OrgSystemAdmin}','{OrgSystemOperator}')"));
        Assert.Equal(0, await ScalarAsync(app, $"SELECT count(*) FROM \"RoleAssignments\" WHERE \"GroupId\" = '{OrgSystemAdmin}'"));
        Assert.Equal(1, await ScalarAsync(app, $"SELECT count(*) FROM \"CapabilityGrants\" WHERE \"GroupId\" = '{SysAdminGroup}'"));

        Assert.Null((await app.KerberosRealms.AsNoTracking().SingleAsync(r => r.Id == Realm)).TenantId);
        Assert.Null((await app.Roles.AsNoTracking().SingleAsync(r => r.Id == CustomRole)).TenantId);
        Assert.Null((await app.RoleAssignments.AsNoTracking().SingleAsync(r => r.Id == SysAdminRoleAssignment)).TenantId);
        var grant = await app.UserCapabilityGrants.AsNoTracking().SingleAsync(g => g.Id == CaScopedGrant);
        Assert.Null(grant.TenantId);
        Assert.Equal(SysCa, grant.CertificateAuthorityId);
        var profile = await app.CertProfiles.IgnoreQueryFilters().AsNoTracking().SingleAsync(p => p.Id == BoundProfile);
        Assert.Null(profile.TenantId);
        Assert.Equal(SysCa, profile.CertificateAuthorityId);
        Assert.Null((await app.EnrollmentTokens.AsNoTracking().SingleAsync(t => t.Id == Token)).TenantId);
        var ceremony = await app.KeyCeremonies.AsNoTracking().SingleAsync(c => c.Id == ExecutedCeremony);
        Assert.Null(ceremony.TenantId);
        Assert.Contains(SystemTenant.ToString(), ceremony.ParametersJson);
        var identity = await app.Users.IgnoreQueryFilters().AsNoTracking().SingleAsync(u => u.Id == ServiceIdentity);
        Assert.Null(identity.ServiceScopeTenantId);
        Assert.Equal(SysCa, identity.ServiceScopeCaId);
        Assert.Equal(1, await app.Users.IgnoreQueryFilters().CountAsync(u => u.Id == Operator));
        Assert.Equal(2, await app.CaGroupMembers.CountAsync(m => m.UserId == Operator));

        foreach (var fk in new[] { "FK_CertificateAuthorities_Tenants_TenantId", "FK_KerberosRealms_Tenants_TenantId", "FK_Roles_Tenants_TenantId",
                     "FK_RoleAssignments_Tenants_TenantId", "FK_UserCapabilityGrants_Tenants_TenantId" })
            Assert.Equal(1, await ScalarAsync(app, $"SELECT count(*) FROM pg_catalog.pg_constraint WHERE conname = '{fk}' AND confdeltype = 'r'"));
        foreach (var index in new[] { "IX_CertificateAuthorities_Label_Instance", "IX_CertificateAuthorities_Name_Instance" })
            Assert.Equal(1, await ScalarAsync(app,
                $"SELECT count(*) FROM pg_catalog.pg_indexes WHERE indexname = '{index}' AND indexdef LIKE 'CREATE UNIQUE INDEX%' AND indexdef LIKE '%WHERE (\"TenantId\" IS NULL)%'"));

        // A second instance CA may not take the system signing CA's label.
        var duplicate = await Assert.ThrowsAsync<PostgresException>(() => ExecAsync(app,
            "INSERT INTO \"CertificateAuthorities\" (\"Id\",\"Name\",\"Label\",\"IsDefault\",\"Type\",\"IsEnabled\",\"KeyStorageType\",\"IsSshCa\",\"TenantId\",\"IsDeleted\") "
            + "VALUES (gen_random_uuid(),'Another','system-signing-ca',false,'Root',true,'Software',false,NULL,false)"));
        Assert.Equal(PostgresErrorCodes.UniqueViolation, duplicate.SqlState);
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
            await MigrateToLatestAsync(app, "application");
            Assert.Equal(0, await ScalarAsync(app, "SELECT count(*) FROM \"Tenants\""));
            // Bootstrap seeds the policy with the wizard's values; the fold must not pre-empt it.
            Assert.Equal(0, await ScalarAsync(app, "SELECT count(*) FROM \"SecurityPolicy\""));
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
        var failure = await FoldAsync(Seed030Sql, async app =>
        {
            var policy = await app.SecurityPolicies.AsNoTracking().SingleAsync();
            var defaults = new ModularCA.Shared.Entities.SecurityPolicyEntity();
            Assert.Equal(defaults.MaxFailedLoginAttempts, policy.MaxFailedLoginAttempts);
            Assert.Equal(defaults.KeystoreScryptN, policy.KeystoreScryptN);
            Assert.Equal(defaults.UserQuorum, policy.UserQuorum);
            Assert.True(policy.RequireKeyCeremony);
            Assert.Equal(3, policy.CeremonyRequiredApprovals);
            Assert.Equal(2, policy.UserCeremonyRequiredApprovals);
        });
        Assert.Null(failure);
    }

    public static TheoryData<string, string, string> RefusedFolds() => new()
    {
        { "P1", $"INSERT INTO \"Tenants\" (\"Id\",\"Name\",\"Slug\",\"IsEnabled\",\"IsSystemTenant\",\"CanBeDeleted\",\"CreatedAt\",\"MaxCertificateAuthorities\",\"MaxCertificatesTotal\",\"MaxUsers\",\"MaxValidityDays\",\"ValidityCeilingBehavior\",\"RequireKeyCeremony\",\"CeremonyRequiredApprovals\",\"IsDeleted\") VALUES (gen_random_uuid(),'System 2','system-2',true,true,false,now(),0,0,0,0,0,true,2,true);",
            "This instance has 2 system tenant(s)" },
        { "P2", $"INSERT INTO \"Tenants\" (\"Id\",\"Name\",\"Slug\",\"IsEnabled\",\"IsSystemTenant\",\"CanBeDeleted\",\"CreatedAt\",\"MaxCertificateAuthorities\",\"MaxCertificatesTotal\",\"MaxUsers\",\"MaxValidityDays\",\"ValidityCeilingBehavior\",\"RequireKeyCeremony\",\"CeremonyRequiredApprovals\",\"IsDeleted\") VALUES (gen_random_uuid(),'Globex','globex',false,false,true,now(),0,0,0,0,0,true,2,false);",
            "This instance has 2 organisation tenants (Acme, Globex)" },
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
        var failure = await FoldAsync(Seed030Sql + SeedFoldSql + offendingSql, async app =>
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
    /// Applies the baseline, runs <paramref name="seedSql"/>, applies every later migration through
    /// the control role's code, runs <paramref name="check"/>, and returns the failure, if any.
    /// </summary>
    private static async Task<MigrationFailure?> FoldAsync(string seedSql, Func<ModularCADbContext, Task> check)
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
                failure = await SchemaVersionGate.ApplyPendingAsync(app, await SchemaVersionGate.ReadAsync(app));
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
        await MigrateToLatestAsync(app, "application");
        var after = await CountsAsync(app);

        // The fold removes the system tenant and its four org-system-* groups, and nothing else.
        Assert.Equal(before with { Tenants = before.Tenants - 1, Groups = before.Groups - 4 }, after);
        Assert.Equal(0, await ScalarAsync(app, "SELECT count(*) FROM information_schema.columns WHERE table_name = 'Tenants' AND column_name = 'IsSystemTenant'"));
        Assert.Equal(0, await ScalarAsync(app, "SELECT count(*) FROM \"CaGroups\" WHERE \"Name\" LIKE 'org-system-%'"));

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

    private static async Task<(int Tenants, int Cas, int Groups, int Users, int Members, int Certificates)> CountsAsync(ModularCADbContext db) => (
        await db.Tenants.IgnoreQueryFilters().CountAsync(),
        await db.CertificateAuthorities.IgnoreQueryFilters().CountAsync(),
        await db.CaGroups.IgnoreQueryFilters().CountAsync(),
        await db.Users.IgnoreQueryFilters().CountAsync(),
        await db.CaGroupMembers.IgnoreQueryFilters().CountAsync(),
        await db.Certificates.IgnoreQueryFilters().CountAsync());

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
