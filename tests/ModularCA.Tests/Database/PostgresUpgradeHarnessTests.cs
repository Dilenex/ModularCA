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

    /// <summary>The 0.4.0 migration that binds each ACME account to a CA, without its timestamp.</summary>
    public const string BindAcmeAccountsToCa = "BindAcmeAccountsToCa";

    /// <summary>The 0.4.1 migration that adds named API keys, the one before <see cref="SshKeyStorage"/>, without its timestamp.</summary>
    public const string ApiKeys = "ApiKeys";

    /// <summary>The 0.4.2 migration that records where each SSH CA key is held, without its timestamp.</summary>
    public const string SshKeyStorage = "SshKeyStorage";

    /// <summary>The 0.4.2 migration that adds the summary of an SSH certificate decision to the signer's audit, without its timestamp.</summary>
    public const string SignerAuditSummary = "SignerAuditSummary";

    /// <summary>The 0.4.2 migration that adds the record of each SSH CA key imported from a file, without its timestamp.</summary>
    public const string SshKeyImports = "SshKeyImports";

    /// <summary>The 0.4.2 migration that adds SSH login name grants and who a certificate is for, without its timestamp.</summary>
    public const string SshLoginNames = "SshLoginNames";

    /// <summary>The 0.4.2 migration that adds when an SSH certificate was revoked, without its timestamp.</summary>
    public const string SshCertificateRevokedAt = "SshCertificateRevokedAt";

    /// <summary>The 0.4.2 migration that adds the advisory review date of an SSH CA key, without its timestamp.</summary>
    public const string SshCaKeyReviewBy = "SshCaKeyReviewBy";

    /// <summary>The 0.4.2 migration that adds the certificate type of an SSH request profile and an SSH certificate profile, without its timestamp.</summary>
    public const string SshProfileCertificateType = "SshProfileCertificateType";

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
    private static readonly Guid SecondOrgTenant = Guid.Parse("00000000-0000-0000-0000-00000000a004");
    private static readonly Guid SecondRootCa = Guid.Parse("00000000-0000-0000-0000-00000000b004");
    private static readonly Guid SecondOrgAdminGroup = Guid.Parse("00000000-0000-0000-0000-00000000c011");
    private static readonly Guid SecondOrgUserGroup = Guid.Parse("00000000-0000-0000-0000-00000000c012");
    private static readonly Guid SecondCaAdminGroup = Guid.Parse("00000000-0000-0000-0000-00000000c013");
    private static readonly Guid AcmeProfile = Guid.Parse("00000000-0000-0000-0000-00000000e00a");
    private static readonly Guid SecondProfile = Guid.Parse("00000000-0000-0000-0000-00000000e00b");
    private static readonly Guid AcmeCeremony = Guid.Parse("00000000-0000-0000-0000-00000000f00b");
    private static readonly Guid SecondCeremony = Guid.Parse("00000000-0000-0000-0000-00000000f00c");
    private static readonly Guid MixedCaseCa = Guid.Parse("00000000-0000-0000-0000-00000000b005");
    private static readonly Guid ZetaDefaultCa = Guid.Parse("00000000-0000-0000-0000-00000000b006");
    private static readonly Guid RetiredDefaultCa = Guid.Parse("00000000-0000-0000-0000-00000000b007");
    private static readonly Guid DisabledDefaultCa = Guid.Parse("00000000-0000-0000-0000-00000000b008");
    private static readonly Guid ReservedDefaultCa = Guid.Parse("00000000-0000-0000-0000-00000000b009");
    private static readonly Guid SshDefaultCa = Guid.Parse("00000000-0000-0000-0000-00000000b00a");
    private static readonly Guid MixedCaseAccount = Guid.Parse("00000000-0000-0000-0000-00000000ac01");
    private static readonly Guid PaddedAccount = Guid.Parse("00000000-0000-0000-0000-00000000ac02");
    private static readonly Guid RetiredAccount = Guid.Parse("00000000-0000-0000-0000-00000000ac03");
    private static readonly Guid GoneAccount = Guid.Parse("00000000-0000-0000-0000-00000000ac04");
    private static readonly Guid LabelLessAccount = Guid.Parse("00000000-0000-0000-0000-00000000ac05");
    private static readonly Guid BlankLabelAccount = Guid.Parse("00000000-0000-0000-0000-00000000ac06");

    /// <summary>The seeded organisation tenant.</summary>
    internal static Guid OrgTenantId => OrgTenant;

    /// <summary>The seeded organisation's root CA.</summary>
    internal static Guid RootCaId => RootCa;

    /// <summary>
    /// A second organisation tenant, Initech, with a policy unlike Acme's and the system tenant's:
    /// its root CA, two <c>org-initech-*</c> groups (the operator in one) and its CA's group. For
    /// each organisation, a profile bound to its root CA and an open ceremony scoped to it. Run
    /// after <see cref="SeedFoldSql"/>.
    /// </summary>
    internal static string SeedSecondOrganisationSql => $$"""

        INSERT INTO "Tenants" ("Id","Name","Slug","Description","IsEnabled","IsSystemTenant","CanBeDeleted","CreatedAt",
            "MaxCertificateAuthorities","MaxCertificatesTotal","MaxUsers","MaxValidityDays","ValidityCeilingBehavior",
            "RequireKeyCeremony","CeremonyRequiredApprovals","UserCeremonyRequiredApprovals","IsDeleted")
        VALUES ('{{SecondOrgTenant}}','Initech','initech','Second organisation',true,false,true,now(),0,0,0,397,0,true,4,3,false);

        INSERT INTO "CertificateAuthorities" ("Id","Name","Label","IsDefault","Type","IsEnabled","KeyStorageType","IsSshCa","TenantId","IsDeleted")
        VALUES ('{{SecondRootCa}}','Initech Root CA','initech-root',false,'Root',true,'Software',false,'{{SecondOrgTenant}}',false);

        INSERT INTO "CaGroups" ("Id","Name","DisplayName","CertificateAuthorityId","TemplateName","IsSystemGroup","IsSystemTierSuper",
            "IsAutoGenerated","RequiredQuorum","MaxCertificates","MaxPendingRequests","CreatedAt","TenantId")
        VALUES ('{{SecondOrgAdminGroup}}','org-initech-admin','Org Initech Admin',NULL,'Administrator',false,false,true,1,0,0,now(),'{{SecondOrgTenant}}'),
               ('{{SecondOrgUserGroup}}','org-initech-user','Organisation Initech User',NULL,'Requester',false,false,true,1,0,0,now(),'{{SecondOrgTenant}}'),
               ('{{SecondCaAdminGroup}}','ca-initech-root-admin','CA initech-root Admin','{{SecondRootCa}}','Administrator',false,false,true,1,0,0,now(),'{{SecondOrgTenant}}');

        INSERT INTO "CaGroupMembers" ("Id","GroupId","UserId","AddedAt")
        VALUES (gen_random_uuid(),'{{SecondOrgAdminGroup}}','{{Operator}}',now());

        INSERT INTO "CertProfiles" ("Id","Name","Description","IsCaProfile","KeyUsages","ExtendedKeyUsages","AllowedKeyAlgorithms",
            "AllowedKeySizes","AllowedSignatureAlgorithms","CreatedAt","Revision","UpdatedAt","CanBeDeleted","ProfileHash","CtEnabled",
            "AllowWildcard","InheritanceEnabled","TenantId","CertificateAuthorityId")
        VALUES ('{{AcmeProfile}}','Acme Leaf','bound to the Acme root',false,'[]','[]','[]','[]','[]',now(),1,now(),true,'',false,false,false,'{{OrgTenant}}','{{RootCa}}'),
               ('{{SecondProfile}}','Initech Leaf','bound to the Initech root',false,'[]','[]','[]','[]','[]',now(),1,now(),true,'',false,false,false,'{{SecondOrgTenant}}','{{SecondRootCa}}');

        INSERT INTO "KeyCeremonies" ("Id","OperationType","Description","TargetEntityId","InitiatedByUserId","InitiatedByUsername",
            "RequiredApprovals","CurrentApprovals","Status","CreatedAt","ExpiresAt","ParametersJson","ApprovalsJson","TenantId")
        VALUES ('{{AcmeCeremony}}','RevokeCa','x','{{RootCa}}','{{Operator}}','operator',2,0,'Pending',now(),now() + interval '1 day',
                   '{"TenantId":"{{OrgTenant}}"}','[]','{{OrgTenant}}'),
               ('{{SecondCeremony}}','RevokeCa','x','{{SecondRootCa}}','{{Operator}}','operator',4,0,'Pending',now(),now() + interval '1 day',
                   '{"tenantId":"{{SecondOrgTenant}}"}','[]','{{SecondOrgTenant}}');
        """;

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
                await SeedAuditChainsAsync(audit, AuditTenantChains);

                await MigrateToLatestAsync(audit, "audit");
                await AssertAuditChainsSealedAsync(audit, AuditTenantChains);
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
    /// A 0.3.x database where a later migration refuses (<c>InstanceUniqueCaNames</c> P1, a label
    /// two CAs share) after <c>RetireTenantHostnames</c> and <c>FoldSystemTenant</c> pass: the dry
    /// run lists P1 with its message and P2 (the same label, also shared up to case) as also found,
    /// skips the rest of the migration, whose unique index the duplicate breaks, then stops at
    /// <c>RenameTenantToSpace</c>, which renames an index the skipped steps would have created. It
    /// applies nothing and leaves no lock behind; then <c>--upgrade-check</c> and the control
    /// role's start both refuse with 3 and list the same, still applying nothing.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public async Task A_later_refusal_is_caught_by_the_dry_run_and_nothing_is_applied()
    {
        var server = Environment.GetEnvironmentVariable(ServerVariable)!;
        var appName = $"modularca_upgrade_app_{Guid.NewGuid().ToString("N")[..12]}";
        var p1 = RefusedUniqueness().Single(r => (string)r[0] == "P1");
        var expected = (string)p1[2];
        await CreateDatabaseAsync(server, appName);
        try
        {
            var connection = WithDatabase(server, appName);
            string refusing, rename;
            await using (var app = CreateApp(connection))
            {
                await app.GetService<IMigrator>().MigrateAsync(AppBaseline);
                await ExecAsync(app, Seed030Sql + SeedFoldSql + (string)p1[1]);
                refusing = MigrationId(app, InstanceUniqueCaNames);
                rename = MigrationId(app, RenameTenantToSpace);

                var result = await SchemaVersionGate.DryRunPendingAsync(app);

                Assert.False(result.Passed);
                Assert.Equal([(refusing, "P1", false), (refusing, "P2", true)], result.Refusals.Select(r => (r.Migration, r.Check, r.AlsoFound)));
                Assert.Contains(expected, result.Refusals[0].Message);
                var skip = Assert.Single(result.Skipped);
                Assert.Equal((refusing, PostgresErrorCodes.UniqueViolation), (skip.Migration, SchemaFailure.SqlState(skip.Error)));
                Assert.Equal(rename, result.Migration);
                Assert.True(result.Stopped);
                Assert.Equal([MigrationId(app, RetireTenantHostnames), MigrationId(app, FoldSystemTenant)], result.Rehearsed);
                await AssertNothingAppliedAsync(app);
            }
            await AssertNoLockHeldAsync(connection);

            var output = new StringWriter();
            var target = ("application", DatabaseKind.Application, Instance(connection));
            Assert.Equal(3, await SchemaStartupApi.UpgradeCheckAsync([target], new SchemaConfig(), output));
            var report = output.ToString();
            Assert.Contains($"UPGRADE CHECK: REFUSED (application: migration {refusing} refuses; then migration {rename} fails, "
                + "and the checks after it could not run). Nothing was changed.", report);
            Assert.Contains($"1 of 2: migration {refusing} (P1) refuses: {expected}", report);
            Assert.Contains($"2 of 2, also found: migration {refusing} (P2) refuses: ", report);
            Assert.Contains($"Skipped: the rest of migration {refusing}, from command 6 of ", report);
            Assert.Contains("which may follow from the steps skipped above. The checks after this point could not run.", report);
            Assert.Contains("nothing was applied", report);

            using var log = new CapturedSerilog();
            Assert.Equal(3, await SchemaStartupApi.EnforceAllAsync([target], true, new SchemaConfig { WaitSeconds = 1 }));
            var events = string.Join(Environment.NewLine, log.Events.Select(e => $"{e.Level}: {e.Text}"));
            Assert.True(log.Has(Serilog.Events.LogEventLevel.Fatal, expected), events);
            Assert.True(log.Has(Serilog.Events.LogEventLevel.Fatal, $"1 of 2: migration {refusing} (P1) refuses: "), events);
            Assert.True(log.Has(Serilog.Events.LogEventLevel.Fatal, $"2 of 2, also found: migration {refusing} (P2) refuses: "), events);
            Assert.True(log.Has(Serilog.Events.LogEventLevel.Fatal, "nothing was applied to either database"), events);
            await using (var app = CreateApp(connection))
                await AssertNothingAppliedAsync(app);
            await AssertNoLockHeldAsync(connection);
        }
        finally
        {
            NpgsqlConnection.ClearAllPools();
            await DropDatabaseAsync(server, appName);
        }
    }

    /// <summary>
    /// A refusal raised after the renames of its own migration (<c>RenameTenantToSpace</c> P2, a
    /// taken group name), followed by its knock-on (the group rename then breaks the unique index
    /// on group names): the dry run reports the refusal and the skipped rest of the migration, not a
    /// crash and not a second problem, and rolls back the renames and every earlier migration with
    /// them. <c>--upgrade-check</c> lists the same and exits 3; nothing stopped it early.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public async Task A_refusal_after_renames_in_the_same_migration_leaves_every_name_as_it_was()
    {
        var server = Environment.GetEnvironmentVariable(ServerVariable)!;
        var appName = $"modularca_upgrade_app_{Guid.NewGuid().ToString("N")[..12]}";
        var taken = RefusedRenames().Single(r => (string)r[0] == "P2 taken");
        await CreateDatabaseAsync(server, appName);
        try
        {
            var connection = WithDatabase(server, appName);
            string rename;
            List<string> before;
            await using (var app = CreateApp(connection))
            {
                await app.GetService<IMigrator>().MigrateAsync(AppBaseline);
                await ExecAsync(app, Seed030Sql + SeedFoldSql + (string)taken[1]);
                rename = MigrationId(app, RenameTenantToSpace);
                before = await FingerprintAsync(app);

                var result = await SchemaVersionGate.DryRunPendingAsync(app);

                Assert.False(result.Passed);
                Assert.False(result.Stopped);
                Assert.Null(result.Migration);
                Assert.Equal(result.Pending.Where(id => id != rename), result.Rehearsed);
                var refusal = Assert.Single(result.Refusals);
                Assert.Equal((rename, "P2", false), (refusal.Migration, refusal.Check, refusal.AlsoFound));
                Assert.Contains((string)taken[2], refusal.Message);
                var skip = Assert.Single(result.Skipped);
                Assert.Equal((rename, PostgresErrorCodes.UniqueViolation), (skip.Migration, SchemaFailure.SqlState(skip.Error)));
                await AssertNothingAppliedAsync(app);
            }
            await AssertNoLockHeldAsync(connection);

            var output = new StringWriter();
            Assert.Equal(3, await SchemaStartupApi.UpgradeCheckAsync(
                [("application", DatabaseKind.Application, Instance(connection))], new SchemaConfig(), output));
            var report = output.ToString();
            Assert.Contains($"UPGRADE CHECK: REFUSED (application: migration {rename} refuses). Nothing was changed.", report);
            Assert.Contains($"1 of 1: migration {rename} (P2) refuses: {(string)taken[2]}", report);
            Assert.Contains($"Skipped: the rest of migration {rename}, from command ", report);
            Assert.Contains("Those steps depend on fixing that refusal; they are checked once it is fixed.", report);
            Assert.DoesNotContain("could not run", report);
            Assert.DoesNotContain("also found", report);
            await using (var app = CreateApp(connection))
                Assert.Equal(before, await FingerprintAsync(app));
        }
        finally
        {
            NpgsqlConnection.ClearAllPools();
            await DropDatabaseAsync(server, appName);
        }
    }

    /// <summary>
    /// Two independent refusals in different migrations, a tenant hostname
    /// (<c>RetireTenantHostnames</c>) and a label two CAs share (<c>InstanceUniqueCaNames</c> P1):
    /// one <c>--upgrade-check</c> run lists both, numbered, the second as also found, exits 3, and
    /// leaves every row and catalog entry of the database as it was. The control role's start
    /// refuses with the same list in the journal, still changing nothing.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public async Task One_upgrade_check_lists_refusals_from_different_migrations_and_changes_nothing()
    {
        var server = Environment.GetEnvironmentVariable(ServerVariable)!;
        var appName = $"modularca_upgrade_app_{Guid.NewGuid().ToString("N")[..12]}";
        var p1 = RefusedUniqueness().Single(r => (string)r[0] == "P1");
        const string hostnames = "This instance has 1 tenant hostname(s), which 0.4.0 no longer serves.";
        await CreateDatabaseAsync(server, appName);
        try
        {
            var connection = WithDatabase(server, appName);
            string retire, unique;
            List<string> before;
            await using (var app = CreateApp(connection))
            {
                await app.GetService<IMigrator>().MigrateAsync(AppBaseline);
                await ExecAsync(app, Seed030Sql + SeedFoldSql + SeedTenantHostnameSql + (string)p1[1]);
                retire = MigrationId(app, RetireTenantHostnames);
                unique = MigrationId(app, InstanceUniqueCaNames);
                before = await FingerprintAsync(app);

                var result = await SchemaVersionGate.DryRunPendingAsync(app);

                Assert.Equal([(retire, null, false), (unique, "P1", true), (unique, "P2", true)],
                    result.Refusals.Select(r => (r.Migration, r.Check, r.AlsoFound)));
                Assert.StartsWith(hostnames, result.Refusals[0].Message);
                Assert.Contains((string)p1[2], result.Refusals[1].Message);
                Assert.Equal(unique, Assert.Single(result.Skipped).Migration);
                Assert.Equal([MigrationId(app, FoldSystemTenant)], result.Rehearsed);
                Assert.Equal(before, await FingerprintAsync(app));
            }

            var output = new StringWriter();
            var target = ("application", DatabaseKind.Application, Instance(connection));
            Assert.Equal(3, await SchemaStartupApi.UpgradeCheckAsync([target], new SchemaConfig(), output));
            var report = output.ToString();
            Assert.Contains("found 3 refusal(s); fix each, then check again:", report);
            Assert.Contains($"1 of 3: migration {retire} refuses: {hostnames}", report);
            Assert.Contains($"2 of 3, also found: migration {unique} (P1) refuses: {(string)p1[2]}", report);
            Assert.Contains($"3 of 3, also found: migration {unique} (P2) refuses: ", report);
            Assert.Contains("\"Also found\" refusals came after an earlier refusal", report);
            Assert.Contains($"UPGRADE CHECK: REFUSED (application: migrations {retire}, {unique} refuse; then migration ", report);
            Assert.Single(report.Split('\n'), l => l.StartsWith("UPGRADE CHECK: ", StringComparison.Ordinal));
            await using (var app = CreateApp(connection))
                Assert.Equal(before, await FingerprintAsync(app));

            using var log = new CapturedSerilog();
            Assert.Equal(3, await SchemaStartupApi.EnforceAllAsync([target], true, new SchemaConfig { WaitSeconds = 1 }));
            var events = string.Join(Environment.NewLine, log.Events.Select(e => $"{e.Level}: {e.Text}"));
            Assert.True(log.Has(Serilog.Events.LogEventLevel.Fatal, $"1 of 3: migration {retire} refuses: {hostnames}"), events);
            Assert.True(log.Has(Serilog.Events.LogEventLevel.Fatal, $"2 of 3, also found: migration {unique} (P1) refuses: {(string)p1[2]}"), events);
            await using (var app = CreateApp(connection))
            {
                Assert.Equal(before, await FingerprintAsync(app));
                await AssertNothingAppliedAsync(app);
            }
            await AssertNoLockHeldAsync(connection);
        }
        finally
        {
            NpgsqlConnection.ClearAllPools();
            await DropDatabaseAsync(server, appName);
        }
    }

    /// <summary>
    /// An error that is not a refusal, with no refusal before it (an index of the name
    /// <c>InstanceUniqueCaNames</c> creates already exists): the dry run stops there and says the
    /// checks after it could not run, so the refusal <c>RenameTenantToSpace</c> P2 would raise
    /// later (a taken group name) is not reported, and nothing is changed.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public async Task An_error_with_no_refusal_before_it_stops_the_check_and_says_the_rest_could_not_run()
    {
        var server = Environment.GetEnvironmentVariable(ServerVariable)!;
        var appName = $"modularca_upgrade_app_{Guid.NewGuid().ToString("N")[..12]}";
        var taken = RefusedRenames().Single(r => (string)r[0] == "P2 taken");
        await CreateDatabaseAsync(server, appName);
        try
        {
            var connection = WithDatabase(server, appName);
            string unique;
            List<string> before;
            await using (var app = CreateApp(connection))
            {
                await app.GetService<IMigrator>().MigrateAsync(AppBaseline);
                await ExecAsync(app, Seed030Sql + SeedFoldSql + (string)taken[1]
                    + "CREATE INDEX \"IX_CertificateAuthorities_LabelLower\" ON \"CertificateAuthorities\" (\"Name\");");
                unique = MigrationId(app, InstanceUniqueCaNames);
                before = await FingerprintAsync(app);

                var result = await SchemaVersionGate.DryRunPendingAsync(app);

                Assert.Empty(result.Refusals);
                Assert.Empty(result.Skipped);
                Assert.True(result.Stopped);
                Assert.Equal(unique, result.Migration);
                Assert.Equal(6, result.Command);
                Assert.Equal(PostgresErrorCodes.DuplicateTable, SchemaFailure.SqlState(result.Error!));
                Assert.Equal([MigrationId(app, RetireTenantHostnames), MigrationId(app, FoldSystemTenant)], result.Rehearsed);
            }

            var output = new StringWriter();
            Assert.Equal(3, await SchemaStartupApi.UpgradeCheckAsync(
                [("application", DatabaseKind.Application, Instance(connection))], new SchemaConfig(), output));
            var report = output.ToString();
            Assert.Contains($"The dry run of the application database failed at migration {unique}, command 6 of ", report);
            Assert.Contains("The checks after this point could not run.", report);
            Assert.Contains($"UPGRADE CHECK: REFUSED (application: migration {unique} fails). Nothing was changed.", report);
            Assert.DoesNotContain((string)taken[2], report);
            await using (var app = CreateApp(connection))
                Assert.Equal(before, await FingerprintAsync(app));
            await AssertNoLockHeldAsync(connection);
        }
        finally
        {
            NpgsqlConnection.ClearAllPools();
            await DropDatabaseAsync(server, appName);
        }
    }

    /// <summary>
    /// A clean 0.3.x database: the dry run passes and leaves it unchanged, the audit database's
    /// dry run passes, <c>--upgrade-check</c> exits 0 still changing nothing, refuses an integration
    /// key scoped to the system tenant (but not one scoped to the instance), and the control role's
    /// start then applies every migration.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public async Task A_clean_030_database_passes_the_dry_run_unchanged_then_the_control_role_upgrades_it()
    {
        var server = Environment.GetEnvironmentVariable(ServerVariable)!;
        var suffix = Guid.NewGuid().ToString("N")[..12];
        var appName = $"modularca_upgrade_app_{suffix}";
        var auditName = $"modularca_upgrade_audit_{suffix}";
        await CreateDatabaseAsync(server, appName);
        await CreateDatabaseAsync(server, auditName);
        try
        {
            var appConnection = WithDatabase(server, appName);
            var auditConnection = WithDatabase(server, auditName);
            int pending, auditPending;
            List<string> before;
            await using (var app = CreateApp(appConnection))
            {
                await app.GetService<IMigrator>().MigrateAsync(AppBaseline);
                await ExecAsync(app, Seed030Sql + SeedFoldSql);
                pending = app.Database.GetMigrations().Count() - 1;
                before = await FingerprintAsync(app);

                var result = await SchemaVersionGate.DryRunPendingAsync(app);

                Assert.True(result.Passed, result.Error?.ToString());
                Assert.Empty(result.Refusals);
                Assert.Empty(result.Skipped);
                Assert.False(result.Stopped);
                Assert.Equal(pending, result.Rehearsed.Count);
                Assert.Equal(result.Pending, result.Rehearsed);
                await AssertNothingAppliedAsync(app);
            }
            await using (var audit = CreateAudit(auditConnection))
            {
                await audit.GetService<IMigrator>().MigrateAsync(AuditBaseline);
                var result = await SchemaVersionGate.DryRunPendingAsync(audit);
                Assert.True(result.Passed, result.Error?.ToString());
                Assert.Equal(audit.Database.GetMigrations().Skip(1), result.Rehearsed);
                auditPending = result.Rehearsed.Count;
                Assert.Equal([AuditBaseline], await audit.Database.GetAppliedMigrationsAsync());
            }
            await AssertNoLockHeldAsync(appConnection);

            var targets = new[]
            {
                ("application", DatabaseKind.Application, Instance(appConnection)),
                ("audit", DatabaseKind.Audit, Instance(auditConnection)),
            };
            var output = new StringWriter();
            Assert.Equal(0, await SchemaStartupApi.UpgradeCheckAsync(targets, new SchemaConfig(), output));
            var report = output.ToString();
            Assert.Contains($"UPGRADE CHECK: PASS ({pending + auditPending} pending migration(s) would apply cleanly). Nothing was changed.", report);
            Assert.Contains($"would apply {auditPending} migration(s) cleanly.", report);
            Assert.DoesNotContain("REFUSED", report);
            Assert.Contains($"dry run: passed; {pending} migration(s) ran in one transaction and were rolled back.", report);

            // An integration key scoped to the system tenant is refused, read-only, with its remedy;
            // one scoped to the instance or an organisation is not.
            output = new StringWriter();
            Assert.Equal(3, await SchemaStartupApi.UpgradeCheckAsync(targets, new SchemaConfig(), output,
                [("IntegrationApi.SpaceId", SystemTenant.ToString()), ("CertManager.SpaceId", OrgTenant.ToString())]));
            report = output.ToString();
            Assert.Contains("UPGRADE CHECK: REFUSED (configuration: IntegrationApi.SpaceId scoped to the system tenant). Nothing was changed.", report);
            Assert.Contains("Set IntegrationApi.SpaceId to 'instance'", report);
            Assert.DoesNotContain("CertManager.SpaceId (named", report);
            output = new StringWriter();
            Assert.Equal(0, await SchemaStartupApi.UpgradeCheckAsync(targets, new SchemaConfig(), output,
                [("IntegrationApi.SpaceId", "instance"), ("CertManager.SpaceId", OrgTenant.ToString())]));
            Assert.Contains("no integration key is scoped to the system tenant or to a space that does not exist.", output.ToString());

            // Before the fold, a GUID that names no tenant at all is refused too.
            output = new StringWriter();
            Assert.Equal(3, await SchemaStartupApi.UpgradeCheckAsync(targets, new SchemaConfig(), output,
                [("CertManager.SpaceId", Guid.NewGuid().ToString())]));
            Assert.Contains("UPGRADE CHECK: REFUSED (configuration: CertManager.SpaceId scoped to no existing space). Nothing was changed.", output.ToString());

            await using (var app = CreateApp(appConnection))
            {
                await AssertNothingAppliedAsync(app);
                Assert.Equal(before, await FingerprintAsync(app));
            }

            Assert.Null(await SchemaStartupApi.EnforceAllAsync(targets, true, new SchemaConfig { WaitSeconds = 1 }));
            await using (var app = CreateApp(appConnection))
                Assert.Equal(SchemaVerdict.Current, SchemaVersionGate.Evaluate(await SchemaVersionGate.ReadAsync(app), appliesMigrations: true));
            await AssertNoLockHeldAsync(appConnection);

            // After the fold, as an enrollment host checks once the control host has upgraded: the
            // system tenant is gone, so its id, like any id naming no space, is refused read-only
            // with the remedy; the instance and an existing space pass.
            List<string> folded;
            await using (var app = CreateApp(appConnection))
                folded = await FingerprintAsync(app);
            output = new StringWriter();
            Assert.Equal(3, await SchemaStartupApi.UpgradeCheckAsync(targets, new SchemaConfig(), output,
                [("IntegrationApi.SpaceId", SystemTenant.ToString()), ("CertManager.SpaceId", OrgTenant.ToString())]));
            report = output.ToString();
            Assert.Contains("UPGRADE CHECK: REFUSED (configuration: IntegrationApi.SpaceId scoped to no existing space). Nothing was changed.", report);
            Assert.Contains($"IntegrationApi.SpaceId (named IntegrationApi.TenantId before 0.4.0) is {SystemTenant}, which names no existing space", report);
            Assert.Contains("set IntegrationApi.SpaceId to 'instance'", report);
            Assert.Contains("otherwise set it to an existing space's id", report);
            Assert.DoesNotContain("CertManager.SpaceId (named", report);
            output = new StringWriter();
            Assert.Equal(0, await SchemaStartupApi.UpgradeCheckAsync(targets, new SchemaConfig(), output,
                [("IntegrationApi.SpaceId", "instance"), ("CertManager.SpaceId", OrgTenant.ToString())]));
            Assert.Contains("no integration key is scoped to the system tenant or to a space that does not exist.", output.ToString());
            await using (var app = CreateApp(appConnection))
                Assert.Equal(folded, await FingerprintAsync(app));
        }
        finally
        {
            NpgsqlConnection.ClearAllPools();
            await DropDatabaseAsync(server, appName);
            await DropDatabaseAsync(server, auditName);
        }
    }

    /// <summary>
    /// A 0.3.x database with the system tenant and two organisation tenants, each with a root CA,
    /// groups, a CA-bound profile and an open ceremony: the dry run passes unchanged,
    /// <c>--upgrade-check</c> exits 0, and the control role's start upgrades it. Each organisation
    /// is then a space with its own rows and policy, the instance has the system tenant's policy,
    /// and the three retired audit chains seal and verify.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public async Task Two_organisations_become_two_spaces_each_keeping_its_own_rows_and_policy()
    {
        var server = Environment.GetEnvironmentVariable(ServerVariable)!;
        var suffix = Guid.NewGuid().ToString("N")[..12];
        var appName = $"modularca_upgrade_app_{suffix}";
        var auditName = $"modularca_upgrade_audit_{suffix}";
        Guid[] chains = [OrgTenant, SecondOrgTenant, SystemTenant];
        await CreateDatabaseAsync(server, appName);
        await CreateDatabaseAsync(server, auditName);
        try
        {
            var appConnection = WithDatabase(server, appName);
            var auditConnection = WithDatabase(server, auditName);
            await using (var app = CreateApp(appConnection))
            {
                await app.GetService<IMigrator>().MigrateAsync(AppBaseline);
                await ExecAsync(app, Seed030Sql + SeedFoldSql + SeedSecondOrganisationSql);
                var result = await SchemaVersionGate.DryRunPendingAsync(app);
                Assert.True(result.Passed, result.Error?.ToString());
                await AssertNothingAppliedAsync(app);
            }
            await using (var audit = CreateAudit(auditConnection))
            {
                await audit.GetService<IMigrator>().MigrateAsync(AuditBaseline);
                await SeedAuditChainsAsync(audit, chains);
            }

            var targets = new[]
            {
                ("application", DatabaseKind.Application, Instance(appConnection)),
                ("audit", DatabaseKind.Audit, Instance(auditConnection)),
            };
            var output = new StringWriter();
            Assert.Equal(0, await SchemaStartupApi.UpgradeCheckAsync(targets, new SchemaConfig(), output));
            Assert.Contains("UPGRADE CHECK: PASS", output.ToString());
            Assert.Null(await SchemaStartupApi.EnforceAllAsync(targets, true, new SchemaConfig { WaitSeconds = 1 }));

            await using (var app = CreateApp(appConnection))
                await AssertTwoSpacesAsync(app);
            await using (var audit = CreateAudit(auditConnection))
                await AssertAuditChainsSealedAsync(audit, chains);
        }
        finally
        {
            NpgsqlConnection.ClearAllPools();
            await DropDatabaseAsync(server, appName);
            await DropDatabaseAsync(server, auditName);
        }
    }

    /// <summary>
    /// What <see cref="SeedSecondOrganisationSql"/> must become at the latest names: two spaces
    /// with their settings as they were; each one's CAs, groups (renamed <c>space-&lt;slug&gt;-*</c>,
    /// members kept), profiles and open ceremony on that space; the instance CAs and groups on the
    /// instance; and the instance policy equal to the system tenant's, read through the resolver.
    /// </summary>
    private static async Task AssertTwoSpacesAsync(ModularCADbContext app)
    {
        var refuse = (int)ModularCA.Shared.Enums.ValidityCeilingBehavior.Refuse;
        var shorten = (int)ModularCA.Shared.Enums.ValidityCeilingBehavior.Shorten;
        Assert.Equal(
            $"{OrgTenant}|Acme|acme|true|false|2|-|825|{refuse}; {SecondOrgTenant}|Initech|initech|true|true|4|3|397|{shorten}",
            await TextAsync(app, """
                SELECT string_agg(concat_ws('|', "Id", "Name", "Slug", "IsEnabled"::text, "RequireKeyCeremony"::text, "CeremonyRequiredApprovals",
                    coalesce("UserCeremonyRequiredApprovals"::text, '-'), "MaxValidityDays", "ValidityCeilingBehavior"), '; ' ORDER BY "Id") FROM "Spaces"
                """));

        Assert.Equal($"acme-root={OrgTenant}; initech-root={SecondOrgTenant}; ops-ssh=instance; system-signing-ca=instance",
            await TextAsync(app, """SELECT string_agg("Label"::text || '=' || coalesce("SpaceId"::text, 'instance'), '; ' ORDER BY "Label"::text COLLATE "C") FROM "CertificateAuthorities" """));

        async Task<string> Groups(string where) => await TextAsync(app,
            $"SELECT string_agg(\"Name\" || '=' || \"DisplayName\", '; ' ORDER BY \"Name\"::text COLLATE \"C\") FROM \"CaGroups\" WHERE {where}");
        Assert.Equal("ca-acme-root-admin=CA acme-root Admin; space-acme-admin=Space Acme Admin", await Groups($"\"SpaceId\" = '{OrgTenant}'"));
        Assert.Equal("ca-initech-root-admin=CA initech-root Admin; space-initech-admin=Space Initech Admin; space-initech-user=Space Initech User",
            await Groups($"\"SpaceId\" = '{SecondOrgTenant}'"));
        Assert.Equal(6, await ScalarAsync(app, "SELECT count(*) FROM \"CaGroups\" WHERE \"SpaceId\" IS NULL"));
        Assert.Equal(0, await ScalarAsync(app, "SELECT count(*) FROM \"CaGroups\" WHERE \"Name\" LIKE 'org-%'"));
        Assert.Equal(3, await ScalarAsync(app,
            $"SELECT count(*) FROM \"CaGroupMembers\" WHERE \"UserId\" = '{Operator}' AND \"GroupId\" IN ('{OrgAdminGroup}','{CaAdminGroup}','{SecondOrgAdminGroup}')"));

        foreach (var (profile, space, ca) in new[] { (AcmeProfile, OrgTenant, RootCa), (SecondProfile, SecondOrgTenant, SecondRootCa) })
            Assert.Equal(1, await ScalarAsync(app,
                $"SELECT count(*) FROM \"CertProfiles\" WHERE \"Id\" = '{profile}' AND \"SpaceId\" = '{space}' AND \"CertificateAuthorityId\" = '{ca}'"));
        foreach (var (ceremony, space, key) in new[] { (AcmeCeremony, OrgTenant, "SpaceId"), (SecondCeremony, SecondOrgTenant, "spaceId") })
            Assert.Equal(1, await ScalarAsync(app,
                $"SELECT count(*) FROM \"KeyCeremonies\" WHERE \"Id\" = '{ceremony}' AND \"SpaceId\" = '{space}' AND \"Status\" = 'Pending' "
                + $"AND (\"ParametersJson\"::jsonb ->> '{key}') = '{space}'"));

        Assert.Equal(1, await ScalarAsync(app, "SELECT count(*) FROM \"SecurityPolicy\""));
        var resolver = new EffectivePolicyResolver(app);
        static (bool, int, int, ModularCA.Shared.Enums.ValidityCeilingBehavior, int?) Values(EffectivePolicy? p) =>
            (p!.RequireKeyCeremony, p.CeremonyRequiredApprovals, p.MaxValidityDays, p.ValidityCeilingBehavior, p.UserCeremonyRequiredApprovals);
        Assert.Equal((true, 3, 0, ModularCA.Shared.Enums.ValidityCeilingBehavior.Shorten, (int?)2), Values(await resolver.ResolveAsync(null)));
        Assert.Equal(Values(await resolver.ResolveAsync(null)), Values(await resolver.ResolveForCaAsync(SysCa)));
        Assert.Equal((false, 2, 825, ModularCA.Shared.Enums.ValidityCeilingBehavior.Refuse, (int?)null), Values(await resolver.ResolveForCaAsync(RootCa)));
        Assert.Equal((true, 4, 397, ModularCA.Shared.Enums.ValidityCeilingBehavior.Shorten, (int?)3), Values(await resolver.ResolveForCaAsync(SecondRootCa)));
    }

    /// <summary>
    /// The audit context's dry run on an empty database rehearses the history table, the baseline
    /// and every migration after it, and leaves the database empty.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public async Task The_audit_dry_run_rehearses_its_baseline_on_an_empty_database_and_leaves_it_empty()
    {
        var server = Environment.GetEnvironmentVariable(ServerVariable)!;
        var auditName = $"modularca_upgrade_audit_{Guid.NewGuid().ToString("N")[..12]}";
        await CreateDatabaseAsync(server, auditName);
        try
        {
            await using var audit = CreateAudit(WithDatabase(server, auditName));
            var result = await SchemaVersionGate.DryRunPendingAsync(audit);

            Assert.True(result.Passed, result.Error?.ToString());
            Assert.Equal(audit.Database.GetMigrations(), result.Rehearsed);
            Assert.Equal(AuditBaseline, result.Rehearsed[0]);
            Assert.Equal(DatabasePresence.Empty, (await SchemaVersionGate.ReadAsync(audit)).Presence);
            Assert.Equal(0, await ScalarAsync(audit, "SELECT count(*) FROM pg_catalog.pg_class WHERE relnamespace = 'public'::regnamespace"));
        }
        finally
        {
            NpgsqlConnection.ClearAllPools();
            await DropDatabaseAsync(server, auditName);
        }
    }

    /// <summary>
    /// The application database still holds only the baseline: the history, the table
    /// <c>RetireTenantHostnames</c> drops, the column <c>FoldSystemTenant</c> drops, and the table
    /// and column <c>RenameTenantToSpace</c> renames.
    /// </summary>
    private static async Task AssertNothingAppliedAsync(DbContext app)
    {
        Assert.Equal([AppBaseline], (await SchemaVersionGate.ReadAsync(app)).Applied);
        Assert.Equal(1, await ScalarAsync(app, "SELECT count(*) FROM pg_catalog.pg_class WHERE relname = 'TenantHostnames' AND relnamespace = 'public'::regnamespace"));
        Assert.Equal(1, await ScalarAsync(app, "SELECT count(*) FROM information_schema.columns WHERE table_name = 'Tenants' AND column_name = 'IsSystemTenant'"));
        Assert.Equal(1, await ScalarAsync(app, "SELECT count(*) FROM information_schema.columns WHERE table_name = 'Users' AND column_name = 'ServiceScopeTenantId'"));
        Assert.Equal(0, await ScalarAsync(app, "SELECT count(*) FROM information_schema.columns WHERE table_name = 'Users' AND column_name = 'ServiceScopeSpaceId'"));
        Assert.Equal(0, await ScalarAsync(app, "SELECT count(*) FROM pg_catalog.pg_class WHERE relname = 'Spaces' AND relnamespace = 'public'::regnamespace"));
    }

    /// <summary>
    /// Everything in <c>public</c>, so two reads compare equal only when nothing changed: every
    /// relation with its kind and index definition, every column with its type, nullability and
    /// default, every constraint's definition, and an md5 of each table's rows as text, in a stable
    /// order.
    /// </summary>
    private static async Task<List<string>> FingerprintAsync(DbContext db)
    {
        var lines = await TextsAsync(db, """
            SELECT 'relation ' || c.relname::text || ' ' || c.relkind::text || ' ' || coalesce(pg_catalog.pg_get_indexdef(c.oid), '')
              FROM pg_catalog.pg_class c WHERE c.relnamespace = 'public'::regnamespace
            UNION ALL
            SELECT 'column ' || c.relname || '.' || a.attname || ' ' || pg_catalog.format_type(a.atttypid, a.atttypmod) || ' '
                   || a.attnotnull::text || ' ' || coalesce(pg_catalog.pg_get_expr(d.adbin, d.adrelid), '')
              FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
              LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
             WHERE c.relnamespace = 'public'::regnamespace AND a.attnum > 0 AND NOT a.attisdropped
            UNION ALL
            SELECT 'constraint ' || conname || ' ' || pg_catalog.pg_get_constraintdef(oid)
              FROM pg_catalog.pg_constraint WHERE connamespace = 'public'::regnamespace
            """);
        foreach (var table in await TextsAsync(db, "SELECT quote_ident(relname) FROM pg_catalog.pg_class WHERE relnamespace = 'public'::regnamespace AND relkind IN ('r','p')"))
            lines.Add($"rows {table} " + await TextAsync(db, $"SELECT md5(coalesce(string_agg(t::text, E'\\n' ORDER BY t::text), '')) FROM {table} t"));
        return lines;
    }

    /// <summary>
    /// No client session holds a lock in the database, and a new connection takes ACCESS EXCLUSIVE
    /// on the history and the tables the migrations alter at once.
    /// </summary>
    private static async Task AssertNoLockHeldAsync(string connectionString)
    {
        await using var probe = new NpgsqlConnection(connectionString);
        await probe.OpenAsync();
        await using (var held = new NpgsqlCommand("""
            SELECT count(*) FROM pg_catalog.pg_locks l JOIN pg_catalog.pg_stat_activity a ON a.pid = l.pid
             WHERE l.database = (SELECT oid FROM pg_catalog.pg_database WHERE datname = current_database())
               AND a.backend_type = 'client backend' AND l.pid <> pg_backend_pid()
            """, probe))
            Assert.Equal(0L, Convert.ToInt64(await held.ExecuteScalarAsync()));
        await using var transaction = await probe.BeginTransactionAsync();
        var tables = await TextsOnAsync(probe, transaction, """
            SELECT quote_ident(relname) FROM pg_catalog.pg_class WHERE relnamespace = 'public'::regnamespace AND relkind IN ('r','p')
            """);
        await using (var lockAll = new NpgsqlCommand(
            $"SET LOCAL lock_timeout = '5s'; LOCK TABLE {string.Join(", ", tables)} IN ACCESS EXCLUSIVE MODE", probe, transaction))
            await lockAll.ExecuteNonQueryAsync();
        await transaction.RollbackAsync();
    }

    /// <summary>The first column of every row of <paramref name="sql"/> on an open connection.</summary>
    private static async Task<List<string>> TextsOnAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, string sql)
    {
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        var values = new List<string>();
        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
            values.Add(reader.GetString(0));
        return values;
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
    /// names; no catalog name or definition in <c>public</c> that says tenant (an index's own
    /// column names are left out: PostgreSQL keeps them from the index's creation through a
    /// column rename, and its definition, which is checked, uses the new name); every stored
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
                    WHERE c.relnamespace = 'public'::regnamespace AND c.relkind NOT IN ('i', 'I') AND a.attnum > 0 AND NOT a.attisdropped
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
        { "P1 across spaces", SeedSecondOrganisationSql + $"UPDATE \"CertificateAuthorities\" SET \"Label\" = 'acme-root' WHERE \"Id\" = '{SecondRootCa}';",
            "This instance has 1 CA label(s) used by more than one CA, counting soft-deleted CAs: acme-root (Acme), acme-root (Initech)." },
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

    /// <summary>
    /// The <c>BindAcmeAccountsToCa</c> backfill, seeded at the stage before it with
    /// <see cref="SeedAcmeAccountsSql"/>: a label binds to the CA with that label ignoring case
    /// and surrounding blanks, a soft-deleted CA's included; a label naming no CA leaves the
    /// account unbound; a label-less or blank account binds to the CA
    /// <c>CaResolverService.DefaultCandidates</c> puts first, passing over deleted, disabled,
    /// <c>system-</c> and SSH CAs marked default and breaking the tie between two defaults by name.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public async Task The_acme_account_backfill_binds_by_label_ignoring_case_and_label_less_accounts_to_the_default()
    {
        var server = Environment.GetEnvironmentVariable(ServerVariable)!;
        var appName = $"modularca_upgrade_app_{Guid.NewGuid().ToString("N")[..12]}";
        await CreateDatabaseAsync(server, appName);
        try
        {
            await using var app = CreateApp(WithDatabase(server, appName));
            await app.GetService<IMigrator>().MigrateAsync(AppBaseline);
            await ExecAsync(app, Seed030Sql + SeedFoldSql);
            await MigrateThroughAsync(app, RenameTenantToSpace);

            await ExecAsync(app, SeedAcmeAccountsSql);
            await MigrateThroughAsync(app, BindAcmeAccountsToCa);

            async Task<string> BoundTo(Guid account) => await TextAsync(app,
                $"SELECT coalesce(\"CertificateAuthorityId\"::text, '') FROM \"AcmeAccounts\" WHERE \"Id\" = '{account}'");
            Assert.Equal(MixedCaseCa.ToString(), await BoundTo(MixedCaseAccount));
            Assert.Equal(RootCa.ToString(), await BoundTo(PaddedAccount));
            Assert.Equal(RetiredDefaultCa.ToString(), await BoundTo(RetiredAccount));
            Assert.Equal("", await BoundTo(GoneAccount));
            Assert.Equal(RootCa.ToString(), await BoundTo(LabelLessAccount));
            Assert.Equal(RootCa.ToString(), await BoundTo(BlankLabelAccount));
            Assert.Equal(6, await ScalarAsync(app, "SELECT count(*) FROM \"AcmeAccounts\""));

            await MigrateToLatestAsync(app, "application");
        }
        finally
        {
            NpgsqlConnection.ClearAllPools();
            await DropDatabaseAsync(server, appName);
        }
    }

    /// <summary>
    /// The <c>SshKeyStorage</c> backfill, seeded at the stage before it: an SSH CA key row that
    /// has a key file path becomes <c>LegacyFile</c>, so its key waits for the import into the
    /// signer; a row with an empty path is left at the column default, <c>Signer</c>. Afterwards
    /// the path may be null, and a row written without a storage gets <c>Signer</c>.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public async Task The_ssh_key_storage_backfill_marks_rows_with_a_key_file_as_legacy_files()
    {
        var server = Environment.GetEnvironmentVariable(ServerVariable)!;
        var appName = $"modularca_upgrade_app_{Guid.NewGuid().ToString("N")[..12]}";
        await CreateDatabaseAsync(server, appName);
        try
        {
            await using var app = CreateApp(WithDatabase(server, appName));
            await MigrateThroughAsync(app, ApiKeys);

            var ca = Guid.NewGuid();
            var withFile = Guid.NewGuid();
            var withoutFile = Guid.NewGuid();
            var added = Guid.NewGuid();
            const string columns = "\"Id\",\"Name\",\"KeyType\",\"PublicKey\",\"PrivateKeyPath\",\"CertificateAuthorityId\",\"IsUserCa\",\"IsHostCa\",\"MaxValidityHours\",\"IsEnabled\",\"CreatedAt\"";
            await ExecAsync(app,
                "INSERT INTO \"CertificateAuthorities\" (\"Id\",\"Name\",\"Label\",\"IsDefault\",\"Type\",\"IsEnabled\",\"KeyStorageType\",\"IsSshCa\",\"SpaceId\",\"IsDeleted\") "
                + $"VALUES ('{ca}','Ops SSH','ops-ssh',false,'SSH',true,'Software',true,NULL,false); "
                + $"INSERT INTO \"SshCaKeys\" ({columns}) "
                + $"VALUES ('{withFile}','Ops SSH','ed25519','ssh-ed25519 AAAA','config/ssh-ca-keys/{withFile}','{ca}',true,false,24,true,now()), "
                + $"('{withoutFile}','Ops SSH empty','ed25519','ssh-ed25519 AAAA','','{ca}',true,false,24,false,now());");

            await MigrateThroughAsync(app, SshKeyStorage);

            async Task<string> Storage(Guid key) => await TextAsync(app, $"SELECT \"KeyStorage\" FROM \"SshCaKeys\" WHERE \"Id\" = '{key}'");
            Assert.Equal("LegacyFile", await Storage(withFile));
            Assert.Equal("Signer", await Storage(withoutFile));
            Assert.Equal($"config/ssh-ca-keys/{withFile}", await TextAsync(app, $"SELECT \"PrivateKeyPath\" FROM \"SshCaKeys\" WHERE \"Id\" = '{withFile}'"));

            await ExecAsync(app,
                $"INSERT INTO \"SshCaKeys\" ({columns}) "
                + $"VALUES ('{added}','Ops SSH new','ed25519','ssh-ed25519 AAAA',NULL,'{ca}',true,false,24,true,now());");
            Assert.Equal("Signer", await Storage(added));
            Assert.Equal(1, await ScalarAsync(app, "SELECT count(*) FROM \"SshCaKeys\" WHERE \"PrivateKeyPath\" IS NULL"));
            Assert.Equal(3, await ScalarAsync(app, "SELECT count(*) FROM \"SshCaKeys\""));

            await MigrateToLatestAsync(app, "application");
        }
        finally
        {
            NpgsqlConnection.ClearAllPools();
            await DropDatabaseAsync(server, appName);
        }
    }

    /// <summary>
    /// The <c>SignerAuditSummary</c> column, seeded at the stage before it: the signer's audit
    /// rows written before the column keep every value they had and have no summary; the column
    /// takes a summary of the longest length the signer writes, and no longer; and a row of an
    /// operation that has none is still written without one.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public async Task The_signer_audit_summary_column_is_added_empty_and_old_rows_are_unchanged()
    {
        var server = Environment.GetEnvironmentVariable(ServerVariable)!;
        var appName = $"modularca_upgrade_app_{Guid.NewGuid().ToString("N")[..12]}";
        await CreateDatabaseAsync(server, appName);
        try
        {
            await using var app = CreateApp(WithDatabase(server, appName));
            await MigrateThroughAsync(app, SshKeyStorage);
            Assert.Equal(0, await ScalarAsync(app,
                "SELECT count(*) FROM information_schema.columns WHERE table_name = 'SignerAudit' AND column_name = 'Summary'"));

            var signed = Guid.NewGuid();
            var refused = Guid.NewGuid();
            var ca = Guid.NewGuid();
            var key = Guid.NewGuid();
            var hash = new string('a', 64);
            await ExecAsync(app,
                "INSERT INTO \"SignerAudit\" (\"Id\",\"At\",\"Operation\",\"Caller\",\"Purpose\",\"KeyCertificateId\",\"Keystore\",\"CaId\",\"SpaceId\",\"EffectiveScope\",\"Algorithm\",\"Outcome\",\"Reason\",\"DataHash\") "
                + $"VALUES ('{signed}','2026-10-01T12:00:00Z','Sign','control','Certificate','{key}','ca-certs.keystore','{ca}',NULL,'instance','SHA256withRSA','allowed',NULL,'{hash}'), "
                + $"('{refused}','2026-10-01T12:00:01Z','CommitKey','control','Ceremony','{key}','ssh-ca.keystore','{ca}',NULL,'instance',NULL,'refused','No SSH CA key row exists.',NULL);");
            const string everyOldColumn = "\"Id\"::text || '|' || to_char(\"At\" AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS') || '|' || \"Operation\" || '|' || \"Caller\" || '|' || \"Purpose\" || '|' || "
                + "\"KeyCertificateId\"::text || '|' || \"Keystore\" || '|' || \"CaId\"::text || '|' || coalesce(\"SpaceId\"::text,'-') || '|' || \"EffectiveScope\" || '|' || "
                + "coalesce(\"Algorithm\",'-') || '|' || \"Outcome\" || '|' || coalesce(\"Reason\",'-') || '|' || coalesce(\"DataHash\",'-')";
            async Task<string> Row(Guid id) => await TextAsync(app, $"SELECT {everyOldColumn} FROM \"SignerAudit\" WHERE \"Id\" = '{id}'");
            var signedBefore = await Row(signed);
            var refusedBefore = await Row(refused);

            await MigrateThroughAsync(app, SignerAuditSummary);

            Assert.Equal(signedBefore, await Row(signed));
            Assert.Equal(refusedBefore, await Row(refused));
            Assert.Equal(2, await ScalarAsync(app, "SELECT count(*) FROM \"SignerAudit\" WHERE \"Summary\" IS NULL"));
            Assert.Equal("YES", await TextAsync(app,
                "SELECT is_nullable FROM information_schema.columns WHERE table_name = 'SignerAudit' AND column_name = 'Summary'"));
            Assert.Equal(ModularCA.Shared.Entities.SignerAuditEntity.SummaryMaxLength, await ScalarAsync(app,
                "SELECT character_maximum_length FROM information_schema.columns WHERE table_name = 'SignerAudit' AND column_name = 'Summary'"));

            // A row with the longest summary the column holds goes in, one character more does
            // not, and a row of an operation with no summary is written as before.
            var longest = new string('x', ModularCA.Shared.Entities.SignerAuditEntity.SummaryMaxLength);
            var withSummary = Guid.NewGuid();
            const string newColumns = "\"Id\",\"At\",\"Operation\",\"Caller\",\"Purpose\",\"Keystore\",\"Outcome\",\"Summary\"";
            await ExecAsync(app,
                $"INSERT INTO \"SignerAudit\" ({newColumns}) VALUES ('{withSummary}',now(),'SignSsh','control','SshCertificate','ssh-ca.keystore','allowed','{longest}');");
            Assert.Equal(longest, await TextAsync(app, $"SELECT \"Summary\" FROM \"SignerAudit\" WHERE \"Id\" = '{withSummary}'"));
            await Assert.ThrowsAsync<PostgresException>(() => ExecAsync(app,
                $"INSERT INTO \"SignerAudit\" ({newColumns}) VALUES ('{Guid.NewGuid()}',now(),'SignSsh','control','SshCertificate','ssh-ca.keystore','allowed','{longest}x');"));
            await ExecAsync(app,
                $"INSERT INTO \"SignerAudit\" (\"Id\",\"At\",\"Operation\",\"Caller\",\"Purpose\",\"Outcome\") VALUES ('{Guid.NewGuid()}',now(),'Sign','control','Crl','allowed');");
            Assert.Equal(3, await ScalarAsync(app, "SELECT count(*) FROM \"SignerAudit\" WHERE \"Summary\" IS NULL"));
            Assert.Equal(4, await ScalarAsync(app, "SELECT count(*) FROM \"SignerAudit\""));

            await MigrateToLatestAsync(app, "application");
        }
        finally
        {
            NpgsqlConnection.ClearAllPools();
            await DropDatabaseAsync(server, appName);
        }
    }

    /// <summary>
    /// The <c>SshKeyImports</c> table, seeded at the stage before it: it is added empty, the SSH
    /// CA key rows are untouched, it takes one record per key and no second one, and a record
    /// outlives its key row, since the notice it is read for is about the past.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public async Task The_ssh_key_imports_table_is_added_empty_and_holds_one_record_per_key()
    {
        var server = Environment.GetEnvironmentVariable(ServerVariable)!;
        var appName = $"modularca_upgrade_app_{Guid.NewGuid().ToString("N")[..12]}";
        await CreateDatabaseAsync(server, appName);
        try
        {
            await using var app = CreateApp(WithDatabase(server, appName));
            await MigrateThroughAsync(app, SignerAuditSummary);
            Assert.Equal(0, await ScalarAsync(app, "SELECT count(*) FROM information_schema.tables WHERE table_name = 'SshKeyImports'"));

            var ca = Guid.NewGuid();
            var key = Guid.NewGuid();
            await ExecAsync(app,
                "INSERT INTO \"CertificateAuthorities\" (\"Id\",\"Name\",\"Label\",\"IsDefault\",\"Type\",\"IsEnabled\",\"KeyStorageType\",\"IsSshCa\",\"SpaceId\",\"IsDeleted\") "
                + $"VALUES ('{ca}','Ops SSH','ops-ssh',false,'SSH',true,'Software',true,NULL,false); "
                + "INSERT INTO \"SshCaKeys\" (\"Id\",\"Name\",\"KeyType\",\"PublicKey\",\"PrivateKeyPath\",\"KeyStorage\",\"CertificateAuthorityId\",\"IsUserCa\",\"IsHostCa\",\"MaxValidityHours\",\"IsEnabled\",\"CreatedAt\") "
                + $"VALUES ('{key}','Ops SSH','ed25519','ssh-ed25519 AAAA','config/ssh-ca-keys/{key}','LegacyFile','{ca}',true,false,24,true,now());");

            await MigrateThroughAsync(app, SshKeyImports);

            Assert.Equal(0, await ScalarAsync(app, "SELECT count(*) FROM \"SshKeyImports\""));
            Assert.Equal("LegacyFile", await TextAsync(app, $"SELECT \"KeyStorage\" FROM \"SshCaKeys\" WHERE \"Id\" = '{key}'"));
            Assert.Equal($"config/ssh-ca-keys/{key}", await TextAsync(app, $"SELECT \"PrivateKeyPath\" FROM \"SshCaKeys\" WHERE \"Id\" = '{key}'"));

            const string columns = "\"SshCaKeyId\",\"Name\",\"Fingerprint\",\"FilePath\",\"ImportedAt\"";
            await ExecAsync(app, $"INSERT INTO \"SshKeyImports\" ({columns}) VALUES ('{key}','Ops SSH','SHA256:abc','/opt/modularca/config/ssh-ca-keys/{key}',now());");
            Assert.Equal(1, await ScalarAsync(app, "SELECT count(*) FROM \"SshKeyImports\" WHERE \"FileRemovedAt\" IS NULL AND \"AuditedAt\" IS NULL"));
            await Assert.ThrowsAsync<PostgresException>(() => ExecAsync(app,
                $"INSERT INTO \"SshKeyImports\" ({columns}) VALUES ('{key}','Ops SSH again','SHA256:abc','/elsewhere',now());"));
            Assert.Equal(1024, await ScalarAsync(app,
                "SELECT character_maximum_length FROM information_schema.columns WHERE table_name = 'SshKeyImports' AND column_name = 'FilePath'"));

            // No foreign key: the record stays when its key row goes.
            await ExecAsync(app, $"DELETE FROM \"SshCaKeys\" WHERE \"Id\" = '{key}';");
            Assert.Equal(1, await ScalarAsync(app, "SELECT count(*) FROM \"SshKeyImports\""));

            await MigrateToLatestAsync(app, "application");
        }
        finally
        {
            NpgsqlConnection.ClearAllPools();
            await DropDatabaseAsync(server, appName);
        }
    }

    /// <summary>
    /// The <c>SshLoginNames</c> backfill, seeded at the stage before it. A user certificate whose
    /// key id is exactly its issuer's username gets that user as its subject. A key id that was
    /// typed, one that differs from the username in case, a host certificate, and a certificate
    /// with no issuer keep no subject. No certificate is revoked, none gets grounds, every
    /// existing SSH CA key lets everyone log in as their own username, and no grant is made.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public async Task The_ssh_login_names_backfill_gives_a_subject_only_where_the_key_id_is_the_issuer_s_username()
    {
        var server = Environment.GetEnvironmentVariable(ServerVariable)!;
        var appName = $"modularca_upgrade_app_{Guid.NewGuid().ToString("N")[..12]}";
        await CreateDatabaseAsync(server, appName);
        try
        {
            await using var app = CreateApp(WithDatabase(server, appName));
            await MigrateThroughAsync(app, SshKeyImports);
            Assert.Equal(0, await ScalarAsync(app, "SELECT count(*) FROM information_schema.tables WHERE table_name = 'SshLoginNameGrants'"));

            var ca = Guid.NewGuid();
            var key = Guid.NewGuid();
            var alice = Guid.NewGuid();
            var own = Guid.NewGuid();
            var typed = Guid.NewGuid();
            var otherCase = Guid.NewGuid();
            var host = Guid.NewGuid();
            var noIssuer = Guid.NewGuid();
            var revoked = Guid.NewGuid();
            const string certificateColumns = "\"Id\",\"SshCaKeyId\",\"CertificateType\",\"KeyId\",\"SerialNumber\",\"Principals\",\"ValidAfter\",\"ValidBefore\","
                + "\"PublicKey\",\"SignedCertificate\",\"IsRevoked\",\"IssuedByUserId\",\"CreatedAt\"";
            string Certificate(Guid id, string type, string keyId, int serial, string issuer, bool isRevoked = false)
                => $"('{id}','{key}','{type}','{keyId}',{serial},'[\"root\"]',now(),now() + interval '1 day','ssh-ed25519 AAAA','ssh-ed25519-cert-v01@openssh.com AAAA',"
                    + $"{(isRevoked ? "true" : "false")},{issuer},now())";
            await ExecAsync(app,
                "INSERT INTO \"CertificateAuthorities\" (\"Id\",\"Name\",\"Label\",\"IsDefault\",\"Type\",\"IsEnabled\",\"KeyStorageType\",\"IsSshCa\",\"SpaceId\",\"IsDeleted\") "
                + $"VALUES ('{ca}','Ops SSH','ops-ssh',false,'SSH',true,'Software',true,NULL,false); "
                + "INSERT INTO \"SshCaKeys\" (\"Id\",\"Name\",\"KeyType\",\"PublicKey\",\"KeyStorage\",\"CertificateAuthorityId\",\"IsUserCa\",\"IsHostCa\",\"MaxValidityHours\",\"IsEnabled\",\"CreatedAt\") "
                + $"VALUES ('{key}','Ops SSH','ed25519','ssh-ed25519 AAAA','Signer','{ca}',true,true,24,true,now()); "
                + "INSERT INTO \"Users\" (\"Id\",\"Username\",\"Email\",\"PasswordHash\",\"PasswordNeverExpires\",\"PasswordChangeOnNextLogon\",\"FirstName\","
                + "\"LastName\",\"IsActive\",\"IsServiceIdentity\",\"IsLocked\",\"FailedLoginAttempts\",\"CreatedAt\",\"SecurityStamp\",\"IsDeleted\") "
                + $"VALUES ('{alice}','alice','alice@acme.example','not-a-hash',false,false,'A','Lice',true,false,false,0,now(),'stamp',false); "
                + $"INSERT INTO \"SshCertificates\" ({certificateColumns}) VALUES "
                + Certificate(own, "user", "alice", 1, $"'{alice}'") + ", "
                + Certificate(typed, "user", "alice-laptop", 2, $"'{alice}'") + ", "
                + Certificate(otherCase, "user", "Alice", 3, $"'{alice}'") + ", "
                + Certificate(host, "host", "alice", 4, $"'{alice}'") + ", "
                + Certificate(noIssuer, "user", "alice", 5, "NULL") + ", "
                + Certificate(revoked, "user", "alice", 6, $"'{alice}'", isRevoked: true) + ";");

            await MigrateThroughAsync(app, SshLoginNames);

            async Task<string> Subject(Guid certificate)
                => await TextAsync(app, $"SELECT coalesce(\"SubjectUserId\"::text, 'none') FROM \"SshCertificates\" WHERE \"Id\" = '{certificate}'");
            Assert.Equal(alice.ToString(), await Subject(own));
            Assert.Equal(alice.ToString(), await Subject(revoked));
            Assert.Equal("none", await Subject(typed));
            Assert.Equal("none", await Subject(otherCase));
            Assert.Equal("none", await Subject(host));
            Assert.Equal("none", await Subject(noIssuer));

            Assert.Equal(6, await ScalarAsync(app, "SELECT count(*) FROM \"SshCertificates\" WHERE \"LoginNameGrounds\" IS NULL"));
            Assert.Equal(1, await ScalarAsync(app, "SELECT count(*) FROM \"SshCertificates\" WHERE \"IsRevoked\""));
            Assert.Equal(1, await ScalarAsync(app, $"SELECT count(*) FROM \"SshCaKeys\" WHERE \"Id\" = '{key}' AND \"AllowOwnUsername\""));
            Assert.Equal(0, await ScalarAsync(app, "SELECT count(*) FROM \"SshLoginNameGrants\""));

            // Deleting the user leaves the certificates, with no subject.
            await ExecAsync(app, $"UPDATE \"SshCertificates\" SET \"IssuedByUserId\" = NULL; DELETE FROM \"Users\" WHERE \"Id\" = '{alice}';");
            Assert.Equal(6, await ScalarAsync(app, "SELECT count(*) FROM \"SshCertificates\" WHERE \"SubjectUserId\" IS NULL"));

            await MigrateToLatestAsync(app, "application");
        }
        finally
        {
            NpgsqlConnection.ClearAllPools();
            await DropDatabaseAsync(server, appName);
        }
    }

    /// <summary>
    /// The <c>SshCertificateRevokedAt</c> column, seeded at the stage before it. It is added
    /// empty and may stay empty: a certificate that was already revoked stays revoked and gets
    /// no time, since none was recorded, and no other column of any row changes. The partial
    /// index a KRL's state is read from covers the revoked rows only, and the index on the key
    /// alone is still there. Afterwards a row takes a time.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public async Task The_ssh_certificate_revoked_at_column_is_added_empty_and_a_revoked_row_keeps_no_time()
    {
        var server = Environment.GetEnvironmentVariable(ServerVariable)!;
        var appName = $"modularca_upgrade_app_{Guid.NewGuid().ToString("N")[..12]}";
        await CreateDatabaseAsync(server, appName);
        try
        {
            await using var app = CreateApp(WithDatabase(server, appName));
            await MigrateThroughAsync(app, SshLoginNames);
            Assert.Equal(0, await ScalarAsync(app,
                "SELECT count(*) FROM information_schema.columns WHERE table_name = 'SshCertificates' AND column_name = 'RevokedAt'"));

            var ca = Guid.NewGuid();
            var key = Guid.NewGuid();
            var live = Guid.NewGuid();
            var revoked = Guid.NewGuid();
            var expiredAndRevoked = Guid.NewGuid();
            const string certificateColumns = "\"Id\",\"SshCaKeyId\",\"CertificateType\",\"KeyId\",\"SerialNumber\",\"Principals\",\"ValidAfter\",\"ValidBefore\","
                + "\"PublicKey\",\"SignedCertificate\",\"IsRevoked\",\"CreatedAt\"";
            string Certificate(Guid id, int serial, bool isRevoked, string validBefore)
                => $"('{id}','{key}','user','alice',{serial},'[\"alice\"]','2026-10-01T12:00:00Z',{validBefore},'ssh-ed25519 AAAA','ssh-ed25519-cert-v01@openssh.com AAAA',"
                    + $"{(isRevoked ? "true" : "false")},'2026-10-01T12:00:00Z')";
            await ExecAsync(app,
                "INSERT INTO \"CertificateAuthorities\" (\"Id\",\"Name\",\"Label\",\"IsDefault\",\"Type\",\"IsEnabled\",\"KeyStorageType\",\"IsSshCa\",\"SpaceId\",\"IsDeleted\") "
                + $"VALUES ('{ca}','Ops SSH','ops-ssh',false,'SSH',true,'Software',true,NULL,false); "
                + "INSERT INTO \"SshCaKeys\" (\"Id\",\"Name\",\"KeyType\",\"PublicKey\",\"KeyStorage\",\"CertificateAuthorityId\",\"IsUserCa\",\"IsHostCa\",\"MaxValidityHours\",\"IsEnabled\",\"CreatedAt\") "
                + $"VALUES ('{key}','Ops SSH','ed25519','ssh-ed25519 AAAA','Signer','{ca}',true,true,24,true,now()); "
                + $"INSERT INTO \"SshCertificates\" ({certificateColumns}) VALUES "
                + Certificate(live, 1, false, "now() + interval '1 day'") + ", "
                + Certificate(revoked, 2, true, "now() + interval '1 day'") + ", "
                + Certificate(expiredAndRevoked, 3, true, "'2026-10-02T12:00:00Z'") + ";");
            const string everyOldColumn = "\"Id\"::text || '|' || \"SshCaKeyId\"::text || '|' || \"CertificateType\" || '|' || \"KeyId\" || '|' || \"SerialNumber\"::text || '|' || "
                + "\"Principals\" || '|' || to_char(\"ValidAfter\" AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US') || '|' || "
                + "to_char(\"ValidBefore\" AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US') || '|' || \"PublicKey\" || '|' || \"SignedCertificate\" || '|' || "
                + "\"IsRevoked\"::text || '|' || coalesce(\"SubjectUserId\"::text,'-') || '|' || coalesce(\"LoginNameGrounds\",'-') || '|' || "
                + "to_char(\"CreatedAt\" AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US')";
            async Task<string> Row(Guid id) => await TextAsync(app, $"SELECT {everyOldColumn} FROM \"SshCertificates\" WHERE \"Id\" = '{id}'");
            var before = new[] { await Row(live), await Row(revoked), await Row(expiredAndRevoked) };

            await MigrateThroughAsync(app, SshCertificateRevokedAt);

            Assert.Equal(before, new[] { await Row(live), await Row(revoked), await Row(expiredAndRevoked) });
            Assert.Equal("YES", await TextAsync(app,
                "SELECT is_nullable FROM information_schema.columns WHERE table_name = 'SshCertificates' AND column_name = 'RevokedAt'"));
            Assert.Equal("timestamp with time zone", await TextAsync(app,
                "SELECT data_type FROM information_schema.columns WHERE table_name = 'SshCertificates' AND column_name = 'RevokedAt'"));
            Assert.Equal(3, await ScalarAsync(app, "SELECT count(*) FROM \"SshCertificates\" WHERE \"RevokedAt\" IS NULL"));
            Assert.Equal(2, await ScalarAsync(app, "SELECT count(*) FROM \"SshCertificates\" WHERE \"IsRevoked\""));

            var partial = await TextAsync(app, "SELECT indexdef FROM pg_indexes WHERE indexname = 'IX_SshCertificates_SshCaKeyId_RevokedAt'");
            Assert.Contains("(\"SshCaKeyId\", \"RevokedAt\")", partial);
            Assert.Contains("WHERE \"IsRevoked\"", partial);
            Assert.Equal(1, await ScalarAsync(app, "SELECT count(*) FROM pg_indexes WHERE indexname = 'IX_SshCertificates_SshCaKeyId'"));

            // From here on a revocation has a time, and the newest of a key is what its KRL is dated by.
            await ExecAsync(app, $"UPDATE \"SshCertificates\" SET \"IsRevoked\" = true, \"RevokedAt\" = '2026-10-08T09:30:00Z' WHERE \"Id\" = '{live}';");
            Assert.Equal("2026-10-08T09:30:00", await TextAsync(app,
                $"SELECT to_char(max(\"RevokedAt\") AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS') FROM \"SshCertificates\" WHERE \"SshCaKeyId\" = '{key}' AND \"IsRevoked\""));
            Assert.Equal(3, await ScalarAsync(app, $"SELECT count(*) FROM \"SshCertificates\" WHERE \"SshCaKeyId\" = '{key}' AND \"IsRevoked\""));

            await MigrateToLatestAsync(app, "application");
        }
        finally
        {
            NpgsqlConnection.ClearAllPools();
            await DropDatabaseAsync(server, appName);
        }
    }

    /// <summary>
    /// The <c>SshCaKeyReviewBy</c> column and its backfill, seeded at the stage before it. Every
    /// existing key gets a review date counted from when it was created: two years for a key
    /// that signs user certificates, alone or with host certificates, and five for a host-only
    /// key. A key whose date is then already past, and a disabled key, get theirs all the same
    /// and are otherwise untouched: no other column of a key changes, and no signing profile,
    /// certificate profile, request profile or certificate row is edited, here or by any later
    /// migration, beyond the certificate type <c>SshProfileCertificateType</c> adds to a profile.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public async Task The_ssh_ca_key_review_date_is_set_from_each_key_s_creation_and_no_profile_or_other_column_changes()
    {
        var server = Environment.GetEnvironmentVariable(ServerVariable)!;
        var appName = $"modularca_upgrade_app_{Guid.NewGuid().ToString("N")[..12]}";
        await CreateDatabaseAsync(server, appName);
        try
        {
            await using var app = CreateApp(WithDatabase(server, appName));
            await MigrateThroughAsync(app, SshCertificateRevokedAt);
            Assert.Equal(0, await ScalarAsync(app,
                "SELECT count(*) FROM information_schema.columns WHERE table_name = 'SshCaKeys' AND column_name = 'ReviewBy'"));

            var userKey = Guid.NewGuid();
            var bothKey = Guid.NewGuid();
            var hostKey = Guid.NewGuid();
            var oldKey = Guid.NewGuid();
            var disabledKey = Guid.NewGuid();
            var leapKey = Guid.NewGuid();
            var signingProfile = Guid.NewGuid();
            var certProfile = Guid.NewGuid();
            var requestProfile = Guid.NewGuid();
            var certificate = Guid.NewGuid();
            var sql = new System.Text.StringBuilder();
            void Key(Guid id, string name, bool user, bool host, int hours, bool enabled, string createdAt)
            {
                var ca = Guid.NewGuid();
                sql.Append("INSERT INTO \"CertificateAuthorities\" (\"Id\",\"Name\",\"Label\",\"IsDefault\",\"Type\",\"IsEnabled\",\"KeyStorageType\",\"IsSshCa\",\"SpaceId\",\"IsDeleted\") "
                    + $"VALUES ('{ca}','{name}','{name.ToLowerInvariant().Replace(' ', '-')}',false,'SSH',{(enabled ? "true" : "false")},'Software',true,NULL,false); "
                    + "INSERT INTO \"SshCaKeys\" (\"Id\",\"Name\",\"KeyType\",\"PublicKey\",\"KeyStorage\",\"CertificateAuthorityId\",\"IsUserCa\",\"IsHostCa\",\"MaxValidityHours\",\"AllowOwnUsername\",\"IsEnabled\",\"CreatedAt\") "
                    + $"VALUES ('{id}','{name}','ed25519','ssh-ed25519 AAAA','Signer','{ca}',{(user ? "true" : "false")},{(host ? "true" : "false")},{hours},true,{(enabled ? "true" : "false")},'{createdAt}'); ");
            }
            Key(userKey, "Users SSH", user: true, host: false, 720, enabled: true, "2026-03-01T08:15:30.123456Z");
            Key(bothKey, "Both SSH", user: true, host: true, 720, enabled: true, "2026-03-01T08:15:30Z");
            Key(hostKey, "Hosts SSH", user: false, host: true, 8760, enabled: true, "2026-03-01T08:15:30Z");
            Key(oldKey, "Old SSH", user: true, host: false, 24, enabled: true, "2021-06-30T23:30:00Z");
            Key(disabledKey, "Disabled SSH", user: true, host: false, 24, enabled: false, "2025-01-01T00:00:00Z");
            Key(leapKey, "Leap SSH", user: true, host: false, 24, enabled: true, "2024-02-29T23:30:00Z");
            sql.Append("INSERT INTO \"SshSigningProfiles\" (\"Id\",\"Name\",\"SshCaKeyId\",\"MaxValidityHours\",\"AllowUserCerts\",\"AllowHostCerts\",\"SourceAddressRestrictions\",\"DefaultExtensions\",\"CreatedAt\") "
                + $"VALUES ('{signingProfile}','Users SSH - User Signing','{userKey}',24,true,false,'[]','[\"permit-pty\",\"permit-agent-forwarding\",\"permit-port-forwarding\"]','2026-03-01T08:15:30Z'); "
                + "INSERT INTO \"SshCertProfiles\" (\"Id\",\"Name\",\"AllowedPrincipalPatterns\",\"MaxPrincipals\",\"AllowedExtensions\",\"RequiredExtensions\",\"MaxValidityHours\",\"CreatedAt\") "
                + $"VALUES ('{certProfile}','SSH User Cert - Standard','[\"^[a-z_][a-z0-9_-]{{0,31}}$\"]',5,"
                + "'[\"permit-pty\",\"permit-agent-forwarding\",\"permit-port-forwarding\",\"permit-X11-forwarding\",\"permit-user-rc\"]','[]',24,'2026-03-01T08:15:30Z'); "
                + "INSERT INTO \"SshRequestProfiles\" (\"Id\",\"Name\",\"AllowedSshSigningProfileIds\",\"AllowedSshCertProfileIds\",\"RequireApproval\",\"MaxValidityHours\",\"CreatedAt\") "
                + $"VALUES ('{requestProfile}','SSH User Request - Default','[]','[\"{certProfile}\"]',false,24,'2026-03-01T08:15:30Z'); "
                + "INSERT INTO \"SshCertificates\" (\"Id\",\"SshCaKeyId\",\"CertificateType\",\"KeyId\",\"SerialNumber\",\"Principals\",\"ValidAfter\",\"ValidBefore\",\"PublicKey\",\"SignedCertificate\",\"IsRevoked\",\"CreatedAt\") "
                + $"VALUES ('{certificate}','{oldKey}','user','alice',1,'[\"alice\"]',now(),now() + interval '1 day','ssh-ed25519 AAAA','ssh-ed25519-cert-v01@openssh.com AAAA',false,now());");
            await ExecAsync(app, sql.ToString());

            const string everyOldKeyColumn = "\"Id\"::text || '|' || \"Name\" || '|' || \"KeyType\" || '|' || coalesce(\"KeySize\"::text,'-') || '|' || \"PublicKey\" || '|' || "
                + "coalesce(\"PrivateKeyPath\",'-') || '|' || \"KeyStorage\" || '|' || \"CertificateAuthorityId\"::text || '|' || \"IsUserCa\"::text || '|' || \"IsHostCa\"::text || '|' || "
                + "\"MaxValidityHours\"::text || '|' || \"AllowOwnUsername\"::text || '|' || \"IsEnabled\"::text || '|' || to_char(\"CreatedAt\" AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US')";
            async Task<string> Keys() => await TextAsync(app, $"SELECT string_agg({everyOldKeyColumn}, E'\\n' ORDER BY \"Id\") FROM \"SshCaKeys\"");
            // Every column but the profile type, which SshProfileCertificateType adds later and sets on the profiles a new install seeds.
            async Task<string> Rows(string table) => await TextAsync(app,
                $"SELECT string_agg((to_jsonb(t) - 'CertificateType')::text, E'\\n' ORDER BY t.\"Id\") FROM \"{table}\" t");
            var keysBefore = await Keys();
            var signingBefore = await Rows("SshSigningProfiles");
            var certProfilesBefore = await Rows("SshCertProfiles");
            var requestProfilesBefore = await Rows("SshRequestProfiles");
            var certificatesBefore = await Rows("SshCertificates");

            await MigrateThroughAsync(app, SshCaKeyReviewBy);

            Assert.Equal("YES", await TextAsync(app,
                "SELECT is_nullable FROM information_schema.columns WHERE table_name = 'SshCaKeys' AND column_name = 'ReviewBy'"));
            Assert.Equal("timestamp with time zone", await TextAsync(app,
                "SELECT data_type FROM information_schema.columns WHERE table_name = 'SshCaKeys' AND column_name = 'ReviewBy'"));
            async Task<string> ReviewBy(Guid key) => await TextAsync(app,
                $"SELECT to_char(\"ReviewBy\" AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US') FROM \"SshCaKeys\" WHERE \"Id\" = '{key}'");
            Assert.Equal("2028-03-01T08:15:30.123456", await ReviewBy(userKey));
            Assert.Equal("2028-03-01T08:15:30.000000", await ReviewBy(bothKey));
            Assert.Equal("2031-03-01T08:15:30.000000", await ReviewBy(hostKey));
            Assert.Equal("2023-06-30T23:30:00.000000", await ReviewBy(oldKey));
            Assert.Equal("2027-01-01T00:00:00.000000", await ReviewBy(disabledKey));
            Assert.Equal("2026-02-28T23:30:00.000000", await ReviewBy(leapKey));
            Assert.Equal(0, await ScalarAsync(app, "SELECT count(*) FROM \"SshCaKeys\" WHERE \"ReviewBy\" IS NULL"));

            // The same rule as a key created from now on is given.
            Assert.Equal(new DateTime(2028, 3, 1, 8, 15, 30, DateTimeKind.Utc),
                ModularCA.Shared.Utils.SshCaKeyDefaults.ReviewBy(new DateTime(2026, 3, 1, 8, 15, 30, DateTimeKind.Utc), isUserCa: true, isHostCa: true));
            Assert.Equal(new DateTime(2031, 3, 1, 8, 15, 30, DateTimeKind.Utc),
                ModularCA.Shared.Utils.SshCaKeyDefaults.ReviewBy(new DateTime(2026, 3, 1, 8, 15, 30, DateTimeKind.Utc), isUserCa: false, isHostCa: true));
            Assert.Equal(new DateTime(2026, 2, 28, 23, 30, 0, DateTimeKind.Utc),
                ModularCA.Shared.Utils.SshCaKeyDefaults.ReviewBy(new DateTime(2024, 2, 29, 23, 30, 0, DateTimeKind.Utc), isUserCa: true, isHostCa: false));

            // A key long past its date is as enabled as it was, and its certificate as live.
            Assert.Equal(keysBefore, await Keys());
            Assert.Equal(1, await ScalarAsync(app, $"SELECT count(*) FROM \"SshCaKeys\" WHERE \"Id\" = '{oldKey}' AND \"IsEnabled\" AND \"ReviewBy\" < now()"));
            Assert.Equal(1, await ScalarAsync(app, $"SELECT count(*) FROM \"SshCertificates\" WHERE \"Id\" = '{certificate}' AND NOT \"IsRevoked\""));

            await MigrateToLatestAsync(app, "application");

            // No migration edits what a profile allows: the profiles of an existing install stay as seeded before,
            // and gain only the certificate type their seeded names stand for.
            Assert.Equal(keysBefore, await Keys());
            Assert.Equal(signingBefore, await Rows("SshSigningProfiles"));
            Assert.Equal(certProfilesBefore, await Rows("SshCertProfiles"));
            Assert.Equal(requestProfilesBefore, await Rows("SshRequestProfiles"));
            Assert.Equal(certificatesBefore, await Rows("SshCertificates"));
            Assert.Equal(1, await ScalarAsync(app, "SELECT count(*) FROM \"SshCertProfiles\""));

            // The column takes a date and takes none.
            await ExecAsync(app, $"UPDATE \"SshCaKeys\" SET \"ReviewBy\" = '2030-01-01T00:00:00Z' WHERE \"Id\" = '{userKey}'; UPDATE \"SshCaKeys\" SET \"ReviewBy\" = NULL WHERE \"Id\" = '{hostKey}';");
            Assert.Equal("2030-01-01T00:00:00.000000", await ReviewBy(userKey));
            Assert.Equal(1, await ScalarAsync(app, "SELECT count(*) FROM \"SshCaKeys\" WHERE \"ReviewBy\" IS NULL"));
        }
        finally
        {
            NpgsqlConnection.ClearAllPools();
            await DropDatabaseAsync(server, appName);
        }
    }

    /// <summary>
    /// The <c>SshProfileCertificateType</c> columns and their backfill, seeded at the stage before
    /// them. The three certificate profiles and two request profiles a new install seeds get
    /// their type, found by their exact names: <c>user</c> for the user profiles, <c>host</c> for
    /// the host profiles. Every other profile stays without one, a name that only resembles a
    /// seeded one and a seeded name in another letter case included, and no other column of any
    /// profile changes.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public async Task The_ssh_profile_certificate_type_is_set_on_the_seeded_names_only_and_every_other_profile_stays_without_one()
    {
        var server = Environment.GetEnvironmentVariable(ServerVariable)!;
        const string typesOf = "SELECT string_agg(\"Name\"::text || '=' || coalesce(\"CertificateType\", 'none'), E'\\n' ORDER BY \"Name\"::text COLLATE \"C\") FROM \"{0}\"";
        const string columnCount = "SELECT count(*) FROM information_schema.columns WHERE table_name = '{0}' AND column_name = 'CertificateType'";

        static string Seed(string[] certProfiles, string[] requestProfiles)
        {
            var sql = new System.Text.StringBuilder();
            foreach (var name in certProfiles)
                sql.Append("INSERT INTO \"SshCertProfiles\" (\"Id\",\"Name\",\"AllowedPrincipalPatterns\",\"MaxPrincipals\",\"AllowedExtensions\",\"RequiredExtensions\",\"MaxValidityHours\",\"CreatedAt\") "
                    + $"VALUES ('{Guid.NewGuid()}','{name}','[]',5,'[\"permit-pty\"]','[]',24,'2026-03-01T08:15:30Z'); ");
            foreach (var name in requestProfiles)
                sql.Append("INSERT INTO \"SshRequestProfiles\" (\"Id\",\"Name\",\"AllowedSshSigningProfileIds\",\"AllowedSshCertProfileIds\",\"RequireApproval\",\"MaxValidityHours\",\"CreatedAt\") "
                    + $"VALUES ('{Guid.NewGuid()}','{name}','[]','[]',false,24,'2026-03-01T08:15:30Z'); ");
            return sql.ToString();
        }

        var appName = $"modularca_upgrade_app_{Guid.NewGuid().ToString("N")[..12]}";
        await CreateDatabaseAsync(server, appName);
        try
        {
            await using var app = CreateApp(WithDatabase(server, appName));
            await MigrateThroughAsync(app, SshCaKeyReviewBy);
            Assert.Equal(0, await ScalarAsync(app, string.Format(columnCount, "SshCertProfiles")));
            Assert.Equal(0, await ScalarAsync(app, string.Format(columnCount, "SshRequestProfiles")));

            await ExecAsync(app, Seed(
                ["SSH User Cert - Standard", "SSH User Cert - Forwarding", "SSH Host Cert - Standard", "Ops users", "SSH User Cert - Standard 2", "SSH Host Cert"],
                ["SSH User Request - Default", "SSH Host Request - Default", "Developers", "SSH Host Request - Default (copy)"]));
            async Task<string> Rows(string table) => await TextAsync(app,
                $"SELECT string_agg((to_jsonb(t) - 'CertificateType')::text, E'\\n' ORDER BY t.\"Id\") FROM \"{table}\" t");
            var certProfilesBefore = await Rows("SshCertProfiles");
            var requestProfilesBefore = await Rows("SshRequestProfiles");

            await MigrateThroughAsync(app, SshProfileCertificateType);

            foreach (var table in new[] { "SshCertProfiles", "SshRequestProfiles" })
            {
                Assert.Equal("YES", await TextAsync(app, $"SELECT is_nullable FROM information_schema.columns WHERE table_name = '{table}' AND column_name = 'CertificateType'"));
                Assert.Equal("character varying", await TextAsync(app, $"SELECT data_type FROM information_schema.columns WHERE table_name = '{table}' AND column_name = 'CertificateType'"));
                Assert.Equal(10, await ScalarAsync(app, $"SELECT character_maximum_length FROM information_schema.columns WHERE table_name = '{table}' AND column_name = 'CertificateType'"));
            }

            Assert.Equal(
                "Ops users=none\nSSH Host Cert=none\nSSH Host Cert - Standard=host\nSSH User Cert - Forwarding=user\nSSH User Cert - Standard=user\nSSH User Cert - Standard 2=none",
                await TextAsync(app, string.Format(typesOf, "SshCertProfiles")));
            Assert.Equal(
                "Developers=none\nSSH Host Request - Default=host\nSSH Host Request - Default (copy)=none\nSSH User Request - Default=user",
                await TextAsync(app, string.Format(typesOf, "SshRequestProfiles")));

            // Nothing else about a profile changed, here or in any later migration.
            Assert.Equal(certProfilesBefore, await Rows("SshCertProfiles"));
            Assert.Equal(requestProfilesBefore, await Rows("SshRequestProfiles"));
            await MigrateToLatestAsync(app, "application");
            Assert.Equal(certProfilesBefore, await Rows("SshCertProfiles"));
            Assert.Equal(requestProfilesBefore, await Rows("SshRequestProfiles"));
            Assert.Equal(3, await ScalarAsync(app, "SELECT count(*) FROM \"SshCertProfiles\" WHERE \"CertificateType\" IS NOT NULL"));
            Assert.Equal(2, await ScalarAsync(app, "SELECT count(*) FROM \"SshRequestProfiles\" WHERE \"CertificateType\" IS NOT NULL"));

            // The column takes either type and takes none.
            await ExecAsync(app, "UPDATE \"SshCertProfiles\" SET \"CertificateType\" = 'host' WHERE \"Name\" = 'Ops users'; "
                + "UPDATE \"SshRequestProfiles\" SET \"CertificateType\" = NULL WHERE \"Name\" = 'SSH User Request - Default';");
            Assert.Equal(4, await ScalarAsync(app, "SELECT count(*) FROM \"SshCertProfiles\" WHERE \"CertificateType\" IS NOT NULL"));
            Assert.Equal(1, await ScalarAsync(app, "SELECT count(*) FROM \"SshRequestProfiles\" WHERE \"CertificateType\" IS NOT NULL"));
        }
        finally
        {
            NpgsqlConnection.ClearAllPools();
            await DropDatabaseAsync(server, appName);
        }

        // The names are matched exactly: a seeded name in another letter case is another profile, and gets no type.
        var otherCase = $"modularca_upgrade_app_{Guid.NewGuid().ToString("N")[..12]}";
        await CreateDatabaseAsync(server, otherCase);
        try
        {
            await using var app = CreateApp(WithDatabase(server, otherCase));
            await MigrateThroughAsync(app, SshCaKeyReviewBy);
            await ExecAsync(app, Seed(
                ["ssh user cert - standard", "SSH USER CERT - FORWARDING", "Ssh Host Cert - Standard"],
                ["ssh user request - default", "SSH HOST REQUEST - DEFAULT"]));

            await MigrateToLatestAsync(app, "application");

            Assert.Equal(3, await ScalarAsync(app, "SELECT count(*) FROM \"SshCertProfiles\" WHERE \"CertificateType\" IS NULL"));
            Assert.Equal(2, await ScalarAsync(app, "SELECT count(*) FROM \"SshRequestProfiles\" WHERE \"CertificateType\" IS NULL"));
        }
        finally
        {
            NpgsqlConnection.ClearAllPools();
            await DropDatabaseAsync(server, otherCase);
        }
    }

    /// <summary>
    /// The SSH part of <c>--upgrade-check</c> against a database from before the SSH keystore:
    /// every key file there and holding its key is clean, with the count; a file that is gone
    /// refuses the upgrade, naming the SSH CA, its row and the path, until the file is back or
    /// the SSH CA is disabled; and the user signing profiles whose certificates will carry fewer
    /// permits are noted without refusing anything. Nothing is applied and no file is touched.
    /// </summary>
    [RequiresEnvironmentFact(ServerVariable)]
    public async Task The_upgrade_check_reports_the_ssh_ca_key_files_and_the_signing_profiles_that_relied_on_default_extensions()
    {
        var server = Environment.GetEnvironmentVariable(ServerVariable)!;
        var appName = $"modularca_upgrade_app_{Guid.NewGuid().ToString("N")[..12]}";
        var install = Path.Combine(Path.GetTempPath(), $"mca-upgrade-ssh-{Guid.NewGuid():N}");
        await CreateDatabaseAsync(server, appName);
        try
        {
            var connection = WithDatabase(server, appName);
            await using var app = CreateApp(connection);
            await MigrateThroughAsync(app, ApiKeys);
            var targets = new[] { ("application", DatabaseKind.Application, Instance(connection)) };
            async Task<(int Exit, string Report)> CheckAsync()
            {
                var output = new StringWriter();
                var exit = await SchemaStartupApi.UpgradeCheckAsync(targets, new SchemaConfig(), output, installDirectory: install);
                return (exit, output.ToString());
            }

            // No SSH CA at all.
            var (exit, report) = await CheckAsync();
            Assert.Equal(0, exit);
            Assert.Contains("SSH CA keys: key files on this host", report);
            Assert.Contains("ok: no SSH CA key is a file on a node; nothing to import.", report);
            Assert.DoesNotContain("SSH signing profiles", report);

            // One SSH CA with its key file where its row says, relative as an older install could record it, and two user profiles.
            var ca = Guid.NewGuid();
            var key = Guid.NewGuid();
            var keys = Path.Combine(install, "config", "ssh-ca-keys");
            Directory.CreateDirectory(keys);
            var keyFile = Path.Combine(keys, key.ToString());
            File.Copy(ModularCA.Tests.Ssh.SshFixtures.PathOf("ca-ed25519.testkey"), keyFile);
            var publicKey = ModularCA.Tests.Ssh.SshFixtures.Text("ca-ed25519.pub").Trim();
            var narrow = Guid.NewGuid();
            var complete = Guid.NewGuid();
            const string profileColumns = "\"Id\",\"Name\",\"SshCaKeyId\",\"MaxValidityHours\",\"AllowUserCerts\",\"AllowHostCerts\",\"SourceAddressRestrictions\",\"DefaultExtensions\",\"CreatedAt\"";
            await ExecAsync(app,
                "INSERT INTO \"CertificateAuthorities\" (\"Id\",\"Name\",\"Label\",\"IsDefault\",\"Type\",\"IsEnabled\",\"KeyStorageType\",\"IsSshCa\",\"SpaceId\",\"IsDeleted\") "
                + $"VALUES ('{ca}','Ops SSH','ops-ssh',false,'SSH',true,'Software',true,NULL,false); "
                + "INSERT INTO \"SshCaKeys\" (\"Id\",\"Name\",\"KeyType\",\"PublicKey\",\"PrivateKeyPath\",\"CertificateAuthorityId\",\"IsUserCa\",\"IsHostCa\",\"MaxValidityHours\",\"IsEnabled\",\"CreatedAt\") "
                + $"VALUES ('{key}','Ops SSH','ed25519','{publicKey}','config/ssh-ca-keys/{key}','{ca}',true,false,24,true,now()); "
                + $"INSERT INTO \"SshSigningProfiles\" ({profileColumns}) VALUES "
                + $"('{narrow}','Ops SSH - User Signing','{key}',24,true,false,'[]','[\"permit-pty\"]',now()), "
                + $"('{complete}','Ops SSH - Everything','{key}',24,true,false,'[]','[\"permit-X11-forwarding\",\"permit-agent-forwarding\",\"permit-port-forwarding\",\"permit-pty\",\"permit-user-rc\"]',now());");

            (exit, report) = await CheckAsync();
            Assert.Equal(0, exit);
            Assert.Contains("ok: 1 SSH CA key(s) will be imported into the signer at first start and their files deleted; "
                + "archives made before this upgrade still contain them in plaintext", report);
            Assert.Contains("SSH signing profiles", report);
            Assert.Contains("note: 1 SSH signing profile(s) for user certificates relied on the extensions", report);
            Assert.Contains($"'Ops SSH - User Signing' ({narrow}): names permit-pty; certificates from it will no longer carry "
                + "permit-X11-forwarding, permit-agent-forwarding, permit-port-forwarding, permit-user-rc", report);
            Assert.DoesNotContain("Ops SSH - Everything", report);
            Assert.DoesNotContain("REFUSED", report);
            Assert.Contains("UPGRADE CHECK: PASS", report);

            // The key file is gone: the upgrade is refused, by name, row and path, and the note is still only a note.
            var bytes = File.ReadAllBytes(keyFile);
            File.Delete(keyFile);
            (exit, report) = await CheckAsync();
            Assert.Equal(3, exit);
            Assert.Contains("REFUSED: 1 SSH CA key file(s) are missing or do not hold their SSH CA's key.", report);
            Assert.Contains($"'Ops SSH' ({key}), expected at {keyFile}", report);
            Assert.Contains("run this check on that host", report);
            Assert.Contains("UPGRADE CHECK: REFUSED (SSH CA keys: 1 key file(s) missing or not matching). Nothing was changed.", report);

            // Disabling the SSH CA is the other way out.
            await ExecAsync(app, $"UPDATE \"SshCaKeys\" SET \"IsEnabled\" = false WHERE \"Id\" = '{key}'; UPDATE \"CertificateAuthorities\" SET \"IsEnabled\" = false WHERE \"Id\" = '{ca}';");
            (exit, report) = await CheckAsync();
            Assert.Equal(0, exit);
            Assert.Contains("1 disabled SSH CA key(s) have no usable key file and stay as they are", report);

            // Nothing was applied, and the check read the key file without changing it.
            await ExecAsync(app, $"UPDATE \"SshCaKeys\" SET \"IsEnabled\" = true WHERE \"Id\" = '{key}'; UPDATE \"CertificateAuthorities\" SET \"IsEnabled\" = true WHERE \"Id\" = '{ca}';");
            File.WriteAllBytes(keyFile, bytes);
            (exit, _) = await CheckAsync();
            Assert.Equal(0, exit);
            Assert.Equal(bytes, File.ReadAllBytes(keyFile));
            Assert.Equal(0, await ScalarAsync(app,
                "SELECT count(*) FROM information_schema.columns WHERE table_name = 'SshCaKeys' AND column_name = 'KeyStorage'"));

            // After the upgrade the same check still finds the key awaiting its import, and words the note for a change that has happened.
            await MigrateToLatestAsync(app, "application");
            (exit, report) = await CheckAsync();
            Assert.Equal(0, exit);
            Assert.Contains("ok: 1 SSH CA key(s) will be imported into the signer at first start", report);
            Assert.Contains("name fewer permits than every user certificate carried by default", report);
            Assert.DoesNotContain("will be narrower than before", report);
        }
        finally
        {
            NpgsqlConnection.ClearAllPools();
            await DropDatabaseAsync(server, appName);
            try { Directory.Delete(install, true); } catch (IOException) { }
        }
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

    /// <summary>The retired chains' tenants: one organisation and the system tenant.</summary>
    private static readonly Guid[] AuditTenantChains = [OrgTenant, SystemTenant];

    /// <summary>
    /// Writes, in SQL against the baseline audit schema, three instance-chain records and two
    /// records on each of <paramref name="tenantChains"/>, each hashed by the real
    /// <see cref="AuditHashChainService.ComputeHash"/> and linked to the one before it.
    /// </summary>
    private static async Task SeedAuditChainsAsync(DbContext audit, IReadOnlyList<Guid> tenantChains)
    {
        var start = new DateTime(2026, 9, 1, 8, 0, 0, DateTimeKind.Utc);
        var rows = new List<ModularCA.Shared.Entities.AuditLogEntity>();
        foreach (var (tenant, count) in new (Guid?, int)[] { (null, 3) }.Concat(tenantChains.Select(t => ((Guid?)t, 2))))
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
    /// that exactly <paramref name="tenantChains"/> were sealed, every chain verifies with no
    /// break, and each retired chain reports <see cref="RetiredChainState.Sealed"/>.
    /// </summary>
    private static async Task AssertAuditChainsSealedAsync(AuditDbContext audit, IReadOnlyList<Guid> tenantChains)
    {
        var chains = new AuditHashChainService();
        Assert.Equal(tenantChains.OrderBy(g => g), (await chains.SealRetiredChainsAsync(audit)).OrderBy(g => g));

        var instance = await chains.VerifyAsync(audit, null);
        Assert.Empty(instance.Breaks);
        Assert.Equal(3 + tenantChains.Count, instance.RecordsVerified);
        foreach (var tenant in tenantChains)
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

    /// <summary>
    /// ACME accounts and the CAs they name, at the names of the stage before
    /// <c>BindAcmeAccountsToCa</c>. Beside the root CA (default, "Acme Root CA"): a CA labelled
    /// <c>mixed-case</c>; a second default named to sort after the root; and defaults named to sort
    /// before it that the label-less resolution must pass over: soft-deleted (labelled
    /// <c>retired</c>), disabled, <c>system-</c> labelled and SSH. Accounts label <c>Mixed-CASE</c>,
    /// <c> acme-root </c>, <c>retired</c>, <c>gone</c> (no CA), nothing, and blanks. Run after
    /// <see cref="SeedFoldSql"/>.
    /// </summary>
    internal static string SeedAcmeAccountsSql => $"""

        INSERT INTO "CertificateAuthorities" ("Id","Name","Label","IsDefault","Type","IsEnabled","KeyStorageType","IsSshCa","SpaceId","IsDeleted")
        VALUES ('{MixedCaseCa}','Mixed Case CA','mixed-case',false,'Root',true,'Software',false,'{OrgTenant}',false),
               ('{ZetaDefaultCa}','Zeta Default CA','zeta',true,'Root',true,'Software',false,'{OrgTenant}',false),
               ('{RetiredDefaultCa}','Aaa Retired CA','retired',true,'Root',true,'Software',false,'{OrgTenant}',true),
               ('{DisabledDefaultCa}','Aab Disabled CA','disabled',true,'Root',false,'Software',false,'{OrgTenant}',false),
               ('{ReservedDefaultCa}','Aac Reserved CA','system-reserved',true,'Root',true,'Software',false,NULL,false),
               ('{SshDefaultCa}','Aad SSH CA','aad-ssh',true,'SSH',true,'Software',true,NULL,false);

        INSERT INTO "AcmeAccounts" ("Id","JwkJson","JwkThumbprint","ContactsJson","Status","TermsOfServiceAgreed","CreatedAt","CaLabel")
        VALUES ('{MixedCaseAccount}','jwk','thumb-mixed','[]','Valid',true,now(),'Mixed-CASE'),
               ('{PaddedAccount}','jwk','thumb-padded','[]','Valid',true,now(),' acme-root '),
               ('{RetiredAccount}','jwk','thumb-retired','[]','Valid',true,now(),'retired'),
               ('{GoneAccount}','jwk','thumb-gone','[]','Valid',true,now(),'gone'),
               ('{LabelLessAccount}','jwk','thumb-label-less','[]','Valid',true,now(),NULL),
               ('{BlankLabelAccount}','jwk','thumb-blank','[]','Valid',true,now(),'   ');
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
