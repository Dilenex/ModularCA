using ModularCA.Database;
using ModularCA.Migrate;
using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// The provisioning plan <see cref="PostgresRoleLayout"/> builds for bootstrap, per server
/// version and per state of the cluster, and every reason it refuses before any DDL. Pure: no
/// server is involved.
/// </summary>
public class PostgresRoleLayoutTests
{
    private const string AppPassword = "app-pass-0123456789";
    private const string AuditPassword = "audit-pass-0123456789";

    private static readonly PostgresLayoutNames Names =
        new("postgres", "modularca_app", "modularca_audit", "modularca-app", "modularca-audit");

    private static readonly ProvisioningMode Fresh = new(ResetApp: true, WipeAudit: false);

    private static ClusterFacts Facts(
        int version = 160004, bool superuser = true, bool appExists = false, bool auditExists = false,
        string? auditOwner = null, SchemaState? auditState = null, params ExistingRole[] roles) =>
        new("postgres", superuser, version, appExists, auditExists, auditOwner, auditState,
            roles.ToDictionary(r => r.Name, StringComparer.Ordinal));

    private static ExistingRole Role(string name, bool canLogin = true, bool createDb = false, bool superuser = false, params string[] memberOf) =>
        new(name, canLogin, superuser, createDb, false, false, false, memberOf);

    private static SchemaState AuditState(DatabasePresence presence, params string[] applied) =>
        new(applied, [PostgresUpgradeHarnessTests.AuditBaseline]) { Presence = presence };

    [Theory]
    [InlineData(140000)]
    [InlineData(150000)]
    [InlineData(160004)]
    public void Schema_public_is_decided_from_its_actual_owner_and_acl_on_every_server_version(int version)
    {
        var plan = PostgresRoleLayout.Plan(Facts(version), Names, Fresh, AppPassword, AuditPassword);

        var schemaSteps = plan.Where(s => s.Sql.Contains("ALTER SCHEMA public OWNER TO", StringComparison.Ordinal)).ToList();
        Assert.Equal(2, schemaSteps.Count);
        var app = Assert.Single(schemaSteps, s => s.Database == "modularca-app");
        Assert.Equal(PostgresRoleLayout.PublicSchemaSql("modularca_app"), app.Sql);
        var audit = Assert.Single(schemaSteps, s => s.Database == "modularca-audit");
        Assert.Equal(PostgresRoleLayout.PublicSchemaSql("modularca_audit_owner"), audit.Sql);
        Assert.True(plan.ToList().IndexOf(app) < plan.ToList().FindIndex(s => s.Sql.Contains("CREATE EXTENSION")));
    }

    [Fact]
    public void The_public_schema_block_reads_the_owner_and_publics_create_right_rather_than_the_version()
    {
        var sql = PostgresRoleLayout.PublicSchemaSql("mca-app");

        Assert.StartsWith("DO $public$", sql);
        Assert.EndsWith("END $public$", sql);
        Assert.Contains("FROM pg_catalog.pg_namespace WHERE nspname = 'public'", sql);
        Assert.Contains("IF (n.nspowner::regrole IN (pg_catalog.to_regrole('pg_database_owner'), pg_catalog.to_regrole('\"mca-app\"'))) IS NOT TRUE THEN", sql);
        Assert.Contains("ALTER SCHEMA public OWNER TO \"mca-app\";", sql);
        Assert.Contains("a.grantee = 0 AND a.privilege_type = 'CREATE') THEN REVOKE CREATE ON SCHEMA public FROM PUBLIC;", sql);
        Assert.DoesNotContain("server_version", sql);
    }

    [Fact]
    public void Existing_roles_get_their_new_passwords_only_after_every_drop()
    {
        var facts = Facts(appExists: true, auditExists: true, auditOwner: "modularca_audit_owner",
            auditState: AuditState(DatabasePresence.Managed, PostgresUpgradeHarnessTests.AuditBaseline),
            roles: [Role("modularca_app"), Role("modularca_audit"), Role("modularca_audit_owner", canLogin: false)]);
        var plan = PostgresRoleLayout.Plan(facts, Names, new ProvisioningMode(ResetApp: true, WipeAudit: true), AppPassword, AuditPassword).ToList();

        var lastDrop = plan.FindLastIndex(s => s.Sql.StartsWith("DROP DATABASE", StringComparison.Ordinal));
        var firstRotation = plan.FindIndex(s => s.Sql.StartsWith("ALTER ROLE", StringComparison.Ordinal) && s.Sql.Contains("PASSWORD"));
        Assert.True(lastDrop >= 0 && firstRotation > lastDrop, string.Join(Environment.NewLine, plan.Select(s => s.Sql)));
        Assert.Equal(2, plan.Count(s => s.Sql.StartsWith("DROP DATABASE", StringComparison.Ordinal)));
    }

    [Fact]
    public void New_roles_are_created_before_the_drops_and_the_databases_they_own()
    {
        var plan = PostgresRoleLayout.Plan(Facts(appExists: true), Names, Fresh, AppPassword, AuditPassword).ToList();

        var create = plan.FindIndex(s => s.Sql.StartsWith("CREATE ROLE \"modularca_app\"", StringComparison.Ordinal));
        var drop = plan.FindIndex(s => s.Sql.StartsWith("DROP DATABASE", StringComparison.Ordinal));
        var database = plan.FindIndex(s => s.Sql.StartsWith("CREATE DATABASE \"modularca-app\"", StringComparison.Ordinal));
        Assert.True(create >= 0 && create < drop && drop < database);
    }

    [Theory]
    [InlineData(140000)]
    [InlineData(150000)]
    [InlineData(160000)]
    public void A_fresh_install_gets_the_whole_layout(int version)
    {
        var plan = PostgresRoleLayout.Plan(Facts(version), Names, Fresh, AppPassword, AuditPassword);
        var all = plan.Select(s => s.Sql).ToList();

        Assert.Contains($"CREATE ROLE \"modularca_app\" WITH LOGIN PASSWORD '{AppPassword}'", all);
        Assert.Contains($"CREATE ROLE \"modularca_audit\" WITH LOGIN PASSWORD '{AuditPassword}'", all);
        Assert.Contains("CREATE ROLE \"modularca_audit_owner\" WITH NOLOGIN", all);
        Assert.Contains("CREATE DATABASE \"modularca-app\" OWNER \"modularca_app\" ENCODING 'UTF8' TEMPLATE template0", all);
        Assert.Contains("CREATE DATABASE \"modularca-audit\" OWNER \"modularca_audit_owner\" ENCODING 'UTF8' TEMPLATE template0", all);
        Assert.Contains("REVOKE ALL ON DATABASE \"modularca-app\" FROM PUBLIC", all);
        Assert.Contains("REVOKE ALL ON DATABASE \"modularca-audit\" FROM PUBLIC", all);
        Assert.Contains("GRANT CONNECT ON DATABASE \"modularca-audit\" TO \"modularca_audit\"", all);

        var citext = Assert.Single(plan, s => s.Sql.Contains("CREATE EXTENSION IF NOT EXISTS citext"));
        Assert.Equal("modularca-app", citext.Database);
        Assert.StartsWith("SET ROLE \"modularca_app\";", citext.Sql);

        var grants = Assert.Single(plan, s => s.Sql.Contains("GRANT USAGE, CREATE ON SCHEMA public TO \"modularca_audit\""));
        Assert.Equal("modularca-audit", grants.Database);
        Assert.StartsWith("SET ROLE \"modularca_audit_owner\";", grants.Sql);
        Assert.EndsWith("RESET ROLE", grants.Sql);

        var drop = Assert.Single(plan, s => s.Sql.StartsWith("DROP DATABASE", StringComparison.Ordinal));
        Assert.Equal("DROP DATABASE IF EXISTS \"modularca-app\" WITH (FORCE)", drop.Sql);
        Assert.Equal("modularca-app", drop.AssertDatabaseAbsent);

        Assert.DoesNotContain(plan, s => s.Description.Contains(AppPassword) || s.Description.Contains(AuditPassword));
        Assert.DoesNotContain(plan, s => s.Sql.Contains("ON ALL TABLES", StringComparison.Ordinal));
        Assert.DoesNotContain(plan, s => s.Sql.Contains("OWNER TO \"postgres\"", StringComparison.Ordinal));
    }

    [Fact]
    public void Roles_that_exist_have_their_passwords_rotated_and_the_owner_is_not_recreated()
    {
        var plan = PostgresRoleLayout.Plan(
            Facts(roles: [Role("modularca_app"), Role("modularca_audit"), Role("modularca_audit_owner", canLogin: false)]),
            Names, Fresh, AppPassword, AuditPassword);

        Assert.Contains(plan, s => s.Sql == $"ALTER ROLE \"modularca_app\" WITH LOGIN PASSWORD '{AppPassword}'");
        Assert.Contains(plan, s => s.Sql == $"ALTER ROLE \"modularca_audit\" WITH LOGIN PASSWORD '{AuditPassword}'");
        Assert.DoesNotContain(plan, s => s.Sql.StartsWith("CREATE ROLE", StringComparison.Ordinal));
    }

    [Fact]
    public void A_preserved_audit_database_with_history_is_handed_over_by_the_repair_block_with_bound_parameters()
    {
        var facts = Facts(auditExists: true, auditOwner: "postgres",
            auditState: AuditState(DatabasePresence.Managed, PostgresUpgradeHarnessTests.AuditBaseline));

        var plan = PostgresRoleLayout.Plan(facts, Names, Fresh, AppPassword, AuditPassword);

        Assert.Contains(plan, s => s.Sql == "ALTER DATABASE \"modularca-audit\" OWNER TO \"modularca_audit_owner\"");
        Assert.DoesNotContain(plan, s => s.Sql.StartsWith("CREATE DATABASE \"modularca-audit\"", StringComparison.Ordinal));
        Assert.DoesNotContain(plan, s => s.Sql.StartsWith("DROP DATABASE IF EXISTS \"modularca-audit\"", StringComparison.Ordinal));
        var adopt = Assert.Single(plan, s => s.Parameters is not null);
        Assert.Equal("modularca-audit", adopt.Database);
        Assert.Equal("audit", adopt.Parameters!["kind"]);
        Assert.Equal("modularca_audit", adopt.Parameters["target"]);
        Assert.Contains(SchemaOwnership.RepairBlock(), adopt.Sql);
        Assert.Contains("set_config('modularca.target', @target, false)", adopt.Sql);
        Assert.DoesNotContain("modularca_audit'", adopt.Sql);
    }

    [Fact]
    public void A_preserved_empty_audit_database_only_hands_over_its_history_table()
    {
        var facts = Facts(auditExists: true, auditOwner: "postgres", auditState: AuditState(DatabasePresence.Empty));
        var plan = PostgresRoleLayout.Plan(facts, Names, Fresh, AppPassword, AuditPassword);

        Assert.DoesNotContain(plan, s => s.Parameters is not null);
        Assert.Contains(plan, s => s.Sql == "ALTER TABLE IF EXISTS public.\"__EFMigrationsHistory\" OWNER TO \"modularca_audit\"");
    }

    [Fact]
    public void Wiping_the_audit_database_drops_and_recreates_it()
    {
        var facts = Facts(auditExists: true, auditOwner: "modularca_audit", auditState: AuditState(DatabasePresence.Unmanaged));
        var wipe = new ProvisioningMode(ResetApp: true, WipeAudit: true);

        Assert.Empty(PostgresRoleLayout.Refusals(facts, Names, wipe));
        var plan = PostgresRoleLayout.Plan(facts, Names, wipe, AppPassword, AuditPassword);
        var drop = Assert.Single(plan, s => s.Sql == "DROP DATABASE IF EXISTS \"modularca-audit\" WITH (FORCE)");
        Assert.Equal("modularca-audit", drop.AssertDatabaseAbsent);
        Assert.Contains(plan, s => s.Sql.StartsWith("CREATE DATABASE \"modularca-audit\" OWNER \"modularca_audit_owner\"", StringComparison.Ordinal));
    }

    [Fact]
    public void Hyphenated_names_are_quoted_everywhere()
    {
        var names = new PostgresLayoutNames("postgres", "mca-app", "mca-audit", "mca-app-db", "mca-audit-db");
        Assert.Empty(PostgresRoleLayout.ValidateNames(names));

        var plan = PostgresRoleLayout.Plan(Facts(140000), names, Fresh, AppPassword, AuditPassword);

        Assert.Contains(plan, s => s.Sql == "CREATE DATABASE \"mca-app-db\" OWNER \"mca-app\" ENCODING 'UTF8' TEMPLATE template0");
        Assert.Contains(plan, s => s.Sql == "CREATE ROLE \"mca-audit_owner\" WITH NOLOGIN");
        Assert.Contains(plan, s => s.Sql.Contains("ALTER SCHEMA public OWNER TO \"mca-app\""));
        Assert.All(plan.Select(s => s.Sql), sql => Assert.DoesNotMatch(@"(?<![""\w-])mca-app(?![""\w-])", sql));
    }

    [Theory]
    [InlineData("modularca app")]
    [InlineData("modularca\"app")]
    [InlineData("modularca;app")]
    [InlineData("")]
    public void Names_outside_the_safe_alphabet_are_refused(string role)
    {
        Assert.NotEmpty(PostgresRoleLayout.ValidateNames(Names with { AppRole = role }));
    }

    [Fact]
    public void Names_longer_than_63_bytes_are_refused_including_the_derived_owner()
    {
        Assert.Empty(PostgresRoleLayout.ValidateNames(Names with { AppRole = new string('a', 63) }));
        Assert.NotEmpty(PostgresRoleLayout.ValidateNames(Names with { AppRole = new string('a', 64) }));
        Assert.NotEmpty(PostgresRoleLayout.ValidateNames(Names with { AppDatabase = new string('d', 64) }));

        var auditAtLimit = Names with { AuditRole = new string('u', 57) };
        Assert.Equal(63, auditAtLimit.AuditOwnerRole.Length);
        Assert.Empty(PostgresRoleLayout.ValidateNames(auditAtLimit));
        var problems = PostgresRoleLayout.ValidateNames(Names with { AuditRole = new string('u', 58) });
        Assert.Contains(problems, p => p.Contains("audit database owner role") && p.Contains("63 bytes"));
    }

    [Fact]
    public void Colliding_roles_or_databases_are_refused()
    {
        Assert.NotEmpty(PostgresRoleLayout.ValidateNames(Names with { AppRole = "POSTGRES" }));
        Assert.NotEmpty(PostgresRoleLayout.ValidateNames(Names with { AuditRole = "modularca_app" }));
        Assert.NotEmpty(PostgresRoleLayout.ValidateNames(Names with { AppRole = "modularca_audit_owner" }));
        Assert.NotEmpty(PostgresRoleLayout.ValidateNames(Names with { AuditDatabase = "Modularca-App" }));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("mca_aud")]
    public void The_audit_owner_name_matches_the_migration_helpers_default(string? auditRole)
    {
        string[] args =
        [
            "--source-host", "mariadb.internal", "--source-user", "mca_app", "--source-password", "s",
            "--source-app-db", "modularca", "--source-audit-db", "modularca_audit",
            "--source-audit-user", "mca_audit", "--source-audit-password", "a",
            "--target-host", "pg.internal", "--target-admin-user", "postgres", "--target-admin-password", "p",
            .. (auditRole is null ? Array.Empty<string>() : new[] { "--target-audit-role", auditRole }),
        ];
        var options = CommandLine.Parse(args);

        var names = new PostgresLayoutNames(options.TargetAdminUser, options.TargetAppRole, options.TargetAuditRole,
            options.TargetAppDatabase, options.TargetAuditDatabase);

        Assert.Equal(options.TargetAuditOwnerRole, names.AuditOwnerRole);
    }

    [Fact]
    public void A_sqlroot_that_is_not_a_superuser_is_refused_first()
    {
        var reasons = PostgresRoleLayout.Refusals(Facts(superuser: false), Names, Fresh);

        var first = Assert.Single(reasons);
        Assert.Contains("SqlRoot 'postgres' is not a PostgreSQL superuser", first);
        Assert.Contains("CREATEDB and CREATEROLE are not enough", first);
    }

    [Fact]
    public void A_server_older_than_postgresql_14_is_refused()
    {
        Assert.Equal(140000, PostgresRoleLayout.MinimumServerVersionNum);
        Assert.Contains(PostgresRoleLayout.Refusals(Facts(130012), Names, Fresh), r => r.Contains("PostgreSQL 13") && r.Contains("14 or later"));
        Assert.Empty(PostgresRoleLayout.Refusals(Facts(140000), Names, Fresh));
    }

    [Fact]
    public void Runtime_roles_with_admin_attributes_or_membership_of_the_owner_are_refused()
    {
        var reasons = PostgresRoleLayout.Refusals(
            Facts(roles: [Role("modularca_app", createDb: true), Role("modularca_audit", memberOf: ["modularca_audit_owner"])]),
            Names, Fresh);

        Assert.Contains(reasons, r => r.Contains("'modularca_app'") && r.Contains("ALTER ROLE \"modularca_app\" NOSUPERUSER NOCREATEDB"));
        Assert.Contains(reasons, r => r.Contains("REVOKE \"modularca_audit_owner\" FROM \"modularca_audit\";"));
        Assert.Contains(PostgresRoleLayout.Refusals(Facts(roles: [Role("modularca_audit", superuser: true)]), Names, Fresh),
            r => r.Contains("'modularca_audit'"));
    }

    [Fact]
    public void An_audit_owner_role_that_can_log_in_is_refused()
    {
        Assert.Contains(PostgresRoleLayout.Refusals(Facts(roles: [Role("modularca_audit_owner", canLogin: true)]), Names, Fresh),
            r => r.Contains("plain NOLOGIN role"));
    }

    [Fact]
    public void An_existing_application_database_needs_a_reset()
    {
        Assert.Contains(PostgresRoleLayout.Refusals(Facts(appExists: true), Names, new ProvisioningMode(ResetApp: false, WipeAudit: false)),
            r => r.Contains("'modularca-app' exists"));
        Assert.Empty(PostgresRoleLayout.Refusals(Facts(appExists: true), Names, Fresh));
    }

    [Fact]
    public void A_preserved_audit_database_is_refused_when_the_audit_role_owns_it_or_it_is_not_this_products()
    {
        Assert.Contains(PostgresRoleLayout.Refusals(
                Facts(auditExists: true, auditOwner: "modularca_audit", auditState: AuditState(DatabasePresence.Managed, PostgresUpgradeHarnessTests.AuditBaseline)),
                Names, Fresh),
            r => r.Contains("owned by the audit role"));

        Assert.Contains(PostgresRoleLayout.Refusals(
                Facts(auditExists: true, auditOwner: "postgres", auditState: AuditState(DatabasePresence.Unmanaged)), Names, Fresh),
            r => r.Contains("no migration history") && r.Contains("--wipe-audit"));

        Assert.Contains(PostgresRoleLayout.Refusals(
                Facts(auditExists: true, auditOwner: "postgres",
                    auditState: AuditState(DatabasePresence.Managed, PostgresUpgradeHarnessTests.AuditBaseline, "20991231000000_Future")),
                Names, Fresh),
            r => r.Contains("20991231000000_Future"));

        Assert.Empty(PostgresRoleLayout.Refusals(
            Facts(auditExists: true, auditOwner: "postgres", auditState: AuditState(DatabasePresence.Managed, PostgresUpgradeHarnessTests.AuditBaseline)),
            Names, Fresh));
    }

    [Fact]
    public void A_preserved_audit_database_without_the_baseline_or_with_objects_the_takeover_would_not_move_is_refused_before_any_ddl()
    {
        Assert.Equal(PostgresUpgradeHarnessTests.AuditBaseline, PostgresRoleLayout.AuditBaselineMigration);

        var noBaseline = PostgresRoleLayout.Refusals(
            Facts(auditExists: true, auditOwner: "postgres",
                auditState: new SchemaState(["20261001000000_Later"], [PostgresUpgradeHarnessTests.AuditBaseline, "20261001000000_Later"])
                {
                    Presence = DatabasePresence.Managed,
                }),
            Names, Fresh);
        Assert.Contains(noBaseline, r => r.Contains(PostgresUpgradeHarnessTests.AuditBaseline) && r.Contains("--wipe-audit"));

        var stray = Facts(auditExists: true, auditOwner: "postgres",
                auditState: AuditState(DatabasePresence.Managed, PostgresUpgradeHarnessTests.AuditBaseline)) with
        {
            AuditNotAdoptable =
            [
                new NotOwnedObject("\"AuditLogs\"", "r", "legacy_owner", true),
                new NotOwnedObject("audit_prune()", "function", "postgres", true),
            ],
        };
        var reasons = PostgresRoleLayout.Refusals(stray, Names, Fresh);
        var reason = Assert.Single(reasons);
        Assert.Contains("2 object(s)", reason);
        Assert.Contains("\"AuditLogs\" (r, owner legacy_owner)", reason);
        Assert.Contains("audit_prune() (function, owner postgres)", reason);
        Assert.Contains("--wipe-audit", reason);

        Assert.Empty(PostgresRoleLayout.Refusals(stray, Names, new ProvisioningMode(ResetApp: true, WipeAudit: true)));
    }

    [Theory]
    [InlineData("28P01", "rejected the password")]
    [InlineData("28000", "pg_hba.conf")]
    public void A_refused_sqlroot_login_is_a_refusal_with_its_fix(string sqlState, string text)
    {
        var refusal = PostgresRoleLayout.LoginRefusal(sqlState, "postgres");
        Assert.NotNull(refusal);
        Assert.Contains("SqlRoot 'postgres'", refusal);
        Assert.Contains(text, refusal);
        Assert.Null(PostgresRoleLayout.LoginRefusal("42501", "postgres"));
    }

    [Fact]
    public void Generated_passwords_are_long_and_need_no_quoting()
    {
        var password = PostgresRoleLayout.GeneratePassword();
        Assert.True(password.Length >= 43, password);
        Assert.Matches("^[A-Za-z0-9_-]+$", password);
        Assert.NotEqual(password, PostgresRoleLayout.GeneratePassword());
    }
}
