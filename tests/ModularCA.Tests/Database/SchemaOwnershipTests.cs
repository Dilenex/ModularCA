using ModularCA.Database;
using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// What <see cref="SchemaOwnership"/> tells an operator when the ownership rule does not hold,
/// and the repair script it points at: that the embedded copy is the file the packages ship, and
/// that the script carries every guard.
/// </summary>
public class SchemaOwnershipTests
{
    private static OwnershipReport Report(
        DatabaseKind kind = DatabaseKind.Application,
        int notOwned = 0,
        bool usable = true,
        bool canCreateTables = true,
        bool canCreateSchema = false,
        bool canBecomeDbOwner = false,
        bool adminAttributes = false,
        IReadOnlyList<RoleMembership>? otherMembers = null,
        string role = "modularca_app",
        string database = "modularca-app",
        string owner = "modularca_app") =>
        new(kind, role, database, owner, 160004,
            Enumerable.Range(1, notOwned).Select(i => new NotOwnedObject($"\"Table{i:00}\"", "r", "postgres", usable)).ToList(),
            canCreateTables, canCreateSchema, canBecomeDbOwner, adminAttributes, otherMembers ?? []);

    [Fact]
    public void Soundness_needs_every_object_owned_and_the_right_to_create_tables()
    {
        Assert.True(Report().IsSound);
        Assert.False(Report(notOwned: 1).IsSound);
        Assert.False(Report(canCreateTables: false).IsSound);
        Assert.False(Report(notOwned: 1).Unusable);
        Assert.True(Report(notOwned: 1, usable: false).Unusable);
    }

    [Fact]
    public void The_refusal_names_the_database_the_role_the_objects_the_pending_migrations_and_the_repair()
    {
        var report = Report(notOwned: 12, usable: false);

        var message = SchemaOwnership.RefusalMessage(report, ["20261001000000_Fold", "20261002000000_Index"], port: 5433);

        Assert.Contains("application database 'modularca-app'", message);
        Assert.Contains("12 object(s)", message);
        Assert.Contains("'modularca_app'", message);
        Assert.Contains("\"Table01\" (owner postgres)", message);
        Assert.Contains("\"Table10\" (owner postgres)", message);
        Assert.DoesNotContain("\"Table11\"", message);
        Assert.Contains("and 2 more", message);
        Assert.Contains("cannot even read 12", message);
        Assert.Contains("20261001000000_Fold, 20261002000000_Index", message);
        Assert.Contains("Nothing was applied to either database.", message);
        Assert.Contains(SchemaOwnership.RepairCommand(DatabaseKind.Application, "modularca-app", "modularca_app", 5433), message);
        Assert.Contains("every ModularCA unit stopped", message);
    }

    [Fact]
    public void The_repair_command_runs_the_root_owned_script_with_kind_and_target()
    {
        var command = SchemaOwnership.RepairCommand(DatabaseKind.Audit, "modularca-audit", "modularca_audit", 5433);

        Assert.Contains("-v kind=audit", command);
        Assert.Contains("modularca_audit", command);
        Assert.Contains(" -p 5433", command);
        Assert.Contains(SchemaOwnership.RepairScriptPath(), command);
        Assert.DoesNotContain(" -p ", SchemaOwnership.RepairCommand(DatabaseKind.Application, "a", "b", 5432));
        if (OperatingSystem.IsWindows())
        {
            Assert.Equal(Path.Combine(AppContext.BaseDirectory, "sql", "adopt-ownership.sql"), SchemaOwnership.RepairScriptPath());
        }
        else
        {
            Assert.Equal("sudo -u postgres psql -X -p 5433 -d 'modularca-audit' -v kind=audit -v target='modularca_audit' "
                + "-f /usr/share/modularca/sql/adopt-ownership.sql", command);
        }
    }

    [Fact]
    public void The_linux_path_is_where_the_package_installs_the_script()
    {
        Assert.Equal("/usr/share/modularca/sql/adopt-ownership.sql", SchemaOwnership.LinuxRepairScriptPath);
        var nfpm = File.ReadAllText(Path.Combine(RepoRoot(), "packaging", "nfpm.yaml"));
        Assert.Contains("dst: " + SchemaOwnership.LinuxRepairScriptPath, nfpm);
    }

    [Fact]
    public void A_role_that_cannot_create_tables_is_told_the_grant()
    {
        var message = SchemaOwnership.RefusalMessage(Report(canCreateTables: false), null);
        Assert.Contains("GRANT USAGE, CREATE ON SCHEMA public TO \"modularca_app\";", message);
        Assert.Contains("Nothing was applied to either database.", message);
        Assert.DoesNotContain("adopt-ownership.sql", message);
    }

    [Fact]
    public void Drift_while_nothing_is_pending_is_a_warning_that_names_the_next_release()
    {
        var warning = SchemaOwnership.DriftWarning(Report(DatabaseKind.Audit, notOwned: 4, role: "modularca_audit", database: "modularca-audit", owner: "modularca_audit_owner"));
        Assert.Contains("audit database 'modularca-audit'", warning);
        Assert.Contains("4 object(s)", warning);
        Assert.Contains("next release that carries a migration will refuse to start", warning);
        Assert.Contains("-v kind=audit", warning);
    }

    [Fact]
    public void An_audit_role_that_could_drop_its_database_is_warned_with_the_fix()
    {
        var owns = SchemaOwnership.Warnings(Report(DatabaseKind.Audit, canBecomeDbOwner: true,
            role: "modularca_audit", database: "modularca-audit", owner: "modularca_audit"));
        Assert.Contains(owns, w => w.Contains("ALTER DATABASE \"modularca-audit\" OWNER TO \"modularca_audit_owner\";"));

        var member = SchemaOwnership.Warnings(Report(DatabaseKind.Audit, canBecomeDbOwner: true,
            role: "modularca_audit", database: "modularca-audit", owner: "modularca_audit_owner"));
        Assert.Contains(member, w => w.Contains("REVOKE \"modularca_audit_owner\" FROM \"modularca_audit\";"));
    }

    [Fact]
    public void Other_members_of_the_audit_database_owner_and_the_audit_role_are_each_given_the_exact_revoke()
    {
        var warnings = SchemaOwnership.Warnings(Report(DatabaseKind.Audit,
            otherMembers:
            [
                new("migrator", "modularca_audit_owner"), new("modularca_audit", "modularca_audit_owner"),
                new("ops-admin", "modularca_audit_owner"), new("mcamigrate", "modularca_audit"),
            ],
            role: "modularca_audit", database: "modularca-audit", owner: "modularca_audit_owner"));

        Assert.Contains(warnings, w => w.Contains("REVOKE \"modularca_audit_owner\" FROM \"migrator\";") && w.Contains("could drop it"));
        Assert.Contains(warnings, w => w.Contains("REVOKE \"modularca_audit_owner\" FROM \"ops-admin\";"));
        Assert.Contains(warnings, w => w.Contains("REVOKE \"modularca_audit\" FROM \"mcamigrate\";")
            && w.Contains("DROP ROLE \"mcamigrate\";") && w.Contains("ALTER ROLE \"mcamigrate\" NOLOGIN;"));
        Assert.DoesNotContain(warnings, w => w.Contains("FROM \"modularca_audit\";"));
    }

    [Fact]
    public void A_leftover_member_of_the_app_role_is_warned_with_the_exact_revoke()
    {
        var warnings = SchemaOwnership.Warnings(Report(otherMembers: [new("mcamigrate", "modularca_app")]));

        var warning = Assert.Single(warnings);
        Assert.Contains("REVOKE \"modularca_app\" FROM \"mcamigrate\";", warning);
        Assert.Contains("runtime role of the application database", warning);
        Assert.Contains("ALTER ROLE \"mcamigrate\" NOLOGIN;", warning);
    }

    [Fact]
    public void Schema_creation_and_admin_attributes_are_warned_and_the_application_database_only_for_attributes()
    {
        var audit = SchemaOwnership.Warnings(Report(DatabaseKind.Audit, canCreateSchema: true, adminAttributes: true,
            role: "modularca_audit", database: "modularca-audit", owner: "modularca_audit_owner"));
        Assert.Contains(audit, w => w.Contains("REVOKE CREATE ON DATABASE \"modularca-audit\" FROM \"modularca_audit\", PUBLIC;"));
        Assert.Contains(audit, w => w.Contains("NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"));

        var app = SchemaOwnership.Warnings(Report(canCreateSchema: true, canBecomeDbOwner: true));
        Assert.Empty(app);
    }

    [Fact]
    public void The_embedded_script_is_the_shipped_file_byte_for_byte()
    {
        using var stream = typeof(SchemaOwnership).Assembly.GetManifestResourceStream(SchemaOwnership.RepairScriptResource);
        Assert.NotNull(stream);
        using var copy = new MemoryStream();
        stream!.CopyTo(copy);

        var shipped = File.ReadAllBytes(Path.Combine(RepoRoot(), "ModularCA.Database", "Sql", "adopt-ownership.sql"));

        Assert.Equal(shipped, copy.ToArray());
        Assert.DoesNotContain((byte)'\r', shipped);
    }

    [Fact]
    public void The_script_carries_every_guard()
    {
        var script = SchemaOwnership.ReadRepairScript();

        Assert.Contains(@"\set ON_ERROR_STOP on", script);
        Assert.Contains("SET lock_timeout = '10s';", script);
        Assert.Contains("SET modularca.kind = :'kind';", script);
        Assert.Contains("SET modularca.target = :'target';", script);
        Assert.Contains("BEGIN;", script);
        Assert.Contains("COMMIT;", script);

        Assert.Contains("IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN RAISE EXCEPTION 'run as a PostgreSQL superuser'", script);
        Assert.Contains($"'{PostgresUpgradeHarnessTests.AppBaseline}'", script);
        Assert.Contains($"'{PostgresUpgradeHarnessTests.AuditBaseline}'", script);
        Assert.Contains("EXECUTE 'SELECT EXISTS (SELECT 1 FROM public.\"__EFMigrationsHistory\" WHERE \"MigrationId\" = $1)' INTO ok USING base;", script);
        Assert.Contains("IF k = 'app' AND dbo <> t.oid THEN RAISE EXCEPTION", script);
        Assert.Contains("IF k = 'audit' AND pg_has_role(t.oid, dbo, 'MEMBER') THEN RAISE EXCEPTION", script);
        Assert.Contains("a.privilege_type = 'CONNECT'", script);
        Assert.Contains("NOT t.rolcanlogin OR t.rolsuper OR t.rolcreatedb OR t.rolcreaterole OR t.rolreplication OR t.rolbypassrls", script);
        Assert.Contains("d.deptype = 'e' OR (c.relkind = 'S' AND d.deptype IN ('a','i'))", script);
        Assert.Contains("(w.rolsuper OR w.rolcreatedb OR w.rolcreaterole OR w.oid = dbo)", script);
        Assert.Contains("format('ALTER %s %s OWNER TO %I'", script);

        Assert.DoesNotContain("REASSIGN OWNED", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(":kind", script.Replace(":'kind'", ""));
        Assert.DoesNotContain(":target", script.Replace(":'target'", ""));
    }

    [Fact]
    public void The_repair_block_is_the_do_block_alone()
    {
        var block = SchemaOwnership.RepairBlock();

        Assert.StartsWith("DO $adopt$", block);
        Assert.EndsWith("END $adopt$;", block);
        Assert.DoesNotContain(@"\set", block);
        Assert.DoesNotContain(":'", block);
        Assert.Contains("current_setting('modularca.kind')", block);
        Assert.Contains("current_setting('modularca.target')", block);
    }

    [Theory]
    [InlineData(DatabaseKind.Application, "app")]
    [InlineData(DatabaseKind.Audit, "audit")]
    public void The_script_kind_matches_the_database(DatabaseKind kind, string expected)
    {
        Assert.Equal(expected, SchemaOwnership.ScriptKind(kind));
    }

    /// <summary>The directory holding ModularCA.sln.</summary>
    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !dir.EnumerateFiles("*.sln").Any())
            dir = dir.Parent;
        Assert.NotNull(dir);
        return dir!.FullName;
    }
}
