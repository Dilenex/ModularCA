using ModularCA.Migrate;
using Xunit;

namespace ModularCA.Tests.Migrate;

/// <summary>
/// What the helper works out for itself.
/// <para>
/// The first version of this tool needed twelve options and a hand-created PostgreSQL role, which
/// is a set of instructions with a binary attached rather than a migration command. Every value
/// describing the database being migrated from already exists in the deployment's own db.yaml, and
/// retyping them into a one-way copy is an invitation to make a typo. These tests pin the
/// defaulting, because a wrong default here is worse than a missing option: it would run against
/// something the operator did not name.
/// </para>
/// </summary>
public class MigrationDefaultsTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "mca-migrate-" + Guid.NewGuid().ToString("N"));

    private string WriteConfig(string yaml)
    {
        Directory.CreateDirectory(_directory);
        var path = Path.Combine(_directory, "db.yaml");
        File.WriteAllText(path, yaml);
        return path;
    }

    private const string Typical = """
        App:
          Host: db.internal
          Port: 3307
          Database: modularca
          Username: mca_app
          Password: app-secret
        Audit:
          Host: db.internal
          Port: 3307
          Database: modularca_audit
          Username: mca_audit
          Password: audit-secret
        """;

    /// <summary>Removes the temporary configuration directory.</summary>
    public void Dispose()
    {
        if (Directory.Exists(_directory))
            Directory.Delete(_directory, recursive: true);
        GC.SuppressFinalize(this);
    }

    [Fact]
    public void The_whole_source_side_comes_from_the_deployments_own_config()
    {
        var options = CommandLine.Parse(["--config", WriteConfig(Typical)]);

        Assert.Equal("db.internal", options.SourceHost);
        Assert.Equal(3307, options.SourcePort);
        Assert.Equal("modularca", options.SourceAppDatabase);
        Assert.Equal("mca_app", options.SourceUser);
        Assert.Equal("app-secret", options.SourcePassword);
        Assert.Equal("modularca_audit", options.SourceAuditDatabase);
    }

    [Fact]
    public void The_separate_audit_account_is_carried_across()
    {
        // A deployment keeps these apart on purpose — it is what stops the node's own credentials
        // rewriting its audit — so collapsing them would mean asking for a MariaDB administrator
        // just to run a migration.
        var options = CommandLine.Parse(["--config", WriteConfig(Typical)]);

        Assert.Equal("mca_audit", options.SourceAuditUser);
        Assert.Equal("audit-secret", options.SourceAuditPassword);
        Assert.NotEqual(options.SourceUser, options.SourceAuditUser);
    }

    [Fact]
    public void The_destination_defaults_to_the_same_names_on_the_same_host()
    {
        // A PostgreSQL server has no database called modularca yet, so reusing the names the
        // operator already knows costs nothing and leaves their mental model intact.
        var options = CommandLine.Parse(["--config", WriteConfig(Typical)]);

        Assert.Equal("127.0.0.1", options.TargetHost);
        Assert.Equal(5432, options.TargetPort);
        Assert.Equal("modularca", options.TargetAppDatabase);
        Assert.Equal("modularca_audit", options.TargetAuditDatabase);
        Assert.Equal("mca_app", options.TargetAppRole);
        Assert.Equal("mca_audit", options.TargetAuditRole);
    }

    [Fact]
    public void An_explicit_option_beats_the_config()
    {
        var options = CommandLine.Parse([
            "--config", WriteConfig(Typical),
            "--source-host", "elsewhere.internal",
            "--target-app-db", "modularca_new",
        ]);

        Assert.Equal("elsewhere.internal", options.SourceHost);
        Assert.Equal("modularca_new", options.TargetAppDatabase);
        Assert.Equal("modularca_audit", options.TargetAuditDatabase);   // still defaulted
    }

    [Fact]
    public void The_config_that_was_used_is_recorded_so_the_run_can_say_so()
    {
        var path = WriteConfig(Typical);

        Assert.Equal(path, CommandLine.Parse(["--config", path]).ConfigPath);
    }

    [Fact]
    public void A_config_path_that_does_not_exist_is_refused_rather_than_ignored()
    {
        // Falling back to a search would be the dangerous behaviour: the operator named a file,
        // and silently migrating whatever else was found is not what they asked for.
        var ex = Assert.Throws<ArgumentException>(
            () => CommandLine.Parse(["--config", Path.Combine(_directory, "absent.yaml")]));

        Assert.Contains("absent.yaml", ex.Message);
    }

    [Fact]
    public void Without_a_config_the_missing_option_says_why_it_is_missing()
    {
        // The unhelpful version of this message names the option. The helpful one explains that
        // it would normally have been read from a file that was not found, and how to point at it.
        var ex = Assert.Throws<ArgumentException>(() => CommandLine.Parse(["--source-host", "db"]));

        Assert.Contains("db.yaml", ex.Message);
        Assert.Contains("--config", ex.Message);
    }

    [Fact]
    public void A_mariadb_port_is_assumed_when_the_config_still_carries_the_postgres_default()
    {
        // db.yaml defaults Port to 5432 because 0.3.1 wrote that class. A 0.3.0 deployment being
        // migrated is on MariaDB, so a value that is merely the unset default must not be taken
        // as a real source port.
        var path = WriteConfig("""
            App:
              Database: modularca
              Username: mca_app
              Password: app-secret
            Audit:
              Database: modularca_audit
              Username: mca_audit
              Password: audit-secret
            """);

        Assert.Equal(3306, CommandLine.Parse(["--config", path]).SourcePort);
    }

    [Fact]
    public void No_administrative_account_is_required_up_front()
    {
        // It is filled in later, by borrowing a temporary role through the local socket on a host
        // that allows it. Requiring it here is what forced the operator to create one by hand.
        var options = CommandLine.Parse(["--config", WriteConfig(Typical)]);

        Assert.Equal("", options.TargetAdminUser);
        Assert.Equal("", options.TargetAdminPassword);
    }

    [Fact]
    public void The_manual_fallback_is_a_single_statement_naming_what_preflight_requires()
    {
        // Printed whenever the automatic path is unavailable. It must grant exactly what the
        // preflight checks for and no more — a superuser here would quietly undo the reason the
        // copier drops and re-adds foreign keys instead of suppressing them.
        var instructions = LocalPostgresAccess.ManualInstructions();

        Assert.Contains("CREATEDB", instructions);
        Assert.Contains("CREATEROLE", instructions);
        Assert.DoesNotContain("SUPERUSER", instructions);
    }
}
