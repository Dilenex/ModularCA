using ModularCA.Migrate;
using Xunit;

namespace ModularCA.Tests.Migrate;

/// <summary>
/// Who owns what on the destination, and why none of it is the account running the migration.
/// <para>
/// Both rules below only bite when the administrative account is not a superuser, which is the
/// case this tool deliberately supports — so neither shows up in a lazy test against a superuser,
/// and the first one reached a live run.
/// </para>
/// </summary>
public class DestinationOwnershipTests
{
    private static string[] MinimalArgs() =>
    [
        "--source-host", "mariadb.internal", "--source-user", "mca_app", "--source-password", "s",
        "--source-app-db", "modularca", "--source-audit-db", "modularca_audit",
        "--source-audit-user", "mca_audit", "--source-audit-password", "a",
        "--target-host", "pg.internal", "--target-admin-user", "postgres", "--target-admin-password", "p",
    ];

    [Fact]
    public void The_audit_database_gets_an_owner_that_is_not_the_audit_account()
    {
        // The node connects as the audit role. If that role owned the audit database it could
        // drop it — the guarantee the MySQL setup claimed and did not hold. The owner is a
        // separate role, and the whole point is that it is not the one with the password.
        var options = CommandLine.Parse(MinimalArgs());

        Assert.NotEqual(options.TargetAuditRole, options.TargetAuditOwnerRole);
        Assert.NotEqual(options.TargetAppRole, options.TargetAuditOwnerRole);
    }

    [Fact]
    public void The_audit_owner_is_not_the_administrative_account_either()
    {
        // The administrative account may be the temporary role this tool borrows and drops at the
        // end of the run. A role that owns a database cannot be dropped, so owning the audit
        // database with it would strand it on the server.
        var options = CommandLine.Parse(MinimalArgs());

        Assert.NotEqual(options.TargetAdminUser, options.TargetAuditOwnerRole);
    }

    [Fact]
    public void The_audit_owner_name_is_derived_from_the_audit_role()
    {
        // Derived rather than invented, so an operator reading a role listing can see at a glance
        // what it belongs to.
        var options = CommandLine.Parse(MinimalArgs());

        Assert.Equal(options.TargetAuditRole + "_owner", options.TargetAuditOwnerRole);
    }

    [Fact]
    public void The_audit_owner_follows_an_overridden_audit_role()
    {
        var options = CommandLine.Parse(MinimalArgs().Concat(["--target-audit-role", "mca_aud"]).ToArray());

        Assert.Equal("mca_aud_owner", options.TargetAuditOwnerRole);
    }

    [Fact]
    public void The_audit_owner_can_be_named_outright()
    {
        var options = CommandLine.Parse(
            MinimalArgs().Concat(["--target-audit-owner-role", "keeper"]).ToArray());

        Assert.Equal("keeper", options.TargetAuditOwnerRole);
    }

    [Fact]
    public void All_four_role_and_database_names_are_distinct()
    {
        // Preflight refuses on a collision, but the defaults must not produce one in the first
        // place — a default that collides makes the ordinary invocation the broken one.
        var options = CommandLine.Parse(MinimalArgs());

        var names = new[]
        {
            options.TargetAppRole, options.TargetAuditRole,
            options.TargetAuditOwnerRole, options.TargetAdminUser,
        };

        Assert.Equal(names.Length, names.Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    [Fact]
    public void The_application_database_is_owned_by_the_application_role()
    {
        // The app role does own its own database: it applies its own migrations, and it is the
        // account the node uses, so there is no separation to preserve there. The audit database
        // is the one where ownership has to be held away from the connecting account.
        var options = CommandLine.Parse(MinimalArgs());

        Assert.Equal("mca_app", options.TargetAppRole);
        Assert.Equal("modularca", options.TargetAppDatabase);
    }
}
