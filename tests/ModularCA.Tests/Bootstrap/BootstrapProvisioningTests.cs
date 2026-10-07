using ModularCA.Bootstrap;
using ModularCA.Database;
using ModularCA.Migrate;
using ModularCA.Shared.Utils;
using Xunit;

namespace ModularCA.Tests.Bootstrap;

/// <summary>
/// The server-free parts of bootstrap provisioning, restore and the migration helper's
/// administrator clean-up. The PostgreSQL behaviour itself belongs to the opt-in harness.
/// </summary>
public class BootstrapProvisioningTests
{
    private static YamlSetupDatabaseLoader.SetupDatabaseConfig Setup(string rootPassword) => new()
    {
        SqlRoot = new() { Host = "127.0.0.1", Port = 1, Username = "postgres", Password = rootPassword, SslMode = "Disable" },
        SqlApp = new() { Database = "modularca-app", Username = "modularca_app@localhost" },
        SqlAudit = new() { Database = "modularca-audit", Username = "modularca_audit" },
    };

    [Fact]
    public void A_sqlroot_without_a_password_is_refused_rather_than_replaced_by_the_app_role()
    {
        var setup = Setup("");
        var ex = Assert.Throws<PostgresLayoutRefusedException>(() => BootstrapDatabaseSetup.AdminConnectionString(setup.SqlRoot));
        Assert.Contains("superuser", ex.Message);
    }

    [Fact]
    public void The_existence_probe_throws_instead_of_reporting_nothing_to_destroy()
    {
        var setup = Setup("secret");
        Assert.ThrowsAny<Exception>(() => BootstrapModularCA.DatabaseExists(setup, setup.SqlRoot));
    }

    [Fact]
    public void Layout_names_drop_the_host_half_of_a_role_name()
    {
        var setup = Setup("secret");
        var names = BootstrapDatabaseSetup.LayoutNames(setup.SqlRoot, setup);
        Assert.Equal("modularca_app", names.AppRole);
        Assert.Equal("modularca_audit_owner", names.AuditOwnerRole);
        Assert.Empty(PostgresRoleLayout.ValidateNames(names));
    }

    [Fact]
    public void Restore_leaves_out_only_the_extension_entries_of_the_table_of_contents()
    {
        const string listing = ";\n; Archive created at 2026-09-27\n;\n"
            + "3; 3079 16385 EXTENSION - citext \r\n"
            + "4297; 0 0 COMMENT - EXTENSION citext \n"
            + "216; 1259 16386 TABLE public Users modularca_app\n"
            + "4100; 0 16386 TABLE DATA public Users modularca_app\n";

        var kept = BackupRestore.WithoutExtensionEntries(listing).ToList();

        Assert.DoesNotContain(kept, l => l.Contains("EXTENSION"));
        Assert.Contains("216; 1259 16386 TABLE public Users modularca_app", kept);
        Assert.Contains("4100; 0 16386 TABLE DATA public Users modularca_app", kept);
        Assert.Contains("; Archive created at 2026-09-27", kept);
    }

    [Fact]
    public void The_migration_helper_takes_back_all_three_roles_from_a_durable_administrator()
    {
        var options = new MigrationOptions
        {
            SourceHost = "h", SourcePort = 3306, SourceUser = "u", SourcePassword = "p",
            SourceAppDatabase = "a", SourceAuditDatabase = "b",
            TargetHost = "127.0.0.1", TargetPort = 5432, TargetAdminUser = "migrator", TargetAdminPassword = "x",
            TargetSslMode = "prefer", TargetAppDatabase = "modularca-app", TargetAuditDatabase = "modularca-audit",
            TargetAppRole = "modularca_app", TargetAuditRole = "modularca_audit", TargetAuditOwnerRole = "modularca_audit_owner",
        };

        Assert.Equal(
            "REVOKE \"modularca_app\", \"modularca_audit\", \"modularca_audit_owner\" FROM \"migrator\"",
            DestinationBuilder.AdministratorMembershipRevokeSql(options));
    }

    [Fact]
    public void A_factory_reset_proves_it_can_drop_the_tables_and_drops_them_before_deleting_any_keystore()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !dir.EnumerateFiles("ModularCA.sln").Any())
            dir = dir.Parent;
        Assert.NotNull(dir);
        var source = File.ReadAllText(Path.Combine(dir!.FullName, "ModularCA.Bootstrap", "BootstrapModularCA.cs"));
        var start = source.IndexOf("public static int FactoryReset(", StringComparison.Ordinal);
        var end = source.IndexOf("public static int Run(", start, StringComparison.Ordinal);
        Assert.True(start > 0 && end > start);
        var reset = source[start..end];

        var probe = reset.IndexOf("SchemaOwnership.ProbeAsync(appConn, DatabaseKind.Application)", StringComparison.Ordinal);
        var drop = reset.IndexOf("DROP TABLE IF EXISTS", StringComparison.Ordinal);
        var commit = reset.IndexOf("tx.Commit()", StringComparison.Ordinal);
        var keystores = reset.IndexOf("DeleteArtifacts(certPath, trustPath)", StringComparison.Ordinal);
        var sshKeyRows = reset.IndexOf("BackupRestore.LegacySshKeyFilesAsync(appConnStr)", StringComparison.Ordinal);
        var sshKeyFiles = reset.IndexOf("DeleteLegacySshKeyFiles(configDir, legacySshKeyFiles)", StringComparison.Ordinal);
        Assert.True(probe > 0 && probe < drop, "The ownership check must come before the drops.");
        Assert.True(drop < commit && commit < keystores, "The drops must be committed before the keystores are deleted.");
        Assert.True(probe < sshKeyRows && sshKeyRows < drop, "Where SSH CA key files lie is read from the rows before the tables are dropped.");
        Assert.True(keystores < sshKeyFiles, "The SSH CA key files go after the keystores.");
        Assert.Contains("SchemaOwnership.RepairCommand(DatabaseKind.Application", reset[probe..drop]);
        Assert.Equal(1, reset.Split("DeleteArtifacts(").Length - 1);
        // The reset once deleted keystores/ssh-ca-*, a pattern that matched neither the SSH
        // keystore nor any key file. The SSH keystore now goes with the other two.
        Assert.DoesNotContain("\"ssh-ca-*\"", source);
        var deleteArtifacts = source[source.IndexOf("public static void DeleteArtifacts(", StringComparison.Ordinal)..];
        Assert.Contains("KeyRef.SshKeystore", deleteArtifacts[..deleteArtifacts.IndexOf("internal static void DeleteLegacySshKeyFiles(", StringComparison.Ordinal)]);
    }

    /// <summary>
    /// What a reset, and a bootstrap over an older install, delete of the keystores: all three
    /// files. An SSH keystore left behind would have no <c>Keystores</c> row in the new database,
    /// and the signer does not unlock with one in that state.
    /// </summary>
    [Fact]
    public void Deleting_the_keystores_deletes_the_ssh_keystore_with_the_other_two()
    {
        var keystores = Path.Combine(Path.GetTempPath(), $"mca-reset-keystores-{Guid.NewGuid():N}");
        Directory.CreateDirectory(keystores);
        try
        {
            string[] deleted = ["ca-certs.keystore", "ca-trust.keystore", "ssh-ca.keystore", "ssh-ca.keystore.creating"];
            foreach (var name in deleted.Append("unrelated.txt"))
                File.WriteAllText(Path.Combine(keystores, name), "x");

            BootstrapModularCA.DeleteArtifacts(Path.Combine(keystores, "ca-certs.keystore"), Path.Combine(keystores, "ca-trust.keystore"));

            Assert.Equal(new[] { "unrelated.txt" }, Directory.GetFiles(keystores).Select(Path.GetFileName));

            // With nothing there it has nothing to do, and says so without failing.
            BootstrapModularCA.DeleteArtifacts(Path.Combine(keystores, "ca-certs.keystore"), Path.Combine(keystores, "ca-trust.keystore"));
        }
        finally
        {
            Directory.Delete(keystores, true);
        }
    }

    /// <summary>
    /// A reset removes the SSH CA key files it would otherwise leave on the host in plaintext:
    /// the default key directory whole, and the key files a row named elsewhere, each with its
    /// .pub. A row cannot point the reset at a file that is not a key file.
    /// </summary>
    [Fact]
    public void A_factory_reset_removes_the_plaintext_ssh_ca_key_files_and_nothing_else()
    {
        var app = Path.Combine(Path.GetTempPath(), $"mca-reset-ssh-{Guid.NewGuid():N}");
        var config = Path.Combine(app, "config");
        try
        {
            const string key = "-----BEGIN OPENSSH PRIVATE KEY-----\nnot-a-real-key\n-----END OPENSSH PRIVATE KEY-----\n";
            Directory.CreateDirectory(Path.Combine(config, "ssh-ca-keys"));
            Directory.CreateDirectory(Path.Combine(config, "custom"));
            Directory.CreateDirectory(Path.Combine(config, "shared"));
            File.WriteAllText(Path.Combine(config, "ssh-ca-keys", "a"), key);
            File.WriteAllText(Path.Combine(config, "ssh-ca-keys", "a.pub"), "ssh-ed25519 AAAA a");
            File.WriteAllText(Path.Combine(config, "custom", "b"), key);
            File.WriteAllText(Path.Combine(config, "custom", "b.pub"), "ssh-ed25519 AAAA b");
            File.WriteAllText(Path.Combine(config, "shared", "c"), key);
            File.WriteAllText(Path.Combine(config, "shared", "kept.txt"), "kept");
            File.WriteAllText(Path.Combine(config, "config.yaml"), "JWT: {}\n");

            BootstrapModularCA.DeleteLegacySshKeyFiles(config,
                [Path.Combine(config, "custom", "b"), "config/shared/c", "config/config.yaml", "config/gone", ""]);

            Assert.False(Directory.Exists(Path.Combine(config, "ssh-ca-keys")));
            Assert.False(Directory.Exists(Path.Combine(config, "custom")), "A key directory left empty is removed.");
            Assert.False(File.Exists(Path.Combine(config, "shared", "c")));
            Assert.Equal("kept", File.ReadAllText(Path.Combine(config, "shared", "kept.txt")));
            Assert.Equal("JWT: {}\n", File.ReadAllText(Path.Combine(config, "config.yaml")));
        }
        finally
        {
            Directory.Delete(app, true);
        }
    }

    [Theory]
    [InlineData("ModularCA.Bootstrap/BootstrapModularCA.cs", "ConfirmDestruction(certPath")]
    [InlineData("ModularCA.Bootstrap/BootstrapService.cs", "var setupDbConfig = new")]
    public void The_keystores_are_deleted_only_after_provisioning_succeeded(string file, string decided)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !dir.EnumerateFiles("ModularCA.sln").Any())
            dir = dir.Parent;
        Assert.NotNull(dir);
        var source = File.ReadAllText(Path.Combine(dir!.FullName, file.Replace('/', Path.DirectorySeparatorChar)));

        var provision = source.IndexOf("BootstrapDatabaseSetup.ProvisionAsync(", StringComparison.Ordinal);
        Assert.True(provision > 0, $"{file} no longer provisions through BootstrapDatabaseSetup.ProvisionAsync.");
        var start = source.LastIndexOf(decided, provision, StringComparison.Ordinal);
        Assert.True(start >= 0, $"{file}: '{decided}' no longer precedes provisioning.");
        Assert.DoesNotContain("DeleteArtifacts(", source[start..provision]);
        var delete = source.IndexOf("DeleteArtifacts(certPath, trustPath)", provision, StringComparison.Ordinal);
        Assert.True(delete > provision, $"{file} does not delete the keystores after provisioning.");
    }

    [Fact]
    public void Bootstrap_and_the_migration_helper_share_the_audit_grants()
    {
        var names = new PostgresLayoutNames("postgres", "modularca_app", "modularca_audit", "modularca-app", "modularca-audit");
        var grants = PostgresRoleLayout.AuditSchemaGrantSql(names);

        Assert.Contains("REVOKE CREATE ON SCHEMA public FROM PUBLIC", grants);
        Assert.Contains("GRANT USAGE, CREATE ON SCHEMA public TO \"modularca_audit\"", grants);
        Assert.DoesNotContain(grants, g => g.Contains("ON ALL TABLES"));
    }
}
