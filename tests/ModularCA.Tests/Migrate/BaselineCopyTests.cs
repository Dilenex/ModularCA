using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Migrate;
using Xunit;

namespace ModularCA.Tests.Migrate;

/// <summary>
/// The copy writes into the frozen baselines, the 0.3.0 schema, never into the current model: the
/// later migrations then fold and rename the copied rows as they would on an upgrade. Copying into
/// the current model by its names would leave behind every column a later migration renames.
/// </summary>
public class BaselineCopyTests
{
    [Fact]
    public void The_baselines_are_each_contexts_first_migration()
    {
        using var app = new ModularCADbContext(new DbContextOptionsBuilder<ModularCADbContext>().UseNpgsql("Host=model-only").Options);
        using var audit = new AuditDbContext(new DbContextOptionsBuilder<AuditDbContext>().UseNpgsql("Host=model-only").Options);
        Assert.Equal(PostgresRoleLayout.AppBaselineMigration, app.Database.GetMigrations().First());
        Assert.Equal(PostgresRoleLayout.AuditBaselineMigration, audit.Database.GetMigrations().First());
        Assert.True(app.Database.GetMigrations().Count() > 1);
    }

    [Fact]
    public void The_application_copy_targets_the_baseline_names()
    {
        var copy = ModelIntrospection.AppCopyTables().ToDictionary(t => t.Name, t => t.Columns.Select(c => c.Name).ToHashSet());

        Assert.Contains("TenantHostnames", copy.Keys);
        Assert.Contains("IsSystemTenant", copy["Tenants"]);
        Assert.Contains("MaxUsers", copy["Tenants"]);
        foreach (var table in new[] { "CaGroups", "CertProfiles", "CertificateAuthorities", "EnrollmentTokens", "KerberosRealms",
                     "KeyCeremonies", "RoleAssignments", "Roles", "UserCapabilityGrants" })
            Assert.Contains("TenantId", copy[table]);
        Assert.Contains("ServiceScopeTenantId", copy["Users"]);
        Assert.Contains("TenantId", ModelIntrospection.AuditCopyTables().Single(t => t.Name == "AuditLogs").Columns.Select(c => c.Name));
    }

    [Fact]
    public void The_copy_is_not_the_current_model()
    {
        var current = ModelIntrospection.Tables(ModelIntrospection.DestinationModel()).Select(t => t.Name).ToHashSet();
        Assert.DoesNotContain("TenantHostnames", current);
        Assert.Contains("TenantHostnames", ModelIntrospection.AppCopyTables().Select(t => t.Name));
    }

    /// <summary>
    /// The whole copy plan, every table, column, provider type and nullability, pinned by digest.
    /// The baseline migrations are frozen, so nothing may change it: a change here means the copy
    /// stopped reading the baseline.
    /// </summary>
    [Fact]
    public void The_copy_plan_is_frozen()
    {
        Assert.Equal(AppPlanDigest, Digest(ModelIntrospection.AppCopyTables()));
        Assert.Equal(AuditPlanDigest, Digest(ModelIntrospection.AuditCopyTables()));
    }

    /// <summary>
    /// The audit chain is verified at the baseline stage, before the later audit migrations add
    /// their columns, through <see cref="BaselineAuditDbContext"/>: it must map exactly the
    /// baseline's tables and columns, or its first query names a column that is not there yet.
    /// </summary>
    [Fact]
    public void The_baseline_stage_audit_context_maps_exactly_the_audit_baseline()
    {
        using var db = new BaselineAuditDbContext(new DbContextOptionsBuilder<AuditDbContext>().UseNpgsql("Host=model-only").Options);
        var model = Microsoft.EntityFrameworkCore.Infrastructure.AccessorExtensions.GetService<Microsoft.EntityFrameworkCore.Metadata.IDesignTimeModel>(db).Model;

        Assert.Equal(Digest(ModelIntrospection.AuditCopyTables()), Digest(ModelIntrospection.Tables(model)));
        Assert.NotEqual(Digest(ModelIntrospection.AuditCopyTables()), Digest(ModelIntrospection.Tables(ModelIntrospection.AuditModel())));
    }

    [Fact]
    public void The_case_sweep_reads_the_baseline_keys()
    {
        var checks = ModelIntrospection.UniquenessChecks(ModelIntrospection.BaselineModel()).ToList();
        Assert.Contains(checks, c => c.Table == "Tenants" && c.FoldsCase.Contains("Slug"));
        Assert.Contains(checks, c => c.Table == "TenantHostnames" && c.FoldsCase.Contains("Hostname"));
        Assert.Contains(checks, c => c.Table == "Users" && c.Columns.SequenceEqual(["Username"]));
    }

    private const string AppPlanDigest = "a42087bc56f9ae6011963febbb283aea0a0db969646ae744a72cd644b1427498";
    private const string AuditPlanDigest = "e2e6a9d617e2a524ec1899515c84593c9ea2043c72a20fa3111a83c477d1d794";

    private static string Digest(IReadOnlyList<ModelIntrospection.TableInfo> tables) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\n", tables.Select(t =>
            $"{t.Name}:{string.Join(",", t.Columns.Select(c => $"{c.Name}/{c.ClrType.Name}/{(c.IsNullable ? "null" : "notnull")}"))}")))));
}
