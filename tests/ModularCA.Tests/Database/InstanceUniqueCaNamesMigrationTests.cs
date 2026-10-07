using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Migrations.Operations;
using ModularCA.Database;
using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// The shape of the 0.4.0 S4 migration, checked without a database: five preconditions first
/// (exact label, label up to case, name, over all rows, deleted included; then enabled protocol
/// configurations and templates whose signing profile issues from another CA), then the raw unique index on
/// lower(Label), the new plain unique indexes
/// before the old ones go, the quota columns dropped last, no suppressed transaction, and no way
/// back. The PostgreSQL harness runs it for real.
/// </summary>
public class InstanceUniqueCaNamesMigrationTests
{
    private static Migration Migration()
    {
        using var db = new ModularCADbContextFactory().CreateDbContext([]);
        var assembly = db.GetService<IMigrationsAssembly>();
        var (_, type) = assembly.Migrations.Single(m => m.Key.EndsWith("_InstanceUniqueCaNames", StringComparison.Ordinal));
        return assembly.CreateMigration(type, db.Database.ProviderName!);
    }

    [Fact]
    public void Five_preconditions_come_first()
    {
        var ops = Migration().UpOperations.ToList();
        var checks = ops.Take(3).Cast<SqlOperation>().Select(s => s.Sql).ToList();
        Assert.All(checks, sql => Assert.StartsWith("DO $$ BEGIN IF (EXISTS (SELECT ca.\"", sql.Replace("SELECT lower(", "SELECT ca.\"")));
        Assert.Contains("GROUP BY ca.\"Label\"", checks[0]);
        Assert.Contains("GROUP BY lower(ca.\"Label\")", checks[1]);
        Assert.Contains("GROUP BY ca.\"Name\"", checks[2]);
        Assert.All(checks, sql => Assert.DoesNotContain("IsDeleted\" = false", sql));
        Assert.All(checks, sql => Assert.Contains("', deleted'", sql));
        Assert.All(checks, sql => Assert.Contains("coalesce(t.\"Name\", 'instance')", sql));

        var p4 = Assert.IsType<SqlOperation>(ops[3]).Sql;
        Assert.Contains("FROM \"CaProtocolConfigs\" pc JOIN \"CertificateAuthorities\" ca ON ca.\"Id\" = pc.\"CaId\" JOIN \"SigningProfiles\" sp ON sp.\"Id\" = pc.\"SigningProfileId\"", p4);
        Assert.Contains("WHERE pc.\"IsEnabled\" AND NOT ca.\"IsDeleted\" AND NOT ca.\"IsSshCa\" AND (sp.\"IssuerId\" IS NULL OR sp.\"IssuerId\" <> ca.\"CertificateId\")", p4);
        Assert.Contains("or disable the protocol, then upgrade.", p4);

        var p5 = Assert.IsType<SqlOperation>(ops[4]).Sql;
        Assert.Contains("FROM \"CertificateTemplates\" ct JOIN \"CertificateAuthorities\" ca ON ca.\"Id\" = ct.\"CaId\" JOIN \"SigningProfiles\" sp ON sp.\"Id\" = ct.\"SigningProfileId\"", p5);
        Assert.Contains("WHERE ct.\"IsEnabled\" AND NOT ca.\"IsDeleted\" AND NOT ca.\"IsSshCa\" AND (sp.\"IssuerId\" IS NULL OR sp.\"IssuerId\" <> ca.\"CertificateId\")", p5);

        Assert.Equal("CREATE UNIQUE INDEX \"IX_CertificateAuthorities_LabelLower\" ON \"CertificateAuthorities\" (lower(\"Label\"))",
            Assert.IsType<SqlOperation>(ops[5]).Sql);
        Assert.False(ops[6] is SqlOperation);
        Assert.DoesNotContain(ops, o => o is SqlOperation { SuppressTransaction: true });
    }

    [Fact]
    public void The_plain_indexes_replace_the_scoped_ones_and_the_quota_columns_go_last()
    {
        var ops = Migration().UpOperations.ToList();
        var created = ops.OfType<CreateIndexOperation>().ToList();
        Assert.Equal(["IX_CertificateAuthorities_Label", "IX_CertificateAuthorities_Name", "IX_CertificateAuthorities_TenantId"], created.Select(i => i.Name));
        Assert.True(created[0].IsUnique && created[1].IsUnique && !created[2].IsUnique);
        Assert.All(created, i => Assert.Null(i.Filter));

        var dropped = ops.OfType<DropIndexOperation>().Select(i => i.Name).ToList();
        Assert.Equal(["IX_CertificateAuthorities_Label_Instance", "IX_CertificateAuthorities_Name_Instance",
            "IX_CertificateAuthorities_TenantId_Label", "IX_CertificateAuthorities_TenantId_Name"], dropped);
        Assert.True(ops.IndexOf(created[^1]) < ops.FindIndex(o => o is DropIndexOperation));

        var columns = ops.OfType<DropColumnOperation>().ToList();
        Assert.Equal(["MaxCertificateAuthorities", "MaxCertificatesTotal", "MaxUsers"], columns.Select(c => c.Name));
        Assert.All(columns, c => Assert.Equal("Tenants", c.Table));
        Assert.Equal(ops.Count - 1, ops.IndexOf(columns[^1]));
    }

    [Fact]
    public void Down_refuses()
    {
        var ex = Assert.Throws<NotSupportedException>(() => Migration().DownOperations.ToList());
        Assert.Contains("restore the pre-upgrade dump", ex.Message);
    }
}
