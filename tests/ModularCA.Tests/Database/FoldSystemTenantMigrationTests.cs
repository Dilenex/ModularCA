using System.Reflection;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Migrations.Operations;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// The shape of the 0.4.0 S3 migration, checked without a database: preconditions first, the
/// steps in the order that makes a missed row abort rather than cascade, a policy row that starts
/// from the entity's defaults, a copy of the system tenant's values as they are, and no way back.
/// The PostgreSQL harness runs it for real.
/// </summary>
public class FoldSystemTenantMigrationTests
{
    private static Migration Fold()
    {
        using var db = new ModularCADbContextFactory().CreateDbContext([]);
        var assembly = db.GetService<IMigrationsAssembly>();
        var (_, type) = assembly.Migrations.Single(m => m.Key.EndsWith("_FoldSystemTenant", StringComparison.Ordinal));
        return assembly.CreateMigration(type, db.Database.ProviderName!);
    }

    private static List<MigrationOperation> Up() => Fold().UpOperations.ToList();

    private static int IndexOf(List<MigrationOperation> ops, Func<MigrationOperation, bool> match)
    {
        var i = ops.FindIndex(o => match(o));
        Assert.True(i >= 0, "operation not found");
        return i;
    }

    private static bool Sql(MigrationOperation o, string startsWith) =>
        o is SqlOperation s && s.Sql.TrimStart().StartsWith(startsWith, StringComparison.Ordinal);

    /// <summary>
    /// Eight preconditions (P1, P3-P9) come first, inside the transaction. None counts the
    /// organisation tenants: each becomes a space, however many there are.
    /// </summary>
    [Fact]
    public void Eight_preconditions_come_first_and_nothing_runs_outside_the_transaction()
    {
        var ops = Up();
        Assert.All(ops.Take(8), o => Assert.True(Sql(o, "DO $$ BEGIN IF (")));
        Assert.False(Sql(ops[8], "DO $$ BEGIN IF ("));
        Assert.DoesNotContain(ops, o => o is SqlOperation { SuppressTransaction: true });
        Assert.Contains("\"IsSystemTenant\") > 1", ((SqlOperation)ops[0]).Sql);
        Assert.Contains("'Pending', 'Approved'", ((SqlOperation)ops[2]).Sql);
        Assert.Contains("strpos(lower(\"ParametersJson\")", ((SqlOperation)ops[2]).Sql);
        Assert.All(ops.Take(8), o => Assert.DoesNotContain("NOT \"IsSystemTenant\"", ((SqlOperation)o).Sql));
    }

    [Fact]
    public void The_steps_run_in_the_order_that_makes_a_missed_row_abort()
    {
        var ops = Up();
        var nullable = ops.OfType<AlterColumnOperation>().Where(a => a.Name == "TenantId").ToList();
        Assert.Equal(["CertificateAuthorities", "CaGroups", "KerberosRealms"], nullable.Select(a => a.Table));
        Assert.All(nullable, a => Assert.True(a.IsNullable));

        var insertPolicy = IndexOf(ops, o => Sql(o, "INSERT INTO \"SecurityPolicy\""));
        var copyPolicy = IndexOf(ops, o => Sql(o, "UPDATE \"SecurityPolicy\""));
        var deleteGroups = IndexOf(ops, o => Sql(o, "DELETE FROM \"CaGroups\""));
        var firstNulling = IndexOf(ops, o => Sql(o, "UPDATE \"CertificateAuthorities\" SET \"TenantId\" = NULL"));
        var lastNulling = IndexOf(ops, o => Sql(o, "UPDATE \"Users\" SET \"ServiceScopeTenantId\" = NULL"));
        var restrict = ops.OfType<AddForeignKeyOperation>().ToList();
        var firstRestrict = ops.IndexOf(restrict[0]);
        var leftovers = ops.FindLastIndex(o => Sql(o, "DO $$ BEGIN IF ("));
        var deleteTenant = IndexOf(ops, o => Sql(o, "DELETE FROM \"Tenants\""));
        var indexes = ops.FindIndex(o => o is CreateIndexOperation);
        var dropColumn = IndexOf(ops, o => o is DropColumnOperation { Name: "IsSystemTenant", Table: "Tenants" });

        Assert.True(ops.IndexOf(nullable[^1]) < insertPolicy);
        Assert.True(insertPolicy < copyPolicy && copyPolicy < deleteGroups && deleteGroups < firstNulling);
        Assert.True(lastNulling < firstRestrict && firstRestrict < leftovers && leftovers < deleteTenant);
        Assert.True(deleteTenant < indexes && indexes < dropColumn && dropColumn == ops.Count - 1);

        Assert.Equal(["KerberosRealms", "RoleAssignments", "Roles", "UserCapabilityGrants"], restrict.Select(f => f.Table));
        Assert.All(restrict, f => Assert.Equal(ReferentialAction.Restrict, f.OnDelete));
        var nulled = ops.OfType<SqlOperation>().Select(s => Regex.Match(s.Sql, "^UPDATE \"(\\w+)\" SET \"TenantId\" = NULL").Groups[1].Value).Where(t => t != "").ToList();
        Assert.Equal(["CertificateAuthorities", "CaGroups", "KerberosRealms", "Roles", "RoleAssignments", "UserCapabilityGrants", "CertProfiles", "EnrollmentTokens", "KeyCeremonies"], nulled);
        Assert.DoesNotContain(ops.OfType<SqlOperation>(), s => s.Sql.Contains("SignerAudit", StringComparison.Ordinal));
    }

    [Fact]
    public void The_instance_index_is_partial_and_unique()
    {
        var indexes = Up().OfType<CreateIndexOperation>().ToList();
        Assert.Equal(["IX_CertificateAuthorities_Label_Instance", "IX_CertificateAuthorities_Name_Instance"], indexes.Select(i => i.Name));
        Assert.All(indexes, i => Assert.True(i.IsUnique));
        Assert.All(indexes, i => Assert.Equal("\"TenantId\" IS NULL", i.Filter));
    }

    [Fact]
    public void The_system_tenants_values_are_copied_as_they_are_and_the_user_quorum_is_left()
    {
        var copy = Up().OfType<SqlOperation>().Single(s => s.Sql.TrimStart().StartsWith("UPDATE \"SecurityPolicy\"", StringComparison.Ordinal)).Sql;
        foreach (var column in new[] { "RequireKeyCeremony", "CeremonyRequiredApprovals", "MaxValidityDays", "ValidityCeilingBehavior", "UserCeremonyRequiredApprovals" })
            Assert.Contains($"\"{column}\" = t.\"{column}\"", copy);
        Assert.DoesNotContain("UserQuorum\" =", copy);
        Assert.DoesNotContain("GREATEST", copy, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("LEAST", copy, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_missing_policy_row_is_created_with_the_entity_defaults()
    {
        var insert = Up().OfType<SqlOperation>().Single(s => s.Sql.TrimStart().StartsWith("INSERT INTO \"SecurityPolicy\"", StringComparison.Ordinal)).Sql;
        Assert.Contains("WHERE NOT EXISTS (SELECT 1 FROM \"SecurityPolicy\")", insert);
        Assert.Contains("AND EXISTS (SELECT 1 FROM \"Tenants\" WHERE \"IsSystemTenant\")", insert);

        var columns = Regex.Matches(insert[..insert.IndexOf("SELECT", StringComparison.Ordinal)], "\"(\\w+)\"")
            .Select(m => m.Groups[1].Value).Skip(1).ToList();
        var valuesText = insert[(insert.IndexOf("SELECT", StringComparison.Ordinal) + 6)..insert.IndexOf("WHERE", StringComparison.Ordinal)];
        var values = valuesText.Split(',').Select(v => v.Trim()).ToList();
        Assert.Equal(columns.Count, values.Count);

        var defaults = new SecurityPolicyEntity();
        var properties = typeof(SecurityPolicyEntity).GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.CanWrite).Select(p => p.Name).ToHashSet();
        Assert.Equal(properties.OrderBy(p => p), columns.OrderBy(c => c));

        for (var i = 0; i < columns.Count; i++)
        {
            var property = typeof(SecurityPolicyEntity).GetProperty(columns[i])!;
            var value = property.GetValue(defaults);
            var sql = values[i];
            switch (columns[i])
            {
                case "Id":
                    Assert.Equal("gen_random_uuid()", sql);
                    break;
                case "UpdatedAt":
                    Assert.Equal("now()", sql);
                    break;
                default:
                    var expected = value switch
                    {
                        null => "NULL",
                        bool b => b ? "true" : "false",
                        Enum e => Convert.ToInt32(e).ToString(System.Globalization.CultureInfo.InvariantCulture),
                        _ => Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture),
                    };
                    Assert.True(expected == sql, $"{columns[i]}: the migration inserts {sql}, the entity defaults to {expected}");
                    break;
            }
        }
    }

    [Fact]
    public void Down_refuses_and_points_at_the_dump()
    {
        var ex = Assert.Throws<NotSupportedException>(() => Fold().DownOperations);
        Assert.Contains("restore the pre-upgrade dump", ex.Message);
    }
}
