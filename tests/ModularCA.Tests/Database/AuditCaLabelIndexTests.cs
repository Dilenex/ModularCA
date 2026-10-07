using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Migrations.Operations;
using ModularCA.Database;
using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// The label lock (<c>CaLabelRules.LabelReferencesAsync</c>) looks a label up case-insensitively in
/// each protocol audit table with <c>CaLabel.ToLower() == label</c>. A plain index on
/// <c>CaLabel</c> cannot serve that, so <c>AuditCaLabelLowerIndexes</c> indexes the expression
/// PostgreSQL is given for it.
/// </summary>
public class AuditCaLabelIndexTests
{
    private const string Migration = "20261004064208_AuditCaLabelLowerIndexes";

    [Fact]
    public void Each_protocol_audit_table_indexes_the_expression_the_label_lock_compares()
    {
        using var db = new AuditDbContextFactory().CreateDbContext([]);
        var lowered = "acme-root";
        var queries = new Dictionary<string, string>
        {
            ["AuditEst"] = db.AuditEst.Where(a => a.CaLabel != null && a.CaLabel.ToLower() == lowered).Select(a => a.Id).ToQueryString(),
            ["AuditScep"] = db.AuditScep.Where(a => a.CaLabel != null && a.CaLabel.ToLower() == lowered).Select(a => a.Id).ToQueryString(),
            ["AuditCmp"] = db.AuditCmp.Where(a => a.CaLabel != null && a.CaLabel.ToLower() == lowered).Select(a => a.Id).ToQueryString(),
            ["AuditMsae"] = db.AuditMsae.Where(a => a.CaLabel != null && a.CaLabel.ToLower() == lowered).Select(a => a.Id).ToQueryString(),
            ["AuditAcme"] = db.AuditAcme.Where(a => a.CaLabel != null && a.CaLabel.ToLower() == lowered).Select(a => a.Id).ToQueryString(),
        };

        var assembly = db.GetService<IMigrationsAssembly>();
        Assert.True(assembly.Migrations.TryGetValue(Migration, out var type), $"{Migration} is missing.");
        var up = string.Join("\n", assembly.CreateMigration(type!, db.Database.ProviderName!).UpOperations
            .OfType<SqlOperation>().Select(o => o.Sql));

        foreach (var (table, sql) in queries)
        {
            Assert.Matches($"FROM \"{table}\" AS (\\w+)\\s", sql);
            var alias = Regex.Match(sql, $"FROM \"{table}\" AS (\\w+)\\s").Groups[1].Value;
            Assert.Contains($"lower({alias}.\"CaLabel\") = ", sql);
            Assert.Contains($"ON \"{table}\" (lower(\"CaLabel\"))", up);
        }
    }
}
