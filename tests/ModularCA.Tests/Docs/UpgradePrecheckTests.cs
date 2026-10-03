using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Migrations.Operations;
using ModularCA.Database;
using Xunit;
using RenameMigration = ModularCA.Database.Migrations.RenameTenantToSpace;

namespace ModularCA.Tests.Docs;

/// <summary>
/// The read-only pre-checks in packaging/README-DEPLOY.md ("Upgrading to 0.4.0") mirror the
/// preconditions of the 0.4.0 migrations. Each precondition (a <c>// P</c> comment in the
/// migration, or the migration itself when it has one check) has a check labelled with its
/// migration and id, every label names a real precondition, and each check holds the key
/// predicates of its precondition as the migration emits them, whitespace aside.
/// </summary>
public sealed class UpgradePrecheckTests
{
    private const string Hostnames = "RetireTenantHostnames";
    private const string Fold = "FoldSystemTenant";
    private const string Unique = "InstanceUniqueCaNames";
    private const string Rename = "RenameTenantToSpace";
    private static readonly string[] Migrations = [Hostnames, Fold, Unique, Rename];

    private const string Sys = """(SELECT "Id" FROM "Tenants" WHERE "IsSystemTenant")""";
    private const string Misissuing = """JOIN "CertificateAuthorities" ca ON ca."Id" = {0}."CaId" JOIN "SigningProfiles" sp ON sp."Id" = {0}."SigningProfileId" WHERE {0}."IsEnabled" AND NOT ca."IsDeleted" AND NOT ca."IsSshCa" AND (sp."IssuerId" IS NULL OR sp."IssuerId" <> ca."CertificateId")""";

    /// <summary>Text each check holds, as the migration emits it.</summary>
    private static readonly Dictionary<string, string[]> KeyPredicates = new()
    {
        [Hostnames] = ["""FROM "TenantHostnames" """],
        [$"{Fold} P1"] = [$"""(SELECT count(*) FROM "Tenants" WHERE "IsSystemTenant") > 1 OR ((SELECT count(*) FROM "Tenants" WHERE "IsSystemTenant") = 0 AND EXISTS (SELECT 1 FROM "Tenants"))"""],
        [$"{Fold} P2"] = ["""(SELECT count(*) FROM "Tenants" WHERE NOT "IsSystemTenant" AND NOT "IsDeleted") > 1"""],
        [$"{Fold} P3"] = ["""(SELECT count(*) FROM "SecurityPolicy") > 1"""],
        [$"{Fold} P4"] = [$"""FROM "KeyCeremonies" WHERE "Status" IN ('Pending', 'Approved') AND ("TenantId" = {Sys} OR strpos(lower("ParametersJson"), {Sys}::text) > 0)"""],
        [$"{Fold} P5"] =
        [
            $"""FROM "UserCapabilityGrants" WHERE "TenantId" = {Sys} AND "CertificateAuthorityId" IS NULL""",
            $"""FROM "RoleAssignments" WHERE "GroupId" IS NULL AND "TenantId" = {Sys} AND "CertificateAuthorityId" IS NULL""",
        ],
        [$"{Fold} P6"] = [$"""FROM "Users" WHERE "ServiceScopeTenantId" = {Sys} AND "ServiceScopeCaId" IS NULL"""],
        [$"{Fold} P7"] =
        [
            $"""g."TenantId" = {Sys} AND NOT g."IsSystemGroup" AND g."CertificateAuthorityId" IS NULL""",
            "\"CaGroupMembers\"",
            "\"AccessBadgeSources\"",
        ],
        [$"{Fold} P8"] =
        [
            """NOT EXISTS (SELECT 1 FROM "Tenants" t WHERE t."Id" = g."TenantId")""",
            $"""(g."TenantId" <> ca."TenantId" AND (g."TenantId" = {Sys} OR ca."TenantId" = {Sys}))""",
        ],
        [$"{Fold} P9"] = [$"""FROM "CertProfiles" WHERE "TenantId" = {Sys} AND "CertificateAuthorityId" IS NULL AND NOT "IsCaProfile" """],
        [$"{Unique} P1"] = ["""FROM "CertificateAuthorities" ca WHERE ca."Label" IS NOT NULL GROUP BY"""],
        [$"{Unique} P2"] = ["""FROM "CertificateAuthorities" ca WHERE ca."Label" IS NOT NULL GROUP BY lower(ca."Label") HAVING count(*) > 1"""],
        [$"{Unique} P3"] = ["""FROM "CertificateAuthorities" ca WHERE ca."Name" IS NOT NULL GROUP BY ca."Name" HAVING count(*) > 1"""],
        [$"{Unique} P4"] = ["""FROM "CaProtocolConfigs" pc """ + string.Format(Misissuing, "pc")],
        [$"{Unique} P5"] = ["""FROM "CertificateTemplates" ct """ + string.Format(Misissuing, "ct")],
        [$"{Rename} P1"] =
        [
            """FROM "KeyCeremonies" k WHERE strpos(lower(k."ParametersJson"), 'tenantid') > 0 ORDER BY k."Id" """,
            RenameMigration.NeutraliseNulOnce("t"),
            """EXCEPTION WHEN data_exception THEN j := NULL;""",
            """IF j IS NULL OR jsonb_typeof(j) <> 'object' OR (SELECT count(*) FROM jsonb_object_keys(j) jk WHERE lower(jk) IN ('tenantid', 'spaceid')) > 1 OR (SELECT count(*) FROM jsonb_object_keys(j) jk WHERE lower(jk) IN ('mintedtiertenantid', 'mintedtierspaceid')) > 1 THEN""",
        ],
        [$"{Rename} P2"] =
        [
            """SELECT g."Id", g."Name", 'space-' || s."Slug"::text || '-' || x.suffix AS new_name, regexp_replace(g."DisplayName", '^(Org|Organisation|Organization) ', 'Space ') AS new_display FROM "CaGroups" g""",
            """CROSS JOIN (VALUES ('admin'), ('operator'), ('auditor'), ('user')) AS x(suffix) WHERE g."CertificateAuthorityId" IS NULL AND lower(g."Name"::text) = lower('org-' || s."Slug"::text || '-' || x.suffix)) r WHERE length(r.new_name) > 200 OR length(r.new_display) > 300 OR EXISTS (SELECT 1 FROM "CaGroups" o WHERE lower(o."Name"::text) = lower(r.new_name)""",
        ],
    };

    private static readonly Regex Label = new(@"^--\s+[a-z]\.\s+(?<m>[A-Za-z]+)(?:\s+(?<ids>P\d+(?:,\s*P\d+)*))?:", RegexOptions.CultureInvariant);

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "ModularCA.sln")))
            dir = dir.Parent;
        Assert.NotNull(dir);
        return dir!.FullName;
    }

    private static string Squash(string text) => Regex.Replace(text, @"\s+", " ").Trim();

    /// <summary>The fenced SQL of the 0.4.0 checklist, one entry per labelled check, keyed "Migration Pn".</summary>
    private static Dictionary<string, string> ReadmeChecks(out string sql)
    {
        var readme = File.ReadAllText(Path.Combine(RepoRoot(), "packaging", "README-DEPLOY.md")).Replace("\r\n", "\n");
        var start = readme.IndexOf("### Upgrading to 0.4.0", StringComparison.Ordinal);
        var end = readme.IndexOf("#### What changes", start, StringComparison.Ordinal);
        Assert.True(start >= 0 && end > start, "README-DEPLOY.md has no \"Upgrading to 0.4.0\" checklist.");
        var fences = Regex.Matches(readme[start..end], @"```sql\n(.*?)\n\s*```", RegexOptions.Singleline);
        sql = string.Join("\n", fences.Select(f => f.Groups[1].Value));

        var checks = new Dictionary<string, List<string>>();
        List<string> current = [];
        foreach (var raw in sql.Split('\n'))
        {
            var line = raw.Trim();
            var label = Label.Match(line);
            if (label.Success)
            {
                string[] ids = label.Groups["ids"].Success ? label.Groups["ids"].Value.Split(',', StringSplitOptions.TrimEntries) : [""];
                current = ids.Select(id => (label.Groups["m"].Value + " " + id).Trim()).ToList();
                foreach (var key in current)
                    Assert.True(checks.TryAdd(key, []), $"{key} is labelled twice.");
            }
            else if (!line.StartsWith("--", StringComparison.Ordinal))
            {
                foreach (var key in current)
                    checks[key].Add(line);
            }
        }
        return checks.ToDictionary(c => c.Key, c => Squash(string.Join("\n", c.Value)));
    }

    /// <summary>The precondition ids each migration declares with a <c>// Pn</c> comment, or the migration's own name.</summary>
    private static List<string> Preconditions()
    {
        var folder = Path.Combine(RepoRoot(), "ModularCA.Database", "Migrations");
        var ids = new List<string>();
        foreach (var name in Migrations)
        {
            var file = Assert.Single(Directory.GetFiles(folder, $"*_{name}.cs"));
            var found = Regex.Matches(File.ReadAllText(file), @"^\s*// (P\d+)\s*$", RegexOptions.Multiline).Select(m => $"{name} {m.Groups[1].Value}").ToList();
            ids.AddRange(found.Count == 0 ? [name] : found);
        }
        return ids;
    }

    /// <summary>The SQL a migration emits, whitespace squashed.</summary>
    private static string MigrationSql(string name)
    {
        using var db = new ModularCADbContextFactory().CreateDbContext([]);
        var assembly = db.GetService<IMigrationsAssembly>();
        var (_, type) = Assert.Single(assembly.Migrations, m => m.Key.EndsWith("_" + name, StringComparison.Ordinal));
        var migration = assembly.CreateMigration(type, db.Database.ProviderName!);
        return Squash(string.Join("\n", migration.UpOperations.OfType<SqlOperation>().Select(o => o.Sql)));
    }

    [Fact]
    public void Every_precondition_has_a_labelled_check_and_every_label_names_one()
    {
        var expected = Preconditions().Order().ToList();
        Assert.Equal(expected, ReadmeChecks(out _).Keys.Order().ToList());
        Assert.Equal(expected, KeyPredicates.Keys.Order().ToList());
    }

    [Fact]
    public void Each_check_holds_its_preconditions_key_predicates_as_the_migration_emits_them()
    {
        var checks = ReadmeChecks(out _);
        var emitted = Migrations.ToDictionary(m => m, MigrationSql);
        var missing = new List<string>();
        foreach (var (id, predicates) in KeyPredicates)
        {
            foreach (var predicate in predicates.Select(Squash))
            {
                if (!emitted[id.Split(' ')[0]].Contains(predicate, StringComparison.Ordinal))
                    missing.Add($"{id}: the migration no longer emits: {predicate}");
                if (!checks.TryGetValue(id, out var check) || !check.Contains(predicate, StringComparison.Ordinal))
                    missing.Add($"{id}: the README check does not hold: {predicate}");
            }
        }
        Assert.True(missing.Count == 0, string.Join("\n", missing));
    }

    [Fact]
    public void The_checks_run_read_only()
    {
        ReadmeChecks(out var sql);
        Assert.StartsWith("SET default_transaction_read_only = on;", sql.TrimStart());
        Assert.DoesNotMatch(new Regex(@"\b(INSERT|UPDATE|DELETE|ALTER|DROP|CREATE|TRUNCATE|RAISE EXCEPTION)\b", RegexOptions.IgnoreCase), sql);
    }
}
