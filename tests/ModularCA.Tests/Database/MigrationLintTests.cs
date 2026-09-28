using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Migrations.Operations;
using ModularCA.Database;
using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// Every migration of both contexts keeps to the rules migrations run under: they run as the
/// runtime role that owns the schema, so they never touch roles, privileges, ownership, schemas,
/// databases or extensions (the application context's <c>citext</c> excepted), and a migration
/// guarded by a <see cref="MigrationPreconditions.FailIf"/> block runs entirely inside its
/// transaction, so a failed precondition leaves nothing applied.
/// </summary>
public class MigrationLintTests
{
    private const string ExtensionAnnotationPrefix = "Npgsql:PostgresExtension:";
    private const string CreatedConcurrentlyAnnotation = "Npgsql:CreatedConcurrently";
    private const string FailIfPrefix = "DO $$ BEGIN IF (";

    private static readonly (Regex Pattern, string What)[] ForbiddenSql =
    [
        (Word(@"GRANT"), "GRANT"),
        (Word(@"REVOKE"), "REVOKE"),
        (Word(@"OWNER\s+TO"), "OWNER TO"),
        (Word(@"(?:SET|RESET)\s+ROLE"), "SET ROLE"),
        (Word(@"SET\s+SESSION\s+AUTHORIZATION"), "SET SESSION AUTHORIZATION"),
        (Word(@"ALTER\s+DEFAULT\s+PRIVILEGES"), "ALTER DEFAULT PRIVILEGES"),
        (Word(@"(?:CREATE|DROP|ALTER)\s+SCHEMA"), "CREATE/DROP SCHEMA"),
        (Word(@"(?:CREATE|DROP|ALTER)\s+(?:ROLE|USER|GROUP)"), "CREATE/DROP ROLE"),
        (Word(@"(?:CREATE|DROP|ALTER)\s+DATABASE"), "CREATE/DROP DATABASE"),
        (Word(@"(?:CREATE|DROP|ALTER)\s+EXTENSION"), "CREATE/DROP EXTENSION"),
    ];

    public static TheoryData<string> Contexts() => new() { "application", "audit" };

    [Theory]
    [MemberData(nameof(Contexts))]
    public void Every_migration_keeps_to_the_rules(string context)
    {
        using var db = Create(context);
        var assembly = db.GetService<IMigrationsAssembly>();
        Assert.NotEmpty(assembly.Migrations);

        var violations = new List<string>();
        foreach (var (id, type) in assembly.Migrations)
        {
            var migration = assembly.CreateMigration(type, db.Database.ProviderName!);
            violations.AddRange(Lint(context, id, migration.UpOperations));
        }

        Assert.True(violations.Count == 0,
            "Migrations run as the runtime role and must not manage roles, privileges, ownership, schemas, databases or "
            + "extensions, nor mix a FailIf precondition with statements outside a transaction:" + Environment.NewLine
            + string.Join(Environment.NewLine, violations));
    }

    [Theory]
    [InlineData("GRANT SELECT ON \"Tenants\" TO reporting")]
    [InlineData("revoke all on schema public from public")]
    [InlineData("ALTER TABLE \"Tenants\" OWNER TO postgres")]
    [InlineData("SET ROLE postgres")]
    [InlineData("ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO x")]
    [InlineData("CREATE SCHEMA reporting")]
    [InlineData("DROP ROLE IF EXISTS x")]
    [InlineData("CREATE DATABASE other")]
    [InlineData("CREATE EXTENSION IF NOT EXISTS pgcrypto")]
    [InlineData("DO $$ BEGIN EXECUTE 'GRANT ALL ON ALL TABLES IN SCHEMA public TO x'; END $$;")]
    public void The_lint_catches_privilege_and_ownership_statements(string sql)
    {
        Assert.NotEmpty(Lint("application", "x", [new SqlOperation { Sql = sql }]));
    }

    [Theory]
    [InlineData("UPDATE \"UserCapabilityGrants\" SET \"Capability\" = 'x'")]
    [InlineData("ALTER TABLE \"Grant\" ADD COLUMN \"Revoke\" integer")]
    [InlineData("CREATE INDEX \"IX_Owner\" ON \"Tenants\" (\"Name\")")]
    public void The_lint_ignores_quoted_identifiers_that_only_look_like_keywords(string sql)
    {
        Assert.Empty(Lint("application", "x", [new SqlOperation { Sql = sql }]));
    }

    [Fact]
    public void The_lint_catches_schemas_and_extensions()
    {
        Assert.NotEmpty(Lint("application", "x", [new EnsureSchemaOperation { Name = "reporting" }]));

        var pgcrypto = new AlterDatabaseOperation();
        pgcrypto.AddAnnotation(ExtensionAnnotationPrefix + "pgcrypto", ",,");
        Assert.NotEmpty(Lint("application", "x", [pgcrypto]));

        var citext = new AlterDatabaseOperation();
        citext.AddAnnotation(ExtensionAnnotationPrefix + "citext", ",,");
        Assert.Empty(Lint("application", "x", [citext]));
        Assert.NotEmpty(Lint("audit", "x", [citext]));
    }

    [Fact]
    public void The_lint_catches_a_precondition_mixed_with_statements_outside_a_transaction()
    {
        var failIf = new SqlOperation { Sql = MigrationPreconditions.BuildSql("(SELECT count(*) FROM \"Tenants\") > 2", "too many") };

        Assert.NotEmpty(Lint("application", "x", [failIf, new SqlOperation { Sql = "UPDATE \"Tenants\" SET \"Name\" = 'x'", SuppressTransaction = true }]));

        var concurrent = new CreateIndexOperation { Name = "IX_x", Table = "Tenants", Columns = ["Name"] };
        concurrent.AddAnnotation(CreatedConcurrentlyAnnotation, true);
        Assert.NotEmpty(Lint("application", "x", [failIf, concurrent]));

        Assert.Empty(Lint("application", "x", [failIf, new SqlOperation { Sql = "UPDATE \"Tenants\" SET \"Name\" = 'x'" }]));
        Assert.Empty(Lint("application", "x", [new SqlOperation { Sql = "UPDATE \"Tenants\" SET \"Name\" = 'x'", SuppressTransaction = true }]));
    }

    /// <summary>
    /// Every rule <paramref name="operations"/> of migration <paramref name="id"/> breaks, one line
    /// each. <paramref name="context"/> is "application" or "audit".
    /// </summary>
    private static List<string> Lint(string context, string id, IReadOnlyList<MigrationOperation> operations)
    {
        var violations = new List<string>();
        foreach (var operation in operations)
        {
            if (operation is SqlOperation sql)
            {
                var text = Regex.Replace(sql.Sql, "\"(?:[^\"]|\"\")*\"", "\"\"");
                foreach (var (pattern, what) in ForbiddenSql)
                    if (pattern.IsMatch(text))
                        violations.Add($"{context} {id}: {what} in SQL: {Excerpt(sql.Sql)}");
            }
            if (operation is EnsureSchemaOperation or DropSchemaOperation)
                violations.Add($"{context} {id}: {operation.GetType().Name} creates or drops a schema");

            foreach (var annotation in operation.GetAnnotations())
            {
                if (!annotation.Name.StartsWith(ExtensionAnnotationPrefix, StringComparison.Ordinal))
                    continue;
                var extension = annotation.Name[ExtensionAnnotationPrefix.Length..];
                if (context != "application" || extension != "citext")
                    violations.Add($"{context} {id}: extension '{extension}'; the {context} context may use "
                        + (context == "application" ? "citext only" : "none"));
            }
        }

        var hasFailIf = operations.OfType<SqlOperation>().Any(o => o.Sql.TrimStart().StartsWith(FailIfPrefix, StringComparison.Ordinal));
        var outsideTransaction = operations.Any(o =>
            o is SqlOperation { SuppressTransaction: true } || o.FindAnnotation(CreatedConcurrentlyAnnotation)?.Value is true);
        if (hasFailIf && outsideTransaction)
            violations.Add($"{context} {id}: a FailIf precondition in a migration that runs statements outside a transaction; "
                + "a failed precondition would leave those applied");
        return violations;
    }

    /// <summary>A case-insensitive whole-word pattern.</summary>
    private static Regex Word(string pattern) =>
        new($@"\b{pattern}\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    /// <summary>The first line of <paramref name="sql"/>, shortened.</summary>
    private static string Excerpt(string sql)
    {
        var line = sql.Split('\n')[0].Trim();
        return line.Length > 120 ? line[..120] + "..." : line;
    }

    /// <summary>A design-time context of <paramref name="context"/>; nothing connects.</summary>
    private static DbContext Create(string context) => context == "application"
        ? new ModularCADbContextFactory().CreateDbContext([])
        : new AuditDbContextFactory().CreateDbContext([]);
}
