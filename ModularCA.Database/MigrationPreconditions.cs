using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Migrations.Operations;
using Microsoft.EntityFrameworkCore.Migrations.Operations.Builders;

namespace ModularCA.Database;

/// <summary>
/// Precondition checks for migrations that transform data. A migration states what must hold
/// before it runs; when a check fails, PostgreSQL raises, the migration's transaction rolls
/// back, and the control role stops with the migration named.
/// </summary>
public static class MigrationPreconditions
{
    /// <summary>
    /// Emits a PostgreSQL <c>DO</c> block that raises <paramref name="message"/> when
    /// <paramref name="failureCondition"/> is true. Call it first in <c>Up</c>, before the
    /// statements that depend on the precondition.
    /// </summary>
    /// <param name="migrationBuilder">The migration's builder.</param>
    /// <param name="failureCondition">
    /// A SQL boolean expression that is true when the migration must NOT proceed, for example
    /// <c>(SELECT count(*) FROM "Tenants" WHERE NOT "IsSystemTenant") &gt; 1</c>.
    /// </param>
    /// <param name="message">What the operator reads. Quotes are escaped; <c>%</c> is taken literally.</param>
    public static OperationBuilder<SqlOperation> FailIf(
        this MigrationBuilder migrationBuilder, string failureCondition, string message)
    {
        ArgumentNullException.ThrowIfNull(migrationBuilder);
        ArgumentException.ThrowIfNullOrWhiteSpace(failureCondition);
        ArgumentException.ThrowIfNullOrWhiteSpace(message);
        return migrationBuilder.Sql(BuildSql(failureCondition, message));
    }

    /// <summary>
    /// The SQL <see cref="FailIf"/> emits, exposed for tests. Throws when either argument
    /// contains <c>$$</c>.
    /// </summary>
    public static string BuildSql(string failureCondition, string message)
    {
        if (failureCondition.Contains("$$") || message.Contains("$$"))
            throw new ArgumentException("A precondition cannot contain $$, which would end the DO block.");
        var literal = message.Replace("'", "''").Replace("%", "%%");
        return $"DO $$ BEGIN IF ({failureCondition}) THEN RAISE EXCEPTION '{literal}'; END IF; END $$;";
    }
}
