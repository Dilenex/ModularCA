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
    /// <c>(SELECT count(*) FROM "Tenants" WHERE NOT "IsDeleted") &gt; 1</c>.
    /// </param>
    /// <param name="message">
    /// What the operator reads. Quotes are escaped; <c>%</c> is taken literally. <c>{0}</c>,
    /// <c>{1}</c> and so on stand for the values of <paramref name="messageValues"/>.
    /// </param>
    /// <param name="messageValues">
    /// SQL expressions evaluated when the check fails, such as <c>(SELECT count(*) FROM "Tenants")</c>,
    /// whose values replace the numbered placeholders in <paramref name="message"/>.
    /// </param>
    public static OperationBuilder<SqlOperation> FailIf(
        this MigrationBuilder migrationBuilder, string failureCondition, string message, params string[] messageValues)
    {
        ArgumentNullException.ThrowIfNull(migrationBuilder);
        ArgumentException.ThrowIfNullOrWhiteSpace(failureCondition);
        ArgumentException.ThrowIfNullOrWhiteSpace(message);
        return migrationBuilder.Sql(BuildSql(failureCondition, message, messageValues));
    }

    /// <summary>
    /// The SQL <see cref="FailIf"/> emits, exposed for tests. A message without placeholders is a
    /// RAISE format string with <c>%</c> doubled. With placeholders it is built by <c>concat</c>
    /// and raised with <c>USING MESSAGE</c>, which applies no format: RAISE's own placeholders
    /// cannot express a value next to a literal <c>%</c> or next to another value, because it reads
    /// <c>%%</c> greedily. Throws when any argument contains <c>$$</c>, or when a placeholder in
    /// <paramref name="message"/> has no value.
    /// </summary>
    public static string BuildSql(string failureCondition, string message, params string[] messageValues)
    {
        messageValues ??= [];
        if (failureCondition.Contains("$$") || message.Contains("$$") || messageValues.Any(v => v.Contains("$$")))
            throw new ArgumentException("A precondition cannot contain $$, which would end the DO block.");
        var segments = System.Text.RegularExpressions.Regex.Split(message, @"\{(\d+)\}");
        string raise;
        if (segments.Length == 1)
        {
            raise = $"'{message.Replace("'", "''").Replace("%", "%%")}'";
        }
        else
        {
            var parts = new List<string>();
            for (var i = 0; i < segments.Length; i++)
            {
                if (i % 2 == 0)
                {
                    if (segments[i].Length > 0)
                        parts.Add($"'{segments[i].Replace("'", "''")}'");
                    continue;
                }
                var index = int.Parse(segments[i], System.Globalization.CultureInfo.InvariantCulture);
                if (index >= messageValues.Length)
                    throw new ArgumentException($"The message names {{{index}}} but only {messageValues.Length} value(s) were given.");
                parts.Add($"({messageValues[index]})::text");
            }
            raise = $"USING MESSAGE = concat({string.Join(", ", parts)})";
        }
        return $"DO $$ BEGIN IF ({failureCondition}) THEN RAISE EXCEPTION {raise}; END IF; END $$;";
    }
}
