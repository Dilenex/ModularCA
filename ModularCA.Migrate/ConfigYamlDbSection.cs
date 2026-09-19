using ModularCA.Shared.Models.Config;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace ModularCA.Migrate;

/// <summary>
/// Replaces the <c>DB:</c> section of a deployment's <c>config.yaml</c>, and nothing else.
/// <para>
/// The database settings live in two files. <c>db.yaml</c> holds them at the top level and is
/// entirely ours to rewrite. <c>config.yaml</c> holds them under a <c>DB:</c> key alongside
/// everything else the deployment has been configured with — TLS, mail, protocols, scheduling —
/// none of which a migration has any business touching.
/// </para>
/// <para>
/// Bootstrap rewrites that whole file from scratch, which is fine on a first install and wrong
/// here: an operator who has edited anything since would lose it. So this splices one block and
/// leaves every other byte alone, and the caller then proves the result by loading it back.
/// </para>
/// </summary>
public static class ConfigYamlDbSection
{
    /// <summary>
    /// Returns the text with its <c>DB:</c> section replaced, appending one if the file has none.
    /// </summary>
    /// <param name="yaml">The existing file contents.</param>
    /// <param name="db">The database settings to write.</param>
    /// <returns>The new file contents.</returns>
    public static string Replace(string yaml, DbConfig db)
    {
        var rendered = Render(db);
        var lines = yaml.Replace("\r\n", "\n").Split('\n');

        var start = Array.FindIndex(lines, l => l.StartsWith("DB:", StringComparison.Ordinal));
        if (start < 0)
            return yaml.TrimEnd('\n', '\r') + "\n\n" + rendered;

        // The block runs until the next line that starts at column zero and is not blank — the
        // next top-level key. Anything indented, or empty, still belongs to DB.
        var end = start + 1;
        while (end < lines.Length
               && (lines[end].Length == 0 || char.IsWhiteSpace(lines[end][0])))
        {
            end++;
        }

        return string.Join("\n", lines[..start])
            + (start > 0 ? "\n" : "")
            + rendered
            + string.Join("\n", lines[end..]);
    }

    /// <summary>
    /// Serialises just the <c>DB:</c> section, with the same conventions the loader reads by.
    /// </summary>
    /// <param name="db">The database settings.</param>
    /// <returns>The YAML for the section, ending in a newline.</returns>
    public static string Render(DbConfig db)
    {
        var serializer = new SerializerBuilder()
            .WithNamingConvention(PascalCaseNamingConvention.Instance)
            .Build();

        var yaml = serializer.Serialize(new { DB = db }).Replace("\r\n", "\n");
        return yaml.EndsWith('\n') ? yaml : yaml + "\n";
    }

    /// <summary>
    /// Builds the settings block from the migration's outcome.
    /// </summary>
    /// <param name="options">The resolved options.</param>
    /// <param name="appPassword">The generated application role password.</param>
    /// <param name="auditPassword">The generated audit role password.</param>
    /// <returns>The database configuration to write.</returns>
    public static DbConfig From(MigrationOptions options, string appPassword, string auditPassword) => new()
    {
        App = Instance(options, options.TargetAppDatabase, options.TargetAppRole, appPassword),
        Audit = Instance(options, options.TargetAuditDatabase, options.TargetAuditRole, auditPassword),
    };

    private static DbInstance Instance(
        MigrationOptions options, string database, string username, string password) => new()
        {
            Host = options.TargetHost,
            Port = options.TargetPort,
            Database = database,
            Username = username,
            Password = password,
            SslMode = options.TargetSslMode,
        };
}
