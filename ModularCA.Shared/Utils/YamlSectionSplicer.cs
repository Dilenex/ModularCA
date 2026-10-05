using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace ModularCA.Shared.Utils;

/// <summary>
/// Replaces one top-level section of a YAML file and leaves every other byte alone.
/// <para>
/// <c>config.yaml</c> carries everything a deployment has been configured with. Rewriting it
/// from an object — which is what bootstrap does on a first install — is wrong for anything
/// that runs later: it discards whatever the operator has changed since, and it turns a
/// well-scoped change into "the whole file is different now". So a tool that needs to update one
/// section splices that section, and the caller proves the result by loading it back.
/// </para>
/// </summary>
public static class YamlSectionSplicer
{
    /// <summary>
    /// Returns the text with the named top-level section replaced, appending one if there is
    /// none. The block runs from the key at column zero to the next non-blank line at column
    /// zero; anything indented or empty in between belongs to it.
    /// </summary>
    /// <param name="yaml">The existing file contents.</param>
    /// <param name="section">The top-level key, such as <c>DB</c> or <c>Signer</c>.</param>
    /// <param name="value">The object to serialise under that key.</param>
    /// <returns>The new file contents, LF-terminated.</returns>
    public static string Replace(string yaml, string section, object value)
    {
        var rendered = Render(section, value);
        var lines = yaml.Replace("\r\n", "\n").Split('\n');
        var key = section + ":";

        var start = Array.FindIndex(lines, l => l.StartsWith(key, StringComparison.Ordinal));
        if (start < 0)
            return yaml.TrimEnd('\n', '\r') + "\n\n" + rendered;

        var end = start + 1;
        while (end < lines.Length && (lines[end].Length == 0 || char.IsWhiteSpace(lines[end][0])))
            end++;

        return string.Join("\n", lines[..start])
            + (start > 0 ? "\n" : "")
            + rendered
            + string.Join("\n", lines[end..]);
    }

    /// <summary>
    /// Returns the text without the named top-level section, or unchanged when there is none.
    /// The block is delimited as in <see cref="Replace"/>.
    /// </summary>
    /// <param name="yaml">The existing file contents.</param>
    /// <param name="section">The top-level key to remove.</param>
    /// <returns>The new file contents.</returns>
    public static string Remove(string yaml, string section)
    {
        var lines = yaml.Replace("\r\n", "\n").Split('\n');
        var key = section + ":";

        var start = Array.FindIndex(lines, l => l.StartsWith(key, StringComparison.Ordinal));
        if (start < 0)
            return yaml;

        var end = start + 1;
        while (end < lines.Length && (lines[end].Length == 0 || char.IsWhiteSpace(lines[end][0])))
            end++;

        return string.Join("\n", lines[..start].Concat(lines[end..]));
    }

    /// <summary>
    /// Serialises one section with the conventions the loaders read by: Pascal-case keys, and
    /// any member marked for quoting rendered quoted.
    /// </summary>
    /// <param name="section">The top-level key.</param>
    /// <param name="value">The object to serialise under it.</param>
    /// <returns>The YAML for the section, ending in a newline.</returns>
    public static string Render(string section, object value)
    {
        var serializer = new SerializerBuilder()
            .WithNamingConvention(PascalCaseNamingConvention.Instance)
            .Build();

        // Serialising a dictionary rather than an anonymous type keeps the key's casing exactly
        // as given: the naming convention would otherwise reshape it.
        var yaml = serializer.Serialize(new Dictionary<string, object> { [section] = value })
            .Replace("\r\n", "\n");
        return yaml.EndsWith('\n') ? yaml : yaml + "\n";
    }
}
