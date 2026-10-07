using ModularCA.Shared.Models.Config;
using YamlDotNet.RepresentationModel;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace ModularCA.Shared.Utils;

/// <summary>
/// Loads system configuration from a YAML file into a SystemConfig object.
/// </summary>
/// <remarks>
/// Keys renamed in 0.4.0 are read under their legacy names too, on the YAML node tree before
/// deserialising: the deserialiser ignores unmatched keys, so a legacy key read as nothing would
/// leave an integration API key unscoped. The first save of the configuration writes the new names.
/// </remarks>
public static class YamlConfigLoader
{
    /// <summary>Renamed keys: the section, the legacy key and the key that replaced it.</summary>
    private static readonly (string Section, string Legacy, string Current)[] RenamedKeys =
    [
        ("IntegrationApi", "TenantId", "SpaceId"),
        ("CertManager", "TenantId", "SpaceId"),
    ];

    /// <summary>Retired keys: the section and the key, with what the operator should know.</summary>
    private static readonly (string Section, string Key, string Note)[] RetiredKeys =
    [
        ("Features", "AllowMultipleOrganizations",
            "is retired and ignored: creating spaces is always allowed, and past four a licence is recommended. Remove the key."),
    ];

    /// <summary>
    /// Reads and deserializes a YAML configuration file at the given path, writing a warning to
    /// standard error for each legacy or retired key it finds.
    /// </summary>
    /// <exception cref="ConfigKeyConflictException">A legacy key and its replacement are both set and differ.</exception>
    public static SystemConfig Load(string path) => Load(path, Console.Error.WriteLine);

    /// <summary>
    /// Reads and deserializes a YAML configuration file at the given path, passing a warning to
    /// <paramref name="warn"/> for each legacy or retired key it finds.
    /// </summary>
    /// <exception cref="ConfigKeyConflictException">A legacy key and its replacement are both set and differ.</exception>
    public static SystemConfig Load(string path, Action<string> warn)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException($"YAML config file not found: {path}");

        var yaml = UpgradeLegacyKeys(File.ReadAllText(path), path, warn);

        var deserializer = new DeserializerBuilder()
            .WithNamingConvention(PascalCaseNamingConvention.Instance)
            .IgnoreUnmatchedProperties()
            .Build();

        return deserializer.Deserialize<SystemConfig>(yaml);
    }

    /// <summary>
    /// Returns <paramref name="yaml"/> with each legacy key moved to its new name when the new one
    /// is not set, warning about every legacy and retired key. Unchanged when there is none.
    /// </summary>
    /// <exception cref="ConfigKeyConflictException">A legacy key and its replacement are both set and differ.</exception>
    public static string UpgradeLegacyKeys(string yaml, string path, Action<string> warn)
    {
        if (!RenamedKeys.Any(k => yaml.Contains(k.Legacy, StringComparison.Ordinal))
            && !RetiredKeys.Any(k => yaml.Contains(k.Key, StringComparison.Ordinal)))
            return yaml;

        var stream = new YamlStream();
        stream.Load(new StringReader(yaml));
        if (stream.Documents.Count == 0 || stream.Documents[0].RootNode is not YamlMappingNode root)
            return yaml;

        foreach (var (section, key, note) in RetiredKeys)
        {
            if (Section(root, section) is { } mapping && mapping.Children.ContainsKey(new YamlScalarNode(key)))
                warn($"[CONFIG] WARNING: {section}.{key} in {path} {note}");
        }

        var changed = false;
        foreach (var (section, legacy, current) in RenamedKeys)
        {
            if (Section(root, section) is not { } mapping)
                continue;
            var legacyKey = new YamlScalarNode(legacy);
            if (!mapping.Children.TryGetValue(legacyKey, out var legacyValue))
                continue;

            var currentKey = new YamlScalarNode(current);
            mapping.Children.TryGetValue(currentKey, out var currentValue);
            if (IsSet(legacyValue) && IsSet(currentValue) && !SameValue(legacyValue, currentValue!))
                throw new ConfigKeyConflictException(
                    $"{path} sets both {section}.{legacy} (the name before 0.4.0) and {section}.{current}, and they differ. "
                    + $"Keep {section}.{current} with the intended value, remove {section}.{legacy}, then start again.");

            warn($"[CONFIG] WARNING: {section}.{legacy} in {path} was renamed {section}.{current} in 0.4.0. "
                + $"It is read as {section}.{current} for now; rename it in the file.");
            mapping.Children.Remove(legacyKey);
            if (!IsSet(currentValue))
                mapping.Children[currentKey] = legacyValue;
            changed = true;
        }

        if (!changed)
            return yaml;
        var writer = new StringWriter();
        stream.Save(writer, assignAnchors: false);
        return writer.ToString();
    }

    private static YamlMappingNode? Section(YamlMappingNode root, string name) =>
        root.Children.TryGetValue(new YamlScalarNode(name), out var node) ? node as YamlMappingNode : null;

    private static bool IsSet(YamlNode? node) =>
        node is YamlScalarNode { Value: { } value } && value.Trim() is { Length: > 0 } trimmed && trimmed != "~"
        && !trimmed.Equals("null", StringComparison.OrdinalIgnoreCase);

    private static bool SameValue(YamlNode a, YamlNode b)
    {
        var x = ((YamlScalarNode)a).Value!.Trim();
        var y = ((YamlScalarNode)b).Value!.Trim();
        return Guid.TryParse(x, out var gx) && Guid.TryParse(y, out var gy)
            ? gx == gy
            : string.Equals(x, y, StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>
/// A configuration file sets a legacy key and the key that replaced it to different values. The
/// process refuses to start rather than guess which the operator meant.
/// </summary>
public sealed class ConfigKeyConflictException(string message) : InvalidOperationException(message);
