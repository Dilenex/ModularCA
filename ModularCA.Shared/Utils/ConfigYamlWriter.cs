using ModularCA.Shared.Models.Config;
using YamlDotNet.RepresentationModel;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace ModularCA.Shared.Utils;

/// <summary>
/// The one way the running node writes <c>config/config.yaml</c>: every settings page, the Web
/// TLS provisioning and the backup encryption switch persist through here.
/// </summary>
/// <remarks>
/// <para>
/// The <c>DB</c> section is never written. The running configuration carries the database
/// credentials overlaid from <c>db.yaml</c> (or, in setup mode, the superuser credentials from
/// <c>setup-database.yaml</c>); serialising them would copy those passwords into
/// <c>config.yaml</c>, and from there into every backup archive, which keeps <c>db.yaml</c> out
/// on purpose. <c>db.yaml</c> is their only home.
/// </para>
/// <para>
/// An existing file is rewritten in place, so it keeps its owner, group and mode. On a split
/// install <c>config.yaml</c> is <c>0640</c> with the signer's group; a temporary file renamed
/// over it would come out owned by the node's own group, and the node cannot give it the
/// signer's group back, so the signer could no longer read its settings.
/// </para>
/// </remarks>
public static class ConfigYamlWriter
{
    /// <summary>The top-level key the serialised configuration leaves out.</summary>
    public const string DbSection = "DB";

    /// <summary>
    /// Serialises the configuration as <c>config.yaml</c> holds it: Pascal-case keys, without
    /// the <c>DB</c> section.
    /// </summary>
    /// <param name="config">The configuration to serialise.</param>
    /// <returns>The YAML text.</returns>
    public static string Serialize(SystemConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        var serializer = new SerializerBuilder()
            .WithNamingConvention(PascalCaseNamingConvention.Instance)
            .WithAttributeOverride<SystemConfig>(c => c.DB, new YamlIgnoreAttribute())
            .Build();
        return serializer.Serialize(config);
    }

    /// <summary>The first lines of a <c>config.yaml</c> that no longer holds the instance's settings.</summary>
    public const string HostOnlyHeader =
        "# This file holds this host's settings: listeners, files, paths and network position. The\n"
        + "# instance's other settings, and its secrets, are in the database. Change them in the\n"
        + "# console under Settings; a value for one of them written here is ignored.\n";

    /// <summary>
    /// Serialises the configuration as <see cref="Serialize(SystemConfig)"/> does, leaving out
    /// the settings named by <paramref name="withoutPaths"/> (dotted, as <c>Acme.Http01.MaxAddresses</c>)
    /// and any section that is left with nothing in it, under <see cref="HostOnlyHeader"/>. This
    /// is the file once the settings store holds those settings: what stays is what belongs to
    /// the host. Only settings are written: a value the configuration computes from others, which
    /// the plain serialisation also emits, is not one and is left out.
    /// </summary>
    /// <param name="config">The configuration to serialise.</param>
    /// <param name="withoutPaths">The settings that are kept elsewhere.</param>
    public static string Serialize(SystemConfig config, IEnumerable<string> withoutPaths)
    {
        ArgumentNullException.ThrowIfNull(withoutPaths);
        var stream = new YamlStream();
        using (var reader = new StringReader(Serialize(config)))
            stream.Load(reader);
        if (stream.Documents.Count == 0 || stream.Documents[0].RootNode is not YamlMappingNode root)
            return HostOnlyHeader;

        var kept = Settings.SettingsCatalog.Definitions.Select(d => d.Path).ToHashSet(StringComparer.Ordinal);
        kept.ExceptWith(withoutPaths);
        KeepOnly(root, string.Empty, kept);

        using var writer = new StringWriter();
        new YamlStream(new YamlDocument(root)).Save(writer, assignAnchors: false);
        // Save closes the document with "...", which a file holding one document does not need.
        var body = writer.ToString().TrimEnd();
        if (body.EndsWith("...", StringComparison.Ordinal))
            body = body[..^3].TrimEnd();
        return HostOnlyHeader + (root.Children.Count == 0 ? string.Empty : body + "\n");
    }

    /// <summary>
    /// <paramref name="yaml"/> without the settings named by <paramref name="paths"/> (dotted),
    /// and without a section they leave empty. For a copy of a configuration file that must not
    /// carry what has just been moved somewhere safer. Comments are not kept.
    /// </summary>
    public static string WithoutPaths(string yaml, IEnumerable<string> paths)
    {
        var stream = new YamlStream();
        using (var reader = new StringReader(yaml))
            stream.Load(reader);
        if (stream.Documents.Count == 0 || stream.Documents[0].RootNode is not YamlMappingNode root)
            return yaml;
        foreach (var path in paths)
            Remove(root, path.Split('.'), 0);

        using var writer = new StringWriter();
        new YamlStream(new YamlDocument(root)).Save(writer, assignAnchors: false);
        var body = writer.ToString().TrimEnd();
        if (body.EndsWith("...", StringComparison.Ordinal))
            body = body[..^3].TrimEnd();
        return root.Children.Count == 0 ? string.Empty : body + "\n";
    }

    /// <summary>Removes the node at <paramref name="segments"/> and each section the removal empties. True when <paramref name="node"/> is left empty.</summary>
    private static bool Remove(YamlMappingNode node, string[] segments, int index)
    {
        var key = new YamlScalarNode(segments[index]);
        if (node.Children.TryGetValue(key, out var child)
            && (index == segments.Length - 1 || (child is YamlMappingNode section && Remove(section, segments, index + 1))))
            node.Children.Remove(key);
        return node.Children.Count == 0;
    }

    /// <summary>
    /// Removes from <paramref name="node"/> everything that is not one of the settings in
    /// <paramref name="kept"/> or a section leading to one, and each section that is left empty.
    /// A setting is kept whole: what is inside a list or a dictionary is its value.
    /// </summary>
    private static void KeepOnly(YamlMappingNode node, string prefix, HashSet<string> kept)
    {
        foreach (var (key, child) in node.Children.ToList())
        {
            var path = prefix + ((YamlScalarNode)key).Value;
            if (kept.Contains(path))
                continue;
            if (child is YamlMappingNode section && kept.Any(k => k.StartsWith(path + ".", StringComparison.Ordinal)))
            {
                KeepOnly(section, path + ".", kept);
                if (section.Children.Count > 0)
                    continue;
            }
            node.Children.Remove(key);
        }
    }

    /// <summary>
    /// Serialises <paramref name="config"/> with <see cref="Serialize(SystemConfig)"/> and writes it to
    /// <paramref name="path"/> with <see cref="WriteKeepingAccess"/>.
    /// </summary>
    /// <param name="path">The <c>config.yaml</c> path.</param>
    /// <param name="config">The configuration to persist.</param>
    public static void Write(string path, SystemConfig config) =>
        WriteKeepingAccess(path, Serialize(config));

    /// <summary>
    /// Writes <paramref name="config"/> without the settings named by <paramref name="withoutPaths"/>;
    /// see <see cref="Serialize(SystemConfig, IEnumerable{string})"/>.
    /// </summary>
    public static void Write(string path, SystemConfig config, IEnumerable<string> withoutPaths) =>
        WriteKeepingAccess(path, Serialize(config, withoutPaths));

    /// <summary>
    /// Writes <paramref name="contents"/> to <paramref name="path"/>. An existing file is
    /// truncated and rewritten in place, keeping its owner, group, mode and (on Windows) ACL; a
    /// file that does not exist yet is created owner-only.
    /// </summary>
    /// <param name="path">The file to write.</param>
    /// <param name="contents">The new contents.</param>
    public static void WriteKeepingAccess(string path, string contents)
    {
        ArgumentNullException.ThrowIfNull(contents);
        if (File.Exists(path))
        {
            File.WriteAllText(path, contents);
            return;
        }

        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
        if (!OperatingSystem.IsWindows())
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        using (var stream = new FileStream(path, options))
        using (var writer = new StreamWriter(stream))
            writer.Write(contents);
        FileSecurityUtil.SetOwnerOnly(path);
    }

    /// <summary>
    /// Returns <paramref name="yaml"/> without its top-level <c>DB</c> section, or unchanged when
    /// it has none. Used where a <c>config.yaml</c> written before 0.4.0, which may carry the
    /// database passwords, is copied: into a backup archive, and back out of one on restore.
    /// </summary>
    /// <param name="yaml">The file contents.</param>
    /// <returns>The contents without the section.</returns>
    public static string WithoutDbSection(string yaml) =>
        YamlSectionSplicer.Remove(yaml, DbSection);
}
