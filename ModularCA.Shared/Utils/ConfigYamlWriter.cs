using ModularCA.Shared.Models.Config;
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

    /// <summary>
    /// Serialises <paramref name="config"/> with <see cref="Serialize"/> and writes it to
    /// <paramref name="path"/> with <see cref="WriteKeepingAccess"/>.
    /// </summary>
    /// <param name="path">The <c>config.yaml</c> path.</param>
    /// <param name="config">The configuration to persist.</param>
    public static void Write(string path, SystemConfig config) =>
        WriteKeepingAccess(path, Serialize(config));

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
