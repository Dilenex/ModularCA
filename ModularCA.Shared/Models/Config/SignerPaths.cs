namespace ModularCA.Shared.Models.Config;

/// <summary>
/// Where the signer role reads its files from. Without <c>--signer-dir</c> it is the layout
/// every install has had: <c>config/config.yaml</c>, <c>config/db.yaml</c>,
/// <c>config/keystore.yaml</c>, the identity files under <c>config/</c> and logs in
/// <c>logs/</c>, all under the application directory. With <c>--signer-dir &lt;dir&gt;</c>
/// every one of them comes from that directory instead (<c>signer.yaml</c>, <c>db.yaml</c>,
/// <c>keystore.yaml</c>, the identity files, <c>logs/</c>), which on a split install belongs
/// to the signer's account so the node cannot write anything the signer reads. The keystores
/// stay in <c>keystores/</c>, which the signer's account already owns.
/// </summary>
/// <remarks>
/// The directory is named on the command line only, in the root-owned unit, never in a file:
/// a setting in <c>config.yaml</c> could be pointed back at the node's files by the node.
/// </remarks>
public sealed class SignerPaths
{
    /// <summary>The flag naming the signer's own directory; takes the path.</summary>
    public const string Flag = "--signer-dir";

    /// <summary>The signer's configuration file in its own directory.</summary>
    public const string ConfigFileName = "signer.yaml";

    /// <summary>The database credentials file, in either layout.</summary>
    public const string DbFileName = "db.yaml";

    /// <summary>The keystore passphrase file, in either layout.</summary>
    public const string KeystoreYamlFileName = "keystore.yaml";

    private const string LegacyConfigPrefix = "config/";

    private SignerPaths(string baseDirectory, string? signerDirectory)
    {
        BaseDirectory = baseDirectory;
        SignerDirectory = signerDirectory;
    }

    /// <summary>The application directory: the binaries, and <c>keystores/</c>.</summary>
    public string BaseDirectory { get; }

    /// <summary>The signer's own directory, or null for the shared layout.</summary>
    public string? SignerDirectory { get; }

    /// <summary>Whether the signer reads from its own directory.</summary>
    public bool IsDedicated => SignerDirectory != null;

    /// <summary>The configuration file: <c>&lt;dir&gt;/signer.yaml</c>, or <c>config/config.yaml</c>.</summary>
    public string ConfigPath => SignerDirectory is { } dir
        ? Path.Combine(dir, ConfigFileName)
        : Path.Combine(BaseDirectory, "config", "config.yaml");

    /// <summary>The database credentials: <c>&lt;dir&gt;/db.yaml</c>, or <c>config/db.yaml</c>.</summary>
    public string DbYamlPath => SignerDirectory is { } dir
        ? Path.Combine(dir, DbFileName)
        : Path.Combine(BaseDirectory, "config", DbFileName);

    /// <summary>The keystore passphrases: <c>&lt;dir&gt;/keystore.yaml</c>, or <c>config/keystore.yaml</c>.</summary>
    public string KeystoreYamlPath => SignerDirectory is { } dir
        ? Path.Combine(dir, KeystoreYamlFileName)
        : Path.Combine(BaseDirectory, "config", KeystoreYamlFileName);

    /// <summary>The keystore files, <c>keystores/</c> under the application directory in either layout.</summary>
    public string KeystoresDirectory => Path.Combine(BaseDirectory, "keystores");

    /// <summary>Where the file logs and the keystore audit go: <c>&lt;dir&gt;/logs</c>, or <c>logs/</c>.</summary>
    public string LogsDirectory => Path.Combine(SignerDirectory ?? BaseDirectory, "logs");

    /// <summary>
    /// Every file the signer role reads its settings and secrets from, for the startup checks and
    /// the tests. The identity files are the ones <paramref name="signer"/> names.
    /// </summary>
    public IReadOnlyList<string> SettingsFiles(SignerConfig signer)
    {
        ArgumentNullException.ThrowIfNull(signer);
        return [ConfigPath, DbYamlPath, KeystoreYamlPath, ResolveFile(signer.ServerCertificate), ResolveFile(signer.IdentityCa)];
    }

    /// <summary>
    /// Resolves a configured file path. A rooted path is used as it is. In the shared layout a
    /// relative path resolves against the application directory, as
    /// <see cref="SignerConfig.ResolvePath"/> does. In the signer's own directory it resolves
    /// against that directory, and a leading <c>config/</c> names the directory itself, so the
    /// defaults and a <c>Signer:</c> section copied from <c>config.yaml</c> find their files there.
    /// </summary>
    public string ResolveFile(string configured)
    {
        ArgumentNullException.ThrowIfNull(configured);
        if (SignerDirectory is not { } dir)
            return SignerConfig.ResolvePath(configured, BaseDirectory);
        if (Path.IsPathRooted(configured))
            return configured;
        var relative = configured.Replace('\\', '/');
        while (relative.StartsWith("./", StringComparison.Ordinal))
            relative = relative[2..];
        if (relative.StartsWith(LegacyConfigPrefix, StringComparison.OrdinalIgnoreCase))
            relative = relative[LegacyConfigPrefix.Length..];
        return Path.Combine(dir, relative);
    }

    /// <summary>The shared layout under <paramref name="baseDirectory"/>: today's paths.</summary>
    public static SignerPaths Shared(string baseDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(baseDirectory);
        return new SignerPaths(baseDirectory, null);
    }

    /// <summary>The signer's own directory, made absolute.</summary>
    public static SignerPaths Dedicated(string baseDirectory, string signerDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(baseDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(signerDirectory);
        return new SignerPaths(baseDirectory, Path.GetFullPath(signerDirectory));
    }

    /// <summary>
    /// Reads <see cref="Flag"/> from the command line: the signer's own directory when it is
    /// given, the shared layout when it is not. Throws <see cref="ArgumentException"/> for a flag
    /// with no value or given twice.
    /// </summary>
    public static SignerPaths FromArgs(IReadOnlyList<string> args, string baseDirectory)
    {
        ArgumentNullException.ThrowIfNull(args);
        string? dir = null;
        for (var i = 0; i < args.Count; i++)
        {
            if (!string.Equals(args[i], Flag, StringComparison.OrdinalIgnoreCase))
                continue;
            if (dir != null)
                throw new ArgumentException($"{Flag} is given twice.");
            if (i + 1 >= args.Count || string.IsNullOrWhiteSpace(args[i + 1]) || args[i + 1].StartsWith("--", StringComparison.Ordinal))
                throw new ArgumentException($"{Flag} needs the signer's directory, e.g. {Flag} /opt/modularca/signer.");
            dir = args[++i];
        }
        return dir == null ? Shared(baseDirectory) : Dedicated(baseDirectory, dir);
    }

    /// <summary>
    /// The layout a signer process runs with: <see cref="FromArgs"/>, except that a named
    /// directory which does not exist is the shared layout, returned in
    /// <paramref name="absentDirectory"/> for the caller to warn about. The packaged unit names
    /// <c>/opt/modularca/signer</c>, so a split install upgraded before it was migrated keeps
    /// running as it did. The node cannot create the directory: its parent belongs to root. A
    /// directory that exists is used strictly, and nothing under <c>config/</c> stands in for a
    /// file missing from it.
    /// </summary>
    public static SignerPaths ForRun(IReadOnlyList<string> args, string baseDirectory, out string? absentDirectory)
    {
        var paths = FromArgs(args, baseDirectory);
        absentDirectory = null;
        if (paths.SignerDirectory is { } dir && !Directory.Exists(dir))
        {
            absentDirectory = dir;
            return Shared(baseDirectory);
        }
        return paths;
    }

    /// <summary>Whether the command line names <see cref="Flag"/>.</summary>
    public static bool IsNamedIn(IReadOnlyList<string> args)
        => args.Any(a => string.Equals(a, Flag, StringComparison.OrdinalIgnoreCase));
}
