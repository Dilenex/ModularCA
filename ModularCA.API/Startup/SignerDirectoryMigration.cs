using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace ModularCA.API.Startup;

/// <summary>
/// <c>--role signer --signer-dir &lt;dir&gt; --migrate-signer-dir</c>: moves an existing split
/// install's signer onto its own directory. Run as the signer's account, which can still read the
/// shared files: it writes <c>signer.yaml</c> with only the sections the signer reads (the
/// signer's half of <c>Signer:</c>, <c>Hsm:</c>, <c>Schema:</c> and the logging levels),
/// <c>db.yaml</c> with only the application database, and copies <c>keystore.yaml</c> and the
/// identity files, all owner-only. It changes nothing under <c>config/</c>, refuses a directory
/// that is missing or already holds any of these files, and checks everything before it writes.
/// </summary>
public static class SignerDirectoryMigration
{
    /// <summary>The flag.</summary>
    public const string Flag = "--migrate-signer-dir";

    /// <summary>Whether the command line names <see cref="Flag"/>.</summary>
    public static bool IsNamedIn(IReadOnlyList<string> args)
        => args.Any(a => string.Equals(a, Flag, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Copies what the signer reads from the shared layout <paramref name="from"/> into the
    /// signer's directory <paramref name="to"/> and returns the exit code: 0 done, 1 refused with
    /// nothing written. Identity paths are rewritten to bare file names in the new directory; one
    /// the shared layout does not have is left for <c>--init-identity</c> to create there.
    /// </summary>
    public static int Run(SignerPaths from, SignerPaths to, TextWriter output, TextWriter error)
    {
        ArgumentNullException.ThrowIfNull(from);
        ArgumentNullException.ThrowIfNull(to);
        if (from.IsDedicated || to.SignerDirectory is not { } dir)
        {
            error.WriteLine($"[FATAL] {Flag} copies from the shared layout into the directory {SignerPaths.Flag} names.");
            return 1;
        }
        if (!Directory.Exists(dir))
        {
            error.WriteLine($"[FATAL] {dir} does not exist. Create it owned by the signer's account, owner-only:");
            error.WriteLine($"        sudo install -d -o modularca-signer -g modularca-signer -m 0700 {dir}");
            return 1;
        }
        if (!File.Exists(from.ConfigPath) || !File.Exists(from.DbYamlPath))
        {
            error.WriteLine($"[FATAL] {from.ConfigPath} and {from.DbYamlPath} are both needed to migrate from; the signer's account must be able to read them.");
            return 1;
        }

        SystemConfig config;
        YamlDbConfigLoader.DbYamlConfig? db;
        try
        {
            config = YamlConfigLoader.Load(from.ConfigPath, error.WriteLine);
            db = YamlDbConfigLoader.Load(from.DbYamlPath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or YamlDotNet.Core.YamlException or InvalidOperationException)
        {
            error.WriteLine($"[FATAL] Could not read the shared configuration: {ex.Message}");
            return 1;
        }
        if (db == null)
        {
            error.WriteLine($"[FATAL] {from.DbYamlPath} is empty.");
            return 1;
        }

        var signer = config.Signer;
        var copies = new List<(string Source, string Target)>();
        var serverCertificate = PlanIdentityFile(from, dir, signer.ServerCertificate, copies);
        var identityCa = PlanIdentityFile(from, dir, signer.IdentityCa, copies);
        if (File.Exists(from.KeystoreYamlPath))
            copies.Add((from.KeystoreYamlPath, to.KeystoreYamlPath));

        var targets = copies.Select(c => c.Target).Prepend(to.DbYamlPath).Prepend(to.ConfigPath).ToList();
        var existing = targets.Where(File.Exists).ToList();
        if (existing.Count > 0)
        {
            error.WriteLine($"[FATAL] {dir} already holds {string.Join(", ", existing.Select(Path.GetFileName))}; nothing was changed.");
            error.WriteLine("        Remove them first to migrate again.");
            return 1;
        }
        foreach (var (source, _) in copies)
        {
            try
            {
                File.OpenRead(source).Dispose();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                error.WriteLine($"[FATAL] Cannot read {source}: {ex.Message}. Nothing was changed.");
                return 1;
            }
        }

        var document = new
        {
            Signer = new
            {
                signer.Listen,
                ServerCertificate = serverCertificate,
                signer.ServerCertificatePassword,
                signer.PinnedClientSpki,
                IdentityCa = identityCa,
                signer.IdentityCaPassword,
            },
            config.Hsm,
            config.Schema,
            Logging = new
            {
                config.Logging.MinLevel,
                config.Logging.RetentionDays,
                config.Logging.MaxFileSizeMb,
                config.Logging.ConsoleFormat,
            },
        };
        var yaml = "# The signer's own settings: --role signer --signer-dir reads this file and nothing under config/.\n"
            + $"# Written by {Flag} from {from.ConfigPath} on {DateTime.UtcNow:yyyy-MM-dd}. Relative paths resolve against this directory.\n"
            + new SerializerBuilder().WithNamingConvention(PascalCaseNamingConvention.Instance).Build().Serialize(document);

        ConfigYamlWriter.WriteKeepingAccess(to.ConfigPath, yaml);
        YamlDbConfigLoader.Write(to.DbYamlPath, new YamlDbConfigLoader.DbYamlConfig { App = db.App });
        foreach (var (source, target) in copies)
        {
            File.Copy(source, target);
            FileSecurityUtil.SetOwnerOnly(target);
        }

        output.WriteLine($"Signer directory {dir} written:");
        output.WriteLine($"  {to.ConfigPath}   Signer (the signer's half), Hsm, Schema, logging levels");
        output.WriteLine($"  {to.DbYamlPath}   the application database only");
        foreach (var (source, target) in copies)
            output.WriteLine($"  {target}   copied from {source}");
        if (!File.Exists(from.KeystoreYamlPath))
            output.WriteLine($"  (no {from.KeystoreYamlPath}: the secondary passphrases must come from the unit's environment)");
        output.WriteLine();
        output.WriteLine($"Review {to.ConfigPath} before the signer reads it, Hsm.ModulePath above all: it was copied from a file the node can write.");
        output.WriteLine("Then, as README-DEPLOY.md, \"Two units\", describes: point the unit at the directory, restart the signer,");
        output.WriteLine("and remove the signer's files from config/ (keystore.yaml, signer-server.pfx, signer-identity-ca.pfx).");
        return 0;
    }

    /// <summary>
    /// Plans the copy of one identity file and returns the path <c>signer.yaml</c> names it by: the
    /// bare file name in the signer's directory. A file the shared layout does not have is not
    /// copied, and is named the same way for <c>--init-identity</c> to create there.
    /// </summary>
    private static string PlanIdentityFile(SignerPaths from, string dir, string configured, List<(string Source, string Target)> copies)
    {
        var source = from.ResolveFile(configured);
        var name = Path.GetFileName(source);
        if (File.Exists(source))
            copies.Add((source, Path.Combine(dir, name)));
        return name;
    }
}
