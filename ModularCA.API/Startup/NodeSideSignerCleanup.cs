using System.Security.Cryptography;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using ModularCA.Signer.Identity;
using YamlDotNet.RepresentationModel;

namespace ModularCA.API.Startup;

/// <summary>
/// Takes the signer's files and settings out of the node's config directory once the signer has
/// its own directory and holds a verified copy of each. Run by <c>--role signer --signer-dir
/// &lt;dir&gt; --issue-node-identity --apply &lt;config.yaml&gt;</c> after the pins are in place,
/// which is the pod's <c>node-identity</c> init container, the one container that mounts both the
/// node's config volume and the signer's, read-write.
/// <para>
/// What it removes, each only after checking the signer's copy: <c>keystore.yaml</c>, when the
/// signer's directory holds one that is byte-identical or carries the same passphrases; and, when
/// the signer's identity in its own directory is whole and is the one both pins were verified
/// against, the identity CA and the server certificate under the node's config directory, the
/// signer's half of <c>Signer:</c> in the node's <c>config.yaml</c> (<see cref="SignerHalf"/>),
/// <c>Hsm:</c> there when <c>signer.yaml</c> has an <c>Hsm:</c> section of its own, and the same
/// keys in the copies of <c>config.yaml</c> kept beside it (<c>config.yaml.*.bak</c>), which are
/// scrubbed rather than deleted (<see cref="Redact"/>). The node with a remote signer reads none
/// of them: it never unlocks a keystore, loads an HSM or listens as the signer, and it reads the
/// node's half of <c>Signer:</c> only.
/// </para>
/// <para>
/// A check that fails leaves the node's copy where it is and says why on standard error; nothing
/// here changes the command's exit code, so the pod still starts. A second run finds nothing to
/// remove and prints nothing. A section the node itself writes back with the default values (it
/// serialises every setting when it saves its settings) carries nothing of the signer's and is
/// left alone, so that is not "something to remove" either.
/// </para>
/// </summary>
public static class NodeSideSignerCleanup
{
    /// <summary>
    /// The keys of <c>Signer:</c> that only the signer role reads: where it listens, its server
    /// certificate, the node's pin, and the identity CA (read by the identity commands alone).
    /// </summary>
    public static readonly IReadOnlyList<string> SignerHalf =
        ["Listen", "ServerCertificate", "ServerCertificatePassword", "PinnedClientSpki", "IdentityCa", "IdentityCaPassword"];

    /// <summary>What <see cref="Redact"/> does with <c>Hsm:</c>.</summary>
    public enum HsmRedaction
    {
        /// <summary>Leaves <c>Hsm:</c> as it is.</summary>
        None,

        /// <summary>Removes <c>Hsm.Pin</c> only: for a copy of a file whose <c>Hsm:</c> the signer has no section of its own for.</summary>
        Pin,

        /// <summary>Removes the whole <c>Hsm:</c> section: the signer's <c>signer.yaml</c> has its own.</summary>
        Section,
    }

    /// <summary>
    /// Removes from the node's config directory what the signer's directory holds a verified copy
    /// of, and reports on <paramref name="output"/> what was removed and on
    /// <paramref name="error"/> what was left and why. Never throws for a file it cannot read or
    /// write: that is reported and left. Does nothing in the shared layout.
    /// </summary>
    /// <param name="nodeConfigPath">The node's <c>config.yaml</c>, as <c>--apply</c> names it.</param>
    /// <param name="paths">The signer's layout; only a dedicated directory has anything to clean up after.</param>
    /// <param name="output">Where what was removed is reported.</param>
    /// <param name="error">Where what was left, and why, is reported.</param>
    public static void Run(string nodeConfigPath, SignerPaths paths, TextWriter output, TextWriter error)
    {
        ArgumentNullException.ThrowIfNull(nodeConfigPath);
        ArgumentNullException.ThrowIfNull(paths);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);
        if (!paths.IsDedicated)
            return;
        try
        {
            Clean(Path.GetFullPath(nodeConfigPath), paths, output, error);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or YamlDotNet.Core.YamlException
            or InvalidOperationException or CryptographicException or ArgumentException)
        {
            error.WriteLine($"[WARNING] The signer's files in the node's config directory were not cleaned up: {ex.GetType().Name}.");
        }
    }

    /// <summary>
    /// The contents for a new copy of the node's <c>config.yaml</c> kept beside it, as
    /// <c>--apply</c> and this clean-up write them: <paramref name="original"/> with the signer's
    /// keys removed as <see cref="Redact"/> removes them, everything else as it was; or, when that
    /// cannot be shown to leave the rest of the configuration unchanged, the file reserialised
    /// without those keys. Either way the copy holds none of the signer's secrets.
    /// </summary>
    /// <param name="original">The node's <c>config.yaml</c> as it was.</param>
    /// <param name="signerConfigPath">The signer's <c>signer.yaml</c>; whether it has an <c>Hsm:</c> section decides what happens to the node's.</param>
    public static string BackupContents(string original, string signerConfigPath)
    {
        ArgumentNullException.ThrowIfNull(original);
        var hsm = SignerHasHsm(signerConfigPath) ? HsmRedaction.Section : HsmRedaction.Pin;
        try
        {
            if (Scrub(original, hsm) is { } scrubbed)
                return scrubbed;
        }
        catch (Exception ex) when (ex is YamlDotNet.Core.YamlException or InvalidOperationException)
        {
            // Falls through to the reserialised copy below.
        }
        var paths = SignerHalf.Select(k => "Signer." + k).Append(hsm == HsmRedaction.Section ? "Hsm" : "Hsm.Pin");
        return ConfigYamlWriter.WithoutPaths(original, paths);
    }

    /// <summary>The work of <see cref="Run"/>, for a node config path already made absolute.</summary>
    private static void Clean(string nodeConfigPath, SignerPaths paths, TextWriter output, TextWriter error)
    {
        var nodeDir = Path.GetDirectoryName(nodeConfigPath)!;
        var node = YamlConfigLoader.Load(nodeConfigPath, _ => { });
        var signer = YamlConfigLoader.Load(paths.ConfigPath, _ => { });
        var signerHasHsm = SignerHasHsm(paths.ConfigPath);
        var removed = new List<string>();

        // keystore.yaml: the passphrases, which the node with a remote signer never reads.
        var nodeKeystore = Path.Combine(nodeDir, SignerPaths.KeystoreYamlFileName);
        var keystoreRemoved = false;
        if (File.Exists(nodeKeystore) && !SamePath(nodeKeystore, paths.KeystoreYamlPath))
        {
            var problem = KeystoreCopyProblem(nodeKeystore, paths.KeystoreYamlPath);
            if (problem != null)
            {
                error.WriteLine($"[WARNING] {nodeKeystore} was left in place: {problem}.");
                error.WriteLine($"          Compare it with {paths.KeystoreYamlPath} and delete the node's copy by hand once the signer's is right.");
            }
            else
            {
                File.Delete(nodeKeystore);
                removed.Add($"{nodeKeystore} (the signer's copy at {paths.KeystoreYamlPath} holds the same passphrases)");
                keystoreRemoved = true;
            }
        }

        // The identity files, the signer's settings in config.yaml and in the copies beside it,
        // all on the same evidence.
        var shared = SignerPaths.Shared(paths.BaseDirectory);
        var nodeFiles = new[] { node.Signer.ServerCertificate, node.Signer.IdentityCa }
            .Select(shared.ResolveFile)
            .Select(Path.GetFullPath)
            .Distinct(PathComparer)
            .Where(File.Exists)
            .ToList();
        var outside = nodeFiles.Where(f => !IsInside(f, nodeDir) || IsInside(f, paths.SignerDirectory!)).ToList();
        nodeFiles.RemoveAll(outside.Contains);
        var signerHalfSet = SignerHalfIsSet(node.Signer);
        var hsmSet = !SameYaml("Hsm", node.Hsm, new HsmConfig());
        var backupHsm = signerHasHsm ? HsmRedaction.Section : HsmRedaction.Pin;
        var (backups, unreadable) = BackupsToScrub(nodeConfigPath, backupHsm);
        foreach (var file in unreadable)
            error.WriteLine($"[WARNING] {file} was left as it is: it could not be read as a configuration file, so the signer's settings in it, if any, were not removed. Check it, and delete it if it is not needed.");

        if (nodeFiles.Count > 0 || signerHalfSet || hsmSet || backups.Count > 0)
        {
            var problem = IdentityProblem(node.Signer, signer.Signer, paths);
            if (problem != null)
            {
                var what = string.Join(", ", nodeFiles.Select(Path.GetFileName)
                    .Concat(signerHalfSet ? ["the signer's half of Signer: in config.yaml"] : [])
                    .Concat(hsmSet ? ["Hsm: in config.yaml"] : [])
                    .Concat(backups.Count > 0 ? ["the signer's settings in " + string.Join(", ", backups.Select(Path.GetFileName))] : []));
                error.WriteLine($"[WARNING] Left in the node's config directory: {what}.");
                error.WriteLine($"          They are removed once the signer's identity in {paths.SignerDirectory} checks out, and it does not: {problem}");
            }
            else
            {
                var filesLeft = false;
                foreach (var file in nodeFiles)
                {
                    try
                    {
                        File.Delete(file);
                        removed.Add($"{file} (the signer's own copy is in {paths.SignerDirectory})");
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                    {
                        error.WriteLine($"[WARNING] {file} could not be removed: {ex.Message}");
                        filesLeft = true;
                    }
                }
                foreach (var file in outside)
                    output.WriteLine($"  (i) {file} is outside {nodeDir} and was not removed; the node does not read it.");

                var removeHsm = hsmSet && signerHasHsm;
                if (hsmSet && !removeHsm)
                    error.WriteLine($"[WARNING] Hsm: was left in {nodeConfigPath}: {paths.ConfigPath} has no Hsm: section, so the signer would lose it. Move it there.");
                if (filesLeft && signerHalfSet)
                {
                    // The paths in the signer's half are how the files left behind are found again.
                    error.WriteLine($"[WARNING] The signer's half of Signer: was left in {nodeConfigPath}, since it names the files that could not be removed.");
                    signerHalfSet = false;
                }
                if (signerHalfSet || removeHsm)
                {
                    var parts = new List<string>();
                    if (signerHalfSet)
                        parts.Add($"the signer's half of Signer: ({string.Join(", ", SignerHalf)})");
                    if (removeHsm)
                        parts.Add("Hsm:");
                    var outcome = RewriteConfig(nodeConfigPath, paths.ConfigPath, removeHsm ? HsmRedaction.Section : HsmRedaction.None);
                    if (outcome.Problem != null)
                        error.WriteLine($"[WARNING] {nodeConfigPath} was left as it was, with {string.Join(" and ", parts)}: {outcome.Problem}");
                    else
                        removed.Add($"{string.Join(" and ", parts)} from {nodeConfigPath} (previous copy, without them, at {outcome.Backup})");
                }

                foreach (var backup in backups)
                {
                    var problemWith = ScrubBackup(backup, backupHsm);
                    if (problemWith != null)
                        error.WriteLine($"[WARNING] {backup} was left as it is: {problemWith}");
                    else
                        removed.Add($"the signer's settings from the copy {backup}, which is otherwise as it was");
                }
            }
        }

        if (removed.Count == 0)
            return;
        output.WriteLine("Removed from the node's config directory what the node with a remote signer never reads,");
        output.WriteLine("each after checking the signer's own copy:");
        foreach (var line in removed)
            output.WriteLine($"  {line}");
        if (keystoreRemoved)
            output.WriteLine($"The keystore passphrases are now only in {paths.KeystoreYamlPath}: keep the signer's directory in your backups.");
    }

    /// <summary>
    /// The copies of the node's <c>config.yaml</c> directly in its directory
    /// (<c>config.yaml.*.bak</c>: <c>.pre-signer-*</c>, <c>.pre-signer-cleanup-*</c>,
    /// <c>.pre-settings-*</c>, <c>.mariadb-*</c>) that still carry something of the signer's: a
    /// key of <see cref="SignerHalf"/> other than its default, or what <paramref name="hsm"/>
    /// removes. Copies that cannot be read as a configuration are returned apart.
    /// </summary>
    private static (List<string> Scrub, List<string> Unreadable) BackupsToScrub(string nodeConfigPath, HsmRedaction hsm)
    {
        var scrub = new List<string>();
        var unreadable = new List<string>();
        var dir = Path.GetDirectoryName(nodeConfigPath)!;
        foreach (var file in Directory.EnumerateFiles(dir, Path.GetFileName(nodeConfigPath) + ".*.bak", SearchOption.TopDirectoryOnly).Order(StringComparer.Ordinal))
        {
            try
            {
                var config = YamlConfigLoader.FromText(File.ReadAllText(file), file, _ => { });
                if (config == null)
                    continue;
                var hsmCarried = hsm == HsmRedaction.Section
                    ? !SameYaml("Hsm", config.Hsm, new HsmConfig())
                    : !string.IsNullOrEmpty(config.Hsm?.Pin);
                if ((config.Signer != null && SignerHalfIsSet(config.Signer)) || hsmCarried)
                    scrub.Add(file);
            }
            catch (Exception ex) when (ex is YamlDotNet.Core.YamlException or InvalidOperationException)
            {
                unreadable.Add(file);
            }
        }
        return (scrub, unreadable);
    }

    /// <summary>
    /// Removes the signer's keys from one copy of <c>config.yaml</c> (<see cref="Scrub"/>) and
    /// writes it back owner-only. Returns why it could not, or null. The copy is never deleted:
    /// it is the operator's way back to an earlier configuration.
    /// </summary>
    private static string? ScrubBackup(string path, HsmRedaction hsm)
    {
        try
        {
            var original = File.ReadAllText(path);
            if (Scrub(original, hsm) is not { } scrubbed)
                return "the signer's settings in it could not be removed while keeping the rest of it as it was (a Signer: or Hsm: section written in flow style?).";
            ConfigYamlWriter.WriteKeepingAccess(path, scrubbed);
            FileSecurityUtil.SetOwnerOnly(path);
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or YamlDotNet.Core.YamlException or InvalidOperationException)
        {
            return $"it could not be rewritten ({ex.GetType().Name}).";
        }
    }

    /// <summary>
    /// <see cref="Redact"/>, checked: <paramref name="yaml"/> with the signer's keys removed, or
    /// null when the result does not deserialise to the same configuration with only those keys at
    /// their defaults. Throws when <paramref name="yaml"/> itself cannot be read.
    /// </summary>
    private static string? Scrub(string yaml, HsmRedaction hsm)
    {
        var expected = YamlConfigLoader.FromText(yaml, "config", _ => { }) ?? new SystemConfig();
        expected.Signer ??= new SignerConfig();
        expected.Hsm ??= new HsmConfig();
        var defaults = new SignerConfig();
        expected.Signer.Listen = defaults.Listen;
        expected.Signer.ServerCertificate = defaults.ServerCertificate;
        expected.Signer.ServerCertificatePassword = defaults.ServerCertificatePassword;
        expected.Signer.PinnedClientSpki = defaults.PinnedClientSpki;
        expected.Signer.IdentityCa = defaults.IdentityCa;
        expected.Signer.IdentityCaPassword = defaults.IdentityCaPassword;
        if (hsm == HsmRedaction.Section)
            expected.Hsm = new HsmConfig();
        else if (hsm == HsmRedaction.Pin)
            expected.Hsm.Pin = string.Empty;

        var redacted = Redact(yaml, hsm);
        SystemConfig? actual;
        try
        {
            actual = YamlConfigLoader.FromText(redacted, "config", _ => { });
        }
        catch (Exception ex) when (ex is YamlDotNet.Core.YamlException or InvalidOperationException)
        {
            return null;
        }
        if (actual == null)
            return null;
        actual.Signer ??= new SignerConfig();
        actual.Hsm ??= new HsmConfig();
        return string.Equals(ConfigYamlWriter.Serialize(actual), ConfigYamlWriter.Serialize(expected), StringComparison.Ordinal)
            ? redacted
            : null;
    }

    /// <summary>
    /// The one redaction of the signer's settings from the node's configuration files, used for
    /// <c>config.yaml</c>, for the copies beside it this clean-up scrubs, and for the copies
    /// <c>--apply</c> and this clean-up write. Removes the lines of the <see cref="SignerHalf"/>
    /// keys from the top-level <c>Signer:</c> block, and the <c>Hsm:</c> block or its <c>Pin</c>
    /// line as <paramref name="hsm"/> says, and leaves every other line byte for byte, line endings
    /// included. A block left with no keys goes with them. It works on lines, not on the parsed
    /// document, so comments and formatting survive; <see cref="Scrub"/> checks the result.
    /// </summary>
    internal static string Redact(string yaml, HsmRedaction hsm)
    {
        ArgumentNullException.ThrowIfNull(yaml);
        var lines = yaml.Split('\n').ToList();
        RemoveKeys(lines, "Signer", SignerHalf);
        if (hsm == HsmRedaction.Section)
            RemoveBlock(lines, "Hsm");
        else if (hsm == HsmRedaction.Pin)
            RemoveKeys(lines, "Hsm", ["Pin"]);
        return string.Join('\n', lines);
    }

    /// <summary>
    /// The lines of a top-level block: from the line that starts with <c>section:</c> at column
    /// zero to the next non-blank line at column zero, as <see cref="YamlSectionSplicer"/> reads
    /// it, less the blank lines at its end. (-1, -1) when there is none.
    /// </summary>
    private static (int Start, int End) FindBlock(List<string> lines, string section)
    {
        var start = lines.FindIndex(l => l.StartsWith(section + ":", StringComparison.Ordinal));
        if (start < 0)
            return (-1, -1);
        var end = start + 1;
        while (end < lines.Count && (lines[end].Length == 0 || char.IsWhiteSpace(lines[end][0])))
            end++;
        while (end - 1 > start && string.IsNullOrWhiteSpace(lines[end - 1]))
            end--;
        return (start, end);
    }

    /// <summary>Removes a top-level block, keeping the blank lines after it.</summary>
    private static void RemoveBlock(List<string> lines, string section)
    {
        var (start, end) = FindBlock(lines, section);
        if (start >= 0)
            lines.RemoveRange(start, end - start);
    }

    /// <summary>
    /// Removes from a top-level block each child line whose key is one of <paramref name="keys"/>,
    /// with the more deeply indented lines that continue its value, and the whole block when no
    /// key is left in it.
    /// </summary>
    private static void RemoveKeys(List<string> lines, string section, IReadOnlyCollection<string> keys)
    {
        var (start, end) = FindBlock(lines, section);
        if (start < 0)
            return;
        int? indent = null;
        for (var i = start + 1; i < end; i++)
        {
            if (!IsBlankOrComment(lines[i]))
            {
                indent = Indent(lines[i]);
                break;
            }
        }
        if (indent is not { } child)
            return;

        for (var i = start + 1; i < end;)
        {
            if (!IsBlankOrComment(lines[i]) && Indent(lines[i]) == child && KeyOf(lines[i]) is { } key && keys.Contains(key))
            {
                var next = i + 1;
                while (next < end && !string.IsNullOrWhiteSpace(lines[next]) && Indent(lines[next]) > child)
                    next++;
                lines.RemoveRange(i, next - i);
                end -= next - i;
                continue;
            }
            i++;
        }

        if (!lines.Skip(start + 1).Take(end - start - 1).Any(l => !IsBlankOrComment(l)))
            lines.RemoveRange(start, end - start);
    }

    /// <summary>Whether a line holds nothing, or only a comment.</summary>
    private static bool IsBlankOrComment(string line)
        => string.IsNullOrWhiteSpace(line) || line.TrimStart().StartsWith('#');

    /// <summary>The number of spaces a line starts with.</summary>
    private static int Indent(string line)
    {
        var n = 0;
        while (n < line.Length && line[n] == ' ')
            n++;
        return n;
    }

    /// <summary>The mapping key a line starts, without quotes, or null when it starts none.</summary>
    private static string? KeyOf(string line)
    {
        var text = line.Trim();
        var colon = text.IndexOf(':');
        if (colon <= 0 || text.StartsWith('-'))
            return null;
        return text[..colon].Trim().Trim('"', '\'');
    }

    /// <summary>
    /// Why the node's <c>keystore.yaml</c> may not be removed, or null when the signer's directory
    /// holds a good copy: one that exists and is byte-identical, or parses to the same keystore
    /// names with the same passphrases. Never names a passphrase.
    /// </summary>
    private static string? KeystoreCopyProblem(string nodeKeystore, string signerKeystore)
    {
        if (!File.Exists(signerKeystore))
            return $"{signerKeystore} does not exist, and the signer would have no passphrases";
        var nodeBytes = File.ReadAllBytes(nodeKeystore);
        var signerBytes = File.ReadAllBytes(signerKeystore);
        if (nodeBytes.AsSpan().SequenceEqual(signerBytes))
            return null;

        var nodeEntries = Passphrases(nodeKeystore);
        var signerEntries = Passphrases(signerKeystore);
        if (nodeEntries == null || signerEntries == null)
            return $"it differs from {signerKeystore}, and {(nodeEntries == null ? nodeKeystore : signerKeystore)} could not be read as keystore passphrases";
        if (nodeEntries.Count == 0
            || nodeEntries.Count != signerEntries.Count
            || nodeEntries.Any(e => !signerEntries.TryGetValue(e.Key, out var value) || !string.Equals(value, e.Value, StringComparison.Ordinal)))
            return $"{signerKeystore} does not hold the same passphrases";
        return null;
    }

    /// <summary>The keystore names and passphrases a <c>keystore.yaml</c> holds, or null when it is not a mapping of names to values.</summary>
    private static Dictionary<string, string>? Passphrases(string path)
    {
        try
        {
            var stream = new YamlStream();
            using (var reader = new StreamReader(path))
                stream.Load(reader);
            if (stream.Documents.Count == 0 || stream.Documents[0].RootNode is not YamlMappingNode root)
                return null;
            var entries = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var (key, value) in root.Children)
            {
                if (key is not YamlScalarNode { Value: { } name } || value is not YamlScalarNode { Value: { } passphrase })
                    return null;
                entries[name] = passphrase;
            }
            return entries;
        }
        catch (YamlDotNet.Core.YamlException)
        {
            return null;
        }
    }

    /// <summary>
    /// Why the signer's identity in its own directory does not stand in for the node's copies, or
    /// null when it does: the node names a remote signer; the identity CA and the server
    /// certificate there open and belong together (<see cref="SignerIdentityCommands.CheckExisting"/>);
    /// the node pins that server certificate; and the node's client certificate opens, was issued
    /// by that identity CA, and is the one <c>signer.yaml</c> pins.
    /// </summary>
    private static string? IdentityProblem(SignerConfig node, SignerConfig signer, SignerPaths paths)
    {
        if (!node.IsRemote)
            return "the node's config.yaml does not name a remote signer.";
        var caPath = paths.ResolveFile(signer.IdentityCa);
        var serverPath = paths.ResolveFile(signer.ServerCertificate);
        var problem = SignerIdentityCommands.CheckExisting(caPath, serverPath, signer, null, out _);
        if (problem != null)
            return problem;
        try
        {
            using var ca = Pkcs12Files.Load(caPath, signer.IdentityCaPassword);
            using var server = Pkcs12Files.Load(serverPath, signer.ServerCertificatePassword);
            if (!SpkiPin.Matches(server, node.PinnedServerSpki))
                return $"the node's PinnedServerSpki is not the public key of {serverPath}.";
            var clientPath = SignerConfig.ResolvePath(node.ClientCertificate, paths.BaseDirectory);
            using var client = Pkcs12Files.Load(clientPath, node.ClientCertificatePassword);
            if (!SpkiPin.Matches(client, signer.PinnedClientSpki))
                return $"the PinnedClientSpki in {paths.ConfigPath} is not the public key of {clientPath}.";
            if (!SignerIdentityCommands.IssuedBy(client, ca))
                return $"{clientPath} was not issued by the identity CA at {caPath}.";
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException)
        {
            return ex.Message;
        }
    }

    /// <summary>Whether any key of the signer's half holds something other than its default.</summary>
    private static bool SignerHalfIsSet(SignerConfig node)
    {
        var defaults = new SignerConfig();
        return !string.Equals(node.Listen, defaults.Listen, StringComparison.Ordinal)
            || !string.Equals(node.ServerCertificate, defaults.ServerCertificate, StringComparison.Ordinal)
            || !string.Equals(node.ServerCertificatePassword, defaults.ServerCertificatePassword, StringComparison.Ordinal)
            || !string.Equals(node.PinnedClientSpki, defaults.PinnedClientSpki, StringComparison.Ordinal)
            || !string.Equals(node.IdentityCa, defaults.IdentityCa, StringComparison.Ordinal)
            || !string.Equals(node.IdentityCaPassword, defaults.IdentityCaPassword, StringComparison.Ordinal);
    }

    /// <summary>
    /// Rewrites the node's <c>config.yaml</c> without the signer's half of <c>Signer:</c> and,
    /// with <see cref="HsmRedaction.Section"/>, without <c>Hsm:</c>, every other line as it was
    /// (<see cref="Scrub"/>). A copy of the file as it was is written beside it first, owner-only,
    /// itself without the signer's keys (<see cref="BackupContents"/>). The result is loaded back
    /// and must be what <see cref="Scrub"/> checked; otherwise the file is put back and the reason
    /// returned.
    /// </summary>
    private static (string? Backup, string? Problem) RewriteConfig(string path, string signerConfigPath, HsmRedaction hsm)
    {
        var original = File.ReadAllText(path);
        if (Scrub(original, hsm) is not { } text)
            return (null, "the signer's settings could not be removed while keeping the rest of the file as it was (a Signer: or Hsm: section written in flow style?)");

        var stamp = $"{DateTime.UtcNow:yyyyMMdd-HHmmss}";
        var backup = $"{path}.pre-signer-cleanup-{stamp}.bak";
        for (var n = 2; File.Exists(backup); n++)
            backup = $"{path}.pre-signer-cleanup-{stamp}-{n}.bak";
        ConfigYamlWriter.WriteKeepingAccess(backup, BackupContents(original, signerConfigPath));

        string? failure;
        try
        {
            ConfigYamlWriter.WriteKeepingAccess(path, text);
            var reloaded = YamlConfigLoader.Load(path, _ => { });
            var expected = YamlConfigLoader.FromText(text, path, _ => { });
            failure = string.Equals(ConfigYamlWriter.Serialize(reloaded), ConfigYamlWriter.Serialize(expected), StringComparison.Ordinal)
                ? null
                : "it did not load back as written";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or YamlDotNet.Core.YamlException or InvalidOperationException)
        {
            failure = ex.GetType().Name;
        }
        if (failure != null)
        {
            ConfigYamlWriter.WriteKeepingAccess(path, original);
            return (null, failure);
        }
        return (backup, null);
    }

    /// <summary>Whether the signer's <c>signer.yaml</c> has an <c>Hsm:</c> section at its top level; false when it cannot be read.</summary>
    private static bool SignerHasHsm(string signerConfigPath)
    {
        try
        {
            var stream = new YamlStream();
            using (var reader = new StreamReader(signerConfigPath))
                stream.Load(reader);
            return stream.Documents.Count > 0
                && stream.Documents[0].RootNode is YamlMappingNode root
                && root.Children.ContainsKey(new YamlScalarNode("Hsm"));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or YamlDotNet.Core.YamlException)
        {
            return false;
        }
    }

    /// <summary>Whether two values serialise to the same YAML under the same section name.</summary>
    private static bool SameYaml(string section, object a, object b)
        => string.Equals(YamlSectionSplicer.Render(section, a), YamlSectionSplicer.Render(section, b), StringComparison.Ordinal);

    /// <summary>File paths compare as the file system does: without case on Windows.</summary>
    private static StringComparer PathComparer => OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;

    /// <summary>Whether two paths name the same file.</summary>
    private static bool SamePath(string a, string b) => PathComparer.Equals(Path.GetFullPath(a), Path.GetFullPath(b));

    /// <summary>Whether <paramref name="path"/> lies inside <paramref name="directory"/>, at any depth.</summary>
    private static bool IsInside(string path, string directory)
    {
        var dir = Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory)) + Path.DirectorySeparatorChar;
        return Path.GetFullPath(path).StartsWith(dir, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
    }
}
