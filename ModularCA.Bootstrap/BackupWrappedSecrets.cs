using System.Security.Cryptography;
using System.Text.Json;
using ModularCA.Shared.Signing;
using ModularCA.Shared.Utils;

namespace ModularCA.Bootstrap;

/// <summary>
/// The configuration directories a backup carries only wrapped by the signer: the Data
/// Protection key ring, which with the database dump opens every DP-protected column (TOTP
/// secrets, held end-entity keys, Kerberos realm keys, LDAP publisher passwords), and the
/// directories of SSH CA private keys that are still unencrypted files on the node, awaiting
/// their import into the signer; once imported they travel in the signer's SSH keystore and
/// those directories are gone. Each directory travels as one
/// <see cref="SecretKind.BackupConfigSecret"/> blob under <c>secrets/</c> in the archive, so
/// opening it needs the keystore and its secondary passphrase as well as the archive key.
/// </summary>
/// <remarks>
/// A restore cannot unwrap at once: on a new host the running signer holds the new host's keys,
/// and the archive's wrapping key only serves once the restored keystore is unlocked. The restore
/// therefore stages the blobs under <c>config/restore-pending/</c>, and the node unwraps them at
/// its next start (<see cref="ApplyPendingAsync"/>), before anything reads the key ring.
/// </remarks>
public static class BackupWrappedSecrets
{
    /// <summary>The archive directory the wrapped blobs sit in.</summary>
    public const string ArchiveDirectory = "secrets";

    /// <summary>The directory under <c>config/</c> a restore stages blobs in until the next start unwraps them.</summary>
    public const string PendingDirectoryName = "restore-pending";

    /// <summary>The extension of a wrapped blob, in the archive and in the pending directory.</summary>
    public const string WrappedExtension = ".wrapped";

    /// <summary>The Data Protection key ring, relative to <c>config/</c>.</summary>
    public const string DataProtectionDirectory = "dp-keys";

    /// <summary>The bundle layout version inside the wrapped blob.</summary>
    private const int BundleVersion = 1;

    /// <summary>The caller the startup unwrap names at the signer.</summary>
    public const string RestoreCaller = "restore";

    /// <summary>What a bundle holds: the directory it restores into, relative to <c>config/</c>, and its files by relative path.</summary>
    private sealed class Bundle
    {
        public int Version { get; set; }
        public string Target { get; set; } = string.Empty;
        public Dictionary<string, string> Files { get; set; } = new(StringComparer.Ordinal);
    }

    /// <summary>
    /// The directory SSH CA key files were written to unless the retired key path setting named
    /// another, relative to <c>config/</c>. It always travels wrapped.
    /// </summary>
    public const string DefaultSshKeyDirectory = "ssh-ca-keys";

    /// <summary>How an unencrypted or encrypted OpenSSH private key file begins.</summary>
    private static readonly byte[] OpenSshPrivateKeyHeader = "-----BEGIN OPENSSH PRIVATE KEY-----"u8.ToArray();

    /// <summary>
    /// The directories under <paramref name="configDir"/> that travel wrapped, relative to it
    /// with forward slashes: the Data Protection key ring, the default SSH CA key directory, and
    /// every other directory inside <c>config/</c> that holds an SSH CA key file. Where those
    /// are comes from the database, never from configuration: <paramref name="legacyKeyFiles"/>
    /// are the key file paths of the SSH CA key rows that are still files on the node, and of
    /// imported keys whose file has not been removed yet. A directory inside another target is
    /// left out, since the outer one carries it. Directories that do not exist are included;
    /// callers skip them. A key file directly in <c>config/</c> is not covered here, since
    /// <c>config/</c> itself is no target: see <see cref="LooseLegacyKeyFiles"/>.
    /// </summary>
    /// <param name="configDir">The <c>config/</c> directory.</param>
    /// <param name="legacyKeyFiles">The key file paths the rows give, absolute or relative to the application directory; null for none.</param>
    public static IReadOnlyList<string> Targets(string configDir, IEnumerable<string>? legacyKeyFiles)
    {
        var targets = new List<string> { DataProtectionDirectory, DefaultSshKeyDirectory };
        foreach (var (directory, _) in LegacyKeyFilesInside(configDir, legacyKeyFiles))
        {
            if (directory != "." && !targets.Contains(directory, StringComparer.Ordinal))
                targets.Add(directory);
        }
        return targets.Where(t => !targets.Any(outer => outer != t && t.StartsWith(outer + "/", StringComparison.Ordinal))).ToList();
    }

    /// <summary>
    /// The SSH CA key files that lie directly in <paramref name="configDir"/>, each with its
    /// <c>.pub</c>, as file names. No directory can stand for them, so they cannot travel
    /// wrapped; the config copy leaves these files out, and the backup says so.
    /// </summary>
    /// <param name="configDir">The <c>config/</c> directory.</param>
    /// <param name="legacyKeyFiles">As for <see cref="Targets"/>.</param>
    public static IReadOnlyList<string> LooseLegacyKeyFiles(string configDir, IEnumerable<string>? legacyKeyFiles)
        => LegacyKeyFilesInside(configDir, legacyKeyFiles)
            .Where(f => f.Directory == ".")
            .SelectMany(f => new[] { f.FileName, f.FileName + ".pub" })
            .Distinct(StringComparer.Ordinal)
            .ToList();

    /// <summary>
    /// The key files among <paramref name="legacyKeyFiles"/> that lie inside
    /// <paramref name="configDir"/>: the directory of each relative to it with forward slashes
    /// (<c>.</c> for <c>config/</c> itself), and its file name. A relative path is relative to
    /// the application directory, the parent of <c>config/</c>, as the service that wrote it
    /// resolved it. A path this system cannot form, or one outside <c>config/</c>, which no
    /// backup copies, is passed over.
    /// </summary>
    private static List<(string Directory, string FileName)> LegacyKeyFilesInside(string configDir, IEnumerable<string>? legacyKeyFiles)
    {
        var inside = new List<(string, string)>();
        var baseDir = Path.GetDirectoryName(Path.GetFullPath(configDir).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar))!;
        foreach (var keyFile in legacyKeyFiles ?? [])
        {
            if (string.IsNullOrWhiteSpace(keyFile))
                continue;
            string full;
            try
            {
                full = Path.GetFullPath(Path.IsPathRooted(keyFile) ? keyFile : Path.Combine(baseDir, keyFile));
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
                continue;
            }
            var directory = Path.GetDirectoryName(full);
            if (directory == null || !BackupRestore.PathIsContainedIn(directory, configDir))
                continue;
            inside.Add((Path.GetRelativePath(configDir, directory).Replace('\\', '/'), Path.GetFileName(full)));
        }
        return inside;
    }

    /// <summary>
    /// The directories of an extracted archive's <c>config/</c> that hold an OpenSSH private key
    /// file, relative to it with forward slashes (<c>.</c> for <c>config/</c> itself), found by
    /// how such a file begins. An archive's own rows name paths on the host it was taken on, so
    /// here the files are recognised by content, wherever they lie.
    /// </summary>
    /// <param name="archiveConfigDir">The extracted archive's <c>config/</c> directory.</param>
    public static IReadOnlyList<string> PlaintextSshKeyDirectoriesIn(string archiveConfigDir)
    {
        var directories = new SortedSet<string>(StringComparer.Ordinal);
        if (!Directory.Exists(archiveConfigDir))
            return [];
        var header = new byte[OpenSshPrivateKeyHeader.Length];
        foreach (var file in Directory.EnumerateFiles(archiveConfigDir, "*", SearchOption.AllDirectories))
        {
            try
            {
                using var stream = File.OpenRead(file);
                if (stream.Length < header.Length || stream.ReadAtLeast(header, header.Length, throwOnEndOfStream: false) < header.Length)
                    continue;
                if (header.AsSpan().SequenceEqual(OpenSshPrivateKeyHeader))
                    directories.Add(Path.GetRelativePath(archiveConfigDir, Path.GetDirectoryName(file)!).Replace('\\', '/'));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // A file that cannot be opened is restored, or not, by the copy that follows.
            }
        }
        return directories.ToList();
    }

    /// <summary>
    /// Wraps each existing, non-empty target directory through the signer under
    /// <see cref="SigningPurpose.Backup"/> and writes the blob to <paramref name="outputDir"/>.
    /// Returns the targets wrapped. A refusal from the signer propagates: a backup that carries
    /// the ring in the clear, or silently lacks it, is not one to write.
    /// </summary>
    public static async Task<IReadOnlyList<string>> WrapAsync(ISigningService signer, string configDir, IEnumerable<string> targets, string outputDir, string caller, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signer);
        var context = new SigningContext(caller, SigningPurpose.Backup, null, null);
        var wrapped = new List<string>();
        foreach (var target in targets)
        {
            var sourceDir = Path.Combine(configDir, target);
            if (!Directory.Exists(sourceDir) || !Directory.EnumerateFiles(sourceDir, "*", SearchOption.AllDirectories).Any())
                continue;

            var payload = Pack(sourceDir, target);
            try
            {
                var blob = await signer.WrapSecretAsync(SecretKind.BackupConfigSecret, payload, context, cancellationToken);
                Directory.CreateDirectory(outputDir);
                await File.WriteAllBytesAsync(Path.Combine(outputDir, SafeName(target) + WrappedExtension), blob, cancellationToken);
                wrapped.Add(target);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(payload);
            }
        }
        return wrapped;
    }

    /// <summary>
    /// Copies the wrapped blobs an extracted archive carries into <c>config/restore-pending/</c>
    /// under names that sort in staging order and never collide with a blob already pending.
    /// Returns how many were staged.
    /// </summary>
    public static int StagePending(string restoreDir, string configDir)
    {
        var source = Path.Combine(restoreDir, ArchiveDirectory);
        if (!Directory.Exists(source))
            return 0;

        var pending = Path.Combine(configDir, PendingDirectoryName);
        var staged = 0;
        foreach (var file in Directory.GetFiles(source, "*" + WrappedExtension, SearchOption.TopDirectoryOnly).OrderBy(f => f, StringComparer.Ordinal))
        {
            Directory.CreateDirectory(pending);
            var name = $"{DateTime.UtcNow:yyyyMMddHHmmssfff}-{Guid.NewGuid():N}-{Path.GetFileName(file)}";
            var destination = Path.Combine(pending, name);
            File.Copy(file, destination, overwrite: false);
            FileSecurityUtil.SetOwnerOnly(destination);
            staged++;
        }
        return staged;
    }

    /// <summary>The outcome of a startup unwrap: blobs applied, and blobs left pending with the reason.</summary>
    public sealed record PendingResult(IReadOnlyList<string> Applied, IReadOnlyList<(string File, string Reason)> Failed);

    /// <summary>
    /// Unwraps every blob pending under <c>config/restore-pending/</c> through the signer under
    /// <see cref="SigningPurpose.Restore"/>, writes its files back into the directory it names,
    /// owner-only, and deletes the blob. A blob that cannot be unwrapped or written stays where
    /// it is for the next start, and the reason is returned; nothing here throws for it.
    /// </summary>
    public static async Task<PendingResult> ApplyPendingAsync(ISigningService signer, string configDir, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signer);
        var applied = new List<string>();
        var failed = new List<(string, string)>();
        var pending = Path.Combine(configDir, PendingDirectoryName);
        if (!Directory.Exists(pending))
            return new PendingResult(applied, failed);

        var context = new SigningContext(RestoreCaller, SigningPurpose.Restore, null, null);
        foreach (var file in Directory.GetFiles(pending, "*" + WrappedExtension, SearchOption.TopDirectoryOnly).OrderBy(f => f, StringComparer.Ordinal))
        {
            byte[]? payload = null;
            try
            {
                payload = await signer.UnwrapSecretAsync(await File.ReadAllBytesAsync(file, cancellationToken), context, cancellationToken);
                var target = Unpack(payload, configDir);
                File.Delete(file);
                applied.Add(target);
            }
            catch (Exception ex) when (ex is SigningRefusedException or IOException or UnauthorizedAccessException or InvalidDataException or JsonException)
            {
                failed.Add((Path.GetFileName(file), ex.Message));
            }
            finally
            {
                if (payload != null)
                    CryptographicOperations.ZeroMemory(payload);
            }
        }

        try
        {
            if (!Directory.EnumerateFileSystemEntries(pending).Any())
                Directory.Delete(pending);
        }
        catch (IOException)
        {
        }
        return new PendingResult(applied, failed);
    }

    /// <summary>
    /// The relative paths of the target directories an extracted archive carries in the clear
    /// under <c>config/</c>: an archive taken before the ring travelled wrapped. Such an archive
    /// still restores, with a warning.
    /// </summary>
    public static IReadOnlyList<string> PlaintextTargetsIn(string archiveConfigDir, IEnumerable<string> targets)
        => targets.Where(t => Directory.Exists(Path.Combine(archiveConfigDir, t))
                              && Directory.EnumerateFiles(Path.Combine(archiveConfigDir, t), "*", SearchOption.AllDirectories).Any())
                  .ToList();

    /// <summary>Serialises a directory's files, by path relative to it, with the target it restores into.</summary>
    internal static byte[] Pack(string sourceDir, string target)
    {
        var bundle = new Bundle { Version = BundleVersion, Target = target };
        foreach (var file in Directory.GetFiles(sourceDir, "*", SearchOption.AllDirectories).OrderBy(f => f, StringComparer.Ordinal))
        {
            var bytes = File.ReadAllBytes(file);
            bundle.Files[Path.GetRelativePath(sourceDir, file).Replace('\\', '/')] = Convert.ToBase64String(bytes);
            CryptographicOperations.ZeroMemory(bytes);
        }
        return JsonSerializer.SerializeToUtf8Bytes(bundle);
    }

    /// <summary>
    /// Writes a bundle's files into its target under <paramref name="configDir"/>, owner-only,
    /// overwriting what is there. The target and every file must stay inside <c>config/</c>,
    /// and no file may bear a name the backup deny-list forbids. Returns the target.
    /// </summary>
    internal static string Unpack(byte[] payload, string configDir)
    {
        var bundle = JsonSerializer.Deserialize<Bundle>(payload)
            ?? throw new InvalidDataException("The wrapped configuration bundle is empty.");
        if (bundle.Version != BundleVersion)
            throw new InvalidDataException($"Unsupported wrapped configuration bundle version {bundle.Version}.");
        if (string.IsNullOrWhiteSpace(bundle.Target) || Path.IsPathRooted(bundle.Target) || bundle.Target.Contains(".."))
            throw new InvalidDataException($"The wrapped configuration bundle names an invalid target '{bundle.Target}'.");

        var targetDir = Path.GetFullPath(Path.Combine(configDir, bundle.Target));
        if (!BackupRestore.PathIsContainedIn(targetDir, configDir) || Path.GetFullPath(configDir).TrimEnd(Path.DirectorySeparatorChar) == targetDir.TrimEnd(Path.DirectorySeparatorChar))
            throw new InvalidDataException($"The wrapped configuration bundle target '{bundle.Target}' is not a directory inside config/.");

        foreach (var (relative, content) in bundle.Files)
        {
            var destination = Path.GetFullPath(Path.Combine(targetDir, relative));
            if (Path.IsPathRooted(relative) || !BackupRestore.PathIsContainedIn(destination, targetDir) || BackupSecretDenylist.IsDenied(Path.GetFileName(destination)))
                throw new InvalidDataException($"The wrapped configuration bundle carries a file it may not restore: '{relative}'.");
        }

        Directory.CreateDirectory(targetDir);
        FileSecurityUtil.SetDirectoryOwnerOnly(targetDir);
        foreach (var (relative, content) in bundle.Files)
        {
            var destination = Path.GetFullPath(Path.Combine(targetDir, relative));
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            var bytes = Convert.FromBase64String(content);
            try
            {
                File.WriteAllBytes(destination, bytes);
                FileSecurityUtil.SetOwnerOnly(destination);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
        return bundle.Target;
    }

    /// <summary>A file name for a target: its relative path with separators flattened.</summary>
    private static string SafeName(string target) => target.Replace('/', '_').Replace('\\', '_');
}
