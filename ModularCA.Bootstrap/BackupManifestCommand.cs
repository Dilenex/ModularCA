using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using ModularCA.Database;

namespace ModularCA.Bootstrap;

/// <summary>
/// <c>--backup-manifest &lt;archive&gt; [--key-file &lt;file&gt;] [--password-file &lt;file&gt;]</c>: says what a
/// backup archive is, on one line of JSON, and exits. It reads the archive and its key file and
/// nothing else: no database, no keystore, no configuration beyond the names of this host's key
/// files. It writes nothing anywhere, so the archive may lie on a read-only mount, and it starts
/// no logger. An orchestrator runs it before it stops anything.
/// </summary>
/// <remarks>
/// <para>
/// Standard output carries exactly one line, the JSON, and only on exit 0. A refusal exits
/// <see cref="RestoreExit.Refused"/> with the reason on standard error and nothing on standard
/// output: the archive is missing, is not a ModularCA backup archive, or does not open with the
/// key given.
/// </para>
/// <para>
/// The manifest lies inside the archive's encryption, so the command needs the archive's key.
/// Nothing that names the instance is kept outside the encryption: whoever holds only the file
/// learns nothing of where it came from.
/// </para>
/// </remarks>
public static class BackupManifestCommand
{
    /// <summary>The flag, followed by the archive's path.</summary>
    public const string Flag = "--backup-manifest";

    /// <summary>The flag that names the archive's key file.</summary>
    public const string KeyFileFlag = "--key-file";

    /// <summary>The flag that names a file holding the backup password.</summary>
    public const string PasswordFileFlag = "--password-file";

    /// <summary>The usage line printed for missing or wrong arguments.</summary>
    public const string Usage = "Usage: --backup-manifest <archive> [--key-file <backup.key or backup-password.key>] [--password-file <file holding the backup password>]";

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
    };

    /// <summary>
    /// What <c>--backup-manifest</c> prints. Every field is always present; one the archive does
    /// not record is null.
    /// </summary>
    /// <param name="Archive">The archive's file name.</param>
    /// <param name="ManifestVersion">The manifest's own format version.</param>
    /// <param name="InstanceId">
    /// The instance that wrote the archive, as the archive's manifest holds it: the instance's
    /// stored identifier, or, for an archive taken before the instance had stored one, the
    /// SHA-256 of the public key of its system signing CA, which is the value that was stored
    /// later; 64 hex digits either way (<see cref="BackupRestore.ReadInstanceIdAsync"/>). The
    /// same value the hub's <c>hello</c> answers. Null for an archive taken before 0.4.5, which
    /// did not record it.
    /// </param>
    /// <param name="ProductVersion">The product version that wrote the archive. Null before 0.4.5.</param>
    /// <param name="SchemaVersion">The fingerprint of the application database's tables and migration history.</param>
    /// <param name="LatestMigration">The newest migration applied to the application database. Null before 0.4.5.</param>
    /// <param name="NewerThanThisBuild">
    /// True when <paramref name="LatestMigration"/> is one this build does not have, so the archive
    /// was taken by a newer build and a restore with this one is refused. Null when the archive
    /// does not say.
    /// </param>
    /// <param name="CreatedAtUtc">When the backup was taken.</param>
    /// <param name="MachineName">The host name of the machine or container that took it.</param>
    /// <param name="AppDatabase">The name of the application database it was taken from.</param>
    /// <param name="AuditDatabase">The name of the audit database it was taken from.</param>
    /// <param name="HasAuditDatabase">Whether the archive holds an audit database, which <c>--restore-audit</c> needs.</param>
    /// <param name="CaCount">How many CAs the application database held.</param>
    /// <param name="CertificateCount">How many certificates it held.</param>
    /// <param name="Encryption"><c>RandomKey</c>, <c>StoredPassword</c> or <c>none</c>.</param>
    /// <param name="SizeBytes">The size of the archive file.</param>
    /// <param name="ReadByVersion">The product version of the build that read the archive.</param>
    public sealed record Summary(
        string Archive,
        string? ManifestVersion,
        string? InstanceId,
        string? ProductVersion,
        string? SchemaVersion,
        string? LatestMigration,
        bool? NewerThanThisBuild,
        DateTime? CreatedAtUtc,
        string? MachineName,
        string? AppDatabase,
        string? AuditDatabase,
        bool HasAuditDatabase,
        int? CaCount,
        int? CertificateCount,
        string Encryption,
        long SizeBytes,
        string ReadByVersion);

    /// <summary>True when <paramref name="args"/> ask for this command.</summary>
    /// <param name="args">The process arguments.</param>
    public static bool IsNamedIn(string[] args) => args.Contains(Flag, StringComparer.OrdinalIgnoreCase);

    /// <summary>The value that follows <paramref name="flag"/>, or null when the flag is absent, last, or followed by another flag.</summary>
    /// <param name="args">The process arguments.</param>
    /// <param name="flag">The flag.</param>
    /// <param name="given">Whether the flag is among the arguments at all.</param>
    public static string? ValueOf(string[] args, string flag, out bool given)
    {
        var index = Array.FindIndex(args, a => a.Equals(flag, StringComparison.OrdinalIgnoreCase));
        given = index >= 0;
        if (index < 0 || index + 1 >= args.Length)
            return null;
        var value = args[index + 1];
        return string.IsNullOrWhiteSpace(value) || value.StartsWith("--", StringComparison.Ordinal) ? null : value;
    }

    /// <summary>
    /// Reads where the archive's key comes from out of the arguments: <see cref="KeyFileFlag"/>
    /// and <see cref="PasswordFileFlag"/>, each naming a file.
    /// </summary>
    /// <param name="args">The process arguments.</param>
    /// <exception cref="BackupArchiveException">A flag has no value, or the password file cannot be read.</exception>
    public static BackupKeySource KeysFrom(string[] args)
    {
        var keyFile = ValueOf(args, KeyFileFlag, out var keyGiven);
        if (keyGiven && keyFile == null)
            throw new BackupArchiveException($"{KeyFileFlag} takes the path of the archive's key file.");
        var passwordFile = ValueOf(args, PasswordFileFlag, out var passwordGiven);
        if (passwordGiven && passwordFile == null)
            throw new BackupArchiveException($"{PasswordFileFlag} takes the path of a file holding the backup password.");
        return new BackupKeySource(keyFile == null ? null : Path.GetFullPath(keyFile),
            passwordFile == null ? null : BackupKeySource.ReadPasswordFile(passwordFile));
    }

    /// <summary>
    /// Runs the command and returns the exit status: 0 with the JSON line on
    /// <paramref name="output"/>, or <see cref="RestoreExit.Refused"/> with the reason on
    /// <paramref name="error"/>.
    /// </summary>
    /// <param name="args">The process arguments.</param>
    /// <param name="baseDirectory">The application directory, for the default key files.</param>
    /// <param name="output">Standard output.</param>
    /// <param name="error">Standard error.</param>
    public static int Run(string[] args, string baseDirectory, TextWriter output, TextWriter error)
    {
        byte[]? zip = null;
        try
        {
            var archivePath = ValueOf(args, Flag, out _);
            if (archivePath == null)
            {
                error.WriteLine(Usage);
                return RestoreExit.Refused;
            }

            zip = BackupArchiveFile.ReadZip(archivePath, KeysFrom(args), baseDirectory, out var encryption);
            var manifestJson = BackupArchiveFile.ReadManifest(zip, out var hasAuditDump)
                ?? throw new BackupArchiveException("The archive holds no manifest.json: it is not a ModularCA backup archive.");
            var summary = Summarise(manifestJson, Path.GetFileName(archivePath), new FileInfo(archivePath).Length, encryption, hasAuditDump);
            output.WriteLine(JsonSerializer.Serialize(summary, Json));
            return RestoreExit.Done;
        }
        catch (BackupArchiveException ex)
        {
            error.WriteLine(ex.Message);
            return RestoreExit.Refused;
        }
        catch (Exception ex)
        {
            error.WriteLine($"The archive could not be read ({ex.GetType().Name}: {ex.Message}).");
            return RestoreExit.Refused;
        }
        finally
        {
            if (zip != null) CryptographicOperations.ZeroMemory(zip);
        }
    }

    /// <summary>The summary of a manifest. The counts of users a manifest carries are left out.</summary>
    /// <param name="manifestJson">The text of <c>manifest.json</c>.</param>
    /// <param name="archiveName">The archive's file name.</param>
    /// <param name="sizeBytes">The archive file's size.</param>
    /// <param name="encryption">How the archive was encrypted.</param>
    /// <param name="hasAuditDump">Whether it holds an audit database.</param>
    /// <exception cref="BackupArchiveException">The manifest is not JSON.</exception>
    internal static Summary Summarise(string manifestJson, string archiveName, long sizeBytes, string encryption, bool hasAuditDump)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(manifestJson);
        }
        catch (JsonException)
        {
            throw new BackupArchiveException("The archive's manifest.json is not JSON: it is not a ModularCA backup archive.");
        }
        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                throw new BackupArchiveException("The archive's manifest.json is not a manifest: it is not a ModularCA backup archive.");

            string? Text(string name) => root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
            int? Number(string name) => root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var n) ? n : null;

            DateTime? created = Text("Timestamp") is { } stamp
                && DateTime.TryParse(stamp, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var parsed)
                ? DateTime.SpecifyKind(parsed, DateTimeKind.Utc) : null;
            var latest = Text("LatestMigration");
            var latestAudit = Text("LatestAuditMigration");
            bool? newer = latest == null ? null
                : !KnownMigrations(audit: false).Contains(latest)
                  || (latestAudit != null && !KnownMigrations(audit: true).Contains(latestAudit));

            return new Summary(
                archiveName, Text("Version"), Text("InstanceId"), Text("ProductVersion"), Text("SchemaVersion"),
                latest, newer, created, Text("MachineName"), Text("AppDatabase"), Text("AuditDatabase"),
                hasAuditDump, Number("CaCount"), Number("CertCount"), encryption, sizeBytes, ProductVersion());
        }
    }

    /// <summary>The product version of this build, without the commit the build stamps after a plus sign.</summary>
    public static string ProductVersion()
    {
        var informational = typeof(BackupManifestCommand).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "unknown";
        var plus = informational.IndexOf('+');
        return plus < 0 ? informational : informational[..plus];
    }

    /// <summary>
    /// The migrations this build has for one database, by id. Read from the assembly: the
    /// connection string names no server and no connection is opened.
    /// </summary>
    /// <param name="audit">True for the audit database, false for the application database.</param>
    public static IReadOnlySet<string> KnownMigrations(bool audit)
    {
        const string nowhere = "Host=unused.invalid;Database=unused;Username=unused";
        if (audit)
        {
            using var auditDb = new AuditDbContext(new DbContextOptionsBuilder<AuditDbContext>().UseNpgsql(nowhere).Options);
            return auditDb.Database.GetMigrations().ToHashSet(StringComparer.Ordinal);
        }
        using var db = new ModularCADbContext(new DbContextOptionsBuilder<ModularCADbContext>().UseNpgsql(nowhere).Options);
        return db.Database.GetMigrations().ToHashSet(StringComparer.Ordinal);
    }
}
