using Microsoft.Extensions.Logging;
using ModularCA.Core.Services;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Models.Config;
using System.Buffers.Binary;
using System.IO.Compression;
using System.Text.Json;

namespace ModularCA.Core.Services.SchedulerJobs;

/// <summary>
/// Scheduled job that verifies the integrity and recency of backup archives.
/// Checks that a recent backup exists within the configured maximum age,
/// validates that the backup manifest is readable, and performs basic structural
/// integrity checks (file size, valid ZIP). Raises security alerts when issues are detected.
/// Gated on the <see cref="BackupConfig.Enabled"/> master flag (Audit Item #11): when
/// that flag is <c>false</c> the verifier returns immediately so a deployment that has
/// scheduled backups disabled doesn't drown operators in <c>BackupMissing</c> /
/// <c>BackupStale</c> alerts for archives the system was never asked to produce.
///
/// Inherits <see cref="SingletonCronJob"/> so the base class owns past-due math, missed-run
/// policy, timeout enforcement, metrics, and <c>SchedulerJobStates</c> persistence — the
/// body below is purely the per-tick verification work. By design this job shares
/// <c>Backup.Schedule</c> with <c>BackupCreationJob</c>: operators set a single backup
/// cadence and both jobs evaluate the same cron expression on each poll cycle, with the
/// per-job <c>Enabled</c> / <c>VerifyOnSchedule</c> flags gating actual execution. The
/// <c>RunAsync(ct)</c> entry point is retained as the operator-facing manual-run path:
/// <c>SchedulerJobRegistry.RunNowAsync</c> calls it directly when an operator clicks
/// "Run Now" in the admin Schedules page — bypassing the cron past-due gate that
/// <see cref="SingletonCronJob.TickAsync"/> evaluates so the work fires immediately
/// regardless of schedule.
/// </summary>
public class BackupVerificationJob : SingletonCronJob
{
    private readonly SystemConfig _config;
    private readonly ISecurityAlertService _alerts;
    private readonly ILogger<BackupVerificationJob> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="BackupVerificationJob"/> class.
    /// </summary>
    /// <param name="serviceProvider">Service provider used by the base class for scoped resolutions.</param>
    /// <param name="config">System configuration containing backup settings.</param>
    /// <param name="alerts">Security alert service for raising backup-related alerts.</param>
    /// <param name="logger">Logger instance.</param>
    /// <param name="runner">Shared scheduler job runner that owns timeout, metrics, and state persistence.</param>
    public BackupVerificationJob(
        IServiceProvider serviceProvider,
        SystemConfig config,
        ISecurityAlertService alerts,
        ILogger<BackupVerificationJob> logger,
        SchedulerJobRunner runner)
        : base(serviceProvider, logger, config, runner)
    {
        _config = config;
        _alerts = alerts;
        _logger = logger;
    }

    /// <inheritdoc />
    public override string Name => "BackupVerification";

    /// <summary>
    /// Cron expression for the verification sweep. Returns <see cref="string.Empty"/>
    /// when scheduled backups are disabled or per-cadence verification is turned off,
    /// which the base <see cref="SingletonCronJob.TickAsync"/> treats as "skip without
    /// state write". Shares <c>Backup.Schedule</c> with <c>BackupCreationJob</c> by
    /// design so a single operator-set cadence drives both create and verify cycles.
    /// </summary>
    protected override string CronExpression =>
        (_config.Backup.Enabled && _config.Backup.VerifyOnSchedule)
            ? _config.Backup.Schedule
            : string.Empty;

    /// <summary>
    /// Manual-run shim. <c>SchedulerJobRegistry.RunNowAsync</c> calls this when an
    /// operator clicks "Run Now" for this job — bypassing the cron past-due gate that
    /// <see cref="SingletonCronJob.TickAsync"/> evaluates so the work fires immediately
    /// regardless of schedule. The protected <see cref="ExecuteAsync"/> body is invoked
    /// directly.
    /// </summary>
    public Task RunAsync(CancellationToken cancellationToken) => ExecuteAsync(cancellationToken);

    /// <summary>
    /// Executes the backup verification check. Scans the configured backup directory
    /// for existing archives, validates recency against MaxBackupAgeDays, and checks
    /// the latest backup for structural integrity (valid ZIP with a readable manifest).
    /// Returns immediately when <see cref="BackupConfig.Enabled"/> (master gate, Audit
    /// Item #11) or <see cref="BackupConfig.VerifyOnSchedule"/> (per-cadence flag) is
    /// <c>false</c>. The master flag is checked first to avoid emitting any
    /// <c>BackupMissing</c> / <c>BackupStale</c> alerts on deployments that have
    /// disabled scheduled backups outright. The CronExpression short-circuit handles
    /// the TickAsync path; the duplicate check below protects the manual-run RunAsync
    /// path which bypasses cron evaluation in the base class. A run that checks archives
    /// leaves what it found in the backup directory (<see cref="BackupVerificationRecord"/>).
    /// </summary>
    /// <param name="cancellationToken">Token to signal cancellation of the operation.</param>
    protected override async Task ExecuteAsync(CancellationToken cancellationToken)
    {
        // Audit Item #11: master gate. Skip verification entirely when scheduled
        // backups are disabled — otherwise the "no archives in OutputPath" branch
        // would fire BackupMissing every cycle on a deployment that intentionally
        // does not produce archives.
        if (!_config.Backup.Enabled)
        {
            _logger.LogDebug("Backup verification: skipped — Backup.Enabled master flag is false");
            return;
        }

        if (!_config.Backup.VerifyOnSchedule)
            return;

        var backupDir = ResolveBackupDirectory();

        // Distinguish "directory does not exist" from "directory exists but the service
        // identity cannot read it" — the latter is a BackupAccessDenied alert rather
        // than a false-positive BackupMissing.
        try
        {
            if (!Directory.Exists(backupDir))
            {
                _logger.LogWarning("Backup verification: backup directory does not exist at {BackupDir}", backupDir);
                await _alerts.RaiseAlertAsync(
                    "BackupMissing",
                    AlertSeverity.Critical,
                    "No backup directory found. Disaster recovery is not possible.",
                    new { BackupDirectory = backupDir });
                return;
            }
        }
        catch (UnauthorizedAccessException uaex)
        {
            _logger.LogError(uaex, "Backup verification: access denied on backup directory {BackupDir}", backupDir);
            await _alerts.RaiseAlertAsync(
                "BackupAccessDenied",
                AlertSeverity.Critical,
                $"Backup directory exists but the scheduler identity cannot read it: {backupDir}",
                new { BackupDirectory = backupDir, Error = uaex.Message });
            return;
        }

        FileInfo[] backupFilesArray;
        try
        {
            backupFilesArray = new DirectoryInfo(backupDir).GetFiles("modularca-backup-*.*");
        }
        catch (UnauthorizedAccessException uaex)
        {
            _logger.LogError(uaex, "Backup verification: access denied while enumerating {BackupDir}", backupDir);
            await _alerts.RaiseAlertAsync(
                "BackupAccessDenied",
                AlertSeverity.Critical,
                $"Access denied while enumerating backup directory: {backupDir}",
                new { BackupDirectory = backupDir, Error = uaex.Message });
            return;
        }

        var backupFiles = backupFilesArray
            .Where(f => f.Extension is ".zip" or ".enc")
            .OrderByDescending(f => f.CreationTimeUtc)
            .ToList();

        if (backupFiles.Count == 0)
        {
            _logger.LogWarning("Backup verification: no backup archives found in {BackupDir}", backupDir);
            await _alerts.RaiseAlertAsync(
                "BackupMissing",
                AlertSeverity.Critical,
                "No backup archives found. Disaster recovery is not possible.",
                new { BackupDirectory = backupDir });
            return;
        }

        var latestBackup = backupFiles[0];
        var ageHours = (TimeProvider.GetUtcNow().UtcDateTime - latestBackup.CreationTimeUtc).TotalHours;
        var maxAgeDays = _config.Backup.MaxBackupAgeDays;

        // Check recency
        if (ageHours > maxAgeDays * 24)
        {
            _logger.LogWarning("Backup verification: latest backup is {AgeHours:F1} hours old, exceeds max age of {MaxAgeDays} days",
                ageHours, maxAgeDays);
            await _alerts.RaiseAlertAsync(
                "BackupStale",
                AlertSeverity.Critical,
                $"Latest backup is {ageHours:F0} hours old (max allowed: {maxAgeDays * 24} hours). Run a new backup immediately.",
                new { FileName = latestBackup.Name, AgeHours = ageHours, MaxAgeDays = maxAgeDays });
        }

        // Validate the N most-recent backups, not just the latest. Catches a corrupted
        // prior archive that the operator may want to restore from if today's backup
        // turns out to be unusable.
        var verifyCount = Math.Max(1, _config.Backup.VerifyCount);
        var toVerify = backupFiles.Take(verifyCount).ToList();
        int ok = 0;
        var found = new List<BackupVerificationRecord.Archive>(toVerify.Count);
        foreach (var archive in toVerify)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var (isValid, issues) = ValidateBackupIntegrity(archive);
            found.Add(new BackupVerificationRecord.Archive(archive.Name, isValid));
            if (!isValid)
            {
                _logger.LogError("Backup verification: backup {FileName} is corrupted. Issues: {Issues}",
                    archive.Name, string.Join("; ", issues));
                await _alerts.RaiseAlertAsync(
                    "BackupCorrupted",
                    AlertSeverity.Critical,
                    $"Backup '{archive.Name}' failed integrity checks.",
                    new { FileName = archive.Name, Issues = issues });
            }
            else
            {
                ok++;
                _logger.LogDebug("Backup verification: backup {FileName} passed integrity checks", archive.Name);
            }
        }
        _logger.LogInformation("Backup verification: {Ok}/{Total} recent backups passed checks (latest age {AgeHours:F1}h)",
            ok, toVerify.Count, ageHours);

        // What this run found is kept beside the archives, for readers that must not verify
        // anything themselves (the hub's inventory). Failing to keep it does not fail the run:
        // the alerts above have already said what matters.
        try
        {
            BackupVerificationRecord.Write(backupDir, new BackupVerificationRecord(TimeProvider.GetUtcNow().UtcDateTime, found));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning("Backup verification: the result of this run could not be written to {File} in {BackupDir} ({Error})",
                BackupVerificationRecord.FileName, backupDir, ex.GetType().Name);
        }
    }

    /// <summary>
    /// Validates the structural integrity of a backup archive without restoring it.
    /// Checks that the file is non-empty, has a valid ZIP structure, and contains
    /// a readable manifest.json entry.
    /// </summary>
    /// <param name="backupFile">The backup archive file to validate.</param>
    /// <returns>A tuple of (isValid, issues) where issues contains descriptions of any problems found.</returns>
    public static (bool isValid, List<string> issues) ValidateBackupIntegrity(FileInfo backupFile)
    {
        var issues = new List<string>();

        // Check file size
        if (backupFile.Length == 0)
        {
            issues.Add("Backup file is empty (0 bytes)");
            return (false, issues);
        }

        // Parse the new-format encrypted backup header and verify field structure
        // and a minimum ciphertext length proportional to the manifest contents. The full
        // 66-byte header layout (defined in BackupKeyManager) is:
        //   [4 magic "MCAB"][1 version][1 mode][16 salt][8 N][4 r][4 p][12 nonce][16 tag][ciphertext]
        // Legacy files are accepted with a 28-byte minimum (12 nonce + 16 tag).
        if (backupFile.Extension == ".enc")
        {
            try
            {
                using var fs = backupFile.OpenRead();
                Span<byte> header = stackalloc byte[66];
                var read = fs.Read(header);
                if (read < 4)
                {
                    issues.Add("Encrypted backup file is too small to contain a valid header");
                    return (false, issues);
                }

                bool isNew = header[0] == 0x4D && header[1] == 0x43 && header[2] == 0x41 && header[3] == 0x42; // "MCAB"
                if (!isNew)
                {
                    if (backupFile.Length < 28)
                        issues.Add("Legacy encrypted backup file is too small to contain a valid header");
                    return (issues.Count == 0, issues);
                }

                if (read < 66)
                {
                    issues.Add("New-format encrypted backup header is truncated");
                    return (false, issues);
                }

                var version = header[4];
                if (version != 0x01)
                    issues.Add($"Unsupported encrypted backup format version: {version}");

                var mode = header[5];
                if (mode != 0 && mode != 1)
                    issues.Add($"Unknown backup encryption mode byte: {mode}");

                // Scrypt params are only meaningful for StoredPassword mode (mode=1).
                // RandomKey mode (mode=0) writes zeroes — skip the bounds check in that case.
                if (mode == 1)
                {
                    var n = BinaryPrimitives.ReadInt64LittleEndian(header.Slice(22, 8));
                    var r = BinaryPrimitives.ReadInt32LittleEndian(header.Slice(30, 4));
                    var p = BinaryPrimitives.ReadInt32LittleEndian(header.Slice(34, 4));
                    if (n <= 0 || r <= 0 || p <= 0 || n > (1L << 24))
                        issues.Add($"Encrypted backup scrypt parameters out of range (N={n}, r={r}, p={p})");
                }

                if (backupFile.Length < 66 + 16) // header + at least 16 bytes of ciphertext
                    issues.Add("Encrypted backup contains no ciphertext payload after the header");
            }
            catch (IOException ex)
            {
                issues.Add($"Unable to read encrypted backup header: {ex.Message}");
            }
            return (issues.Count == 0, issues);
        }

        // Check valid ZIP structure
        try
        {
            using var zipStream = new FileStream(backupFile.FullName, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var archive = new ZipArchive(zipStream, ZipArchiveMode.Read);

            // Check for manifest.json
            var manifestEntry = archive.GetEntry("manifest.json");
            if (manifestEntry == null)
            {
                issues.Add("Missing manifest.json in backup archive");
            }
            else
            {
                // Validate manifest is readable JSON
                try
                {
                    using var reader = new StreamReader(manifestEntry.Open());
                    var manifestJson = reader.ReadToEnd();
                    using var doc = JsonDocument.Parse(manifestJson);

                    // Verify required fields exist
                    if (!doc.RootElement.TryGetProperty("Version", out _))
                        issues.Add("Manifest missing 'Version' field");
                    if (!doc.RootElement.TryGetProperty("Timestamp", out _))
                        issues.Add("Manifest missing 'Timestamp' field");
                    if (!doc.RootElement.TryGetProperty("SchemaVersion", out _))
                        issues.Add("Manifest missing 'SchemaVersion' field");
                }
                catch (JsonException ex)
                {
                    issues.Add($"Manifest is not valid JSON: {ex.Message}");
                }
            }

            // Verify the archive contains expected content directories
            var hasDb = archive.Entries.Any(e => e.FullName.StartsWith("db-", StringComparison.OrdinalIgnoreCase));
            var hasConfig = archive.Entries.Any(e => e.FullName.StartsWith("config/", StringComparison.OrdinalIgnoreCase));
            var hasKeystores = archive.Entries.Any(e => e.FullName.StartsWith("keystores/", StringComparison.OrdinalIgnoreCase));

            if (!hasDb)
                issues.Add("No database dump files found in archive");
            if (!hasConfig)
                issues.Add("No config directory found in archive");
            if (!hasKeystores)
                issues.Add("No keystores directory found in archive");
        }
        catch (InvalidDataException)
        {
            issues.Add("File is not a valid ZIP archive (corrupted or truncated)");
        }
        catch (IOException ex)
        {
            issues.Add($"Unable to read backup file: {ex.Message}");
        }

        return (issues.Count == 0, issues);
    }

    /// <summary>
    /// Reads and parses the manifest.json from a backup archive.
    /// Returns null if the manifest cannot be read or parsed.
    /// </summary>
    /// <param name="backupFile">The backup archive file.</param>
    /// <returns>The parsed JSON document element, or null on failure.</returns>
    public static JsonElement? ReadManifest(FileInfo backupFile)
    {
        try
        {
            using var zipStream = new FileStream(backupFile.FullName, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var archive = new ZipArchive(zipStream, ZipArchiveMode.Read);
            var manifestEntry = archive.GetEntry("manifest.json");
            if (manifestEntry == null) return null;

            using var reader = new StreamReader(manifestEntry.Open());
            var json = reader.ReadToEnd();
            var doc = JsonDocument.Parse(json);
            return doc.RootElement.Clone();
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Resolves the backup directory to an absolute path.
    /// </summary>
    /// <returns>The absolute path to the backup directory.</returns>
    private string ResolveBackupDirectory()
    {
        var outputPath = _config.Backup.OutputPath;
        if (Path.IsPathRooted(outputPath))
            return outputPath;
        return Path.Combine(AppContext.BaseDirectory, outputPath);
    }
}
