using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;
using ModularCA.API.Controllers.v1.Auth;
using ModularCA.API.Filters;
using ModularCA.Auth.Interfaces;
using ModularCA.Bootstrap;
using ModularCA.Bootstrap.Crypto;
using ModularCA.Core.Services;
using ModularCA.Core.Services.SchedulerJobs;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using System.IO.Compression;
using System.Text.Json;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for triggering backups, listing available backup archives,
/// and restoring from a previous backup. All operations require the SystemAdmin
/// authorization policy and are recorded in the audit log.
/// </summary>
[ApiController]
[Route("api/v1/admin/backup")]
[Authorize(Policy = "SystemAdmin")]
public class AdminBackupController(
    SystemConfig config,
    IAuditService audit,
    ICurrentUserService currentUser,
    IDistributedCache cache,
    ISecurityAlertService alertService,
    ModularCA.Shared.Signing.ISigningService signer) : ControllerBase
{
    private readonly SystemConfig _config = config;
    /// <summary>The node's signer, which exports and imports the keystore files a backup carries.</summary>
    private readonly ModularCA.Shared.Signing.ISigningService _signer = signer;
    private readonly IAuditService _audit = audit;
    private readonly ICurrentUserService _currentUser = currentUser;
    private readonly IDistributedCache _cache = cache;
    private readonly ISecurityAlertService _alertService = alertService;

    /// <summary>
    /// Triggers an on-demand backup. Requires step-up MFA verification via X-MFA-Token header.
    /// The backup archive is written to the configured output directory and old backups
    /// beyond the retention count are pruned.
    /// </summary>
    /// <returns>The filename of the created backup archive.</returns>
    [HttpPost]
    [RequireStepUp(StepUpOps.CreateBackup)]
    public async Task<IActionResult> CreateBackup()
    {
        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null) return Unauthorized();

        var backupDir = ResolveBackupDirectory();
        Directory.CreateDirectory(backupDir);

        // Append a 16-byte cryptographically-random suffix so directory enumeration
        // or timestamp-guessing cannot list backup file names.
        var timestamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss");
        var suffix = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var fileName = $"modularca-backup-{timestamp}-{suffix}.zip";
        var outputPath = Path.Combine(backupDir, fileName);

        var exitCode = await BackupRestore.Backup(outputPath, _ => _signer);

        if (exitCode != 0)
        {
            await _audit.LogAsync(
                AuditActionType.BackupCreated,
                _currentUser.User?.Id,
                _currentUser.User?.Username,
                targetEntityType: "Backup",
                targetEntityId: fileName,
                success: false,
                errorMessage: $"Backup failed with exit code {exitCode}",
                sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString());

            return StatusCode(500, new { error = "Backup failed", exitCode });
        }

        // Enforce retention policy — delete oldest archives beyond the configured limit
        EnforceRetention(backupDir);

        await _audit.LogAsync(
            AuditActionType.BackupCreated,
            _currentUser.User?.Id,
            _currentUser.User?.Username,
            targetEntityType: "Backup",
            targetEntityId: fileName,
            details: new { outputPath },
            sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new { fileName, path = outputPath });
    }

    /// <summary>
    /// Lists all available backup archives in the configured backup directory,
    /// sorted by creation time (newest first).
    /// </summary>
    /// <returns>An array of backup file metadata including name, size, and creation time.</returns>
    [HttpGet]
    public async Task<IActionResult> ListBackups()
    {
        var backupDir = ResolveBackupDirectory();

        if (!Directory.Exists(backupDir))
            return Ok(Array.Empty<object>());

        // Backup filenames now include a 16-byte hex suffix; the wildcard catches both
        // legacy "modularca-backup-{ts}.zip" and the suffixed "modularca-backup-{ts}-{hex}.zip" forms.
        var dirInfo = new DirectoryInfo(backupDir);
        var files = dirInfo.GetFiles("modularca-backup-*.zip")
            .Concat(dirInfo.GetFiles("modularca-backup-*.enc"))
            .OrderByDescending(f => f.CreationTimeUtc)
            .Select(f => new
            {
                fileName = f.Name,
                sizeBytes = f.Length,
                createdUtc = f.CreationTimeUtc,
                encrypted = f.Name.EndsWith(".enc", StringComparison.OrdinalIgnoreCase)
            })
            .ToList();

        await _audit.LogAsync(
            AuditActionType.BackupListed,
            _currentUser.User?.Id,
            _currentUser.User?.Username,
            targetEntityType: "Backup",
            details: new { count = files.Count },
            sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(files);
    }

    /// <summary>
    /// Issues a single-use restore-confirmation token after returning a manifest summary so
    /// the admin UI can show the operator what would be restored before the destructive call.
    /// Replaces the trivially-bypassable static <c>X-Confirm-Restore</c> header.
    /// The token is bound to the requesting user and the specific archive filename, expires
    /// after 5 minutes, and is consumed atomically by <see cref="RestoreBackup"/>.
    /// </summary>
    /// <param name="request">Restore request containing the target archive filename.</param>
    /// <returns>A one-time confirmation token plus a manifest summary.</returns>
    [HttpPost("preview-restore")]
    [RequireStepUp(StepUpOps.RestoreBackup)]
    public async Task<IActionResult> PreviewRestore(
        [FromBody] RestoreRequest request)
    {
        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null) return Unauthorized();

        if (string.IsNullOrWhiteSpace(request?.FileName))
            return BadRequest(new { error = "fileName is required" });

        var sanitized = Path.GetFileName(request.FileName);
        var backupDir = ResolveBackupDirectory();
        var archivePath = Path.Combine(backupDir, sanitized);
        if (!System.IO.File.Exists(archivePath))
            return NotFound(new { error = $"Backup file not found: {sanitized}" });

        var fileInfo = new FileInfo(archivePath);
        var manifest = BackupVerificationJob.ReadManifest(fileInfo);
        object? manifestObj = null;
        if (manifest != null)
        {
            try
            {
                manifestObj = JsonSerializer.Deserialize<JsonElement>(manifest.Value.GetRawText());
            }
            catch { /* best effort */ }
        }

        // Issue a one-time token bound to (user, file). Stored in the distributed cache
        // with a short TTL so a leaked token cannot be replayed long after the preview call.
        var token = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        var cacheKey = $"restore-token:{_currentUser.User.Id}:{token}";
        var payload = JsonSerializer.Serialize(new { fileName = sanitized });
        await _cache.SetStringAsync(cacheKey, payload, new Microsoft.Extensions.Caching.Distributed.DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(5)
        });

        return Ok(new
        {
            confirmationToken = token,
            expiresInSeconds = 300,
            fileName = sanitized,
            sizeBytes = fileInfo.Length,
            createdUtc = fileInfo.CreationTimeUtc,
            encrypted = sanitized.EndsWith(".enc", StringComparison.OrdinalIgnoreCase),
            manifest = manifestObj
        });
    }

    /// <summary>
    /// Restores the application from a previously created backup archive.
    /// The backup file must exist in the configured backup directory.
    /// A restart is required after a successful restore.
    /// Requires step-up MFA verification AND a single-use confirmation token from
    /// <see cref="PreviewRestore"/>.
    /// </summary>
    /// <param name="request">The request body containing the backup filename and confirmation token.</param>
    /// <returns>A success message or error details.</returns>
    [HttpPost("restore")]
    [RequireStepUp(StepUpOps.RestoreBackup)]
    public async Task<IActionResult> RestoreBackup(
        [FromBody] RestoreRequest request)
    {
        await _currentUser.EnsureLoadedAsync();
        if (_currentUser.User == null) return Unauthorized();

        if (string.IsNullOrWhiteSpace(request?.FileName))
            return BadRequest(new { error = "fileName is required" });

        // Validate the single-use confirmation token issued by /preview-restore.
        if (string.IsNullOrWhiteSpace(request.ConfirmationToken))
            return BadRequest(new { error = "confirmationToken is required. Call /api/v1/admin/backup/preview-restore first." });

        var tokenKey = $"restore-token:{_currentUser.User.Id}:{request.ConfirmationToken}";
        var cachedPayload = await _cache.GetStringAsync(tokenKey);
        if (cachedPayload == null)
            return BadRequest(new { error = "Invalid or expired confirmation token. Re-call /api/v1/admin/backup/preview-restore." });
        // Consume the token immediately so it cannot be replayed.
        await _cache.RemoveAsync(tokenKey);

        // Sanitize: only allow filenames, no path traversal
        var sanitized = Path.GetFileName(request.FileName);
        var backupDir = ResolveBackupDirectory();
        var archivePath = Path.Combine(backupDir, sanitized);

        // Confirm the token was issued for THIS archive — not just any archive the user could
        // see. Prevents bait-and-switch where preview is on file A and restore is on file B.
        try
        {
            using var doc = JsonDocument.Parse(cachedPayload);
            var tokenFile = doc.RootElement.GetProperty("fileName").GetString();
            if (!string.Equals(tokenFile, sanitized, StringComparison.Ordinal))
                return BadRequest(new { error = "Confirmation token does not match the supplied fileName." });
        }
        catch (JsonException)
        {
            return BadRequest(new { error = "Confirmation token payload is corrupt." });
        }

        if (!System.IO.File.Exists(archivePath))
        {
            return NotFound(new { error = $"Backup file not found: {sanitized}" });
        }

        // Run restore with schema check but skip interactive confirmation (API mode).
        // providedPassword is forwarded straight through — the restore path ignores it for
        // legacy and RandomKey archives, and only uses it when the archive is StoredPassword-mode
        // and the on-disk password file can't decrypt it.
        var exitCode = await BackupRestore.Restore(
            archivePath,
            _ => _signer,
            skipSchemaCheck: false,
            providedPassword: string.IsNullOrEmpty(request.Password) ? null : request.Password,
            interactive: false);

        if (exitCode != 0)
        {
            await _audit.LogAsync(
                AuditActionType.BackupRestored,
                _currentUser.User?.Id,
                _currentUser.User?.Username,
                targetEntityType: "Backup",
                targetEntityId: sanitized,
                success: false,
                errorMessage: $"Restore failed with exit code {exitCode}",
                sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString());

            return StatusCode(500, new { error = "Restore failed", exitCode });
        }

        await _audit.LogAsync(
            AuditActionType.BackupRestored,
            _currentUser.User?.Id,
            _currentUser.User?.Username,
            targetEntityType: "Backup",
            targetEntityId: sanitized,
            details: new { archivePath },
            sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString());

        _ = _alertService.RaiseAlertAsync("BackupRestored", AlertSeverity.Critical, $"Backup restored from {sanitized} by {_currentUser.User?.Username}", new { FileName = sanitized });
        return Ok(new { message = "Restore complete. Restart the application to apply changes.", fileName = sanitized });
    }

    /// <summary>
    /// Returns the current disaster recovery readiness status, including information about
    /// the most recent backup, its validity, and any issues that may impact recovery capability.
    /// DR readiness levels: Ready (recent valid backup), Warning (backup older than 3 days),
    /// Critical (no backup or latest backup is corrupted).
    /// </summary>
    /// <returns>A DR status summary with readiness level and any detected issues.</returns>
    [HttpGet("dr-status")]
    public async Task<IActionResult> GetDrStatus()
    {
        var backupDir = ResolveBackupDirectory();
        var issues = new List<string>();

        DateTime? lastBackupTimestamp = null;
        double? lastBackupAgeHours = null;
        int backupCount = 0;
        bool latestBackupValid = false;
        bool? keystoreBackedUp = null;
        bool? configBackedUp = null;
        string drReadiness = "Critical";

        if (!Directory.Exists(backupDir))
        {
            issues.Add("Backup directory does not exist");
        }
        else
        {
            var drDirInfo = new DirectoryInfo(backupDir);
            var backupFiles = drDirInfo.GetFiles("modularca-backup-*.zip")
                .Concat(drDirInfo.GetFiles("modularca-backup-*.enc"))
                .OrderByDescending(f => f.CreationTimeUtc)
                .ToList();

            backupCount = backupFiles.Count;

            if (backupCount == 0)
            {
                issues.Add("No backup archives found");
            }
            else
            {
                var latestBackup = backupFiles[0];
                lastBackupTimestamp = latestBackup.CreationTimeUtc;
                lastBackupAgeHours = (DateTime.UtcNow - latestBackup.CreationTimeUtc).TotalHours;

                // Validate structural integrity
                var (isValid, validationIssues) = BackupVerificationJob.ValidateBackupIntegrity(latestBackup);
                latestBackupValid = isValid;

                if (!isValid)
                {
                    issues.AddRange(validationIssues);
                }

                // Content inspection is only possible for unencrypted ZIP archives.
                // Encrypted .enc files cannot be inspected without the decryption key,
                // so we skip keystore/config presence checks for them.
                if (!latestBackup.Name.EndsWith(".enc", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        using var zipStream = new FileStream(latestBackup.FullName, FileMode.Open, FileAccess.Read, FileShare.Read);
                        using var archive = new ZipArchive(zipStream, ZipArchiveMode.Read);
                        var hasKeystores = archive.Entries.Any(e => e.FullName.StartsWith("keystores/", StringComparison.OrdinalIgnoreCase));
                        var hasConfig = archive.Entries.Any(e => e.FullName.StartsWith("config/", StringComparison.OrdinalIgnoreCase));
                        keystoreBackedUp = hasKeystores;
                        configBackedUp = hasConfig;

                        if (!hasKeystores)
                            issues.Add("Latest backup does not contain keystores");
                        if (!hasConfig)
                            issues.Add("Latest backup does not contain configuration");
                    }
                    catch (Exception ex)
                    {
                        Serilog.Log.Warning(ex, "Unable to inspect latest backup archive contents");
                        issues.Add("Unable to inspect latest backup archive contents");
                    }
                }

                // Determine readiness level
                if (!latestBackupValid)
                {
                    drReadiness = "Critical";
                }
                else if (lastBackupAgeHours > _config.Backup.MaxBackupAgeDays * 24)
                {
                    drReadiness = "Critical";
                    issues.Add($"Latest backup exceeds maximum age of {_config.Backup.MaxBackupAgeDays} days");
                }
                else if (lastBackupAgeHours > 72) // 3 days
                {
                    drReadiness = "Warning";
                    issues.Add("Latest backup is older than 3 days");
                }
                else
                {
                    drReadiness = "Ready";
                }
            }
        }

        await _audit.LogAsync(
            AuditActionType.BackupListed,
            _currentUser.User?.Id,
            _currentUser.User?.Username,
            targetEntityType: "Backup",
            details: new { action = "dr-status", drReadiness },
            sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new
        {
            lastBackupTimestamp,
            lastBackupAgeHours = lastBackupAgeHours.HasValue ? Math.Round(lastBackupAgeHours.Value, 1) : (double?)null,
            backupCount,
            latestBackupValid,
            keystoreBackedUp,
            configBackedUp,
            drReadiness,
            issues
        });
    }

    /// <summary>
    /// Returns the current backup encryption configuration: which mode is active
    /// (<c>RandomKey</c> or <c>StoredPassword</c>), whether each key file exists on disk,
    /// and the configured paths. This is a read-only status check and does not require
    /// step-up MFA verification.
    /// </summary>
    /// <returns>A <see cref="BackupEncryptionStatusResponse"/> describing the current mode and key file presence.</returns>
    [HttpGet("encryption")]
    public IActionResult GetEncryptionStatus()
    {
        var randomKeyPath = Path.Combine(AppContext.BaseDirectory, _config.Backup?.EncryptionKeyPath ?? "config/backup.key");
        var passwordKeyPath = Path.Combine(AppContext.BaseDirectory, _config.Backup?.PasswordFilePath ?? "config/backup-password.key");

        return Ok(new BackupEncryptionStatusResponse
        {
            Mode = BackupKeyManager.ParseMode(_config.Backup?.EncryptionMode).ToString(),
            PasswordSet = System.IO.File.Exists(passwordKeyPath),
            RandomKeySet = System.IO.File.Exists(randomKeyPath),
            PasswordFilePath = _config.Backup?.PasswordFilePath ?? "config/backup-password.key",
            RandomKeyFilePath = _config.Backup?.EncryptionKeyPath ?? "config/backup.key",
        });
    }

    /// <summary>
    /// Sets a stored password for backup encryption, switching the system into
    /// <c>StoredPassword</c> mode. Derives a KEK from the password via scrypt and writes it
    /// to the password key file. The password itself is never persisted, logged, or echoed back.
    /// Requires step-up MFA verification with operation token <c>set-backup-password</c>.
    /// </summary>
    /// <param name="request">Request body containing the new password.</param>
    /// <returns>Success message with the new mode, or an error response.</returns>
    [HttpPost("encryption/set-password")]
    [RequireStepUp(StepUpOps.SetBackupPassword)]
    public async Task<IActionResult> SetBackupPassword(
        [FromBody] SetBackupPasswordRequest request)
    {
        var userId = _currentUser.UserId;
        if (userId == null)
            return Unauthorized(new { error = "Authentication required" });

        if (string.IsNullOrWhiteSpace(request?.Password))
            return BadRequest(new { error = "Password is required." });

        var validationError = BackupKeyManager.ValidatePassword(request.Password);
        if (validationError != null)
            return BadRequest(new { error = validationError });

        var passwordKeyPath = Path.Combine(AppContext.BaseDirectory, _config.Backup?.PasswordFilePath ?? "config/backup-password.key");
        var configDir = Path.GetDirectoryName(passwordKeyPath);
        if (!string.IsNullOrEmpty(configDir) && !Directory.Exists(configDir))
            Directory.CreateDirectory(configDir);

        // Derive + write the KEK file (BackupKeyManager handles atomic write + owner-only perms + zero-memory)
        try
        {
            BackupKeyManager.WritePasswordKeyFile(passwordKeyPath, request.Password);
        }
        catch (Exception ex)
        {
            Serilog.Log.Error(ex, "Failed to write backup password key file");
            return StatusCode(500, new { error = "Failed to write backup password key file. Please try again or contact your administrator." });
        }

        // Update the in-memory config and persist to config.yaml so future process restarts pick it up.
        if (_config.Backup != null)
            _config.Backup.EncryptionMode = "StoredPassword";
        TryPersistConfig();

        // Audit — NEVER include request.Password in the details object or any log call.
        await _audit.LogAsync(
            AuditActionType.ConfigUpdated,
            userId.Value,
            _currentUser.User?.Username,
            targetEntityType: "BackupEncryption",
            details: new { Action = "SetBackupPassword", Mode = "StoredPassword" },
            sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new { message = "Backup encryption password set. New backups will use StoredPassword mode.", mode = "StoredPassword" });
    }

    /// <summary>
    /// Reverts backup encryption from <c>StoredPassword</c> mode back to <c>RandomKey</c> mode.
    /// Requires the random key file (<c>backup.key</c>) to already exist — if it is missing,
    /// the caller must bootstrap or regenerate it first. Deletes the password key file on success.
    /// Requires step-up MFA verification with operation token <c>change-backup-encryption-mode</c>.
    /// </summary>
    /// <returns>Success message with the new mode, or an error response.</returns>
    [HttpPost("encryption/revert-to-random-key")]
    [RequireStepUp(StepUpOps.ChangeBackupEncryptionMode)]
    public async Task<IActionResult> RevertToRandomKey()
    {
        var userId = _currentUser.UserId;
        if (userId == null)
            return Unauthorized(new { error = "Authentication required" });

        var passwordKeyPath = Path.Combine(AppContext.BaseDirectory, _config.Backup?.PasswordFilePath ?? "config/backup-password.key");
        var randomKeyPath = Path.Combine(AppContext.BaseDirectory, _config.Backup?.EncryptionKeyPath ?? "config/backup.key");

        if (!System.IO.File.Exists(randomKeyPath))
            return BadRequest(new { error = "Cannot revert to RandomKey mode: backup.key is missing. Run `--bootstrap` or regenerate the key first." });

        // Delete the password key file (if it exists)
        if (System.IO.File.Exists(passwordKeyPath))
        {
            try { System.IO.File.Delete(passwordKeyPath); }
            catch (Exception ex) { Serilog.Log.Warning(ex, "Failed to delete password key file"); }
        }

        if (_config.Backup != null)
            _config.Backup.EncryptionMode = "RandomKey";
        TryPersistConfig();

        await _audit.LogAsync(
            AuditActionType.ConfigUpdated,
            userId.Value,
            _currentUser.User?.Username,
            targetEntityType: "BackupEncryption",
            details: new { Action = "RevertToRandomKey", Mode = "RandomKey" },
            sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new { message = "Reverted to RandomKey mode. Password file deleted.", mode = "RandomKey" });
    }

    /// <summary>
    /// Persists the current <see cref="SystemConfig"/> to <c>config/config.yaml</c>, matching the
    /// serialization pattern used by <c>AdminConfigController.PersistConfig</c>. Failures are swallowed —
    /// the in-memory change still applies for the running process even if the YAML file is read-only
    /// (e.g. container deployments).
    /// </summary>
    /// <remarks>
    /// The rewrite uses a tempfile + atomic rename and re-applies
    /// <see cref="ModularCA.Shared.Utils.FileSecurityUtil.SetOwnerOnly"/> after the rename so the
    /// tightened ACL on the original file is not lost when this method runs.
    /// </remarks>
    private void TryPersistConfig()
    {
        try
        {
            var configYamlPath = Path.Combine(AppContext.BaseDirectory, "config", "config.yaml");
            if (!System.IO.File.Exists(configYamlPath))
                return;
            var serializer = new SerializerBuilder()
                .WithNamingConvention(PascalCaseNamingConvention.Instance)
                .Build();
            var yaml = serializer.Serialize(_config);

            // Atomic write: stage to sibling tempfile, then File.Move with overwrite.
            var tempPath = configYamlPath + ".tmp-" + Guid.NewGuid().ToString("N");
            System.IO.File.WriteAllText(tempPath, yaml);
            ModularCA.Shared.Utils.FileSecurityUtil.SetOwnerOnly(tempPath);
            System.IO.File.Move(tempPath, configYamlPath, overwrite: true);
            // Re-apply owner-only ACL after the rename — the destination inode was replaced.
            ModularCA.Shared.Utils.FileSecurityUtil.SetOwnerOnly(configYamlPath);
        }
        catch (Exception ex)
        {
            // Don't fail the request — the in-memory config change took effect.
            Serilog.Log.Warning(ex, "Failed to persist backup encryption mode to config.yaml — change is in-memory only until next save");
        }
    }

    /// <summary>
    /// Resolves the backup output directory to an absolute path, using the application base directory
    /// as the root for relative paths.
    /// </summary>
    /// <returns>The absolute path to the backup directory.</returns>
    private string ResolveBackupDirectory()
    {
        var outputPath = _config.Backup.OutputPath;
        if (Path.IsPathRooted(outputPath))
            return outputPath;
        return Path.Combine(AppContext.BaseDirectory, outputPath);
    }

    /// <summary>
    /// Deletes the oldest backup archives when the total count exceeds the configured retention limit.
    /// </summary>
    /// <remarks>
    /// Honours <see cref="BackupConfig.MinimumRetentionDays"/> as a hard floor.
    /// Archives newer than the floor are never deleted, even if the count would otherwise exceed
    /// the configured retention. Each deletion is logged at warning level for forensic timeline
    /// reconstruction (no audit-log dependency injected here, so Serilog is the durable trail).
    /// </remarks>
    /// <param name="backupDir">The directory containing backup archives.</param>
    private void EnforceRetention(string backupDir)
    {
        var retentionCount = _config.Backup.RetentionCount;
        if (retentionCount <= 0) return;

        var retentionDirInfo = new DirectoryInfo(backupDir);
        var files = retentionDirInfo.GetFiles("modularca-backup-*.zip")
            .Concat(retentionDirInfo.GetFiles("modularca-backup-*.enc"))
            .OrderByDescending(f => f.CreationTimeUtc)
            .ToList();

        var minDays = Math.Max(0, _config.Backup.MinimumRetentionDays);
        var floor = DateTime.UtcNow.AddDays(-minDays);

        foreach (var file in files.Skip(retentionCount))
        {
            if (minDays > 0 && file.CreationTimeUtc > floor)
            {
                Serilog.Log.Information(
                    "Backup retention: skipping delete of {FileName} — younger than MinimumRetentionDays={MinDays} floor",
                    file.Name, minDays);
                continue;
            }
            try
            {
                file.Delete();
                Serilog.Log.Warning("Backup retention: deleted {FileName} (retentionCount={Count})", file.Name, retentionCount);
            }
            catch (Exception ex)
            {
                Serilog.Log.Warning(ex, "Backup retention: failed to delete {FileName}", file.Name);
            }
        }
    }
}

/// <summary>
/// Request body for the backup restore endpoint.
/// </summary>
public class RestoreRequest
{
    /// <summary>
    /// The filename of the backup archive to restore (e.g. "modularca-backup-20260410-020000.zip").
    /// Must be a file in the configured backup directory.
    /// </summary>
    public string FileName { get; set; } = string.Empty;

    /// <summary>
    /// Optional backup password for disaster-recovery restoration of <c>StoredPassword</c>-mode
    /// archives. Only consulted when the archive header indicates <c>StoredPassword</c> mode AND
    /// either (a) <c>config/backup-password.key</c> is missing, or (b) the file on disk was rotated
    /// and no longer matches the salt embedded in this specific archive. Leave blank for
    /// <c>RandomKey</c> archives, legacy archives, or when the current password file is expected
    /// to decrypt the archive normally.
    /// </summary>
    public string? Password { get; set; }

    /// <summary>
    /// Single-use confirmation token returned by the <c>/preview-restore</c> endpoint.
    /// Bound to the requesting user and the specific <see cref="FileName"/>; consumed atomically
    /// by the restore call. Required for the destructive restore endpoint, ignored by preview.
    /// </summary>
    public string? ConfirmationToken { get; set; }
}

/// <summary>
/// Response describing the current backup encryption configuration — the active mode,
/// whether each key file is present on disk, and the configured file paths.
/// </summary>
public class BackupEncryptionStatusResponse
{
    /// <summary>The active encryption mode: <c>RandomKey</c> or <c>StoredPassword</c>.</summary>
    public string Mode { get; set; } = "RandomKey";

    /// <summary>True if the password key file (derived KEK) exists on disk.</summary>
    public bool PasswordSet { get; set; }

    /// <summary>True if the random key file exists on disk.</summary>
    public bool RandomKeySet { get; set; }

    /// <summary>The configured relative path to the password key file.</summary>
    public string PasswordFilePath { get; set; } = "";

    /// <summary>The configured relative path to the random key file.</summary>
    public string RandomKeyFilePath { get; set; } = "";
}

/// <summary>
/// Request body for the set-backup-password endpoint. The password is used to derive a KEK
/// via scrypt and is never persisted, logged, or returned in responses.
/// </summary>
public class SetBackupPasswordRequest
{
    /// <summary>The plaintext password to derive the backup KEK from. Validated by <c>BackupKeyManager.ValidatePassword</c>.</summary>
    public string Password { get; set; } = "";
}
