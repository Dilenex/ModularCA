using System.Text.Json;
using Microsoft.Extensions.Logging;
using ModularCA.Shared.Interfaces;

namespace ModularCA.Core.Services;

/// <summary>
/// One-shot startup hook that drains any
/// <c>logs/bootstrap-audit-*.jsonl</c> files left by the bootstrap pipeline
/// (where audit writes must be deferred because the audit DB is not yet
/// reachable) and replays each line as a real <see cref="IAuditService.LogAsync"/>
/// call. Drained files are renamed to <c>{file}.replayed</c> so re-runs are
/// idempotent. A replay failure is logged but never blocks startup.
/// </summary>
/// <remarks>
/// This is intentionally NOT an <see cref="Microsoft.Extensions.Hosting.IHostedService"/>
/// or background service — it's a single call made from <c>StartModularCA.cs</c>
/// after the audit <c>DbContext</c> is resolvable and before <c>app.Run()</c>.
/// </remarks>
public sealed class BootstrapAuditReplayService(
    IAuditService auditService,
    ILogger<BootstrapAuditReplayService> logger)
{
    /// <summary>
    /// Scans the local <c>logs/</c> directory for <c>bootstrap-audit-*.jsonl</c>
    /// files, replays every non-empty JSON line as an audit-DB entry via
    /// <see cref="IAuditService.LogAsync"/>, then renames the source file with a
    /// <c>.replayed</c> suffix. Exceptions are caught and logged so a replay
    /// failure does not block application startup.
    /// </summary>
    public Task ReplayPendingAsync(CancellationToken cancellationToken = default)
        => ReplayPendingAsync(Path.Combine(AppContext.BaseDirectory, "logs"), cancellationToken);

    /// <summary><see cref="ReplayPendingAsync(CancellationToken)"/> over <paramref name="logsDir"/>.</summary>
    internal async Task ReplayPendingAsync(string logsDir, CancellationToken cancellationToken = default)
    {
        try
        {
            if (!Directory.Exists(logsDir))
            {
                return;
            }

            var files = Directory.GetFiles(logsDir, "bootstrap-audit-*.jsonl");
            if (files.Length == 0)
            {
                return;
            }

            foreach (var file in files)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    return;
                }

                try
                {
                    await ReplayFileAsync(file, cancellationToken);
                    var replayedPath = file + ".replayed";
                    // If a prior half-finished replay exists, overwrite it.
                    if (File.Exists(replayedPath))
                    {
                        File.Delete(replayedPath);
                    }
                    File.Move(file, replayedPath);
                    logger.LogInformation(
                        "Replayed bootstrap audit file {File} into audit DB ({Replayed})",
                        Path.GetFileName(file), Path.GetFileName(replayedPath));
                }
                catch (Exception ex)
                {
                    logger.LogWarning(ex,
                        "Failed to replay bootstrap audit file {File}; leaving in place for retry on next startup",
                        file);
                }
            }
        }
        catch (Exception ex)
        {
            // Never escalate: a broken replay must not stop the CA from starting.
            logger.LogWarning(ex, "BootstrapAuditReplayService encountered an error during scan");
        }
    }

    // The writers emit camelCase keys; read without regard to case, or every line binds to nothing
    // and is skipped.
    private static readonly JsonSerializerOptions LineOptions = new() { PropertyNameCaseInsensitive = true };

    /// <summary>
    /// Replays one file. A keystore line is logged against its keystore, as a failure with its
    /// detail when the writer recorded one; a setup decision against the target it names, with its
    /// own details.
    /// </summary>
    private async Task ReplayFileAsync(string filePath, CancellationToken cancellationToken)
    {
        var lines = await File.ReadAllLinesAsync(filePath, cancellationToken);
        foreach (var line in lines)
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            BootstrapAuditEntry? entry = null;
            try
            {
                entry = JsonSerializer.Deserialize<BootstrapAuditEntry>(line, LineOptions);
            }
            catch (JsonException ex)
            {
                logger.LogWarning(ex,
                    "Skipping malformed bootstrap audit line in {File}: {Line}",
                    Path.GetFileName(filePath), line);
                continue;
            }

            if (entry is null || string.IsNullOrWhiteSpace(entry.Action))
            {
                continue;
            }

            // A setup decision names its own target and carries its own details.
            if (!string.IsNullOrWhiteSpace(entry.TargetEntityType))
            {
                await auditService.LogAsync(
                    actionType: entry.Action,
                    actorUserId: null,
                    actorUsername: "system-bootstrap",
                    targetEntityType: entry.TargetEntityType,
                    targetEntityId: entry.TargetEntityId,
                    details: new
                    {
                        ReplayedFromBootstrap = true,
                        BootstrapTimestamp = entry.Timestamp,
                        entry.InstanceId,
                        Decision = entry.Details,
                    },
                    sourceIp: "local",
                    success: true);
                continue;
            }

            await auditService.LogAsync(
                actionType: entry.Action,
                actorUserId: null,
                actorUsername: "system-bootstrap",
                targetEntityType: "Keystore",
                targetEntityId: entry.KeystoreName,
                details: new
                {
                    ReplayedFromBootstrap = true,
                    BootstrapTimestamp = entry.Timestamp,
                    entry.InstanceId,
                    entry.SubjectDn,
                    entry.Thumbprint,
                    entry.Detail,
                },
                sourceIp: "local",
                success: entry.Success ?? true,
                errorMessage: entry.Success == false ? entry.Detail : null);
        }
    }

    private sealed class BootstrapAuditEntry
    {
        public string? Timestamp { get; set; }
        public string? Action { get; set; }
        public string? KeystoreName { get; set; }
        public string? SubjectDn { get; set; }
        public string? Thumbprint { get; set; }
        public string? InstanceId { get; set; }
        public bool? Success { get; set; }
        public string? Detail { get; set; }
        public string? TargetEntityType { get; set; }
        public string? TargetEntityId { get; set; }
        public JsonElement? Details { get; set; }
    }
}
