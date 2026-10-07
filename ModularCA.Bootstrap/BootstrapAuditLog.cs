using System.Text.Json;
using ModularCA.Shared.Utils;

namespace ModularCA.Bootstrap;

/// <summary>
/// Minimal, write-only JSON-lines audit sink used by the
/// bootstrap pipeline. Bootstrap writes keystores and issues the root CA before
/// the audit database is reachable, so audit events are appended to
/// <c>logs/bootstrap-audit-{yyyyMMdd}.jsonl</c> and later replayed into the
/// audit database by <see cref="ModularCA.Core.Services.BootstrapAuditReplayService"/>
/// on the first successful startup connection.
/// </summary>
/// <remarks>
/// The sink is intentionally simple: each call writes one JSON object per line,
/// then tightens the file to owner-only via
/// <see cref="FileSecurityUtil.SetOwnerOnly(string)"/>. Failures are swallowed
/// so audit-log issues never break the bootstrap itself (the canonical signal
/// of "audit write failed" remains the runtime audit path).
/// </remarks>
public static class BootstrapAuditLog
{
    private static readonly string InstanceId = Guid.NewGuid().ToString("N");
    private static readonly object WriteLock = new();

    /// <summary>The directory the file is written to; null for <c>logs/</c> under the application directory.</summary>
    internal static string? LogDirectory { get; set; }

    /// <summary>
    /// Appends a keystore-related audit entry to today's bootstrap-audit JSONL file.
    /// </summary>
    /// <param name="keystoreName">Logical keystore file name (e.g. <c>ca-certs.keystore</c>).</param>
    /// <param name="action">Audit action type (see <c>AuditActionType.Keystore*</c> constants).</param>
    /// <param name="subjectDn">Optional subject DN for the primary cert/key involved.</param>
    /// <param name="thumbprint">Optional SHA-256 thumbprint (hex) for the primary cert involved.</param>
    public static void LogKeystoreWrite(
        string keystoreName,
        string action,
        string? subjectDn = null,
        string? thumbprint = null)
        => Append(new
        {
            timestamp = DateTime.UtcNow.ToString("o"),
            action,
            keystoreName,
            subjectDn,
            thumbprint,
            instanceId = InstanceId,
        });

    /// <summary>
    /// Appends a setup decision (something the operator chose during bootstrap) to today's
    /// bootstrap-audit JSONL file, to be replayed against <paramref name="targetEntityType"/>
    /// and <paramref name="targetEntityId"/> with <paramref name="details"/>. Property names in
    /// <paramref name="details"/> that the audit scrubber redacts (any containing "key") lose
    /// their values on replay.
    /// </summary>
    public static void LogSetupDecision(string action, string targetEntityType, string? targetEntityId, object details)
        => Append(new
        {
            timestamp = DateTime.UtcNow.ToString("o"),
            action,
            targetEntityType,
            targetEntityId,
            details,
            instanceId = InstanceId,
        });

    private static void Append(object entry)
    {
        try
        {
            var logsDir = LogDirectory ?? Path.Combine(AppContext.BaseDirectory, "logs");
            Directory.CreateDirectory(logsDir);

            var fileName = $"bootstrap-audit-{DateTime.UtcNow:yyyyMMdd}.jsonl";
            var filePath = Path.Combine(logsDir, fileName);

            var line = JsonSerializer.Serialize(entry);

            lock (WriteLock)
            {
                File.AppendAllText(filePath, line + Environment.NewLine);
                try
                {
                    FileSecurityUtil.SetOwnerOnly(filePath);
                }
                catch
                {
                    // Best-effort ACL tightening — failure here should never break bootstrap.
                }
            }
        }
        catch
        {
            // Never let audit log failures escalate out of bootstrap.
        }
    }
}
