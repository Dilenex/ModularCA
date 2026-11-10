using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;

namespace ModularCA.Bootstrap;

/// <summary>
/// The bootstrap's last audit step: writes the records its earlier steps queued in
/// <c>logs/bootstrap-audit-*.jsonl</c> (<see cref="BootstrapAuditLog"/>, and the keystore
/// service's own events) into the audit database itself, before the process exits.
/// </summary>
/// <remarks>
/// <para>
/// Those steps run where no audit service is at hand, some of them before the audit schema
/// exists, so they queue to a file. They used to wait there for the node's first start. That
/// only works where the bootstrap's <c>logs/</c> is also the node's: a bootstrap run in an init
/// container (the pod) loses the directory when it exits, and the records with it. By the end of
/// the bootstrap the audit schema has long been applied
/// (<see cref="BootstrapDatabaseSetup.ApplySchemasAsync"/>), so the bootstrap drains the file
/// here, through the same <see cref="BootstrapAuditReplayService"/> the node uses: the rows are
/// the ones the node would have written, by the same actor, on the same hash chain. It holds for
/// every install type because it depends on nothing but the audit database.
/// </para>
/// <para>
/// The file stays the fallback. When the audit database refuses, the bootstrap is not failed for
/// it: what was not written is moved, file by file and under the same names, into
/// <c>config/audit-pending/</c> (<see cref="BootstrapAuditReplayService.PendingDirectory"/>),
/// owner-only, which every install type keeps and the node replays from at each start, and a
/// warning says so. <c>logs/</c> would not do: the pod's bootstrap container mounts the
/// configuration volume and no log volume. Lines already written are recognised by their id,
/// which a move does not change, and are not written twice. The files hold no secret
/// (<see cref="BootstrapAuditLog"/>).
/// </para>
/// </remarks>
public static class BootstrapAuditDrain
{
    /// <summary>
    /// Replays the pending bootstrap audit files into the audit database, with a failed write
    /// treated as a failure (the audit service's fail-closed mode) so that nothing is marked
    /// replayed that is not in the trail. Files that could not be drained are moved into
    /// <paramref name="pendingDirectory"/> for the node.
    /// </summary>
    /// <param name="openAuditDb">Opens the audit database as the audit role; the context is disposed here.</param>
    /// <param name="output">Where the outcome is written. Nothing is written when nothing was queued.</param>
    /// <param name="pendingDirectory">
    /// Where files the audit database refused are kept for the node:
    /// <c>config/audit-pending</c>. Null leaves them in <c>logs/</c>.
    /// </param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>True when no queued record is left outside the audit database.</returns>
    public static async Task<bool> RunAsync(
        Func<AuditDbContext> openAuditDb, TextWriter output, string? pendingDirectory = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(openAuditDb);
        ArgumentNullException.ThrowIfNull(output);

        var logsDir = BootstrapAuditLog.LogDirectory ?? Path.Combine(AppContext.BaseDirectory, "logs");
        BootstrapAuditReplayResult result;
        try
        {
            if (!Directory.Exists(logsDir) || Directory.GetFiles(logsDir, "bootstrap-audit-*.jsonl").Length == 0)
                return true;

            await using var auditDb = openAuditDb();
            var failClosed = new SystemConfig();
            failClosed.Audit.FailMode = AuditFailMode.FailClosed;
            var audit = new AuditService(
                NullLogger<AuditService>.Instance, auditDb, failClosed, hashChain: new AuditHashChainService());
            result = await new BootstrapAuditReplayService(
                audit, NullLogger<BootstrapAuditReplayService>.Instance, auditDb).ReplayPendingAsync(logsDir, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            result = new BootstrapAuditReplayResult(0, 0, 0, [$"{ex.GetType().Name}: {ex.Message}"]);
        }

        if (result.Recorded > 0)
            output.WriteLine($"✓ {result.Recorded} setup record(s) written to the audit trail.");
        if (result.Failures.Count == 0)
            return true;

        output.WriteLine("[WARNING] Some setup records could not be written to the audit database:");
        foreach (var failure in result.Failures)
            output.WriteLine($"          {failure}");

        var left = pendingDirectory == null ? PendingIn(logsDir) : KeepForTheNode(logsDir, pendingDirectory, output);
        if (pendingDirectory != null && left.Length == 0)
        {
            output.WriteLine($"          They are kept in {pendingDirectory} and are recorded when the node next starts.");
        }
        else
        {
            output.WriteLine("          They stay queued in logs/bootstrap-audit-*.jsonl and are recorded when the node first starts;");
            output.WriteLine("          if that directory is not kept (an init container), they are lost: note by hand what this run set up.");
        }
        return false;
    }

    private static string[] PendingIn(string logsDir)
        => Directory.Exists(logsDir) ? Directory.GetFiles(logsDir, "bootstrap-audit-*.jsonl") : [];

    /// <summary>
    /// Moves the files still pending in <paramref name="logsDir"/> into
    /// <paramref name="pendingDirectory"/>, created for its owner alone, each under its own name:
    /// a line's id is derived from its file's name, so a renamed file would be recorded again.
    /// When a file of that name already waits there (an earlier run, the same day), the new one
    /// goes into a numbered directory under it, which the node also replays. Returns the files
    /// that could not be moved, after saying why.
    /// </summary>
    private static string[] KeepForTheNode(string logsDir, string pendingDirectory, TextWriter output)
    {
        try
        {
            FileSecurityUtil.EnsureOwnerOnlyDirectory(pendingDirectory, tightenExisting: true);
            foreach (var file in PendingIn(logsDir).Order(StringComparer.Ordinal))
            {
                var directory = pendingDirectory;
                for (var n = 1; File.Exists(Path.Combine(directory, Path.GetFileName(file))); n++)
                {
                    directory = Path.Combine(pendingDirectory, n.ToString(System.Globalization.CultureInfo.InvariantCulture));
                    FileSecurityUtil.EnsureOwnerOnlyDirectory(directory, tightenExisting: true);
                }
                var target = Path.Combine(directory, Path.GetFileName(file));
                File.Move(file, target);
                FileSecurityUtil.SetOwnerOnly(target);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            output.WriteLine($"          They could not be moved to {pendingDirectory}: {ex.Message}");
        }
        return PendingIn(logsDir);
    }
}
