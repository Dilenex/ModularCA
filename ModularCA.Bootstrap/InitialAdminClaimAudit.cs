using ModularCA.Auth.Services;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Utils;

namespace ModularCA.Bootstrap;

/// <summary>
/// The audit record of the claim the headless bootstrap creates for the first administrator
/// (<c>Administration.ClaimTokenSha256</c> in bootstrap.yaml), so the audit trail says that the
/// account was handed over by claim, and until when, from the moment the instance exists.
/// </summary>
/// <remarks>
/// <para>
/// The bootstrap applies the audit schema before it seeds anything
/// (<see cref="BootstrapDatabaseSetup.ApplySchemasAsync"/>), so the record goes straight into the
/// audit database through <see cref="AuditHashChainService.AppendAsync"/>, the same hash chain
/// every other writer uses, as the host commands that run without the node do. It does not wait
/// in <see cref="BootstrapAuditLog"/> for the node's first start: that file is written under
/// <c>logs/</c>, which a bootstrap run in an init container does not keep.
/// </para>
/// <para>
/// When the audit database refuses the write, the bootstrap is not failed for it (the instance
/// and the claim stand): the record is queued in <see cref="BootstrapAuditLog"/> instead, which
/// the node replays into the audit database at its first start, and a warning says so.
/// </para>
/// </remarks>
public static class InitialAdminClaimAudit
{
    /// <summary>The actor recorded: the bootstrap, the same name the claim's <c>IssuedBy</c> carries.</summary>
    public const string Actor = AccountClaims.IssuedByBootstrap;

    /// <summary>
    /// Records <see cref="AuditActionType.UserClaimTokenIssuedAtBootstrap"/> for
    /// <paramref name="handover"/> when it is a handover by claim; does nothing for a generated
    /// password. The details carry the username, when the claim expires and the host; never the
    /// token (which the bootstrap never sees) or its hash.
    /// </summary>
    /// <param name="openAuditDb">Opens the audit database as the audit role; the context is disposed here.</param>
    /// <param name="handover">How the first administrator was handed over.</param>
    /// <param name="output">Where the outcome is written.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>
    /// True when the record is in the audit database; false when there was nothing to record or the
    /// write failed and the record was queued for the node's first start instead.
    /// </returns>
    public static async Task<bool> RecordAsync(
        Func<AuditDbContext> openAuditDb, InitialAdminHandover handover, TextWriter output, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(openAuditDb);
        ArgumentNullException.ThrowIfNull(handover);
        ArgumentNullException.ThrowIfNull(output);
        if (handover.ClaimExpiresAt is not DateTime expiresAt)
            return false;

        var userId = handover.UserId.ToString();
        var details = new
        {
            handover.Username,
            ExpiresAt = expiresAt,
            Host = Environment.MachineName,
        };
        try
        {
            await using var auditDb = openAuditDb();
            await new AuditHashChainService().AppendAsync(auditDb, new AuditLogEntity
            {
                ActionType = AuditActionType.UserClaimTokenIssuedAtBootstrap,
                ActorUsername = Actor,
                TargetEntityType = "User",
                TargetEntityId = userId,
                DetailsJson = AuditJsonScrubber.SerializeAndScrub(details),
            }, ct);
            output.WriteLine($"✓ The claim for '{handover.Username}' is recorded in the audit trail.");
            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // The instance and the claim stand; the record is replayed by the node's first start.
            BootstrapAuditLog.LogSetupDecision(AuditActionType.UserClaimTokenIssuedAtBootstrap, "User", userId, details);
            output.WriteLine($"[WARNING] The claim for '{handover.Username}' could not be recorded in the audit database ({ex.GetType().Name}: {ex.Message}).");
            output.WriteLine("          It is queued in logs/bootstrap-audit-*.jsonl and recorded when the node first starts;");
            output.WriteLine("          if that directory is not kept (an init container), record by hand that the claim was issued.");
            return false;
        }
    }
}
