using System.Text.Json;
using ModularCA.HubConnection.Contract;

namespace ModularCA.HubConnection.Server;

/// <summary>
/// What the node does for each request on the hub's local connection. The listener
/// (<see cref="HubLocalHost"/>) owns the wire: the token check, the list of operations, the
/// version, the request identifier and the per-request audit record. This is everything behind it.
/// </summary>
public interface IHubLocalOperations
{
    /// <summary>
    /// The SHA-256 of the affiliation token, 32 bytes, or null while the instance holds none and
    /// the check is off. Read on every request and never cached by the listener, so a replaced
    /// hash is in force for the next request.
    /// </summary>
    byte[]? AffiliationTokenHash { get; }

    /// <summary>The instance's product version.</summary>
    string InstanceVersion { get; }

    /// <summary>
    /// The instance's identifier, for <c>hello</c>: the value a backup's manifest records as its
    /// <c>instanceId</c>. Null when it is not known. Does not throw for an identifier that cannot
    /// be read: that is null too.
    /// </summary>
    /// <param name="cancellationToken">Cancels the read.</param>
    Task<string?> ReadInstanceIdAsync(CancellationToken cancellationToken);

    /// <summary>
    /// SHA-256 of the system key's public key (SubjectPublicKeyInfo), lower-case hex, for
    /// <c>hello</c>'s <c>systemKey</c>. Null when it is not known. Does not throw for a key that
    /// cannot be read: that is null too.
    /// </summary>
    /// <param name="cancellationToken">Cancels the read.</param>
    Task<string?> ReadSystemKeyAsync(CancellationToken cancellationToken) => Task.FromResult<string?>(null);

    /// <summary>Runs the instance's readiness checks.</summary>
    /// <param name="cancellationToken">Cancels the read.</param>
    Task<HubHealthReport> ReadHealthAsync(CancellationToken cancellationToken);

    /// <summary>The mode now and who set it.</summary>
    Task<HubMode> ReadModeAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Sets the mode as the hub, recording it in the audit trail with the operator name the hub
    /// claimed. Throws <see cref="ArgumentException"/> when <paramref name="mode"/> is not a mode.
    /// </summary>
    /// <param name="mode"><c>full</c>, <c>restricted</c> or <c>dr</c>.</param>
    /// <param name="reason">The reason the hub gave, if any.</param>
    /// <param name="operatorName">The operator name the hub claimed, if any.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    Task<HubMode> SetModeAsync(string mode, string? reason, string? operatorName, CancellationToken cancellationToken);

    /// <summary>Writes a backup now. Throws when the backup does not complete.</summary>
    /// <param name="operatorName">The operator name the hub claimed, if any.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    Task<HubBackupResult> CreateBackupAsync(string? operatorName, CancellationToken cancellationToken);

    /// <summary>Replaces the hash of the affiliation token and keeps it with the instance's data.</summary>
    /// <param name="newTokenSha256">The new hash, 32 bytes.</param>
    /// <param name="operatorName">The operator name the hub claimed, if any.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    Task ReplaceAffiliationTokenAsync(byte[] newTokenSha256, string? operatorName, CancellationToken cancellationToken);

    /// <summary>
    /// Reads the inventory: what the instance already knows about its versions, signer, web TLS
    /// certificate, newest backup, failing scheduled jobs and CAs. A read only: it starts no
    /// work, asks the signer nothing, and carries no issued certificate, user, key, secret or
    /// audit entry.
    /// </summary>
    /// <param name="cancellationToken">Cancels the read.</param>
    Task<HubInventory> ReadInventoryAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Deletes old backup archives from the instance's backup directory by the rule its own
    /// scheduled and console backups prune by, and records it in the audit trail as one record.
    /// The newest archive is never deleted. Throws <see cref="ArgumentException"/> when neither
    /// value is given or one is out of range.
    /// </summary>
    /// <param name="keep">How many of the newest archives to keep, or null.</param>
    /// <param name="maxAgeDays">The age in days beyond which an archive is deleted, or null.</param>
    /// <param name="operatorName">The operator name the hub claimed, if any.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    Task<HubPruneBackupsResult> PruneBackupsAsync(int? keep, int? maxAgeDays, string? operatorName, CancellationToken cancellationToken);

    /// <summary>Records one request in the audit trail, under the hub.</summary>
    /// <param name="record">The request and its outcome.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    Task AuditAsync(HubRequestRecord record, CancellationToken cancellationToken);
}

/// <summary>The instance's readiness as its own checks report it.</summary>
/// <param name="Status"><c>healthy</c>, <c>degraded</c> or <c>unhealthy</c>.</param>
/// <param name="Checks">The checks' data, as <c>/health/ready</c> reports it.</param>
public sealed record HubHealthReport(string Status, JsonElement? Checks = null);

/// <summary>One request on the local connection and what became of it, for the audit trail.</summary>
/// <param name="Operation">The operation's name, or null for a request outside the list.</param>
/// <param name="Method">The HTTP method.</param>
/// <param name="Path">The request path.</param>
/// <param name="Status">The HTTP status answered.</param>
/// <param name="Refusal">The error code when the request was refused or failed; null when it was served.</param>
/// <param name="RequestId">The request identifier, when one was given.</param>
/// <param name="OperatorName">The operator name the hub claimed. A claim: the instance cannot check it.</param>
/// <param name="ContractVersion">The contract version the hub stated.</param>
/// <param name="Replayed">True when the answer repeats an earlier one and nothing was done again.</param>
/// <param name="TokenCheck"><c>enforced</c> or <c>off</c> at the time of the request.</param>
public sealed record HubRequestRecord(
    string? Operation,
    string Method,
    string Path,
    int Status,
    string? Refusal,
    string? RequestId,
    string? OperatorName,
    string? ContractVersion,
    bool Replayed,
    string TokenCheck);
