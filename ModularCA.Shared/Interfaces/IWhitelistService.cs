using System.Net;
using ModularCA.Shared.Entities;

namespace ModularCA.Shared.Interfaces;

/// <summary>
/// Result of evaluating a request against the IP whitelist service.
/// </summary>
public enum WhitelistDecision
{
    /// <summary>
    /// A matching rule was found and the client IP is inside its CIDR set.
    /// The middleware should let the request continue down the pipeline.
    /// </summary>
    Allow,

    /// <summary>
    /// A matching rule was found but the client IP is not inside its CIDR
    /// set (or the rule's CIDR set is empty, which denotes an explicit
    /// lockdown). The middleware should respond with 403.
    /// </summary>
    Deny,

    /// <summary>
    /// No rule covers this request at any scope level. The middleware
    /// should pass the request through — the whitelist is an additional
    /// layer, not a universal ACL, so unknown paths rely on JWT / policy.
    /// </summary>
    NotCovered,
}

/// <summary>
/// Centralized IP whitelist service. Owns an in-memory snapshot of the
/// <c>Whitelists</c> table and serves lookup queries from that snapshot
/// to avoid per-request database hits. Also exposes CRUD helpers that
/// wrap the DbContext so controllers don't touch the table directly; the
/// service invalidates and reloads its snapshot after every mutation so
/// middleware sees the new state immediately.
/// </summary>
public interface IWhitelistService
{
    /// <summary>
    /// Whether at least one snapshot has ever been loaded from the database.
    /// </summary>
    /// <remarks>
    /// Distinct from <c>IsWarm</c>: a reload failure clears warmth but keeps the last good
    /// snapshot. The middleware evaluates against that snapshot rather than passing traffic
    /// through, which is what "cold" used to mean for every non-admin path.
    /// </remarks>
    bool HasSnapshot { get; }

    /// <summary>
    /// True once the service has successfully loaded rules from the
    /// database at least once. Starts false at construction time and
    /// stays false if the <c>Whitelists</c> table does not yet exist
    /// (pre-bootstrap), if migrations have not been applied, or if any
    /// reload fails. Middleware inspects this flag to choose between the
    /// snapshot lookup path and the hardcoded
    /// <c>WhitelistDefaults.InternalOnlyCidrs</c> fallback for
    /// <c>/setup/*</c> paths.
    /// </summary>
    bool IsWarm { get; }

    /// <summary>
    /// Re-reads the <c>Whitelists</c> table into the in-memory snapshot
    /// and flips <see cref="IsWarm"/> to true on success. Called once
    /// during startup (after migrations apply), again at the end of
    /// bootstrap (after the seeder runs), and once after every admin CRUD
    /// mutation so the next request sees the new state without waiting
    /// for an app restart.
    /// </summary>
    Task ReloadAsync(CancellationToken ct = default);

    /// <summary>
    /// Evaluates a single request against the snapshot. The middleware
    /// supplies the normalized request path and the already-resolved
    /// client <see cref="IPAddress"/> (may be null if the connection has
    /// no remote endpoint, in which case implementations should return
    /// <see cref="WhitelistDecision.Deny"/> as a safety default). The
    /// evaluator walks scopes from most specific to most general until it
    /// finds an enabled rule; see <c>WhitelistScope</c> for the scope
    /// ordering semantics.
    /// </summary>
    WhitelistDecision Evaluate(string path, IPAddress? remoteIp);

    /// <summary>
    /// Returns every whitelist row in the table, ordered for admin UI
    /// display. Reads directly from the database (not the snapshot) so
    /// the admin UI always sees a fully-consistent list even if the
    /// snapshot is stale between reloads.
    /// </summary>
    Task<List<WhitelistEntity>> GetAllAsync(CancellationToken ct = default);

    /// <summary>
    /// Fetches a single whitelist by primary key, or null if the row does
    /// not exist. Reads directly from the database.
    /// </summary>
    Task<WhitelistEntity?> GetByIdAsync(Guid id, CancellationToken ct = default);

    /// <summary>
    /// Inserts a new whitelist row, calls <c>SaveChangesAsync</c>, and
    /// triggers a <see cref="ReloadAsync(CancellationToken)"/> so the new
    /// rule applies to the next request. Implementations should timestamp
    /// <c>CreatedAt</c> / <c>UpdatedAt</c> automatically.
    /// </summary>
    Task<WhitelistEntity> CreateAsync(WhitelistEntity entity, CancellationToken ct = default);

    /// <summary>
    /// Updates mutable fields on an existing whitelist row (Name,
    /// Description, Scope, CertificateAuthorityId, Protocol, Cidrs,
    /// IsEnabled), bumps <c>UpdatedAt</c>, saves, and reloads the
    /// snapshot. Returns null if no row with <paramref name="id"/>
    /// exists. <c>IsSystemDefault</c> is not mutable via this method.
    /// </summary>
    Task<WhitelistEntity?> UpdateAsync(Guid id, WhitelistEntity updates, CancellationToken ct = default);

    /// <summary>
    /// Deletes a whitelist row and reloads the snapshot. Returns false if
    /// no row with <paramref name="id"/> exists. Implementations should
    /// refuse to delete rows with <c>IsSystemDefault = true</c> — the
    /// controller translates that refusal into a 409 response, but the
    /// service layer is the authoritative enforcement point.
    /// </summary>
    Task<bool> DeleteAsync(Guid id, CancellationToken ct = default);
}
