using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Utils;

namespace ModularCA.Core.Services;

/// <summary>
/// Manages key ceremony workflows for catastrophic CA operations.
/// Enforces quorum-based multi-party approval, self-approval prevention,
/// 24-hour expiry, and permanent audit trails. A ceremony that could never reach its quorum is
/// refused at initiation (<see cref="ICeremonyQuorumGuard"/>).
/// </summary>
public class KeyCeremonyService : IKeyCeremonyService
{
    private readonly ModularCADbContext _db;
    private readonly IAuditService _audit;
    private readonly IEffectivePolicyResolver _policies;
    private readonly ICeremonyQuorumGuard _quorumGuard;

    /// <summary>
    /// Initializes a new instance of <see cref="KeyCeremonyService"/>. <paramref name="policies"/>
    /// resolves scope quorums and <paramref name="quorumGuard"/> refuses ceremonies nobody could
    /// approve; each defaults to one over <paramref name="db"/>.
    /// </summary>
    public KeyCeremonyService(ModularCADbContext db, IAuditService audit, IEffectivePolicyResolver? policies = null, ICeremonyQuorumGuard? quorumGuard = null)
    {
        _db = db;
        _audit = audit;
        _policies = policies ?? new EffectivePolicyResolver(db);
        _quorumGuard = quorumGuard ?? new CeremonyQuorumGuard(db);
    }

    /// <summary>
    /// Opens a ceremony, or throws <see cref="ModularCA.Shared.Errors.CeremonyQuorumUnreachableException"/>
    /// and creates nothing when fewer accounts other than the initiator could approve it than its
    /// quorum needs. Every initiation path ends here, so this is the one place that check is made.
    /// </summary>
    public async Task<KeyCeremonyEntity> InitiateAsync(
        string operationType,
        string description,
        string targetEntityId,
        Guid initiatorUserId,
        string initiatorUsername,
        string parametersJson,
        int? quorumOverride = null)
    {
        // A legacy scope key throws rather than reading as the instance.
        Guid? spaceId = string.IsNullOrEmpty(parametersJson)
            ? null
            : ModularCA.Shared.Models.CeremonyParametersJson.ReadSpaceId(parametersJson);
        var quorum = quorumOverride ?? await ResolveQuorumAsync(operationType, targetEntityId, spaceId);

        // Minimum quorum is 1: since self-approval is blocked, a quorum of 1 still
        // requires at least one other person to approve. A quorum of 0 would auto-approve
        // (bypassing the ceremony purpose), so we clamp to at least 1.
        if (quorum < 1)
            quorum = 1;

        await _quorumGuard.EnsureReachableAsync(operationType, spaceId, parametersJson, initiatorUserId, quorum);

        var ceremony = new KeyCeremonyEntity
        {
            OperationType = operationType,
            Description = description,
            TargetEntityId = targetEntityId,
            InitiatedByUserId = initiatorUserId,
            InitiatedByUsername = initiatorUsername,
            RequiredApprovals = quorum,
            CurrentApprovals = 0,
            Status = "Pending",
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddHours(24),
            ParametersJson = parametersJson,
            ApprovalsJson = "[]",
            SpaceId = spaceId
        };

        _db.KeyCeremonies.Add(ceremony);
        await _db.SaveChangesAsync();

        await _audit.LogAsync(
            AuditActionType.KeyCeremonyInitiated,
            initiatorUserId,
            initiatorUsername,
            "KeyCeremony",
            ceremony.Id.ToString(),
            new { operationType, description, targetEntityId, quorum, autoApproved = quorum <= 1 });

        return ceremony;
    }

    /// <inheritdoc />
    public async Task<KeyCeremonyEntity> ApproveAsync(Guid ceremonyId, Guid approverId, string approverUsername)
    {
        var ceremony = await _db.KeyCeremonies.FindAsync(ceremonyId)
            ?? throw new InvalidOperationException("Ceremony not found.");

        if (ceremony.Status != "Pending")
            throw new InvalidOperationException($"Ceremony is not pending (current status: {ceremony.Status}).");

        if (ceremony.ExpiresAt <= DateTime.UtcNow)
        {
            ceremony.Status = "Expired";
            await _db.SaveChangesAsync();
            throw new InvalidOperationException("Ceremony has expired.");
        }

        if (ceremony.InitiatedByUserId == approverId)
            throw new InvalidOperationException("Self-approval is forbidden. The initiator cannot approve their own ceremony.");

        var approvals = DeserializeApprovals(ceremony.ApprovalsJson);

        if (approvals.Any(a => a.UserId == approverId))
            throw new InvalidOperationException("This user has already approved this ceremony.");

        approvals.Add(new ApprovalRecord
        {
            UserId = approverId,
            Username = approverUsername,
            Timestamp = DateTime.UtcNow,
            Decision = "Approved"
        });

        ceremony.ApprovalsJson = JsonSerializer.Serialize(approvals, SafeJsonOptions.Stored);
        ceremony.CurrentApprovals = approvals.Count(a => a.Decision == "Approved");

        if (ceremony.CurrentApprovals >= ceremony.RequiredApprovals)
            ceremony.Status = "Approved";

        await _db.SaveChangesAsync();

        await _audit.LogAsync(
            AuditActionType.KeyCeremonyApproved,
            approverId,
            approverUsername,
            "KeyCeremony",
            ceremonyId.ToString(),
            new { ceremony.CurrentApprovals, ceremony.RequiredApprovals, ceremony.Status });

        return ceremony;
    }

    /// <inheritdoc />
    public async Task<KeyCeremonyEntity> RejectAsync(Guid ceremonyId, Guid rejectorId, string rejectorUsername)
    {
        var ceremony = await _db.KeyCeremonies.FindAsync(ceremonyId)
            ?? throw new InvalidOperationException("Ceremony not found.");

        if (ceremony.Status != "Pending")
            throw new InvalidOperationException($"Ceremony is not pending (current status: {ceremony.Status}).");

        var approvals = DeserializeApprovals(ceremony.ApprovalsJson);
        approvals.Add(new ApprovalRecord
        {
            UserId = rejectorId,
            Username = rejectorUsername,
            Timestamp = DateTime.UtcNow,
            Decision = "Rejected"
        });

        ceremony.ApprovalsJson = JsonSerializer.Serialize(approvals, SafeJsonOptions.Stored);
        ceremony.Status = "Rejected";
        await _db.SaveChangesAsync();

        await _audit.LogAsync(
            AuditActionType.KeyCeremonyRejected,
            rejectorId,
            rejectorUsername,
            "KeyCeremony",
            ceremonyId.ToString(),
            new { ceremony.OperationType, ceremony.TargetEntityId });

        return ceremony;
    }

    /// <inheritdoc />
    public async Task<KeyCeremonyEntity> CancelAsync(Guid ceremonyId, Guid requestorId)
    {
        var ceremony = await _db.KeyCeremonies.FindAsync(ceremonyId)
            ?? throw new InvalidOperationException("Ceremony not found.");

        if (ceremony.Status != "Pending")
            throw new InvalidOperationException($"Ceremony is not pending (current status: {ceremony.Status}).");

        if (ceremony.InitiatedByUserId != requestorId)
            throw new UnauthorizedAccessException("Only the initiator can cancel a ceremony.");

        ceremony.Status = "Cancelled";
        await _db.SaveChangesAsync();

        await _audit.LogAsync(
            AuditActionType.KeyCeremonyCancelled,
            requestorId,
            ceremony.InitiatedByUsername,
            "KeyCeremony",
            ceremonyId.ToString(),
            new { ceremony.OperationType, ceremony.TargetEntityId });

        return ceremony;
    }

    /// <inheritdoc />
    public async Task MarkExecutedAsync(Guid ceremonyId)
    {
        var ceremony = await _db.KeyCeremonies.FindAsync(ceremonyId)
            ?? throw new InvalidOperationException("Ceremony not found.");

        if (ceremony.Status != "Approved")
            throw new CeremonyNotExecutableException(ceremonyId, ceremony.Status);

        ceremony.Status = "Executed";
        ceremony.ExecutedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync();

        await _audit.LogAsync(
            AuditActionType.KeyCeremonyExecuted,
            ceremony.InitiatedByUserId,
            ceremony.InitiatedByUsername,
            "KeyCeremony",
            ceremonyId.ToString(),
            new { ceremony.OperationType, ceremony.TargetEntityId });
    }

    /// <summary>
    /// Takes a PostgreSQL session advisory lock keyed on the ceremony, on this context's connection,
    /// which stays open until the handle is disposed. An advisory lock rather than a row lock, because
    /// CA creation runs outside any one transaction and the signer must still read the ceremony as
    /// Approved while it does. Providers without advisory locks (unit tests) get a no-op handle.
    /// </summary>
    public async Task<IAsyncDisposable?> TryAcquireExecutionLockAsync(Guid ceremonyId)
    {
        if (!_db.Database.IsNpgsql())
            return new ExecutionLock(null);

        var key = ExecutionLockKey(ceremonyId);
        await _db.Database.OpenConnectionAsync();
        var acquired = await _db.Database
            .SqlQuery<bool>($"SELECT pg_try_advisory_lock({ExecutionLockNamespace}, {key}) AS \"Value\"")
            .SingleAsync();
        if (!acquired)
        {
            await _db.Database.CloseConnectionAsync();
            return null;
        }
        return new ExecutionLock(async () =>
        {
            try
            {
                await _db.Database.ExecuteSqlInterpolatedAsync($"SELECT pg_advisory_unlock({ExecutionLockNamespace}, {key})");
            }
            finally
            {
                await _db.Database.CloseConnectionAsync();
            }
        });
    }

    private const int ExecutionLockNamespace = 0x4B434558;

    private static int ExecutionLockKey(Guid ceremonyId)
    {
        var bytes = ceremonyId.ToByteArray();
        return BitConverter.ToInt32(bytes, 0) ^ BitConverter.ToInt32(bytes, 4) ^ BitConverter.ToInt32(bytes, 8) ^ BitConverter.ToInt32(bytes, 12);
    }

    private sealed class ExecutionLock(Func<Task>? release) : IAsyncDisposable
    {
        private Func<Task>? _release = release;

        public async ValueTask DisposeAsync()
        {
            var release = Interlocked.Exchange(ref _release, null);
            if (release != null) await release();
        }
    }

    /// <summary>
    /// Takes a row lock on the ceremony for the rest of the current transaction (PostgreSQL only), so
    /// a second execute waits and then reads the first one's committed status. A no-op elsewhere.
    /// </summary>
    public static async Task LockRowAsync(ModularCADbContext db, Guid ceremonyId)
    {
        if (db.Database.IsNpgsql())
            await db.Database.ExecuteSqlInterpolatedAsync($"SELECT 1 FROM \"KeyCeremonies\" WHERE \"Id\" = {ceremonyId} FOR UPDATE");
    }

    /// <inheritdoc />
    public async Task<KeyCeremonyEntity?> GetByIdAsync(Guid ceremonyId)
    {
        return await _db.KeyCeremonies.AsNoTracking().FirstOrDefaultAsync(c => c.Id == ceremonyId);
    }

    /// <inheritdoc />
    public async Task<List<KeyCeremonyEntity>> ListAsync(string? statusFilter = null)
    {
        var query = _db.KeyCeremonies.AsNoTracking().AsQueryable();

        if (!string.IsNullOrWhiteSpace(statusFilter))
            query = query.Where(c => c.Status == statusFilter);

        return await query.OrderByDescending(c => c.CreatedAt).ToListAsync();
    }

    /// <inheritdoc />
    public async Task<List<KeyCeremonyEntity>> ListBySpacesAsync(IEnumerable<Guid> spaceIds, string? statusFilter = null, bool includeInstance = false)
    {
        var ids = spaceIds.ToList();
        var query = _db.KeyCeremonies.AsNoTracking()
            .Where(c => (c.SpaceId == null && includeInstance) || (c.SpaceId != null && ids.Contains(c.SpaceId.Value)));

        if (!string.IsNullOrWhiteSpace(statusFilter))
            query = query.Where(c => c.Status == statusFilter);

        return await query.OrderByDescending(c => c.CreatedAt).ToListAsync();
    }

    /// <inheritdoc />
    public async Task<int> ExpireStaleCeremoniesAsync()
    {
        var now = DateTime.UtcNow;
        var stale = await _db.KeyCeremonies
            .Where(c => c.Status == "Pending" && c.ExpiresAt <= now)
            .ToListAsync();

        foreach (var ceremony in stale)
        {
            ceremony.Status = "Expired";

            await _audit.LogAsync(
                AuditActionType.KeyCeremonyExpired,
                ceremony.InitiatedByUserId,
                ceremony.InitiatedByUsername,
                "KeyCeremony",
                ceremony.Id.ToString(),
                new { ceremony.OperationType, ceremony.TargetEntityId });
        }

        if (stale.Count > 0)
            await _db.SaveChangesAsync();

        return stale.Count;
    }

    /// <summary>
    /// Resolves the raw quorum from the scope's policy or the CA admin group. For the scoped
    /// operations a null space means the instance, whose own CeremonyRequiredApprovals applies.
    /// The CA admin group is the CA's <c>Administrator</c>-template group holding <c>ca.manage</c>
    /// (the auto-generated one first); the CA's Operator group also holds <c>ca.manage</c> and
    /// never sets the quorum. The caller clamps the result to a minimum of 1.
    /// </summary>
    private async Task<int> ResolveQuorumAsync(string operationType, string targetEntityId, Guid? spaceId)
    {
        // For new CA creation, use the scope-level ceremony approval count since the target CA
        // (and its admin group) don't exist yet. SpacePolicyChange and InstancePolicyChange are
        // scope-level too and use the same quorum.
        if (operationType is "CreateRootCA" or "CreateIntermediateCA" or "CreateSshCa" or "DeleteSshCa" or "RevokeCa"
            or nameof(CeremonyType.SpacePolicyChange) or nameof(CeremonyType.InstancePolicyChange))
        {
            var policy = await _policies.ResolveAsync(spaceId);
            if (policy.Found)
                return Math.Max(1, policy.CeremonyRequiredApprovals);
        }

        // For existing CA operations, use the CA's admin group quorum
        if (Guid.TryParse(targetEntityId, out var caId))
        {
            var adminGroup = await _db.CaGroups
                .AsNoTracking()
                .Where(g => g.CertificateAuthorityId == caId
                    && g.TemplateName == "Administrator"
                    && g.Grants.Any(gr => gr.Capability == Capabilities.CaManage && gr.ResourceType == null))
                .OrderByDescending(g => g.IsAutoGenerated)
                .ThenBy(g => g.CreatedAt)
                .ThenBy(g => g.Id)
                .FirstOrDefaultAsync();
            if (adminGroup != null)
                return adminGroup.RequiredQuorum;
        }

        return 1;
    }

    /// <summary>
    /// Deserializes the approval records from the ceremony's ApprovalsJson field.
    /// </summary>
    private static List<ApprovalRecord> DeserializeApprovals(string json)
    {
        try
        {
            // SafeJsonOptions.Stored is case-insensitive, so rows written before the camelCase
            // switch (PascalCase keys) and rows written after it both deserialize.
            return JsonSerializer.Deserialize<List<ApprovalRecord>>(json, SafeJsonOptions.Stored) ?? new List<ApprovalRecord>();
        }
        catch
        {
            return new List<ApprovalRecord>();
        }
    }
}

/// <summary>
/// Represents a single approval or rejection record within a key ceremony.
/// </summary>
public class ApprovalRecord
{
    /// <summary>The user ID of the approver/rejector.</summary>
    public Guid UserId { get; set; }

    /// <summary>The username of the approver/rejector.</summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>When the decision was recorded.</summary>
    public DateTime Timestamp { get; set; }

    /// <summary>The decision: "Approved" or "Rejected".</summary>
    public string Decision { get; set; } = string.Empty;
}
