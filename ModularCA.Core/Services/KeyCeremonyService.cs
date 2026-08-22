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
/// 24-hour expiry, and permanent audit trails.
/// </summary>
public class KeyCeremonyService : IKeyCeremonyService
{
    private readonly ModularCADbContext _db;
    private readonly IAuditService _audit;

    /// <summary>
    /// Initializes a new instance of <see cref="KeyCeremonyService"/>.
    /// </summary>
    public KeyCeremonyService(ModularCADbContext db, IAuditService audit)
    {
        _db = db;
        _audit = audit;
    }

    /// <inheritdoc />
    public async Task<KeyCeremonyEntity> InitiateAsync(
        string operationType,
        string description,
        string targetEntityId,
        Guid initiatorUserId,
        string initiatorUsername,
        string parametersJson,
        int? quorumOverride = null)
    {
        // Extract tenant ID from parameters for quorum resolution
        Guid? tenantId = null;
        if (!string.IsNullOrEmpty(parametersJson))
        {
            try
            {
                var parameters = JsonSerializer.Deserialize<ModularCA.Shared.Models.KeyCeremonyParameters>(parametersJson, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                tenantId = parameters?.TenantId;
            }
            catch { /* Fall through to default quorum */ }
        }
        var quorum = quorumOverride ?? await ResolveQuorumAsync(operationType, targetEntityId, tenantId);

        // Minimum quorum is 1: since self-approval is blocked, a quorum of 1 still
        // requires at least one other person to approve. A quorum of 0 would auto-approve
        // (bypassing the ceremony purpose), so we clamp to at least 1.
        if (quorum < 1)
            quorum = 1;

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
            TenantId = tenantId
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
            throw new InvalidOperationException($"Ceremony must be in Approved status to execute (current: {ceremony.Status}).");

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
    public async Task<List<KeyCeremonyEntity>> ListByTenantsAsync(IEnumerable<Guid> tenantIds, string? statusFilter = null)
    {
        var ids = tenantIds.ToList();
        var query = _db.KeyCeremonies.AsNoTracking()
            .Where(c => c.TenantId != null && ids.Contains(c.TenantId.Value));

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
    /// Resolves the raw quorum from the tenant or CA admin group. The caller clamps the
    /// result to a minimum of 2 (initiator + at least one approver, since self-approval
    /// is blocked).
    /// </summary>
    private async Task<int> ResolveQuorumAsync(string operationType, string targetEntityId, Guid? tenantId)
    {
        // For new CA creation, use the tenant-level ceremony approval count
        // since the target CA (and its admin group) don't exist yet. TenantPolicyChange
        // is also tenant-scoped and uses the same tenant-level quorum.
        if (operationType is "CreateRootCA" or "CreateIntermediateCA" or "CreateSshCa" or "DeleteSshCa" or "RevokeCa" or "TenantPolicyChange" && tenantId.HasValue)
        {
            var tenant = await _db.Tenants.AsNoTracking().FirstOrDefaultAsync(t => t.Id == tenantId.Value);
            if (tenant != null)
                return Math.Max(1, tenant.CeremonyRequiredApprovals);
        }

        // For existing CA operations, use the CA's admin group quorum
        if (Guid.TryParse(targetEntityId, out var caId))
        {
            var adminGroup = await _db.CaGroups
                .AsNoTracking()
                .Where(g => g.CertificateAuthorityId == caId
                    && g.Grants.Any(gr => gr.Capability == Capabilities.CaManage && gr.ResourceType == null))
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
