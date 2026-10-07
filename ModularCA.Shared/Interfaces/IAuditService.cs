namespace ModularCA.Shared.Interfaces;

/// <summary>
/// Records audit log entries for security-sensitive operations.
/// </summary>
public interface IAuditService
{
    /// <summary>
    /// Logs an audit event with actor, action, target, and outcome details.
    /// </summary>
    /// <param name="certificateAuthorityId">Optional CA scope for the audit event. Null for system-wide events.</param>
    /// <param name="spaceId">Optional space scope for the audit event. Null for system-wide events.</param>
    Task LogAsync(
        string actionType,
        Guid? actorUserId,
        string? actorUsername,
        string? targetEntityType = null,
        string? targetEntityId = null,
        object? details = null,
        string? sourceIp = null,
        bool success = true,
        string? errorMessage = null,
        Guid? certificateAuthorityId = null,
        Guid? spaceId = null);
}
