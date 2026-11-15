namespace ModularCA.Shared.Models;

/// <summary>
/// The instance's mode as the console shows it: the mode, who set it and when. Returned by
/// <c>GET /api/v1/admin/instance-mode</c> and by a successful <c>PUT</c> there.
/// </summary>
public class InstanceModeStatus
{
    /// <summary>The mode: <c>full</c>, <c>restricted</c> or <c>dr</c>.</summary>
    public string Mode { get; set; } = "full";

    /// <summary>
    /// Who set it: <c>default</c> (nobody; no hub and nothing recorded), <c>start</c> (the start
    /// rule of an instance with a hub connection), <c>hub</c>, <c>administrator</c>, or
    /// <c>unreadable</c> (the record on this host could not be read, so the instance holds itself restricted).
    /// </summary>
    public string Source { get; set; } = "default";

    /// <summary>The administrator's username, or the operator name the hub claimed. Null when nobody was named.</summary>
    public string? SetBy { get; set; }

    /// <summary>The reason given when it was set.</summary>
    public string? Reason { get; set; }

    /// <summary>When it was set (UTC). Null when it never was.</summary>
    public DateTime? SetAtUtc { get; set; }

    /// <summary>Whether this instance has a hub connection configured, so a hub may set the mode too.</summary>
    public bool HubConnection { get; set; }

    /// <summary>What still works in this mode, as plain sentences.</summary>
    public string StillWorks { get; set; } = string.Empty;

    /// <summary>
    /// In a mode that signs no new CRL (DR mode): the earliest <c>nextUpdate</c> among the newest
    /// full CRLs of the instance's enabled CAs. From that moment a relying party that checks the
    /// CRL sees an expired one, until the mode is lifted. Null in every other mode, and when no
    /// CRL has been signed.
    /// </summary>
    public DateTime? CrlsExpireFromUtc { get; set; }
}

/// <summary>The body of <c>PUT /api/v1/admin/instance-mode</c>.</summary>
public class SetInstanceModeRequest
{
    /// <summary>The mode to set: <c>full</c>, <c>restricted</c> or <c>dr</c>.</summary>
    public string Mode { get; set; } = string.Empty;

    /// <summary>Why. Required; it is recorded in the audit trail and shown beside the mode.</summary>
    public string Reason { get; set; } = string.Empty;
}
