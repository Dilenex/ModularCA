namespace ModularCA.Shared.Modes;

/// <summary>
/// What this instance may do right now. An instance with no hub, and nothing set by hand, is
/// always <see cref="Full"/>. The hub sets the mode over its local connection and an
/// administrator sets it in the console; the last writer wins.
/// </summary>
public enum InstanceMode
{
    /// <summary>Everything is allowed. The answer when nothing was ever set.</summary>
    Full = 0,

    /// <summary>
    /// New facts and restrictions only: issuing, revoking, disabling a CA and locking an account
    /// go on; grants, users, roles, profiles, policy, new CAs, key operations, ceremonies,
    /// releasing a hold and un-revoking are frozen until the instance is full again.
    /// </summary>
    Restricted = 1,

    /// <summary>
    /// DR mode. The instance's data is treated as locked: nothing is issued or revoked, no new
    /// CRL is signed and OCSP reports itself unavailable. A CRL that is already signed is still
    /// served, and an administrator can still sign in to manage and repair the instance, which
    /// includes changing the mode.
    /// </summary>
    DisasterRecovery = 2,

    /// <summary>
    /// Maintenance: for an instance that is being updated or audited. Nothing is issued, and
    /// nothing that changes how the instance is run is accepted; revoking, signing CRLs and
    /// answering OCSP go on, because a relying party must still be able to check a certificate
    /// and an administrator to revoke one. Stricter than restricted (which issues), looser than
    /// DR mode (which neither revokes nor answers OCSP).
    /// </summary>
    Maintenance = 3,
}

/// <summary>
/// The class every mutating operation declares, which decides the modes it is allowed in.
/// </summary>
public enum ModeOperation
{
    /// <summary>
    /// A new fact: issuing a certificate, signing a CRL, a timestamp or an OCSP answer, recording
    /// a request. Allowed while full or restricted; refused in DR mode.
    /// </summary>
    Fact = 0,

    /// <summary>
    /// A restriction: revoking, placing a hold, disabling a CA, locking or disabling an account,
    /// rejecting or cancelling a request. Allowed while full or restricted; refused in DR mode.
    /// </summary>
    Restriction = 1,

    /// <summary>
    /// Frozen unless the instance is full: grants, users, roles, profiles, policy, settings, new
    /// CAs, key operations, ceremonies, releasing a hold and un-revoking.
    /// </summary>
    Frozen = 2,

    /// <summary>
    /// Signing in to manage and repair the instance: sign-in, sign-out, the caller's own
    /// credentials and second factors, step-up, the mode itself, backups, and requests that use
    /// a mutating verb but change nothing. Allowed in every mode.
    /// </summary>
    Manage = 3,

    /// <summary>
    /// Issuing: a certificate is requested, approved, issued, renewed, reissued or enrolled for,
    /// over the console, the API or an enrollment protocol. Allowed in full and restricted mode,
    /// refused in maintenance and DR mode. Apart from <see cref="Fact"/> so that maintenance mode
    /// can stop issuance while CRLs, OCSP and the other facts go on.
    /// </summary>
    Issue = 4,
}

/// <summary>Who set the mode an instance is in.</summary>
public enum InstanceModeSource
{
    /// <summary>Nobody: there is no hub connection and no record, so the instance is full.</summary>
    Default = 0,

    /// <summary>The start rule: a hub connection is configured and no mode had been recorded yet.</summary>
    Start = 1,

    /// <summary>The hub, over its local connection.</summary>
    Hub = 2,

    /// <summary>An administrator, in the console.</summary>
    Administrator = 3,

    /// <summary>The record on disk could not be read, so the instance holds itself restricted.</summary>
    Unreadable = 4,
}

/// <summary>
/// The mode and who set it. This is what the console and the hub's health answer show.
/// </summary>
/// <param name="Mode">The mode.</param>
/// <param name="Source">Who set it.</param>
/// <param name="SetBy">
/// The administrator's username, or the operator name the hub claimed; null when the hub named
/// nobody and for <see cref="InstanceModeSource.Default"/> and <see cref="InstanceModeSource.Start"/>.
/// </param>
/// <param name="Reason">The reason given, when one was.</param>
/// <param name="SetAtUtc">When it was set; null for <see cref="InstanceModeSource.Default"/>.</param>
public sealed record InstanceModeRecord(
    InstanceMode Mode,
    InstanceModeSource Source,
    string? SetBy = null,
    string? Reason = null,
    DateTime? SetAtUtc = null)
{
    /// <summary>The answer of an instance nobody has set a mode on: full.</summary>
    public static InstanceModeRecord DefaultFull { get; } = new(InstanceMode.Full, InstanceModeSource.Default);
}

/// <summary>
/// The one question the core asks before it does certain things: what may this instance do right
/// now? The default answer, with no hub and nothing set, is <see cref="InstanceMode.Full"/>.
/// </summary>
public interface IInstanceModeGate
{
    /// <summary>The mode now, and who set it.</summary>
    InstanceModeRecord Current { get; }
}

/// <summary>
/// The answer of an instance that has no hub connection and no recorded mode, and of every
/// process that is not serving one (a host command, bootstrap, the setup wizard): full, always.
/// </summary>
public sealed class FullInstanceModeGate : IInstanceModeGate
{
    /// <summary>The one instance.</summary>
    public static FullInstanceModeGate Instance { get; } = new();

    /// <inheritdoc/>
    public InstanceModeRecord Current => InstanceModeRecord.DefaultFull;
}

/// <summary>
/// Declares the <see cref="ModeOperation"/> of an endpoint. Every mutating endpoint (POST, PUT,
/// PATCH, DELETE) carries one, on the action itself; an architecture test fails an endpoint that
/// declares nothing. The request filter refuses, and audits the refusal, when the instance's
/// mode does not allow the class.
/// </summary>
[AttributeUsage(AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
public sealed class ModeGateAttribute(ModeOperation operation) : Attribute
{
    /// <summary>The class of the endpoint's operation.</summary>
    public ModeOperation Operation { get; } = operation;

    /// <summary>
    /// True when the action answers the mode itself, because the refusal has a form of its own
    /// that the generic one would break: OCSP answers in its own protocol. The filter then lets
    /// the request through and the action must ask the gate.
    /// </summary>
    public bool AnsweredByAction { get; init; }
}
