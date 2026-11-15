using ModularCA.Shared.Errors;

namespace ModularCA.Shared.Modes;

/// <summary>
/// The table of what each mode allows, and the refusal an operator or a client sees when the
/// mode does not allow what was asked.
/// </summary>
/// <remarks>
/// Shaped like <see cref="ModularCA.Shared.Licensing.FeatureGate"/>: <see cref="Require"/>
/// returns the refusal and does not throw, so the caller writes its audit record first and
/// throws second, and the refusal names the mode and says what still works.
/// </remarks>
public static class InstanceModeGate
{
    /// <summary>The wire and file name of full mode.</summary>
    public const string FullName = "full";

    /// <summary>The wire and file name of restricted mode.</summary>
    public const string RestrictedName = "restricted";

    /// <summary>The wire and file name of DR mode.</summary>
    public const string DisasterRecoveryName = "dr";

    /// <summary>The name of <see cref="InstanceMode.Maintenance"/> on the wire and in the state file.</summary>
    public const string MaintenanceName = "maintenance";

    /// <summary>The mode names, as a refusal of an unknown one lists them.</summary>
    public const string NamesForMessages = "full, restricted, maintenance or dr";

    /// <summary>Whether an operation of class <paramref name="operation"/> is allowed in <paramref name="mode"/>.</summary>
    /// <param name="mode">The instance's mode.</param>
    /// <param name="operation">The operation's class.</param>
    public static bool Allows(InstanceMode mode, ModeOperation operation) => mode switch
    {
        InstanceMode.Full => true,
        InstanceMode.Restricted => operation != ModeOperation.Frozen,
        // Maintenance: nothing is issued and nothing about how the instance is run changes;
        // revoking, CRLs, OCSP and the other facts go on.
        InstanceMode.Maintenance => operation is not (ModeOperation.Frozen or ModeOperation.Issue),
        // DR mode, and any value this build does not know, allow managing and repairing only.
        _ => operation == ModeOperation.Manage,
    };

    /// <summary>
    /// Returns the refusal to throw when the instance's mode does not allow
    /// <paramref name="operation"/>, or <see langword="null"/> when it may proceed. A null
    /// <paramref name="gate"/> is an instance nobody set a mode on, and allows everything.
    /// </summary>
    /// <param name="gate">The instance's gate, or null where none is in force.</param>
    /// <param name="operation">The class of what is being attempted.</param>
    /// <param name="whatIsRefused">The operation as a sentence opener, in the operator's words: "Creating a CA".</param>
    public static InstanceModeException? Require(IInstanceModeGate? gate, ModeOperation operation, string whatIsRefused)
    {
        // A gate that answers nothing (a test double) is an instance nobody set a mode on.
        var mode = gate?.Current is { } record ? record.Mode : InstanceMode.Full;
        if (Allows(mode, operation))
            return null;
        return new InstanceModeException(mode, operation,
            $"{whatIsRefused} is not available while this instance is in {DisplayName(mode)}. {WhatStillWorks(mode)}");
    }

    /// <summary>
    /// Throws the refusal when the instance's mode does not allow <paramref name="operation"/>.
    /// For the places below the request filter, which has already audited a refused request:
    /// the node before it asks the signer for a key operation, and the CRL signer. A null
    /// <paramref name="gate"/> allows everything.
    /// </summary>
    /// <param name="gate">The instance's gate, or null where none is in force.</param>
    /// <param name="operation">The class of what is being attempted.</param>
    /// <param name="whatIsRefused">The operation as a sentence opener, in the operator's words.</param>
    /// <exception cref="InstanceModeException">The mode does not allow the operation.</exception>
    public static void ThrowIfRefused(IInstanceModeGate? gate, ModeOperation operation, string whatIsRefused)
    {
        if (Require(gate, operation, whatIsRefused) is { } refusal)
            throw refusal;
    }

    /// <summary>The name used on the wire, in the state file and in <c>MODULARCA__HUB__STARTMODE</c>.</summary>
    /// <param name="mode">The mode.</param>
    public static string NameOf(InstanceMode mode) => mode switch
    {
        InstanceMode.Full => FullName,
        InstanceMode.Restricted => RestrictedName,
        InstanceMode.DisasterRecovery => DisasterRecoveryName,
        InstanceMode.Maintenance => MaintenanceName,
        _ => throw new ArgumentOutOfRangeException(nameof(mode), mode, "Not a mode."),
    };

    /// <summary>
    /// Parses a mode name: <c>full</c>, <c>restricted</c> or <c>dr</c>, in any case, with
    /// surrounding white space ignored. Nothing else is a mode.
    /// </summary>
    /// <param name="name">The text.</param>
    /// <param name="mode">The mode, when the text names one.</param>
    public static bool TryParse(string? name, out InstanceMode mode)
    {
        switch (name?.Trim().ToLowerInvariant())
        {
            case FullName: mode = InstanceMode.Full; return true;
            case RestrictedName: mode = InstanceMode.Restricted; return true;
            case DisasterRecoveryName: mode = InstanceMode.DisasterRecovery; return true;
            case MaintenanceName: mode = InstanceMode.Maintenance; return true;
            default: mode = InstanceMode.Full; return false;
        }
    }

    /// <summary>The mode as people read it: "full mode", "restricted mode", "DR mode".</summary>
    /// <param name="mode">The mode.</param>
    public static string DisplayName(InstanceMode mode) => mode switch
    {
        InstanceMode.Full => "full mode",
        InstanceMode.Restricted => "restricted mode",
        InstanceMode.Maintenance => "maintenance mode",
        _ => "DR mode",
    };

    /// <summary>What still works in <paramref name="mode"/>, as plain sentences.</summary>
    /// <param name="mode">The mode.</param>
    public static string WhatStillWorks(InstanceMode mode) => mode switch
    {
        InstanceMode.Full => "Everything is available.",
        InstanceMode.Restricted =>
            "Issuing, revoking, placing a hold, disabling a CA, locking an account, CRLs and OCSP still work. "
            + "Users, groups, roles, grants, profiles, policy, settings, new CAs, key operations, ceremonies, "
            + "releasing a hold and un-revoking wait until the instance is back in full mode.",
        InstanceMode.Maintenance =>
            "Revoking, placing a hold, revoking a certificate this CA does not hold, disabling a CA, locking an account, "
            + "CRLs and OCSP still work. Nothing is issued, renewed or enrolled for, and users, groups, roles, grants, "
            + "profiles, policy, settings, new CAs, key operations, ceremonies, releasing a hold and un-revoking wait "
            + "until the mode is changed.",
        _ =>
            "Signing in, backups and changing the mode still work, and CRLs that are already signed are still served. "
            + "Nothing is issued or revoked, no new CRL is signed and OCSP reports itself unavailable "
            + "until the mode is changed.",
    };

    /// <summary>The stable code of a refusal in <paramref name="mode"/>.</summary>
    /// <param name="mode">The mode that refused.</param>
    public static string CodeFor(InstanceMode mode)
        => mode switch
        {
            InstanceMode.Restricted => ErrorCodes.InstanceRestricted,
            InstanceMode.Maintenance => ErrorCodes.InstanceInMaintenance,
            _ => ErrorCodes.InstanceInDisasterRecovery,
        };
}

/// <summary>
/// Raised when the instance's mode does not allow the operation that was asked for. Nothing about
/// the request is wrong: the same request succeeds once the mode allows it, so it answers 503.
/// </summary>
/// <remarks>
/// Deliberately not a <see cref="RequestValidationException"/>: that family means the request
/// was at fault and is 4xx by construction. This carries the same four fields, and
/// <c>RequestValidationMiddleware</c> renders it the same way, with its own status.
/// </remarks>
public sealed class InstanceModeException(InstanceMode mode, ModeOperation operation, string message)
    : Exception(message)
{
    /// <summary>The mode that refused.</summary>
    public InstanceMode Mode { get; } = mode;

    /// <summary>The class of the refused operation.</summary>
    public ModeOperation Operation { get; } = operation;

    /// <summary>Short problem-details title.</summary>
    public string Title => Mode switch
    {
        InstanceMode.Restricted => "The instance is in restricted mode",
        InstanceMode.Maintenance => "The instance is in maintenance mode",
        _ => "The instance is in DR mode",
    };

    /// <summary>The HTTP status: 503, with a Retry-After.</summary>
    public int Status => 503;

    /// <summary>The stable code, from <see cref="ErrorCodes"/>.</summary>
    public string Code => InstanceModeGate.CodeFor(Mode);

    /// <summary>What to do about it.</summary>
    public string Remediation =>
        "The mode is set by the instance's hub, or by an administrator under Settings, Instance mode. "
        + "Try again once the mode allows it.";
}
