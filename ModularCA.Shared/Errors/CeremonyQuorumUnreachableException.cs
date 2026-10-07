namespace ModularCA.Shared.Errors;

/// <summary>
/// Raised instead of opening a ceremony that could never reach its quorum: fewer accounts other
/// than the initiator can approve it than it needs approvals. Nothing is created. Answers 409 with
/// <see cref="ErrorCodes.CeremonyNoApprover"/> when nobody else can approve, and
/// <see cref="ErrorCodes.CeremonyQuorumUnreachable"/> when some can but too few.
/// </summary>
public sealed class CeremonyQuorumUnreachableException : RequestValidationException
{
    /// <summary><see cref="RequirementScope"/> for a ceremony the instance's requirement opened.</summary>
    public const string InstanceScope = "instance";

    /// <summary><see cref="RequirementScope"/> for a ceremony a space's requirement opened.</summary>
    public const string SpaceScope = "space";

    /// <summary>Creates the refusal for a ceremony of <paramref name="operationType"/>.</summary>
    /// <param name="operationType">The ceremony's operation type, e.g. <c>CreateIntermediateCA</c>.</param>
    /// <param name="requiredApprovals">Approvals the ceremony would need.</param>
    /// <param name="eligibleApprovers">Accounts other than the initiator that could approve it.</param>
    /// <param name="requirementScope">
    /// Whose <c>RequireKeyCeremony</c> switch opened it: <see cref="InstanceScope"/>,
    /// <see cref="SpaceScope"/>, or null when no switch governs this kind of ceremony.
    /// </param>
    /// <param name="spaceId">The space, when <paramref name="requirementScope"/> is <see cref="SpaceScope"/>.</param>
    /// <param name="spaceName">That space's name.</param>
    public CeremonyQuorumUnreachableException(
        string operationType, int requiredApprovals, int eligibleApprovers,
        string? requirementScope = null, Guid? spaceId = null, string? spaceName = null)
        : base(Describe(requiredApprovals, eligibleApprovers))
    {
        OperationType = operationType;
        RequiredApprovals = requiredApprovals;
        EligibleApprovers = eligibleApprovers;
        RequirementScope = requirementScope;
        SpaceId = spaceId;
        SpaceName = spaceName;
    }

    /// <inheritdoc/>
    public override string Title => "This ceremony could never be approved";

    /// <inheritdoc/>
    public override int Status => 409;

    /// <inheritdoc/>
    public override string Code => EligibleApprovers <= 0 ? ErrorCodes.CeremonyNoApprover : ErrorCodes.CeremonyQuorumUnreachable;

    /// <inheritdoc/>
    public override string? Remediation => RemediationFor(callerMayDisableRequirement: false);

    /// <summary>
    /// What to do next, for a caller who may (a system super-administrator) or may not switch the
    /// scope's key ceremony requirement off themselves.
    /// </summary>
    public string RemediationFor(bool callerMayDisableRequirement)
    {
        var where = RequirementScope switch
        {
            InstanceScope => "for the instance, in Settings",
            SpaceScope => $"for space '{SpaceName ?? SpaceId?.ToString()}', on its page",
            _ => null,
        };
        if (where == null)
            return "Add another administrator who can approve it, or ask a system super-administrator to make the change directly.";
        return callerMayDisableRequirement
            ? $"Add another administrator, or turn the key ceremony requirement off {where}."
            : $"Ask a system super-administrator to add another administrator, or to turn the key ceremony requirement off {where}.";
    }

    /// <summary>The ceremony's operation type.</summary>
    public string OperationType { get; }

    /// <summary>Approvals the ceremony would need.</summary>
    public int RequiredApprovals { get; }

    /// <summary>Accounts other than the initiator that could approve it.</summary>
    public int EligibleApprovers { get; }

    /// <summary><see cref="InstanceScope"/>, <see cref="SpaceScope"/>, or null when no requirement switch applies.</summary>
    public string? RequirementScope { get; }

    /// <summary>The space whose requirement applies, for <see cref="SpaceScope"/>.</summary>
    public Guid? SpaceId { get; }

    /// <summary>That space's name.</summary>
    public string? SpaceName { get; }

    private static string Describe(int required, int eligible) => eligible <= 0
        ? "You're the only administrator who can approve this, so the ceremony could never be completed. Nothing was started."
        : $"This needs {required} approvals and only {eligible} other administrator{(eligible == 1 ? "" : "s")} can approve. Nothing was started.";
}
