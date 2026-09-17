namespace ModularCA.API.Startup;

/// <summary>
/// The roles one process of the binary runs. Every role by default, which is the single-server
/// install as it has always been. <c>--role signer</c> runs the keystore and the signing
/// service alone; the three node roles host the controllers and background work that belong to
/// them (see <see cref="NodeRoleAttribute"/> and <see cref="SchedulerJobRoles"/>) and reach a
/// signer as <c>Signer.Mode</c> says. <c>--role node</c> is the three node roles together.
/// </summary>
[Flags]
public enum ProcessRole
{
    /// <summary>No role; never the result of parsing.</summary>
    None = 0,

    /// <summary>The enrollment protocols (ACME, EST, SCEP, CMP, MSAE, token and integration enrollment), TSA, and protocol cleanup.</summary>
    Enrollment = 1,

    /// <summary>Distribution: CRL, OCSP, AIA and CA certificate serving, on the HTTPS and the plain-HTTP listener.</summary>
    Validation = 2,

    /// <summary>The console, the setup wizard, the admin, auth, user and account API, and every scheduled job that mutates.</summary>
    Control = 4,

    /// <summary>The keystore, its passwords and the signing service behind mutual TLS.</summary>
    Signer = 8,

    /// <summary>Enrollment, validation and the control plane: everything but the signer.</summary>
    Node = Enrollment | Validation | Control,

    /// <summary>Every role in one process, the signer in process.</summary>
    All = Node | Signer,
}

/// <summary>
/// Reads the role set from the command line: <c>--role signer</c>, <c>--role node</c>,
/// <c>--role enrollment,validation</c>, <c>--role all</c>, repeatable or comma-separated. No
/// <c>--role</c> means the configured <c>Roles</c> value, and no configuration means every
/// role.
/// </summary>
public static class ProcessRoles
{
    /// <summary>The flag.</summary>
    public const string Flag = "--role";

    /// <summary>The names <see cref="Parse"/> accepts, for messages.</summary>
    public const string Names = "signer, enrollment, validation, control, node or all";

    /// <summary>
    /// Parses the roles named on the command line, falling back to <paramref name="configured"/>
    /// (the <c>Roles</c> key of <c>config.yaml</c>, in the same comma-separated form) when the
    /// command line names none, and to <see cref="ProcessRole.All"/> when neither does. The
    /// command line wins outright: a configured value is not merged into it. Throws
    /// <see cref="ArgumentException"/> for a value that is not a role or a flag with no value,
    /// with a message the caller prints.
    /// </summary>
    public static ProcessRole Parse(IReadOnlyList<string> args, string? configured = null)
    {
        ArgumentNullException.ThrowIfNull(args);
        var roles = ProcessRole.None;
        var seen = false;
        for (var i = 0; i < args.Count; i++)
        {
            if (!string.Equals(args[i], Flag, StringComparison.OrdinalIgnoreCase))
                continue;
            if (i + 1 >= args.Count || args[i + 1].StartsWith("--", StringComparison.Ordinal))
                throw new ArgumentException($"{Flag} needs a value: {Names}.");
            seen = true;
            roles |= ParseList(args[i + 1], Flag);
            i++;
        }
        if (seen)
            return roles;
        if (!string.IsNullOrWhiteSpace(configured))
        {
            var fromConfig = ParseList(configured, "Roles in config.yaml");
            if (fromConfig != ProcessRole.None)
                return fromConfig;
        }
        return ProcessRole.All;
    }

    /// <summary>
    /// Parses one comma-separated list of role names; <paramref name="source"/> names where
    /// the value came from in the error message.
    /// </summary>
    private static ProcessRole ParseList(string value, string source)
    {
        var roles = ProcessRole.None;
        foreach (var name in value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            roles |= name.ToLowerInvariant() switch
            {
                "signer" => ProcessRole.Signer,
                "enrollment" => ProcessRole.Enrollment,
                "validation" => ProcessRole.Validation,
                "control" => ProcessRole.Control,
                "node" => ProcessRole.Node,
                "all" => ProcessRole.All,
                _ => throw new ArgumentException($"'{name}' is not a role; {source} takes {Names}."),
            };
        }
        return roles;
    }

    /// <summary>True when <paramref name="role"/> is exactly one of the three node roles.</summary>
    public static bool IsSingleNodeRole(ProcessRole role)
        => role is ProcessRole.Enrollment or ProcessRole.Validation or ProcessRole.Control;

    /// <summary>The lower-case name of a single role, as the health endpoints and logs print it.</summary>
    public static string NameOf(ProcessRole role) => role switch
    {
        ProcessRole.Enrollment => "enrollment",
        ProcessRole.Validation => "validation",
        ProcessRole.Control => "control",
        ProcessRole.Signer => "signer",
        _ => throw new ArgumentOutOfRangeException(nameof(role), role, "Not a single role."),
    };

    /// <summary>The single roles present in <paramref name="roles"/>, in a fixed order.</summary>
    public static IReadOnlyList<ProcessRole> Split(ProcessRole roles)
    {
        var list = new List<ProcessRole>(4);
        foreach (var role in new[] { ProcessRole.Enrollment, ProcessRole.Validation, ProcessRole.Control, ProcessRole.Signer })
        {
            if (roles.HasFlag(role))
                list.Add(role);
        }
        return list;
    }
}

/// <summary>
/// The role set this process runs, registered as a singleton so middleware, health checks and
/// registrations ask one object rather than carrying the enum around.
/// </summary>
public sealed class ActiveRoles
{
    /// <summary>Creates the set; <paramref name="roles"/> is what <see cref="ProcessRoles.Parse"/> returned.</summary>
    public ActiveRoles(ProcessRole roles)
    {
        if (roles == ProcessRole.None)
            throw new ArgumentException("A process runs at least one role.", nameof(roles));
        Roles = roles;
    }

    /// <summary>The roles as flags.</summary>
    public ProcessRole Roles { get; }

    /// <summary>Whether every flag of <paramref name="role"/> is active here.</summary>
    public bool Has(ProcessRole role) => (Roles & role) == role;

    /// <summary>The lower-case names of the active roles, in a fixed order, for health reports and logs.</summary>
    public IReadOnlyList<string> Names => ProcessRoles.Split(Roles).Select(ProcessRoles.NameOf).ToList();
}
