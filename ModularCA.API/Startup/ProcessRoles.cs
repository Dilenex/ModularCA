namespace ModularCA.API.Startup;

/// <summary>
/// The roles one process of the binary runs. Every role by default, which is the single-server
/// install as it has always been; <c>--role signer</c> runs the keystore and the signing
/// service alone, <c>--role node</c> runs everything else and reaches a signer as
/// <c>Signer.Mode</c> says.
/// </summary>
[Flags]
public enum ProcessRole
{
    /// <summary>No role; never the result of parsing.</summary>
    None = 0,

    /// <summary>Enrollment, validation, the control plane and the console.</summary>
    Node = 1,

    /// <summary>The keystore, its passwords and the signing service behind mutual TLS.</summary>
    Signer = 2,

    /// <summary>Every role in one process, the signer in process.</summary>
    All = Node | Signer,
}

/// <summary>
/// Reads the role set from the command line: <c>--role signer</c>, <c>--role node</c>,
/// <c>--role all</c>, repeatable or comma-separated. No <c>--role</c> means every role.
/// </summary>
public static class ProcessRoles
{
    /// <summary>The flag.</summary>
    public const string Flag = "--role";

    /// <summary>
    /// Parses the roles named on the command line. Throws <see cref="ArgumentException"/> for
    /// a value that is not a role or a flag with no value, with a message the caller prints.
    /// </summary>
    public static ProcessRole Parse(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);
        var roles = ProcessRole.None;
        var seen = false;
        for (var i = 0; i < args.Count; i++)
        {
            if (!string.Equals(args[i], Flag, StringComparison.OrdinalIgnoreCase))
                continue;
            if (i + 1 >= args.Count || args[i + 1].StartsWith("--", StringComparison.Ordinal))
                throw new ArgumentException($"{Flag} needs a value: signer, node or all.");
            seen = true;
            foreach (var value in args[i + 1].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                roles |= value.ToLowerInvariant() switch
                {
                    "signer" => ProcessRole.Signer,
                    "node" => ProcessRole.Node,
                    "all" => ProcessRole.All,
                    _ => throw new ArgumentException($"'{value}' is not a role; {Flag} takes signer, node or all."),
                };
            }
            i++;
        }
        return seen ? roles : ProcessRole.All;
    }
}
