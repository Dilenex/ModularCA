using System.Security.Cryptography;
using System.Text;

namespace ModularCA.Core.Services.Continuity;

/// <summary>
/// What the machine reports as its incarnation at one start: the source that answered, and the
/// SHA-256 of its value. The value itself is never kept or shown; it is only compared, and a
/// short tag made from the hash names it in the audit trail and the notice.
/// </summary>
/// <param name="Source">The name of the source that answered, or <see cref="NoneSource"/>.</param>
/// <param name="ValueHash">SHA-256 of the value in upper-case hex; null when no source answered.</param>
public sealed record IncarnationReading(string Source, string? ValueHash)
{
    /// <summary>The source name stored when the machine reports no incarnation.</summary>
    public const string NoneSource = "none";

    /// <summary>The length of <see cref="Tag"/> in hex digits: 64 bits of the hash.</summary>
    public const int TagLength = 16;

    /// <summary>The reading of a machine with no incarnation source: bare metal, or a VM or pod nobody injected one into.</summary>
    public static readonly IncarnationReading None = new(NoneSource, null);

    /// <summary>Whether no source answered.</summary>
    public bool IsNone => ValueHash == null;

    /// <summary>The short tag of this incarnation, or null for <see cref="None"/>.</summary>
    public string? Tag => TagOf(ValueHash);

    /// <summary>The short tag of a stored hash: its first <see cref="TagLength"/> hex digits. Null for null.</summary>
    public static string? TagOf(string? valueHash)
        => valueHash == null ? null : valueHash.Length <= TagLength ? valueHash : valueHash[..TagLength];

    /// <summary>
    /// The reading for <paramref name="value"/> as <paramref name="source"/> reported it. Leading
    /// and trailing white space is not part of the value, so a manifest's trailing newline does
    /// not make a new incarnation.
    /// </summary>
    public static IncarnationReading From(string source, string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(source);
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return new IncarnationReading(source, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value.Trim()))));
    }
}

/// <summary>
/// One place an incarnation ID can come from (<c>docs/architecture/rollback-continuity.md</c>,
/// section 1). A source answers with a value, or with null when it has none on this machine.
/// It must take its value from outside the state a rollback takes back: a value read from the
/// database or from a file beside it would go back with them and compare equal.
/// </summary>
public interface IIncarnationSource
{
    /// <summary>The source's name, as stored beside the value: lower case, at most 32 characters.</summary>
    string Name { get; }

    /// <summary>The incarnation ID as this source sees it now, or null when the source has none here.</summary>
    string? Read();
}

/// <summary>
/// The incarnation an orchestrator injects through the environment. Whatever restores this
/// instance's volumes or promotes a standby sets a new value when it does; it always knows.
/// A container has no hypervisor ID, so this is the only source in a pod.
/// </summary>
/// <param name="environment">Reads an environment variable; the process environment by default.</param>
public sealed class InjectedIncarnationSource(Func<string, string?>? environment = null) : IIncarnationSource
{
    /// <summary>The environment variable an orchestrator sets.</summary>
    public const string Variable = "MODULARCA__INSTANCE__INCARNATION";

    /// <summary>The stored name of this source.</summary>
    public const string SourceName = "injected";

    private readonly Func<string, string?> _environment = environment ?? Environment.GetEnvironmentVariable;

    /// <inheritdoc />
    public string Name => SourceName;

    /// <inheritdoc />
    public string? Read()
    {
        var value = _environment(Variable);
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }
}

/// <summary>
/// The incarnation sources this build has, in order of preference, and the one reading a start
/// compares. The orchestrator-injected value is the only source today; the hypervisor's VM
/// generation ID goes after it here once it is built, and a machine where no source answers
/// reads <see cref="IncarnationReading.None"/>.
/// </summary>
public static class IncarnationSources
{
    /// <summary>The sources of this build, most preferred first.</summary>
    public static IReadOnlyList<IIncarnationSource> Default { get; } = [new InjectedIncarnationSource()];

    /// <summary>
    /// The reading of the first of <paramref name="sources"/> that answers, or
    /// <see cref="IncarnationReading.None"/> when none does. A source that throws is taken as
    /// having no value: a start is never stopped by one.
    /// </summary>
    public static IncarnationReading Read(IEnumerable<IIncarnationSource>? sources = null)
    {
        foreach (var source in sources ?? Default)
        {
            string? value;
            try { value = source.Read(); }
            catch { value = null; }
            if (!string.IsNullOrWhiteSpace(value))
                return IncarnationReading.From(source.Name, value);
        }
        return IncarnationReading.None;
    }
}
