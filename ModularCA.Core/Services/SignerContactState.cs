using ModularCA.Shared.Signing;

namespace ModularCA.Core.Services;

/// <summary>
/// What this process learned the last time its readiness check asked the signer for its health,
/// and when. The readiness check writes it on every run; a reader that must not call the signer
/// itself (the hub's inventory) reads it instead. Nothing is observed until the first readiness
/// check of the process, and the observation is as old as the last one.
/// </summary>
public sealed class SignerContactState
{
    private readonly object _gate = new();
    private Observation? _last;

    /// <summary>One answer, or one failure to answer, with its time.</summary>
    /// <param name="Reachable">Whether the signer answered.</param>
    /// <param name="Unlocked">Whether it said its keystore is open. False when it did not answer.</param>
    /// <param name="AtUtc">When the process asked.</param>
    public sealed record Observation(bool Reachable, bool Unlocked, DateTime AtUtc);

    /// <summary>The last observation; null when the signer has not been asked since the process started.</summary>
    public Observation? Last
    {
        get { lock (_gate) return _last; }
    }

    /// <summary>
    /// Records what the signer answered. A report whose backend is
    /// <see cref="SignerHealth.UnreachableBackend"/> is the node's own account of a remote signer
    /// that did not answer, and is recorded as unreachable.
    /// </summary>
    /// <param name="health">The signer's health as just read.</param>
    /// <param name="atUtc">When it was read.</param>
    public void Observe(SignerHealth health, DateTime atUtc)
    {
        ArgumentNullException.ThrowIfNull(health);
        var reachable = !string.Equals(health.Backend, SignerHealth.UnreachableBackend, StringComparison.Ordinal);
        lock (_gate)
            _last = new Observation(reachable, reachable && health.Unlocked, atUtc);
    }

    /// <summary>Records that asking the signer failed.</summary>
    /// <param name="atUtc">When it was asked.</param>
    public void ObserveUnreachable(DateTime atUtc)
    {
        lock (_gate)
            _last = new Observation(false, false, atUtc);
    }
}
