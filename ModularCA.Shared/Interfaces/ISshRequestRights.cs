namespace ModularCA.Shared.Interfaces;

/// <summary>
/// Which certificate authorities a user may request certificates from, as the SSH login name
/// rules ask it of a certificate's subject. The answer is the user's own, from every grant
/// source: it never depends on who is asking, on a badge worn by the caller, or on a request.
/// </summary>
public interface ISshRequestRights
{
    /// <summary>The certificate authorities <paramref name="userId"/> holds cert.request on now. Empty for an unknown user.</summary>
    Task<IReadOnlySet<Guid>> RequestableCaIdsAsync(Guid userId, CancellationToken cancellationToken = default);
}
