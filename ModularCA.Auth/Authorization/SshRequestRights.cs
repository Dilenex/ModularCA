using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Interfaces;

namespace ModularCA.Auth.Authorization;

/// <summary>
/// <see cref="ISshRequestRights"/> over the capability resolver, read for the subject of a
/// certificate and not for a caller.
/// </summary>
/// <remarks>
/// The resolver the request pipeline uses narrows every answer to the badge on the caller's
/// token, and a badge that is not the asked user's grants nothing. Asked about another user
/// inside a request, it would say that user holds no right. So this builds its own resolver
/// with no badge, no request and no audit.
/// </remarks>
public sealed class SshRequestRights(ModularCADbContext db, ILogger<CaGroupAuthorizationService>? logger = null) : ISshRequestRights
{
    private readonly CaGroupAuthorizationService _rights = new(db, logger ?? NullLogger<CaGroupAuthorizationService>.Instance);

    /// <inheritdoc />
    public async Task<IReadOnlySet<Guid>> RequestableCaIdsAsync(Guid userId, CancellationToken cancellationToken = default)
        => (await _rights.GetAccessibleCaIdsAsync(userId, Capabilities.CertRequest)).ToHashSet();
}
