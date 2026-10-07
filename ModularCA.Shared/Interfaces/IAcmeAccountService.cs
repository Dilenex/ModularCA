using ModularCA.Shared.Models.Acme;

namespace ModularCA.Shared.Interfaces;

/// <summary>
/// Manages ACME account lifecycle including creation, lookup, updates, deactivation, and key changes.
/// </summary>
public interface IAcmeAccountService
{
    /// <summary>
    /// Creates a new ACME account with the specified JWK and contact information, bound to
    /// <paramref name="certificateAuthorityId"/>, the CA its new-account request addressed.
    /// <paramref name="caLabel"/> is the route label, kept for display and audit.
    /// </summary>
    Task<AcmeAccountDto> CreateAsync(string jwkJson, string thumbprint, List<string>? contacts, bool termsAgreed, Guid certificateAuthorityId, string? caLabel = null);

    /// <summary>
    /// Returns the full <see cref="ModularCA.Shared.Entities.AcmeAccountEntity"/> status string
    /// (e.g. <c>Valid</c>, <c>Deactivated</c>). Callers need the
    /// raw status to reject deactivated accounts on <c>new-account</c> fast path.
    /// </summary>
    Task<string?> GetStatusByThumbprintAsync(string thumbprint);

    /// <summary>
    /// Returns the id of the CA the account is bound to, or null when the account does not
    /// exist or could not be bound at upgrade; such an account is refused at every CA until a
    /// new-account request with its key binds it (<see cref="BindAsync"/>).
    /// </summary>
    Task<Guid?> GetBoundCaIdAsync(Guid id);

    /// <summary>
    /// The enabled CA the account is bound to, which is the CA its requests on the label-less
    /// routes address; null when the account is unbound or that CA is disabled or deleted.
    /// </summary>
    Task<ModularCA.Shared.Entities.CertificateAuthorityEntity?> GetBoundCaAsync(Guid id);

    /// <summary>
    /// Binds an account the upgrade left unbound to <paramref name="certificateAuthorityId"/> and
    /// records <paramref name="caLabel"/> as its label. Returns false, changing nothing, when the
    /// account does not exist or is already bound.
    /// </summary>
    Task<bool> BindAsync(Guid id, Guid certificateAuthorityId, string? caLabel);

    /// <summary>
    /// Retrieves an ACME account by its ID.
    /// </summary>
    Task<AcmeAccountDto?> GetByIdAsync(Guid id);

    /// <summary>
    /// Retrieves an ACME account by its JWK thumbprint.
    /// </summary>
    Task<AcmeAccountDto?> GetByThumbprintAsync(string thumbprint);

    /// <summary>
    /// Updates an existing ACME account's contacts or terms agreement.
    /// </summary>
    Task<AcmeAccountDto> UpdateAsync(Guid id, UpdateAcmeAccountRequest request);

    /// <summary>
    /// Deactivates an ACME account, preventing further use.
    /// </summary>
    Task<AcmeAccountDto> DeactivateAsync(Guid id);

    /// <summary>
    /// Gets the raw JWK JSON for an ACME account by ID.
    /// </summary>
    Task<string?> GetJwkByIdAsync(Guid id);

    /// <summary>
    /// Changes the key associated with an ACME account.
    /// </summary>
    Task KeyChangeAsync(Guid accountId, string newJwkJson, string newThumbprint);
}
