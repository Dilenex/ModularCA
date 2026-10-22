using ModularCA.Shared.Models.CertProfiles;

namespace ModularCA.Shared.Interfaces
{
    /// <summary>
    /// Manages certificate profiles that define extension templates and constraints.
    /// </summary>
    public interface ICertProfileService
    {
        /// <summary>
        /// Returns all certificate profiles. With <paramref name="caVisible"/>, uses by CAs the
        /// caller may not see are counted rather than named.
        /// </summary>
        /// <param name="caVisible">Whether the caller may see a CA of the given space (null for the instance); null to name every CA.</param>
        Task<List<CertProfileDto>> GetAllAsync(Func<Guid?, bool>? caVisible = null);

        /// <summary>
        /// Creates a new certificate profile from the given request. <paramref name="spaceId"/> stamps the
        /// profile with its space (null for the instance). An inheritance parent must pass
        /// <paramref name="parentAllowed"/> (the caller's fence over the parent's space and CA; null admits
        /// any), be in the child's scope or instance-wide, and, when bound to a CA, be bound to the child's.
        /// </summary>
        Task<CertProfileDto> CreateAsync(CreateCertProfileRequest request, Guid? spaceId = null, Func<Guid?, Guid?, bool>? parentAllowed = null);

        /// <summary>
        /// Updates an existing certificate profile by ID. A changed inheritance parent is checked as
        /// <see cref="CreateAsync"/> checks it.
        /// </summary>
        Task UpdateAsync(Guid id, UpdateCertProfileRequest request, Func<Guid?, Guid?, bool>? parentAllowed = null);

        /// <summary>
        /// Deletes a certificate profile by ID.
        /// </summary>
        Task DeleteAsync(Guid id);

        /// <summary>
        /// Retrieves a certificate profile by its GUID. With <paramref name="caVisible"/>, uses by
        /// CAs the caller may not see are counted rather than named.
        /// </summary>
        /// <param name="id">The profile.</param>
        /// <param name="caVisible">Whether the caller may see a CA of the given space (null for the instance); null to name every CA.</param>
        Task<CertProfileDto?> GetByIdAsync(Guid id, Func<Guid?, bool>? caVisible = null);

    }
}