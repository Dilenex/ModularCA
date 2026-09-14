using ModularCA.Shared.Entities;

namespace ModularCA.Shared.Interfaces;

/// <summary>
/// Resolves the Certificate Authority and its protocol-specific configuration
/// from an optional route label and protocol identifier.
/// </summary>
public interface ICaResolverService
{
    /// <summary>
    /// Resolves the CA and its protocol-specific signing/cert profile configuration.
    /// If <paramref name="caLabel"/> is null or empty, resolves the default CA.
    /// Falls back to global FeatureFlag configuration when no per-CA config exists.
    /// </summary>
    Task<ResolvedCaContext> ResolveAsync(string? caLabel, string protocol);

    /// <summary>
    /// Resolves the CA, signing profile, cert profile, and optional request profile
    /// from a named certificate template. Throws if the template is not found or disabled.
    /// </summary>
    /// <param name="templateName">The unique name of the certificate template.</param>
    /// <returns>A <see cref="ResolvedCaContext"/> populated from the template's configuration.</returns>
    Task<ResolvedCaContext> ResolveByTemplateAsync(string templateName);

    /// <summary>
    /// Resolves the CA entity a protocol request addresses: the enabled CA with the given label,
    /// or — when no label is supplied — the default CA, falling back to any enabled CA.
    /// </summary>
    /// <remarks>
    /// Exposed so that authorization decisions are made against the same CA that will issue.
    /// <c>EnrollmentAuthorizationService</c> previously selected a protocol row by
    /// <c>FirstOrDefault</c> with no ordering and no enabled filter; for a label-less request that
    /// could be any CA's row, including a disabled one, while <see cref="ResolveAsync"/> issued from
    /// the default CA. Policy from one CA applied to issuance from another.
    /// </remarks>
    /// <returns>The CA, or null when no enabled CA matches.</returns>
    Task<CertificateAuthorityEntity?> ResolveCaEntityAsync(string? caLabel);
}

/// <summary>
/// Contains the resolved CA identity and profile IDs for a protocol request.
/// </summary>
public class ResolvedCaContext
{
    /// <summary>
    /// The resolved CA entity, or null if no CA entities are configured (legacy fallback).
    /// </summary>
    public CertificateAuthorityEntity? Ca { get; init; }

    public Guid SigningProfileId { get; init; }
    public Guid CertProfileId { get; init; }

    /// <summary>
    /// The optional request profile that controls subject/SAN validation and approval behavior.
    /// Null when no request profile is configured for the protocol.
    /// </summary>
    public Guid? RequestProfileId { get; init; }
}
