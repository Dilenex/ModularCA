using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Authorization;
using ModularCA.Core.Models;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Models.Issuance;
using ModularCA.Shared.Utils;

namespace ModularCA.Core.Services;

/// <summary>
/// Answers which keys the CA may generate for a request under one signing profile and
/// certificate profile, so a request form offers only keys that will be accepted.
/// </summary>
public interface IServerKeyOptionsService
{
    /// <summary>
    /// Resolves the accepted and refused server-generated keys for a profile pair.
    /// </summary>
    /// <param name="signingProfileId">The signing profile the request would name.</param>
    /// <param name="certProfileId">The certificate profile the request would name.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The answer, or null when either profile does not exist or the certificate profile is
    /// outside the scope of the signing profile's CA.
    /// </returns>
    Task<ServerKeyOptions?> ResolveAsync(Guid signingProfileId, Guid certProfileId, CancellationToken cancellationToken = default);
}

/// <summary>
/// Loads the profile pair and hands it to <see cref="ServerKeyOptionsResolver"/>.
/// </summary>
public sealed class ServerKeyOptionsService(
    ModularCADbContext db,
    IProfileResolutionService profileResolver,
    IssuanceValidationService validation) : IServerKeyOptionsService
{
    /// <inheritdoc />
    public async Task<ServerKeyOptions?> ResolveAsync(Guid signingProfileId, Guid certProfileId, CancellationToken cancellationToken = default)
    {
        var signingProfile = await db.SigningProfiles.AsNoTracking()
            .FirstOrDefaultAsync(p => p.Id == signingProfileId, cancellationToken);
        var certProfile = await db.CertProfiles.AsNoTracking()
            .FirstOrDefaultAsync(p => p.Id == certProfileId, cancellationToken);
        if (signingProfile == null || certProfile == null)
            return null;

        if (signingProfile.IssuerId is Guid issuerId)
        {
            var ca = await db.CertificateAuthorities.AsNoTracking()
                .Where(c => c.CertificateId == issuerId)
                .Select(c => new { c.Id, c.SpaceId })
                .FirstOrDefaultAsync(cancellationToken);
            if (ca != null && !CertProfileScope.Admits(certProfile.SpaceId, certProfile.CertificateAuthorityId, ca.Id, ca.SpaceId))
                return null;
        }

        var effective = await profileResolver.ResolveCertProfileAsync(certProfileId);
        return ServerKeyOptionsResolver.Resolve(signingProfile, certProfile, effective, validation);
    }
}

/// <summary>
/// Decides which of the keys the CA can generate a profile pair accepts, by running each one
/// through the checks a server-generated request meets: the system key policy, the submission
/// check (<see cref="CsrService.IsValidKeyParameters"/>, against the stored profiles) and the two
/// issuance checks (<see cref="IssuanceValidationService"/>, against the effective certificate
/// profile). The signature tested is the one the CA signs the generated request with.
/// </summary>
public static class ServerKeyOptionsResolver
{
    /// <summary>
    /// Every key the request handlers can generate, in the order a form offers them. A null
    /// size is an algorithm whose name is also its parameter set.
    /// </summary>
    public static readonly IReadOnlyList<(string Algorithm, string? KeySize)> Catalog =
    [
        ("RSA", "2048"), ("RSA", "3072"), ("RSA", "4096"), ("RSA", "7680"), ("RSA", "8192"),
        ("ECDSA", "P-256"), ("ECDSA", "P-384"), ("ECDSA", "P-521"),
        ("Ed25519", null), ("Ed448", null),
        ("ML-DSA-44", null), ("ML-DSA-65", null), ("ML-DSA-87", null),
        ("SLH-DSA-SHA2-128F", null),
    ];

    /// <summary>
    /// Sorts <see cref="Catalog"/> into the keys the pair accepts and the keys it refuses.
    /// </summary>
    /// <param name="signingProfile">The signing profile as stored.</param>
    /// <param name="certProfile">The certificate profile as stored; submission checks this row.</param>
    /// <param name="effective">The certificate profile after inheritance; issuance checks this.</param>
    /// <param name="validation">The issuance checks.</param>
    public static ServerKeyOptions Resolve(
        SigningProfileEntity signingProfile,
        CertProfileEntity certProfile,
        EffectiveCertProfile effective,
        IssuanceValidationService validation)
    {
        var options = new List<ServerKeyOption>();
        var refused = new List<ServerKeyRefusal>();
        foreach (var (algorithm, keySize) in Catalog)
        {
            var reason = Refusal(algorithm, keySize, signingProfile, certProfile, effective, validation, out var signature);
            if (reason == null)
                options.Add(new ServerKeyOption(algorithm, keySize, signature));
            else
                refused.Add(new ServerKeyRefusal(algorithm, keySize, reason));
        }
        return new ServerKeyOptions(signingProfile.Name, effective.Name, options, refused);
    }

    private static string? Refusal(
        string algorithm,
        string? keySize,
        SigningProfileEntity signingProfile,
        CertProfileEntity certProfile,
        EffectiveCertProfile effective,
        IssuanceValidationService validation,
        out string signature)
    {
        signature = string.Empty;
        if (effective.IsCaProfile)
            return "A CA certificate profile cannot be used for a certificate request.";
        if (!KeyAlgorithmPolicy.IsAllowed(algorithm, keySize ?? algorithm))
            return "Not permitted by the system key policy.";

        signature = KeyAlgorithmPolicy.ResolveSignatureAlgorithm(algorithm, keySize ?? algorithm);
        // A parsed request reports no size for an algorithm that has none.
        var parsedSize = keySize ?? string.Empty;
        try
        {
            if (!CsrService.IsValidKeyParameters(algorithm, parsedSize, signature, signingProfile, certProfile))
                return "The allow-lists of the profiles could not be read.";
            validation.ValidateAgainstCertProfile(algorithm, parsedSize, signature, effective);
            validation.ValidateAgainstSigningProfile(algorithm, signature, signingProfile);
        }
        catch (Exception ex)
        {
            return ex.Message;
        }
        return null;
    }
}
