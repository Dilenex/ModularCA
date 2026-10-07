using ModularCA.Shared.Entities;

namespace ModularCA.Shared.Interfaces;

/// <summary>
/// Who asked for an SSH CA operation, for the audit entry the service writes and for the
/// certificate row: the user, the name the audit shows, and the address the request came from.
/// </summary>
/// <param name="UserId">The user, or null for the system.</param>
/// <param name="Username">The name the audit entry carries.</param>
/// <param name="SourceIp">The address the request came from, when there was a request.</param>
public sealed record SshCaActor(Guid? UserId, string? Username, string? SourceIp = null);

/// <summary>
/// SSH certificate authorities: their keys, which the signer generates and holds, the
/// certificates it signs with them, and their revocation lists. The service writes the audit
/// entry of each operation itself, once, whichever controller or ceremony called it.
/// </summary>
public interface ISshCaService
{
    /// <summary>
    /// Creates an SSH CA: the signer generates the key, the CA, its groups, its key row and its
    /// default signing profiles are written, and the key is committed to the row.
    /// </summary>
    /// <param name="ceremonyId">The approved <c>CreateSshCa</c> ceremony this executes, when the instance requires one.</param>
    /// <param name="actor">Who asked, for the audit entry.</param>
    /// <exception cref="ModularCA.Shared.Errors.SshCaKeyUnavailableException">The signer is locked, cannot hold SSH CA keys, or predates the SSH keystore.</exception>
    Task<SshCaKeyEntity> GenerateKeyPairAsync(string name, string keyType, bool isUserCa, bool isHostCa, int maxValidityHours, int? keySize = null,
        Guid? ceremonyId = null, SshCaActor? actor = null);

    /// <summary>
    /// Disables an SSH CA key and revokes all active certificates issued by it. No key is touched.
    /// </summary>
    /// <param name="actor">Who asked, for the audit entry.</param>
    /// <param name="ceremonyId">The <c>DeleteSshCa</c> ceremony this executes, when there is one.</param>
    Task DisableAsync(Guid caKeyId, SshCaActor? actor = null, Guid? ceremonyId = null);

    /// <summary>
    /// Signs a user certificate for <paramref name="publicKey"/> through the signer. The
    /// certificate carries exactly <paramref name="extensions"/>, and the row returned is what
    /// the certificate says.
    /// </summary>
    /// <exception cref="ModularCA.Shared.Errors.SshCaKeyUnavailableException">The signer is locked or cannot serve the key, or the key awaits its import into the signer.</exception>
    /// <exception cref="ModularCA.Shared.Errors.RequestValidationException">The public key is unusable, the CA is disabled, or the signer refused the certificate's fields.</exception>
    Task<SshCertificateEntity> SignUserKeyAsync(Guid caKeyId, string publicKey, List<string> principals, int? validityHours, string? keyId, List<string>? extensions, SshCaActor? actor = null);

    /// <summary>
    /// Signs a host certificate for <paramref name="publicKey"/> through the signer. A host
    /// certificate carries no options, and the row returned is what the certificate says.
    /// </summary>
    /// <exception cref="ModularCA.Shared.Errors.SshCaKeyUnavailableException">The signer is locked or cannot serve the key, or the key awaits its import into the signer.</exception>
    /// <exception cref="ModularCA.Shared.Errors.RequestValidationException">The public key is unusable, the CA is disabled, or the signer refused the certificate's fields.</exception>
    Task<SshCertificateEntity> SignHostKeyAsync(Guid caKeyId, string publicKey, List<string> hostnames, int? validityHours, string? keyId, SshCaActor? actor = null);

    /// <summary>Returns the public key of an SSH CA key, as an authorized_keys line.</summary>
    Task<string> GetPublicKeyAsync(Guid caKeyId);

    /// <summary>Lists the SSH CA keys, by name.</summary>
    Task<List<SshCaKeyEntity>> GetCaKeysAsync();

    /// <summary>
    /// Lists issued SSH certificates, optionally filtered by CA key.
    /// </summary>
    Task<List<SshCertificateEntity>> GetCertificatesAsync(int page = 1, int pageSize = 50, Guid? caKeyId = null, string? sort = null);

    /// <summary>
    /// Revokes an SSH certificate, optionally only when it belongs to <paramref name="requiredCaKeyId"/>.
    /// </summary>
    /// <param name="actor">Who asked, for the audit entry.</param>
    Task<bool> RevokeCertificateAsync(Guid certId, Guid? requiredCaKeyId = null, SshCaActor? actor = null);

    /// <summary>Returns one issued SSH certificate, or null.</summary>
    Task<SshCertificateEntity?> GetCertificateByIdAsync(Guid certId);

    /// <summary>
    /// Builds the key revocation list of an SSH CA key from its public key and the serials of
    /// its revoked certificates. No signer and no private key take part.
    /// </summary>
    Task<byte[]> GenerateKrlAsync(Guid caKeyId);
}
