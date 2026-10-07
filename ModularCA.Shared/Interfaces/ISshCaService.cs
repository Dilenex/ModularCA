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
/// Who an SSH user certificate is for: a user of this console, or a service identity that has
/// no account and is known by a label. The CA writes the certificate's key id from it (the
/// user's username, or <c>svc:</c> and the label), so no caller chooses the name hosts log.
/// </summary>
public sealed record SshCertificateSubject
{
    private SshCertificateSubject(Guid? userId, string? serviceLabel)
    {
        UserId = userId;
        ServiceLabel = serviceLabel;
    }

    /// <summary>The user, or null for a service identity.</summary>
    public Guid? UserId { get; }

    /// <summary>The service identity's label, or null for a user.</summary>
    public string? ServiceLabel { get; }

    /// <summary>A user: the certificate carries only login names that user holds.</summary>
    public static SshCertificateSubject ForUser(Guid userId) => new(userId, null);

    /// <summary>A service identity: its login names are typed, and checked by the caller against the certificate profile.</summary>
    public static SshCertificateSubject ForService(string label) => new(null, label);
}

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
    /// Signs a user certificate for <paramref name="publicKey"/> through the signer. The CA
    /// writes the key id from <paramref name="subject"/>. For a user, every one of
    /// <paramref name="principals"/> must be a login name that user holds on the key, and the
    /// certificate ends no later than those names allow. The certificate carries exactly
    /// <paramref name="extensions"/>, and the row returned is what the certificate says.
    /// </summary>
    /// <param name="validityHours">The validity asked, in hours; null for the most allowed.</param>
    /// <param name="profileMaxValidityHours">The limit of the profiles the caller checked, in hours; null when there is none beyond the key's.</param>
    /// <exception cref="ModularCA.Shared.Errors.SshCaKeyUnavailableException">The signer is locked or cannot serve the key, or the key awaits its import into the signer.</exception>
    /// <exception cref="ModularCA.Shared.Errors.RequestValidationException">
    /// The public key is unusable, the CA is disabled, the subject is unknown or inactive, a login
    /// name is not held, the validity asked is over what a login name allows, or the signer
    /// refused the certificate's fields.
    /// </exception>
    Task<SshCertificateEntity> SignUserKeyAsync(Guid caKeyId, string publicKey, SshCertificateSubject subject, List<string> principals,
        int? validityHours, List<string>? extensions, SshCaActor? actor = null, int? profileMaxValidityHours = null);

    /// <summary>
    /// Signs a host certificate for <paramref name="publicKey"/> through the signer. The CA
    /// writes the key id: the first hostname. A host certificate carries no options, and the row
    /// returned is what the certificate says.
    /// </summary>
    /// <param name="validityHours">The validity asked, in hours; null for the most allowed.</param>
    /// <param name="profileMaxValidityHours">The limit of the profiles the caller checked, in hours; null when there is none beyond the key's.</param>
    /// <exception cref="ModularCA.Shared.Errors.SshCaKeyUnavailableException">The signer is locked or cannot serve the key, or the key awaits its import into the signer.</exception>
    /// <exception cref="ModularCA.Shared.Errors.RequestValidationException">The public key is unusable, the CA is disabled, or the signer refused the certificate's fields.</exception>
    Task<SshCertificateEntity> SignHostKeyAsync(Guid caKeyId, string publicKey, List<string> hostnames, int? validityHours, SshCaActor? actor = null,
        int? profileMaxValidityHours = null);

    /// <summary>
    /// The key id the CA would write for <paramref name="subject"/>: the user's username, or
    /// <c>svc:</c> and the label.
    /// </summary>
    /// <exception cref="ModularCA.Shared.Errors.RequestValidationException">The user is unknown or inactive, or the username or label cannot be a key id.</exception>
    Task<string> KeyIdOfAsync(SshCertificateSubject subject);

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
