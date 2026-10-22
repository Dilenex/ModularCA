namespace ModularCA.Shared.Signing;

/// <summary>
/// A critical option or an extension of an SSH certificate: its name, and its value, which is
/// empty for a flag such as <c>permit-pty</c>.
/// </summary>
/// <param name="Name">The option name, for example <c>force-command</c> or <c>permit-pty</c>.</param>
/// <param name="Value">The value, or empty for a flag.</param>
public sealed record SshCertificateOption(string Name, string Value = "");

/// <summary>
/// What a caller asks <see cref="ISigningService.SignSshCertificateAsync"/> to certify: the SSH CA
/// key, and every field of an OpenSSH certificate that a caller may choose. It is plain types on
/// purpose, the same shape as the wire message: this assembly references no other, so it names
/// no OpenSSH type.
/// </summary>
/// <remarks>
/// There is nothing here for the nonce, the signature key or the signature algorithm. The signer
/// makes the first, writes its own public key as the second and derives the third from that key,
/// so a request cannot state any of them. A member left null is read as empty, which is what the
/// wire carries for it, and the signer then refuses whatever an empty value breaks.
/// </remarks>
/// <param name="Key">The SSH CA key: its <c>SshCaKeys</c> row id in <see cref="KeyRef.SshKeystore"/>.</param>
/// <param name="SubjectPublicKey">The key being certified, as its OpenSSH wire-format public key blob (the base64 part of an authorized_keys line, decoded).</param>
/// <param name="CertType"><see cref="UserType"/> or <see cref="HostType"/>, exactly.</param>
/// <param name="Serial">The serial number. Zero is refused.</param>
/// <param name="KeyId">The key id, free text that sshd logs.</param>
/// <param name="Principals">The principals, in order. An empty list is refused: such a certificate is valid for every principal.</param>
/// <param name="ValidAfter">Start of validity, in Unix seconds.</param>
/// <param name="ValidBefore">End of validity, in Unix seconds.</param>
/// <param name="CriticalOptions">Critical options, in any order; the certificate carries them sorted by name.</param>
/// <param name="Extensions">Extensions, in any order. The certificate carries exactly these, with no defaults added.</param>
public sealed record SshCertificateRequest(
    KeyRef Key,
    byte[] SubjectPublicKey,
    string CertType,
    ulong Serial,
    string KeyId,
    IReadOnlyList<string> Principals,
    long ValidAfter,
    long ValidBefore,
    IReadOnlyList<SshCertificateOption>? CriticalOptions = null,
    IReadOnlyList<SshCertificateOption>? Extensions = null)
{
    /// <summary>The certificate type of a user certificate, which authenticates a user to a server.</summary>
    public const string UserType = "user";

    /// <summary>The certificate type of a host certificate, which authenticates a server to a client.</summary>
    public const string HostType = "host";
}
