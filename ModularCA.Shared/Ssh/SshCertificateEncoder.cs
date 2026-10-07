using System.Security.Cryptography;

namespace ModularCA.Shared.Ssh;

/// <summary>
/// Encodes OpenSSH v01 certificates (<c>PROTOCOL.certkeys</c>). Signing is two steps:
/// <see cref="EncodeToBeSigned"/> gives the bytes the CA key signs, and <see cref="Assemble"/>
/// appends the signature blob to make the certificate.
/// </summary>
public static class SshCertificateEncoder
{
    /// <summary>The nonce length the encoder requires, as <c>ssh-keygen</c> uses.</summary>
    public const int NonceLength = 32;

    /// <summary>A fresh random nonce.</summary>
    public static byte[] NewNonce() => RandomNumberGenerator.GetBytes(NonceLength);

    /// <summary>
    /// Encodes every certificate field up to and including the signature key: the data the CA
    /// signs. Options and extensions are sorted by name (ordinal, as OpenSSH compares them).
    /// </summary>
    /// <param name="fields">The certificate content.</param>
    /// <param name="signatureKey">The CA public key, written as the <c>signature key</c> field.</param>
    /// <param name="nonce">A <see cref="NonceLength"/>-byte random nonce.</param>
    /// <exception cref="ArgumentException">
    /// The nonce is the wrong length, the subject or CA key cannot be used in a certificate, or an
    /// option name is empty or repeated.
    /// </exception>
    public static byte[] EncodeToBeSigned(SshCertificateFields fields, SshPublicKey signatureKey, byte[] nonce)
    {
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(signatureKey);
        ArgumentNullException.ThrowIfNull(nonce);
        if (nonce.Length != NonceLength)
            throw new ArgumentException($"The nonce must be {NonceLength} bytes.", nameof(nonce));
        if (!SshKeyTypes.Certifiable.Contains(signatureKey.KeyType))
            throw new ArgumentException($"A {signatureKey.KeyType} key cannot sign certificates.", nameof(signatureKey));
        if (fields.Type is not (SshCertificateType.User or SshCertificateType.Host))
            throw new ArgumentException("The certificate type must be user or host.", nameof(fields));

        var principals = new SshWriter();
        foreach (var principal in fields.Principals)
            principals.String(principal);

        return new SshWriter()
            .String(SshKeyTypes.CertificateType(fields.SubjectKey.KeyType))
            .String(nonce)
            .Raw(fields.SubjectKey.KeyFields)
            .UInt64(fields.Serial)
            .UInt32((uint)fields.Type)
            .String(fields.KeyId)
            .String(principals.ToArray())
            .UInt64(fields.ValidAfter)
            .UInt64(fields.ValidBefore)
            .String(EncodeOptions(fields.CriticalOptions, nameof(SshCertificateFields.CriticalOptions)))
            .String(EncodeOptions(fields.Extensions, nameof(SshCertificateFields.Extensions)))
            .String([])
            .String(signatureKey.Blob)
            .ToArray();
    }

    /// <summary>Appends <paramref name="signatureBlob"/> (see <see cref="SshSignature.Encode"/>) to make the certificate blob.</summary>
    public static byte[] Assemble(byte[] toBeSigned, byte[] signatureBlob)
    {
        ArgumentNullException.ThrowIfNull(toBeSigned);
        ArgumentNullException.ThrowIfNull(signatureBlob);
        return new SshWriter().Raw(toBeSigned).String(signatureBlob).ToArray();
    }

    /// <summary>
    /// Encodes a critical option or extension list: sorted by ordinal name, each as
    /// <c>string name, string data</c>, where data is empty for a flag and <c>string value</c> otherwise.
    /// </summary>
    /// <exception cref="ArgumentException">A name is empty or appears twice.</exception>
    public static byte[] EncodeOptions(IEnumerable<SshOption> options, string listName = "options")
    {
        ArgumentNullException.ThrowIfNull(options);
        var sorted = options.OrderBy(o => o.Name, StringComparer.Ordinal).ToList();
        var writer = new SshWriter();
        string? previous = null;
        foreach (var option in sorted)
        {
            if (string.IsNullOrEmpty(option.Name))
                throw new ArgumentException($"An entry in {listName} has no name.", listName);
            if (option.Name == previous)
                throw new ArgumentException($"'{option.Name}' appears twice in {listName}.", listName);
            previous = option.Name;

            writer.String(option.Name);
            writer.String(string.IsNullOrEmpty(option.Value) ? [] : new SshWriter().String(option.Value).ToArray());
        }
        return writer.ToArray();
    }
}
