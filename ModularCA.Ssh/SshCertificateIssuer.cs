namespace ModularCA.Ssh;

/// <summary>A certificate was not issued because it breaks one of the CA key's rules.</summary>
/// <param name="reason">The refusal, as <see cref="SshCertificateRules"/> words it.</param>
public sealed class SshCertificateRefusedException(string reason) : Exception(reason);

/// <summary>
/// The signer returned something that is not a signature by the CA key over the certificate. No
/// certificate is handed out in that case.
/// </summary>
public sealed class SshSigningFailedException(string message) : Exception(message);

/// <summary>
/// Issues OpenSSH certificates: checks the fields against the CA key's rules, builds the
/// certificate, has the key sign it and returns it only when the signature verifies.
/// </summary>
/// <remarks>
/// The caller chooses the fields in <see cref="SshCertificateFields"/> and nothing else. The nonce
/// is made here, the signature key is the signer's own public key, and the signature algorithm
/// follows from that key.
/// </remarks>
public static class SshCertificateIssuer
{
    /// <summary>Issues a certificate for <paramref name="fields"/>, signed by <paramref name="signer"/>.</summary>
    /// <param name="fields">What the certificate says.</param>
    /// <param name="signer">The CA key.</param>
    /// <param name="limits">What that CA key is allowed to sign.</param>
    /// <param name="now">The issuer's clock, which <c>valid_after</c> is held to.</param>
    /// <param name="maxClockSkew">How far <c>valid_after</c> may be from <paramref name="now"/>; <see cref="SshCertificateRules.DefaultClockSkew"/> when null.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <exception cref="SshCertificateRefusedException">The fields break a rule. Nothing was signed.</exception>
    /// <exception cref="SshSigningFailedException">The signer's answer does not verify under its own public key.</exception>
    public static async ValueTask<SshCertificate> IssueAsync(SshCertificateFields fields, ISshSigner signer, SshCaLimits limits,
        DateTimeOffset now, TimeSpan? maxClockSkew = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(limits);

        var caKey = signer.PublicKey;
        if (SshCertificateRules.Check(fields, caKey, limits, now, maxClockSkew) is { } refusal)
            throw new SshCertificateRefusedException(refusal);

        var algorithm = SshSignatureAlgorithms.ForKeyType(caKey.KeyType);
        var toBeSigned = SshCertificateEncoder.EncodeToBeSigned(fields, caKey, SshCertificateEncoder.NewNonce());
        var signature = await signer.SignAsync(algorithm, toBeSigned, cancellationToken).ConfigureAwait(false);

        // A wrong key behind the signer, or a token that answers in another shape, must not
        // become a certificate nothing accepts.
        if (signature is null || !Names(signature, algorithm) || !SshSignature.Verify(caKey, toBeSigned, signature))
            throw new SshSigningFailedException($"The signer did not return a {algorithm} signature by the CA key over the certificate.");

        return SshCertificate.Parse(SshCertificateEncoder.Assemble(toBeSigned, signature));
    }

    private static bool Names(byte[] signatureBlob, string algorithm)
    {
        try
        {
            return SshSignature.Decode(signatureBlob).Algorithm == algorithm;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
