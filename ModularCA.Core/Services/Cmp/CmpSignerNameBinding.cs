namespace ModularCA.Core.Services.Cmp;

/// <summary>
/// Binds the names in a signature-protected CMP request to the certificate that signed it.
/// </summary>
/// <remarks>
/// <para>
/// A signature-protected <c>ir</c>, <c>cr</c> or <c>kur</c> proves that the sender holds a
/// certificate this CA issued. It does not prove the sender may hold the name in the
/// CertTemplate. Before this existed, only <c>kur</c> compared subjects, and only the subject:
/// any device with any unrevoked certificate from the CA could sign a request for
/// <c>CN=ca-admin</c> with <c>DNS:ca.example.com</c>, the protection verified, and the CA issued.
/// The PBMAC path was already scoped to its token's name restrictions; the signature path had no
/// equivalent.
/// </para>
/// <para>
/// The rule is the same one EST applies to its mTLS branch: the request may name exactly the
/// signer's subject, and only SANs the signer already holds. A registration authority that
/// legitimately requests on behalf of other identities does so with a PBMAC credential scoped to
/// those names; RFC 4210's <c>raVerified</c> shortcut is refused elsewhere for the same reason.
/// </para>
/// </remarks>
public static class CmpSignerNameBinding
{
    /// <summary>
    /// Checks a requested subject and SANs against the signer's.
    /// </summary>
    /// <param name="requestedSubject">The CertTemplate subject DN, or empty.</param>
    /// <param name="requestedSans">Requested SANs in <c>TYPE:value</c> form.</param>
    /// <param name="signerSubject">The signing certificate's subject DN.</param>
    /// <param name="signerSans">The signing certificate's SANs in <c>TYPE:value</c> form.</param>
    /// <param name="dnEquals">DN equivalence, supplied so this stays free of certificate parsing.</param>
    /// <returns>Null when bound, otherwise the reason it is not.</returns>
    public static string? Check(
        string? requestedSubject,
        IReadOnlyCollection<string> requestedSans,
        string? signerSubject,
        IReadOnlyCollection<string> signerSans,
        Func<string, string, bool> dnEquals)
    {
        // An empty template subject would leave the issued subject to whatever the profile
        // supplies, which is not the signer's name either. Signature-protected requests must
        // name themselves.
        if (string.IsNullOrWhiteSpace(requestedSubject))
            return "Signature-protected requests must carry the signer's subject in the CertTemplate.";

        if (string.IsNullOrWhiteSpace(signerSubject) || !dnEquals(requestedSubject, signerSubject))
            return "CertTemplate subject does not match the signing certificate's subject.";

        foreach (var san in requestedSans)
        {
            if (!signerSans.Any(s => string.Equals(s, san, StringComparison.OrdinalIgnoreCase)))
                return $"Requested SAN '{san}' is not held by the signing certificate.";
        }

        return null;
    }
}
