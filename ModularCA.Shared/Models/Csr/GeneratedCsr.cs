namespace ModularCA.Shared.Models.Csr;

/// <summary>
/// What a server-side key generation returns: the request the CA now holds, and the private
/// key that goes back to the requester in this response and nowhere else. The CA does not
/// keep the key; the holder stores it when they receive it and pairs it with the certificate
/// once the request is issued.
/// </summary>
/// <param name="CsrPem">The PEM-encoded PKCS#10 request the key signed.</param>
/// <param name="RequestId">The certificate request row the CSR was stored under.</param>
/// <param name="PrivateKeyPem">The PEM-encoded PKCS#8 private key, delivered once.</param>
public sealed record GeneratedCsr(string CsrPem, Guid RequestId, string PrivateKeyPem);
