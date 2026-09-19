namespace ModularCA.Shared.Models.Csr;

/// <summary>
/// What a server-side key generation returns: the request the CA now holds and the CSR that
/// was signed with the generated key. The private key is not in the response. The CA keeps it
/// wrapped on the request row until the certificate is issued and the holder downloads the
/// PKCS#12 that carries certificate and key together; it is deleted on delivery.
/// </summary>
/// <param name="CsrPem">The PEM-encoded PKCS#10 request the key signed.</param>
/// <param name="RequestId">The certificate request row the CSR was stored under.</param>
/// <param name="KeyHeld">True when the CA holds the private key for delivery at issuance.</param>
public sealed record GeneratedCsr(string CsrPem, Guid RequestId, bool KeyHeld);
