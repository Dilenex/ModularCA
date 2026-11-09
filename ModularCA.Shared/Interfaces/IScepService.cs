namespace ModularCA.Shared.Interfaces;

public interface IScepService
{
    /// <summary>
    /// Returns the CA certificate(s) for the GetCACert operation.
    /// Returns DER-encoded: single X.509 cert if one CA, or PKCS#7 certs-only if chain.
    /// Throws <see cref="ModularCA.Shared.Enrollment.ProtocolIncompatibleException"/>, after an
    /// unsuccessful audit row, when SCEP cannot run on the addressed CA.
    /// </summary>
    Task<(byte[] data, bool isPkcs7)> GetCaCertAsync(string? caLabel = null, string? sourceIp = null);

    /// <summary>
    /// Returns the SCEP server capabilities (GetCACaps).
    /// </summary>
    string GetCaCaps();

    /// <summary>
    /// Processes a SCEP PKIOperation request (PKCSReq / GetCertInitial / etc.).
    /// Accepts the raw CMS (PKCS#7) DER message and returns a CMS response.
    /// Throws <see cref="ModularCA.Shared.Enrollment.ProtocolIncompatibleException"/>, after an
    /// unsuccessful audit row, when SCEP cannot run on the addressed CA.
    /// </summary>
    Task<byte[]> PkiOperationAsync(byte[] cmsRequest, string? caLabel = null, string? sourceIp = null);
}
