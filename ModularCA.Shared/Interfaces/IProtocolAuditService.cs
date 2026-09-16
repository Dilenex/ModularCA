namespace ModularCA.Shared.Interfaces;

public interface IProtocolAuditService
{
    /// <summary>
    /// Logs an EST protocol event. <paramref name="callerPrincipal"/>
    /// records the authenticated caller (mTLS cert serial, HTTP basic username, bearer
    /// subject) so incident response can attribute a cert back to a specific credential.
    /// </summary>
    Task LogEstAsync(string operation, string? subjectDN, string? certSerial,
        string? keyAlgorithm, string? keySize, string? caLabel, string? sourceIp,
        bool success = true, string? errorMessage = null,
        Guid? certificateAuthorityId = null, Guid? tenantId = null,
        string? callerPrincipal = null);

    /// <summary>
    /// Logs a SCEP protocol event. <paramref name="callerPrincipal"/>
    /// records the authenticated caller — SCEP challenge-token id or the CMS signer
    /// cert serial when the request was self-signed.
    /// </summary>
    Task LogScepAsync(string operation, string? subjectDN, string? certSerial,
        string? keyAlgorithm, string? keySize, string? caLabel, string? transactionId,
        string? sourceIp, bool success = true, string? errorMessage = null,
        Guid? certificateAuthorityId = null, Guid? tenantId = null,
        string? callerPrincipal = null);

    /// <summary>
    /// Logs a CMP protocol event. <paramref name="callerPrincipal"/>
    /// records the CMP <c>senderKID</c> for PBMAC or the signing cert serial for
    /// signature-protected requests.
    /// </summary>
    Task LogCmpAsync(string messageType, string? subjectDN, string? certSerial,
        string? keyAlgorithm, string? keySize, string? caLabel, string? transactionId,
        string? revocationReason, string? sourceIp, bool success = true, string? errorMessage = null,
        Guid? certificateAuthorityId = null, Guid? tenantId = null,
        string? callerPrincipal = null);

    /// <summary>
    /// Logs a Windows autoenrollment (MSAE, MS-WSTEP) protocol event.
    /// <paramref name="templateName"/> is the certificate template the client named in its
    /// CSR, or null; <paramref name="callerPrincipal"/> records the authenticated username.
    /// </summary>
    Task LogMsaeAsync(string operation, string? subjectDN, string? certSerial,
        string? keyAlgorithm, string? keySize, string? templateName, string? caLabel,
        string? sourceIp, bool success = true, string? errorMessage = null,
        Guid? certificateAuthorityId = null, Guid? tenantId = null,
        string? callerPrincipal = null);

    /// <summary>
    /// Logs an ACME protocol event to the audit database.
    /// <paramref name="signingProfileId"/> and <paramref name="certProfileId"/>
    /// are persisted so post-incident analysis can trace a revoked cert back to
    /// the profile that issued it.
    /// </summary>
    Task LogAcmeAsync(string operation, Guid? accountId, Guid? orderId,
        string? subjectDN, string? certSerial, string? identifiers, string? revocationReason,
        string? sourceIp, bool success = true, string? errorMessage = null,
        string? caLabel = null, Guid? certificateAuthorityId = null, Guid? tenantId = null,
        Guid? signingProfileId = null, Guid? certProfileId = null);

    /// <summary>
    /// Logs a network request (allowed or blocked) to the audit database.
    /// Captures HTTP status code, response time, and whether the request was blocked.
    /// </summary>
    Task LogNetworkRequestAsync(string sourceIp, string requestPath, string httpMethod,
        int statusCode, long? responseTimeMs, string? protocol, string? caLabel,
        bool blocked, string? reason, string? userAgent,
        Guid? certificateAuthorityId = null, Guid? tenantId = null);
}
