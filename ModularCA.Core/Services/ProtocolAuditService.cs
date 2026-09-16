using Microsoft.Extensions.Logging;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using System.Net;

namespace ModularCA.Core.Services;

/// <summary>
/// Records protocol-specific audit entries (EST, SCEP, CMP, ACME) to the audit database.
/// </summary>
public class ProtocolAuditService : IProtocolAuditService
{
    private readonly AuditDbContext? _auditDb;
    private readonly ILogger<ProtocolAuditService> _logger;

    public ProtocolAuditService(
        ILogger<ProtocolAuditService> logger,
        AuditDbContext? auditDb = null)
    {
        _logger = logger;
        _auditDb = auditDb;
    }

    /// <summary>
    /// Logs an EST protocol event to the audit database.
    /// </summary>
    public async Task LogEstAsync(string operation, string? subjectDN, string? certSerial,
        string? keyAlgorithm, string? keySize, string? caLabel, string? sourceIp,
        bool success = true, string? errorMessage = null,
        Guid? certificateAuthorityId = null, Guid? tenantId = null,
        string? callerPrincipal = null)
    {
        if (!ShouldLog()) return;
        try
        {
            _auditDb!.AuditEst.Add(new AuditEstEntity
            {
                Operation = operation,
                SubjectDN = subjectDN,
                CertificateSerial = certSerial,
                KeyAlgorithm = keyAlgorithm,
                KeySize = keySize,
                CaLabel = caLabel,
                SourceIp = NormalizeIp(sourceIp),
                Success = success,
                ErrorMessage = errorMessage,
                CertificateAuthorityId = certificateAuthorityId,
                TenantId = tenantId,
                CallerPrincipal = Truncate(callerPrincipal, 255)
            });
            await _auditDb.SaveChangesAsync();
        }
        catch (Exception ex) { _logger.LogError(ex, "Failed to write EST audit log"); }
    }

    /// <inheritdoc />
    public async Task LogMsaeAsync(string operation, string? subjectDN, string? certSerial,
        string? keyAlgorithm, string? keySize, string? templateName, string? caLabel,
        string? sourceIp, bool success = true, string? errorMessage = null,
        Guid? certificateAuthorityId = null, Guid? tenantId = null,
        string? callerPrincipal = null, string? realm = null, string? authMethod = null)
    {
        if (!ShouldLog()) return;
        try
        {
            _auditDb!.AuditMsae.Add(new AuditMsaeEntity
            {
                Operation = operation,
                SubjectDN = Truncate(subjectDN, 255),
                CertificateSerial = certSerial,
                KeyAlgorithm = keyAlgorithm,
                KeySize = keySize,
                TemplateName = Truncate(templateName, 100),
                CaLabel = caLabel,
                SourceIp = NormalizeIp(sourceIp),
                Success = success,
                ErrorMessage = Truncate(errorMessage, 500),
                CertificateAuthorityId = certificateAuthorityId,
                TenantId = tenantId,
                CallerPrincipal = Truncate(callerPrincipal, 255),
                Realm = Truncate(realm, 255),
                AuthMethod = Truncate(authMethod, 32),
            });
            await _auditDb.SaveChangesAsync();
        }
        catch (Exception ex) { _logger.LogError(ex, "Failed to write MSAE audit log"); }
    }

    /// <summary>
    /// Logs a SCEP protocol event to the audit database.
    /// </summary>
    public async Task LogScepAsync(string operation, string? subjectDN, string? certSerial,
        string? keyAlgorithm, string? keySize, string? caLabel, string? transactionId,
        string? sourceIp, bool success = true, string? errorMessage = null,
        Guid? certificateAuthorityId = null, Guid? tenantId = null,
        string? callerPrincipal = null)
    {
        if (!ShouldLog()) return;
        try
        {
            _auditDb!.AuditScep.Add(new AuditScepEntity
            {
                Operation = operation,
                SubjectDN = subjectDN,
                CertificateSerial = certSerial,
                KeyAlgorithm = keyAlgorithm,
                KeySize = keySize,
                CaLabel = caLabel,
                TransactionId = transactionId,
                SourceIp = NormalizeIp(sourceIp),
                Success = success,
                ErrorMessage = errorMessage,
                CertificateAuthorityId = certificateAuthorityId,
                TenantId = tenantId,
                CallerPrincipal = Truncate(callerPrincipal, 255)
            });
            await _auditDb.SaveChangesAsync();
        }
        catch (Exception ex) { _logger.LogError(ex, "Failed to write SCEP audit log"); }
    }

    /// <summary>
    /// Logs a CMP protocol event to the audit database.
    /// </summary>
    public async Task LogCmpAsync(string messageType, string? subjectDN, string? certSerial,
        string? keyAlgorithm, string? keySize, string? caLabel, string? transactionId,
        string? revocationReason, string? sourceIp, bool success = true, string? errorMessage = null,
        Guid? certificateAuthorityId = null, Guid? tenantId = null,
        string? callerPrincipal = null)
    {
        if (!ShouldLog()) return;
        try
        {
            _auditDb!.AuditCmp.Add(new AuditCmpEntity
            {
                MessageType = messageType,
                SubjectDN = subjectDN,
                CertificateSerial = certSerial,
                KeyAlgorithm = keyAlgorithm,
                KeySize = keySize,
                CaLabel = caLabel,
                TransactionId = transactionId,
                RevocationReason = revocationReason,
                SourceIp = NormalizeIp(sourceIp),
                Success = success,
                ErrorMessage = errorMessage,
                CertificateAuthorityId = certificateAuthorityId,
                TenantId = tenantId,
                CallerPrincipal = Truncate(callerPrincipal, 255)
            });
            await _auditDb.SaveChangesAsync();
        }
        catch (Exception ex) { _logger.LogError(ex, "Failed to write CMP audit log"); }
    }

    private static string? Truncate(string? value, int maxLength)
    {
        if (value == null) return null;
        return value.Length <= maxLength ? value : value[..maxLength];
    }

    /// <summary>
    /// Logs an ACME protocol event to the audit database.
    /// Signing profile and cert profile ids are now persisted so a revoked cert
    /// can be traced back to the policy that issued it without re-deriving from
    /// the order graph.
    /// </summary>
    public async Task LogAcmeAsync(string operation, Guid? accountId, Guid? orderId,
        string? subjectDN, string? certSerial, string? identifiers, string? revocationReason,
        string? sourceIp, bool success = true, string? errorMessage = null,
        string? caLabel = null, Guid? certificateAuthorityId = null, Guid? tenantId = null,
        Guid? signingProfileId = null, Guid? certProfileId = null)
    {
        if (!ShouldLog()) return;
        try
        {
            _auditDb!.AuditAcme.Add(new AuditAcmeEntity
            {
                Operation = operation,
                AccountId = accountId,
                OrderId = orderId,
                SubjectDN = subjectDN,
                CertificateSerial = certSerial,
                Identifiers = identifiers,
                RevocationReason = revocationReason,
                CaLabel = caLabel,
                SourceIp = NormalizeIp(sourceIp),
                Success = success,
                ErrorMessage = errorMessage,
                CertificateAuthorityId = certificateAuthorityId,
                TenantId = tenantId,
                SigningProfileId = signingProfileId,
                CertProfileId = certProfileId
            });
            await _auditDb.SaveChangesAsync();
        }
        catch (Exception ex) { _logger.LogError(ex, "Failed to write ACME audit log"); }
    }

    /// <summary>
    /// Logs a network request (allowed or blocked) to the audit database.
    /// Captures HTTP status code, response time, and whether the request was blocked.
    /// </summary>
    public async Task LogNetworkRequestAsync(string sourceIp, string requestPath, string httpMethod,
        int statusCode, long? responseTimeMs, string? protocol, string? caLabel,
        bool blocked, string? reason, string? userAgent,
        Guid? certificateAuthorityId = null, Guid? tenantId = null)
    {
        if (!ShouldLog()) return;
        try
        {
            _auditDb!.AuditNetwork.Add(new AuditNetworkEntity
            {
                SourceIp = NormalizeIp(sourceIp) ?? sourceIp,
                RequestPath = requestPath,
                HttpMethod = httpMethod,
                StatusCode = statusCode,
                ResponseTimeMs = responseTimeMs,
                Protocol = protocol,
                CaLabel = caLabel,
                Blocked = blocked,
                Reason = reason ?? string.Empty,
                UserAgent = userAgent,
                CertificateAuthorityId = certificateAuthorityId,
                TenantId = tenantId
            });
            await _auditDb.SaveChangesAsync();
        }
        catch (Exception ex) { _logger.LogError(ex, "Failed to write network audit log"); }
    }

    private bool ShouldLog() => _auditDb != null;

    private static string? NormalizeIp(string? ip)
    {
        if (ip == null) return null;
        if (IPAddress.TryParse(ip, out var addr) && addr.IsIPv4MappedToIPv6)
            return addr.MapToIPv4().ToString();
        return ip;
    }
}
