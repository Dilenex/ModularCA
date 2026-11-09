using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using ModularCA.API.Filters;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Acme;
using ModularCA.Shared.Models.Config;
using ModularCA.Core.Services;
using ModularCA.Core.Services.Acme;
using ModularCA.Database;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Utils;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Acme;

/// <summary>
/// ACME order endpoints for certificate issuance, finalization, and revocation (RFC 8555).
/// </summary>
[ApiController]
[Route("api/v1/acme")]
[Route("api/v1/acme/{caLabel}")]
[Route("acme/{caLabel}")]
[AllowAnonymous]
[RequireUnlockedSigner]
[NodeRole(ProcessRole.Enrollment)]
public class AcmeOrderController(
    IAcmeOrderService orderService,
    IAcmeAuthorizationService authzService,
    ICertificateRevocationService revocationService,
    IProtocolAuditService protocolAudit,
    IAcmeAccountRateLimiter acmeAccountLimiter,
    IAuditService audit,
    ILogger<AcmeOrderController> logger,
    SystemConfig config,
    ModularCADbContext db) : ControllerBase
{
    private readonly ModularCADbContext _db = db;
    private readonly IAcmeOrderService _orderService = orderService;
    private readonly IAcmeAuthorizationService _authzService = authzService;
    private readonly ICertificateRevocationService _revocationService = revocationService;
    private readonly IProtocolAuditService _protocolAudit = protocolAudit;
    private readonly IAcmeAccountRateLimiter _acmeAccountLimiter = acmeAccountLimiter;
    private readonly IAuditService _audit = audit;
    private readonly ILogger<AcmeOrderController> _logger = logger;
    private readonly SystemConfig _config = config;

    /// <summary>
    /// Canonical base URL is derived from
    /// <c>SystemConfig.Https.PublicDomain</c>, not the proxy-rewritable
    /// request Host header.
    /// </summary>
    private string GetBaseUrl() => _config.Https.GetPublicHttpsBaseUrl();

    /// <summary>
    /// Create a new certificate order (RFC 8555 §7.4) at the CA the account is bound to, whose
    /// label the order records. A CA that does not serve ACME
    /// (<see cref="AcmeCaPolicy.RefusalAsync"/>) is refused. The order's URLs, the
    /// <c>Location</c> header included, are under that CA's path.
    /// </summary>
    [AcmeJws]
    [HttpPost("new-order")]
    public async Task<IActionResult> NewOrder()
    {
        var jws = GetJws();
        if (jws.AccountId == null)
            return AcmeError(400, "urn:ietf:params:acme:error:malformed", "Account not identified.");

        if (AddressedCa() is not { } ca)
            return AcmeError(404, "urn:ietf:params:acme:error:malformed", "No enabled CA serves this ACME directory.");
        if (await AcmeCaPolicy.RefusalAsync(_db, ca) is { } notServed)
            return AcmeError(403, "urn:ietf:params:acme:error:unauthorized", notServed);

        var request = JsonSerializer.Deserialize<CreateAcmeOrderRequest>(jws.Payload, JsonOpts);
        if (request == null || request.Identifiers.Count == 0)
            return AcmeError(400, "urn:ietf:params:acme:error:malformed", "Identifiers are required.");

        // Validate all identifiers are dns type
        foreach (var id in request.Identifiers)
        {
            if (id.Type != "dns" || string.IsNullOrWhiteSpace(id.Value))
                return AcmeError(400, "urn:ietf:params:acme:error:unsupportedIdentifier",
                    $"Unsupported identifier type: {id.Type}");
        }

        // Per-account new-order budget (default 20/hour).
        if (!await _acmeAccountLimiter.TryRecordNewOrderAsync(jws.AccountId.Value))
            return AcmeError(429, "urn:ietf:params:acme:error:rateLimited",
                "Account has exceeded the new-order rate limit. Try again later.");

        var baseUrl = GetBaseUrl();
        // The filter addressed the account's bound CA, on the label-less routes too, so the order
        // records that CA's label and is finalized there whatever the default becomes.
        var order = await _orderService.CreateAsync(jws.AccountId.Value, request, baseUrl, ca);

        // Record order creation on the ACME audit tab. Previously only finalize/issue/revoke
        // were logged, so the tab gave no visibility into orders that never completed.
        await _protocolAudit.LogAcmeAsync("OrderCreated", jws.AccountId, order.Id,
            subjectDN: null, certSerial: null,
            identifiers: JsonSerializer.Serialize(order.Identifiers), revocationReason: null,
            sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString(),
            caLabel: ca.Label, certificateAuthorityId: ca.Id, spaceId: ca.SpaceId);

        Response.Headers["Location"] = $"{baseUrl}{AcmeCaPolicy.PathPrefix(ca.Label)}/order/{order.Id}";
        return StatusCode(201, order);
    }

    /// <summary>
    /// Get order status (RFC 8555 §7.4 POST-as-GET). Verifies account ownership.
    /// </summary>
    [AcmeJws]
    [HttpPost("order/{id:guid}")]
    public async Task<IActionResult> GetOrder(Guid id)
    {
        var jws = GetJws();
        var orderAccountId = await _orderService.GetAccountIdForOrderAsync(id);
        if (orderAccountId == null)
            return NotFound();
        if (orderAccountId != jws.AccountId)
            return AcmeError(403, "urn:ietf:params:acme:error:unauthorized", "Account does not own this resource.");

        var baseUrl = GetBaseUrl();
        var order = await _orderService.GetByIdAsync(id, baseUrl);
        if (order == null)
            return NotFound();
        return Ok(order);
    }

    /// <summary>
    /// Finalize an order by submitting a CSR (RFC 8555 §7.4). Verifies account ownership, and
    /// finalizes at the CA the account is bound to, refusing an order placed at another CA.
    /// Audit findings #28: emits an <see cref="AuditActionType.AcmeOrderFinalized"/> record
    /// after the certificate is issued and the order status is updated, under that CA.
    /// Audit findings #23: maps <see cref="InvalidOperationException"/> messages from the
    /// service layer (auth-state mismatches, profile errors, internal lookup failures, an expired
    /// order) to a fixed RFC 7807 detail string instead of leaking internal text to anonymous ACME
    /// clients. The original exception is logged at warn level for operator diagnostics, and the
    /// service has written the <c>FinalizeRefused</c> audit row. A certificate-policy refusal is
    /// answered 400: <c>badPublicKey</c> for a key outside the key policy, <c>badCSR</c> otherwise
    /// (RFC 8555 section 7.4); the order is invalid either way, as after any other finalize refusal.
    /// </summary>
    [AcmeJws]
    [HttpPost("order/{id:guid}/finalize")]
    public async Task<IActionResult> FinalizeOrder(Guid id)
    {
        var jws = GetJws();
        var orderAccountId = await _orderService.GetAccountIdForOrderAsync(id);
        if (orderAccountId == null)
            return NotFound();
        if (orderAccountId != jws.AccountId)
            return AcmeError(403, "urn:ietf:params:acme:error:unauthorized", "Account does not own this resource.");

        var request = JsonSerializer.Deserialize<FinalizeAcmeOrderRequest>(jws.Payload, JsonOpts);
        if (request == null || string.IsNullOrEmpty(request.Csr))
            return AcmeError(400, "urn:ietf:params:acme:error:malformed", "CSR is required.");

        // Per-account finalize budget (default 10/hour).
        if (!await _acmeAccountLimiter.TryRecordFinalizeAsync(jws.AccountId!.Value))
            return AcmeError(429, "urn:ietf:params:acme:error:rateLimited",
                "Account has exceeded the finalize rate limit. Try again later.");

        if (AddressedCa() is not { } ca)
            return AcmeError(404, "urn:ietf:params:acme:error:malformed", "No enabled CA serves this ACME directory.");

        try
        {
            var baseUrl = GetBaseUrl();
            var order = await _orderService.FinalizeAsync(id, request.Csr, baseUrl, ca);

            var identifiersJson = System.Text.Json.JsonSerializer.Serialize(order.Identifiers);
            await _protocolAudit.LogAcmeAsync("OrderFinalized", jws.AccountId, id,
                null, null, identifiersJson, null,
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                caLabel: ca.Label, certificateAuthorityId: ca.Id, spaceId: ca.SpaceId);

            // Emit a structured AcmeOrderFinalized audit
            // record with the order id, joined SAN list, and the issued certificate's
            // serial number. Wrapped so an audit failure can't shadow a successful finalize.
            try
            {
                var serial = await _orderService.GetIssuedCertificateSerialForOrderAsync(id);
                var identifiersCsv = string.Join(",", order.Identifiers.Select(i => i.Value));
                await _audit.LogAsync(
                    AuditActionType.AcmeOrderFinalized,
                    actorUserId: null,
                    actorUsername: "acme-client",
                    targetEntityType: "AcmeOrder",
                    targetEntityId: id.ToString(),
                    details: new
                    {
                        OrderId = id,
                        CertificateSerial = serial,
                        IdentifiersCsv = identifiersCsv,
                        CaLabel = ca.Label,
                    },
                    sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString(),
                    certificateAuthorityId: ca.Id,
                    spaceId: ca.SpaceId);
            }
            catch (Exception auditEx)
            {
                _logger.LogWarning(auditEx, "Audit emission for AcmeOrderFinalized failed for order {OrderId}.", id);
            }

            Response.Headers["Location"] = $"{baseUrl}{AcmeCaPolicy.PathPrefix(ca.Label)}/order/{order.Id}";
            return Ok(order);
        }
        catch (CertificatePolicyViolationException ex)
        {
            _logger.LogWarning(ex, "ACME finalize refused by certificate policy for order {OrderId}: {Reason}", id, ex.Message);
            return RefusesSubjectKey(ex)
                ? AcmeError(400, "urn:ietf:params:acme:error:badPublicKey",
                    $"The CSR's public key is not permitted by the key policy. Allowed: {KeyAlgorithmPolicy.AllowedPublicKeysText}.")
                : AcmeError(400, "urn:ietf:params:acme:error:badCSR",
                    "The CSR is not permitted by the certificate policy.");
        }
        catch (Exception ex) when (ex is RequestValidationException or InvalidOperationException)
        {
            // Audit findings #23: ACME service throws InvalidOperationException for many
            // internal states (auth state mismatch, profile missing, CSR/identifier
            // mismatch, CAA failure). The raw message must not flow to anonymous clients.
            _logger.LogWarning(ex, "ACME finalize failed for order {OrderId}: {Reason}", id, ex.Message);
            return AcmeError(403, "urn:ietf:params:acme:error:orderNotReady",
                "Order cannot be finalized in its current state.");
        }
    }

    /// <summary>
    /// Download the issued certificate (RFC 8555 §7.4.2). Verifies account ownership.
    /// </summary>
    [AcmeJws]
    [HttpPost("cert/{id:guid}")]
    public async Task<IActionResult> DownloadCertificate(Guid id)
    {
        var jws = GetJws();
        var orderAccountId = await _orderService.GetAccountIdForOrderAsync(id);
        if (orderAccountId == null)
            return NotFound();
        if (orderAccountId != jws.AccountId)
            return AcmeError(403, "urn:ietf:params:acme:error:unauthorized", "Account does not own this resource.");

        var certPem = await _orderService.DownloadCertificateAsync(id);
        if (certPem == null)
            return NotFound();

        return Content(certPem, "application/pem-certificate-chain");
    }

    /// <summary>
    /// Revoke a certificate (RFC 8555 §7.6). Verifies that the requesting account
    /// originally issued the certificate via ACME before allowing revocation.
    /// Audit findings #23: the catch on <see cref="InvalidOperationException"/> now returns
    /// a fixed RFC 7807 detail string instead of <c>ex.Message</c>; the underlying message
    /// is logged at warn level so operators retain diagnostic information. The
    /// <c>CertificateRevoked</c> protocol audit row names the CA by label and id; every refusal
    /// writes a <c>RevokeRefused</c> row (see <see cref="AuditRevokeRefusedAsync"/>).
    /// </summary>
    // RFC 8555 §6.2 lets revokeCert be signed with an inline jwk. Here that jwk must be an
    // account key: the filter looks the account up by its thumbprint and refuses an unknown key,
    // so revocation by the certificate's own key (§7.6) is not supported.
    [AcmeJws(AllowJwk = true)]
    [HttpPost("revoke-cert")]
    public async Task<IActionResult> RevokeCert()
    {
        var jws = GetJws();
        var request = JsonSerializer.Deserialize<AcmeRevokeCertRequest>(jws.Payload, JsonOpts);
        if (request == null || string.IsNullOrEmpty(request.Certificate))
            return AcmeError(400, "urn:ietf:params:acme:error:malformed", "Certificate is required.");

        string? serial = null;
        string? subject = null;
        try
        {
            // Decode the base64url DER certificate to find the serial
            var certDer = Base64UrlDecode(request.Certificate);
            var parser = new Org.BouncyCastle.X509.X509CertificateParser();
            var cert = parser.ReadCertificate(certDer)
                ?? throw new InvalidOperationException("The certificate could not be read.");
            serial = ModularCA.Shared.Utils.CertificateUtil.FormatSerialNumber(cert.SerialNumber);
            subject = cert.SubjectDN.ToString();

            // Ownership verification: the revoking account must have issued this certificate
            var ownerAccountId = await _orderService.GetAccountIdForCertificateSerialAsync(serial, certDer);
            if (ownerAccountId == null)
            {
                await AuditRevokeRefusedAsync(jws, subject, serial, request.Reason, "Certificate was not issued via ACME.");
                return AcmeError(403, "urn:ietf:params:acme:error:unauthorized",
                    "Certificate was not issued via ACME.");
            }
            if (ownerAccountId != jws.AccountId)
            {
                await AuditRevokeRefusedAsync(jws, subject, serial, request.Reason, "Account did not issue this certificate.");
                return AcmeError(403, "urn:ietf:params:acme:error:unauthorized",
                    "Account did not issue this certificate.");
            }

            // Full RFC 5280 reason code coverage and
            // per-account policy. Reason 2 (cACompromise) and 10 (aACompromise)
            // are reserved for CA operators and are rejected from ACME
            // account-holder revocation with badRevocationReason. Reason 7 is
            // reserved by the RFC.
            ModularCA.Shared.Enums.RevocationReason reason;
            switch (request.Reason)
            {
                case 0: reason = ModularCA.Shared.Enums.RevocationReason.Unspecified; break;
                case 1: reason = ModularCA.Shared.Enums.RevocationReason.KeyCompromise; break;
                case 3: reason = ModularCA.Shared.Enums.RevocationReason.AffiliationChanged; break;
                case 4: reason = ModularCA.Shared.Enums.RevocationReason.Superseded; break;
                case 5: reason = ModularCA.Shared.Enums.RevocationReason.CessationOfOperation; break;
                case 6: reason = ModularCA.Shared.Enums.RevocationReason.CertificateHold; break;
                case 9: reason = ModularCA.Shared.Enums.RevocationReason.PrivilegeWithdrawn; break;
                case 2:
                case 10:
                    await AuditRevokeRefusedAsync(jws, subject, serial, request.Reason, "Revocation reason reserved for CA operators.");
                    return AcmeError(403, "urn:ietf:params:acme:error:badRevocationReason",
                        $"Revocation reason {request.Reason} is reserved for CA operators and cannot be set by ACME account holders.");
                case 8:
                    await AuditRevokeRefusedAsync(jws, subject, serial, request.Reason, "Revocation reason 8 (removeFromCRL) is not supported.");
                    return AcmeError(400, "urn:ietf:params:acme:error:badRevocationReason",
                        "Revocation reason 8 (removeFromCRL) is only valid when reversing a certificate hold via delta CRL and is not supported on the revoke-cert endpoint.");
                default:
                    await AuditRevokeRefusedAsync(jws, subject, serial, request.Reason, "Revocation reason not supported.");
                    return AcmeError(400, "urn:ietf:params:acme:error:badRevocationReason",
                        $"Revocation reason '{request.Reason}' is not supported.");
            }

            await _revocationService.RevokeCertificateAsync(null, serial, reason);

            var ca = AddressedCa();
            await _protocolAudit.LogAcmeAsync("CertificateRevoked", jws.AccountId, null,
                cert.SubjectDN.ToString(), serial, null, reason.ToString(),
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                caLabel: ca?.Label, certificateAuthorityId: ca?.Id, spaceId: ca?.SpaceId);

            return Ok();
        }
        catch (Exception ex) when (ex is RequestValidationException or InvalidOperationException or FormatException)
        {
            // Audit findings #23: do not leak service-layer exception messages to anonymous
            // ACME clients (could include internal state hints, DB lookup failures, or
            // ownership-check details). Log for diagnostics, return a fixed string.
            _logger.LogWarning(ex, "ACME revoke-cert rejected: {Reason}", ex.Message);
            await AuditRevokeRefusedAsync(jws, subject, serial, request.Reason, ex.Message);
            return AcmeError(400, "urn:ietf:params:acme:error:malformed",
                "Certificate revocation request rejected.");
        }
    }

    /// <summary>
    /// Writes a <c>RevokeRefused</c> row on the ACME audit tab under the addressed CA. Revocation
    /// refusals (not issued over ACME, another account's certificate, a reason the account may not
    /// set, an unreadable request) were answered and recorded nowhere. An audit failure is logged
    /// and does not change the answer.
    /// </summary>
    /// <param name="jws">The verified request, which names the account.</param>
    /// <param name="subject">The certificate's subject, when it could be read.</param>
    /// <param name="serial">The certificate's serial, when it could be read.</param>
    /// <param name="reasonCode">The revocation reason the client asked for.</param>
    /// <param name="refusal">Why the revocation was refused, for the operator.</param>
    private async Task AuditRevokeRefusedAsync(AcmeJwsPayload jws, string? subject, string? serial, int? reasonCode, string refusal)
    {
        try
        {
            var ca = AddressedCa();
            await _protocolAudit.LogAcmeAsync("RevokeRefused", jws.AccountId, null,
                subject, serial, null, reasonCode?.ToString(),
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                success: false, errorMessage: refusal,
                caLabel: ca?.Label, certificateAuthorityId: ca?.Id, spaceId: ca?.SpaceId);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Audit emission for a refused ACME revocation failed.");
        }
    }

    private AcmeJwsPayload GetJws() =>
        HttpContext.Items["AcmeJws"] as AcmeJwsPayload
        ?? throw new InvalidOperationException("JWS not parsed.");

    /// <summary>
    /// The CA this request addresses, which <see cref="AcmeJwsActionFilter"/> resolved and held
    /// the signing account to.
    /// </summary>
    private ModularCA.Shared.Entities.CertificateAuthorityEntity? AddressedCa() =>
        HttpContext.Items[AcmeJwsActionFilter.AddressedCaItem] as ModularCA.Shared.Entities.CertificateAuthorityEntity;

    /// <summary>
    /// Whether a certificate-policy refusal is about the subject key: the system key policy, or
    /// the configured minimum RSA key size. RFC 8555 section 7.4 answers those with
    /// <c>badPublicKey</c> and other CSR refusals with <c>badCSR</c>.
    /// </summary>
    /// <param name="refusal">The refusal.</param>
    internal static bool RefusesSubjectKey(CertificatePolicyViolationException refusal)
        => refusal.Violations.Any(v =>
            v.StartsWith($"[{KeyAlgorithmPolicy.RuleName}]", StringComparison.Ordinal)
            || v.StartsWith("[MinRsaKeySize]", StringComparison.Ordinal));

    private ObjectResult AcmeError(int status, string type, string detail)
    {
        var error = new AcmeErrorResponse { Type = type, Detail = detail, Status = status };
        return new ObjectResult(error) { StatusCode = status, ContentTypes = { "application/problem+json" } };
    }

    private static byte[] Base64UrlDecode(string input)
    {
        var s = input.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }
        return Convert.FromBase64String(s);
    }

    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNameCaseInsensitive = true };
}
