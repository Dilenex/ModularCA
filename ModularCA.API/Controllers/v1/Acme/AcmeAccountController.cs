using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.API.Filters;
using ModularCA.Database;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Acme;
using ModularCA.Shared.Models.Config;
using ModularCA.Core.Services;
using ModularCA.Shared.Errors;

namespace ModularCA.API.Controllers.v1.Acme;

[ApiController]
[Route("api/v1/acme")]
[Route("api/v1/acme/{caLabel}")]
[Route("acme/{caLabel}")]
[AllowAnonymous]
public class AcmeAccountController(
    IAcmeAccountService accountService,
    IAcmeJwsService jwsService,
    ModularCADbContext db,
    SystemConfig config,
    IAuditService audit,
    IProtocolAuditService protocolAudit) : ControllerBase
{
    private readonly IAcmeAccountService _accountService = accountService;
    private readonly IAcmeJwsService _jwsService = jwsService;
    private readonly ModularCADbContext _db = db;
    private readonly SystemConfig _config = config;
    private readonly IAuditService _audit = audit;
    private readonly IProtocolAuditService _protocolAudit = protocolAudit;

    /// <summary>
    /// Canonical base URL sourced from
    /// <c>SystemConfig.Https.PublicDomain</c>.
    /// </summary>
    private string GetBaseUrl() => _config.Https.GetPublicHttpsBaseUrl();

    /// <summary>
    /// When the client posted to <c>/acme/{label}/new-account</c>,
    /// echo the label on the <c>Location</c> header so the client stores a kid
    /// that routes subsequent requests through the labeled subtree.
    /// </summary>
    private string LabelPrefix()
    {
        var caLabel = HttpContext.Request.RouteValues["caLabel"] as string;
        return !string.IsNullOrWhiteSpace(caLabel) ? $"/acme/{caLabel}" : "/api/v1/acme";
    }

    /// <summary>
    /// Create or retrieve an ACME account (RFC 8555 §7.3).
    /// The existing-account fast path rejects deactivated accounts and,
    /// when EAB is required, still runs EAB validation before returning an
    /// existing account. The Location header echoes the
    /// CA label from the route and the account record stores the label.
    /// </summary>
    [HttpPost("new-account")]
    [AcmeJws(AllowNewAccount = true)]
    public async Task<IActionResult> NewAccount()
    {
        var jws = GetJws();
        var payload = string.IsNullOrEmpty(jws.Payload)
            ? new CreateAcmeAccountRequest()
            : JsonSerializer.Deserialize<CreateAcmeAccountRequest>(jws.Payload, JsonOpts)
              ?? new CreateAcmeAccountRequest();

        var baseUrl = GetBaseUrl();
        var labelPrefix = LabelPrefix();

        // Global setting OR the addressed CA's own AcmeRequireEab. The per-CA flag was stored
        // and shown and read by nothing, so an operator who required EAB on one CA and left the
        // global switch off got anonymous account creation anyway.
        var eabRequired = await EabRequiredAsync(HttpContext.Request.RouteValues["caLabel"] as string);

        // Check if account exists AND verify its status before
        // returning the fast path body. Deactivated accounts must be rejected
        // with unauthorized regardless of whether the client asked for
        // onlyReturnExisting.
        if (jws.JwkThumbprint != null)
        {
            var existing = await _accountService.GetByThumbprintAsync(jws.JwkThumbprint);
            if (existing != null)
            {
                // When EAB is required, run validation before
                // returning the existing account body. RFC 8555 §7.3.4 permits
                // this, and it matches Let's Encrypt Boulder behaviour: clients
                // without valid EAB can't observe which keys have accounts.
                if (eabRequired)
                {
                    // Pull the stored JWK for the existing account so EAB's
                    // thumbprint check compares against the canonical value,
                    // not whatever raw JWK the caller happens to resend.
                    var storedJwk = jws.Jwk?.GetRawText()
                        ?? await _accountService.GetJwkByIdAsync(existing.Id)
                        ?? "{}";
                    var eabExistingResult = await ValidateExternalAccountBindingAsync(payload, storedJwk);
                    if (eabExistingResult != null)
                        return eabExistingResult;
                }

                var status = await _accountService.GetStatusByThumbprintAsync(jws.JwkThumbprint);
                if (!string.Equals(status, "Valid", StringComparison.Ordinal))
                {
                    return AcmeError(403, "urn:ietf:params:acme:error:unauthorized",
                        "Account is deactivated.");
                }

                Response.Headers["Location"] = $"{baseUrl}{labelPrefix}/account/{existing.Id}";
                return StatusCode(200, existing);
            }
        }

        if (payload.OnlyReturnExisting)
        {
            // Return the same shape whether or not EAB would
            // have been required, so an unauthenticated caller can't use this
            // endpoint as an existence oracle for account keys.
            return AcmeError(400, "urn:ietf:params:acme:error:accountDoesNotExist",
                "Account does not exist and onlyReturnExisting was set.");
        }

        // Only demand agreement to terms this server actually publishes. RFC 8555 §7.3.3 makes
        // the requirement conditional on advertising meta.termsOfService in the directory, and
        // conforming clients set termsOfServiceAgreed only when they saw a URL to agree to.
        // Rejecting unconditionally (as this did) locked every client out of registration with
        // no way to comply.
        var termsUrl = _config.Acme.PublishedTermsOfServiceUrl;
        if (termsUrl != null && !payload.TermsOfServiceAgreed)
        {
            return AcmeError(400, "urn:ietf:params:acme:error:malformed",
                $"Must agree to the terms of service at {termsUrl}.");
        }

        var jwkJson = jws.Jwk?.GetRawText()
            ?? throw new InvalidOperationException("JWK required for new account.");
        var thumbprint = _jwsService.ComputeThumbprint(jwkJson);

        // Validate External Account Binding if required (RFC 8555 section 7.3.4)
        if (eabRequired)
        {
            var eabResult = await ValidateExternalAccountBindingAsync(payload, jwkJson);
            if (eabResult != null)
                return eabResult;
        }

        // Persist the CA label the account was created under.
        var caLabel = HttpContext.Request.RouteValues["caLabel"] as string;
        var account = await _accountService.CreateAsync(jwkJson, thumbprint, payload.Contact, payload.TermsOfServiceAgreed, caLabel);

        // Surface account registration on the ACME audit tab so operators can see new
        // enrollments, not just issuance/revocation.
        await _protocolAudit.LogAcmeAsync("AccountRegistered", account.Id, null,
            subjectDN: null, certSerial: null, identifiers: null, revocationReason: null,
            sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString(),
            caLabel: caLabel);

        // Mark EAB key as used if present
        if (eabRequired && payload.ExternalAccountBinding.HasValue)
        {
            await MarkEabKeyUsedAsync(payload.ExternalAccountBinding.Value, account.Id);
        }

        var accountUrl = $"{baseUrl}{labelPrefix}/account/{account.Id}";
        Response.Headers["Location"] = accountUrl;
        return StatusCode(201, account);
    }

    /// <summary>
    /// Get or update an existing account (RFC 8555 §7.3.2).
    /// </summary>
    [HttpPost("account/{id:guid}")]
    [AcmeJws]
    public async Task<IActionResult> UpdateAccount(Guid id)
    {
        var jws = GetJws();
        if (jws.AccountId != id)
            return AcmeError(403, "urn:ietf:params:acme:error:unauthorized", "Account ID mismatch.");

        // POST-as-GET (empty payload) = retrieve
        if (string.IsNullOrEmpty(jws.Payload))
        {
            var account = await _accountService.GetByIdAsync(id);
            if (account == null)
                return NotFound();
            return Ok(account);
        }

        var request = JsonSerializer.Deserialize<UpdateAcmeAccountRequest>(jws.Payload, JsonOpts);
        if (request == null)
            return AcmeError(400, "urn:ietf:params:acme:error:malformed", "Invalid request body.");

        // Deactivation
        if (request.Status == "deactivated")
        {
            var deactivated = await _accountService.DeactivateAsync(id);

            // RFC 8555 §7.3.6 account deactivation is an
            // auth-impacting event — a deactivated account can no longer request certs,
            // and an attacker who deactivates a victim's account causes silent DoS.
            // Capture the account key thumbprint, CA label, and source IP so responders
            // can correlate the deactivation with later new-account attempts reusing the
            // same key material.
            var caLabel = HttpContext.Request.RouteValues["caLabel"] as string;
            await _audit.LogAsync(
                AuditActionType.AcmeAccountDeactivated,
                actorUserId: null,
                actorUsername: "acme-client",
                targetEntityType: "AcmeAccount",
                targetEntityId: id.ToString(),
                sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString(),
                details: new
                {
                    AccountId = id,
                    JwkThumbprint = jws.JwkThumbprint,
                    CaLabel = caLabel,
                    Status = deactivated.Status,
                });

            return Ok(deactivated);
        }

        var updated = await _accountService.UpdateAsync(id, request);
        return Ok(updated);
    }

    /// <summary>
    /// Account key rollover (RFC 8555 §7.3.5).
    /// </summary>
    [HttpPost("key-change")]
    [AcmeJws]
    public async Task<IActionResult> KeyChange()
    {
        var jws = GetJws();
        if (jws.AccountId == null)
            return AcmeError(400, "urn:ietf:params:acme:error:malformed", "Account not identified.");

        if (string.IsNullOrEmpty(jws.Payload))
            return AcmeError(400, "urn:ietf:params:acme:error:malformed", "Key change requires inner JWS payload.");

        // The payload is an inner JWS containing the new key
        JsonElement innerJws;
        try
        {
            innerJws = JsonSerializer.Deserialize<JsonElement>(jws.Payload);
        }
        catch
        {
            return AcmeError(400, "urn:ietf:params:acme:error:malformed", "Key change payload is not valid JSON.");
        }

        if (!innerJws.TryGetProperty("protected", out var innerProtectedProp) ||
            !innerJws.TryGetProperty("payload", out var innerPayloadProp))
            return AcmeError(400, "urn:ietf:params:acme:error:malformed", "Key change payload must be a valid inner JWS with protected and payload fields.");

        // Verify inner JWS signature field is present
        if (!innerJws.TryGetProperty("signature", out var innerSignatureProp) ||
            string.IsNullOrEmpty(innerSignatureProp.GetString()))
            return AcmeError(400, "urn:ietf:params:acme:error:malformed", "Key change inner JWS must contain a signature field.");

        var innerProtectedB64 = innerProtectedProp.GetString()!;
        var innerPayloadB64 = innerPayloadProp.GetString()!;
        var innerSignatureB64 = innerSignatureProp.GetString()!;

        // Derive expected url from SystemConfig, not the
        // proxy-rewritable request Host header.
        var basePublic = GetBaseUrl();
        if (string.IsNullOrEmpty(basePublic))
            return AcmeError(400, "urn:ietf:params:acme:error:malformed",
                "Server misconfigured: Https.PublicDomain is not set.");

        // Verify inner JWS header and payload fully. RFC 8555
        // §7.3.5 requires inner `url` match the canonical URL, inner `jwk` field
        // to be set to the new key, and the inner payload to include
        // `{ account, oldKey }`. We additionally reject a no-op rollover where
        // the new key equals the current key.
        JsonElement innerHeader;
        try
        {
            var innerHeaderJson = System.Text.Encoding.UTF8.GetString(Base64UrlDecode(innerProtectedB64));
            innerHeader = JsonSerializer.Deserialize<JsonElement>(innerHeaderJson);
        }
        catch (FormatException)
        {
            return AcmeError(400, "urn:ietf:params:acme:error:malformed", "Inner JWS protected header is not valid base64url-encoded JSON.");
        }
        catch (JsonException)
        {
            return AcmeError(400, "urn:ietf:params:acme:error:malformed", "Inner JWS protected header is not valid JSON.");
        }

        if (!innerHeader.TryGetProperty("url", out var innerUrlProp) ||
            string.IsNullOrEmpty(innerUrlProp.GetString()))
            return AcmeError(400, "urn:ietf:params:acme:error:malformed", "Inner JWS protected header must contain a url field.");

        var requestUrl = $"{basePublic}{Request.Path}";
        if (innerUrlProp.GetString() != requestUrl)
            return AcmeError(400, "urn:ietf:params:acme:error:malformed", "Inner JWS url does not match the request URL.");

        // Inner JWS must carry the new key as `jwk`, not `kid`.
        if (!innerHeader.TryGetProperty("jwk", out var innerHeaderJwkProp) ||
            innerHeaderJwkProp.ValueKind != JsonValueKind.Object)
            return AcmeError(400, "urn:ietf:params:acme:error:malformed", "Inner JWS protected header must contain a jwk field.");
        if (innerHeader.TryGetProperty("kid", out _))
            return AcmeError(400, "urn:ietf:params:acme:error:malformed", "Inner JWS protected header must not contain a kid field.");

        string innerPayloadJson;
        JsonElement innerPayload;
        try
        {
            innerPayloadJson = System.Text.Encoding.UTF8.GetString(Base64UrlDecode(innerPayloadB64));
            innerPayload = JsonSerializer.Deserialize<JsonElement>(innerPayloadJson);
        }
        catch
        {
            return AcmeError(400, "urn:ietf:params:acme:error:malformed", "Inner JWS payload is not valid.");
        }

        // Require `account` to match outer account URL.
        if (!innerPayload.TryGetProperty("account", out var innerAccountProp) ||
            string.IsNullOrEmpty(innerAccountProp.GetString()))
            return AcmeError(400, "urn:ietf:params:acme:error:malformed", "Inner JWS payload must contain account.");

        var labelPrefix = LabelPrefix();
        var outerAccountUrl = $"{basePublic}{labelPrefix}/account/{jws.AccountId.Value}";
        var altAccountUrl = $"{basePublic}/api/v1/acme/account/{jws.AccountId.Value}";
        var claimedAccount = innerAccountProp.GetString()!;
        if (!string.Equals(claimedAccount, outerAccountUrl, StringComparison.Ordinal) &&
            !string.Equals(claimedAccount, altAccountUrl, StringComparison.Ordinal))
            return AcmeError(400, "urn:ietf:params:acme:error:malformed", "Inner JWS payload account does not match outer account URL.");

        // Require oldKey in payload — it must canonicalize to the current
        // account JWK (RFC 8555 §7.3.5).
        if (!innerPayload.TryGetProperty("oldKey", out var oldKeyProp) ||
            oldKeyProp.ValueKind != JsonValueKind.Object)
            return AcmeError(400, "urn:ietf:params:acme:error:malformed", "Inner JWS payload must contain oldKey.");

        // Inner payload is required to contain newKey for the actual key rollover.
        if (!innerPayload.TryGetProperty("newKey", out var newKeyProp) ||
            newKeyProp.ValueKind != JsonValueKind.Object)
            return AcmeError(400, "urn:ietf:params:acme:error:malformed", "Inner JWS payload must contain newKey.");

        var newJwkJson = newKeyProp.GetRawText();

        // The inner header jwk must be the same as the payload newKey.
        var headerJwkThumbprint = _jwsService.ComputeThumbprint(innerHeaderJwkProp.GetRawText());
        var payloadNewKeyThumbprint = _jwsService.ComputeThumbprint(newJwkJson);
        if (!string.Equals(headerJwkThumbprint, payloadNewKeyThumbprint, StringComparison.Ordinal))
            return AcmeError(400, "urn:ietf:params:acme:error:malformed",
                "Inner JWS protected header jwk does not match payload newKey.");

        // Fetch current account JWK to compare thumbprints.
        var currentJwkJson = await _accountService.GetJwkByIdAsync(jws.AccountId.Value)
            ?? throw new InvalidOperationException("Account JWK not found.");
        var currentThumbprint = _jwsService.ComputeThumbprint(currentJwkJson);
        var claimedOldThumbprint = _jwsService.ComputeThumbprint(oldKeyProp.GetRawText());
        if (!string.Equals(currentThumbprint, claimedOldThumbprint, StringComparison.Ordinal))
            return AcmeError(403, "urn:ietf:params:acme:error:unauthorized",
                "oldKey in inner JWS payload does not match the account's current key.");

        // Reject no-op rollover.
        if (string.Equals(currentThumbprint, payloadNewKeyThumbprint, StringComparison.Ordinal))
            return AcmeError(400, "urn:ietf:params:acme:error:malformed",
                "New key is identical to the current account key.");

        // Verify inner JWS signature using the new key
        try
        {
            _jwsService.VerifySignature(innerProtectedB64, innerPayloadB64, innerSignatureB64, newJwkJson);
        }
        catch (Exception ex) when (ex is RequestValidationException or InvalidOperationException)
        {
            return AcmeError(403, "urn:ietf:params:acme:error:unauthorized", "Inner JWS signature verification failed.");
        }

        await _accountService.KeyChangeAsync(jws.AccountId.Value, newJwkJson, payloadNewKeyThumbprint);
        return Ok();
    }

    /// <summary>
    /// Validates the externalAccountBinding JWS per RFC 8555 section 7.3.4.
    /// Returns an error result if validation fails, or null if the binding is valid.
    /// </summary>
    private async Task<IActionResult?> ValidateExternalAccountBindingAsync(CreateAcmeAccountRequest payload, string accountJwkJson)
    {
        if (!payload.ExternalAccountBinding.HasValue ||
            payload.ExternalAccountBinding.Value.ValueKind == JsonValueKind.Null)
        {
            return AcmeError(400, "urn:ietf:params:acme:error:externalAccountRequired",
                "This server requires external account binding for new accounts.");
        }

        var eab = payload.ExternalAccountBinding.Value;

        // The EAB is a JWS with { "protected", "payload", "signature" }
        if (!eab.TryGetProperty("protected", out var eabProtectedProp) ||
            !eab.TryGetProperty("payload", out var eabPayloadProp) ||
            !eab.TryGetProperty("signature", out var eabSignatureProp))
        {
            return AcmeError(400, "urn:ietf:params:acme:error:malformed",
                "externalAccountBinding must be a JWS with protected, payload, and signature fields.");
        }

        var eabProtectedB64 = eabProtectedProp.GetString();
        var eabPayloadB64 = eabPayloadProp.GetString();
        var eabSignatureB64 = eabSignatureProp.GetString();

        if (string.IsNullOrEmpty(eabProtectedB64) || string.IsNullOrEmpty(eabPayloadB64) || string.IsNullOrEmpty(eabSignatureB64))
        {
            return AcmeError(400, "urn:ietf:params:acme:error:malformed",
                "externalAccountBinding JWS fields must not be empty.");
        }

        // Decode the protected header to get the key ID and algorithm
        JsonElement eabHeader;
        try
        {
            var headerJson = System.Text.Encoding.UTF8.GetString(Base64UrlDecode(eabProtectedB64));
            eabHeader = JsonSerializer.Deserialize<JsonElement>(headerJson);
        }
        catch
        {
            return AcmeError(400, "urn:ietf:params:acme:error:malformed",
                "externalAccountBinding protected header is not valid base64url-encoded JSON.");
        }

        if (!eabHeader.TryGetProperty("kid", out var kidProp) || string.IsNullOrEmpty(kidProp.GetString()))
        {
            return AcmeError(400, "urn:ietf:params:acme:error:malformed",
                "externalAccountBinding protected header must contain a 'kid' field.");
        }

        if (!eabHeader.TryGetProperty("alg", out var algProp) || algProp.GetString() != "HS256")
        {
            return AcmeError(400, "urn:ietf:params:acme:error:malformed",
                "externalAccountBinding must use HS256 algorithm.");
        }

        var keyId = kidProp.GetString()!;

        // Look up the EAB key in the database
        var eabKey = await _db.AcmeEabKeys.FirstOrDefaultAsync(k => k.KeyId == keyId);
        if (eabKey == null)
        {
            return AcmeError(403, "urn:ietf:params:acme:error:unauthorized",
                "Unknown external account binding key ID.");
        }

        if (eabKey.IsUsed)
        {
            return AcmeError(403, "urn:ietf:params:acme:error:unauthorized",
                "External account binding key has already been used.");
        }

        if (eabKey.ExpiresAt.HasValue && eabKey.ExpiresAt.Value < DateTime.UtcNow)
        {
            return AcmeError(403, "urn:ietf:params:acme:error:unauthorized",
                "External account binding key has expired.");
        }

        // Compare RFC 7638 JWK thumbprints rather than
        // raw JSON text. The previous byte-equality check was brittle against
        // whitespace and property ordering and also could accept non-canonical
        // JWK forms if both sides happened to match verbatim.
        try
        {
            var innerPayloadJson = System.Text.Encoding.UTF8.GetString(Base64UrlDecode(eabPayloadB64));
            // The payload of the EAB JWS should be the account key (JWK)
            var innerPayloadJwkRaw = JsonSerializer.Deserialize<JsonElement>(innerPayloadJson).GetRawText();

            var innerThumbprint = _jwsService.ComputeThumbprint(innerPayloadJwkRaw);
            var accountThumbprint = _jwsService.ComputeThumbprint(accountJwkJson);

            if (!string.Equals(innerThumbprint, accountThumbprint, StringComparison.Ordinal))
            {
                return AcmeError(400, "urn:ietf:params:acme:error:malformed",
                    "externalAccountBinding payload must contain the account public key.");
            }
        }
        catch (Exception ex) when (ex is RequestValidationException or InvalidOperationException)
        {
            return AcmeError(400, "urn:ietf:params:acme:error:malformed",
                "externalAccountBinding payload JWK is not valid.");
        }
        catch
        {
            return AcmeError(400, "urn:ietf:params:acme:error:malformed",
                "externalAccountBinding payload is not valid.");
        }

        // Verify the HMAC-SHA256 signature
        var hmacKeyBytes = Base64UrlDecode(eabKey.HmacKey);
        var signingInput = System.Text.Encoding.ASCII.GetBytes($"{eabProtectedB64}.{eabPayloadB64}");
        using var hmac = new HMACSHA256(hmacKeyBytes);
        var expectedSignature = hmac.ComputeHash(signingInput);
        var actualSignature = Base64UrlDecode(eabSignatureB64);

        if (!CryptographicOperations.FixedTimeEquals(expectedSignature, actualSignature))
        {
            return AcmeError(403, "urn:ietf:params:acme:error:unauthorized",
                "External account binding signature verification failed.");
        }

        return null; // Validation passed
    }

    /// <summary>
    /// Marks an EAB key as used after successful account creation.
    /// </summary>
    private async Task MarkEabKeyUsedAsync(JsonElement eab, Guid accountId)
    {
        try
        {
            var eabProtectedB64 = eab.GetProperty("protected").GetString()!;
            var headerJson = System.Text.Encoding.UTF8.GetString(Base64UrlDecode(eabProtectedB64));
            var eabHeader = JsonSerializer.Deserialize<JsonElement>(headerJson);
            var keyId = eabHeader.GetProperty("kid").GetString()!;

            var eabKey = await _db.AcmeEabKeys.FirstOrDefaultAsync(k => k.KeyId == keyId);
            if (eabKey != null)
            {
                eabKey.IsUsed = true;
                eabKey.UsedAt = DateTime.UtcNow;
                eabKey.UsedByAccountId = accountId;
                await _db.SaveChangesAsync();
            }
        }
        catch
        {
            // Best-effort; account was already created
        }
    }

    private AcmeJwsPayload GetJws() =>
        HttpContext.Items["AcmeJws"] as AcmeJwsPayload
        ?? throw new InvalidOperationException("JWS not parsed.");

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

    /// <summary>
    /// Whether external account binding is required for accounts under the given CA.
    /// </summary>
    private async Task<bool> EabRequiredAsync(string? caLabel)
    {
        if (_config.Acme.ExternalAccountRequired)
            return true;

        var cas = _db.CertificateAuthorities.AsNoTracking().Where(c => c.IsEnabled);
        cas = string.IsNullOrWhiteSpace(caLabel)
            ? cas.OrderByDescending(c => c.IsDefault)
            : cas.Where(c => c.Label == caLabel);
        var caId = await cas.Select(c => (Guid?)c.Id).FirstOrDefaultAsync();
        if (caId == null)
            return false;

        return await _db.CaProtocolConfigs.AsNoTracking()
            .Where(c => c.CaId == caId && c.Protocol == "ACME")
            .Select(c => c.AcmeRequireEab)
            .FirstOrDefaultAsync();
    }
}
