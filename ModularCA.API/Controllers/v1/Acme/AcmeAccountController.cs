using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ModularCA.API.Filters;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Acme;
using ModularCA.Shared.Models.Config;
using ModularCA.Core.Services;
using ModularCA.Core.Services.Acme;
using ModularCA.Shared.Errors;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Acme;

/// <summary>
/// ACME account endpoints (RFC 8555 §7.3): registration, account update and deactivation, and key
/// rollover. Open to anonymous callers; each request is a JWS verified by
/// <see cref="AcmeJwsAttribute"/>, so the account key is the credential. Served for the default CA
/// on <c>/api/v1/acme</c> and per CA label, and refused with 503 while the signer is locked.
/// </summary>
[ApiController]
[Route("api/v1/acme")]
[Route("api/v1/acme/{caLabel}")]
[Route("acme/{caLabel}")]
[AllowAnonymous]
[RequireUnlockedSigner]
[NodeRole(ProcessRole.Enrollment)]
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
    /// CA label from the route and the account record stores the label. A new account is bound
    /// to the CA the route addresses (the default CA on the label-less routes), whose EAB policy
    /// applies; an existing key addresses the CA its account is bound to (see
    /// <see cref="AcmeJwsActionFilter"/>). An existing account the upgrade left unbound is bound
    /// here to the route's CA, under that CA's EAB policy as a new account would be. A CA that
    /// does not serve ACME (<see cref="AcmeCaPolicy.RefusalAsync"/>) is refused. An EAB key binds
    /// one account: it is claimed atomically (<see cref="AcmeEabKeyClaim"/>) in the transaction
    /// that creates or binds the account, and a request that loses the claim to a concurrent one
    /// is refused with <c>unauthorized</c> and changes nothing.
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

        if (HttpContext.Items[AcmeJwsActionFilter.AddressedCaItem] is not CertificateAuthorityEntity addressedCa)
            return AcmeError(404, "urn:ietf:params:acme:error:malformed", "No enabled CA serves this ACME directory.");
        if (await AcmeCaPolicy.RefusalAsync(_db, addressedCa) is { } notServed)
            return AcmeError(403, "urn:ietf:params:acme:error:unauthorized", notServed);

        // Global setting OR the addressed CA's own AcmeRequireEab. The per-CA flag was stored
        // and shown and read by nothing, so an operator who required EAB on one CA and left the
        // global switch off got anonymous account creation anyway.
        var eabRequired = await EabRequiredAsync(addressedCa.Id);

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
                Guid? existingEabKeyId = null;
                if (eabRequired)
                {
                    // Pull the stored JWK for the existing account so EAB's
                    // thumbprint check compares against the canonical value,
                    // not whatever raw JWK the caller happens to resend.
                    var storedJwk = jws.Jwk?.GetRawText()
                        ?? await _accountService.GetJwkByIdAsync(existing.Id)
                        ?? "{}";
                    var (eabExistingResult, eabKeyId) = await ValidateExternalAccountBindingAsync(payload, storedJwk);
                    if (eabExistingResult != null)
                        return eabExistingResult;
                    existingEabKeyId = eabKeyId;
                }

                var status = await _accountService.GetStatusByThumbprintAsync(jws.JwkThumbprint);
                if (!string.Equals(status, "Valid", StringComparison.Ordinal))
                {
                    return AcmeError(403, "urn:ietf:params:acme:error:unauthorized",
                        "Account is deactivated.");
                }

                if (await _accountService.GetBoundCaIdAsync(existing.Id) == null)
                {
                    // Binding spends the EAB key, as creating an account does: claimed first, in
                    // the same transaction as the binding, so of two requests with one key only
                    // one binds (AcmeEabKeyClaim).
                    await using var tx = existingEabKeyId != null ? await _db.Database.BeginTransactionAsync() : null;
                    if (existingEabKeyId is Guid claimKey && !await AcmeEabKeyClaim.TryClaimAsync(_db, claimKey, DateTime.UtcNow))
                        return EabKeyAlreadyUsed();
                    if (await _accountService.BindAsync(existing.Id, addressedCa.Id, addressedCa.Label))
                    {
                        if (existingEabKeyId is Guid usedKey)
                            await AcmeEabKeyClaim.RecordAccountAsync(_db, usedKey, existing.Id);
                        if (tx != null)
                            await tx.CommitAsync();
                        await _protocolAudit.LogAcmeAsync("AccountBound", existing.Id, null,
                            subjectDN: null, certSerial: null, identifiers: null, revocationReason: null,
                            sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString(),
                            caLabel: addressedCa.Label, certificateAuthorityId: addressedCa.Id, spaceId: addressedCa.SpaceId);
                    }
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
        Guid? newEabKeyId = null;
        if (eabRequired)
        {
            var (eabResult, eabKeyId) = await ValidateExternalAccountBindingAsync(payload, jwkJson);
            if (eabResult != null)
                return eabResult;
            newEabKeyId = eabKeyId;
        }

        // The check above read the key as unused, as can a concurrent request presenting the same
        // key. The key used to be marked used after the account was created, unconditionally and
        // best-effort, so both requests got an account. It is claimed first now, in the same
        // transaction as the account, and the request that loses the claim creates nothing.
        AcmeAccountDto account;
        await using (var tx = newEabKeyId != null ? await _db.Database.BeginTransactionAsync() : null)
        {
            if (newEabKeyId is Guid claimKey && !await AcmeEabKeyClaim.TryClaimAsync(_db, claimKey, DateTime.UtcNow))
                return EabKeyAlreadyUsed();

            // Persist the CA label the account was created under.
            var caLabel = HttpContext.Request.RouteValues["caLabel"] as string;
            account = await _accountService.CreateAsync(jwkJson, thumbprint, payload.Contact, payload.TermsOfServiceAgreed, addressedCa.Id, caLabel);

            if (newEabKeyId is Guid usedKey)
                await AcmeEabKeyClaim.RecordAccountAsync(_db, usedKey, account.Id);
            if (tx != null)
                await tx.CommitAsync();
        }

        // Surface account registration on the ACME audit tab so operators can see new
        // enrollments, not just issuance/revocation.
        await _protocolAudit.LogAcmeAsync("AccountRegistered", account.Id, null,
            subjectDN: null, certSerial: null, identifiers: null, revocationReason: null,
            sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString(),
            caLabel: addressedCa.Label, certificateAuthorityId: addressedCa.Id, spaceId: addressedCa.SpaceId);

        var accountUrl = $"{baseUrl}{labelPrefix}/account/{account.Id}";
        Response.Headers["Location"] = accountUrl;
        return StatusCode(201, account);
    }

    /// <summary>
    /// Get or update an existing account (RFC 8555 §7.3.2). A deactivation is audited under the
    /// CA the account is bound to, in the main audit log and as an <c>AccountDeactivated</c> row on
    /// the ACME tab, beside the account's <c>AccountRegistered</c>. Any other update (a change of
    /// contact) is an <c>AccountUpdated</c> row on the ACME tab.
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
            var ca = HttpContext.Items[AcmeJwsActionFilter.AddressedCaItem] as CertificateAuthorityEntity;
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
                    CaLabel = ca?.Label,
                    Status = deactivated.Status,
                },
                certificateAuthorityId: ca?.Id,
                spaceId: ca?.SpaceId);

            // The ACME tab showed an account being registered and never its end, so a reader of
            // that tab alone saw an account that simply stopped ordering.
            await _protocolAudit.LogAcmeAsync("AccountDeactivated", id, null,
                subjectDN: null, certSerial: null, identifiers: null, revocationReason: null,
                sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString(),
                caLabel: ca?.Label, certificateAuthorityId: ca?.Id, spaceId: ca?.SpaceId);

            return Ok(deactivated);
        }

        var updated = await _accountService.UpdateAsync(id, request);

        // A change of contact is where expiry and problem notices go from now on. It left no
        // trace; the addresses themselves are not copied into the audit row.
        var addressed = HttpContext.Items[AcmeJwsActionFilter.AddressedCaItem] as CertificateAuthorityEntity;
        await _protocolAudit.LogAcmeAsync("AccountUpdated", id, null,
            subjectDN: null, certSerial: null, identifiers: null, revocationReason: null,
            sourceIp: HttpContext.Connection.RemoteIpAddress?.ToString(),
            caLabel: addressed?.Label, certificateAuthorityId: addressed?.Id, spaceId: addressed?.SpaceId);
        return Ok(updated);
    }

    /// <summary>
    /// Account key rollover (RFC 8555 §7.3.5). Replacing the key replaces the account's only
    /// credential, and it used to leave no record at all. A rollover is now audited in the main
    /// audit log (<c>AcmeAccountKeyChanged</c>, with the old and new key thumbprints) and as an
    /// <c>AccountKeyChanged</c> row on the ACME tab; a refused one is an unsuccessful
    /// <c>KeyChangeRefused</c> row on the ACME tab carrying the reason the client was given.
    /// The new key is the one in the inner JWS header; the inner payload carries <c>account</c>
    /// and <c>oldKey</c>, and a <c>newKey</c> member is optional and must match the header.
    /// </summary>
    [HttpPost("key-change")]
    [AcmeJws]
    public async Task<IActionResult> KeyChange()
    {
        var jws = GetJws();
        var trace = new KeyChangeTrace();
        var result = await KeyChangeCoreAsync(jws, trace);
        if (jws.AccountId is not Guid accountId)
            return result;

        var ca = HttpContext.Items[AcmeJwsActionFilter.AddressedCaItem] as CertificateAuthorityEntity;
        var sourceIp = HttpContext.Connection.RemoteIpAddress?.ToString();
        if (result is ObjectResult { Value: AcmeErrorResponse refusal })
        {
            await _protocolAudit.LogAcmeAsync("KeyChangeRefused", accountId, null,
                subjectDN: null, certSerial: null, identifiers: null, revocationReason: null,
                sourceIp: sourceIp, success: false, errorMessage: refusal.Detail,
                caLabel: ca?.Label, certificateAuthorityId: ca?.Id, spaceId: ca?.SpaceId);
            return result;
        }

        await _audit.LogAsync(
            AuditActionType.AcmeAccountKeyChanged,
            actorUserId: null,
            actorUsername: "acme-client",
            targetEntityType: "AcmeAccount",
            targetEntityId: accountId.ToString(),
            sourceIp: sourceIp,
            details: new
            {
                AccountId = accountId,
                OldJwkThumbprint = trace.OldThumbprint,
                NewJwkThumbprint = trace.NewThumbprint,
                CaLabel = ca?.Label,
            },
            certificateAuthorityId: ca?.Id,
            spaceId: ca?.SpaceId);
        await _protocolAudit.LogAcmeAsync("AccountKeyChanged", accountId, null,
            subjectDN: null, certSerial: null, identifiers: null, revocationReason: null,
            sourceIp: sourceIp,
            caLabel: ca?.Label, certificateAuthorityId: ca?.Id, spaceId: ca?.SpaceId);
        return result;
    }

    /// <summary>The key thumbprints of a rollover that was carried out, for its audit entry.</summary>
    private sealed class KeyChangeTrace
    {
        /// <summary>Thumbprint of the key the account had.</summary>
        public string? OldThumbprint { get; set; }

        /// <summary>Thumbprint of the key the account has now.</summary>
        public string? NewThumbprint { get; set; }
    }

    /// <summary>
    /// Checks a key rollover request and carries it out. Every refusal is returned as an
    /// <see cref="AcmeErrorResponse"/>, which <see cref="KeyChange"/> audits.
    /// </summary>
    /// <param name="jws">The outer JWS, already verified against the account's current key.</param>
    /// <param name="trace">Filled with the thumbprints when the rollover is carried out.</param>
    private async Task<IActionResult> KeyChangeCoreAsync(AcmeJwsPayload jws, KeyChangeTrace trace)
    {
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

        // The new key is the inner header's jwk (RFC 8555 §7.3.5): the keyChange object has only
        // "account" and "oldKey". A "newKey" member was required here, which no standard client
        // sends, so every real key rollover was refused. One that is sent is still held to the
        // header's key, so a client written against the old behaviour keeps working.
        var newJwkJson = innerHeaderJwkProp.GetRawText();
        var payloadNewKeyThumbprint = _jwsService.ComputeThumbprint(newJwkJson);
        if (innerPayload.TryGetProperty("newKey", out var newKeyProp))
        {
            if (newKeyProp.ValueKind != JsonValueKind.Object ||
                !string.Equals(_jwsService.ComputeThumbprint(newKeyProp.GetRawText()), payloadNewKeyThumbprint, StringComparison.Ordinal))
                return AcmeError(400, "urn:ietf:params:acme:error:malformed",
                    "Inner JWS protected header jwk does not match payload newKey.");
        }

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
        trace.OldThumbprint = currentThumbprint;
        trace.NewThumbprint = payloadNewKeyThumbprint;
        return Ok();
    }

    /// <summary>
    /// Validates the externalAccountBinding JWS per RFC 8555 section 7.3.4.
    /// Returns the refusal if validation fails, or no refusal and the id of the EAB key row if the
    /// binding is valid. The key was unused when read; spending it is
    /// <see cref="AcmeEabKeyClaim.TryClaimAsync"/>, which a concurrent request may win.
    /// </summary>
    /// <param name="payload">The new-account payload carrying the binding.</param>
    /// <param name="accountJwkJson">The account key the binding must contain.</param>
    private async Task<(IActionResult? Refusal, Guid? EabKeyId)> ValidateExternalAccountBindingAsync(CreateAcmeAccountRequest payload, string accountJwkJson)
    {
        if (!payload.ExternalAccountBinding.HasValue ||
            payload.ExternalAccountBinding.Value.ValueKind == JsonValueKind.Null)
        {
            return EabRefusal(400, "urn:ietf:params:acme:error:externalAccountRequired",
                "This server requires external account binding for new accounts.");
        }

        var eab = payload.ExternalAccountBinding.Value;

        // The EAB is a JWS with { "protected", "payload", "signature" }
        if (!eab.TryGetProperty("protected", out var eabProtectedProp) ||
            !eab.TryGetProperty("payload", out var eabPayloadProp) ||
            !eab.TryGetProperty("signature", out var eabSignatureProp))
        {
            return EabRefusal(400, "urn:ietf:params:acme:error:malformed",
                "externalAccountBinding must be a JWS with protected, payload, and signature fields.");
        }

        var eabProtectedB64 = eabProtectedProp.GetString();
        var eabPayloadB64 = eabPayloadProp.GetString();
        var eabSignatureB64 = eabSignatureProp.GetString();

        if (string.IsNullOrEmpty(eabProtectedB64) || string.IsNullOrEmpty(eabPayloadB64) || string.IsNullOrEmpty(eabSignatureB64))
        {
            return EabRefusal(400, "urn:ietf:params:acme:error:malformed",
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
            return EabRefusal(400, "urn:ietf:params:acme:error:malformed",
                "externalAccountBinding protected header is not valid base64url-encoded JSON.");
        }

        if (!eabHeader.TryGetProperty("kid", out var kidProp) || string.IsNullOrEmpty(kidProp.GetString()))
        {
            return EabRefusal(400, "urn:ietf:params:acme:error:malformed",
                "externalAccountBinding protected header must contain a 'kid' field.");
        }

        if (!eabHeader.TryGetProperty("alg", out var algProp) || algProp.GetString() != "HS256")
        {
            return EabRefusal(400, "urn:ietf:params:acme:error:malformed",
                "externalAccountBinding must use HS256 algorithm.");
        }

        var keyId = kidProp.GetString()!;

        // Look up the EAB key in the database
        var eabKey = await _db.AcmeEabKeys.FirstOrDefaultAsync(k => k.KeyId == keyId);
        if (eabKey == null)
        {
            return EabRefusal(403, "urn:ietf:params:acme:error:unauthorized",
                "Unknown external account binding key ID.");
        }

        if (eabKey.IsUsed)
        {
            return EabRefusal(403, "urn:ietf:params:acme:error:unauthorized",
                "External account binding key has already been used.");
        }

        if (eabKey.ExpiresAt.HasValue && eabKey.ExpiresAt.Value < DateTime.UtcNow)
        {
            return EabRefusal(403, "urn:ietf:params:acme:error:unauthorized",
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
                return EabRefusal(400, "urn:ietf:params:acme:error:malformed",
                    "externalAccountBinding payload must contain the account public key.");
            }
        }
        catch (Exception ex) when (ex is RequestValidationException or InvalidOperationException)
        {
            return EabRefusal(400, "urn:ietf:params:acme:error:malformed",
                "externalAccountBinding payload JWK is not valid.");
        }
        catch
        {
            return EabRefusal(400, "urn:ietf:params:acme:error:malformed",
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
            return EabRefusal(403, "urn:ietf:params:acme:error:unauthorized",
                "External account binding signature verification failed.");
        }

        return (null, eabKey.Id); // Validation passed
    }

    /// <summary>A refusal from <see cref="ValidateExternalAccountBindingAsync"/>: the problem document and no key.</summary>
    private (IActionResult? Refusal, Guid? EabKeyId) EabRefusal(int status, string type, string detail)
        => (AcmeError(status, type, detail), null);

    /// <summary>
    /// The refusal of a request whose EAB key was spent between its validation and its claim, by a
    /// concurrent request presenting the same key; the same answer as for a key already used.
    /// </summary>
    private ObjectResult EabKeyAlreadyUsed()
        => AcmeError(403, "urn:ietf:params:acme:error:unauthorized", "External account binding key has already been used.");

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
    /// Whether external account binding is required for accounts under CA <paramref name="caId"/>,
    /// the CA the request addresses as <see cref="ICaResolverService.ResolveCaEntityAsync"/>
    /// resolves it, so the policy checked is that of the CA that issues.
    /// </summary>
    private async Task<bool> EabRequiredAsync(Guid caId)
    {
        if (_config.Acme.ExternalAccountRequired)
            return true;

        return await _db.CaProtocolConfigs.AsNoTracking()
            .Where(c => c.CaId == caId && c.Protocol == "ACME")
            .Select(c => c.AcmeRequireEab)
            .FirstOrDefaultAsync();
    }
}
