using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Acme;
using ModularCA.Shared.Models.Config;

namespace ModularCA.API.Filters;

/// <summary>
/// Action filter that validates ACME JWS signatures on incoming requests before the controller runs.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class AcmeJwsAttribute : Attribute, IFilterFactory
{
    /// <summary>
    /// Marks the newAccount endpoint: an inline <c>jwk</c> is accepted and need not belong to an
    /// existing account, and the deactivated-account and unbound-account refusals are left to the
    /// controller. Implies <see cref="AllowJwk"/>.
    /// </summary>
    public bool AllowNewAccount { get; set; }

    /// <summary>
    /// Whether this endpoint accepts a JWS signed with an inline <c>jwk</c> rather than the
    /// account's <c>kid</c>.
    /// </summary>
    /// <remarks>
    /// RFC 8555 §6.2 permits <c>jwk</c> only on newAccount and revokeCert; every other request
    /// must identify the account by key id. The filter used to resolve an account from an inline
    /// jwk on ANY endpoint, so a caller holding the account key could bypass kid entirely —
    /// which, before nonces were required on jwk-signed requests, also meant those requests were
    /// replayable. <see cref="AllowNewAccount"/> implies this.
    /// </remarks>
    public bool AllowJwk { get; set; }
    /// <summary>False: a new filter instance is created for every request.</summary>
    public bool IsReusable => false;

    /// <summary>Creates the <see cref="AcmeJwsActionFilter"/> for one request with this attribute's settings.</summary>
    /// <param name="serviceProvider">The request's service provider, which supplies the ACME services.</param>
    /// <returns>The filter instance.</returns>
    public IFilterMetadata CreateInstance(IServiceProvider serviceProvider)
    {
        return new AcmeJwsActionFilter(
            serviceProvider.GetRequiredService<IAcmeJwsService>(),
            serviceProvider.GetRequiredService<IAcmeNonceService>(),
            serviceProvider.GetRequiredService<IAcmeAccountService>(),
            serviceProvider.GetRequiredService<ICaResolverService>(),
            serviceProvider.GetRequiredService<SystemConfig>(),
            AllowNewAccount,
            AllowJwk);
    }
}

/// <summary>
/// Builds the expected JWS <c>url</c> from the trusted
/// server-side <c>SystemConfig.Https.PublicDomain</c> rather than the
/// proxy-rewritable <c>Host</c> header on the inbound request.
/// Error responses now flow back through an <see cref="ObjectResult"/> with
/// <c>application/problem+json</c> so strict ACME clients can parse §6.7 errors.
/// </summary>
public class AcmeJwsActionFilter(
    IAcmeJwsService jwsService,
    IAcmeNonceService nonceService,
    IAcmeAccountService accountService,
    ICaResolverService caResolver,
    SystemConfig config,
    bool allowNewAccount,
    bool allowJwk) : IAsyncActionFilter
{
    /// <summary>
    /// The <c>HttpContext.Items</c> key holding the <see cref="ModularCA.Shared.Entities.CertificateAuthorityEntity"/>
    /// the request addresses (null when none resolves): for a request signed by an account, the
    /// CA it is bound to; otherwise the CA the route's label names, or the default CA.
    /// </summary>
    public const string AddressedCaItem = "AcmeCa";

    /// <summary>The detail of the refusal of an account at a CA other than the one it is bound to.</summary>
    public const string AccountBoundElsewhere =
        "This account is not registered at this CA. An ACME account is bound to the CA whose directory it registered "
        + "at; register a separate account, with its own key, at this CA's directory.";

    /// <summary>The detail of the refusal of an account the upgrade could not bind to any CA.</summary>
    public const string AccountUnbound =
        "This account is not bound to a CA. Post new-account with the account key to the directory of the CA it "
        + "should use; that binds it.";

    /// <summary>The detail of the refusal of a request signed by a deactivated or revoked account.</summary>
    public const string AccountNotValid =
        "This account is deactivated or revoked and can no longer be used (RFC 8555 §7.3.6). Register a new account "
        + "with a new key.";

    /// <summary>
    /// Runs <see cref="VerifyAndRunAsync"/>, then finishes the response the RFC 8555 way. A request
    /// refused before the action ran gets a fresh Replay-Nonce, as §6.5 asks of error responses and
    /// requires of <c>badNonce</c>, so the client can retry. A payload the action could not read
    /// (a <see cref="JsonException"/> from binding it, such as a member of the wrong type) is
    /// answered 400 <c>malformed</c> rather than escaping as a 500.
    /// </summary>
    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        ActionExecutedContext? executed = null;
        await VerifyAndRunAsync(context, async () => executed = await next());

        if (executed == null)
        {
            await AddReplayNonceAsync(context.HttpContext);
            return;
        }

        if (executed.Exception is JsonException unreadable && !executed.ExceptionHandled)
        {
            Serilog.Log.Information(unreadable, "ACME request payload could not be read for {Path}", context.HttpContext.Request.Path.Value);
            executed.Result = AcmeError(400, "urn:ietf:params:acme:error:malformed",
                "The request payload could not be read: a member does not have the expected type or shape.");
            executed.ExceptionHandled = true;
        }
    }

    /// <summary>
    /// Verifies the JWS, resolves the signing account, refuses a request signed by an account that
    /// is no longer valid, and decides which CA the request addresses; then runs the action.
    /// A request signed by an account addresses the CA the account is bound to: on the label-less
    /// routes that CA, whatever the default is now, and on a labelled route only when the label
    /// names it; any other CA is refused (403 <c>unauthorized</c>). That covers new-order,
    /// finalize, order, authz, challenge, certificate, revocation, key change, account update and
    /// the new-account lookup of an existing key. An unbound account is refused everywhere except
    /// new-account, which addresses the route's CA (the default on the label-less routes) and
    /// binds it there. A new-account request with a new key addresses the route's CA.
    /// A refusal sets <c>context.Result</c> and does not call <paramref name="next"/>. A JWS the
    /// verifier refuses maps to its problem type (<see cref="MapAcmeProblem"/>): <c>badNonce</c>,
    /// <c>badSignatureAlgorithm</c>, <c>badPublicKey</c>, otherwise <c>malformed</c>.
    /// </summary>
    /// <param name="context">The action about to run.</param>
    /// <param name="next">Runs the action.</param>
    private async Task VerifyAndRunAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        var request = context.HttpContext.Request;

        // All ACME POST requests must be application/jose+json
        if (!request.ContentType?.Contains("application/jose+json", StringComparison.OrdinalIgnoreCase) ?? true)
        {
            context.Result = AcmeError(415, "urn:ietf:params:acme:error:malformed", "Content-Type must be application/jose+json.");
            return;
        }

        request.EnableBuffering();
        request.Body.Position = 0;
        using var reader = new StreamReader(request.Body, leaveOpen: true);
        var rawBody = await reader.ReadToEndAsync();
        request.Body.Position = 0;

        AcmeJwsPayload jws;
        try
        {
            // Derive the canonical base URL from SystemConfig
            // (Https.PublicDomain is mandatory at startup) instead of the
            // proxy-rewritable request Host header. Falls back to the request
            // origin only when PublicDomain is unset, which startup fails on in
            // non-setup mode anyway.
            var publicDomain = config.Https.PublicDomain?.Trim();
            string requestUrl;
            if (!string.IsNullOrEmpty(publicDomain))
            {
                requestUrl = $"{config.Https.GetPublicHttpsBaseUrl()}{request.Path}";
            }
            else
            {
                context.Result = AcmeError(400, "urn:ietf:params:acme:error:malformed",
                    "Server misconfigured: Https.PublicDomain is not set.");
                return;
            }
            jws = await jwsService.ParseAndVerifyAsync(rawBody, requestUrl);
        }
        catch (InvalidOperationException ex)
        {
            var (type, detail) = MapAcmeProblem(ex.Message);
            context.Result = AcmeError(400, type, detail);
            return;
        }

        if (jws.Jwk != null && !allowNewAccount && !allowJwk)
        {
            context.Result = AcmeError(400, "urn:ietf:params:acme:error:malformed",
                "This request must be signed with the account key identifier (kid). An inline jwk is "
                + "only permitted on newAccount and revokeCert (RFC 8555 §6.2).");
            return;
        }

        // For new-account with jwk, resolve or create account
        if (allowNewAccount && jws.Jwk != null)
        {
            var existing = await accountService.GetByThumbprintAsync(jws.JwkThumbprint!);
            if (existing != null)
            {
                jws.AccountId = existing.Id;
            }
            // else: new-account will create it
        }
        else if (jws.AccountId == null && jws.Jwk != null)
        {
            // JWK-based request for non-new-account: look up account
            var existing = await accountService.GetByThumbprintAsync(jws.JwkThumbprint!);
            if (existing == null)
            {
                context.Result = AcmeError(400, "urn:ietf:params:acme:error:accountDoesNotExist", "Account not found for the provided JWK.");
                return;
            }
            jws.AccountId = existing.Id;
        }

        // RFC 8555 §7.3.6: a server refuses every request signed by a deactivated account. Status
        // used to be checked only on account update and key change, so after an owner deactivated
        // an account whose key they believed compromised, whoever held the key could still order,
        // finalize, answer challenges and revoke. new-account answers an existing key's lookup
        // itself (with the same refusal), so it is left to the controller.
        if (jws.AccountId is Guid signer && !allowNewAccount)
        {
            var account = await accountService.GetByIdAsync(signer);
            if (account == null)
            {
                context.Result = AcmeError(400, "urn:ietf:params:acme:error:accountDoesNotExist", "Account not found.");
                return;
            }
            if (!string.Equals(account.Status, nameof(ModularCA.Shared.Enums.AcmeAccountStatus.Valid), StringComparison.OrdinalIgnoreCase))
            {
                context.Result = AcmeError(403, "urn:ietf:params:acme:error:unauthorized", AccountNotValid);
                return;
            }
        }

        var routeLabel = context.HttpContext.Request.RouteValues["caLabel"] as string;
        ModularCA.Shared.Entities.CertificateAuthorityEntity? addressedCa;
        if (jws.AccountId is Guid accountId)
        {
            var boundCaId = await accountService.GetBoundCaIdAsync(accountId);
            if (boundCaId == null)
            {
                if (!allowNewAccount)
                {
                    context.Result = AcmeError(403, "urn:ietf:params:acme:error:unauthorized", AccountUnbound);
                    return;
                }
                addressedCa = await caResolver.ResolveCaEntityAsync(routeLabel);
            }
            else
            {
                addressedCa = string.IsNullOrWhiteSpace(routeLabel)
                    ? await accountService.GetBoundCaAsync(accountId)
                    : await caResolver.ResolveCaEntityAsync(routeLabel);
                if (addressedCa == null || addressedCa.Id != boundCaId)
                {
                    context.Result = AcmeError(403, "urn:ietf:params:acme:error:unauthorized", AccountBoundElsewhere);
                    return;
                }
            }
        }
        else
        {
            addressedCa = await caResolver.ResolveCaEntityAsync(routeLabel);
        }

        // Store parsed JWS in HttpContext for controllers
        context.HttpContext.Items["AcmeJws"] = jws;
        context.HttpContext.Items[AddressedCaItem] = addressedCa;

        // Add fresh nonce to response
        await AddReplayNonceAsync(context.HttpContext);

        await next();
    }

    /// <summary>Puts a fresh nonce on the response (RFC 8555 §6.5), not to be cached.</summary>
    /// <param name="http">The request whose response carries it.</param>
    private async Task AddReplayNonceAsync(Microsoft.AspNetCore.Http.HttpContext http)
    {
        http.Response.Headers["Replay-Nonce"] = await nonceService.GenerateAsync();
        http.Response.Headers["Cache-Control"] = "no-store";
    }

    /// <summary>
    /// Problem-type prefixes the JWS verifier stamps onto its exception messages, mapped to the
    /// RFC 8555 problem type each one means. The verifier lives in ModularCA.Core and has no
    /// business constructing HTTP problem documents, so it tags the message and this filter does
    /// the translation — <c>badSignatureAlgorithm:</c> for a rejected <c>alg</c>,
    /// <c>badPublicKey:</c> for a key that is malformed or outside the CA's key-size policy
    /// (RFC 8555 §6.7 defines <c>badPublicKey</c> for exactly that), and <c>badNonce:</c> for a
    /// nonce that is missing, unknown or spent (§6.5). Anything untagged is a generic
    /// malformed-request problem. Ordered longest-prefix-first is unnecessary here since the
    /// prefixes are disjoint.
    /// </summary>
    private static readonly (string Prefix, string Type)[] ProblemPrefixes =
    [
        ("badSignatureAlgorithm:", "urn:ietf:params:acme:error:badSignatureAlgorithm"),
        ("badPublicKey:", "urn:ietf:params:acme:error:badPublicKey"),
        ("badNonce:", "urn:ietf:params:acme:error:badNonce"),
    ];

    /// <summary>
    /// Translates a JWS verifier exception message into an ACME problem type and a detail string
    /// with the routing prefix stripped, so the prefix convention never leaks to the client.
    /// Falls back to <c>urn:ietf:params:acme:error:malformed</c> for untagged messages.
    /// </summary>
    private static (string Type, string Detail) MapAcmeProblem(string message)
    {
        foreach (var (prefix, type) in ProblemPrefixes)
        {
            if (message.StartsWith(prefix, StringComparison.Ordinal))
                return (type, message[prefix.Length..].TrimStart());
        }
        return ("urn:ietf:params:acme:error:malformed", message);
    }

    /// <summary>
    /// Return ACME errors as an <see cref="ObjectResult"/> with
    /// the <c>application/problem+json</c> content type so ASP.NET's MVC
    /// output formatter emits the correct Content-Type header. Previously a
    /// <see cref="JsonResult"/> here could leak <c>application/json</c> on error
    /// paths depending on the formatter pipeline.
    /// </summary>
    private static ObjectResult AcmeError(int status, string type, string detail)
    {
        var error = new AcmeErrorResponse
        {
            Type = type,
            Detail = detail,
            Status = status
        };
        var result = new ObjectResult(error) { StatusCode = status };
        result.ContentTypes.Add("application/problem+json");
        return result;
    }
}
