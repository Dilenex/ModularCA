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
    public bool AllowNewAccount { get; set; }
    public bool IsReusable => false;

    public IFilterMetadata CreateInstance(IServiceProvider serviceProvider)
    {
        return new AcmeJwsActionFilter(
            serviceProvider.GetRequiredService<IAcmeJwsService>(),
            serviceProvider.GetRequiredService<IAcmeNonceService>(),
            serviceProvider.GetRequiredService<IAcmeAccountService>(),
            serviceProvider.GetRequiredService<SystemConfig>(),
            AllowNewAccount);
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
    SystemConfig config,
    bool allowNewAccount) : IAsyncActionFilter
{
    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
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

        // Store parsed JWS in HttpContext for controllers
        context.HttpContext.Items["AcmeJws"] = jws;

        // Add fresh nonce to response
        var newNonce = await nonceService.GenerateAsync();
        context.HttpContext.Response.Headers["Replay-Nonce"] = newNonce;
        context.HttpContext.Response.Headers["Cache-Control"] = "no-store";

        await next();
    }

    /// <summary>
    /// Problem-type prefixes the JWS verifier stamps onto its exception messages, mapped to the
    /// RFC 8555 problem type each one means. The verifier lives in ModularCA.Core and has no
    /// business constructing HTTP problem documents, so it tags the message and this filter does
    /// the translation — <c>badSignatureAlgorithm:</c> for a rejected <c>alg</c>, and
    /// <c>badPublicKey:</c> for a key that is malformed or outside the CA's key-size policy
    /// (RFC 8555 §6.7 defines <c>badPublicKey</c> for exactly that). Anything untagged is a
    /// generic malformed-request problem. Ordered longest-prefix-first is unnecessary here since
    /// the prefixes are disjoint.
    /// </summary>
    private static readonly (string Prefix, string Type)[] ProblemPrefixes =
    [
        ("badSignatureAlgorithm:", "urn:ietf:params:acme:error:badSignatureAlgorithm"),
        ("badPublicKey:", "urn:ietf:params:acme:error:badPublicKey"),
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
