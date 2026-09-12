using System.Text.Json;
using ModularCA.Core.Services;
using ModularCA.Shared.Errors;

namespace ModularCA.API.Middleware;

/// <summary>
/// Translates <see cref="RequestValidationException"/> into a 4xx
/// <c>application/problem+json</c> response, so a request the profile or the certificate policy
/// does not permit gets a clean, actionable error instead of a 500 with a stack trace.
/// </summary>
/// <remarks>
/// Mirrors <see cref="ConcurrencyConflictMiddleware"/> and <see cref="AuditFailClosedMiddleware"/>:
/// catches the single exception family it owns and re-throws everything else. A middleware
/// rather than a per-controller catch because issuance reaches these checks from several entry
/// points (admin issue, admin issue-with-key, admin upload, user upload, the enrollment
/// protocols) and all of them want the same answer.
/// <para>
/// Deriving a new exception from <see cref="RequestValidationException"/> is all that is needed
/// to have it reported correctly here.
/// </para>
/// </remarks>
public sealed class RequestValidationMiddleware(
    RequestDelegate next,
    ILogger<RequestValidationMiddleware> logger)
{
    /// <summary>
    /// Invokes the pipeline and converts a propagated <see cref="RequestValidationException"/>
    /// into an RFC 7807 problem-details response carrying the exception's own status.
    /// </summary>
    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await next(context);
        }
        catch (RequestValidationException ex)
        {
            var correlationId =
                context.Items.TryGetValue("CorrelationId", out var cid) && cid is string s
                    ? s
                    : context.TraceIdentifier;

            // Information, not Error: the server is fine, the request asked for something that
            // is not allowed. Logging these at Error level trains operators to scroll past the
            // stream that also carries genuine failures.
            logger.LogInformation(
                "Request rejected by validation on {Method} {Path} (correlationId={CorrelationId}): {Message}",
                context.Request.Method, context.Request.Path, correlationId, ex.Message);

            if (context.Response.HasStarted)
            {
                throw;
            }

            var status = ex.Status;

            context.Response.Clear();
            context.Response.StatusCode = status;
            context.Response.ContentType = "application/problem+json";

            var type = TypeUriFor(status);

            object payload = ex switch
            {
                ProfileValidationException profile => new
                {
                    type,
                    title = profile.Title,
                    status,
                    detail = profile.Message,
                    parameter = profile.Parameter,
                    supplied = profile.SuppliedValue,
                    allowed = profile.AllowedValues,
                    code = ex.Code,
                    remediation = ex.Remediation,
                    correlationId
                },
                CertificatePolicyViolationException policy => new
                {
                    type,
                    title = policy.Title,
                    status,
                    detail = policy.Message,
                    violations = policy.Violations,
                    code = ex.Code,
                    remediation = ex.Remediation,
                    correlationId
                },
                ResourceNotFoundException notFound => new
                {
                    type,
                    title = notFound.Title,
                    status,
                    detail = notFound.Message,
                    resourceKind = notFound.ResourceKind,
                    identifier = notFound.Identifier,
                    code = ex.Code,
                    remediation = ex.Remediation,
                    correlationId
                },
                _ => new
                {
                    type,
                    title = ex.Title,
                    status,
                    detail = ex.Message,
                    code = ex.Code,
                    remediation = ex.Remediation,
                    correlationId
                }
            };

            await context.Response.WriteAsync(JsonSerializer.Serialize(payload));
        }
    }

    /// <summary>
    /// Returns the problem-type URI for a status code.
    /// </summary>
    /// <remarks>
    /// Every response used to carry the RFC 7231 §6.5.1 link, which is specifically "400 Bad
    /// Request". Once the family gained 404 and 409 members that link became wrong on exactly
    /// the responses a client is most likely to branch on, so the URI now follows the status.
    /// </remarks>
    private static string TypeUriFor(int status) => status switch
    {
        400 => "https://tools.ietf.org/html/rfc7231#section-6.5.1",
        403 => "https://tools.ietf.org/html/rfc7231#section-6.5.3",
        404 => "https://tools.ietf.org/html/rfc7231#section-6.5.4",
        409 => "https://tools.ietf.org/html/rfc7231#section-6.5.8",
        _ => "about:blank",
    };
}
