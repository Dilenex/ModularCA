using System.Text.Json;
using ModularCA.Core.Services;

namespace ModularCA.API.Middleware;

/// <summary>
/// Translates <see cref="RequestValidationException"/> into an HTTP 400
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
    /// into an RFC 7807 problem-details response with status 400.
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

            context.Response.Clear();
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            context.Response.ContentType = "application/problem+json";

            object payload = ex switch
            {
                ProfileValidationException profile => new
                {
                    type = "https://tools.ietf.org/html/rfc7231#section-6.5.1",
                    title = profile.Title,
                    status = 400,
                    detail = profile.Message,
                    parameter = profile.Parameter,
                    supplied = profile.SuppliedValue,
                    allowed = profile.AllowedValues,
                    correlationId
                },
                CertificatePolicyViolationException policy => new
                {
                    type = "https://tools.ietf.org/html/rfc7231#section-6.5.1",
                    title = policy.Title,
                    status = 400,
                    detail = policy.Message,
                    violations = policy.Violations,
                    correlationId
                },
                _ => new
                {
                    type = "https://tools.ietf.org/html/rfc7231#section-6.5.1",
                    title = ex.Title,
                    status = 400,
                    detail = ex.Message,
                    correlationId
                }
            };

            await context.Response.WriteAsync(JsonSerializer.Serialize(payload));
        }
    }
}
