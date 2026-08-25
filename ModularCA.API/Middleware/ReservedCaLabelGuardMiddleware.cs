using System.Text.Json;

namespace ModularCA.API.Middleware;

/// <summary>
/// Blocks any request whose route resolves a <c>caLabel</c> parameter to a reserved
/// system-only label. Runs after <c>UseRouting</c> so <c>HttpContext.Request.RouteValues</c>
/// is populated, and returns 404 before controller execution. This is the single
/// enforcement point that keeps the System Signing CA off every enrollment protocol
/// (ACME, EST, SCEP, CMP, OCSP, public enrollment) regardless of whether a specific
/// controller remembered to filter the label itself.
/// </summary>
public class ReservedCaLabelGuardMiddleware
{
    private readonly RequestDelegate _next;

    /// <summary>
    /// Labels that identify system-internal CAs which must not serve enrollment
    /// protocols. The System Signing CA signs keystore entries and other system
    /// artifacts; exposing it to ACME/EST/SCEP/CMP/OCSP clients would turn an
    /// internal identity into a public CA.
    /// </summary>
    public static readonly IReadOnlySet<string> ReservedLabels = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "system-signing-ca",
    };

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public ReservedCaLabelGuardMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    /// <summary>
    /// Returns 404 if the matched route binds <c>caLabel</c> to a reserved label.
    /// Lets everything else through unchanged.
    /// </summary>
    public async Task InvokeAsync(HttpContext context)
    {
        // Short-URL routes bind the same value under a DIFFERENT name — PublicShortUrlController
        // uses {serialOrLabel} and resolves it against CertificateAuthorities.Label — so this
        // guard, which only inspected "caLabel", did not see them. GET /ca/system-signing-ca
        // therefore returned the System Signing CA certificate that PublicCaCertController
        // deliberately hides.
        if (!context.Request.RouteValues.TryGetValue("caLabel", out var labelObj))
            context.Request.RouteValues.TryGetValue("serialOrLabel", out labelObj);

        if (labelObj != null
            && labelObj is string label
            && ReservedLabels.Contains(label))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            context.Response.ContentType = "application/problem+json";
            var body = JsonSerializer.Serialize(
                new { type = "urn:ietf:params:acme:error:notFound", detail = $"CA '{label}' is not available for enrollment protocols." },
                JsonOptions);
            await context.Response.WriteAsync(body);
            return;
        }

        await _next(context);
    }
}
