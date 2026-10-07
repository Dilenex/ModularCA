using System.Net;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;

namespace ModularCA.API.Middleware;

/// <summary>
/// Enforces JWT IP binding by comparing the <c>ip</c> claim in the token against the
/// current request's remote IP. Supports three binding modes through
/// the new <see cref="SecurityConfig.BindJwtToIp"/> tri-state plus a per-token <c>ipm</c>
/// claim. <c>Off</c> skips enforcement entirely. <c>Exact</c> requires a byte-for-byte
/// match. <c>Subnet24</c> allows /24 (IPv4) or /64 (IPv6) subnet tolerance so mobile
/// clients can roam inside a NAT without losing their session. The configured mode is read
/// on every request, so a saved change applies to the next one.
/// </summary>
public class JwtIpBindingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IServiceProvider _serviceProvider;
    private readonly SystemConfig _config;

    /// <summary>
    /// Initializes a new instance of the <see cref="JwtIpBindingMiddleware"/> class.
    /// </summary>
    public JwtIpBindingMiddleware(RequestDelegate next, SystemConfig config, IServiceProvider serviceProvider)
    {
        _next = next;
        _serviceProvider = serviceProvider;
        _config = config;
    }

    /// <summary>
    /// Checks the authenticated user's JWT for an <c>ip</c> claim and compares it against
    /// the current request's remote IP address at the binding granularity dictated by
    /// the token's <c>ipm</c> claim (falling back to the server-configured mode, as it is
    /// set when the request arrives).
    /// </summary>
    public async Task InvokeAsync(HttpContext context)
    {
        var configuredMode = _config.Security.BindJwtToIp;
        if (configuredMode == JwtIpBindingMode.Off)
        {
            await _next(context);
            return;
        }

        var user = context.User;
        if (user?.Identity?.IsAuthenticated == true)
        {
            var boundIp = user.FindFirst("ip")?.Value;
            if (!string.IsNullOrEmpty(boundIp))
            {
                var remoteIp = context.Connection.RemoteIpAddress;
                var currentIpAddr = remoteIp != null
                    ? (remoteIp.IsIPv4MappedToIPv6 ? remoteIp.MapToIPv4() : remoteIp)
                    : null;
                var currentIpStr = currentIpAddr?.ToString() ?? "unknown";

                // Prefer the per-token mode so a token issued as Exact remains Exact
                // even if the server later switches to Subnet24.
                var effectiveMode = configuredMode;
                var ipmClaim = user.FindFirst("ipm")?.Value;
                if (int.TryParse(ipmClaim, out var parsed) && Enum.IsDefined(typeof(JwtIpBindingMode), parsed))
                    effectiveMode = (JwtIpBindingMode)parsed;

                if (!IpMatches(effectiveMode, boundIp, currentIpAddr))
                {
                    // Log the IP mismatch via audit service
                    var userId = user.FindFirst("sub")?.Value;
                    var username = user.FindFirst("name")?.Value ?? user.Identity.Name;

                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            using var scope = _serviceProvider.CreateScope();
                            var auditService = scope.ServiceProvider.GetService<IAuditService>();
                            if (auditService != null)
                            {
                                await auditService.LogAsync(
                                    AuditActionType.UserLoginFailed,
                                    userId != null ? Guid.Parse(userId) : null,
                                    username,
                                    details: new { reason = "IP_MISMATCH", boundIp, currentIp = currentIpStr, mode = effectiveMode.ToString() },
                                    sourceIp: currentIpStr,
                                    success: false,
                                    errorMessage: $"JWT bound to {boundIp} but request originated from {currentIpStr}");
                            }
                        }
                        catch
                        {
                            // Swallow — audit logging must never crash the pipeline
                        }
                    });

                    context.Response.StatusCode = 401;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(
                        "{\"error\":\"Session bound to a different IP address\",\"code\":\"IP_MISMATCH\"}");
                    return;
                }
            }
        }

        await _next(context);
    }

    /// <summary>
    /// True when <paramref name="currentIp"/> is within the binding granularity of
    /// <paramref name="boundIp"/> under the chosen <paramref name="mode"/>.
    /// </summary>
    private static bool IpMatches(JwtIpBindingMode mode, string boundIp, IPAddress? currentIp)
    {
        if (currentIp == null) return false;
        if (!IPAddress.TryParse(boundIp, out var boundAddr)) return false;

        switch (mode)
        {
            case JwtIpBindingMode.Exact:
                return boundAddr.Equals(currentIp);

            case JwtIpBindingMode.Subnet24:
                // /24 for IPv4, /64 for IPv6
                if (boundAddr.AddressFamily != currentIp.AddressFamily) return false;
                var boundBytes = boundAddr.GetAddressBytes();
                var currBytes = currentIp.GetAddressBytes();
                int prefixBytes = boundAddr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 8 : 3;
                if (boundBytes.Length < prefixBytes || currBytes.Length < prefixBytes) return false;
                for (int i = 0; i < prefixBytes; i++)
                    if (boundBytes[i] != currBytes[i]) return false;
                return true;

            case JwtIpBindingMode.Off:
            default:
                return true;
        }
    }
}
