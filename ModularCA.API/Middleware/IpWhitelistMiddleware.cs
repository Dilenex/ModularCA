using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using System.Net;

namespace ModularCA.API.Middleware;

/// <summary>
/// IP whitelist enforcement. Delegates all rule lookup and CIDR matching to
/// <see cref="IWhitelistService"/>'s in-memory snapshot, so there is no
/// per-request database hit and no path-bucket derivation logic duplicated
/// in the middleware. Pre-bootstrap (when the service has not yet warmed
/// from the database), applies a hardcoded RFC1918 / loopback fallback
/// sourced from <see cref="WhitelistDefaults.InternalOnlyCidrs"/> to the
/// <c>/setup/*</c> and <c>/api/v1/setup/*</c> paths so the setup wizard is
/// internal-only before the database exists. Every other path passes through
/// in that state only when the process started in setup mode; a configured
/// instance whose snapshot never loaded gates every path against the same
/// fallback, and a stale snapshot is evaluated rather than ignored.
/// Preserves the <c>config.IpWhitelist.Enabled</c> master kill switch and
/// the YAML-sourced <c>ExemptPaths</c> list (path exclusion, not IP allow
/// list — a separate concept that stays in config.yaml). Blocked requests
/// return an HTTP 403 with a plain-text body and set
/// <c>HttpContext.Items["IpWhitelistBlocked"] = true</c> so
/// <see cref="RequestAuditMiddleware"/> can record the denial in the audit
/// log.
/// </summary>
public class IpWhitelistMiddleware
{
    private readonly RequestDelegate _next;
    private readonly SystemConfig _config;
    private readonly IWhitelistService _whitelistService;
    private readonly bool _enabled;

    // Whether this process started without a config.yaml, i.e. a genuinely fresh install where
    // nothing exists yet to protect. Decided once: the file appears only when setup completes,
    // and setup ends by restarting the process. Read the same way SetupRedirectMiddleware reads
    // it, so the two agree on what "setup mode" is.
    private readonly bool _startedInSetupMode;

    /// <summary>
    /// Constructs the middleware. The master kill switch is captured once
    /// at startup from <c>config.IpWhitelist.Enabled</c>; flipping it at
    /// runtime requires a restart (same behavior as before).
    /// </summary>
    /// <param name="next">The next delegate in the pipeline.</param>
    /// <param name="config">System configuration for the kill switch and exempt paths.</param>
    /// <param name="whitelistService">Centralized whitelist evaluator backed by the in-memory snapshot of the <c>Whitelists</c> table.</param>
    public IpWhitelistMiddleware(RequestDelegate next, SystemConfig config, IWhitelistService whitelistService)
    {
        _next = next;
        _config = config;
        _whitelistService = whitelistService;
        _enabled = config.IpWhitelist.Enabled;
        _startedInSetupMode = !File.Exists(Path.Combine(AppContext.BaseDirectory, "config", "config.yaml"));
    }

    /// <summary>
    /// Evaluates the incoming request against the whitelist snapshot (or
    /// the pre-bootstrap fallback if the service has not yet warmed) and
    /// either passes the request to the next middleware or returns 403.
    /// </summary>
    public async Task InvokeAsync(HttpContext context)
    {
        // Master kill switch — whitelist enforcement fully disabled.
        if (!_enabled)
        {
            await _next(context);
            return;
        }

        var path = context.Request.Path.Value ?? "";

        // YAML exempt paths — path exclusion layer, bypasses IP checks entirely.
        foreach (var exempt in _config.IpWhitelist.ExemptPaths)
        {
            if (path.StartsWith(exempt, StringComparison.OrdinalIgnoreCase))
            {
                await _next(context);
                return;
            }
        }

        var remoteIp = context.Connection.RemoteIpAddress;
        if (remoteIp != null && remoteIp.IsIPv4MappedToIPv6)
        {
            remoteIp = remoteIp.MapToIPv4();
        }

        // Cold snapshot handling. "Not warm" covers three different situations, and they
        // used to get one answer (gate setup and admin against RFC 1918, pass everything
        // else), which was right for exactly one of them:
        //
        //   1. A stale snapshot exists: the boot-time load succeeded and a later reload
        //      failed. Evaluate against the stale snapshot. Rules that were right a minute
        //      ago are far better than none.
        //   2. No snapshot, and the process started in setup mode: a fresh install. Only
        //      the wizard exists; gate it and pass the rest. The original design.
        //   3. No snapshot, and the process did NOT start in setup mode: the database was
        //      unreachable at boot, on an instance that has CAs and protocol endpoints.
        //      Passing traffic through here opened ACME, EST, CMP, SCEP and the integration
        //      API to any source address for as long as the outage lasted, and with no
        //      re-warm timer, for the life of the process. Gate every path against the
        //      RFC 1918 fallback, the same default a new rule gets.
        //
        // WhitelistRewarmService retries the load in the background so states 2 and 3 end
        // when the database comes back rather than at the next admin edit.
        if (!_whitelistService.IsWarm && !_whitelistService.HasSnapshot)
        {
            var isSetupPath = path.StartsWith("/setup/", StringComparison.OrdinalIgnoreCase)
                           || path.StartsWith("/api/v1/setup/", StringComparison.OrdinalIgnoreCase)
                           || path.Equals("/setup", StringComparison.OrdinalIgnoreCase)
                           || path.Equals("/api/v1/setup", StringComparison.OrdinalIgnoreCase);
            var isAdminPath = path.StartsWith("/admin/", StringComparison.OrdinalIgnoreCase)
                           || path.StartsWith("/api/v1/admin/", StringComparison.OrdinalIgnoreCase)
                           || path.Equals("/admin", StringComparison.OrdinalIgnoreCase)
                           || path.Equals("/api/v1/admin", StringComparison.OrdinalIgnoreCase);
            if (isSetupPath || isAdminPath || !_startedInSetupMode)
            {
                if (remoteIp == null)
                {
                    context.Items["IpWhitelistBlocked"] = true;
                    context.Response.StatusCode = 403;
                    context.Response.ContentType = "text/plain";
                    await context.Response.WriteAsync("IP address could not be determined");
                    return;
                }

                var fallbackNetworks = CidrMatcher.ParseNetworks(WhitelistDefaults.InternalOnlyCidrs);
                if (!CidrMatcher.IsAllowed(remoteIp, fallbackNetworks))
                {
                    var surface = isSetupPath ? "setup" : isAdminPath ? "admin" : "all endpoints while the whitelist is unavailable";
                    context.Items["IpWhitelistBlocked"] = true;
                    context.Response.StatusCode = 403;
                    context.Response.ContentType = "text/plain";
                    await context.Response.WriteAsync($"Access denied: {remoteIp} is not in the allowed IP ranges for {surface} (pre-bootstrap RFC1918 fallback)");
                    return;
                }

                // Gated path from an internal network — allow through.
                await _next(context);
                return;
            }

            // Non-setup, non-admin path on a fresh install: nothing exists to protect yet.
            await _next(context);
            return;
        }

        // Service-backed evaluation against the in-memory snapshot, current or stale.
        var decision = _whitelistService.Evaluate(path, remoteIp);

        switch (decision)
        {
            case WhitelistDecision.Allow:
            case WhitelistDecision.NotCovered:
                await _next(context);
                return;

            case WhitelistDecision.Deny:
                if (remoteIp == null)
                {
                    context.Items["IpWhitelistBlocked"] = true;
                    context.Response.StatusCode = 403;
                    context.Response.ContentType = "text/plain";
                    await context.Response.WriteAsync("IP address could not be determined");
                    return;
                }
                context.Items["IpWhitelistBlocked"] = true;
                context.Response.StatusCode = 403;
                context.Response.ContentType = "text/plain";
                await context.Response.WriteAsync($"Access denied: {remoteIp} is not in the allowed IP ranges for {path}");
                return;

            default:
                await _next(context);
                return;
        }
    }
}
