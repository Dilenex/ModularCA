using ModularCA.Shared.Utils;
using ModularCA.Core.Services;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Models.Config;
using System.Diagnostics;

namespace ModularCA.API.Middleware;

/// <summary>
/// Logs all HTTP requests (allowed and blocked) to the network audit table.
/// This middleware wraps the entire pipeline so it captures the final status code,
/// response time, and whether the request was blocked by IP whitelisting.
/// Writes are enqueued to <see cref="AuditNetworkDrainService"/>
/// (a bounded channel + batched inserter) instead of a per-request Task.Run, so
/// under ACME/OCSP fan-out the audit sink never saturates the request hot path.
/// </summary>
public class RequestAuditMiddleware
{
    private readonly RequestDelegate _next;
    private readonly bool _enabled;
    private readonly bool _logAll;
    private readonly List<string> _excludePaths;

    /// <summary>
    /// Protocol/admin path prefixes that are always logged when <c>LogAllRequests</c> is false.
    /// </summary>
    private static readonly string[] MonitoredPrefixes =
    {
        "/api/v1/admin", "/api/v1/user", "/api/v1/est", "/api/v1/scep",
        "/api/v1/cmp", "/api/v1/acme", "/api/v1/msae", "/api/v1/public/",
        "/est/", "/scep/", "/cmp/", "/acme/", "/msae/", "/ocsp", "/tsa",
        "/crl/", "/ca/", "/admin"
    };

    /// <summary>
    /// Protocol path prefixes mapped to their protocol name for audit records.
    /// </summary>
    private static readonly (string prefix, string protocol)[] ProtocolPaths =
    {
        ("/api/v1/admin", "ADMIN"),
        ("/api/v1/user", "ADMIN"),
        ("/api/v1/est", "EST"),
        ("/api/v1/scep", "SCEP"),
        ("/api/v1/cmp", "CMP"),
        ("/api/v1/acme", "ACME"),
        ("/api/v1/msae", "MSAE"),
        ("/api/v1/public/ocsp", "OCSP"),
        ("/api/v1/public/tsa", "TSA"),
        ("/est/", "EST"),
        ("/scep/", "SCEP"),
        ("/cmp/", "CMP"),
        ("/acme/", "ACME"),
        ("/msae/", "MSAE"),
        ("/ocsp", "OCSP"),
        ("/tsa", "TSA"),
        ("/crl/", "CRL"),
        ("/ca/", "CA"),
        ("/admin", "ADMIN"),
    };

    /// <summary>
    /// Known sub-paths that are not CA labels (used by ExtractCaLabel).
    /// </summary>
    private static readonly HashSet<string> KnownSubPaths = new(StringComparer.OrdinalIgnoreCase)
    {
        "cacerts", "csrattrs", "simpleenroll", "simplereenroll",
        "new-nonce", "new-account", "new-order", "directory",
        "order", "authz", "challenge", "cert", "key-change", "revoke-cert",
        "account", "ca", "delta", "ces"
    };

    public RequestAuditMiddleware(RequestDelegate next, SystemConfig config)
    {
        _next = next;
        _enabled = config.NetworkAudit.Enabled;
        _logAll = config.NetworkAudit.LogAllRequests;
        _excludePaths = config.NetworkAudit.ExcludePaths;
    }

    /// <summary>
    /// Wraps the full request pipeline, measuring response time and logging the outcome.
    /// </summary>
    public async Task InvokeAsync(HttpContext context)
    {
        if (!_enabled)
        {
            await _next(context);
            return;
        }

        // Enrollment tokens travel in the path; the audit must not keep them.
        var path = AuditPathRedaction.Redact(context.Request.Path.Value);

        // Check if this path should be logged
        if (!ShouldLog(path))
        {
            await _next(context);
            return;
        }

        // Capture timing — log both successful and failed requests
        var sw = Stopwatch.StartNew();
        bool exceptionThrown = false;

        try
        {
            await _next(context);
        }
        catch
        {
            exceptionThrown = true;
            throw; // Re-throw so the exception middleware handles it
        }
        finally
        {
        sw.Stop();
        var elapsed = sw.ElapsedMilliseconds;
        var statusCode = exceptionThrown ? 500 : context.Response.StatusCode;

        // Only mark as blocked if the IP whitelist middleware explicitly flagged it
        var blocked = context.Items.ContainsKey("IpWhitelistBlocked");

        // Determine protocol from path
        var protocol = MatchProtocol(path);

        // Extract CA label from path if possible
        var caLabel = protocol != null ? ExtractCaLabel(path, protocol) : null;

        // Determine reason for blocked requests
        string? reason = blocked ? "IpWhitelist" : null;

        // Get source IP
        var remoteIp = context.Connection.RemoteIpAddress;
        var sourceIp = remoteIp != null
            ? (remoteIp.IsIPv4MappedToIPv6 ? remoteIp.MapToIPv4().ToString() : remoteIp.ToString())
            : "unknown";

        var userAgent = context.Request.Headers.UserAgent.ToString();
        var httpMethod = context.Request.Method;

        // Replace the per-request Task.Run/CreateScope/SaveChangesAsync
        // pattern with a bounded-channel enqueue. The AuditNetworkDrainService batches
        // inserts (100 rows or 1 s). Drops are non-blocking and counted via
        // modularca_audit_network_dropped_total so operators can alert on sustained
        // data loss without the request hot path paying a DB round-trip per call.
        var entity = new AuditNetworkEntity
        {
            SourceIp = sourceIp,
            RequestPath = path,
            HttpMethod = httpMethod,
            StatusCode = statusCode,
            ResponseTimeMs = elapsed,
            Protocol = protocol,
            CaLabel = caLabel,
            Blocked = blocked,
            Reason = reason ?? string.Empty,
            UserAgent = userAgent,
        };

        if (!AuditNetworkDrainService.TryEnqueue(entity))
        {
            // Drop counter already incremented inside TryEnqueue; log a Warning (not Error)
            // so sustained backpressure during load spikes doesn't spam Error-level alerts.
            try
            {
                Serilog.Log.Warning(
                    "Network audit drop: channel full for {HttpMethod} {Path} from {SourceIp} (status={StatusCode}, protocol={Protocol})",
                    httpMethod, path, sourceIp, statusCode, protocol ?? "none");
            }
            catch
            {
                // Absolute last-resort swallow — if even the logger is broken we must
                // not crash the request pipeline.
            }
        }
        } // end finally
    }

    /// <summary>
    /// Determines whether a request path should be audit-logged based on configuration.
    /// Excludes paths in the exclude list; when LogAllRequests is false, only monitors protocol paths.
    /// </summary>
    private bool ShouldLog(string path)
    {
        // Skip excluded paths
        foreach (var exclude in _excludePaths)
        {
            if (path.StartsWith(exclude, StringComparison.OrdinalIgnoreCase))
                return false;
        }

        // If logging all requests, include everything not excluded
        if (_logAll)
            return true;

        // Otherwise, only log monitored protocol/admin paths
        foreach (var prefix in MonitoredPrefixes)
        {
            if (path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    /// <summary>
    /// Matches a request path to a protocol name, or null if not a protocol endpoint.
    /// </summary>
    private static string? MatchProtocol(string path)
    {
        foreach (var (prefix, protocol) in ProtocolPaths)
        {
            if (path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return protocol;
        }
        return null;
    }

    /// <summary>
    /// Extracts the CA label from the URL path, if present.
    /// Handles both /api/v1/{protocol}/{label}/... and /{protocol}/{label}/... patterns.
    /// </summary>
    private static string? ExtractCaLabel(string path, string protocol)
    {
        // Try /api/v1/{protocol}/{label}/... pattern
        var apiPrefix = $"/api/v1/{protocol.ToLowerInvariant()}/";
        if (path.StartsWith(apiPrefix, StringComparison.OrdinalIgnoreCase))
        {
            var rest = path.Substring(apiPrefix.Length);
            var slashIdx = rest.IndexOf('/');
            var candidate = slashIdx >= 0 ? rest.Substring(0, slashIdx) : rest.Split('?')[0];
            if (!KnownSubPaths.Contains(candidate))
                return candidate;
        }

        // Try /{protocol}/{label}/... short URL pattern
        var shortPrefix = $"/{protocol.ToLowerInvariant()}/";
        if (path.StartsWith(shortPrefix, StringComparison.OrdinalIgnoreCase))
        {
            var rest = path.Substring(shortPrefix.Length);
            // Handle /ocsp/ca/{label} special pattern
            if (rest.StartsWith("ca/", StringComparison.OrdinalIgnoreCase))
                rest = rest.Substring(3);
            var slashIdx = rest.IndexOf('/');
            var candidate = slashIdx >= 0 ? rest.Substring(0, slashIdx) : rest.Split('?')[0];
            if (!KnownSubPaths.Contains(candidate))
                return candidate;
        }

        return null;
    }
}
