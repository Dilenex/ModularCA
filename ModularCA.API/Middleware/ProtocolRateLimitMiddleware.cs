using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using ModularCA.Shared.Interfaces;

namespace ModularCA.API.Middleware;

/// <summary>
/// Rate-limiting middleware that throttles protocol-specific endpoints (ACME,
/// EST, SCEP, CMP, OCSP, TSA, CRL, CA download, and <c>/health</c>) per IP
/// address. Limiter state now lives in
/// <see cref="IDistributedCache"/> (same as
/// <see cref="LoginRateLimitMiddleware"/>), with a local
/// <see cref="ConcurrentDictionary{TKey, TValue}"/> fallback when the cache is
/// unreachable. Default buckets now cover the entire plain-HTTP PKI surface so
/// an anonymous flood cannot saturate the DB connection pool.
/// <para>
/// Per-protocol overrides come from the DB-backed <c>ProtocolRateLimits</c> table
/// via <see cref="IProtocolRateLimitService"/> — resolved per-request so admin
/// changes take effect on the next request scope (no restart required).
/// </para>
/// </summary>
public class ProtocolRateLimitMiddleware
{
    private readonly RequestDelegate _next;

    // Local fallback store, used when IDistributedCache is not resolvable.
    private static readonly ConcurrentDictionary<string, Queue<DateTime>> _requestLog = new();
    private static DateTime _lastCleanup = DateTime.UtcNow;

    // Map protocol names to URL path prefixes
    // Public CRL endpoints get their own rate-limit bucket so a
    // malicious client can't exhaust DB IO by hammering /crl/{label} or
    // /api/v1/public/crl/{serial} at full throttle.
    // Add /ca/, /api/v1/public/ca, /health, /tsa short
    // prefixes so the plain-HTTP surface is fully throttled.
    private static readonly Dictionary<string, string> ProtocolPrefixes = new(StringComparer.OrdinalIgnoreCase)
    {
        { "EST", "/api/v1/est" },
        { "SCEP", "/api/v1/scep" },
        { "CMP", "/api/v1/cmp" },
        // The enrollment controllers also serve /est/{caLabel}, /scep/{caLabel} and
        // /cmp/{caLabel} — the SHORT forms are the ones documented to clients and therefore the
        // ones an attacker reaches for. Only the /api/v1 forms were bucketed, so the primary
        // enrollment surface was unthrottled while its alias was limited. The other short
        // prefixes below (OCSP/TSA/CRL/CA) already had this treatment; enrollment was missed.
        { "EST_SHORT", "/est/" },
        // RFC 7030 section 3.2.2 form. Same omission as the short prefixes above, one route later.
        { "EST_WELLKNOWN", "/.well-known/est/" },
        // Anonymous CSR parsing behind a URL token. The token is 256-bit so guessing is not the
        // concern; unbounded ASN.1 parsing from any source is.
        { "PUBLIC_ENROLL", "/api/v1/public/enroll" },
        { "SCEP_SHORT", "/scep/" },
        { "CMP_SHORT", "/cmp/" },
        // Windows autoenrollment (MS-WSTEP). Same long/short pairing as the others.
        { "MSAE", "/api/v1/msae" },
        { "MSAE_SHORT", "/msae/" },
        { "ACME", "/api/v1/acme" },
        { "OCSP", "/api/v1/public/ocsp" },
        { "OCSP_SHORT", "/ocsp" },
        { "TSA", "/api/v1/public/tsa" },
        { "TSA_SHORT", "/tsa" },
        { "Integration", "/api/v1/integration" },
        { "CRL", "/api/v1/public/crl" },
        { "CRL_SHORT", "/crl/" },
        { "CA", "/api/v1/public/ca" },
        { "CA_SHORT", "/ca/" },
        { "HEALTH", "/health" },
    };

    // Default rate limits for protocols not explicitly configured via the DB.
    // Generous per-IP per-minute caps for each plain-HTTP bucket.
    // 60 req/min is comfortable for legitimate clients (CRL refresh is typically
    // hourly or daily) but closes the "hammer the anonymous surface to saturate DB IO" vector.
    // Enrollment / OCSP / TSA defaults are safety nets for deployments where the admin
    // has DELETEd the seeded DB row — the primary configuration surface is the
    // ProtocolRateLimits table, seeded by BootstrapProfileSeeder.SeedProtocolRateLimits.
    private static readonly Dictionary<string, (int maxRequests, int windowMinutes)> DefaultLimits = new(StringComparer.OrdinalIgnoreCase)
    {
        { "EST", (100, 1) },
        { "SCEP", (50, 1) },
        { "CMP", (100, 1) },
        // Mirror the long-form caps: these are the same operations reached by a different URL,
        // so a client that respects one should never notice the other. Not seeded into
        // ProtocolRateLimits, so these defaults are the live values unless an operator adds rows.
        { "EST_SHORT", (100, 1) },
        { "EST_WELLKNOWN", (100, 1) },
        { "PUBLIC_ENROLL", (30, 1) },
        { "SCEP_SHORT", (50, 1) },
        { "CMP_SHORT", (100, 1) },
        { "MSAE", (100, 1) },
        { "MSAE_SHORT", (100, 1) },
        { "ACME", (200, 1) },
        { "Integration", (60, 1) },
        { "CRL", (60, 1) },
        { "CRL_SHORT", (60, 1) },
        { "CA", (60, 1) },
        { "CA_SHORT", (60, 1) },
        { "OCSP", (1000, 1) },
        { "OCSP_SHORT", (120, 1) },
        { "TSA", (500, 1) },
        { "TSA_SHORT", (60, 1) },
        { "HEALTH", (120, 1) },
    };

    /// <summary>
    /// Per-operation ACME buckets applied in addition to
    /// the protocol-wide /api/v1/acme bucket above. Keyed on path fragment so
    /// both /api/v1/acme/* and /acme/{label}/* variants match. Per-IP limits
    /// with hour-long windows are the conventional "fair use" defaults used by
    /// Let's Encrypt Boulder. Per-account limits live in
    /// <c>IAcmeAccountRateLimiter</c> and are enforced by the controllers after
    /// the JWS filter resolves the account id.
    /// </summary>
    private static readonly (string fragment, int max, int windowMinutes)[] AcmeOperationBuckets = new[]
    {
        ("/new-account", 10, 60),
        ("/new-order",   20, 60),
        ("/finalize",    10, 60),
        ("/revoke-cert", 10, 60),
    };

    /// <summary>
    /// Constructs the middleware. Per-protocol limits are resolved per-request
    /// via <see cref="IProtocolRateLimitService"/> so admin changes take effect
    /// without a restart.
    /// </summary>
    public ProtocolRateLimitMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    /// <summary>
    /// Builds the effective per-prefix limit map for a single request by
    /// merging DB overrides on top of the middleware-built-in defaults.
    /// </summary>
    private static async Task<Dictionary<string, (string pathPrefix, int maxRequests, TimeSpan window)>> BuildProtocolLimitsAsync(
        IProtocolRateLimitService? policyService)
    {
        var result = new Dictionary<string, (string pathPrefix, int maxRequests, TimeSpan window)>(StringComparer.OrdinalIgnoreCase);

        IReadOnlyDictionary<string, (int MaxRequests, int WindowMinutes)> overrides =
            policyService != null
                ? await policyService.GetAllAsync()
                : new Dictionary<string, (int, int)>();

        foreach (var (protocol, (max, windowMinutes)) in overrides)
        {
            if (ProtocolPrefixes.TryGetValue(protocol, out var prefix))
            {
                result[prefix] = (prefix, max, TimeSpan.FromMinutes(windowMinutes));
            }
        }

        // Apply defaults for protocols that weren't explicitly overridden.
        foreach (var (protocol, (maxRequests, windowMinutes)) in DefaultLimits)
        {
            if (ProtocolPrefixes.TryGetValue(protocol, out var prefix) && !result.ContainsKey(prefix))
            {
                result[prefix] = (prefix, maxRequests, TimeSpan.FromMinutes(windowMinutes));
            }
        }

        return result;
    }

    /// <summary>
    /// Evaluates incoming requests against per-protocol, per-IP rate limits and
    /// sets standard rate limit response headers. Returns 429 Too Many Requests
    /// when the limit is exceeded. Normalizes the request path to prevent bypass
    /// via trailing slashes or matrix parameters.
    /// </summary>
    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value?.TrimEnd('/') ?? "";
        // Normalize: remove any matrix parameters (semicolons)
        var semicolonIndex = path.IndexOf(';');
        if (semicolonIndex >= 0)
            path = path[..semicolonIndex];

        // Fast-path for non-protocol paths: if the request isn't targeted at any
        // prefix we care about (SPA assets, /public/*, /favicon.ico, root path,
        // static admin/setup UI, anything uncategorized), skip the DB-backed
        // policy query entirely. This keeps ProtocolRateLimitMiddleware zero-cost
        // for the 95% of requests that have no protocol bucket AND prevents
        // pre-bootstrap DB crashes on setup-UI asset requests.
        bool couldMatchProtocol =
            path.Contains("/acme/", StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith("/acme/", StringComparison.OrdinalIgnoreCase);
        if (!couldMatchProtocol)
        {
            foreach (var prefix in ProtocolPrefixes.Values)
            {
                if (path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    couldMatchProtocol = true;
                    break;
                }
            }
        }
        if (!couldMatchProtocol)
        {
            await _next(context);
            return;
        }

        // ACME per-operation sub-bucket runs BEFORE the
        // shared /api/v1/acme prefix bucket so a client that spams finalize
        // hits the finalize limit first (not the shared-protocol one). Both
        // apply — exhausting either returns 429.
        if (path.Contains("/acme/", StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith("/acme/", StringComparison.OrdinalIgnoreCase))
        {
            var ipForAcme = GetClientIp(context);
            if (ipForAcme != null)
            {
                foreach (var (fragment, max, windowMinutes) in AcmeOperationBuckets)
                {
                    if (path.EndsWith(fragment, StringComparison.OrdinalIgnoreCase))
                    {
                        var opKey = $"rl:acme-op:{fragment}:{ipForAcme}";
                        var opWindow = TimeSpan.FromMinutes(windowMinutes);
                        var (opLimited, _) = await CheckRateLimitAsync(context, opKey, max, opWindow);
                        if (opLimited)
                        {
                            context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                            context.Response.Headers["Retry-After"] = ((int)opWindow.TotalSeconds).ToString();
                            context.Response.ContentType = "application/problem+json";
                            await context.Response.WriteAsJsonAsync(new
                            {
                                type = "urn:ietf:params:acme:error:rateLimited",
                                detail = $"ACME operation '{fragment.TrimStart('/')}' is rate-limited. Try again later.",
                                status = 429
                            });
                            return;
                        }
                        break;
                    }
                }
            }
        }

        var policyService = context.RequestServices.GetService<IProtocolRateLimitService>();
        var protocolLimits = await BuildProtocolLimitsAsync(policyService);

        foreach (var (prefix, limitConfig) in protocolLimits)
        {
            if (path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                var ip = GetClientIp(context);
                if (ip != null)
                {
                    var key = $"rl:proto:{prefix}:{ip}";
                    var (limited, currentCount) = await CheckRateLimitAsync(context, key, limitConfig.maxRequests, limitConfig.window);

                    var remaining = Math.Max(0, limitConfig.maxRequests - currentCount);
                    var windowEnd = DateTimeOffset.UtcNow.Add(limitConfig.window);

                    context.Response.Headers["X-RateLimit-Limit"] = limitConfig.maxRequests.ToString();
                    context.Response.Headers["X-RateLimit-Remaining"] = remaining.ToString();
                    context.Response.Headers["X-RateLimit-Reset"] = windowEnd.ToUnixTimeSeconds().ToString();

                    if (limited)
                    {
                        var secondsUntilReset = (int)limitConfig.window.TotalSeconds;

                        context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                        context.Response.Headers["Retry-After"] = secondsUntilReset.ToString();

                        // ACME has its own error format
                        if (prefix.Contains("/acme", StringComparison.OrdinalIgnoreCase))
                        {
                            context.Response.ContentType = "application/problem+json";
                            await context.Response.WriteAsJsonAsync(new
                            {
                                type = "urn:ietf:params:acme:error:rateLimited",
                                detail = "Too many requests. Try again later.",
                                status = 429
                            });
                        }
                        else
                        {
                            await context.Response.WriteAsJsonAsync(new
                            {
                                error = "Too many requests. Try again later.",
                                retryAfterSeconds = secondsUntilReset
                            });
                        }
                        return;
                    }
                }
                break;
            }
        }

        await _next(context);
    }

    /// <summary>
    /// Sliding-window rate-limit check backed by <see cref="IDistributedCache"/>
    /// when available, falling back to a process-local dict otherwise. Mirrors
    /// the approach used by <see cref="LoginRateLimitMiddleware"/>.
    /// </summary>
    private static async Task<(bool limited, int currentCount)> CheckRateLimitAsync(
        HttpContext context, string key, int maxRequests, TimeSpan window)
    {
        var cache = context.RequestServices.GetService<IDistributedCache>();
        if (cache != null)
        {
            try
            {
                var now = DateTime.UtcNow;
                var cutoff = now - window;

                var raw = await cache.GetStringAsync(key);
                List<long> timestamps = raw != null
                    ? JsonSerializer.Deserialize<List<long>>(raw) ?? new List<long>()
                    : new List<long>();

                timestamps.RemoveAll(t => DateTime.FromBinary(t) < cutoff);

                if (timestamps.Count >= maxRequests)
                {
                    // Refresh TTL so the entry doesn't evict under steady abuse.
                    await cache.SetStringAsync(key, JsonSerializer.Serialize(timestamps),
                        new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = window });
                    return (true, timestamps.Count);
                }

                timestamps.Add(now.ToBinary());
                await cache.SetStringAsync(key, JsonSerializer.Serialize(timestamps),
                    new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = window });
                return (false, timestamps.Count);
            }
            catch
            {
                // Fall through to local fallback on any cache failure.
            }
        }

        return CheckRateLimitLocal(key, maxRequests, window);
    }

    /// <summary>
    /// Local fallback used when the distributed cache isn't resolvable.
    /// Maintains a sliding window keyed by the opaque bucket id.
    /// </summary>
    private static (bool limited, int currentCount) CheckRateLimitLocal(string key, int maxRequests, TimeSpan window)
    {
        var now = DateTime.UtcNow;

        // Periodic cleanup
        if (now - _lastCleanup > TimeSpan.FromMinutes(5))
        {
            _lastCleanup = now;
            foreach (var k in _requestLog.Keys.ToList())
            {
                if (_requestLog.TryGetValue(k, out var q))
                {
                    lock (q) { while (q.Count > 0 && now - q.Peek() > window) q.Dequeue(); }
                    if (q.Count == 0) _requestLog.TryRemove(k, out _);
                }
            }
        }

        var queue = _requestLog.GetOrAdd(key, _ => new Queue<DateTime>());
        lock (queue)
        {
            while (queue.Count > 0 && now - queue.Peek() > window)
                queue.Dequeue();
            if (queue.Count >= maxRequests)
                return (true, queue.Count);
            queue.Enqueue(now);
            return (false, queue.Count);
        }
    }

    /// <summary>
    /// Extracts the remote client IP address from the connection, mapping
    /// IPv4-mapped IPv6 addresses back to their IPv4 representation.
    /// </summary>
    private static string? GetClientIp(HttpContext context)
    {
        var ip = context.Connection.RemoteIpAddress;
        if (ip == null) return null;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        return ip.ToString();
    }
}
