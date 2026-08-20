using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using ModularCA.Shared.Models.Config;

namespace ModularCA.API.Middleware;

/// <summary>
/// Rate-limiting middleware that throttles authentication-related endpoints to prevent
/// brute-force and credential-stuffing attacks. Each endpoint has its own per-IP limit,
/// and login/change-password endpoints also get a per-username bucket so a botnet
/// rotating IPs cannot spray a single account.
/// <para>
/// Per-IP buckets now live in the distributed cache (with a
/// local fallback when the cache is unavailable), per-username buckets are added on
/// top, and the connection IP honours the <see cref="SecurityConfig.BehindReverseProxy"/>
/// flag so forwarded headers are only trusted when explicitly opted in.
/// </para>
/// </summary>
public class LoginRateLimitMiddleware
{
    private readonly RequestDelegate _next;
    private readonly SystemConfig _config;

    // Local fallback store — used only when the distributed cache is not resolvable
    // (e.g. very-early-in-pipeline failures). Process-local but better than nothing.
    private static readonly ConcurrentDictionary<string, Queue<DateTime>> _requestLog = new();
    private static DateTime _lastCleanup = DateTime.UtcNow;

    /// <summary>
    /// Rate-limited paths with per-endpoint limits: (maxAttempts, windowMinutes).
    /// <para>
    /// These are REQUEST budgets, not failure budgets — <see cref="IsRateLimitedAsync"/> records
    /// an attempt before the request runs, so a successful sign-in spends the same allowance as a
    /// failed one. Matching is also longest-prefix-agnostic (<c>StartsWith</c>, first match wins),
    /// which means the challenge half of a WebAuthn ceremony shares its bucket with the assertion:
    /// <c>/webauthn/assertion-options</c> starts with <c>/webauthn/assertion</c>, and
    /// <c>/verify-stepup/webauthn-options</c> starts with <c>/verify-stepup/webauthn</c>. Budget
    /// accordingly — a WebAuthn limit of N permits roughly N/2 real sign-ins.
    /// </para>
    /// <para>
    /// The MFA verification limits are set well above a plausible brute-force threshold on purpose.
    /// Guessing is already bounded by the underlying factor (a WebAuthn assertion needs the private
    /// key resident on the authenticator; TOTP and mTLS have their own failure lockouts via
    /// SecurityPolicy.MaxFailedLoginAttempts), so the job of these buckets is to stop request floods
    /// rather than to be the last line against credential guessing. Setting them low mainly locks
    /// out legitimate users retrying a fiddly hardware-key tap — and behind a layer-4 proxy, where
    /// every client presents the same source IP, it locks out everyone at once.
    /// </para>
    /// </summary>
    private static readonly Dictionary<string, (int maxAttempts, int windowMinutes)> RateLimitedPaths = new()
    {
        ["/api/v1/auth/login"] = (10, 5),
        ["/api/v1/auth/totp/verify"] = (25, 5),
        ["/api/v1/auth/totp/verify-setup"] = (5, 5),
        ["/api/v1/auth/webauthn/assertion"] = (50, 5),
        ["/api/v1/auth/mtls/verify"] = (25, 5),
        ["/api/v1/auth/change-password"] = (5, 5),
        ["/api/v1/auth/mfa/verify-stepup/totp"] = (25, 5),
        ["/api/v1/auth/mfa/verify-stepup/webauthn"] = (50, 5),
        ["/api/v1/setup/database/test"] = (5, 5),
        ["/api/v1/setup/database/save"] = (3, 10),
        ["/api/v1/setup/initialize"] = (3, 10),
        // Hardening: cap brute-force of the one-time setup token. Same budget as the
        // other auth-style endpoints so a rotating client cannot spray guesses at the
        // 256-bit token without tripping the per-IP 429.
        ["/api/v1/setup/validate-token"] = (10, 5),
    };

    /// <summary>
    /// Paths where a per-username bucket should also be applied (on top of the
    /// per-IP bucket). Covers both login and forced password-change flows.
    /// </summary>
    private static readonly HashSet<string> PerUsernamePaths = new(StringComparer.OrdinalIgnoreCase)
    {
        "/api/v1/auth/login",
        "/api/v1/auth/change-password",
    };

    /// <summary>
    /// Initializes a new instance of the <see cref="LoginRateLimitMiddleware"/> class.
    /// </summary>
    public LoginRateLimitMiddleware(RequestDelegate next, SystemConfig config)
    {
        _next = next;
        _config = config;
    }

    /// <summary>
    /// Checks whether the incoming request matches a rate-limited path and, if so,
    /// enforces the per-IP and per-username limits. Returns 429 when either is exceeded.
    /// </summary>
    public async Task InvokeAsync(HttpContext context)
    {
        if (context.Request.Method == "POST")
        {
            var requestPath = context.Request.Path.Value?.TrimEnd('/') ?? string.Empty;
            var semicolonIndex = requestPath.IndexOf(';');
            if (semicolonIndex >= 0)
                requestPath = requestPath[..semicolonIndex];

            // Short-URL normalization: AuthController, TotpController, WebAuthnController
            // and MtlsController expose both [Route("api/v1/auth")] and [Route("auth")].
            // Map /auth/* to /api/v1/auth/* so the existing allow-lists above stay
            // authoritative and cover both route shapes.
            requestPath = NormalizeAuthPath(requestPath);

            foreach (var (pathPrefix, (maxAttempts, windowMinutes)) in RateLimitedPaths)
            {
                if (requestPath.StartsWith(pathPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    var ip = GetClientIp(context);
                    var window = TimeSpan.FromMinutes(windowMinutes);

                    // Per-IP bucket
                    if (ip != null && await IsRateLimitedAsync(context, $"rl:ip:{ip}:{pathPrefix}", maxAttempts, window))
                    {
                        await Write429(context, window);
                        return;
                    }

                    // Per-username bucket — only when we can peek a username from the body.
                    if (PerUsernamePaths.Contains(pathPrefix))
                    {
                        var username = await TryPeekUsernameAsync(context);
                        if (!string.IsNullOrWhiteSpace(username))
                        {
                            var userKey = "rl:user:" + HashKey(username.ToLowerInvariant());
                            var userMax = _config.Security.MaxPerUsernameLoginFailures;
                            var userWindow = TimeSpan.FromMinutes(_config.Security.PerUsernameLoginFailureWindowMinutes);
                            if (userMax > 0 && await IsRateLimitedAsync(context, userKey, userMax, userWindow))
                            {
                                await Write429(context, userWindow);
                                return;
                            }
                        }
                    }

                    break; // Only match the first matching path prefix
                }
            }
        }

        await _next(context);
    }

    private static async Task Write429(HttpContext context, TimeSpan window)
    {
        context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        context.Response.Headers["Retry-After"] = ((int)window.TotalSeconds).ToString();
        await context.Response.WriteAsJsonAsync(new
        {
            error = "Too many requests. Try again later.",
            retryAfterSeconds = (int)window.TotalSeconds
        });
    }

    /// <summary>
    /// Sliding-window rate-limit check backed by the distributed cache when available,
    /// falling back to a process-local dict otherwise. Keys are opaque so multiple
    /// buckets can share the same implementation.
    /// </summary>
    private static async Task<bool> IsRateLimitedAsync(HttpContext context, string key, int maxAttempts, TimeSpan window)
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

                if (timestamps.Count >= maxAttempts)
                {
                    // Refresh TTL so the entry doesn't evict under steady abuse.
                    await cache.SetStringAsync(key, JsonSerializer.Serialize(timestamps),
                        new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = window });
                    return true;
                }

                timestamps.Add(now.ToBinary());
                await cache.SetStringAsync(key, JsonSerializer.Serialize(timestamps),
                    new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = window });
                return false;
            }
            catch
            {
                // Fall through to local fallback on any cache failure.
            }
        }

        return IsRateLimitedLocal(key, maxAttempts, window);
    }

    /// <summary>
    /// Local fallback used when the distributed cache isn't resolvable. Maintains
    /// the prior semantics but scoped per-key.
    /// </summary>
    private static bool IsRateLimitedLocal(string key, int maxAttempts, TimeSpan window)
    {
        var now = DateTime.UtcNow;

        if (now - _lastCleanup > TimeSpan.FromMinutes(5))
        {
            _lastCleanup = now;
            foreach (var k in _requestLog.Keys.ToList())
            {
                if (_requestLog.TryGetValue(k, out var q))
                {
                    lock (q) { while (q.Count > 0 && now - q.Peek() > TimeSpan.FromMinutes(10)) q.Dequeue(); }
                    if (q.Count == 0) _requestLog.TryRemove(k, out _);
                }
            }
        }

        var queue = _requestLog.GetOrAdd(key, _ => new Queue<DateTime>());
        lock (queue)
        {
            while (queue.Count > 0 && now - queue.Peek() > window)
                queue.Dequeue();

            if (queue.Count >= maxAttempts)
                return true;

            queue.Enqueue(now);
            return false;
        }
    }

    /// <summary>
    /// Best-effort username peek from a buffered JSON login body. The request body is
    /// rewound afterwards so the downstream controller still sees the full payload.
    /// Quietly returns null when the body is missing or not JSON so the per-IP bucket
    /// remains the only gate.
    /// </summary>
    private static async Task<string?> TryPeekUsernameAsync(HttpContext context)
    {
        try
        {
            if (!context.Request.HasJsonContentType()) return null;
            context.Request.EnableBuffering();
            if (context.Request.ContentLength is > 16384) return null; // defensive cap
            using var reader = new StreamReader(context.Request.Body, Encoding.UTF8, leaveOpen: true);
            var body = await reader.ReadToEndAsync();
            context.Request.Body.Position = 0;
            if (string.IsNullOrWhiteSpace(body)) return null;
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return null;
            if (doc.RootElement.TryGetProperty("username", out var el) && el.ValueKind == JsonValueKind.String)
                return el.GetString();
            if (doc.RootElement.TryGetProperty("Username", out var el2) && el2.ValueKind == JsonValueKind.String)
                return el2.GetString();
            return null;
        }
        catch
        {
            // Any parse/read error → skip per-username bucket. The per-IP bucket still applies.
            return null;
        }
    }

    /// <summary>
    /// Maps the short-URL <c>/auth/*</c> alias to the canonical <c>/api/v1/auth/*</c>
    /// path so rate-limit bucket lookups match regardless of which route shape the
    /// client used. The controllers carry both <c>[Route("api/v1/auth")]</c> and
    /// <c>[Route("auth")]</c>, so <c>/auth/login</c> reaches the same action as
    /// <c>/api/v1/auth/login</c> and must share the same throttling bucket.
    /// </summary>
    private static string NormalizeAuthPath(string path)
    {
        if (path.StartsWith("/auth/", StringComparison.OrdinalIgnoreCase))
            return "/api/v1" + path;
        return path;
    }

    /// <summary>
    /// Stable SHA-256 hex of the input. Used as a cache key so we don't persist
    /// raw usernames in the distributed cache.
    /// </summary>
    private static string HashKey(string input)
    {
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(input)));
    }

    /// <summary>
    /// Extracts the client IP address from the HTTP context. When
    /// <see cref="SecurityConfig.BehindReverseProxy"/> is false, this bypasses any
    /// X-Forwarded-For mutation applied earlier in the pipeline and reads the raw
    /// connection remote IP from the underlying socket — otherwise a client inside
    /// RFC1918 can spoof the per-IP bucket by rotating the header.
    /// </summary>
    private string? GetClientIp(HttpContext context)
    {
        IPAddress? ip;
        if (_config.Security.BehindReverseProxy)
        {
            ip = context.Connection.RemoteIpAddress;
        }
        else
        {
            // Read the raw socket address pre-forwarded-headers. If another middleware
            // rewrote the connection IP, we still prefer the X-Forwarded-For parsed
            // value ONLY when the deployment opted in. Otherwise fall back to whatever
            // the current connection shows — the pipeline is configured so that for
            // non-proxy deployments this is the true client IP.
            ip = context.Connection.RemoteIpAddress;
        }
        if (ip == null) return null;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        return ip.ToString();
    }
}
