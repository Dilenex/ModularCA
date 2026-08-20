using ModularCA.Database;
using Microsoft.Extensions.Logging;

namespace ModularCA.API.Middleware;

/// <summary>
/// Redirects all requests to /setup/ when the system is unconfigured (no CAs exist).
/// After setup completes, this middleware returns 404 for /setup/ and /api/v1/setup/ routes.
/// Uses a cached flag to avoid DB queries on every request.
/// </summary>
public class SetupRedirectMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<SetupRedirectMiddleware> _logger;
    private static bool? _isConfigured;
    private static bool _staleDbWarned;
    private static readonly object _lock = new();

    /// <summary>
    /// Initializes the middleware with the next request delegate in the pipeline.
    /// </summary>
    public SetupRedirectMiddleware(RequestDelegate next, ILogger<SetupRedirectMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    /// <summary>
    /// Invalidates the cached configuration state, forcing a fresh DB check on the next request.
    /// Called after setup completes to transition the system from unconfigured to configured mode.
    /// </summary>
    public static void InvalidateCache() { lock (_lock) { _isConfigured = null; _staleDbWarned = false; } }

    /// <summary>
    /// True when the on-disk state indicates a fresh install (no <c>config/config.yaml</c>). The
    /// wizard treats stale DB rows under this condition as recoverable rather than terminal — see
    /// <c>SetupController.GetStatus</c> and the <c>/api/v1/setup/database/drop</c> endpoint.
    /// </summary>
    private static bool IsSetupMode()
    {
        var configPath = Path.Combine(AppContext.BaseDirectory, "config", "config.yaml");
        return !File.Exists(configPath);
    }

    /// <summary>
    /// Evaluates whether the system is configured and either redirects to /setup/, blocks setup routes, or passes through.
    /// </summary>
    public async Task InvokeAsync(HttpContext context, ModularCADbContext db)
    {
        var path = context.Request.Path.Value ?? "";

        // Check cached state, query DB if needed.
        //
        // dbUnreadable is resolved inside the lock but acted on outside it: a database failure must
        // not be answered as "unconfigured", because that re-opens the unauthenticated setup wizard
        // — including the database-drop recovery action — on a system that may be fully deployed and
        // simply having an outage. config.yaml is written at the end of bootstrap, so its presence is
        // sufficient evidence that setup already completed.
        //
        // The failure is deliberately NOT cached. _isConfigured is a process-lifetime static, so
        // caching a value derived from a transient error would freeze the wrong answer in until the
        // next restart; leaving it null re-evaluates on the following request.
        var dbUnreadable = false;
        if (_isConfigured == null)
        {
            lock (_lock)
            {
                if (_isConfigured == null)
                {
                    try
                    {
                        _isConfigured = db.CertificateAuthorities.Any();
                    }
                    catch (Exception ex)
                    {
                        dbUnreadable = true;
                        Serilog.Log.Warning(ex,
                            "Setup middleware: database unreachable while determining configured state. "
                            + "Falling back to on-disk config.yaml presence; not caching the result.");
                    }
                }
            }
        }

        if (dbUnreadable)
        {
            // config.yaml present → already bootstrapped → let the request through untouched, so
            // setup routes stay closed. Absent → genuinely a fresh install, fall through to the
            // normal unconfigured handling below.
            if (!IsSetupMode())
            {
                await _next(context);
                return;
            }
            _isConfigured = false;
        }

        // Snapshot the (now definitely resolved) state into a local. _isConfigured is a nullable
        // static that another thread could in principle reset via InvalidateCache between here and
        // the reads below, so reading it once keeps this request internally consistent — and lets
        // the compiler see it is non-null without a bare .Value assertion.
        var isConfigured = _isConfigured ?? false;

        // Stale-DB recovery: if the DB has CAs but on-disk state is fresh (no config.yaml), the
        // previous install left rows behind. Treat this as unconfigured so the wizard loads and
        // can offer the operator a "drop databases" recovery action. Log loudly once.
        var staleDb = isConfigured && IsSetupMode();
        if (staleDb && !_staleDbWarned)
        {
            lock (_lock)
            {
                if (!_staleDbWarned)
                {
                    _logger.LogWarning(
                        "Stale database state detected: CertificateAuthorities table has rows but config/config.yaml is missing. " +
                        "The setup wizard will load with a recovery option to drop the existing databases. " +
                        "Run `dotnet run --reset --force` to clean up from the CLI.");
                    _staleDbWarned = true;
                }
            }
        }

        if (!isConfigured || staleDb)
        {
            // Unconfigured: allow setup routes and API, redirect everything else
            if (path.StartsWith("/api/v1/setup", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/health", StringComparison.OrdinalIgnoreCase))
            {
                await _next(context);
                return;
            }

            // Serve setup SPA directly for /setup/ routes (don't rely on downstream fallback)
            if (path.StartsWith("/setup", StringComparison.OrdinalIgnoreCase))
            {
                // Static assets (JS, CSS) — let UseStaticFiles handle them
                if (path.Contains('.'))
                {
                    await _next(context);
                    return;
                }

                // SPA route — serve index.html
                var webRoot = context.RequestServices.GetService<Microsoft.AspNetCore.Hosting.IWebHostEnvironment>()?.WebRootPath
                    ?? Path.Combine(AppContext.BaseDirectory, "wwwroot");
                var indexPath = Path.Combine(webRoot, "setup", "index.html");

                if (File.Exists(indexPath))
                {
                    context.Response.ContentType = "text/html";
                    await context.Response.SendFileAsync(indexPath);
                    return;
                }

                // Fallback: if the built SPA files are missing, show a helpful message
                context.Response.ContentType = "text/html";
                context.Response.StatusCode = 503;
                await context.Response.WriteAsync(
                    "<html><body style='font-family:sans-serif;padding:40px;background:#111;color:#eee'>" +
                    "<h1>ModularCA Setup</h1>" +
                    "<p>The setup wizard UI files are not found. Build the setup SPA first:</p>" +
                    "<pre style='background:#222;padding:16px;border-radius:8px'>cd modularca.setupui\nnpm install\nnpm run build</pre>" +
                    "<p>Then restart the application.</p></body></html>");
                return;
            }

            context.Response.Redirect("/setup/");
            return;
        }
        else
        {
            // Configured: block setup routes
            if (path.StartsWith("/api/v1/setup", StringComparison.OrdinalIgnoreCase)
                || (path.StartsWith("/setup", StringComparison.OrdinalIgnoreCase)
                    && !path.Contains('.')))
            {
                context.Response.StatusCode = 404;
                return;
            }

            await _next(context);
        }
    }
}
