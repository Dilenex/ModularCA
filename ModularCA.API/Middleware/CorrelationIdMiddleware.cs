using ModularCA.Core.Services;
using Serilog.Context;
using System.Diagnostics;

namespace ModularCA.API.Middleware;

/// <summary>
/// Honours inbound W3C <c>traceparent</c> and legacy <c>X-Correlation-Id</c> /
/// <c>X-Request-Id</c> headers, pushes the resulting correlation id into the
/// Serilog <see cref="LogContext"/>, echoes it back in the response headers, and
/// stamps it on the current <see cref="Activity"/> (if any). When no inbound
/// header is present a fresh lowercase-hex id is generated.
/// </summary>
/// <remarks>
/// The prior setup relied solely on Serilog's auto-generated
/// <c>RequestId</c>, which does not cross process boundaries and cannot be
/// reconstructed from logs when a downstream caller (Kong, ACME client,
/// cert-manager) originated the trace. This middleware restores the chain so a
/// single id follows a request through the full pipeline.
/// </remarks>
public sealed class CorrelationIdMiddleware
{
    private const string CorrelationIdHeader = "X-Correlation-Id";
    private const string RequestIdHeader = "X-Request-Id";
    private const string TraceparentHeader = "traceparent";
    private const string HttpContextItemKey = "CorrelationId";

    private readonly RequestDelegate _next;

    /// <summary>Initializes a new <see cref="CorrelationIdMiddleware"/>.</summary>
    /// <param name="next">The next delegate in the pipeline.</param>
    public CorrelationIdMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    /// <summary>
    /// Resolves or generates the correlation id, pushes it into LogContext, and
    /// ensures the response echoes the same value.
    /// </summary>
    public async Task InvokeAsync(HttpContext context)
    {
        var correlationId = ExtractCorrelationId(context);
        context.Items[HttpContextItemKey] = correlationId;

        // Start (or enrich) an Activity so any ActivitySource listener — including the
        // OpenTelemetry AspNetCore instrumentation once it is wired up — automatically
        // sees the correlation id and the request envelope.
        using var activity = ModularCaActivitySources.Api.StartActivity(
            "http.request",
            ActivityKind.Server);
        if (activity != null)
        {
            activity.SetTag("correlation.id", correlationId);
            activity.SetTag("http.method", context.Request.Method);
            activity.SetTag("http.route", context.Request.Path.Value);
        }
        else if (Activity.Current != null)
        {
            Activity.Current.SetTag("correlation.id", correlationId);
        }

        // Echo on the way out (registered as an OnStarting callback so downstream
        // middleware cannot strip it).
        context.Response.OnStarting(() =>
        {
            if (!context.Response.Headers.ContainsKey(CorrelationIdHeader))
            {
                context.Response.Headers[CorrelationIdHeader] = correlationId;
            }
            return Task.CompletedTask;
        });

        using (LogContext.PushProperty("CorrelationId", correlationId))
        {
            await _next(context);
            if (activity != null)
            {
                activity.SetTag("http.status_code", context.Response.StatusCode);
            }
        }
    }

    /// <summary>
    /// The correlation id of the request, or its trace identifier when this middleware did not
    /// run. An endpoint that hides an exception's message returns this so the operator can find
    /// the logged exception.
    /// </summary>
    /// <param name="context">The request.</param>
    public static string Of(HttpContext context)
        => context.Items.TryGetValue(HttpContextItemKey, out var id) && id is string s && s.Length > 0
            ? s
            : context.TraceIdentifier;

    /// <summary>
    /// Resolves the correlation id from the first present inbound header
    /// (<c>traceparent</c> trace-id segment, <c>X-Correlation-Id</c>, or
    /// <c>X-Request-Id</c>), generating a fresh one when absent.
    /// </summary>
    private static string ExtractCorrelationId(HttpContext context)
    {
        // traceparent format: "version-traceid-spanid-flags"
        if (context.Request.Headers.TryGetValue(TraceparentHeader, out var tp)
            && !string.IsNullOrWhiteSpace(tp))
        {
            var parts = tp.ToString().Split('-');
            if (parts.Length >= 2 && parts[1].Length == 32 && IsHex(parts[1]))
            {
                return parts[1];
            }
        }

        if (context.Request.Headers.TryGetValue(CorrelationIdHeader, out var cid)
            && !string.IsNullOrWhiteSpace(cid))
        {
            return Sanitize(cid.ToString());
        }

        if (context.Request.Headers.TryGetValue(RequestIdHeader, out var rid)
            && !string.IsNullOrWhiteSpace(rid))
        {
            return Sanitize(rid.ToString());
        }

        // Generate a fresh lowercase-hex id matching W3C trace-id width.
        Span<byte> buf = stackalloc byte[16];
        System.Security.Cryptography.RandomNumberGenerator.Fill(buf);
        return Convert.ToHexString(buf).ToLowerInvariant();
    }

    private static bool IsHex(string s)
    {
        foreach (var c in s)
        {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                return false;
        }
        return true;
    }

    /// <summary>
    /// Strips anything that is not an ASCII letter/digit/dash/underscore and
    /// truncates to 128 characters. Prevents header injection of CRLF or control
    /// characters into the response echo.
    /// </summary>
    private static string Sanitize(string value)
    {
        var trimmed = value.Trim();
        if (trimmed.Length > 128) trimmed = trimmed.Substring(0, 128);
        var span = trimmed.AsSpan();
        foreach (var c in span)
        {
            if (!(char.IsLetterOrDigit(c) || c == '-' || c == '_' || c == '.' || c == ':'))
            {
                // Reject and regenerate rather than partial-sanitize — avoids giving the
                // caller a partially-honored id that diverges from what they sent.
                Span<byte> buf = stackalloc byte[16];
                System.Security.Cryptography.RandomNumberGenerator.Fill(buf);
                return Convert.ToHexString(buf).ToLowerInvariant();
            }
        }
        return trimmed;
    }
}
