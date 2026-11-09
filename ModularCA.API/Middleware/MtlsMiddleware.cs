using ModularCA.API.Startup;
using ModularCA.Shared.Models.Config;
using System.Security.Cryptography.X509Certificates;

namespace ModularCA.API.Middleware;

/// <summary>
/// Enforces mutual TLS (client certificate) authentication on configured paths.
/// When enabled, requests to admin API paths must present a valid client certificate
/// issued by one of the trusted CAs (<see cref="MtlsTrustAnchors"/>, shared with the handshake).
/// Whether mTLS is on and which CAs are trusted are fixed at start, as the listener's handshake is; the required paths are read on every
/// request, so a saved change to them applies to the next one.
/// </summary>
public class MtlsMiddleware
{
    private readonly RequestDelegate _next;
    private readonly SystemConfig _config;
    private readonly bool _enabled;
    private readonly IReadOnlyList<X509Certificate2> _trustedCas;

    /// <summary>
    /// Initializes a new instance of the <see cref="MtlsMiddleware"/> class with the trust
    /// anchors loaded at start, the set the TLS handshake on the mTLS auth subdomain validates
    /// against: the configured paths resolved against the application base directory, or the
    /// enrolled mTLS signing CAs from the database when none loads.
    /// </summary>
    /// <param name="next">The next middleware in the pipeline.</param>
    /// <param name="config">System configuration containing mTLS settings.</param>
    /// <param name="anchors">The trust anchors loaded at start.</param>
    [ActivatorUtilitiesConstructor]
    public MtlsMiddleware(RequestDelegate next, SystemConfig config, MtlsTrustAnchors anchors)
    {
        _next = next;
        _config = config;
        _enabled = config.Mtls.Enabled;
        _trustedCas = anchors.Certificates;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="MtlsMiddleware"/> class with the anchors in
    /// the configured paths only (<see cref="MtlsTrustAnchors.Load"/> without a database), for a
    /// host that registered no <see cref="MtlsTrustAnchors"/>.
    /// </summary>
    /// <param name="next">The next middleware in the pipeline.</param>
    /// <param name="config">System configuration containing mTLS settings.</param>
    public MtlsMiddleware(RequestDelegate next, SystemConfig config)
        : this(next, config, MtlsTrustAnchors.Load(config, appConnStr: null, isSetupMode: false))
    {
    }

    /// <summary>
    /// Evaluates the incoming request against mTLS policy. If mTLS was enabled at start and
    /// the request path matches a required path as configured now, a valid client certificate
    /// must be presented. Returns 403 if no certificate is provided or if the certificate
    /// is not trusted.
    /// </summary>
    /// <param name="context">The HTTP context for the current request.</param>
    public async Task InvokeAsync(HttpContext context)
    {
        if (!_enabled)
        {
            await _next(context);
            return;
        }

        var path = context.Request.Path.Value ?? "";

        // Only check configured paths
        if (!_config.Mtls.RequiredPaths.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
        {
            await _next(context);
            return;
        }

        // Get client certificate
        var clientCert = await context.Connection.GetClientCertificateAsync();
        if (clientCert == null)
        {
            context.Response.StatusCode = 403;
            context.Response.ContentType = "text/plain";
            await context.Response.WriteAsync("Client certificate required for admin API access");
            return;
        }

        // Validate client cert against trusted CAs.
        //
        // `using` because X509Chain holds unmanaged certificate-context handles; this runs on every
        // request to a configured mTLS path, and both failure branches below return early, so an
        // undisposed chain leaked a handle per request.
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.Offline;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
        // Offline revocation consults only the local CRL cache. On a cold cache the chain reports
        // RevocationStatusUnknown and Build() returns false, which would 403 every client for a
        // reason unrelated to its standing. These flags suppress "could not determine" only — an
        // explicitly Revoked certificate still fails the build.
        chain.ChainPolicy.VerificationFlags =
            X509VerificationFlags.IgnoreEndRevocationUnknown
            | X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown
            | X509VerificationFlags.IgnoreRootRevocationUnknown;
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        foreach (var ca in _trustedCas)
            chain.ChainPolicy.CustomTrustStore.Add(ca);

        if (!chain.Build(clientCert))
        {
            context.Response.StatusCode = 403;
            context.Response.ContentType = "text/plain";
            await context.Response.WriteAsync("Client certificate not trusted");
            return;
        }

        await _next(context);
    }
}
