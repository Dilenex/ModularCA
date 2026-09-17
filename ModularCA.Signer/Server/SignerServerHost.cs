using System.Net;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;
using ModularCA.Shared.Signing;
using ModularCA.Signer.Identity;

namespace ModularCA.Signer.Server;

/// <summary>
/// How the signer role listens: one address, one server certificate, one pinned client. The
/// listener speaks HTTP/2 over TLS only, requires a client certificate on every connection,
/// and accepts a client by the SPKI pin alone; there is no trust store and no chain check.
/// </summary>
/// <param name="ListenAddress">The interface to bind; loopback on a single host.</param>
/// <param name="ListenPort">The port to bind; 0 lets the operating system pick one, which a test reads back from the started host.</param>
/// <param name="ServerCertificate">The signer's server certificate with its private key, issued by the signer's identity CA.</param>
/// <param name="PinnedClientSpki">The node's client certificate SPKI pin; every other client is refused at the handshake.</param>
public sealed record SignerServerOptions(IPAddress ListenAddress, int ListenPort, X509Certificate2 ServerCertificate, string PinnedClientSpki)
{
    /// <summary>The largest message either direction carries; a whole keystore file crosses on a backup.</summary>
    public const int MaxMessageSize = 64 * 1024 * 1024;

    /// <summary>
    /// Parses a configured <c>host:port</c> listen address: an IPv4 or bracketed IPv6 address,
    /// or <c>localhost</c> for loopback. A hostname is not resolved, since the listener binds an
    /// interface, not a name.
    /// </summary>
    public static (IPAddress Address, int Port) ParseListen(string listen)
    {
        if (string.IsNullOrWhiteSpace(listen))
            throw new ArgumentException("Signer.Listen is empty; it names the address and port the signer role listens on, such as 127.0.0.1:8446.", nameof(listen));
        var value = listen.Trim();
        var colon = value.LastIndexOf(':');
        if (colon <= 0 || colon == value.Length - 1)
            throw new ArgumentException($"Signer.Listen '{listen}' is not host:port.", nameof(listen));
        var host = value[..colon].Trim('[', ']');
        if (!int.TryParse(value[(colon + 1)..], out var port) || port < 0 || port > 65535)
            throw new ArgumentException($"Signer.Listen '{listen}' has no valid port.", nameof(listen));
        if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase))
            return (IPAddress.Loopback, port);
        if (!IPAddress.TryParse(host, out var address))
            throw new ArgumentException($"Signer.Listen '{listen}' must name an IP address to bind, not a hostname.", nameof(listen));
        return (address, port);
    }
}

/// <summary>
/// Builds the signer role's web host: Kestrel on the configured address with mutual TLS, the
/// gRPC signer service over whatever <see cref="ISigningService"/> the caller registers, and
/// a health route on the same listener that reports the signer's own state. Nothing else is
/// mapped: no controllers, no console, no protocol endpoint, no scheduler. The caller adds
/// the database, the audit sink, the unlocked keystore and its logging through
/// <c>configure</c>; a test adds an in-memory signer the same way.
/// </summary>
public static class SignerServerHost
{
    /// <summary>The route the health report is served on, over the same mutually authenticated listener.</summary>
    public const string HealthPath = "/health";

    /// <summary>
    /// Builds the host. <paramref name="configure"/> runs after Kestrel and gRPC are configured
    /// and before the application is built, and must register an <see cref="ISigningService"/>.
    /// </summary>
    public static WebApplication Build(SignerServerOptions options, Action<WebApplicationBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(configure);
        if (!options.ServerCertificate.HasPrivateKey)
            throw new ArgumentException("The signer's server certificate has no private key.", nameof(options));
        if (SpkiPin.Normalize(options.PinnedClientSpki) == null)
            throw new ArgumentException("Signer.PinnedClientSpki is not a SHA-256 SPKI pin; the signer refuses to listen with no client to admit.", nameof(options));

        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = Array.Empty<string>() });

        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            kestrel.Limits.MaxRequestBodySize = SignerServerOptions.MaxMessageSize;
            kestrel.Listen(options.ListenAddress, options.ListenPort, listen =>
            {
                listen.Protocols = HttpProtocols.Http2;
                listen.UseHttps(https =>
                {
                    https.ServerCertificate = options.ServerCertificate;
                    https.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
                    https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
                    https.CheckCertificateRevocation = false;
                    // The pin is the whole decision: chain errors are expected, since the
                    // identity CA is in no store, and a certificate with the pinned key is
                    // the node whatever else it carries.
                    https.ClientCertificateValidation = (certificate, _, _) => SpkiPin.Matches(certificate, options.PinnedClientSpki);
                    https.HandshakeTimeout = TimeSpan.FromSeconds(10);
                });
            });
        });

        builder.Services.AddGrpc(grpc =>
        {
            grpc.MaxReceiveMessageSize = SignerServerOptions.MaxMessageSize;
            grpc.MaxSendMessageSize = SignerServerOptions.MaxMessageSize;
        });

        configure(builder);

        var app = builder.Build();
        app.MapGrpcService<SignerGrpcService>();
        app.MapGet(HealthPath, async (ISigningService signer, HttpContext http) =>
        {
            var health = await signer.HealthAsync(http.RequestAborted);
            return Results.Json(new
            {
                status = health.Unlocked ? "healthy" : "unhealthy",
                unlocked = health.Unlocked,
                keyCount = health.KeyCount,
                backend = health.Backend,
            }, statusCode: health.Unlocked ? StatusCodes.Status200OK : StatusCodes.Status503ServiceUnavailable);
        });
        return app;
    }
}
