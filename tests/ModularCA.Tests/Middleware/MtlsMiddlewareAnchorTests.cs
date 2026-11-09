using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Http;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.Roles;
using Xunit;

namespace ModularCA.Tests.Middleware;

/// <summary>
/// <c>MtlsMiddleware</c> validates client certificates against the anchors the TLS handshake uses
/// (<c>MtlsTrustAnchors</c>): the database-seeded mTLS signing CAs when no configured path loads,
/// and configured paths resolved against the application base directory. It used to read the
/// configured paths itself, relative to the working directory, with no database fallback, so a
/// certificate the handshake accepted was refused on a required path.
/// </summary>
public sealed class MtlsMiddlewareAnchorTests
{
    private const string Ns = "ModularCA.API.";

    private static (X509Certificate2 Ca, X509Certificate2 Leaf) Issue()
    {
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var caRequest = new CertificateRequest("CN=mTLS signing CA", caKey, HashAlgorithmName.SHA256);
        caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        var ca = caRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));

        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var leafRequest = new CertificateRequest("CN=operator", leafKey, HashAlgorithmName.SHA256);
        leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        var leaf = leafRequest.Create(ca, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddDays(7), [1, 2, 3, 4]);
        return (ca, leaf);
    }

    private static object Anchors(params X509Certificate2[] certificates)
    {
        var anchors = Activator.CreateInstance(ApiAssembly.TypeNamed(Ns + "Startup.MtlsTrustAnchors"))!;
        var list = (List<X509Certificate2>)anchors.GetType().GetProperty("Certificates")!.GetValue(anchors)!;
        list.AddRange(certificates);
        return anchors;
    }

    private static SystemConfig Config(params string[] trustedPaths)
        => new() { Mtls = { Enabled = true, RequiredPaths = ["/api/v1/admin"], TrustedCaCertPaths = [.. trustedPaths] } };

    private static async Task<(int Status, int Reached)> Send(object[] ctorArgs, X509Certificate2 clientCert)
    {
        var reached = 0;
        RequestDelegate next = _ => { reached++; return Task.CompletedTask; };
        var middleware = Activator.CreateInstance(ApiAssembly.TypeNamed(Ns + "Middleware.MtlsMiddleware"), [next, .. ctorArgs])!;

        var context = new DefaultHttpContext();
        context.Request.Path = "/api/v1/admin/users";
        context.Connection.RemoteIpAddress = IPAddress.Loopback;
        context.Connection.ClientCertificate = clientCert;
        await (Task)middleware.GetType().GetMethod("InvokeAsync")!.Invoke(middleware, [context])!;
        return (context.Response.StatusCode, reached);
    }

    [Fact]
    public async Task A_client_certificate_from_a_shared_anchor_passes()
    {
        var (ca, leaf) = Issue();

        // No configured path: the anchors came from the database, as the handshake's do.
        var (status, reached) = await Send([Config(), Anchors(ca)], leaf);

        Assert.Equal(1, reached);
        Assert.Equal(200, status);
    }

    [Fact]
    public async Task A_client_certificate_from_another_ca_is_refused()
    {
        var (_, leaf) = Issue();
        var (otherCa, _) = Issue();

        var (status, reached) = await Send([Config(), Anchors(otherCa)], leaf);

        Assert.Equal(0, reached);
        Assert.Equal(403, status);
    }

    [Fact]
    public async Task A_relative_anchor_path_resolves_against_the_application_directory()
    {
        var (ca, leaf) = Issue();
        var name = $"mtls-anchor-{Guid.NewGuid():N}.cer";
        var full = Path.Combine(AppContext.BaseDirectory, name);
        await File.WriteAllBytesAsync(full, ca.Export(X509ContentType.Cert));
        try
        {
            var config = Config(name);

            var load = ApiAssembly.TypeNamed(Ns + "Startup.MtlsTrustAnchors").GetMethod("Load")!;
            var anchors = load.Invoke(null, [config, null, false])!;
            var loaded = (List<X509Certificate2>)anchors.GetType().GetProperty("Certificates")!.GetValue(anchors)!;
            Assert.Equal(ca.Thumbprint, Assert.Single(loaded).Thumbprint);

            var (status, reached) = await Send([config], leaf);
            Assert.Equal(1, reached);
            Assert.Equal(200, status);
        }
        finally
        {
            File.Delete(full);
        }
    }
}
