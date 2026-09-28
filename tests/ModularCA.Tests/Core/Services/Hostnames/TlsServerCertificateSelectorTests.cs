using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Logging;
using ModularCA.Core.Services;
using ModularCA.Core.Services.Hostnames;
using Xunit;

namespace ModularCA.Tests.Core.Services.Hostnames;

/// <summary>
/// The HTTPS listener presents the instance's web TLS certificate for its public domain, for any
/// other name and for a client that sends no name, and presents a renewed certificate from the
/// next handshake on.
/// </summary>
public class TlsServerCertificateSelectorTests
{
    private static X509Certificate2 ServerCertificate(string cn)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={cn}", key, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(cn);
        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        using var ephemeral = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(1));
        // SChannel will not serve an ephemeral key; a PKCS#12 round trip gives it a usable one.
        return X509CertificateLoader.LoadPkcs12(ephemeral.Export(X509ContentType.Pkcs12), null);
    }

    [Theory]
    [InlineData("ca4.example.test")]
    [InlineData("ca.customer-a.example")]
    [InlineData("mtls.ca4.example.test")]
    [InlineData("")]
    [InlineData(null)]
    public void Every_name_gets_the_instance_certificate(string? serverName)
    {
        var provider = new ApiCertificateProvider();
        using var instance = ServerCertificate("ca4.example.test");
        provider.SetCertificate(instance);

        Assert.Same(instance, TlsServerCertificateSelector.Select(serverName, provider));
    }

    [Fact]
    public void A_renewed_certificate_is_presented_from_the_next_selection_on()
    {
        var provider = new ApiCertificateProvider();
        using var first = ServerCertificate("ca4.example.test");
        using var renewed = ServerCertificate("ca4.example.test");
        provider.SetCertificate(first);
        Assert.Same(first, TlsServerCertificateSelector.Select("ca4.example.test", provider));

        provider.SetCertificate(renewed);
        Assert.Same(renewed, TlsServerCertificateSelector.Select("ca4.example.test", provider));
        Assert.Null(TlsServerCertificateSelector.Select("ca4.example.test", new ApiCertificateProvider()));
    }

    [Fact]
    public async Task A_real_handshake_presents_the_instance_certificate_whatever_name_the_client_sends()
    {
        var provider = new ApiCertificateProvider();
        using var instance = ServerCertificate("ca4.example.test");
        provider.SetCertificate(instance);

        var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        var port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();

        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = Array.Empty<string>() });
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.Loopback, port, listen => listen.UseHttps(new TlsHandshakeCallbackOptions
        {
            OnConnection = ctx => ValueTask.FromResult(new SslServerAuthenticationOptions
            {
                ServerCertificate = TlsServerCertificateSelector.Select(ctx.ClientHelloInfo.ServerName, provider),
            }),
        })));
        await using var app = builder.Build();
        app.Run((HttpContext context) => context.Response.WriteAsync("ok"));
        await app.StartAsync();
        try
        {
            foreach (var name in new[] { "ca4.example.test", "ca.customer-a.example", "unknown.example.test", "127.0.0.1" })
                Assert.Equal(instance.Thumbprint, await PresentedThumbprintAsync(port, name));
        }
        finally
        {
            await app.StopAsync();
        }
    }

    [Fact]
    public void The_listener_in_startup_selects_through_the_instance_certificate_alone()
    {
        var startup = File.ReadAllText(Path.Combine(RepoRoot(), "ModularCA.API", "StartModularCA.cs"));
        Assert.Contains("ServerCertificate = ModularCA.Core.Services.Hostnames.TlsServerCertificateSelector.Select(sni, apiCertProvider),", startup);
        Assert.Single(System.Text.RegularExpressions.Regex.Matches(startup, @"\bServerCertificate\s*="));
        Assert.DoesNotContain("TenantHostname", startup);
    }

    /// <summary>The thumbprint of the certificate the server presents to a client asking for <paramref name="serverName"/>.</summary>
    private static async Task<string> PresentedThumbprintAsync(int port, string serverName)
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);
        string? thumbprint = null;
        await using var tls = new SslStream(client.GetStream(), false, (_, certificate, _, _) =>
        {
            thumbprint = certificate?.GetCertHashString();
            return true;
        });
        await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = serverName });
        Assert.NotNull(thumbprint);
        return thumbprint!;
    }

    /// <summary>The directory holding ModularCA.sln.</summary>
    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !dir.EnumerateFiles("ModularCA.sln").Any())
            dir = dir.Parent;
        Assert.NotNull(dir);
        return dir!.FullName;
    }
}
