using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using IPNetwork = System.Net.IPNetwork;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Logging;
using ModularCA.Core.Services.ProxyProtocol;
using ModularCA.Tests.Core.Services.ProxyProtocol;
using ModularCA.Tests.Ingress;
using ModularCA.Tests.Roles;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// The PROXY protocol wiring from the API (<c>ProxyProtocolHosting</c>, loaded by reflection) on
/// real Kestrel listeners, driven with a raw <see cref="TcpClient"/> standing for the proxy: a
/// trusted peer's header sets the address the application sees, over plain HTTP and ahead of a
/// TLS handshake with a client certificate; a connection without the header, from an untrusted
/// peer, or too slow, is closed; a listener without the protocol behaves as before; and on a
/// PROXY listener <c>X-Forwarded-For</c> cannot replace the header's address, even from a client
/// address the forwarded-headers step trusts.
/// </summary>
public sealed class ProxyProtocolListenerTests : IAsyncLifetime
{
    private static readonly IPEndPoint FakeClient = new(IPAddress.Parse("203.0.113.7"), 51234);
    private static readonly IPEndPoint Front = new(IPAddress.Parse("198.51.100.1"), 443);

    /// <summary>A network the test's forwarded-headers step trusts, standing for <c>Http.TrustedProxyCidrs</c>.</summary>
    private static readonly IPNetwork XffTrusted = IPNetwork.Parse("198.51.100.0/24");

    private WebApplication _app = null!;
    private X509Certificate2 _serverCert = null!;
    private X509Certificate2 _clientCa = null!;
    private X509Certificate2 _clientCert = null!;
    private X509Certificate2 _strangerCert = null!;

    private int _proxyHttpPort;
    private int _plainHttpPort;
    private int _proxyHttpsPort;
    private int _untrustedPort;

    private static Type Hosting => ApiAssembly.TypeNamed("ModularCA.API.ProxyProtocol.ProxyProtocolHosting");

    private static void UseProxyProtocol(ListenOptions listen, IPNetwork[] trusted, string name, TimeSpan? timeout)
        => Invoke("UseProxyProtocol", listen, trusted, name, timeout);

    private static object? Invoke(string method, params object?[] args)
    {
        var m = Hosting.GetMethod(method, BindingFlags.Public | BindingFlags.Static);
        Assert.True(m != null, $"ProxyProtocolHosting.{method} is not a public static method.");
        try
        {
            return m!.Invoke(null, args);
        }
        catch (TargetInvocationException ex) when (ex.InnerException != null)
        {
            throw ex.InnerException;
        }
    }

    public async Task InitializeAsync()
    {
        _serverCert = Certificates.Server("node.test");
        (_clientCa, _clientCert) = Certificates.CaAndClient("Test client CA", "client.test");
        (_, _strangerCert) = Certificates.CaAndClient("Stranger CA", "stranger.test");

        _proxyHttpPort = IngressHost.FreePort();
        _plainHttpPort = IngressHost.FreePort();
        _proxyHttpsPort = IngressHost.FreePort();
        _untrustedPort = IngressHost.FreePort();

        var loopback = new[] { IPNetwork.Parse("127.0.0.0/8"), IPNetwork.Parse("::1/128") };
        var elsewhere = new[] { IPNetwork.Parse("10.99.0.0/16") };
        var clientCa = _clientCa;
        var serverCert = _serverCert;

        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = Array.Empty<string>() });
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(k =>
        {
            k.Listen(IPAddress.Loopback, _proxyHttpPort, listen => UseProxyProtocol(listen, loopback, "test HTTP", TimeSpan.FromSeconds(1)));
            k.Listen(IPAddress.Loopback, _plainHttpPort);
            k.Listen(IPAddress.Loopback, _untrustedPort, listen => UseProxyProtocol(listen, elsewhere, "test untrusted", null));
            k.Listen(IPAddress.Loopback, _proxyHttpsPort, listen =>
            {
                // As in startup: the PROXY middleware first, then TLS with a required client certificate.
                UseProxyProtocol(listen, loopback, "test HTTPS", TimeSpan.FromSeconds(2));
                listen.UseHttps(new TlsHandshakeCallbackOptions
                {
                    OnConnection = _ => ValueTask.FromResult(new SslServerAuthenticationOptions
                    {
                        ServerCertificate = serverCert,
                        ClientCertificateRequired = true,
                        RemoteCertificateValidationCallback = (_, cert, _, _) =>
                        {
                            if (cert is not X509Certificate2 x509)
                                return false;
                            using var chain = new X509Chain();
                            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                            chain.ChainPolicy.CustomTrustStore.Add(clientCa);
                            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                            chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.2"));
                            return chain.Build(x509);
                        },
                    }),
                    HandshakeTimeout = TimeSpan.FromSeconds(10),
                });
            });
        });

        _app = builder.Build();

        // The forwarded-headers step as startup configures it: loopback always known, plus a
        // stand-in for Http.TrustedProxyCidrs.
        var forwarded = new ForwardedHeadersOptions
        {
            ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost,
        };
        forwarded.KnownIPNetworks.Add(new IPNetwork(IPAddress.Loopback, 32));
        forwarded.KnownIPNetworks.Add(new IPNetwork(IPAddress.IPv6Loopback, 128));
        forwarded.KnownIPNetworks.Add(XffTrusted);
        Invoke("UseForwardedHeadersUnlessProxyProtocol", _app, forwarded);

        _app.Run(async context =>
        {
            var body = JsonSerializer.Serialize(new Whoami(
                context.Connection.RemoteIpAddress?.ToString(),
                context.Connection.RemotePort,
                context.Features.Get<ProxyProtocolFeature>() != null,
                context.Connection.ClientCertificate?.Subject,
                context.Request.Scheme));
            context.Response.ContentType = "application/json";
            context.Response.ContentLength = Encoding.UTF8.GetByteCount(body);
            await context.Response.WriteAsync(body);
        });

        await _app.StartAsync();
    }

    public async Task DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
        _serverCert.Dispose();
        _clientCa.Dispose();
        _clientCert.Dispose();
        _strangerCert.Dispose();
    }

    /// <summary>What the test endpoint reports about the request.</summary>
    private sealed record Whoami(string? Ip, int Port, bool Proxied, string? ClientCertificate, string Scheme);

    [Fact]
    public async Task A_trusted_proxys_v2_header_sets_the_address_the_application_sees()
    {
        using var tcp = await ConnectAsync(_proxyHttpPort);
        var stream = tcp.GetStream();

        // Header and request in one write, so they arrive in one read.
        var who = await RequestAsync(stream, prefix: ProxyProtocolParserTests.V2Tcp(FakeClient, Front));

        Assert.Equal("203.0.113.7", who.Ip);
        Assert.Equal(51234, who.Port);
        Assert.True(who.Proxied);
    }

    [Fact]
    public async Task A_header_arriving_in_pieces_is_waited_for()
    {
        using var tcp = await ConnectAsync(_proxyHttpPort);
        var stream = tcp.GetStream();
        var header = ProxyProtocolParserTests.V2Tcp(new IPEndPoint(IPAddress.Parse("2001:db8::7"), 61000), new IPEndPoint(IPAddress.Parse("2001:db8::1"), 443));
        foreach (var piece in new[] { header[..5], header[5..14], header[14..30], header[30..] })
        {
            await stream.WriteAsync(piece);
            await stream.FlushAsync();
            await Task.Delay(50);
        }

        var who = await RequestAsync(stream);

        Assert.Equal("2001:db8::7", who.Ip);
        Assert.Equal(61000, who.Port);
    }

    [Fact]
    public async Task A_v1_line_from_nginx_sets_the_address_too()
    {
        using var tcp = await ConnectAsync(_proxyHttpPort);
        var who = await RequestAsync(tcp.GetStream(), prefix: "PROXY TCP4 203.0.113.9 198.51.100.1 40404 80\r\n"u8.ToArray());

        Assert.Equal("203.0.113.9", who.Ip);
        Assert.Equal(40404, who.Port);
    }

    [Fact]
    public async Task A_local_header_keeps_the_proxy_as_the_peer()
    {
        using var tcp = await ConnectAsync(_proxyHttpPort);
        var who = await RequestAsync(tcp.GetStream(), prefix: ProxyProtocolParserTests.V2(0x20, 0x00, []));

        Assert.Equal("127.0.0.1", who.Ip);
        Assert.Equal(((IPEndPoint)tcp.Client.LocalEndPoint!).Port, who.Port);
        Assert.True(who.Proxied);
    }

    [Fact]
    public async Task A_connection_without_the_header_is_closed_without_an_answer()
    {
        using var tcp = await ConnectAsync(_proxyHttpPort);
        var stream = tcp.GetStream();
        await TryWriteAsync(stream, Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: test\r\n\r\n"));

        await AssertClosedAsync(stream);
    }

    [Fact]
    public async Task A_TLS_ClientHello_without_the_header_is_closed_not_handshaken()
    {
        using var tcp = await ConnectAsync(_proxyHttpsPort);
        await using var tls = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);

        await Assert.ThrowsAnyAsync<Exception>(() => tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = "node.test" }));
    }

    [Fact]
    public async Task An_invalid_header_is_closed()
    {
        using var tcp = await ConnectAsync(_proxyHttpPort);
        var stream = tcp.GetStream();
        var header = ProxyProtocolParserTests.V2Tcp(FakeClient, Front);
        header[13] = 0x12; // UDP over IPv4
        await TryWriteAsync(stream, header.Concat(Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: test\r\n\r\n")).ToArray());

        await AssertClosedAsync(stream);
    }

    [Fact]
    public async Task A_peer_that_sends_nothing_or_half_a_header_is_closed_at_the_deadline()
    {
        using var silent = await ConnectAsync(_proxyHttpPort);
        using var half = await ConnectAsync(_proxyHttpPort);
        await half.GetStream().WriteAsync(ProxyProtocolParserTests.V2Tcp(FakeClient, Front)[..20]);

        var started = System.Diagnostics.Stopwatch.StartNew();
        await AssertClosedAsync(silent.GetStream());
        await AssertClosedAsync(half.GetStream());
        // Not at once (the deadline is one second), and closed by the server: each read above gives
        // up after ten seconds, which fails the test. The upper bound is those two reads, not the
        // deadline, because under a loaded test run the close can arrive seconds late.
        Assert.InRange(started.Elapsed, TimeSpan.FromMilliseconds(500), TimeSpan.FromSeconds(20));
    }

    /// <summary>
    /// The server drops an untrusted peer as soon as it is accepted, before it reads a byte. On
    /// Linux that reset can reach the client while its connect is still completing, which is the
    /// same outcome one step earlier: the peer was closed and never answered.
    /// </summary>
    [Fact]
    public async Task An_untrusted_peer_is_closed_even_with_a_valid_header()
    {
        TcpClient tcp;
        try
        {
            tcp = await ConnectAsync(_untrustedPort);
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset)
        {
            return;
        }

        using var client = tcp;
        var stream = tcp.GetStream();
        await TryWriteAsync(stream, ProxyProtocolParserTests.V2Tcp(FakeClient, Front)
            .Concat(Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: test\r\n\r\n")).ToArray());

        await AssertClosedAsync(stream);
    }

    [Fact]
    public async Task A_listener_without_the_protocol_behaves_as_before()
    {
        using (var tcp = await ConnectAsync(_plainHttpPort))
        {
            var who = await RequestAsync(tcp.GetStream());
            Assert.Equal("127.0.0.1", who.Ip);
            Assert.Equal(((IPEndPoint)tcp.Client.LocalEndPoint!).Port, who.Port);
            Assert.False(who.Proxied);
        }

        // A header sent there is not read as one: it is just bytes in front of the request.
        using (var tcp = await ConnectAsync(_plainHttpPort))
        {
            var stream = tcp.GetStream();
            await TryWriteAsync(stream, ProxyProtocolParserTests.V2Tcp(FakeClient, Front)
                .Concat(Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")).ToArray());
            var response = await ReadAllAsync(stream);
            Assert.DoesNotContain("203.0.113.7", response);
            Assert.False(response.StartsWith("HTTP/1.1 200", StringComparison.Ordinal), response);
        }
    }

    [Fact]
    public async Task X_Forwarded_For_still_applies_on_a_listener_without_the_protocol()
    {
        // The control for the next test: the same header from the same peer is honoured here.
        using var tcp = await ConnectAsync(_plainHttpPort);
        var who = await RequestAsync(tcp.GetStream(), headers: "X-Forwarded-For: 203.0.113.99\r\n");

        Assert.Equal("203.0.113.99", who.Ip);
    }

    [Theory]
    [InlineData("127.0.0.1", 40002)]     // loopback: always a known proxy to the forwarded-headers step
    [InlineData("198.51.100.7", 40001)]  // inside the stand-in for Http.TrustedProxyCidrs
    [InlineData("203.0.113.7", 51234)]   // an ordinary client
    public async Task X_Forwarded_For_cannot_replace_the_address_a_PROXY_header_set(string client, int port)
    {
        using var tcp = await ConnectAsync(_proxyHttpPort);
        var header = ProxyProtocolParserTests.V2Tcp(new IPEndPoint(IPAddress.Parse(client), port), Front);
        var who = await RequestAsync(tcp.GetStream(), prefix: header,
            headers: "X-Forwarded-For: 203.0.113.99\r\nX-Forwarded-Proto: https\r\nX-Forwarded-Host: evil.test\r\n");

        Assert.Equal(client, who.Ip);
        Assert.Equal(port, who.Port);
        Assert.Equal("http", who.Scheme);
    }

    [Fact]
    public async Task Over_TLS_the_header_precedes_the_handshake_and_the_client_certificate_still_validates()
    {
        using var tcp = await ConnectAsync(_proxyHttpsPort);
        // The header and the ClientHello leave in one write, so they arrive in one read.
        var stream = new PrefixOnFirstWriteStream(tcp.GetStream(), ProxyProtocolParserTests.V2Tcp(FakeClient, Front));
        await using var tls = new SslStream(stream, false, (_, _, _, _) => true, (_, _, _, _, _) => _clientCert);
        await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = "node.test",
            ClientCertificates = new X509CertificateCollection { _clientCert },
        });

        var who = await RequestAsync(tls);

        Assert.Equal("203.0.113.7", who.Ip);
        Assert.Equal(51234, who.Port);
        Assert.True(who.Proxied);
        Assert.Equal("https", who.Scheme);
        Assert.Equal("CN=client.test", who.ClientCertificate);
    }

    [Fact]
    public async Task Over_TLS_a_client_certificate_from_another_CA_is_still_refused()
    {
        using var tcp = await ConnectAsync(_proxyHttpsPort);
        var stream = new PrefixOnFirstWriteStream(tcp.GetStream(), ProxyProtocolParserTests.V2Tcp(FakeClient, Front));
        await using var tls = new SslStream(stream, false, (_, _, _, _) => true, (_, _, _, _, _) => _strangerCert);

        string? response = null;
        try
        {
            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = "node.test",
                ClientCertificates = new X509CertificateCollection { _strangerCert },
            });
            // TLS 1.3 reports the server's refusal of the certificate on the first read.
            await tls.WriteAsync(Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"));
            response = await ReadAllAsync(tls);
        }
        catch (Exception ex) when (ex is IOException or System.Security.Authentication.AuthenticationException or ObjectDisposedException)
        {
        }

        Assert.True(string.IsNullOrEmpty(response), response);
    }

    private static async Task<TcpClient> ConnectAsync(int port)
    {
        var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, port);
        return tcp;
    }

    /// <summary>Writes, ignoring a reset: the server may already have closed the connection.</summary>
    private static async Task TryWriteAsync(Stream stream, byte[] bytes)
    {
        try
        {
            await stream.WriteAsync(bytes);
            await stream.FlushAsync();
        }
        catch (IOException)
        {
        }
    }

    /// <summary>Sends a GET with <paramref name="prefix"/> in front in the same write, and parses the endpoint's answer.</summary>
    private static async Task<Whoami> RequestAsync(Stream stream, byte[]? prefix = null, string headers = "")
    {
        var request = Encoding.ASCII.GetBytes($"GET /whoami HTTP/1.1\r\nHost: node.test\r\n{headers}Connection: close\r\n\r\n");
        await stream.WriteAsync((prefix ?? []).Concat(request).ToArray());
        await stream.FlushAsync();
        var response = await ReadAllAsync(stream);
        Assert.StartsWith("HTTP/1.1 200", response);
        var body = response[(response.IndexOf("\r\n\r\n", StringComparison.Ordinal) + 4)..];
        return JsonSerializer.Deserialize<Whoami>(body)!;
    }

    /// <summary>Reads to the end of the stream, within ten seconds.</summary>
    private static async Task<string> ReadAllAsync(Stream stream)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var buffer = new MemoryStream();
        var chunk = new byte[4096];
        int read;
        while ((read = await stream.ReadAsync(chunk, timeout.Token)) > 0)
            buffer.Write(chunk, 0, read);
        return Encoding.ASCII.GetString(buffer.ToArray());
    }

    /// <summary>The server closes the connection without sending a byte: end of stream or a reset.</summary>
    private static async Task AssertClosedAsync(Stream stream)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var buffer = new byte[512];
        int read;
        try
        {
            read = await stream.ReadAsync(buffer, timeout.Token);
        }
        catch (IOException)
        {
            return;
        }
        Assert.True(read == 0, $"the server answered: {Encoding.ASCII.GetString(buffer, 0, read)}");
    }

    /// <summary>A stream that puts a prefix in front of the first write, in the same write.</summary>
    private sealed class PrefixOnFirstWriteStream(Stream inner, byte[] prefix) : Stream
    {
        private byte[]? _prefix = prefix;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => inner.Flush();
        public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);
        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => inner.ReadAsync(buffer, cancellationToken);
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) => inner.ReadAsync(buffer, offset, count, cancellationToken);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => inner.Write(Take(buffer.AsSpan(offset, count)));

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => inner.WriteAsync(Take(buffer.Span), cancellationToken);

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => inner.WriteAsync(Take(buffer.AsSpan(offset, count)), cancellationToken).AsTask();

        private byte[] Take(ReadOnlySpan<byte> data)
        {
            var prefix = Interlocked.Exchange(ref _prefix, null);
            return prefix == null ? data.ToArray() : [.. prefix, .. data];
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
                inner.Dispose();
            base.Dispose(disposing);
        }
    }

    /// <summary>Test certificates; each goes through PKCS#12 so SChannel accepts its key.</summary>
    private static class Certificates
    {
        public static X509Certificate2 Server(string name)
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request = new CertificateRequest($"CN={name}", key, HashAlgorithmName.SHA256);
            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName(name);
            request.CertificateExtensions.Add(san.Build());
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
            using var ephemeral = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(1));
            return X509CertificateLoader.LoadPkcs12(ephemeral.Export(X509ContentType.Pkcs12), null);
        }

        public static (X509Certificate2 Ca, X509Certificate2 Client) CaAndClient(string caName, string clientName)
        {
            using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var caRequest = new CertificateRequest($"CN={caName}", caKey, HashAlgorithmName.SHA256);
            caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            caRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(caRequest.PublicKey, false));
            using var ca = caRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(1));

            using var clientKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var clientRequest = new CertificateRequest($"CN={clientName}", clientKey, HashAlgorithmName.SHA256);
            clientRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            clientRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            clientRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.2")], false));
            clientRequest.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(ca, true, false));
            using var issued = clientRequest.Create(ca, DateTimeOffset.UtcNow.AddMinutes(-4), DateTimeOffset.UtcNow.AddMinutes(50), RandomNumberGenerator.GetBytes(12));
            using var withKey = issued.CopyWithPrivateKey(clientKey);

            return (X509CertificateLoader.LoadCertificate(ca.RawData),
                X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pkcs12), null));
        }
    }
}
