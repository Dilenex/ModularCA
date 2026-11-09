using System.Security.Authentication;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Http;
using ModularCA.Tests.Roles;
using Xunit;

namespace ModularCA.Tests.Middleware;

/// <summary>
/// A request for the mTLS or EST subdomain that arrives on a connection made for another hostname
/// (a browser reusing its HTTP/2 connection to the main hostname) is answered 421, so the browser
/// retries on a connection whose handshake asks for the client certificate. Everything else passes.
/// </summary>
public class MisdirectedRequestMiddlewareTests
{
    private const string TypeName = "ModularCA.API.Middleware.MisdirectedRequestMiddleware";
    private static readonly IReadOnlyList<string> Gated = ["mtls.ca4.example.test", "est.ca4.example.test"];

    private static bool IsMisdirected(string? sni, string host)
        => (bool)ApiAssembly.TypeNamed(TypeName).GetMethod("IsMisdirected")!.Invoke(null, [sni, host, Gated])!;

    [Theory]
    [InlineData("ca4.example.test", "mtls.ca4.example.test")]
    [InlineData("ca4.example.test", "est.ca4.example.test")]
    [InlineData("est.ca4.example.test", "mtls.ca4.example.test")]
    [InlineData("ca4.example.test", "MTLS.ca4.example.test")]
    public void A_gated_host_on_another_hosts_connection_is_misdirected(string sni, string host)
        => Assert.True(IsMisdirected(sni, host));

    [Theory]
    [InlineData("mtls.ca4.example.test", "mtls.ca4.example.test")]
    [InlineData("MTLS.CA4.example.test", "mtls.ca4.example.test")]
    [InlineData("ca4.example.test", "ca4.example.test")]
    [InlineData("mtls.ca4.example.test", "ca4.example.test")]
    [InlineData(null, "mtls.ca4.example.test")]
    [InlineData("", "mtls.ca4.example.test")]
    public void Matching_names_other_hosts_and_connections_without_sni_pass(string? sni, string host)
        => Assert.False(IsMisdirected(sni, host));

    [Fact]
    public async Task A_coalesced_request_is_answered_421_and_goes_no_further()
    {
        var context = Context("ca4.example.test", "mtls.ca4.example.test");

        var reached = await Send(context);

        Assert.Equal(StatusCodes.Status421MisdirectedRequest, context.Response.StatusCode);
        Assert.False(reached);
    }

    [Fact]
    public async Task A_request_on_its_own_connection_reaches_the_pipeline()
        => Assert.True(await Send(Context("mtls.ca4.example.test", "mtls.ca4.example.test")));

    [Fact]
    public async Task A_request_without_a_handshake_on_this_node_reaches_the_pipeline()
    {
        var context = new DefaultHttpContext();
        context.Request.Host = new HostString("mtls.ca4.example.test");

        Assert.True(await Send(context));
    }

    private static async Task<bool> Send(HttpContext context)
    {
        var reached = false;
        RequestDelegate next = _ => { reached = true; return Task.CompletedTask; };
        var middleware = Activator.CreateInstance(ApiAssembly.TypeNamed(TypeName), [next, Gated])!;
        await (Task)middleware.GetType().GetMethod("InvokeAsync")!.Invoke(middleware, [context])!;
        return reached;
    }

    private static DefaultHttpContext Context(string sni, string host)
    {
        var context = new DefaultHttpContext();
        context.Features.Set<ITlsHandshakeFeature>(new Handshake(sni));
        context.Request.Host = new HostString(host, 443);
        return context;
    }

#pragma warning disable SYSLIB0058
    private sealed class Handshake(string sni) : ITlsHandshakeFeature
    {
        public string? HostName => sni;
        public SslProtocols Protocol => SslProtocols.Tls13;
        public CipherAlgorithmType CipherAlgorithm => CipherAlgorithmType.None;
        public int CipherStrength => 0;
        public HashAlgorithmType HashAlgorithm => HashAlgorithmType.None;
        public int HashStrength => 0;
        public ExchangeAlgorithmType KeyExchangeAlgorithm => ExchangeAlgorithmType.None;
        public int KeyExchangeStrength => 0;
    }
#pragma warning restore SYSLIB0058
}
