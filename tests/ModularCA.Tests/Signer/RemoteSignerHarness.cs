using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Keystore.Signing;
using ModularCA.Shared.Signing;
using ModularCA.Signer.Client;
using ModularCA.Signer.Identity;
using ModularCA.Signer.Server;

namespace ModularCA.Tests.Signer;

/// <summary>
/// The identities a test signer channel runs on, generated once per test run the way
/// <c>--init-identity</c> and <c>--issue-node-identity</c> generate them: one identity CA, a
/// server certificate for loopback, the node's client certificate, and a second client
/// certificate the same CA issued that no signer pins, to prove the pin is on the key and not
/// on the chain.
/// </summary>
internal sealed class RemoteSignerIdentity
{
    public static readonly RemoteSignerIdentity Instance = new();

    public X509Certificate2 IdentityCa { get; }
    public X509Certificate2 Server { get; }
    public X509Certificate2 Client { get; }
    public X509Certificate2 UnpinnedClient { get; }
    public string ServerPin => SpkiPin.Compute(Server);
    public string ClientPin => SpkiPin.Compute(Client);

    private RemoteSignerIdentity()
    {
        var now = DateTimeOffset.UtcNow;
        IdentityCa = SignerIdentity.CreateIdentityCa(now);
        Server = SignerIdentity.IssueServerCertificate(IdentityCa, "127.0.0.1", now);
        Client = SignerIdentity.IssueClientCertificate(IdentityCa, now);
        UnpinnedClient = SignerIdentity.IssueClientCertificate(IdentityCa, now);
    }
}

/// <summary>
/// A signer role hosted in the test process on a loopback port: the real Kestrel listener
/// with mutual TLS, the real gRPC service, over whatever <see cref="ISigningService"/> the
/// test supplies. <see cref="Connect"/> opens a <see cref="RemoteSigningService"/> to it with
/// the identity and pin the test chooses, so a test can present the wrong client or expect the
/// wrong server and watch the handshake refuse it.
/// </summary>
internal sealed class HostedSigner : IAsyncDisposable
{
    private readonly WebApplication _app;

    public Uri Endpoint { get; }
    public int Port => Endpoint.Port;

    private HostedSigner(WebApplication app, Uri endpoint)
    {
        _app = app;
        Endpoint = endpoint;
    }

    /// <summary>
    /// Starts a signer over <paramref name="signer"/> on <paramref name="port"/> (0 for any
    /// free port), admitting the client whose pin is <paramref name="pinnedClientSpki"/>: the
    /// test node's by default.
    /// </summary>
    public static async Task<HostedSigner> StartAsync(ISigningService signer, int port = 0, string? pinnedClientSpki = null)
    {
        var identity = RemoteSignerIdentity.Instance;
        var options = new SignerServerOptions(IPAddress.Loopback, port, identity.Server, pinnedClientSpki ?? identity.ClientPin);
        var app = SignerServerHost.Build(options, builder =>
        {
            builder.Logging.ClearProviders();
            builder.Services.AddSingleton(signer);
        });
        await app.StartAsync();
        var address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
        return new HostedSigner(app, new Uri(address.Replace("[::1]", "127.0.0.1").Replace("0.0.0.0", "127.0.0.1")));
    }

    /// <summary>Starts the signer role's in-process signer over a test world, failing closed on its audit as the role does.</summary>
    public static Task<HostedSigner> StartAsync(SignerTestWorld world, ISignerAuditSink? audit = null, int port = 0, string? pinnedClientSpki = null)
        => StartAsync(InProcessOver(world, audit), port, pinnedClientSpki);

    /// <summary>The signer the signer role would run over a test world.</summary>
    public static InProcessSigningService InProcessOver(SignerTestWorld world, ISignerAuditSink? audit = null) => new(
        world.Keystore,
        world.Scopes,
        audit ?? new DatabaseSignerAuditSink(world.Scopes),
        world.Persistence,
        NullLogger<InProcessSigningService>.Instance,
        unlocked: true,
        failClosedOnAuditFailure: true);

    /// <summary>Opens a client to this signer as the test node, or as whoever <paramref name="clientCertificate"/> is, trusting the pin given.</summary>
    public RemoteSigningService Connect(X509Certificate2? clientCertificate = null, string? pinnedServerSpki = null)
        => ConnectTo(Endpoint, clientCertificate, pinnedServerSpki);

    /// <summary>Opens a client to <paramref name="endpoint"/>, which need not be listening.</summary>
    public static RemoteSigningService ConnectTo(Uri endpoint, X509Certificate2? clientCertificate = null, string? pinnedServerSpki = null)
    {
        var identity = RemoteSignerIdentity.Instance;
        var options = new RemoteSignerOptions(endpoint, clientCertificate ?? identity.Client, pinnedServerSpki ?? identity.ServerPin)
        {
            CallTimeout = TimeSpan.FromSeconds(20),
            TransferTimeout = TimeSpan.FromSeconds(60),
            ConnectTimeout = TimeSpan.FromSeconds(3),
        };
        return new RemoteSigningService(options, NullLogger<RemoteSigningService>.Instance);
    }

    /// <summary>Stops the listener; the port is free again and the client sees the signer as down.</summary>
    public Task StopAsync() => _app.StopAsync();

    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
    }
}

/// <summary>
/// One hosted signer per test world, kept for the run: the contract suite asks for a signer
/// many times over the same world, and a Kestrel host per call would be the slowest thing in
/// the suite.
/// </summary>
internal static class HostedSigners
{
    private static readonly ConcurrentDictionary<string, Lazy<(HostedSigner Host, RemoteSigningService Client)>> ByWorld = new();

    /// <summary>The remote client bound to the signer hosted over <paramref name="world"/>.</summary>
    public static RemoteSigningService For(SignerTestWorld world)
        => ByWorld.GetOrAdd(world.DatabaseName, _ => new Lazy<(HostedSigner, RemoteSigningService)>(() =>
        {
            var host = HostedSigner.StartAsync(world).GetAwaiter().GetResult();
            return (host, host.Connect());
        })).Value.Client;
}
