using System.Net;
using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ModularCA.Keystore.Signing;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Signing;
using ModularCA.Signer.Identity;
using Xunit;

namespace ModularCA.Tests.Signer;

/// <summary>
/// What the wire refuses that the contract cannot express: a client the signer has not
/// pinned, a server the node has not pinned, a signer that cannot record its decision, a
/// signer that is not there, and the reason of a refusal crossing intact. Each runs against
/// the real Kestrel listener with mutual TLS on loopback.
/// </summary>
public sealed class RemoteSignerWireTests
{
    private static readonly byte[] Tbs = Encoding.ASCII.GetBytes("to-be-signed bytes for the wire");

    private static SigningContext CertificateContext(SignerTestWorld world)
        => new("wire-test", SigningPurpose.Certificate, world.TenantA, world.CaRsaId);

    private static Task<byte[]> SignCaRsaAsync(ISigningService signer, SignerTestWorld world)
        => signer.SignAsync(world["ca-rsa"].Ref, SignatureAlgorithm.FromName("SHA256withRSA"), Tbs, CertificateContext(world));

    private static int AuditRows(SignerTestWorld world)
    {
        using var db = world.OpenDb();
        return db.SignerAudit.Count();
    }

    [Fact]
    public async Task A_client_the_signer_has_not_pinned_is_refused_at_the_handshake_and_nothing_is_audited()
    {
        var world = SignerTestWorld.Create();
        await using var host = await HostedSigner.StartAsync(world);

        // Issued by the same identity CA: the pin is on the key, not on the chain.
        using var unpinned = host.Connect(clientCertificate: RemoteSignerIdentity.Instance.UnpinnedClient);
        var ex = await Assert.ThrowsAsync<SigningRefusedException>(() => SignCaRsaAsync(unpinned, world));
        Assert.Equal(SigningRefusalReason.SignerUnavailable, ex.Reason);
        var health = await unpinned.HealthAsync();
        Assert.False(health.Unlocked);
        Assert.Equal(SignerHealth.UnreachableBackend, health.Backend);
        Assert.Equal(0, AuditRows(world));

        // The pinned client is admitted by the same listener.
        using var pinned = host.Connect();
        Assert.NotEmpty(await SignCaRsaAsync(pinned, world));
        Assert.Equal(1, AuditRows(world));
    }

    [Fact]
    public async Task A_server_whose_key_is_not_the_pinned_one_is_refused_by_the_client()
    {
        var world = SignerTestWorld.Create();
        await using var host = await HostedSigner.StartAsync(world);
        var wrongPin = SpkiPin.Compute(RemoteSignerIdentity.Instance.UnpinnedClient);

        using var client = host.Connect(pinnedServerSpki: wrongPin);
        var ex = await Assert.ThrowsAsync<SigningRefusedException>(() => SignCaRsaAsync(client, world));
        Assert.Equal(SigningRefusalReason.SignerUnavailable, ex.Reason);
        Assert.False((await client.HealthAsync()).Unlocked);
        Assert.Equal(0, AuditRows(world));
    }

    [Fact]
    public async Task A_signer_that_cannot_record_its_decision_refuses_and_hands_out_no_signature()
    {
        var world = SignerTestWorld.Create();
        await using var host = await HostedSigner.StartAsync(world, audit: new FailingAuditSink());
        using var client = host.Connect();

        var ex = await Assert.ThrowsAsync<SigningRefusedException>(() => SignCaRsaAsync(client, world));
        Assert.Equal(SigningRefusalReason.AuditUnavailable, ex.Reason);

        var generate = await Assert.ThrowsAsync<SigningRefusedException>(
            () => client.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), new SigningContext("wire-test", SigningPurpose.Ceremony, world.TenantA, null)));
        Assert.Equal(SigningRefusalReason.AuditUnavailable, generate.Reason);
        Assert.Empty(world.Persistence.Appended);
        Assert.Equal(0, AuditRows(world));

        // Health needs no audit row and still answers.
        Assert.True((await client.HealthAsync()).Unlocked);
    }

    [Fact]
    public async Task A_signer_that_is_down_is_unavailable_and_is_found_again_when_it_returns()
    {
        var world = SignerTestWorld.Create();
        var host = await HostedSigner.StartAsync(world);
        using var client = host.Connect();
        Assert.NotEmpty(await SignCaRsaAsync(client, world));
        var port = host.Port;

        await host.DisposeAsync();
        var down = await Assert.ThrowsAsync<SigningRefusedException>(() => SignCaRsaAsync(client, world));
        Assert.Equal(SigningRefusalReason.SignerUnavailable, down.Reason);
        Assert.Contains("unreachable", down.Message);
        var health = await client.HealthAsync();
        Assert.False(health.Unlocked);
        Assert.Equal(SignerHealth.UnreachableBackend, health.Backend);

        // The channel backs off between reconnection attempts, bounded by the client's
        // MaxReconnectBackoff; the signer is found again within that bound.
        await using var returned = await HostedSigner.StartAsync(world, port: port);
        var deadline = DateTime.UtcNow.AddSeconds(15);
        while (!(await client.HealthAsync()).Unlocked)
        {
            Assert.True(DateTime.UtcNow < deadline, "the client did not reconnect to the returned signer within its backoff bound");
            await Task.Delay(250);
        }
        Assert.NotEmpty(await SignCaRsaAsync(client, world));
    }

    [Fact]
    public async Task Nothing_listening_is_unavailable_too()
    {
        var world = SignerTestWorld.Create();
        using var client = HostedSigner.ConnectTo(new Uri("https://127.0.0.1:1"));

        var ex = await Assert.ThrowsAsync<SigningRefusedException>(() => SignCaRsaAsync(client, world));
        Assert.Equal(SigningRefusalReason.SignerUnavailable, ex.Reason);
        Assert.Equal(SignerHealth.Unreachable(), await client.HealthAsync());
    }

    [Fact]
    public async Task The_reason_of_a_refusal_crosses_the_wire_with_its_message()
    {
        var world = SignerTestWorld.Create();
        await using var host = await HostedSigner.StartAsync(world);
        using var client = host.Connect();

        var ex = await Assert.ThrowsAsync<SigningRefusedException>(
            () => client.SignAsync(world["tsa"].Ref, SignatureAlgorithm.FromName("SHA256withRSA"), Tbs, CertificateContext(world)));

        Assert.Equal(SigningRefusalReason.PurposeNotPermitted, ex.Reason);
        Assert.Contains("Tsa", ex.Message);
        using var db = world.OpenDb();
        var row = Assert.Single(db.SignerAudit);
        Assert.Equal(SignerAuditEntity.RefusedOutcome, row.Outcome);
    }

    [Fact]
    public async Task The_health_route_answers_on_the_same_listener_to_the_pinned_client_only()
    {
        var world = SignerTestWorld.Create();
        await using var host = await HostedSigner.StartAsync(world);
        var identity = RemoteSignerIdentity.Instance;

        using var http = Http2Client(identity.Client, identity.ServerPin);
        var response = await http.GetAsync(new Uri(host.Endpoint, "/health"));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<HealthBody>();
        Assert.NotNull(body);
        Assert.True(body!.Unlocked);
        Assert.Equal(SignerHealth.SoftwareBackend, body.Backend);

        using var stranger = Http2Client(identity.UnpinnedClient, identity.ServerPin);
        await Assert.ThrowsAnyAsync<HttpRequestException>(() => stranger.GetAsync(new Uri(host.Endpoint, "/health")));
    }

    private sealed record HealthBody(string Status, bool Unlocked, int KeyCount, string Backend);

    /// <summary>A plain HTTP/2 client presenting <paramref name="client"/> and pinning the server, as the listener requires.</summary>
    private static HttpClient Http2Client(X509Certificate2 client, string serverPin) => new(new SocketsHttpHandler
    {
        SslOptions = new SslClientAuthenticationOptions
        {
            ClientCertificates = new X509CertificateCollection { client },
            LocalCertificateSelectionCallback = (_, _, _, _, _) => client,
            RemoteCertificateValidationCallback = (_, cert, _, _) => cert is X509Certificate2 x && SpkiPin.Matches(x, serverPin),
        },
    })
    {
        DefaultRequestVersion = HttpVersion.Version20,
        DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
    };

    /// <summary>An audit sink whose database is gone.</summary>
    private sealed class FailingAuditSink : ISignerAuditSink
    {
        public Task RecordAsync(SignerDecision decision, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("The signer audit table cannot be written.");
    }
}
