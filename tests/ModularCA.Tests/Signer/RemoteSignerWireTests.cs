using System.Net;
using System.Net.Http.Json;
using System.Net.Security;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Google.Protobuf;
using Grpc.Core;
using Grpc.Net.Client;
using ModularCA.Keystore.Signing;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Signing;
using ModularCA.Signer.Identity;
using ModularCA.Ssh;
using Xunit;
using Wire = ModularCA.Signer.Wire;

namespace ModularCA.Tests.Signer;

/// <summary>
/// What the wire refuses that the contract cannot express: a client the signer has not
/// pinned, a server the node has not pinned, a signer that cannot record its decision, a
/// signer that is not there, and the reason of a refusal crossing intact. Each runs against
/// the real Kestrel listener with mutual TLS on loopback, in <see cref="RemoteSignerCollection"/>.
/// </summary>
[Collection(RemoteSignerCollection.Name)]
public sealed class RemoteSignerWireTests
{
    private static readonly byte[] Tbs = Encoding.ASCII.GetBytes("to-be-signed bytes for the wire");

    private static SigningContext CertificateContext(SignerTestWorld world)
        => new("wire-test", SigningPurpose.Certificate, world.SpaceA, world.CaRsaId);

    /// <summary>A leaf TBSCertificate under the RSA CA, which its key signs under the certificate purpose.</summary>
    private static byte[] LeafTbs(SignerTestWorld world)
        => TypedSigningData.Certificate(world["ca-rsa"].Certificate.SubjectDN, world["leaf"].PublicKey, SignatureAlgorithm.FromName("SHA256withRSA"));

    private static Task<byte[]> SignCaRsaAsync(ISigningService signer, SignerTestWorld world)
        => signer.SignAsync(world["ca-rsa"].Ref, SignatureAlgorithm.FromName("SHA256withRSA"), LeafTbs(world), CertificateContext(world));

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
            () => client.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), new SigningContext("wire-test", SigningPurpose.Ceremony, world.SpaceA, null)));
        Assert.Equal(SigningRefusalReason.AuditUnavailable, generate.Reason);
        Assert.Empty(world.Persistence.Appended);
        Assert.Equal(0, AuditRows(world));

        // Health needs no audit row and still answers.
        Assert.True((await client.HealthAsync()).Unlocked);
    }

    /// <summary>
    /// The client stays pointed at one address, a <see cref="LoopbackRelay"/> that holds its port,
    /// while the signer behind it goes away and a new one, on a port of its own, takes its place.
    /// </summary>
    [Fact]
    public async Task A_signer_that_is_down_is_unavailable_and_is_found_again_when_it_returns()
    {
        var world = SignerTestWorld.Create();
        await using var relay = new LoopbackRelay();
        var host = await HostedSigner.StartAsync(world);
        relay.Target = host.Endpoint;
        using var client = HostedSigner.ConnectTo(relay.Endpoint);
        Assert.NotEmpty(await SignCaRsaAsync(client, world));

        relay.Target = null;
        await host.DisposeAsync();
        relay.Drop();
        var down = await Assert.ThrowsAsync<SigningRefusedException>(() => SignCaRsaAsync(client, world));
        Assert.Equal(SigningRefusalReason.SignerUnavailable, down.Reason);
        Assert.Contains("unreachable", down.Message);
        var health = await client.HealthAsync();
        Assert.False(health.Unlocked);
        Assert.Equal(SignerHealth.UnreachableBackend, health.Backend);

        // The channel backs off between reconnection attempts, bounded by the client's
        // MaxReconnectBackoff; the signer is found again within that bound.
        await using var returned = await HostedSigner.StartAsync(world);
        relay.Target = returned.Endpoint;
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

    /// <summary>
    /// A client that predates the instance marker sends a context without it. An empty space
    /// id from it reads as no stated scope, never as the instance, so the signer refuses its key
    /// operation as having no context even where the instance waives ceremonies.
    /// </summary>
    [Fact]
    public async Task An_omitted_instance_marker_is_no_scope_and_is_refused()
    {
        var oldClientBytes = new ModularCA.Signer.Wire.SigningContext { Caller = "old-node", Purpose = nameof(SigningPurpose.Ceremony) }.ToByteArray();
        var parsed = ModularCA.Signer.Wire.WireMapping.FromWire(ModularCA.Signer.Wire.SigningContext.Parser.ParseFrom(oldClientBytes));
        Assert.Null(parsed.SpaceId);
        Assert.False(parsed.InstanceScope);
        Assert.True(ModularCA.Signer.Wire.WireMapping.FromWire(
            ModularCA.Signer.Wire.WireMapping.ToWire(SigningContext.ForScope("new-node", SigningPurpose.Ceremony, null))).InstanceScope);

        var world = SignerTestWorld.Create();
        using (var db = world.OpenDb())
        {
            db.SecurityPolicies.Add(new SecurityPolicyEntity { RequireKeyCeremony = false });
            db.SaveChanges();
        }
        await using var host = await HostedSigner.StartAsync(world);
        using var client = host.Connect();

        var ex = await Assert.ThrowsAsync<SigningRefusedException>(
            () => client.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), new SigningContext("old-node", SigningPurpose.Ceremony, null, null)));
        Assert.Equal(SigningRefusalReason.ContextRequired, ex.Reason);
        var generated = await client.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), SigningContext.ForScope("new-node", SigningPurpose.Ceremony, null));
        await client.RetireKeyAsync(generated.Key, SigningContext.ForScope("new-node", SigningPurpose.Ceremony, null));
    }

    /// <summary>
    /// The key usage is a field older peers do not have. An older node omits it, which reads as
    /// the X.509 usage; and a newer node asking for an X.509 key sends byte for byte what an
    /// older node sends, so an older signer sees nothing new in anything it already serves. The
    /// two SSH purposes cross by name, and a purpose a signer does not know is bad input, not a
    /// guess.
    /// </summary>
    [Fact]
    public void The_key_usage_and_the_ssh_purposes_cross_the_wire_and_an_omitted_usage_is_x509()
    {
        var fromAnOlderNode = new ModularCA.Signer.Wire.KeySpec { Algorithm = "ECDSA", SizeOrCurve = "P-256" }.ToByteArray();
        Assert.Equal(KeySpec.X509Usage, ModularCA.Signer.Wire.WireMapping.FromWire(ModularCA.Signer.Wire.KeySpec.Parser.ParseFrom(fromAnOlderNode)).Usage);
        Assert.Equal(fromAnOlderNode, ModularCA.Signer.Wire.WireMapping.ToWire(new KeySpec("ECDSA", "P-256")).ToByteArray());

        var ssh = new KeySpec("Ed25519", "", Usage: KeySpec.SshUsage);
        var crossed = ModularCA.Signer.Wire.WireMapping.FromWire(
            ModularCA.Signer.Wire.KeySpec.Parser.ParseFrom(ModularCA.Signer.Wire.WireMapping.ToWire(ssh).ToByteArray()));
        Assert.Equal(ssh, crossed);

        var caId = Guid.NewGuid();
        foreach (var purpose in new[] { SigningPurpose.SshCertificate, SigningPurpose.SshKeyMigration })
        {
            var context = SigningContext.ForScope("node", purpose, null, caId);
            var back = ModularCA.Signer.Wire.WireMapping.FromWire(
                ModularCA.Signer.Wire.SigningContext.Parser.ParseFrom(ModularCA.Signer.Wire.WireMapping.ToWire(context).ToByteArray()));
            Assert.Equal(context, back);
        }
        Assert.Throws<ArgumentException>(() => ModularCA.Signer.Wire.WireMapping.FromWire(
            new ModularCA.Signer.Wire.SigningContext { Caller = "node", Purpose = "APurposeThisSignerPredates" }));
    }

    // ---- SignSshCertificate ---------------------------------------------------------------------

    /// <summary>A user certificate for one principal, valid for an hour from now, that every rule allows.</summary>
    private static SshCertificateRequest SshRequest(KeyRef key)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var subject = SshPublicKey.FromKeyParameter(ModularCA.Shared.Utils.KeyAlgorithmPolicy.GenerateKeyPair("Ed25519", "").Public).Blob;
        return new SshCertificateRequest(key, subject, SshCertificateRequest.UserType, 77, "wire-test-key-id", new[] { "wire-principal" }, now, now + 3600,
            new[] { new SshCertificateOption("force-command", "/usr/bin/true") }, new[] { new SshCertificateOption("permit-pty") });
    }

    private static SigningContext SshContext(Guid caId) => SigningContext.ForCa("wire-test", SigningPurpose.SshCertificate, caId, null);

    /// <summary>A gRPC channel to the hosted signer as the test node, for calls <see cref="ModularCA.Signer.Client.RemoteSigningService"/> would never make.</summary>
    private static GrpcChannel RawChannel(HostedSigner host)
    {
        var identity = RemoteSignerIdentity.Instance;
        return GrpcChannel.ForAddress(host.Endpoint, new GrpcChannelOptions
        {
            DisposeHttpClient = true,
            HttpHandler = new SocketsHttpHandler
            {
                SslOptions = new SslClientAuthenticationOptions
                {
                    ClientCertificates = new X509CertificateCollection { identity.Client },
                    LocalCertificateSelectionCallback = (_, _, _, _, _) => identity.Client,
                    RemoteCertificateValidationCallback = (_, cert, _, _) => cert is X509Certificate2 x && SpkiPin.Matches(x, identity.ServerPin),
                },
            },
        });
    }

    private static CallOptions RawOptions() => new(deadline: DateTime.UtcNow.AddSeconds(60));

    /// <summary>
    /// The request crosses as the design's message gives it, field for field, and the message
    /// has no field for what is the signer's to choose: the nonce, the signature key and the
    /// signature algorithm.
    /// </summary>
    [Fact]
    public void An_ssh_certificate_request_crosses_the_wire_field_for_field()
    {
        var key = new KeyRef(Guid.NewGuid(), KeyRef.SshKeystore);
        var request = new SshCertificateRequest(key, new byte[] { 0, 1, 2, 255 }, SshCertificateRequest.HostType, ulong.MaxValue, "key id \"quoted\" 鍵",
            new[] { "first", "second", "" }, long.MinValue, long.MaxValue,
            new[] { new SshCertificateOption("force-command", "/bin/true"), new SshCertificateOption("verify-required") },
            new[] { new SshCertificateOption("permit-pty") });
        var context = SigningContext.ForScope("node", SigningPurpose.SshCertificate, null, Guid.NewGuid());

        var wire = Wire.SignSshCertificateRequest.Parser.ParseFrom(Wire.WireMapping.ToWire(request, context).ToByteArray());
        var back = Wire.WireMapping.FromWire(wire);

        Assert.Equal(request.Key, back.Key);
        Assert.Equal(request.SubjectPublicKey, back.SubjectPublicKey);
        Assert.Equal(request.CertType, back.CertType);
        Assert.Equal(request.Serial, back.Serial);
        Assert.Equal(request.KeyId, back.KeyId);
        Assert.Equal(request.Principals, back.Principals);
        Assert.Equal(request.ValidAfter, back.ValidAfter);
        Assert.Equal(request.ValidBefore, back.ValidBefore);
        Assert.Equal(request.CriticalOptions, back.CriticalOptions);
        Assert.Equal(request.Extensions, back.Extensions);
        Assert.Equal(context, Wire.WireMapping.FromWire(wire.Context));

        Assert.Equal(
            new[]
            {
                (1, "key"), (2, "subject_public_key"), (3, "cert_type"), (4, "serial"), (5, "key_id"), (6, "principals"),
                (7, "valid_after"), (8, "valid_before"), (9, "critical_options"), (10, "extensions"), (11, "context"),
            },
            Wire.SignSshCertificateRequest.Descriptor.Fields.InFieldNumberOrder().Select(f => (f.FieldNumber, f.Name)));
        Assert.Equal(new[] { (1, "certificate") }, Wire.SignSshCertificateResponse.Descriptor.Fields.InFieldNumberOrder().Select(f => (f.FieldNumber, f.Name)));

        // The wire has no null: a member left null crosses as empty.
        var bare = Wire.WireMapping.FromWire(Wire.SignSshCertificateRequest.Parser.ParseFrom(
            Wire.WireMapping.ToWire(new SshCertificateRequest(key, null!, null!, 1, null!, null!, 0, 0), context).ToByteArray()));
        Assert.Empty(bare.SubjectPublicKey);
        Assert.Equal(string.Empty, bare.CertType);
        Assert.Equal(string.Empty, bare.KeyId);
        Assert.Empty(bare.Principals);
        Assert.Empty(bare.CriticalOptions!);
        Assert.Empty(bare.Extensions!);

        // A request that names no key, or names one that is no id, is bad input.
        Assert.Throws<ArgumentException>(() => Wire.WireMapping.FromWire((Wire.SignSshCertificateRequest?)null));
        Assert.Throws<ArgumentException>(() => Wire.WireMapping.FromWire(new Wire.SignSshCertificateRequest { CertType = SshCertificateRequest.UserType }));
        Assert.Throws<ArgumentException>(() => Wire.WireMapping.FromWire(
            new Wire.SignSshCertificateRequest { Key = new Wire.KeyRef { CertificateId = "not-an-id", Keystore = KeyRef.SshKeystore } }));
        // A reference that names no keystore is a key of the certificate keystore, never of the SSH keystore.
        Assert.Equal(KeyRef.DefaultKeystore, Wire.WireMapping.FromWire(
            new Wire.SignSshCertificateRequest { Key = new Wire.KeyRef { CertificateId = Guid.NewGuid().ToString("D") } }).Key.Keystore);
    }

    /// <summary>
    /// A signer from before the SSH keystore, as the node sees one: every call it has is served
    /// by the signer behind it, and the call it lacks is answered UNIMPLEMENTED, as a gRPC
    /// server answers a method it does not have.
    /// </summary>
    public class OlderSigner : DispatchProxy
    {
        private ISigningService _inner = null!;

        /// <summary>An older signer over <paramref name="inner"/>.</summary>
        public static ISigningService Over(ISigningService inner)
        {
            var proxy = Create<ISigningService, OlderSigner>();
            ((OlderSigner)(object)proxy)._inner = inner;
            return proxy;
        }

        /// <inheritdoc />
        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
            => targetMethod!.Name == nameof(ISigningService.SignSshCertificateAsync)
                ? throw new RpcException(new Status(StatusCode.Unimplemented, "Method is unimplemented."))
                : targetMethod.Invoke(_inner, args);
    }

    [Fact]
    public async Task A_signer_that_predates_the_ssh_keystore_is_reported_as_one_to_upgrade_first()
    {
        var world = SignerTestWorld.Create();
        var (caId, key, publicKey) = world.SeedBoundSshKey();
        await using var older = await HostedSigner.StartAsync(OlderSigner.Over(HostedSigner.InProcessOver(world)));
        using var client = older.Connect();

        var ex = await Assert.ThrowsAsync<SigningRefusedException>(() => client.SignSshCertificateAsync(SshRequest(key), SshContext(caId)));

        Assert.Equal(SigningRefusalReason.OperationUnsupported, ex.Reason);
        Assert.Contains("predates the SSH keystore", ex.Message);
        Assert.Contains("Upgrade the signer first", ex.Message);
        // The older signer decided nothing, so it recorded nothing.
        Assert.Equal(0, AuditRows(world));
        // It answered, so it is not taken for a signer that is down: its other calls are served.
        Assert.True((await client.HealthAsync()).Unlocked);
        Assert.NotEmpty(await SignCaRsaAsync(client, world));

        // The same node in front of a current signer over the same keys is served.
        await using var current = await HostedSigner.StartAsync(world);
        using var upgraded = current.Connect();
        var certificate = SshCertificate.Parse(await upgraded.SignSshCertificateAsync(SshRequest(key), SshContext(caId)));
        Assert.True(certificate.VerifySignature());
        Assert.Equal(publicKey, certificate.SignatureKey);
    }

    /// <summary>
    /// A signer from before the SSH keystore, as the import of a key file meets one: it has the
    /// import call, and cannot read a context whose purpose it has never heard of, which its
    /// wire mapping answers as bad input before the signer is reached.
    /// </summary>
    public class SignerBeforeTheMigrationPurpose : DispatchProxy
    {
        private ISigningService _inner = null!;

        /// <summary>An older signer over <paramref name="inner"/>.</summary>
        public static ISigningService Over(ISigningService inner)
        {
            var proxy = Create<ISigningService, SignerBeforeTheMigrationPurpose>();
            ((SignerBeforeTheMigrationPurpose)(object)proxy)._inner = inner;
            return proxy;
        }

        /// <inheritdoc />
        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
            => args?.OfType<SigningContext>().Any(c => c.Purpose == SigningPurpose.SshKeyMigration) == true
                ? throw new ArgumentException("'SshKeyMigration' is not a signing purpose.", "context.purpose")
                : targetMethod!.Invoke(_inner, args);
    }

    [Fact]
    public async Task A_signer_that_predates_the_ssh_keystore_leaves_every_key_file_as_it_is_and_is_named_as_one_to_upgrade_first()
    {
        var world = SignerTestWorld.Create();
        var install = Path.Combine(Path.GetTempPath(), $"mca-older-signer-{Guid.NewGuid():N}");
        var keys = Path.Combine(install, "config", "ssh-ca-keys");
        Directory.CreateDirectory(keys);
        try
        {
            // Two SSH CAs of an install from before the SSH keystore, with their key files.
            var rows = new List<SshCaKeyEntity>();
            using (var db = world.OpenDb())
            {
                foreach (var fixture in new[] { "ed25519", "p256" })
                {
                    var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = $"old {fixture}", Label = $"old-{fixture}", Type = "SSH", IsSshCa = true, IsEnabled = true };
                    var row = new SshCaKeyEntity
                    {
                        Id = Guid.NewGuid(), Name = $"old {fixture}", KeyType = fixture, CertificateAuthorityId = ca.Id,
                        PublicKey = ModularCA.Tests.Ssh.SshFixtures.Text($"ca-{fixture}.pub").Trim(), KeyStorage = SshCaKeyStorage.LegacyFile,
                        IsUserCa = true, MaxValidityHours = 24,
                    };
                    row.PrivateKeyPath = Path.Combine(keys, row.Id.ToString());
                    File.Copy(ModularCA.Tests.Ssh.SshFixtures.PathOf($"ca-{fixture}.testkey"), row.PrivateKeyPath);
                    db.CertificateAuthorities.Add(ca);
                    db.SshCaKeys.Add(row);
                    rows.Add(row);
                }
                db.SaveChanges();
            }
            var files = rows.ToDictionary(r => r.Id, r => File.ReadAllBytes(r.PrivateKeyPath!));

            await using var older = await HostedSigner.StartAsync(SignerBeforeTheMigrationPurpose.Over(HostedSigner.InProcessOver(world)));
            using var client = older.Connect();

            // The call itself: bad input on the wire, a refusal that says what to do at the node.
            var migration = SigningContext.ForCa("wire-test", SigningPurpose.SshKeyMigration, rows[0].CertificateAuthorityId, null);
            var ex = await Assert.ThrowsAsync<SigningRefusedException>(() => client.ImportKeyAsync(
                new KeyMaterial(ModularCA.Tests.Ssh.SshFixtures.CaPrivate("ed25519").ToPkcs8(), KeyMaterial.Pkcs8, rows[0].Id, KeyRef.SshKeystore), migration));
            Assert.Equal(SigningRefusalReason.OperationUnsupported, ex.Reason);
            Assert.Contains("predates the SSH keystore", ex.Message);
            Assert.Contains("Upgrade the signer first", ex.Message);
            // It is the import of an SSH key that is translated, nothing else: other bad input stays what it is.
            await Assert.ThrowsAsync<RpcException>(() => client.ListKeysAsync(migration));

            // The import pass over that signer: nothing is switched, nothing is removed, and the reason says to upgrade the signer.
            var state = new ModularCA.Core.Services.SshKeyImportState();
            var report = await new ModularCA.Core.Services.SshKeyFileImport(world.OpenDb(), client, new ModularCA.Tests.Core.Services.SshAuditLog(), state,
                Microsoft.Extensions.Logging.Abstractions.NullLogger<ModularCA.Core.Services.SshKeyFileImport>.Instance, install).RunAsync();

            Assert.Empty(report.Imported);
            Assert.Equal(2, report.Awaiting.Count);
            Assert.All(report.Awaiting, a =>
            {
                Assert.Equal(ModularCA.Core.Services.SshKeyImportReasons.SignerUpgradeRequired, a.Code);
                Assert.Contains(ModularCA.Shared.Errors.SshCaKeyUnavailableException.SignerPredatesSshKeystore, a.Detail);
            });
            using (var db = world.OpenDb())
            {
                Assert.All(db.SshCaKeys.ToList(), r => Assert.Equal(SshCaKeyStorage.LegacyFile, r.KeyStorage));
                Assert.All(db.SshCaKeys.ToList(), r => Assert.False(string.IsNullOrEmpty(r.PrivateKeyPath)));
                Assert.Empty(db.SshKeyImports.ToList());
            }
            Assert.All(rows, r => Assert.Equal(files[r.Id], File.ReadAllBytes(r.PrivateKeyPath!)));
            Assert.Empty(world.Persistence.SshAppended);

            // The signer is upgraded; the same node imports both with its next pass.
            await using var current = await HostedSigner.StartAsync(world);
            using var upgraded = current.Connect();
            var done = await new ModularCA.Core.Services.SshKeyFileImport(world.OpenDb(), upgraded, new ModularCA.Tests.Core.Services.SshAuditLog(), state,
                Microsoft.Extensions.Logging.Abstractions.NullLogger<ModularCA.Core.Services.SshKeyFileImport>.Instance, install).RunAsync();
            Assert.Equal(2, done.Imported.Count);
            Assert.All(rows, r => Assert.False(File.Exists(r.PrivateKeyPath!)));
            Assert.Equal(2, world.Persistence.SshAppended.Count);
        }
        finally
        {
            try { Directory.Delete(install, true); } catch (IOException) { }
        }
    }

    /// <summary>
    /// What the mapping above rests on, asked of the real listener: a call the signer does not
    /// have is answered UNIMPLEMENTED by the framework, with no refusal trailer, and never
    /// reaches the signer.
    /// </summary>
    [Fact]
    public async Task A_call_the_signer_does_not_have_is_answered_unimplemented_by_the_listener()
    {
        var world = SignerTestWorld.Create();
        await using var host = await HostedSigner.StartAsync(world);
        using var channel = RawChannel(host);
        var unknown = new Method<Wire.SignSshCertificateRequest, Wire.SignSshCertificateResponse>(
            MethodType.Unary, "modularca.signer.v1.Signer", "ACallThisSignerPredates",
            Marshallers.Create(m => m.ToByteArray(), Wire.SignSshCertificateRequest.Parser.ParseFrom),
            Marshallers.Create(m => m.ToByteArray(), Wire.SignSshCertificateResponse.Parser.ParseFrom));

        var ex = await Assert.ThrowsAsync<RpcException>(async () =>
            await channel.CreateCallInvoker().AsyncUnaryCall(unknown, null, RawOptions(), new Wire.SignSshCertificateRequest()));

        Assert.Equal(StatusCode.Unimplemented, ex.StatusCode);
        Assert.Null(ex.Trailers.GetValue(Wire.WireMapping.RefusalReasonTrailer));
        Assert.Equal(0, AuditRows(world));
    }

    /// <summary>
    /// What a peer that is not <see cref="ModularCA.Signer.Client.RemoteSigningService"/> could
    /// send. A request the signer cannot attribute (no key reference, no context, an id or a
    /// purpose that is not one) is bad input, InvalidArgument, as for every call, and is not
    /// audited because it never reaches the signer. A request it can attribute but that is not a
    /// certificate reaches the signer, which refuses it and records the refusal.
    /// </summary>
    [Fact]
    public async Task A_malformed_ssh_certificate_request_is_bad_input_or_a_recorded_refusal_and_never_an_unhandled_failure()
    {
        var world = SignerTestWorld.Create();
        var (caId, key, publicKey) = world.SeedBoundSshKey();
        await using var host = await HostedSigner.StartAsync(world);
        using var channel = RawChannel(host);
        var raw = new Wire.Signer.SignerClient(channel);
        var good = Wire.WireMapping.ToWire(SshRequest(key), SshContext(caId));
        Wire.SignSshCertificateRequest With(Action<Wire.SignSshCertificateRequest> change)
        {
            var copy = good.Clone();
            change(copy);
            return copy;
        }

        var unattributable = new (string What, Wire.SignSshCertificateRequest Request)[]
        {
            ("an empty message", new Wire.SignSshCertificateRequest()),
            ("no key reference", With(r => r.Key = null)),
            ("a key id that is not an id", With(r => r.Key.CertificateId = "not-an-id")),
            ("an empty key id", With(r => r.Key.CertificateId = "")),
            ("no context", With(r => r.Context = null)),
            ("a purpose the signer does not know", With(r => r.Context.Purpose = "APurposeThisSignerPredates")),
            ("a CA id that is not an id", With(r => r.Context.CaId = "not-an-id")),
        };
        foreach (var (what, request) in unattributable)
        {
            var ex = await Assert.ThrowsAsync<RpcException>(async () => await raw.SignSshCertificateAsync(request, RawOptions()));
            Assert.True(StatusCode.InvalidArgument == ex.StatusCode, $"{what}: {ex.StatusCode} ({ex.Status.Detail})");
            Assert.Null(ex.Trailers.GetValue(Wire.WireMapping.RefusalReasonTrailer));
        }
        Assert.Equal(0, AuditRows(world));

        var refused = new (string What, SigningRefusalReason Reason, Wire.SignSshCertificateRequest Request)[]
        {
            ("a type that is neither", SigningRefusalReason.UntypedData, With(r => r.CertType = "superuser")),
            ("no type", SigningRefusalReason.UntypedData, With(r => r.CertType = "")),
            ("a subject key that is no blob", SigningRefusalReason.UntypedData, With(r => r.SubjectPublicKey = ByteString.CopyFrom(1, 2, 3))),
            ("no subject key", SigningRefusalReason.UntypedData, With(r => r.SubjectPublicKey = ByteString.Empty)),
            ("a start before the epoch", SigningRefusalReason.UntypedData, With(r => r.ValidAfter = -1)),
            ("no principals", SigningRefusalReason.UntypedData, With(r => r.Principals.Clear())),
            ("a reference that names no keystore", SigningRefusalReason.PurposeNotPermitted, With(r => r.Key.Keystore = "")),
            ("a context that does not state the instance", SigningRefusalReason.ContextRequired, With(r => r.Context.InstanceScope = false)),
        };
        foreach (var (what, reason, request) in refused)
        {
            var ex = await Assert.ThrowsAsync<RpcException>(async () => await raw.SignSshCertificateAsync(request, RawOptions()));
            Assert.True(StatusCode.PermissionDenied == ex.StatusCode, $"{what}: {ex.StatusCode} ({ex.Status.Detail})");
            Assert.Equal(reason.ToString(), ex.Trailers.GetValue(Wire.WireMapping.RefusalReasonTrailer));
        }
        using (var db = world.OpenDb())
        {
            var rows = db.SignerAudit.ToList();
            Assert.Equal(refused.Length, rows.Count);
            Assert.All(rows, row =>
            {
                Assert.Equal("SignSsh", row.Operation);
                Assert.Equal(SignerAuditEntity.RefusedOutcome, row.Outcome);
                Assert.NotNull(row.Summary);
                Assert.DoesNotContain("wire-principal", row.Summary);
                Assert.Equal(RemoteSignerIdentity.Instance.ClientPin, row.PeerIdentity);
            });
        }

        // The message it was all made from is a certificate, and is served.
        var response = await raw.SignSshCertificateAsync(good, RawOptions());
        var certificate = SshCertificate.Parse(response.Certificate.ToByteArray());
        Assert.True(certificate.VerifySignature());
        Assert.Equal(publicKey, certificate.SignatureKey);
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
