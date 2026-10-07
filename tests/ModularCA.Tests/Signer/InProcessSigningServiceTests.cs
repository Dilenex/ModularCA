using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Keystore.Signing;
using ModularCA.Shared.Signing;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Xunit;

namespace ModularCA.Tests.Signer;

/// <summary>
/// The contract suite bound to <see cref="InProcessSigningService"/>, plus what is specific to
/// the in-process signer: the locked state, a commit that cannot persist, and the BouncyCastle
/// factory that lets a certificate generator sign through the contract.
/// </summary>
public sealed class InProcessSigningServiceTests : SigningServiceContractTests
{
    internal override Task<ISigningService> CreateSignerAsync(SignerTestWorld world) => Task.FromResult(world.CreateInProcessSigner());

    protected override string ExpectedBackend => SignerHealth.SoftwareBackend;

    internal override void AssertPersisted(SignerTestWorld world, byte[] certificateDer)
        => Assert.Contains(world.Persistence.Appended, p => p.CertificateDer.AsSpan().SequenceEqual(certificateDer));

    private static InProcessSigningService Create(SignerTestWorld world, bool unlocked) => new(
        world.Keystore,
        world.Scopes,
        new DatabaseSignerAuditSink(world.Scopes),
        world.Persistence,
        NullLogger<InProcessSigningService>.Instance,
        unlocked: unlocked);

    [Fact]
    public async Task A_locked_signer_refuses_everything_and_reports_no_keys()
    {
        var world = SignerTestWorld.Create();
        var signer = Create(world, unlocked: false);

        var ex = await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.SignAsync(world["ca-rsa"].Ref, SignatureAlgorithm.FromName("SHA256withRSA"), new byte[] { 1, 2, 3 },
                new SigningContext("contract-test", SigningPurpose.Certificate, world.SpaceA, world.CaRsaId)));
        Assert.Equal(SigningRefusalReason.SignerLocked, ex.Reason);

        var health = await signer.HealthAsync();
        Assert.False(health.Unlocked);
        Assert.Equal(0, health.KeyCount);

        var row = Assert.Single(await ReadAuditAsync(world));
        Assert.Equal("refused", row.Outcome);
    }

    [Fact]
    public async Task A_locked_signer_manages_no_keys()
    {
        var world = SignerTestWorld.Create();
        var signer = Create(world, unlocked: false);
        var ceremony = new SigningContext("contract-test", SigningPurpose.Ceremony, world.SpaceA, null);

        async Task Locked(Func<Task> operation)
        {
            var ex = await Assert.ThrowsAsync<SigningRefusedException>(operation);
            Assert.Equal(SigningRefusalReason.SignerLocked, ex.Reason);
        }
        await Locked(() => signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), ceremony));
        await Locked(() => signer.ImportKeyAsync(new KeyMaterial((byte[])world["keyless"].PrivateKeyPkcs8.Clone(), KeyMaterial.Pkcs8, world["keyless"].Ref.CertificateId), ceremony));
        await Locked(() => signer.CommitKeyAsync(new KeyRef(Guid.NewGuid()), world["leaf"].Ref.CertificateId, ceremony));
        await Locked(() => signer.RetireKeyAsync(new KeyRef(Guid.NewGuid()), ceremony));
        await Locked(() => signer.DecryptAsync(world["ca-rsa"].Ref, new byte[] { 1 }, new SigningContext("contract-test", SigningPurpose.Scep, world.SpaceA, world.CaRsaId)));
        Assert.Empty(world.Persistence.Appended);
    }

    [Fact]
    public async Task A_locked_signer_wraps_and_unwraps_nothing()
    {
        var world = SignerTestWorld.Create();
        var unlocked = Create(world, unlocked: true);
        var context = new SigningContext("contract-test", SigningPurpose.Cmp, null, null);
        var blob = await unlocked.WrapSecretAsync(SecretKind.CmpSharedSecret, new byte[] { 1, 2, 3, 4 }, context);

        // The wrapping key is derived from a keystore key, so a signer that has not unlocked has
        // nothing to derive it from and must say so rather than fail somewhere deeper.
        var locked = Create(world, unlocked: false);

        var wrap = await Assert.ThrowsAsync<SigningRefusedException>(
            () => locked.WrapSecretAsync(SecretKind.CmpSharedSecret, new byte[] { 1, 2, 3, 4 }, context));
        Assert.Equal(SigningRefusalReason.SignerLocked, wrap.Reason);

        var unwrap = await Assert.ThrowsAsync<SigningRefusedException>(() => locked.UnwrapSecretAsync(blob, context));
        Assert.Equal(SigningRefusalReason.SignerLocked, unwrap.Reason);

        var refusals = (await ReadAuditAsync(world)).Where(r => r.Outcome == "refused").ToList();
        Assert.Equal(new[] { "WrapSecret", "UnwrapSecret" }, refusals.Select(r => r.Operation));
    }

    [Fact]
    public async Task A_locked_signer_still_moves_whole_keystore_files_since_that_is_how_it_comes_to_hold_keys()
    {
        var world = SignerTestWorld.Create();
        world.Persistence.KeystoreFiles[KeyRef.DefaultKeystore] = new byte[] { 9, 9, 9 };
        var signer = Create(world, unlocked: false);

        var exported = await signer.ExportKeyAsync(KeyRef.ForKeystore(KeyRef.DefaultKeystore), ExportWrap.ForKeystoreFile(),
            new SigningContext("contract-test", SigningPurpose.Backup, null, null));
        Assert.Equal(new byte[] { 9, 9, 9 }, exported);

        await signer.ImportKeyAsync(new KeyMaterial(new byte[] { 7 }, KeyMaterial.KeystoreFile, Guid.Empty, KeyRef.TrustKeystore),
            new SigningContext("contract-test", SigningPurpose.Restore, null, null));
        Assert.Equal(new byte[] { 7 }, world.Persistence.KeystoreFiles[KeyRef.TrustKeystore]);

        // ... and nothing else.
        var ex = await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.ExportKeyAsync(world["leaf"].Ref, new ExportWrap(ExportWrap.Pkcs12, "pw"),
                new SigningContext("contract-test", SigningPurpose.Export, null, null)));
        Assert.Equal(SigningRefusalReason.SignerLocked, ex.Reason);
    }

    [Fact]
    public async Task A_commit_that_cannot_persist_propagates_and_leaves_the_key_pending()
    {
        var world = SignerTestWorld.Create();
        var signer = Create(world, unlocked: true);
        var ceremony = new SigningContext("contract-test", SigningPurpose.Ceremony, world.SpaceA, null);
        var generated = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), ceremony);
        var certificateId = Guid.NewGuid();
        using (var db = world.OpenDb())
        {
            var publicKey = PublicKeyFactory.CreateKey(generated.PublicKeyDer);
            var gen = new X509V3CertificateGenerator();
            gen.SetSerialNumber(BigInteger.ValueOf(7));
            gen.SetIssuerDN(new X509Name("CN=pending"));
            gen.SetSubjectDN(new X509Name("CN=pending"));
            gen.SetNotBefore(DateTime.UtcNow.AddMinutes(-1));
            gen.SetNotAfter(DateTime.UtcNow.AddDays(1));
            gen.SetPublicKey(publicKey);
            // A new CA's key self-signs its CA certificate and nothing else of its own.
            gen.AddExtension(Org.BouncyCastle.Asn1.X509.X509Extensions.BasicConstraints, true, new Org.BouncyCastle.Asn1.X509.BasicConstraints(true));
            var cert = gen.Generate(new SigningServiceSignatureFactory(signer, generated.Key, SignatureAlgorithm.ForPublicKey(publicKey), ceremony));
            db.Certificates.Add(new ModularCA.Shared.Entities.CertificateEntity
            {
                CertificateId = certificateId, SerialNumber = "07", SubjectDN = "CN=pending", Issuer = "CN=pending",
                IsCA = true, RawCertificate = cert.GetEncoded(), NotBefore = cert.NotBefore, NotAfter = cert.NotAfter,
            });
            await db.SaveChangesAsync();
        }
        world.Persistence.FailWith = new IOException("keystore file locked");

        await Assert.ThrowsAsync<IOException>(() => signer.CommitKeyAsync(generated.Key, certificateId, ceremony));

        // Still pending: it signs under the ceremony, and can be retired by it.
        Assert.Null(world.Keystore.GetPrivateKeyFor(new X509Certificate(
            (await ReadRawAsync(world, certificateId))!)));
        await signer.RetireKeyAsync(generated.Key, ceremony);
    }

    private static Task<byte[]?> ReadRawAsync(SignerTestWorld world, Guid certificateId)
    {
        using var db = world.OpenDb();
        return Task.FromResult(db.Certificates.Single(c => c.CertificateId == certificateId).RawCertificate);
    }

    [Fact]
    public async Task A_locked_signer_manages_no_ssh_keys()
    {
        var world = SignerTestWorld.Create();
        var signer = Create(world, unlocked: false);
        var instance = new SigningContext("contract-test", SigningPurpose.Ceremony, null, null) { InstanceScope = true };
        var sshRef = new KeyRef(Guid.NewGuid(), KeyRef.SshKeystore);
        var pkcs8 = Org.BouncyCastle.Pkcs.PrivateKeyInfoFactory.CreatePrivateKeyInfo(
            ModularCA.Shared.Utils.KeyAlgorithmPolicy.GenerateKeyPair("Ed25519", "").Private).GetDerEncoded();

        async Task Locked(Func<Task> operation)
        {
            var ex = await Assert.ThrowsAsync<SigningRefusedException>(operation);
            Assert.Equal(SigningRefusalReason.SignerLocked, ex.Reason);
        }
        await Locked(() => signer.GenerateKeyAsync(new KeySpec("Ed25519", "", Usage: KeySpec.SshUsage), instance));
        await Locked(() => signer.CommitKeyAsync(sshRef, Guid.NewGuid(), instance));
        await Locked(() => signer.RetireKeyAsync(sshRef, instance));
        await Locked(() => signer.ImportKeyAsync(new KeyMaterial(pkcs8, KeyMaterial.Pkcs8, Guid.NewGuid(), KeyRef.SshKeystore),
            instance with { Purpose = SigningPurpose.SshKeyMigration }));
        await Locked(() => signer.ExportKeyAsync(sshRef, new ExportWrap(ExportWrap.Pkcs12, "pw"), instance with { Purpose = SigningPurpose.Export }));
        Assert.Empty(await signer.ListKeysAsync(instance));
        Assert.Empty(world.Persistence.SshAppended);
    }

    [Fact]
    public async Task An_ssh_commit_that_cannot_persist_propagates_and_leaves_the_key_pending()
    {
        var world = SignerTestWorld.Create();
        var signer = Create(world, unlocked: true);
        var instance = new SigningContext("contract-test", SigningPurpose.Ceremony, null, null) { InstanceScope = true };
        var caId = Guid.NewGuid();
        var keyId = Guid.NewGuid();
        using (var db = world.OpenDb())
        {
            db.SecurityPolicies.Add(new ModularCA.Shared.Entities.SecurityPolicyEntity { RequireKeyCeremony = false });
            await db.SaveChangesAsync();
        }
        var generated = await signer.GenerateKeyAsync(new KeySpec("Ed25519", "", Usage: KeySpec.SshUsage), instance);
        using (var db = world.OpenDb())
        {
            db.CertificateAuthorities.Add(new ModularCA.Shared.Entities.CertificateAuthorityEntity
            {
                Id = caId, Name = "ssh-unwritable", Label = "ssh-unwritable", Type = "SSH", IsSshCa = true, SpaceId = null,
            });
            db.SshCaKeys.Add(new ModularCA.Shared.Entities.SshCaKeyEntity
            {
                Id = keyId, Name = "ssh-unwritable", CertificateAuthorityId = caId,
                PublicKey = ModularCA.Ssh.SshPublicKey.FromKeyParameter(PublicKeyFactory.CreateKey(generated.PublicKeyDer)).ToAuthorizedKey(),
            });
            await db.SaveChangesAsync();
        }
        var forCa = instance with { CaId = caId };
        world.Persistence.FailWith = new IOException("keystore file locked");

        await Assert.ThrowsAsync<IOException>(() => signer.CommitKeyAsync(generated.Key, keyId, forCa));

        // Not written and not bound; still pending, so it commits once the file can be written.
        Assert.Empty(world.Persistence.SshAppended);
        Assert.DoesNotContain(await signer.ListKeysAsync(forCa), k => k.Kind == KeyKind.SshCa);
        world.Persistence.FailWith = null;
        await signer.CommitKeyAsync(generated.Key, keyId, forCa);
        Assert.Single(world.Persistence.SshAppended);
        Assert.Contains(await signer.ListKeysAsync(forCa), k => k.Kind == KeyKind.SshCa && k.Key.CertificateId == keyId);
    }

    /// <summary>A user certificate for one principal, valid for an hour from now, that every rule allows.</summary>
    private static SshCertificateRequest SshRequest(KeyRef key)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var subject = ModularCA.Ssh.SshPublicKey.FromKeyParameter(ModularCA.Shared.Utils.KeyAlgorithmPolicy.GenerateKeyPair("Ed25519", "").Public).Blob;
        return new SshCertificateRequest(key, subject, SshCertificateRequest.UserType, 1, "in-process", new[] { "alice-principal" }, now, now + 3600);
    }

    private static SigningContext SshSigning(Guid caId)
        => new("contract-test", SigningPurpose.SshCertificate, null, caId) { InstanceScope = true };

    [Fact]
    public async Task A_locked_signer_signs_no_ssh_certificate()
    {
        var world = SignerTestWorld.Create();
        var (caId, key, _) = world.SeedBoundSshKey();
        var signer = Create(world, unlocked: false);

        var ex = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.SignSshCertificateAsync(SshRequest(key), SshSigning(caId)));

        Assert.Equal(SigningRefusalReason.SignerLocked, ex.Reason);
        var row = Assert.Single(await ReadAuditAsync(world));
        Assert.Equal("SignSsh", row.Operation);
        Assert.Equal("refused", row.Outcome);
        Assert.Equal(KeyRef.SshKeystore, row.Keystore);
        Assert.NotNull(row.Summary);
        Assert.Null(row.DataHash);
    }

    /// <summary>
    /// The wire has no null, so a member of the request left null is read as empty here too, and
    /// the two bindings refuse and allow the same requests. Only the request itself, its key
    /// reference and the context have to be there.
    /// </summary>
    [Fact]
    public async Task A_member_of_an_ssh_certificate_request_left_null_is_read_as_empty()
    {
        var world = SignerTestWorld.Create();
        var (caId, key, publicKey) = world.SeedBoundSshKey();
        var signer = Create(world, unlocked: true);
        var context = SshSigning(caId);
        var request = SshRequest(key);

        await Assert.ThrowsAsync<ArgumentNullException>(() => signer.SignSshCertificateAsync(null!, context));
        await Assert.ThrowsAsync<ArgumentNullException>(() => signer.SignSshCertificateAsync(request, null!));
        await Assert.ThrowsAsync<ArgumentException>(() => signer.SignSshCertificateAsync(request with { Key = null! }, context));
        Assert.Empty(await ReadAuditAsync(world));

        foreach (var missing in new[] { request with { SubjectPublicKey = null! }, request with { CertType = null! }, request with { Principals = null! }, request with { Principals = new string[] { null! } } })
        {
            var ex = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.SignSshCertificateAsync(missing, context));
            Assert.Equal(SigningRefusalReason.UntypedData, ex.Reason);
        }

        var bare = request with { KeyId = null!, CriticalOptions = null, Extensions = new SshCertificateOption[] { new("permit-pty", null!) } };
        var certificate = ModularCA.Ssh.SshCertificate.Parse(await signer.SignSshCertificateAsync(bare, context));
        Assert.True(certificate.VerifySignature());
        Assert.Equal(publicKey, certificate.SignatureKey);
        Assert.Equal(string.Empty, certificate.Fields.KeyId);
        Assert.Empty(certificate.Fields.CriticalOptions);
        Assert.Equal("permit-pty", Assert.Single(certificate.Fields.Extensions).Name);

        var rows = await ReadAuditAsync(world);
        Assert.Equal(5, rows.Count);
        Assert.All(rows, r => Assert.NotNull(r.Summary));
    }

    /// <summary>
    /// A .NET string can hold half of a surrogate pair, which is not text and has no place in a
    /// certificate. In process, where no wire has already replaced it, the signer refuses it and
    /// still writes a summary that is valid JSON.
    /// </summary>
    [Fact]
    public async Task Text_that_cannot_be_encoded_is_refused_and_still_summarised()
    {
        var world = SignerTestWorld.Create();
        var (caId, key, _) = world.SeedBoundSshKey();
        var signer = Create(world, unlocked: true);
        var request = SshRequest(key);

        foreach (var unencodable in new[] { request with { KeyId = "kid\uD83D" }, request with { Principals = new[] { "alice-principal\uDE00" } } })
        {
            var ex = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.SignSshCertificateAsync(unencodable, SshSigning(caId)));
            Assert.Equal(SigningRefusalReason.UntypedData, ex.Reason);
            Assert.Contains("cannot be encoded", ex.Message);
        }

        var rows = await ReadAuditAsync(world);
        Assert.Equal(2, rows.Count);
        Assert.All(rows, r => Assert.Equal("refused", r.Outcome));
        using var summary = System.Text.Json.JsonDocument.Parse(rows.Single(r => r.Summary!.Contains("FFFD")).Summary!);
        Assert.Equal("kid�", summary.RootElement.GetProperty("key_id").GetString());
    }

    /// <summary>An audit sink whose database is gone: it counts what it was asked to record and records none of it.</summary>
    private sealed class UnwritableAuditSink : ISignerAuditSink
    {
        public List<SignerDecision> Asked { get; } = new();

        public Task RecordAsync(SignerDecision decision, CancellationToken cancellationToken = default)
        {
            Asked.Add(decision);
            throw new InvalidOperationException("The signer audit table cannot be written.");
        }
    }

    /// <summary>
    /// The signer role fails closed on its audit. An SSH certificate is recorded before it is
    /// returned, so one that cannot be recorded is not handed out, although it was signed.
    /// </summary>
    [Fact]
    public async Task An_ssh_certificate_the_signer_role_cannot_record_is_not_handed_out()
    {
        var world = SignerTestWorld.Create();
        var (caId, key, _) = world.SeedBoundSshKey();
        var audit = new UnwritableAuditSink();
        var signer = new InProcessSigningService(world.Keystore, world.Scopes, audit, world.Persistence,
            NullLogger<InProcessSigningService>.Instance, unlocked: true, failClosedOnAuditFailure: true);

        var ex = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.SignSshCertificateAsync(SshRequest(key), SshSigning(caId)));

        Assert.Equal(SigningRefusalReason.AuditUnavailable, ex.Reason);
        var asked = Assert.Single(audit.Asked);
        Assert.Equal("SignSsh", asked.Operation);
        Assert.True(asked.Allowed);
        Assert.NotNull(asked.DataHash);
        Assert.NotNull(asked.Summary);
    }

    [Fact]
    public async Task The_signature_factory_lets_a_generator_sign_a_certificate_the_ca_key_verifies()
    {
        var world = SignerTestWorld.Create();
        var signer = Create(world, unlocked: true);
        var ca = world["ca-ec"];
        var subject = world["leaf"];

        var gen = new X509V3CertificateGenerator();
        gen.SetSerialNumber(BigInteger.ValueOf(99));
        gen.SetIssuerDN(ca.Certificate.SubjectDN);
        gen.SetSubjectDN(new X509Name("CN=through-the-signer"));
        gen.SetNotBefore(DateTime.UtcNow.AddMinutes(-1));
        gen.SetNotAfter(DateTime.UtcNow.AddDays(1));
        gen.SetPublicKey(subject.PublicKey);
        var factory = new SigningServiceSignatureFactory(signer, ca.Ref, SignatureAlgorithm.ForPublicKey(ca.PublicKey),
            new SigningContext("contract-test", SigningPurpose.Certificate, world.SpaceB, world.CaEcId));

        var cert = gen.Generate(factory);

        cert.Verify(ca.PublicKey);
        Assert.Equal("SHA256WITHECDSA", cert.SigAlgName.ToUpperInvariant().Replace("-", ""));
        var row = Assert.Single(await ReadAuditAsync(world));
        Assert.Equal("allowed", row.Outcome);
        Assert.Equal(ca.Ref.CertificateId, row.KeyCertificateId);
    }

    [Fact]
    public void The_signature_factory_refuses_through_the_generator_when_policy_does()
    {
        var world = SignerTestWorld.Create();
        var signer = Create(world, unlocked: true);
        var ca = world["ca-rsa"];

        var gen = new X509V3CertificateGenerator();
        gen.SetSerialNumber(BigInteger.ValueOf(100));
        gen.SetIssuerDN(ca.Certificate.SubjectDN);
        gen.SetSubjectDN(new X509Name("CN=wrong-ca"));
        gen.SetNotBefore(DateTime.UtcNow.AddMinutes(-1));
        gen.SetNotAfter(DateTime.UtcNow.AddDays(1));
        gen.SetPublicKey(world["leaf"].PublicKey);
        var factory = new SigningServiceSignatureFactory(signer, ca.Ref, SignatureAlgorithm.ForPublicKey(ca.PublicKey),
            new SigningContext("contract-test", SigningPurpose.Certificate, world.SpaceB, world.CaEcId));

        var ex = Assert.Throws<SigningRefusedException>(() => gen.Generate(factory));
        Assert.Equal(SigningRefusalReason.CaMismatch, ex.Reason);
    }
}
