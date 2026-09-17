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
    internal override ISigningService CreateSigner(SignerTestWorld world) => Create(world, unlocked: true);

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
                new SigningContext("contract-test", SigningPurpose.Certificate, world.TenantA, world.CaRsaId)));
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
        var ceremony = new SigningContext("contract-test", SigningPurpose.Ceremony, world.TenantA, null);

        async Task Locked(Func<Task> operation)
        {
            var ex = await Assert.ThrowsAsync<SigningRefusedException>(operation);
            Assert.Equal(SigningRefusalReason.SignerLocked, ex.Reason);
        }
        await Locked(() => signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), ceremony));
        await Locked(() => signer.ImportKeyAsync(new KeyMaterial((byte[])world["keyless"].PrivateKeyPkcs8.Clone(), KeyMaterial.Pkcs8, world["keyless"].Ref.CertificateId), ceremony));
        await Locked(() => signer.CommitKeyAsync(new KeyRef(Guid.NewGuid()), world["leaf"].Ref.CertificateId, ceremony));
        await Locked(() => signer.RetireKeyAsync(new KeyRef(Guid.NewGuid()), ceremony));
        await Locked(() => signer.DecryptAsync(world["ca-rsa"].Ref, new byte[] { 1 }, new SigningContext("contract-test", SigningPurpose.Scep, world.TenantA, world.CaRsaId)));
        Assert.Empty(world.Persistence.Appended);
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
        var signer = CreateSigner(world);
        var ceremony = new SigningContext("contract-test", SigningPurpose.Ceremony, world.TenantA, null);
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
    public async Task The_signature_factory_lets_a_generator_sign_a_certificate_the_ca_key_verifies()
    {
        var world = SignerTestWorld.Create();
        var signer = CreateSigner(world);
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
            new SigningContext("contract-test", SigningPurpose.Certificate, world.TenantB, world.CaEcId));

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
        var signer = CreateSigner(world);
        var ca = world["ca-rsa"];

        var gen = new X509V3CertificateGenerator();
        gen.SetSerialNumber(BigInteger.ValueOf(100));
        gen.SetIssuerDN(ca.Certificate.SubjectDN);
        gen.SetSubjectDN(new X509Name("CN=wrong-ca"));
        gen.SetNotBefore(DateTime.UtcNow.AddMinutes(-1));
        gen.SetNotAfter(DateTime.UtcNow.AddDays(1));
        gen.SetPublicKey(world["leaf"].PublicKey);
        var factory = new SigningServiceSignatureFactory(signer, ca.Ref, SignatureAlgorithm.ForPublicKey(ca.PublicKey),
            new SigningContext("contract-test", SigningPurpose.Certificate, world.TenantB, world.CaEcId));

        var ex = Assert.Throws<SigningRefusedException>(() => gen.Generate(factory));
        Assert.Equal(SigningRefusalReason.CaMismatch, ex.Reason);
    }
}
