using System.Security.Cryptography;
using System.Text;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Signing;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Xunit;

namespace ModularCA.Tests.Signer;

/// <summary>
/// The contract every <see cref="ISigningService"/> implementation has to keep: the policy
/// table row by row, the audit row every decision leaves, the health report, and signatures
/// that verify under the key's public half. Written against the interface so the remote
/// implementation runs the same suite by binding <see cref="CreateSigner"/> to itself.
/// </summary>
public abstract class SigningServiceContractTests
{
    private const string Caller = "contract-test";

    /// <summary>
    /// One world per implementation for the tests that only read from it: building eight keys
    /// per test would make the policy table the slowest thing in the suite. Tests that assert on
    /// audit rows create their own world so the rows they count are theirs.
    /// </summary>
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<Type, SignerTestWorld> SharedWorlds = new();

    private SignerTestWorld SharedWorld => SharedWorlds.GetOrAdd(GetType(), _ => SignerTestWorld.Create());

    /// <summary>Binds the suite to an implementation over the world's keys and database.</summary>
    internal abstract ISigningService CreateSigner(SignerTestWorld world);

    /// <summary>Reads the signer's audit rows for the world, oldest first.</summary>
    internal virtual Task<IReadOnlyList<SignerAuditEntity>> ReadAuditAsync(SignerTestWorld world)
    {
        using var db = world.OpenDb();
        IReadOnlyList<SignerAuditEntity> rows = db.SignerAudit.OrderBy(r => r.At).ToList();
        return Task.FromResult(rows);
    }

    /// <summary>The backend the implementation under test reports.</summary>
    protected abstract string ExpectedBackend { get; }

    /// <summary>
    /// Asserts that a committed or imported key's certificate reached the implementation's
    /// durable store. The contract cannot see the store, so the in-process binding overrides
    /// this over its persistence; a remote binding will assert through its own signer.
    /// </summary>
    internal virtual void AssertPersisted(SignerTestWorld world, byte[] certificateDer) { }

    private static readonly byte[] Tbs = Encoding.ASCII.GetBytes("to-be-signed bytes for the signer contract");

    private static SigningContext Context(SigningPurpose purpose, Guid? caId, Guid? tenantId) => new(Caller, purpose, tenantId, caId);

    private static SigningContext ContextFor(SignerTestWorld world, string key, SigningPurpose purpose)
        => Context(purpose, world[key].CaId, world[key].TenantId);

    private static SignatureAlgorithm AlgorithmFor(SignerTestWorld world, string key)
        => SignatureAlgorithm.ForPublicKey(world[key].PublicKey);

    /// <summary>
    /// The policy table, one row per (key kind, purpose, which CA the context names). <c>own</c>
    /// names the CA that owns the key, <c>other</c> the other CA, <c>none</c> no CA at all.
    /// </summary>
    public static IEnumerable<object[]> PolicyRows()
    {
        // A CA key signs certificates, CRLs, OCSP, SCEP and CMP for its own CA.
        foreach (var p in new[] { SigningPurpose.Certificate, SigningPurpose.Crl, SigningPurpose.Ocsp, SigningPurpose.Scep, SigningPurpose.Cmp })
        {
            yield return new object[] { "ca-rsa", p, "own", null! };
            yield return new object[] { "ca-ec", p, "own", null! };
            yield return new object[] { "ca-rsa", p, "other", SigningRefusalReason.CaMismatch };
            yield return new object[] { "ca-rsa", p, "none", SigningRefusalReason.ContextRequired };
        }
        // ... and nothing else.
        foreach (var p in new[] { SigningPurpose.Tsa, SigningPurpose.Ceremony, SigningPurpose.Backup, SigningPurpose.Export, SigningPurpose.Bootstrap })
            yield return new object[] { "ca-rsa", p, "own", SigningRefusalReason.PurposeNotPermitted };

        // A delegated OCSP responder key signs OCSP responses for its own CA, and nothing else.
        yield return new object[] { "ocsp", SigningPurpose.Ocsp, "own", null! };
        yield return new object[] { "ocsp", SigningPurpose.Ocsp, "other", SigningRefusalReason.CaMismatch };
        yield return new object[] { "ocsp", SigningPurpose.Ocsp, "none", SigningRefusalReason.ContextRequired };
        foreach (var p in Enum.GetValues<SigningPurpose>().Where(p => p != SigningPurpose.Ocsp))
            yield return new object[] { "ocsp", p, "own", SigningRefusalReason.PurposeNotPermitted };

        // The TSA key signs timestamp tokens for its own CA, and nothing else.
        yield return new object[] { "tsa", SigningPurpose.Tsa, "own", null! };
        yield return new object[] { "tsa", SigningPurpose.Tsa, "other", SigningRefusalReason.CaMismatch };
        foreach (var p in Enum.GetValues<SigningPurpose>().Where(p => p != SigningPurpose.Tsa))
            yield return new object[] { "tsa", p, "own", SigningRefusalReason.PurposeNotPermitted };

        // The CMP protection key signs CMP responses for its own CA, and nothing else.
        yield return new object[] { "cmp", SigningPurpose.Cmp, "own", null! };
        yield return new object[] { "cmp", SigningPurpose.Cmp, "other", SigningRefusalReason.CaMismatch };
        foreach (var p in Enum.GetValues<SigningPurpose>().Where(p => p != SigningPurpose.Cmp))
            yield return new object[] { "cmp", p, "own", SigningRefusalReason.PurposeNotPermitted };

        // An end-entity key signs nothing, whatever CA the context names.
        foreach (var p in Enum.GetValues<SigningPurpose>())
            yield return new object[] { "leaf", p, "rsa", SigningRefusalReason.PurposeNotPermitted };

        // A CA certificate no CertificateAuthorities row names has no kind, so no row applies.
        yield return new object[] { "orphan", SigningPurpose.Certificate, "rsa", SigningRefusalReason.UnknownKeyKind };
        yield return new object[] { "orphan", SigningPurpose.Crl, "rsa", SigningRefusalReason.UnknownKeyKind };

        // A CA with a row but no key in the signer cannot sign.
        yield return new object[] { "keyless", SigningPurpose.Certificate, "own", SigningRefusalReason.UnknownKey };
    }

    [Theory]
    [MemberData(nameof(PolicyRows))]
    public async Task Policy_row(string key, SigningPurpose purpose, string ca, SigningRefusalReason? expectedRefusal)
    {
        var world = SharedWorld;
        var signer = CreateSigner(world);
        var k = world[key];
        var (caId, tenantId) = ResolveCa(world, k, ca);
        var context = Context(purpose, caId, tenantId);

        if (expectedRefusal == null)
        {
            var signature = await signer.SignAsync(k.Ref, AlgorithmFor(world, key), Tbs, context);
            Assert.True(Verify(world, key, signature), $"{key} signed for {purpose} but the signature does not verify");
        }
        else
        {
            var ex = await Assert.ThrowsAsync<SigningRefusedException>(
                () => signer.SignAsync(k.Ref, AlgorithmFor(world, key), Tbs, context));
            Assert.Equal(expectedRefusal, ex.Reason);
        }
    }

    [Fact]
    public async Task A_key_is_refused_for_a_tenant_that_does_not_own_its_ca()
    {
        var world = SharedWorld;
        var signer = CreateSigner(world);

        var ex = await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.SignAsync(world["ca-rsa"].Ref, AlgorithmFor(world, "ca-rsa"), Tbs,
                Context(SigningPurpose.Certificate, world.CaRsaId, world.TenantB)));

        Assert.Equal(SigningRefusalReason.TenantMismatch, ex.Reason);
    }

    [Fact]
    public async Task A_context_that_names_no_tenant_is_held_to_the_ca_alone()
    {
        var world = SharedWorld;
        var signer = CreateSigner(world);

        var signature = await signer.SignAsync(world["ca-rsa"].Ref, AlgorithmFor(world, "ca-rsa"), Tbs,
            Context(SigningPurpose.Crl, world.CaRsaId, tenantId: null));

        Assert.True(Verify(world, "ca-rsa", signature));
    }

    [Fact]
    public async Task A_certificate_the_signer_has_never_heard_of_is_refused()
    {
        var world = SharedWorld;
        var signer = CreateSigner(world);

        var ex = await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.SignAsync(new KeyRef(Guid.NewGuid()), SignatureAlgorithm.FromName("SHA256withRSA"), Tbs,
                Context(SigningPurpose.Certificate, world.CaRsaId, world.TenantA)));

        Assert.Equal(SigningRefusalReason.UnknownKey, ex.Reason);
    }

    [Theory]
    [InlineData("ca-rsa", "SHA256withRSA")]
    [InlineData("ca-ec", "SHA256withECDSA")]
    public async Task A_signature_verifies_under_the_public_key(string key, string algorithm)
    {
        var world = SharedWorld;
        var signer = CreateSigner(world);

        var signature = await signer.SignAsync(world[key].Ref, SignatureAlgorithm.FromName(algorithm), Tbs, ContextFor(world, key, SigningPurpose.Certificate));

        Assert.True(Verify(world, key, signature, algorithm));
        Assert.False(Verify(world, key, signature, algorithm, Encoding.ASCII.GetBytes("different bytes")));
    }

    [Fact]
    public async Task An_allowed_decision_is_audited_with_its_context_and_the_hash_of_what_was_signed()
    {
        var world = SignerTestWorld.Create();
        var signer = CreateSigner(world);
        var before = DateTime.UtcNow.AddSeconds(-1);

        await signer.SignAsync(world["ocsp"].Ref, SignatureAlgorithm.FromName("SHA256withRSA"), Tbs, ContextFor(world, "ocsp", SigningPurpose.Ocsp));

        var row = Assert.Single(await ReadAuditAsync(world));
        Assert.Equal("Sign", row.Operation);
        Assert.Equal(Caller, row.Caller);
        Assert.Equal("Ocsp", row.Purpose);
        Assert.Equal(world["ocsp"].Ref.CertificateId, row.KeyCertificateId);
        Assert.Equal(KeyRef.DefaultKeystore, row.Keystore);
        Assert.Equal(world.CaRsaId, row.CaId);
        Assert.Equal(world.TenantA, row.TenantId);
        Assert.Equal("SHA256withRSA", row.Algorithm);
        Assert.Equal(SignerAuditEntity.AllowedOutcome, row.Outcome);
        Assert.Null(row.Reason);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(Tbs)), row.DataHash);
        Assert.InRange(row.At, before, DateTime.UtcNow.AddSeconds(1));
    }

    [Fact]
    public async Task A_refused_decision_is_audited_with_its_reason()
    {
        var world = SignerTestWorld.Create();
        var signer = CreateSigner(world);

        await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.SignAsync(world["tsa"].Ref, SignatureAlgorithm.FromName("SHA256withRSA"), Tbs, ContextFor(world, "tsa", SigningPurpose.Certificate)));

        var row = Assert.Single(await ReadAuditAsync(world));
        Assert.Equal(SignerAuditEntity.RefusedOutcome, row.Outcome);
        Assert.Equal("Certificate", row.Purpose);
        Assert.Equal(world["tsa"].Ref.CertificateId, row.KeyCertificateId);
        Assert.Equal(world.CaRsaId, row.CaId);
        Assert.NotNull(row.Reason);
        Assert.Contains("Tsa", row.Reason);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(Tbs)), row.DataHash);
    }

    [Fact]
    public async Task An_unknown_key_is_audited_as_refused()
    {
        var world = SignerTestWorld.Create();
        var signer = CreateSigner(world);
        var unknown = new KeyRef(Guid.NewGuid());

        await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.SignAsync(unknown, SignatureAlgorithm.FromName("SHA256withRSA"), Tbs, Context(SigningPurpose.Crl, world.CaRsaId, world.TenantA)));

        var row = Assert.Single(await ReadAuditAsync(world));
        Assert.Equal(SignerAuditEntity.RefusedOutcome, row.Outcome);
        Assert.Equal(unknown.CertificateId, row.KeyCertificateId);
    }

    [Fact]
    public async Task Every_decision_leaves_exactly_one_row()
    {
        var world = SignerTestWorld.Create();
        var signer = CreateSigner(world);

        await signer.SignAsync(world["ca-rsa"].Ref, AlgorithmFor(world, "ca-rsa"), Tbs, ContextFor(world, "ca-rsa", SigningPurpose.Certificate));
        await signer.SignAsync(world["ca-rsa"].Ref, AlgorithmFor(world, "ca-rsa"), Tbs, ContextFor(world, "ca-rsa", SigningPurpose.Crl));
        await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.SignAsync(world["ca-rsa"].Ref, AlgorithmFor(world, "ca-rsa"), Tbs, ContextFor(world, "ca-rsa", SigningPurpose.Tsa)));

        var rows = await ReadAuditAsync(world);
        Assert.Equal(3, rows.Count);
        Assert.Equal(new[] { "allowed", "allowed", "refused" }, rows.Select(r => r.Outcome));
        Assert.Equal(new[] { "Certificate", "Crl", "Tsa" }, rows.Select(r => r.Purpose));
    }

    [Fact]
    public async Task Health_reports_unlocked_the_key_count_and_the_backend()
    {
        var world = SharedWorld;
        var signer = CreateSigner(world);

        var health = await signer.HealthAsync();

        Assert.True(health.Unlocked);
        Assert.Equal(world.HeldKeys.Count(), health.KeyCount);
        Assert.Equal(ExpectedBackend, health.Backend);
    }

    [Fact]
    public async Task Listing_keys_for_a_ca_names_its_own_keys_with_their_kinds()
    {
        var world = SharedWorld;
        var signer = CreateSigner(world);

        var keys = await signer.ListKeysAsync(Context(SigningPurpose.Ocsp, world.CaRsaId, world.TenantA));

        var byId = keys.ToDictionary(k => k.Key.CertificateId);
        Assert.Equal(4, byId.Count);
        Assert.Equal(KeyKind.Ca, byId[world["ca-rsa"].Ref.CertificateId].Kind);
        Assert.Equal(KeyKind.OcspResponder, byId[world["ocsp"].Ref.CertificateId].Kind);
        Assert.Equal(KeyKind.Tsa, byId[world["tsa"].Ref.CertificateId].Kind);
        Assert.Equal(KeyKind.CmpSigner, byId[world["cmp"].Ref.CertificateId].Kind);
        Assert.All(keys, k =>
        {
            Assert.Equal(world.CaRsaId, k.CaId);
            Assert.Equal(world.TenantA, k.TenantId);
            Assert.Equal(ExpectedBackend, k.Backend);
        });
        var caPublic = PublicKeyFactory.CreateKey(byId[world["ca-rsa"].Ref.CertificateId].PublicKeyDer);
        Assert.Equal(world["ca-rsa"].PublicKey, caPublic);
    }

    [Fact]
    public async Task Listing_keys_without_a_ca_names_every_owned_key_the_signer_holds()
    {
        var world = SharedWorld;
        var signer = CreateSigner(world);

        var keys = await signer.ListKeysAsync(Context(SigningPurpose.Ceremony, caId: null, tenantId: null));

        var ids = keys.Select(k => k.Key.CertificateId).ToHashSet();
        Assert.Equal(5, ids.Count);
        Assert.Contains(world["ca-ec"].Ref.CertificateId, ids);
        Assert.DoesNotContain(world["keyless"].Ref.CertificateId, ids);
        Assert.DoesNotContain(world["leaf"].Ref.CertificateId, ids);
        Assert.DoesNotContain(world["orphan"].Ref.CertificateId, ids);
    }

    /// <summary>
    /// The CA a policy row names: <c>own</c> is the CA that owns the key, <c>other</c> the other
    /// CA, <c>rsa</c> the RSA CA whatever the key, <c>none</c> no CA at all; the tenant follows
    /// the CA.
    /// </summary>
    private static (Guid? CaId, Guid? TenantId) ResolveCa(SignerTestWorld world, SignerTestKey k, string ca)
    {
        Guid? caId = ca switch
        {
            "own" => k.CaId,
            "other" => k.CaId == world.CaRsaId ? world.CaEcId : world.CaRsaId,
            "rsa" => world.CaRsaId,
            _ => null,
        };
        Guid? tenantId = caId == world.CaRsaId ? world.TenantA : caId == world.CaEcId ? world.TenantB : null;
        return (caId, tenantId);
    }

    // ------------------------------------------------------------------ Decrypt

    private static readonly byte[] Secret = Encoding.ASCII.GetBytes("the enveloped content for the signer contract");

    /// <summary>Builds a CMS EnvelopedData addressed to <paramref name="cert"/>, as a SCEP client does.</summary>
    private static byte[] EnvelopeTo(X509Certificate cert, byte[] content)
    {
        var gen = new CmsEnvelopedDataGenerator();
        gen.AddKeyTransRecipient(cert);
        return gen.Generate(new CmsProcessableByteArray(content), NistObjectIdentifiers.IdAes256Cbc.Id).GetEncoded();
    }

    /// <summary>
    /// The decryption policy table: a CA key opens SCEP envelopes for its own CA, and no other
    /// key opens anything under any purpose. The envelope is always addressed to the RSA CA;
    /// a refused row never gets as far as opening it.
    /// </summary>
    public static IEnumerable<object[]> DecryptPolicyRows()
    {
        yield return new object[] { "ca-rsa", SigningPurpose.Scep, "own", null! };
        yield return new object[] { "ca-rsa", SigningPurpose.Scep, "other", SigningRefusalReason.CaMismatch };
        yield return new object[] { "ca-rsa", SigningPurpose.Scep, "none", SigningRefusalReason.ContextRequired };
        foreach (var p in Enum.GetValues<SigningPurpose>().Where(p => p != SigningPurpose.Scep))
            yield return new object[] { "ca-rsa", p, "own", SigningRefusalReason.PurposeNotPermitted };
        foreach (var k in new[] { "ocsp", "tsa", "cmp" })
            yield return new object[] { k, SigningPurpose.Scep, "own", SigningRefusalReason.PurposeNotPermitted };
        yield return new object[] { "leaf", SigningPurpose.Scep, "rsa", SigningRefusalReason.PurposeNotPermitted };
        yield return new object[] { "orphan", SigningPurpose.Scep, "rsa", SigningRefusalReason.UnknownKeyKind };
        yield return new object[] { "keyless", SigningPurpose.Scep, "own", SigningRefusalReason.UnknownKey };
    }

    [Theory]
    [MemberData(nameof(DecryptPolicyRows))]
    public async Task Decrypt_policy_row(string key, SigningPurpose purpose, string ca, SigningRefusalReason? expectedRefusal)
    {
        var world = SharedWorld;
        var signer = CreateSigner(world);
        var k = world[key];
        var (caId, tenantId) = ResolveCa(world, k, ca);
        var context = Context(purpose, caId, tenantId);
        var enveloped = EnvelopeTo(world["ca-rsa"].Certificate, Secret);

        if (expectedRefusal == null)
        {
            var content = await signer.DecryptAsync(k.Ref, enveloped, context);
            Assert.Equal(Secret, content);
        }
        else
        {
            var ex = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.DecryptAsync(k.Ref, enveloped, context));
            Assert.Equal(expectedRefusal, ex.Reason);
        }
    }

    [Fact]
    public async Task An_allowed_decryption_is_audited_with_the_hash_of_the_envelope()
    {
        var world = SignerTestWorld.Create();
        var signer = CreateSigner(world);
        var enveloped = EnvelopeTo(world["ca-rsa"].Certificate, Secret);

        await signer.DecryptAsync(world["ca-rsa"].Ref, enveloped, ContextFor(world, "ca-rsa", SigningPurpose.Scep));

        var row = Assert.Single(await ReadAuditAsync(world));
        Assert.Equal("Decrypt", row.Operation);
        Assert.Equal("Scep", row.Purpose);
        Assert.Equal(SignerAuditEntity.AllowedOutcome, row.Outcome);
        Assert.Equal(world["ca-rsa"].Ref.CertificateId, row.KeyCertificateId);
        Assert.Equal(world.CaRsaId, row.CaId);
        Assert.Null(row.Algorithm);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(enveloped)), row.DataHash);
    }

    [Fact]
    public async Task A_refused_decryption_is_audited_with_its_reason()
    {
        var world = SignerTestWorld.Create();
        var signer = CreateSigner(world);
        var enveloped = EnvelopeTo(world["ca-rsa"].Certificate, Secret);

        await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.DecryptAsync(world["ocsp"].Ref, enveloped, ContextFor(world, "ocsp", SigningPurpose.Scep)));

        var row = Assert.Single(await ReadAuditAsync(world));
        Assert.Equal("Decrypt", row.Operation);
        Assert.Equal(SignerAuditEntity.RefusedOutcome, row.Outcome);
        Assert.Contains("OcspResponder", row.Reason);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(enveloped)), row.DataHash);
    }

    [Fact]
    public async Task An_envelope_not_addressed_to_the_key_fails_after_the_decision_was_allowed()
    {
        var world = SignerTestWorld.Create();
        var signer = CreateSigner(world);
        var enveloped = EnvelopeTo(world["keyless"].Certificate, Secret);

        var ex = await Assert.ThrowsAnyAsync<Exception>(
            () => signer.DecryptAsync(world["ca-rsa"].Ref, enveloped, ContextFor(world, "ca-rsa", SigningPurpose.Scep)));

        Assert.IsNotType<SigningRefusedException>(ex);
        var row = Assert.Single(await ReadAuditAsync(world));
        Assert.Equal(SignerAuditEntity.AllowedOutcome, row.Outcome);
    }

    // ------------------------------------------------------------------ GenerateKey

    /// <summary>Key management happens under a ceremony or bootstrap context, and under nothing else.</summary>
    public static IEnumerable<object[]> KeyManagementPurposeRows()
    {
        foreach (var p in Enum.GetValues<SigningPurpose>())
            yield return new object[] { p, p is SigningPurpose.Ceremony or SigningPurpose.Bootstrap };
    }

    [Theory]
    [MemberData(nameof(KeyManagementPurposeRows))]
    public async Task Generate_key_policy_row(SigningPurpose purpose, bool allowed)
    {
        var world = SharedWorld;
        var signer = CreateSigner(world);
        var context = Context(purpose, null, world.TenantA);

        if (allowed)
        {
            var generated = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), context);
            Assert.NotEqual(Guid.Empty, generated.Key.CertificateId);
            Assert.Equal(KeyRef.DefaultKeystore, generated.Key.Keystore);
            Assert.IsType<ECPublicKeyParameters>(PublicKeyFactory.CreateKey(generated.PublicKeyDer));
        }
        else
        {
            var ex = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), context));
            Assert.Equal(SigningRefusalReason.PurposeNotPermitted, ex.Reason);
        }
    }

    [Fact]
    public async Task A_generated_key_signs_under_the_context_that_generated_it_and_nowhere_else()
    {
        var world = SharedWorld;
        var signer = CreateSigner(world);
        var ceremony = Context(SigningPurpose.Ceremony, world.CaRsaId, world.TenantA);
        var generated = await signer.GenerateKeyAsync(new KeySpec("RSA", "2048"), ceremony);
        var publicKey = PublicKeyFactory.CreateKey(generated.PublicKeyDer);
        var algorithm = SignatureAlgorithm.ForPublicKey(publicKey);

        var signature = await signer.SignAsync(generated.Key, algorithm, Tbs, ceremony);
        Assert.True(VerifyWith(publicKey, algorithm.Name, signature));

        // Nothing named at all is held to nothing.
        Assert.True(VerifyWith(publicKey, algorithm.Name,
            await signer.SignAsync(generated.Key, algorithm, Tbs, Context(SigningPurpose.Ceremony, null, null))));

        async Task Refused(SigningContext context, SigningRefusalReason reason)
        {
            var ex = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.SignAsync(generated.Key, algorithm, Tbs, context));
            Assert.Equal(reason, ex.Reason);
        }
        await Refused(Context(SigningPurpose.Certificate, world.CaRsaId, world.TenantA), SigningRefusalReason.PurposeNotPermitted);
        await Refused(Context(SigningPurpose.Crl, world.CaRsaId, world.TenantA), SigningRefusalReason.PurposeNotPermitted);
        await Refused(Context(SigningPurpose.Bootstrap, world.CaRsaId, world.TenantA), SigningRefusalReason.PurposeNotPermitted);
        await Refused(Context(SigningPurpose.Ceremony, world.CaRsaId, world.TenantB), SigningRefusalReason.TenantMismatch);
        await Refused(Context(SigningPurpose.Ceremony, world.CaEcId, world.TenantA), SigningRefusalReason.CaMismatch);

        var decrypt = await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.DecryptAsync(generated.Key, EnvelopeTo(world["ca-rsa"].Certificate, Secret), ceremony));
        Assert.Equal(SigningRefusalReason.PurposeNotPermitted, decrypt.Reason);
    }

    [Fact]
    public async Task Key_generation_is_audited_with_the_reference_and_the_hash_of_the_public_key()
    {
        var world = SignerTestWorld.Create();
        var signer = CreateSigner(world);

        var generated = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), Context(SigningPurpose.Bootstrap, null, world.TenantA));
        await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), Context(SigningPurpose.Certificate, world.CaRsaId, world.TenantA)));

        var rows = await ReadAuditAsync(world);
        Assert.Equal(2, rows.Count);
        Assert.Equal("GenerateKey", rows[0].Operation);
        Assert.Equal(SignerAuditEntity.AllowedOutcome, rows[0].Outcome);
        Assert.Equal("Bootstrap", rows[0].Purpose);
        Assert.Equal(generated.Key.CertificateId, rows[0].KeyCertificateId);
        Assert.Equal(world.TenantA, rows[0].TenantId);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(generated.PublicKeyDer)), rows[0].DataHash);
        Assert.Equal("GenerateKey", rows[1].Operation);
        Assert.Equal(SignerAuditEntity.RefusedOutcome, rows[1].Outcome);
        Assert.Null(rows[1].KeyCertificateId);
        Assert.Contains("Certificate", rows[1].Reason);
    }

    [Fact]
    public async Task A_key_spec_the_signer_cannot_honour_is_refused_as_unsupported()
    {
        var world = SharedWorld;
        var signer = CreateSigner(world);
        var ceremony = Context(SigningPurpose.Ceremony, null, world.TenantA);

        var labelled = await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.GenerateKeyAsync(new KeySpec("RSA", "2048", Label: "hsm-object"), ceremony));
        Assert.Equal(SigningRefusalReason.OperationUnsupported, labelled.Reason);

        var tooSmall = await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.GenerateKeyAsync(new KeySpec("RSA", "1024"), ceremony));
        Assert.Equal(SigningRefusalReason.OperationUnsupported, tooSmall.Reason);
    }

    // ------------------------------------------------------------------ CommitKey

    /// <summary>
    /// Self-signs a CA certificate over a generated key through the contract, and seeds the
    /// rows that make it a CA in tenant A. Returns the certificate row id and the CA id.
    /// </summary>
    private async Task<(X509Certificate Certificate, Guid CertificateId, Guid CaId)> SeedGeneratedCaAsync(
        SignerTestWorld world, ISigningService signer, GeneratedKey generated, SigningContext ceremony)
    {
        var publicKey = PublicKeyFactory.CreateKey(generated.PublicKeyDer);
        var subject = new X509Name("CN=Generated Through The Signer, O=ModularCA");
        var gen = new X509V3CertificateGenerator();
        gen.SetSerialNumber(BigInteger.ValueOf(DateTime.UtcNow.Ticks));
        gen.SetIssuerDN(subject);
        gen.SetSubjectDN(subject);
        gen.SetNotBefore(DateTime.UtcNow.AddMinutes(-1));
        gen.SetNotAfter(DateTime.UtcNow.AddDays(1));
        gen.SetPublicKey(publicKey);
        gen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
        var cert = gen.Generate(new SigningServiceSignatureFactory(signer, generated.Key, SignatureAlgorithm.ForPublicKey(publicKey), ceremony));
        cert.Verify(publicKey);

        var certificateId = Guid.NewGuid();
        var caId = Guid.NewGuid();
        using (var db = world.OpenDb())
        {
            db.Certificates.Add(new CertificateEntity
            {
                CertificateId = certificateId,
                SerialNumber = cert.SerialNumber.ToString(16).ToUpperInvariant(),
                SubjectDN = cert.SubjectDN.ToString(),
                Issuer = cert.IssuerDN.ToString(),
                IsCA = true,
                RawCertificate = cert.GetEncoded(),
                Pem = "-----BEGIN CERTIFICATE-----\n" + Convert.ToBase64String(cert.GetEncoded()) + "\n-----END CERTIFICATE-----\n",
                NotBefore = cert.NotBefore,
                NotAfter = cert.NotAfter,
            });
            db.CertificateAuthorities.Add(new CertificateAuthorityEntity
            {
                Id = caId, Name = "generated", Label = "generated", TenantId = world.TenantA, CertificateId = certificateId,
            });
            await db.SaveChangesAsync();
        }
        return (cert, certificateId, caId);
    }

    [Fact]
    public async Task A_generated_key_committed_to_its_certificate_serves_the_policy_for_its_kind()
    {
        var world = SignerTestWorld.Create();
        var signer = CreateSigner(world);
        var ceremony = Context(SigningPurpose.Ceremony, null, world.TenantA);
        var generated = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), ceremony);
        var publicKey = PublicKeyFactory.CreateKey(generated.PublicKeyDer);
        var (cert, certificateId, caId) = await SeedGeneratedCaAsync(world, signer, generated, ceremony);

        await signer.CommitKeyAsync(generated.Key, certificateId, ceremony);

        var committed = new KeyRef(certificateId);
        var algorithm = SignatureAlgorithm.ForPublicKey(publicKey);
        var signature = await signer.SignAsync(committed, algorithm, Tbs, Context(SigningPurpose.Certificate, caId, world.TenantA));
        Assert.True(VerifyWith(publicKey, algorithm.Name, signature));
        Assert.True(VerifyWith(publicKey, algorithm.Name,
            await signer.SignAsync(committed, algorithm, Tbs, Context(SigningPurpose.Crl, caId, world.TenantA))));

        var wrongCa = await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.SignAsync(committed, algorithm, Tbs, Context(SigningPurpose.Certificate, world.CaRsaId, world.TenantA)));
        Assert.Equal(SigningRefusalReason.CaMismatch, wrongCa.Reason);

        // The generated reference is spent.
        var spent = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.SignAsync(generated.Key, algorithm, Tbs, ceremony));
        Assert.Equal(SigningRefusalReason.UnknownKey, spent.Reason);

        var listed = Assert.Single(await signer.ListKeysAsync(Context(SigningPurpose.Ocsp, caId, world.TenantA)));
        Assert.Equal(certificateId, listed.Key.CertificateId);
        Assert.Equal(KeyKind.Ca, listed.Kind);
        Assert.Equal(generated.PublicKeyDer, listed.PublicKeyDer);

        var commitRow = Assert.Single(await ReadAuditAsync(world), r => r.Operation == "CommitKey");
        Assert.Equal(SignerAuditEntity.AllowedOutcome, commitRow.Outcome);
        Assert.Equal(certificateId, commitRow.KeyCertificateId);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(generated.PublicKeyDer)), commitRow.DataHash);
        AssertPersisted(world, cert.GetEncoded());
    }

    [Fact]
    public async Task A_commit_is_refused_when_the_certificate_is_missing_or_is_not_the_keys()
    {
        var world = SignerTestWorld.Create();
        var signer = CreateSigner(world);
        var ceremony = Context(SigningPurpose.Ceremony, null, world.TenantA);
        var generated = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), ceremony);
        var (_, certificateId, _) = await SeedGeneratedCaAsync(world, signer, generated, ceremony);

        async Task Refused(KeyRef key, Guid certId, SigningContext context, SigningRefusalReason reason)
        {
            var ex = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.CommitKeyAsync(key, certId, context));
            Assert.Equal(reason, ex.Reason);
        }
        await Refused(generated.Key, Guid.NewGuid(), ceremony, SigningRefusalReason.CertificateMismatch);
        await Refused(generated.Key, world["leaf"].Ref.CertificateId, ceremony, SigningRefusalReason.CertificateMismatch);
        await Refused(new KeyRef(Guid.NewGuid()), certificateId, ceremony, SigningRefusalReason.UnknownKey);
        await Refused(world["ca-rsa"].Ref, certificateId, ceremony, SigningRefusalReason.UnknownKey);
        await Refused(generated.Key, certificateId, Context(SigningPurpose.Certificate, null, world.TenantA), SigningRefusalReason.PurposeNotPermitted);
        await Refused(generated.Key, certificateId, Context(SigningPurpose.Ceremony, null, world.TenantB), SigningRefusalReason.TenantMismatch);

        // A refused commit spends nothing: the key is still pending and still signs.
        var publicKey = PublicKeyFactory.CreateKey(generated.PublicKeyDer);
        var algorithm = SignatureAlgorithm.ForPublicKey(publicKey);
        Assert.True(VerifyWith(publicKey, algorithm.Name, await signer.SignAsync(generated.Key, algorithm, Tbs, ceremony)));

        var refusedCommits = (await ReadAuditAsync(world)).Where(r => r.Operation == "CommitKey").ToList();
        Assert.Equal(6, refusedCommits.Count);
        Assert.All(refusedCommits, r => Assert.Equal(SignerAuditEntity.RefusedOutcome, r.Outcome));
    }

    // ------------------------------------------------------------------ RetireKey

    [Fact]
    public async Task A_retired_key_is_gone_and_a_committed_key_cannot_be_retired()
    {
        var world = SignerTestWorld.Create();
        var signer = CreateSigner(world);
        var ceremony = Context(SigningPurpose.Ceremony, null, world.TenantA);
        var generated = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), ceremony);
        var algorithm = SignatureAlgorithm.ForPublicKey(PublicKeyFactory.CreateKey(generated.PublicKeyDer));

        var wrongPurpose = await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.RetireKeyAsync(generated.Key, Context(SigningPurpose.Certificate, null, world.TenantA)));
        Assert.Equal(SigningRefusalReason.PurposeNotPermitted, wrongPurpose.Reason);

        var otherTenant = await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.RetireKeyAsync(generated.Key, Context(SigningPurpose.Ceremony, null, world.TenantB)));
        Assert.Equal(SigningRefusalReason.TenantMismatch, otherTenant.Reason);

        await signer.RetireKeyAsync(generated.Key, ceremony);

        var gone = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.SignAsync(generated.Key, algorithm, Tbs, ceremony));
        Assert.Equal(SigningRefusalReason.UnknownKey, gone.Reason);
        var again = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.RetireKeyAsync(generated.Key, ceremony));
        Assert.Equal(SigningRefusalReason.UnknownKey, again.Reason);

        var committed = await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.RetireKeyAsync(world["ca-rsa"].Ref, ContextFor(world, "ca-rsa", SigningPurpose.Ceremony)));
        Assert.Equal(SigningRefusalReason.OperationUnsupported, committed.Reason);

        var retireRows = (await ReadAuditAsync(world)).Where(r => r.Operation == "RetireKey").ToList();
        Assert.Equal(5, retireRows.Count);
        Assert.Equal(new[] { "refused", "refused", "allowed", "refused", "refused" }, retireRows.Select(r => r.Outcome));
        Assert.Equal(generated.Key.CertificateId, retireRows[2].KeyCertificateId);
    }

    // ------------------------------------------------------------------ ImportKey

    [Fact]
    public async Task An_imported_key_serves_the_certificate_it_was_imported_for()
    {
        var world = SignerTestWorld.Create();
        var signer = CreateSigner(world);
        var keyless = world["keyless"];
        var material = new KeyMaterial((byte[])keyless.PrivateKeyPkcs8.Clone(), KeyMaterial.Pkcs8, keyless.Ref.CertificateId);

        var imported = await signer.ImportKeyAsync(material, Context(SigningPurpose.Ceremony, null, world.TenantA));

        Assert.Equal(keyless.Ref, imported);
        Assert.All(material.Wrapped, b => Assert.Equal(0, b));
        var signature = await signer.SignAsync(imported, AlgorithmFor(world, "keyless"), Tbs, Context(SigningPurpose.Certificate, world.KeylessCaId, world.TenantA));
        Assert.True(Verify(world, "keyless", signature));
        Assert.Contains(await signer.ListKeysAsync(Context(SigningPurpose.Ceremony, world.KeylessCaId, world.TenantA)),
            k => k.Key == imported && k.Kind == KeyKind.Ca);

        var row = Assert.Single(await ReadAuditAsync(world), r => r.Operation == "ImportKey");
        Assert.Equal(SignerAuditEntity.AllowedOutcome, row.Outcome);
        Assert.Equal(keyless.Ref.CertificateId, row.KeyCertificateId);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(
            SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyless.PublicKey).GetDerEncoded())), row.DataHash);
        AssertPersisted(world, keyless.Certificate.GetEncoded());
    }

    [Fact]
    public async Task An_import_is_refused_outside_a_ceremony_for_an_unknown_format_or_for_a_certificate_that_is_not_the_keys()
    {
        // Its own world: an import that wrongly succeeded would change what every other test sees.
        var world = SignerTestWorld.Create();
        var signer = CreateSigner(world);
        var ceremony = Context(SigningPurpose.Ceremony, null, world.TenantA);
        var keylessId = world["keyless"].Ref.CertificateId;
        byte[] Pkcs8(string key) => (byte[])world[key].PrivateKeyPkcs8.Clone();

        async Task Refused(KeyMaterial material, SigningContext context, SigningRefusalReason reason)
        {
            var ex = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.ImportKeyAsync(material, context));
            Assert.Equal(reason, ex.Reason);
        }
        await Refused(new KeyMaterial(Pkcs8("keyless"), KeyMaterial.Pkcs8, keylessId), Context(SigningPurpose.Certificate, null, world.TenantA), SigningRefusalReason.PurposeNotPermitted);
        await Refused(new KeyMaterial(Pkcs8("keyless"), "pem", keylessId), ceremony, SigningRefusalReason.OperationUnsupported);
        await Refused(new KeyMaterial(new byte[] { 1, 2, 3 }, KeyMaterial.Pkcs8, keylessId), ceremony, SigningRefusalReason.OperationUnsupported);
        await Refused(new KeyMaterial(Pkcs8("keyless"), KeyMaterial.Pkcs8, Guid.NewGuid()), ceremony, SigningRefusalReason.CertificateMismatch);
        await Refused(new KeyMaterial(Pkcs8("leaf"), KeyMaterial.Pkcs8, keylessId), ceremony, SigningRefusalReason.CertificateMismatch);
        await Refused(new KeyMaterial(Pkcs8("ca-rsa"), KeyMaterial.Pkcs8, world["ca-rsa"].Ref.CertificateId), ceremony, SigningRefusalReason.OperationUnsupported);

        // None of it left the keyless CA with a key.
        var still = await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.SignAsync(world["keyless"].Ref, AlgorithmFor(world, "keyless"), Tbs, ContextFor(world, "keyless", SigningPurpose.Certificate)));
        Assert.Equal(SigningRefusalReason.UnknownKey, still.Reason);
    }

    // ---- Export ----------------------------------------------------------------------------

    /// <summary>
    /// The export table. Under Export only an end-entity key leaves, to its holder; under Backup
    /// every key the signer holds leaves; no other purpose exports anything; a key the signer
    /// does not hold is unknown whatever the purpose.
    /// </summary>
    public static IEnumerable<object[]> ExportRows()
    {
        yield return new object[] { "leaf", SigningPurpose.Export, null! };
        foreach (var k in new[] { "ca-rsa", "ca-ec", "ocsp", "tsa", "cmp", "orphan", "keyless" })
            yield return new object[] { k, SigningPurpose.Export, SigningRefusalReason.PurposeNotPermitted };

        foreach (var k in new[] { "ca-rsa", "ca-ec", "ocsp", "tsa", "cmp", "orphan", "leaf" })
            yield return new object[] { k, SigningPurpose.Backup, null! };

        foreach (var p in Enum.GetValues<SigningPurpose>().Where(p => p is not (SigningPurpose.Export or SigningPurpose.Backup)))
        {
            yield return new object[] { "leaf", p, SigningRefusalReason.PurposeNotPermitted };
            yield return new object[] { "ca-rsa", p, SigningRefusalReason.PurposeNotPermitted };
        }

        yield return new object[] { "keyless", SigningPurpose.Backup, SigningRefusalReason.UnknownKey };
        yield return new object[] { "leaf-unheld", SigningPurpose.Export, SigningRefusalReason.UnknownKey };
        yield return new object[] { "leaf-unheld", SigningPurpose.Backup, SigningRefusalReason.UnknownKey };
    }

    [Theory]
    [MemberData(nameof(ExportRows))]
    public async Task Export_policy_row(string key, SigningPurpose purpose, SigningRefusalReason? expectedRefusal)
    {
        var world = SharedWorld;
        var signer = CreateSigner(world);
        var context = ContextFor(world, key, purpose);
        var wrap = new ExportWrap(ExportWrap.Pkcs12, "export-password");

        if (expectedRefusal == null)
        {
            var pkcs12 = await signer.ExportKeyAsync(world[key].Ref, wrap, context);
            var (privateKey, chain) = OpenPkcs12(pkcs12, wrap.Password);
            Assert.Equal(world[key].PrivateKeyPkcs8, Org.BouncyCastle.Pkcs.PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey).GetDerEncoded());
            Assert.Equal(world[key].Certificate, Assert.Single(chain));
        }
        else
        {
            var ex = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.ExportKeyAsync(world[key].Ref, wrap, context));
            Assert.Equal(expectedRefusal, ex.Reason);
        }
    }

    [Fact]
    public async Task An_export_carries_the_chain_the_caller_supplies_after_the_certificate()
    {
        var world = SharedWorld;
        var signer = CreateSigner(world);
        var wrap = new ExportWrap(ExportWrap.Pkcs12, "pw", new[] { world["ca-rsa"].Certificate.GetEncoded() });

        var pkcs12 = await signer.ExportKeyAsync(world["leaf"].Ref, wrap, ContextFor(world, "leaf", SigningPurpose.Export));

        var (_, chain) = OpenPkcs12(pkcs12, "pw");
        Assert.Equal(new[] { world["leaf"].Certificate, world["ca-rsa"].Certificate }, chain);
    }

    [Fact]
    public async Task An_export_without_a_named_caller_is_refused()
    {
        var world = SignerTestWorld.Create();
        var signer = CreateSigner(world);
        var wrap = new ExportWrap(ExportWrap.Pkcs12, "pw");

        foreach (var caller in new[] { "", "   " })
        {
            var ex = await Assert.ThrowsAsync<SigningRefusedException>(
                () => signer.ExportKeyAsync(world["leaf"].Ref, wrap, new SigningContext(caller, SigningPurpose.Export, null, null)));
            Assert.Equal(SigningRefusalReason.ContextRequired, ex.Reason);
        }
        var backup = await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.ExportKeyAsync(world["ca-rsa"].Ref, wrap, new SigningContext("", SigningPurpose.Backup, null, null)));
        Assert.Equal(SigningRefusalReason.ContextRequired, backup.Reason);

        var rows = await ReadAuditAsync(world);
        Assert.Equal(3, rows.Count);
        Assert.All(rows, row => Assert.Equal(SignerAuditEntity.RefusedOutcome, row.Outcome));
    }

    [Fact]
    public async Task An_export_in_a_wrap_the_signer_does_not_produce_is_refused()
    {
        var world = SharedWorld;
        var signer = CreateSigner(world);

        var ex = await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.ExportKeyAsync(world["leaf"].Ref, new ExportWrap("pem", "pw"), ContextFor(world, "leaf", SigningPurpose.Export)));
        Assert.Equal(SigningRefusalReason.OperationUnsupported, ex.Reason);
    }

    [Fact]
    public async Task A_certificate_whose_key_was_never_stored_is_refused_and_says_the_key_was_delivered_once()
    {
        var world = SharedWorld;
        var signer = CreateSigner(world);

        var ex = await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.ExportKeyAsync(world["leaf-unheld"].Ref, new ExportWrap(ExportWrap.Pkcs12, "pw"), ContextFor(world, "leaf-unheld", SigningPurpose.Export)));

        Assert.Equal(SigningRefusalReason.UnknownKey, ex.Reason);
        Assert.Contains("delivered once", ex.Message);
    }

    [Fact]
    public async Task An_allowed_export_is_audited_with_the_hash_of_what_left_and_a_refused_one_with_its_reason()
    {
        var world = SignerTestWorld.Create();
        var signer = CreateSigner(world);
        var wrap = new ExportWrap(ExportWrap.Pkcs12, "pw");

        var pkcs12 = await signer.ExportKeyAsync(world["leaf"].Ref, wrap, Context(SigningPurpose.Export, world.CaRsaId, world.TenantA));
        await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.ExportKeyAsync(world["ca-rsa"].Ref, wrap, ContextFor(world, "ca-rsa", SigningPurpose.Export)));

        var rows = await ReadAuditAsync(world);
        Assert.Equal(2, rows.Count);
        Assert.Equal("ExportKey", rows[0].Operation);
        Assert.Equal(SignerAuditEntity.AllowedOutcome, rows[0].Outcome);
        Assert.Equal("Export", rows[0].Purpose);
        Assert.Equal(Caller, rows[0].Caller);
        Assert.Equal(world["leaf"].Ref.CertificateId, rows[0].KeyCertificateId);
        Assert.Equal(world.CaRsaId, rows[0].CaId);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(pkcs12)), rows[0].DataHash);
        Assert.Equal("ExportKey", rows[1].Operation);
        Assert.Equal(SignerAuditEntity.RefusedOutcome, rows[1].Outcome);
        Assert.Equal(world["ca-rsa"].Ref.CertificateId, rows[1].KeyCertificateId);
        Assert.Contains("Ca", rows[1].Reason);
    }

    /// <summary>Opens a PKCS#12 and returns the one key entry with its certificate chain, the key's own certificate first.</summary>
    private static (Org.BouncyCastle.Crypto.AsymmetricKeyParameter PrivateKey, X509Certificate[] Chain) OpenPkcs12(byte[] pkcs12, string password)
    {
        var store = new Org.BouncyCastle.Pkcs.Pkcs12StoreBuilder().Build();
        store.Load(new MemoryStream(pkcs12), password.ToCharArray());
        var alias = Assert.Single(store.Aliases, store.IsKeyEntry);
        var key = store.GetKey(alias).Key;
        Assert.True(key.IsPrivate);
        return (key, store.GetCertificateChain(alias).Select(e => e.Certificate).ToArray());
    }

    // ---- Keystore files: the backup wrap and the restore import -------------------------------

    private static readonly byte[] CertsFile = Encoding.ASCII.GetBytes("ca-certs.keystore bytes as the persistence keeps them");
    private static readonly byte[] TrustFile = Encoding.ASCII.GetBytes("ca-trust.keystore bytes as the persistence keeps them");

    /// <summary>A world whose persistence keeps the two keystore files a backup carries.</summary>
    private static SignerTestWorld WorldWithKeystoreFiles()
    {
        var world = SignerTestWorld.Create();
        world.Persistence.KeystoreFiles[KeyRef.DefaultKeystore] = (byte[])CertsFile.Clone();
        world.Persistence.KeystoreFiles[KeyRef.TrustKeystore] = (byte[])TrustFile.Clone();
        return world;
    }

    [Fact]
    public async Task A_backup_exports_each_keystore_file_as_the_persistence_keeps_it_and_audits_the_hash()
    {
        var world = WorldWithKeystoreFiles();
        var signer = CreateSigner(world);
        var backup = new SigningContext(Caller, SigningPurpose.Backup, null, null);

        var certs = await signer.ExportKeyAsync(KeyRef.ForKeystore(KeyRef.DefaultKeystore), ExportWrap.ForKeystoreFile(), backup);
        var trust = await signer.ExportKeyAsync(KeyRef.ForKeystore(KeyRef.TrustKeystore), ExportWrap.ForKeystoreFile(), backup);

        Assert.Equal(CertsFile, certs);
        Assert.Equal(TrustFile, trust);
        var rows = await ReadAuditAsync(world);
        Assert.Equal(2, rows.Count);
        Assert.All(rows, r =>
        {
            Assert.Equal("ExportKey", r.Operation);
            Assert.Equal(SignerAuditEntity.AllowedOutcome, r.Outcome);
            Assert.Equal("Backup", r.Purpose);
            Assert.Equal(Guid.Empty, r.KeyCertificateId);
        });
        Assert.Equal(KeyRef.DefaultKeystore, rows[0].Keystore);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(CertsFile)), rows[0].DataHash);
        Assert.Equal(KeyRef.TrustKeystore, rows[1].Keystore);
    }

    /// <summary>
    /// The keystore-file table: a whole keystore leaves under Backup only and returns under
    /// Restore or Bootstrap only, to a named caller, in the keystore-file wrap and format.
    /// </summary>
    public static IEnumerable<object[]> KeystoreFileRows()
    {
        foreach (var p in Enum.GetValues<SigningPurpose>())
        {
            yield return new object[] { "export", p, p == SigningPurpose.Backup ? null! : SigningRefusalReason.PurposeNotPermitted };
            yield return new object[] { "import", p, p is SigningPurpose.Restore or SigningPurpose.Bootstrap ? null! : SigningRefusalReason.PurposeNotPermitted };
        }
    }

    [Theory]
    [MemberData(nameof(KeystoreFileRows))]
    public async Task Keystore_file_policy_row(string operation, SigningPurpose purpose, SigningRefusalReason? expectedRefusal)
    {
        var world = WorldWithKeystoreFiles();
        var signer = CreateSigner(world);
        var context = new SigningContext(Caller, purpose, null, null);
        var replacement = Encoding.ASCII.GetBytes("replacement " + purpose);

        Func<Task> act = operation == "export"
            ? () => signer.ExportKeyAsync(KeyRef.ForKeystore(KeyRef.DefaultKeystore), ExportWrap.ForKeystoreFile(), context)
            : () => signer.ImportKeyAsync(new KeyMaterial(replacement, KeyMaterial.KeystoreFile, Guid.Empty, KeyRef.DefaultKeystore), context);

        if (expectedRefusal == null)
        {
            await act();
            if (operation == "import")
                Assert.Equal(replacement, world.Persistence.KeystoreFiles[KeyRef.DefaultKeystore]);
        }
        else
        {
            var ex = await Assert.ThrowsAsync<SigningRefusedException>(act);
            Assert.Equal(expectedRefusal, ex.Reason);
            Assert.Equal(CertsFile, world.Persistence.KeystoreFiles[KeyRef.DefaultKeystore]);
        }
        var row = Assert.Single(await ReadAuditAsync(world));
        Assert.Equal(expectedRefusal == null ? SignerAuditEntity.AllowedOutcome : SignerAuditEntity.RefusedOutcome, row.Outcome);
        Assert.Equal(KeyRef.DefaultKeystore, row.Keystore);
    }

    [Fact]
    public async Task A_keystore_file_moves_only_for_a_named_caller_in_its_own_wrap_and_format()
    {
        var world = WorldWithKeystoreFiles();
        var signer = CreateSigner(world);
        var backup = new SigningContext(Caller, SigningPurpose.Backup, null, null);
        var restore = new SigningContext(Caller, SigningPurpose.Restore, null, null);
        var bytes = Encoding.ASCII.GetBytes("replacement");

        async Task Refused(Func<Task> act, SigningRefusalReason reason)
        {
            var ex = await Assert.ThrowsAsync<SigningRefusedException>(act);
            Assert.Equal(reason, ex.Reason);
        }

        await Refused(() => signer.ExportKeyAsync(KeyRef.ForKeystore(KeyRef.DefaultKeystore), ExportWrap.ForKeystoreFile(), new SigningContext(" ", SigningPurpose.Backup, null, null)), SigningRefusalReason.ContextRequired);
        await Refused(() => signer.ImportKeyAsync(new KeyMaterial(bytes, KeyMaterial.KeystoreFile, Guid.Empty, KeyRef.DefaultKeystore), new SigningContext("", SigningPurpose.Restore, null, null)), SigningRefusalReason.ContextRequired);
        // A key's own reference does not take the keystore-file wrap, and a keystore reference does not take a key wrap.
        await Refused(() => signer.ExportKeyAsync(world["ca-rsa"].Ref, ExportWrap.ForKeystoreFile(), backup), SigningRefusalReason.OperationUnsupported);
        await Refused(() => signer.ExportKeyAsync(KeyRef.ForKeystore(KeyRef.DefaultKeystore), new ExportWrap(ExportWrap.Pkcs12, "pw"), backup), SigningRefusalReason.OperationUnsupported);
        // A keystore file names a keystore, not a certificate.
        await Refused(() => signer.ImportKeyAsync(new KeyMaterial(bytes, KeyMaterial.KeystoreFile, world["ca-rsa"].Ref.CertificateId, KeyRef.DefaultKeystore), restore), SigningRefusalReason.OperationUnsupported);
        // A keystore the persistence does not keep is unknown.
        await Refused(() => signer.ExportKeyAsync(KeyRef.ForKeystore("other.keystore"), ExportWrap.ForKeystoreFile(), backup), SigningRefusalReason.UnknownKey);

        Assert.Equal(CertsFile, world.Persistence.KeystoreFiles[KeyRef.DefaultKeystore]);
        Assert.Equal(2, world.Persistence.KeystoreFiles.Count);
    }

    [Fact]
    public async Task A_keystore_file_that_does_not_verify_is_refused_as_an_integrity_failure_and_nothing_changes()
    {
        var world = WorldWithKeystoreFiles();
        world.Persistence.Verifies = (name, bytes) => !bytes.AsSpan().SequenceEqual(Encoding.ASCII.GetBytes("tampered"));
        var signer = CreateSigner(world);
        var restore = new SigningContext(Caller, SigningPurpose.Restore, null, null);
        var tampered = Encoding.ASCII.GetBytes("tampered");

        var ex = await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.ImportKeyAsync(new KeyMaterial(tampered, KeyMaterial.KeystoreFile, Guid.Empty, KeyRef.DefaultKeystore), restore));

        Assert.Equal(SigningRefusalReason.IntegrityFailure, ex.Reason);
        Assert.Equal(CertsFile, world.Persistence.KeystoreFiles[KeyRef.DefaultKeystore]);
        var row = Assert.Single(await ReadAuditAsync(world));
        Assert.Equal("ImportKey", row.Operation);
        Assert.Equal(SignerAuditEntity.RefusedOutcome, row.Outcome);
        Assert.Contains("did not verify", row.Reason);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(tampered)), row.DataHash);
    }

    [Fact]
    public async Task What_a_backup_exported_restores_byte_for_byte()
    {
        var source = WorldWithKeystoreFiles();
        var exported = new List<(string Name, byte[] Bytes)>();
        foreach (var name in KeyRef.BackupKeystores)
            exported.Add((name, await CreateSigner(source).ExportKeyAsync(KeyRef.ForKeystore(name), ExportWrap.ForKeystoreFile(), new SigningContext(Caller, SigningPurpose.Backup, null, null))));

        var target = SignerTestWorld.Create();
        var signer = CreateSigner(target);
        foreach (var (name, bytes) in exported)
            await signer.ImportKeyAsync(new KeyMaterial(bytes, KeyMaterial.KeystoreFile, Guid.Empty, name), new SigningContext(Caller, SigningPurpose.Restore, null, null));

        Assert.Equal(source.Persistence.KeystoreFiles.Keys.OrderBy(k => k), target.Persistence.KeystoreFiles.Keys.OrderBy(k => k));
        foreach (var name in KeyRef.BackupKeystores)
            Assert.Equal(source.Persistence.KeystoreFiles[name], target.Persistence.KeystoreFiles[name]);
    }

    // ---- Ceremonies: the signer verifies the approval it is told about ----------------------

    /// <summary>Seeds a ceremony row as the control plane writes one, and returns its id.</summary>
    private static Guid SeedCeremony(SignerTestWorld world, string status, Guid? tenantId, string targetEntityId = "")
    {
        var id = Guid.NewGuid();
        using var db = world.OpenDb();
        db.KeyCeremonies.Add(new KeyCeremonyEntity
        {
            Id = id,
            OperationType = "CreateRootCA",
            Description = "signer contract",
            Status = status,
            TenantId = tenantId,
            TargetEntityId = targetEntityId,
            RequiredApprovals = 1,
            CurrentApprovals = status == "Approved" ? 1 : 0,
            ExpiresAt = DateTime.UtcNow.AddHours(1),
        });
        db.SaveChanges();
        return id;
    }

    [Fact]
    public async Task Keys_are_generated_committed_and_imported_under_a_ceremony_the_signer_verified()
    {
        var world = SignerTestWorld.Create();
        var signer = CreateSigner(world);
        var approved = SeedCeremony(world, "Approved", world.TenantA);
        var ceremony = Context(SigningPurpose.Ceremony, null, world.TenantA) with { CeremonyId = approved };

        var generated = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), ceremony);
        var (_, certificateId, caId) = await SeedGeneratedCaAsync(world, signer, generated, ceremony);
        await signer.CommitKeyAsync(generated.Key, certificateId, ceremony);
        Assert.Contains(await signer.ListKeysAsync(Context(SigningPurpose.Ceremony, caId, world.TenantA)), k => k.Key.CertificateId == certificateId);

        var keyless = world["keyless"];
        var imported = await signer.ImportKeyAsync(
            new KeyMaterial((byte[])keyless.PrivateKeyPkcs8.Clone(), KeyMaterial.Pkcs8, keyless.Ref.CertificateId),
            Context(SigningPurpose.Ceremony, world.KeylessCaId, world.TenantA) with { CeremonyId = approved });
        Assert.Equal(keyless.Ref, imported);
    }

    /// <summary>
    /// The ceremonies the signer cannot verify: none by that id, one not approved in any of its
    /// other states, one approved for another tenant, one targeting another CA.
    /// </summary>
    public static IEnumerable<object[]> UnverifiableCeremonyRows()
    {
        yield return new object[] { "missing" };
        yield return new object[] { "Pending" };
        yield return new object[] { "Rejected" };
        yield return new object[] { "Executed" };
        yield return new object[] { "Expired" };
        yield return new object[] { "Cancelled" };
        yield return new object[] { "other-tenant" };
        yield return new object[] { "other-ca" };
    }

    [Theory]
    [MemberData(nameof(UnverifiableCeremonyRows))]
    public async Task Key_management_under_a_ceremony_the_signer_cannot_verify_is_refused(string kind)
    {
        var world = SignerTestWorld.Create();
        var signer = CreateSigner(world);
        var ceremonyId = kind switch
        {
            "missing" => Guid.NewGuid(),
            "other-tenant" => SeedCeremony(world, "Approved", world.TenantB),
            "other-ca" => SeedCeremony(world, "Approved", world.TenantA, world.CaEcId.ToString()),
            _ => SeedCeremony(world, kind, world.TenantA),
        };
        var caId = kind == "other-ca" ? world.CaRsaId : (Guid?)null;
        var context = Context(SigningPurpose.Ceremony, caId, world.TenantA) with { CeremonyId = ceremonyId };

        async Task Refused(Func<Task> operation)
        {
            var ex = await Assert.ThrowsAsync<SigningRefusedException>(operation);
            Assert.Equal(SigningRefusalReason.CeremonyNotApproved, ex.Reason);
        }
        await Refused(() => signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), context));
        await Refused(() => signer.ImportKeyAsync(
            new KeyMaterial((byte[])world["keyless"].PrivateKeyPkcs8.Clone(), KeyMaterial.Pkcs8, world["keyless"].Ref.CertificateId), context));

        // A key generated under a verified ceremony is not committed under an unverifiable one,
        // but it is still retired under it: retiring is the undo of a ceremony that failed.
        var approved = Context(SigningPurpose.Ceremony, caId, world.TenantA) with { CeremonyId = SeedCeremony(world, "Approved", world.TenantA) };
        var generated = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), approved);
        var (_, certificateId, _) = await SeedGeneratedCaAsync(world, signer, generated, approved);
        await Refused(() => signer.CommitKeyAsync(generated.Key, certificateId, context));
        await signer.RetireKeyAsync(generated.Key, context);

        var rows = (await ReadAuditAsync(world)).Where(r => r.Outcome == SignerAuditEntity.RefusedOutcome).ToList();
        Assert.Equal(3, rows.Count);
        Assert.Equal(new[] { "GenerateKey", "ImportKey", "CommitKey" }, rows.Select(r => r.Operation));
        Assert.All(rows, r => Assert.Contains("eremony", r.Reason));
        Assert.Empty(world.Persistence.Appended);
    }

    private static bool VerifyWith(Org.BouncyCastle.Crypto.AsymmetricKeyParameter publicKey, string algorithm, byte[] signature)
    {
        var verifier = SignerUtilities.GetSigner(algorithm);
        verifier.Init(false, publicKey);
        verifier.BlockUpdate(Tbs, 0, Tbs.Length);
        return verifier.VerifySignature(signature);
    }

    private static bool Verify(SignerTestWorld world, string key, byte[] signature, string? algorithm = null, byte[]? data = null)
    {
        var verifier = SignerUtilities.GetSigner(algorithm ?? AlgorithmFor(world, key).Name);
        verifier.Init(false, world[key].PublicKey);
        var bytes = data ?? Tbs;
        verifier.BlockUpdate(bytes, 0, bytes.Length);
        return verifier.VerifySignature(signature);
    }
}
