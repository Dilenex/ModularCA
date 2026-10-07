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
/// implementation runs the same suite by binding <see cref="CreateSignerAsync"/> to itself.
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

    /// <summary>The world the read-only tests share; an implementation may build it ahead, in a fixture.</summary>
    internal virtual SignerTestWorld SharedWorld => SharedWorlds.GetOrAdd(GetType(), _ => SignerTestWorld.Create());

    /// <summary>Binds the suite to an implementation over the world's keys and database.</summary>
    internal abstract Task<ISigningService> CreateSignerAsync(SignerTestWorld world);

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
    /// What the signer's audit records as the peer of every decision: null in process, where
    /// there is no peer, and the node's client certificate pin over the wire, where the signer
    /// stamps it from the connection it admitted.
    /// </summary>
    protected virtual string? ExpectedPeerIdentity => null;

    /// <summary>
    /// Asserts that a committed or imported key's certificate reached the implementation's
    /// durable store. The contract cannot see the store, so the in-process binding overrides
    /// this over its persistence; a remote binding will assert through its own signer.
    /// </summary>
    internal virtual void AssertPersisted(SignerTestWorld world, byte[] certificateDer) { }

    /// <summary>Bytes that are no structure: what a refusal decided before the data is looked at is signed over.</summary>
    private static readonly byte[] Tbs = TypedSigningData.Junk;

    /// <summary>The subject key of the leaf certificates the CA keys are asked to sign.</summary>
    private static readonly Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair LeafKey = ModularCA.Shared.Utils.KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-256");

    /// <summary>
    /// Well-formed bytes for what <paramref name="key"/> would sign under <paramref name="purpose"/>:
    /// a leaf TBSCertificate or a TBSCertList naming the key's certificate as issuer, an OCSP
    /// ResponseData naming it as responder, SCEP or timestamp signed attributes, a CMP
    /// ProtectedPart. Junk for a purpose that signs no structure.
    /// </summary>
    private static byte[] Typed(SignerTestWorld world, string key, SigningPurpose purpose)
    {
        var k = world[key];
        var algorithm = AlgorithmFor(world, key);
        return purpose switch
        {
            SigningPurpose.Certificate => TypedSigningData.Certificate(k.Certificate.SubjectDN, LeafKey.Public, algorithm),
            SigningPurpose.Crl => TypedSigningData.Crl(k.Certificate.SubjectDN, algorithm),
            SigningPurpose.Ocsp => TypedSigningData.OcspResponse(k.PublicKey, world["ca-rsa"].Certificate, algorithm),
            SigningPurpose.Scep => TypedSigningData.ScepAttributes(),
            SigningPurpose.Cmp => TypedSigningData.CmpProtectedPart(algorithm),
            SigningPurpose.Tsa => TypedSigningData.TimestampAttributes(),
            _ => Tbs,
        };
    }

    private static SigningContext Context(SigningPurpose purpose, Guid? caId, Guid? spaceId) => new(Caller, purpose, spaceId, caId);

    private static SigningContext ContextFor(SignerTestWorld world, string key, SigningPurpose purpose)
        => Context(purpose, world[key].CaId, world[key].SpaceId);

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
        var signer = await CreateSignerAsync(world);
        var k = world[key];
        var (caId, spaceId) = ResolveCa(world, k, ca);
        var context = Context(purpose, caId, spaceId);
        var data = Typed(world, key, purpose);

        if (expectedRefusal == null)
        {
            var signature = await signer.SignAsync(k.Ref, AlgorithmFor(world, key), data, context);
            Assert.True(Verify(world, key, signature, data: data), $"{key} signed for {purpose} but the signature does not verify");
        }
        else
        {
            var ex = await Assert.ThrowsAsync<SigningRefusedException>(
                () => signer.SignAsync(k.Ref, AlgorithmFor(world, key), data, context));
            Assert.Equal(expectedRefusal, ex.Reason);
        }
    }

    [Fact]
    public async Task A_key_is_refused_for_a_space_that_does_not_own_its_ca()
    {
        var world = SharedWorld;
        var signer = await CreateSignerAsync(world);

        var ex = await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.SignAsync(world["ca-rsa"].Ref, AlgorithmFor(world, "ca-rsa"), Tbs,
                Context(SigningPurpose.Certificate, world.CaRsaId, world.SpaceB)));

        Assert.Equal(SigningRefusalReason.TenantMismatch, ex.Reason);
    }

    [Fact]
    public async Task A_context_that_names_no_space_is_held_to_the_ca_alone()
    {
        var world = SharedWorld;
        var signer = await CreateSignerAsync(world);

        var crl = Typed(world, "ca-rsa", SigningPurpose.Crl);
        var signature = await signer.SignAsync(world["ca-rsa"].Ref, AlgorithmFor(world, "ca-rsa"), crl,
            Context(SigningPurpose.Crl, world.CaRsaId, spaceId: null));

        Assert.True(Verify(world, "ca-rsa", signature, data: crl));
    }

    [Fact]
    public async Task A_certificate_the_signer_has_never_heard_of_is_refused()
    {
        var world = SharedWorld;
        var signer = await CreateSignerAsync(world);

        var ex = await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.SignAsync(new KeyRef(Guid.NewGuid()), SignatureAlgorithm.FromName("SHA256withRSA"), Tbs,
                Context(SigningPurpose.Certificate, world.CaRsaId, world.SpaceA)));

        Assert.Equal(SigningRefusalReason.UnknownKey, ex.Reason);
    }

    [Theory]
    [InlineData("ca-rsa", "SHA256withRSA")]
    [InlineData("ca-ec", "SHA256withECDSA")]
    public async Task A_signature_verifies_under_the_public_key(string key, string algorithm)
    {
        var world = SharedWorld;
        var signer = await CreateSignerAsync(world);

        var tbs = TypedSigningData.Certificate(world[key].Certificate.SubjectDN, LeafKey.Public, SignatureAlgorithm.FromName(algorithm));
        var signature = await signer.SignAsync(world[key].Ref, SignatureAlgorithm.FromName(algorithm), tbs, ContextFor(world, key, SigningPurpose.Certificate));

        Assert.True(Verify(world, key, signature, algorithm, tbs));
        Assert.False(Verify(world, key, signature, algorithm, Encoding.ASCII.GetBytes("different bytes")));
    }

    [Fact]
    public async Task An_allowed_decision_is_audited_with_its_context_and_the_hash_of_what_was_signed()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        var before = DateTime.UtcNow.AddSeconds(-1);

        var response = Typed(world, "ocsp", SigningPurpose.Ocsp);
        await signer.SignAsync(world["ocsp"].Ref, SignatureAlgorithm.FromName("SHA256withRSA"), response, ContextFor(world, "ocsp", SigningPurpose.Ocsp));

        var row = Assert.Single(await ReadAuditAsync(world));
        Assert.Equal("Sign", row.Operation);
        Assert.Equal(Caller, row.Caller);
        Assert.Equal("Ocsp", row.Purpose);
        Assert.Equal(world["ocsp"].Ref.CertificateId, row.KeyCertificateId);
        Assert.Equal(KeyRef.DefaultKeystore, row.Keystore);
        Assert.Equal(world.CaRsaId, row.CaId);
        Assert.Equal(world.SpaceA, row.SpaceId);
        Assert.Equal("SHA256withRSA", row.Algorithm);
        Assert.Equal(SignerAuditEntity.AllowedOutcome, row.Outcome);
        Assert.Null(row.Reason);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(response)), row.DataHash);
        Assert.InRange(row.At, before, DateTime.UtcNow.AddSeconds(1));
    }

    [Fact]
    public async Task A_refused_decision_is_audited_with_its_reason()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);

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
        var signer = await CreateSignerAsync(world);
        var unknown = new KeyRef(Guid.NewGuid());

        await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.SignAsync(unknown, SignatureAlgorithm.FromName("SHA256withRSA"), Tbs, Context(SigningPurpose.Crl, world.CaRsaId, world.SpaceA)));

        var row = Assert.Single(await ReadAuditAsync(world));
        Assert.Equal(SignerAuditEntity.RefusedOutcome, row.Outcome);
        Assert.Equal(unknown.CertificateId, row.KeyCertificateId);
    }

    [Fact]
    public async Task Every_decision_leaves_exactly_one_row()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);

        await signer.SignAsync(world["ca-rsa"].Ref, AlgorithmFor(world, "ca-rsa"), Typed(world, "ca-rsa", SigningPurpose.Certificate), ContextFor(world, "ca-rsa", SigningPurpose.Certificate));
        await signer.SignAsync(world["ca-rsa"].Ref, AlgorithmFor(world, "ca-rsa"), Typed(world, "ca-rsa", SigningPurpose.Crl), ContextFor(world, "ca-rsa", SigningPurpose.Crl));
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
        var signer = await CreateSignerAsync(world);

        var health = await signer.HealthAsync();

        Assert.True(health.Unlocked);
        Assert.Equal(world.HeldKeys.Count(), health.KeyCount);
        Assert.Equal(ExpectedBackend, health.Backend);
    }

    [Fact]
    public async Task Listing_keys_for_a_ca_names_its_own_keys_with_their_kinds()
    {
        var world = SharedWorld;
        var signer = await CreateSignerAsync(world);

        var keys = await signer.ListKeysAsync(Context(SigningPurpose.Ocsp, world.CaRsaId, world.SpaceA));

        var byId = keys.ToDictionary(k => k.Key.CertificateId);
        Assert.Equal(4, byId.Count);
        Assert.Equal(KeyKind.Ca, byId[world["ca-rsa"].Ref.CertificateId].Kind);
        Assert.Equal(KeyKind.OcspResponder, byId[world["ocsp"].Ref.CertificateId].Kind);
        Assert.Equal(KeyKind.Tsa, byId[world["tsa"].Ref.CertificateId].Kind);
        Assert.Equal(KeyKind.CmpSigner, byId[world["cmp"].Ref.CertificateId].Kind);
        Assert.All(keys, k =>
        {
            Assert.Equal(world.CaRsaId, k.CaId);
            Assert.Equal(world.SpaceA, k.SpaceId);
            Assert.Equal(ExpectedBackend, k.Backend);
        });
        var caPublic = PublicKeyFactory.CreateKey(byId[world["ca-rsa"].Ref.CertificateId].PublicKeyDer);
        Assert.Equal(world["ca-rsa"].PublicKey, caPublic);
    }

    [Fact]
    public async Task Listing_keys_without_a_ca_names_every_owned_key_the_signer_holds()
    {
        var world = SharedWorld;
        var signer = await CreateSignerAsync(world);

        var keys = await signer.ListKeysAsync(Context(SigningPurpose.Ceremony, caId: null, spaceId: null));

        var ids = keys.Select(k => k.Key.CertificateId).ToHashSet();
        Assert.Equal(5, ids.Count);
        Assert.Contains(world["ca-ec"].Ref.CertificateId, ids);
        Assert.DoesNotContain(world["keyless"].Ref.CertificateId, ids);
        Assert.DoesNotContain(world["leaf"].Ref.CertificateId, ids);
        Assert.DoesNotContain(world["orphan"].Ref.CertificateId, ids);
    }

    /// <summary>
    /// The CA a policy row names: <c>own</c> is the CA that owns the key, <c>other</c> the other
    /// CA, <c>rsa</c> the RSA CA whatever the key, <c>none</c> no CA at all; the space follows
    /// the CA.
    /// </summary>
    private static (Guid? CaId, Guid? SpaceId) ResolveCa(SignerTestWorld world, SignerTestKey k, string ca)
    {
        Guid? caId = ca switch
        {
            "own" => k.CaId,
            "other" => k.CaId == world.CaRsaId ? world.CaEcId : world.CaRsaId,
            "rsa" => world.CaRsaId,
            _ => null,
        };
        Guid? spaceId = caId == world.CaRsaId ? world.SpaceA : caId == world.CaEcId ? world.SpaceB : null;
        return (caId, spaceId);
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
        var signer = await CreateSignerAsync(world);
        var k = world[key];
        var (caId, spaceId) = ResolveCa(world, k, ca);
        var context = Context(purpose, caId, spaceId);
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
        var signer = await CreateSignerAsync(world);
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
        var signer = await CreateSignerAsync(world);
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
        var signer = await CreateSignerAsync(world);
        var enveloped = EnvelopeTo(world["keyless"].Certificate, Secret);

        var ex = await Assert.ThrowsAnyAsync<Exception>(
            () => signer.DecryptAsync(world["ca-rsa"].Ref, enveloped, ContextFor(world, "ca-rsa", SigningPurpose.Scep)));

        Assert.IsNotType<SigningRefusedException>(ex);
        var row = Assert.Single(await ReadAuditAsync(world));
        Assert.Equal(SignerAuditEntity.AllowedOutcome, row.Outcome);
    }

    // ------------------------------------------------------------------ GenerateKey

    /// <summary>Key management happens under a ceremony or infrastructure context, and under nothing else, bootstrap included.</summary>
    public static IEnumerable<object[]> KeyManagementPurposeRows()
    {
        foreach (var p in Enum.GetValues<SigningPurpose>())
            yield return new object[] { p, p is SigningPurpose.Ceremony or SigningPurpose.Infrastructure };
    }

    /// <summary>
    /// A bootstrap context is held to no ceremony, so it manages no key: a caller could otherwise
    /// generate and commit, or import, a CA key into any scope without one. It still moves whole
    /// keystore files (see the keystore-file rows).
    /// </summary>
    [Fact]
    public async Task Bootstrap_manages_no_key()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        var bootstrap = Context(SigningPurpose.Bootstrap, null, world.SpaceA);
        var ceremony = Context(SigningPurpose.Ceremony, null, world.SpaceA);
        var keyless = world["keyless"];

        async Task Refused(Func<Task> operation)
        {
            var ex = await Assert.ThrowsAsync<SigningRefusedException>(operation);
            Assert.Equal(SigningRefusalReason.PurposeNotPermitted, ex.Reason);
        }
        await Refused(() => signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), bootstrap));
        await Refused(() => signer.ImportKeyAsync(
            new KeyMaterial((byte[])keyless.PrivateKeyPkcs8.Clone(), KeyMaterial.Pkcs8, keyless.Ref.CertificateId), bootstrap));
        await Refused(() => signer.ImportKeyAsync(
            new KeyMaterial((byte[])keyless.PrivateKeyPkcs8.Clone(), KeyMaterial.Pkcs8, keyless.Ref.CertificateId), bootstrap with { InstanceScope = true, SpaceId = null }));

        var generated = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), ceremony);
        var (_, certificateId, _) = await SeedGeneratedCaAsync(world, signer, generated, ceremony);
        await Refused(() => signer.CommitKeyAsync(generated.Key, certificateId, bootstrap));
        await Refused(() => signer.RetireKeyAsync(generated.Key, bootstrap));

        Assert.Empty(world.Persistence.Appended);
        var rows = (await ReadAuditAsync(world)).Where(r => r.Purpose == "Bootstrap").ToList();
        Assert.Equal(5, rows.Count);
        Assert.All(rows, r => Assert.Equal(SignerAuditEntity.RefusedOutcome, r.Outcome));
    }

    [Theory]
    [MemberData(nameof(KeyManagementPurposeRows))]
    public async Task Generate_key_policy_row(SigningPurpose purpose, bool allowed)
    {
        var world = SharedWorld;
        var signer = await CreateSignerAsync(world);
        var context = Context(purpose, null, world.SpaceA);

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
        var signer = await CreateSignerAsync(world);
        var ceremony = Context(SigningPurpose.Ceremony, world.CaRsaId, world.SpaceA);
        var generated = await signer.GenerateKeyAsync(new KeySpec("RSA", "2048"), ceremony);
        var publicKey = PublicKeyFactory.CreateKey(generated.PublicKeyDer);
        var algorithm = SignatureAlgorithm.ForPublicKey(publicKey);
        var request = TypedSigningData.CertificationRequest(publicKey);

        var signature = await signer.SignAsync(generated.Key, algorithm, request, ceremony);
        Assert.True(VerifyWith(publicKey, algorithm.Name, signature, request));

        // Nothing named at all is held to nothing.
        Assert.True(VerifyWith(publicKey, algorithm.Name,
            await signer.SignAsync(generated.Key, algorithm, request, Context(SigningPurpose.Ceremony, null, null)), request));

        async Task Refused(SigningContext context, SigningRefusalReason reason)
        {
            var ex = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.SignAsync(generated.Key, algorithm, Tbs, context));
            Assert.Equal(reason, ex.Reason);
        }
        await Refused(Context(SigningPurpose.Certificate, world.CaRsaId, world.SpaceA), SigningRefusalReason.PurposeNotPermitted);
        await Refused(Context(SigningPurpose.Crl, world.CaRsaId, world.SpaceA), SigningRefusalReason.PurposeNotPermitted);
        await Refused(Context(SigningPurpose.Bootstrap, world.CaRsaId, world.SpaceA), SigningRefusalReason.PurposeNotPermitted);
        await Refused(Context(SigningPurpose.Ceremony, world.CaRsaId, world.SpaceB), SigningRefusalReason.TenantMismatch);
        await Refused(Context(SigningPurpose.Ceremony, world.CaEcId, world.SpaceA), SigningRefusalReason.CaMismatch);

        var decrypt = await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.DecryptAsync(generated.Key, EnvelopeTo(world["ca-rsa"].Certificate, Secret), ceremony));
        Assert.Equal(SigningRefusalReason.PurposeNotPermitted, decrypt.Reason);
    }

    [Fact]
    public async Task Key_generation_is_audited_with_the_reference_and_the_hash_of_the_public_key()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);

        var generated = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), Context(SigningPurpose.Ceremony, null, world.SpaceA));
        await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), Context(SigningPurpose.Certificate, world.CaRsaId, world.SpaceA)));

        var rows = await ReadAuditAsync(world);
        Assert.Equal(2, rows.Count);
        Assert.Equal("GenerateKey", rows[0].Operation);
        Assert.Equal(SignerAuditEntity.AllowedOutcome, rows[0].Outcome);
        Assert.Equal("Ceremony", rows[0].Purpose);
        Assert.Equal(generated.Key.CertificateId, rows[0].KeyCertificateId);
        Assert.Equal(world.SpaceA, rows[0].SpaceId);
        Assert.Equal(SignerAuditEntity.SpaceScope, rows[0].EffectiveScope);
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
        var signer = await CreateSignerAsync(world);
        var ceremony = Context(SigningPurpose.Ceremony, null, world.SpaceA);

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
    /// rows that make it a CA in the scope the context states (space A when it states none), or
    /// in <paramref name="owner"/>'s scope when given. Returns the certificate row id and the CA id.
    /// A key generated under a context the signer lets no CA certificate be signed for (an
    /// infrastructure context, or a ceremony context naming an existing CA) gets a CA
    /// certificate made outside the signer instead, for the tests that go on to show the commit
    /// is refused.
    /// </summary>
    private async Task<(X509Certificate Certificate, Guid CertificateId, Guid CaId)> SeedGeneratedCaAsync(
        SignerTestWorld world, ISigningService signer, GeneratedKey generated, SigningContext ceremony, (Guid? SpaceId, bool Set) owner = default)
    {
        var caSpace = owner.Set ? owner.SpaceId : ceremony.InstanceScope ? null : ceremony.SpaceId ?? world.SpaceA;
        var publicKey = PublicKeyFactory.CreateKey(generated.PublicKeyDer);
        var subject = new X509Name("CN=Generated Through The Signer, O=ModularCA");
        X509Certificate cert;
        if (ceremony.Purpose == SigningPurpose.Ceremony && ceremony.CaId == null)
        {
            var gen = new X509V3CertificateGenerator();
            gen.SetSerialNumber(BigInteger.ValueOf(DateTime.UtcNow.Ticks));
            gen.SetIssuerDN(subject);
            gen.SetSubjectDN(subject);
            gen.SetNotBefore(DateTime.UtcNow.AddMinutes(-1));
            gen.SetNotAfter(DateTime.UtcNow.AddDays(1));
            gen.SetPublicKey(publicKey);
            gen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
            cert = gen.Generate(new SigningServiceSignatureFactory(signer, generated.Key, SignatureAlgorithm.ForPublicKey(publicKey), ceremony));
            cert.Verify(publicKey);
        }
        else
        {
            cert = TypedSigningData.OutsideCertificate(publicKey, subject, isCa: true);
        }

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
                Id = caId, Name = "generated", Label = $"generated-{caId:N}", SpaceId = caSpace, CertificateId = certificateId,
            });
            await db.SaveChangesAsync();
        }
        return (cert, certificateId, caId);
    }

    [Fact]
    public async Task A_generated_key_committed_to_its_certificate_serves_the_policy_for_its_kind()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        var ceremony = Context(SigningPurpose.Ceremony, null, world.SpaceA);
        var generated = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), ceremony);
        var publicKey = PublicKeyFactory.CreateKey(generated.PublicKeyDer);
        var (cert, certificateId, caId) = await SeedGeneratedCaAsync(world, signer, generated, ceremony);

        await signer.CommitKeyAsync(generated.Key, certificateId, ceremony);

        var committed = new KeyRef(certificateId);
        var algorithm = SignatureAlgorithm.ForPublicKey(publicKey);
        var leafTbs = TypedSigningData.Certificate(cert.SubjectDN, LeafKey.Public, algorithm);
        var crlTbs = TypedSigningData.Crl(cert.SubjectDN, algorithm);
        var signature = await signer.SignAsync(committed, algorithm, leafTbs, Context(SigningPurpose.Certificate, caId, world.SpaceA));
        Assert.True(VerifyWith(publicKey, algorithm.Name, signature, leafTbs));
        Assert.True(VerifyWith(publicKey, algorithm.Name,
            await signer.SignAsync(committed, algorithm, crlTbs, Context(SigningPurpose.Crl, caId, world.SpaceA)), crlTbs));

        var wrongCa = await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.SignAsync(committed, algorithm, Tbs, Context(SigningPurpose.Certificate, world.CaRsaId, world.SpaceA)));
        Assert.Equal(SigningRefusalReason.CaMismatch, wrongCa.Reason);

        // The generated reference is spent.
        var spent = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.SignAsync(generated.Key, algorithm, Tbs, ceremony));
        Assert.Equal(SigningRefusalReason.UnknownKey, spent.Reason);

        var listed = Assert.Single(await signer.ListKeysAsync(Context(SigningPurpose.Ocsp, caId, world.SpaceA)));
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
        var signer = await CreateSignerAsync(world);
        var ceremony = Context(SigningPurpose.Ceremony, null, world.SpaceA);
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
        await Refused(generated.Key, certificateId, Context(SigningPurpose.Certificate, null, world.SpaceA), SigningRefusalReason.PurposeNotPermitted);
        await Refused(generated.Key, certificateId, Context(SigningPurpose.Ceremony, null, world.SpaceB), SigningRefusalReason.TenantMismatch);

        // A refused commit spends nothing: the key is still pending and still signs.
        var publicKey = PublicKeyFactory.CreateKey(generated.PublicKeyDer);
        var algorithm = SignatureAlgorithm.ForPublicKey(publicKey);
        var request = TypedSigningData.CertificationRequest(publicKey);
        Assert.True(VerifyWith(publicKey, algorithm.Name, await signer.SignAsync(generated.Key, algorithm, request, ceremony), request));

        var refusedCommits = (await ReadAuditAsync(world)).Where(r => r.Operation == "CommitKey").ToList();
        Assert.Equal(6, refusedCommits.Count);
        Assert.All(refusedCommits, r => Assert.Equal(SignerAuditEntity.RefusedOutcome, r.Outcome));
    }

    // ------------------------------------------------------------------ RetireKey

    [Fact]
    public async Task A_retired_key_is_gone_and_a_committed_key_cannot_be_retired()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        var ceremony = Context(SigningPurpose.Ceremony, null, world.SpaceA);
        var generated = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), ceremony);
        var algorithm = SignatureAlgorithm.ForPublicKey(PublicKeyFactory.CreateKey(generated.PublicKeyDer));

        var wrongPurpose = await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.RetireKeyAsync(generated.Key, Context(SigningPurpose.Certificate, null, world.SpaceA)));
        Assert.Equal(SigningRefusalReason.PurposeNotPermitted, wrongPurpose.Reason);

        var otherSpace = await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.RetireKeyAsync(generated.Key, Context(SigningPurpose.Ceremony, null, world.SpaceB)));
        Assert.Equal(SigningRefusalReason.TenantMismatch, otherSpace.Reason);

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
        var signer = await CreateSignerAsync(world);
        var keyless = world["keyless"];
        var material = new KeyMaterial((byte[])keyless.PrivateKeyPkcs8.Clone(), KeyMaterial.Pkcs8, keyless.Ref.CertificateId);

        var imported = await signer.ImportKeyAsync(material, Context(SigningPurpose.Ceremony, null, world.SpaceA));

        Assert.Equal(keyless.Ref, imported);
        Assert.All(material.Wrapped, b => Assert.Equal(0, b));
        var tbs = Typed(world, "keyless", SigningPurpose.Certificate);
        var signature = await signer.SignAsync(imported, AlgorithmFor(world, "keyless"), tbs, Context(SigningPurpose.Certificate, world.KeylessCaId, world.SpaceA));
        Assert.True(Verify(world, "keyless", signature, data: tbs));
        Assert.Contains(await signer.ListKeysAsync(Context(SigningPurpose.Ceremony, world.KeylessCaId, world.SpaceA)),
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
        var signer = await CreateSignerAsync(world);
        var ceremony = Context(SigningPurpose.Ceremony, null, world.SpaceA);
        var keylessId = world["keyless"].Ref.CertificateId;
        byte[] Pkcs8(string key) => (byte[])world[key].PrivateKeyPkcs8.Clone();

        async Task Refused(KeyMaterial material, SigningContext context, SigningRefusalReason reason)
        {
            var ex = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.ImportKeyAsync(material, context));
            Assert.Equal(reason, ex.Reason);
        }
        await Refused(new KeyMaterial(Pkcs8("keyless"), KeyMaterial.Pkcs8, keylessId), Context(SigningPurpose.Certificate, null, world.SpaceA), SigningRefusalReason.PurposeNotPermitted);
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
    /// The export table. Only an end-entity key leaves as PKCS#12, and only under Export, to its
    /// holder. Backup takes whole keystore files and never a single key as PKCS#12, so every
    /// key, CA or end-entity, is refused under it; no other purpose exports anything; a key the
    /// signer does not hold is unknown under Export.
    /// </summary>
    public static IEnumerable<object[]> ExportRows()
    {
        yield return new object[] { "leaf", SigningPurpose.Export, null! };
        foreach (var k in new[] { "ca-rsa", "ca-ec", "ocsp", "tsa", "cmp", "orphan", "keyless" })
            yield return new object[] { k, SigningPurpose.Export, SigningRefusalReason.PurposeNotPermitted };

        foreach (var k in new[] { "ca-rsa", "ca-ec", "ocsp", "tsa", "cmp", "orphan", "leaf", "keyless", "leaf-unheld" })
            yield return new object[] { k, SigningPurpose.Backup, SigningRefusalReason.PurposeNotPermitted };

        foreach (var p in Enum.GetValues<SigningPurpose>().Where(p => p is not (SigningPurpose.Export or SigningPurpose.Backup)))
        {
            yield return new object[] { "leaf", p, SigningRefusalReason.PurposeNotPermitted };
            yield return new object[] { "ca-rsa", p, SigningRefusalReason.PurposeNotPermitted };
        }

        yield return new object[] { "leaf-unheld", SigningPurpose.Export, SigningRefusalReason.UnknownKey };
    }

    [Theory]
    [MemberData(nameof(ExportRows))]
    public async Task Export_policy_row(string key, SigningPurpose purpose, SigningRefusalReason? expectedRefusal)
    {
        var world = SharedWorld;
        var signer = await CreateSignerAsync(world);
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
        var signer = await CreateSignerAsync(world);
        var wrap = new ExportWrap(ExportWrap.Pkcs12, "pw", new[] { world["ca-rsa"].Certificate.GetEncoded() });

        var pkcs12 = await signer.ExportKeyAsync(world["leaf"].Ref, wrap, ContextFor(world, "leaf", SigningPurpose.Export));

        var (_, chain) = OpenPkcs12(pkcs12, "pw");
        Assert.Equal(new[] { world["leaf"].Certificate, world["ca-rsa"].Certificate }, chain);
    }

    [Fact]
    public async Task An_export_without_a_named_caller_is_refused()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
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
        var signer = await CreateSignerAsync(world);

        var ex = await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.ExportKeyAsync(world["leaf"].Ref, new ExportWrap("pem", "pw"), ContextFor(world, "leaf", SigningPurpose.Export)));
        Assert.Equal(SigningRefusalReason.OperationUnsupported, ex.Reason);
    }

    [Fact]
    public async Task A_certificate_whose_key_was_never_stored_is_refused_and_says_the_key_was_delivered_once()
    {
        var world = SharedWorld;
        var signer = await CreateSignerAsync(world);

        var ex = await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.ExportKeyAsync(world["leaf-unheld"].Ref, new ExportWrap(ExportWrap.Pkcs12, "pw"), ContextFor(world, "leaf-unheld", SigningPurpose.Export)));

        Assert.Equal(SigningRefusalReason.UnknownKey, ex.Reason);
        Assert.Contains("delivered once", ex.Message);
    }

    [Fact]
    public async Task An_allowed_export_is_audited_with_the_hash_of_what_left_and_a_refused_one_with_its_reason()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        var wrap = new ExportWrap(ExportWrap.Pkcs12, "pw");

        var pkcs12 = await signer.ExportKeyAsync(world["leaf"].Ref, wrap, Context(SigningPurpose.Export, world.CaRsaId, world.SpaceA));
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
        var signer = await CreateSignerAsync(world);
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
        var signer = await CreateSignerAsync(world);
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
        var signer = await CreateSignerAsync(world);
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
        var signer = await CreateSignerAsync(world);
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
        var sourceSigner = await CreateSignerAsync(source);
        foreach (var name in KeyRef.BackupKeystores)
            exported.Add((name, await sourceSigner.ExportKeyAsync(KeyRef.ForKeystore(name), ExportWrap.ForKeystoreFile(), new SigningContext(Caller, SigningPurpose.Backup, null, null))));

        var target = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(target);
        foreach (var (name, bytes) in exported)
            await signer.ImportKeyAsync(new KeyMaterial(bytes, KeyMaterial.KeystoreFile, Guid.Empty, name), new SigningContext(Caller, SigningPurpose.Restore, null, null));

        Assert.Equal(source.Persistence.KeystoreFiles.Keys.OrderBy(k => k), target.Persistence.KeystoreFiles.Keys.OrderBy(k => k));
        foreach (var name in KeyRef.BackupKeystores)
            Assert.Equal(source.Persistence.KeystoreFiles[name], target.Persistence.KeystoreFiles[name]);
    }

    // ---- Ceremonies: the signer verifies the approval it is told about ----------------------

    /// <summary>Seeds a ceremony row as the control plane writes one, and returns its id. It expires in an hour unless told otherwise.</summary>
    private static Guid SeedCeremony(SignerTestWorld world, string status, Guid? spaceId, string targetEntityId = "", DateTime? expiresAt = null, string operationType = "CreateRootCA", string parametersJson = "{}")
    {
        var id = Guid.NewGuid();
        using var db = world.OpenDb();
        db.KeyCeremonies.Add(new KeyCeremonyEntity
        {
            Id = id,
            OperationType = operationType,
            ParametersJson = parametersJson,
            Description = "signer contract",
            Status = status,
            SpaceId = spaceId,
            TargetEntityId = targetEntityId,
            RequiredApprovals = 1,
            CurrentApprovals = status == "Approved" ? 1 : 0,
            ExpiresAt = expiresAt ?? DateTime.UtcNow.AddHours(1),
        });
        db.SaveChanges();
        return id;
    }

    /// <summary>
    /// Seeds a space as the control plane writes one, with its ceremony requirement as given,
    /// and a CA row in it with no certificate, so a context can name the CA and let the signer
    /// find the space through it. Returns both ids.
    /// </summary>
    private static (Guid SpaceId, Guid CaId) SeedSpace(SignerTestWorld world, bool requireKeyCeremony)
    {
        var spaceId = Guid.NewGuid();
        var caId = Guid.NewGuid();
        using var db = world.OpenDb();
        db.Spaces.Add(new SpaceEntity { Id = spaceId, Name = $"space-{spaceId:N}", Slug = $"space-{spaceId:N}", RequireKeyCeremony = requireKeyCeremony });
        db.CertificateAuthorities.Add(new CertificateAuthorityEntity { Id = caId, Name = "strict", Label = $"strict-{caId:N}", SpaceId = spaceId });
        db.SaveChanges();
        return (spaceId, caId);
    }

    /// <summary>Seeds another CA row, with no certificate, in <paramref name="spaceId"/>'s scope, and returns its id.</summary>
    private static Guid SeedCa(SignerTestWorld world, Guid? spaceId)
    {
        var caId = Guid.NewGuid();
        using var db = world.OpenDb();
        db.CertificateAuthorities.Add(new CertificateAuthorityEntity { Id = caId, Name = "another", Label = $"another-{caId:N}", SpaceId = spaceId });
        db.SaveChanges();
        return caId;
    }

    /// <summary>Moves a world CA to another scope, as the tests that need its key held to a stricter one do.</summary>
    private static void MoveCa(SignerTestWorld world, Guid caId, Guid? spaceId)
    {
        using var db = world.OpenDb();
        db.CertificateAuthorities.Single(c => c.Id == caId).SpaceId = spaceId;
        db.SaveChanges();
    }

    /// <summary>
    /// Seeds a non-CA certificate over a generated key and names it the strict CA's OCSP
    /// responder, so the signer classifies the committed key as a delegated signer of that CA.
    /// </summary>
    private async Task<Guid> SeedGeneratedResponderAsync(SignerTestWorld world, ISigningService signer, GeneratedKey generated, SigningContext context, Guid caId)
    {
        var publicKey = PublicKeyFactory.CreateKey(generated.PublicKeyDer);
        var cert = TypedSigningData.OutsideCertificate(publicKey, new X509Name("CN=Generated Responder, O=ModularCA"), isCa: false);
        var certificateId = Guid.NewGuid();
        using var db = world.OpenDb();
        db.Certificates.Add(new CertificateEntity
        {
            CertificateId = certificateId,
            SerialNumber = cert.SerialNumber.ToString(16).ToUpperInvariant(),
            SubjectDN = cert.SubjectDN.ToString(),
            Issuer = cert.IssuerDN.ToString(),
            IsCA = false,
            RawCertificate = cert.GetEncoded(),
            Pem = "-----BEGIN CERTIFICATE-----\n" + Convert.ToBase64String(cert.GetEncoded()) + "\n-----END CERTIFICATE-----\n",
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter,
        });
        var ca = db.CertificateAuthorities.First(c => c.Id == caId);
        ca.OcspResponderCertificateId = certificateId;
        db.SaveChanges();
        return certificateId;
    }

    [Fact]
    public async Task Infrastructure_keys_of_an_existing_ca_need_no_ceremony_and_never_become_ca_keys()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        var (strictSpace, strictCa) = SeedSpace(world, requireKeyCeremony: true);
        var infrastructure = Context(SigningPurpose.Infrastructure, strictCa, strictSpace);

        // A responder key for a CA of a space that requires ceremonies: generated and committed
        // without one, because reissuing a delegated signer is an operator's action.
        var generated = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), infrastructure);
        var responderId = await SeedGeneratedResponderAsync(world, signer, generated, infrastructure, strictCa);
        await signer.CommitKeyAsync(generated.Key, responderId, infrastructure);
        var listed = Assert.Single(await signer.ListKeysAsync(Context(SigningPurpose.Ocsp, strictCa, strictSpace)), k => k.Key.CertificateId == responderId);
        Assert.Equal(KeyKind.OcspResponder, listed.Kind);
        var publicKey = PublicKeyFactory.CreateKey(generated.PublicKeyDer);
        var algorithm = SignatureAlgorithm.ForPublicKey(publicKey);
        var response = TypedSigningData.OcspResponse(publicKey, world["ca-rsa"].Certificate, algorithm);
        Assert.True(VerifyWith(publicKey, algorithm.Name,
            await signer.SignAsync(new KeyRef(responderId), algorithm, response, Context(SigningPurpose.Ocsp, strictCa, strictSpace)), response));

        // The same context can never turn a generated key into a CA key.
        var second = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), infrastructure);
        var (_, caCertificateId, _) = await SeedGeneratedCaAsync(world, signer, second, infrastructure);
        var asCa = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.CommitKeyAsync(second.Key, caCertificateId, infrastructure));
        Assert.Equal(SigningRefusalReason.PurposeNotPermitted, asCa.Reason);
        Assert.Contains("CA certificate", asCa.Message);

        // Infrastructure keys are generated, never imported, and the context must name a CA.
        var keyless = world["keyless"];
        var import = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.ImportKeyAsync(
            new KeyMaterial((byte[])keyless.PrivateKeyPkcs8.Clone(), KeyMaterial.Pkcs8, keyless.Ref.CertificateId), infrastructure));
        Assert.Equal(SigningRefusalReason.PurposeNotPermitted, import.Reason);
        var committedCa = await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.SignAsync(world["ca-rsa"].Ref, SignatureAlgorithm.ForPublicKey(publicKey), Tbs, Context(SigningPurpose.Infrastructure, world.CaRsaId, world.SpaceA)));
        Assert.Equal(SigningRefusalReason.PurposeNotPermitted, committedCa.Reason);
    }

    /// <summary>
    /// An infrastructure key binds only to a delegated certificate of the CA it was generated
    /// for and the commit names, in that CA's scope: an infrastructure context for CA A cannot
    /// commit a key to CA B's responder certificate.
    /// </summary>
    [Fact]
    public async Task An_infrastructure_key_commits_only_to_the_responder_of_the_ca_the_context_names()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        var (space, caA) = SeedSpace(world, requireKeyCeremony: true);
        var caB = SeedCa(world, space);
        var (otherSpace, _) = SeedSpace(world, requireKeyCeremony: false);
        var forA = Context(SigningPurpose.Infrastructure, caA, space);
        var forB = Context(SigningPurpose.Infrastructure, caB, space);

        async Task Refused(GeneratedKey generated, Guid certificateId, SigningContext context, SigningRefusalReason reason)
        {
            var ex = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.CommitKeyAsync(generated.Key, certificateId, context));
            Assert.Equal(reason, ex.Reason);
        }

        // Generated for CA A: not committed to CA B's responder, whichever CA the commit names.
        var forAKey = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), forA);
        var bResponder = await SeedGeneratedResponderAsync(world, signer, forAKey, forA, caB);
        await Refused(forAKey, bResponder, forA, SigningRefusalReason.CaMismatch);
        await Refused(forAKey, bResponder, forB, SigningRefusalReason.CaMismatch);

        // Generated naming no CA or scope: held to the CA and scope of the certificate at commit.
        var unbound = Context(SigningPurpose.Infrastructure, null, null);
        var unboundKey = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), unbound);
        var bSecondResponder = await SeedGeneratedResponderAsync(world, signer, unboundKey, unbound, caB);
        await Refused(unboundKey, bSecondResponder, forA, SigningRefusalReason.CaMismatch);
        await Refused(unboundKey, bSecondResponder, unbound, SigningRefusalReason.ContextRequired);
        await Refused(unboundKey, bSecondResponder, Context(SigningPurpose.Infrastructure, caB, otherSpace), SigningRefusalReason.TenantMismatch);
        await Refused(unboundKey, bSecondResponder, InstanceContext(SigningPurpose.Infrastructure, caB), SigningRefusalReason.TenantMismatch);
        Assert.Empty(world.Persistence.Appended);

        await signer.CommitKeyAsync(unboundKey.Key, bSecondResponder, forB);
        Assert.Single(world.Persistence.Appended);
        Assert.Contains(await signer.ListKeysAsync(Context(SigningPurpose.Ocsp, caB, space)),
            k => k.Key.CertificateId == bSecondResponder && k.Kind == KeyKind.OcspResponder);
    }

    /// <summary>
    /// The signer's audit records the scope the context stated, so a null space on a row reads
    /// as the instance or as no stated scope, and never as either by guess.
    /// </summary>
    [Fact]
    public async Task The_audit_tells_the_instance_from_no_stated_scope()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        SeedInstance(world, requireKeyCeremony: false);

        await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), InstanceContext(SigningPurpose.Ceremony));
        await Assert.ThrowsAsync<SigningRefusedException>(() => signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), Context(SigningPurpose.Ceremony, null, null)));
        await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), Context(SigningPurpose.Ceremony, null, world.SpaceA));

        var rows = await ReadAuditAsync(world);
        Assert.Equal(3, rows.Count);
        Assert.Contains(rows, r => r.SpaceId == null && r.EffectiveScope == SignerAuditEntity.InstanceScope && r.Outcome == SignerAuditEntity.AllowedOutcome);
        Assert.Contains(rows, r => r.SpaceId == null && r.EffectiveScope == SignerAuditEntity.NoScope && r.Outcome == SignerAuditEntity.RefusedOutcome);
        Assert.Contains(rows, r => r.SpaceId == world.SpaceA && r.EffectiveScope == SignerAuditEntity.SpaceScope);
        Assert.All(rows.Where(r => r.SpaceId != null), r => Assert.True(SignerAuditEntity.IsSpaceScope(r.EffectiveScope)));
        Assert.Equal("space", SignerAuditEntity.SpaceScope);
        Assert.True(SignerAuditEntity.IsSpaceScope(SignerAuditEntity.TenantScope));
        Assert.False(SignerAuditEntity.IsSpaceScope(SignerAuditEntity.InstanceScope));
    }

    [Fact]
    public async Task Key_management_without_a_ceremony_is_refused_where_the_space_requires_one()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        var (strictSpace, strictCa) = SeedSpace(world, requireKeyCeremony: true);
        var keyless = world["keyless"];
        MoveCa(world, world.KeylessCaId, strictSpace);
        KeyMaterial Material() => new((byte[])keyless.PrivateKeyPkcs8.Clone(), KeyMaterial.Pkcs8, keyless.Ref.CertificateId);

        async Task Refused(Func<Task> operation, SigningRefusalReason reason)
        {
            var ex = await Assert.ThrowsAsync<SigningRefusedException>(operation);
            Assert.Equal(reason, ex.Reason);
        }

        // Generation: the space named requires a ceremony; the space of the CA named requires
        // one; a space the signer cannot find has no waiver it can verify; and nothing holds a
        // context with no space, no CA, or a CA the signer does not know.
        foreach (var (context, reason) in new[]
                 {
                     (Context(SigningPurpose.Ceremony, null, strictSpace), SigningRefusalReason.CeremonyRequired),
                     (Context(SigningPurpose.Ceremony, strictCa, null), SigningRefusalReason.CeremonyRequired),
                     (Context(SigningPurpose.Ceremony, null, Guid.NewGuid()), SigningRefusalReason.CeremonyRequired),
                     (Context(SigningPurpose.Ceremony, null, null), SigningRefusalReason.ContextRequired),
                     (Context(SigningPurpose.Ceremony, Guid.NewGuid(), null), SigningRefusalReason.ContextRequired),
                 })
            await Refused(() => signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), context), reason);

        // An import is held to the scope of the CA that owns the certificate: that scope's
        // requirement applies whether the context states it, names a CA in it, or states nothing,
        // and a context that states another scope is refused as that, whatever its own policy.
        foreach (var (context, reason) in new[]
                 {
                     (Context(SigningPurpose.Ceremony, null, strictSpace), SigningRefusalReason.CeremonyRequired),
                     (Context(SigningPurpose.Ceremony, strictCa, null), SigningRefusalReason.CeremonyRequired),
                     (Context(SigningPurpose.Ceremony, null, null), SigningRefusalReason.CeremonyRequired),
                     (Context(SigningPurpose.Ceremony, null, world.SpaceA), SigningRefusalReason.TenantMismatch),
                     (Context(SigningPurpose.Ceremony, null, Guid.NewGuid()), SigningRefusalReason.TenantMismatch),
                     (InstanceContext(SigningPurpose.Ceremony), SigningRefusalReason.TenantMismatch),
                     (Context(SigningPurpose.Ceremony, Guid.NewGuid(), null), SigningRefusalReason.ContextRequired),
                 })
            await Refused(() => signer.ImportKeyAsync(Material(), context), reason);

        // Under an approved ceremony of that space the same operations go through, and a key
        // generated under it is not committed without it.
        var approved = Context(SigningPurpose.Ceremony, null, strictSpace) with { CeremonyId = SeedCeremony(world, "Approved", strictSpace) };
        var generated = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), approved);
        var (_, certificateId, _) = await SeedGeneratedCaAsync(world, signer, generated, approved);
        var commit = await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.CommitKeyAsync(generated.Key, certificateId, Context(SigningPurpose.Ceremony, null, strictSpace)));
        Assert.Equal(SigningRefusalReason.CeremonyRequired, commit.Reason);
        Assert.Empty(world.Persistence.Appended);

        await signer.CommitKeyAsync(generated.Key, certificateId, approved);
        Assert.Equal(keyless.Ref, await signer.ImportKeyAsync(Material(), approved));
        Assert.Equal(2, world.Persistence.Appended.Count);

        var refused = (await ReadAuditAsync(world)).Where(r => r.Outcome == SignerAuditEntity.RefusedOutcome).ToList();
        Assert.Equal(13, refused.Count);
        Assert.All(refused, r => Assert.Null(r.CeremonyId));
        Assert.All(refused, r => Assert.Contains("ceremony", r.Reason, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// An instance CA (no space, as the system signing CA and SSH CAs are after 0.4.0 S3) is held
    /// to the instance's own policy, never refused as having no context and never waved through as
    /// having no policy.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task An_instance_ca_is_held_to_the_instance_policy(bool instanceRequiresCeremony)
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        var instanceCa = SeedInstance(world, instanceRequiresCeremony);

        var byCa = Context(SigningPurpose.Ceremony, instanceCa, null);
        var stated = InstanceContext(SigningPurpose.Ceremony);
        if (instanceRequiresCeremony)
        {
            foreach (var context in new[] { byCa, stated })
            {
                var refused = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), context));
                Assert.Equal(SigningRefusalReason.CeremonyRequired, refused.Reason);
                Assert.Contains("instance", refused.Message);
            }

            var approvedId = SeedCeremony(world, "Approved", null);
            var byCaApproved = byCa with { CeremonyId = approvedId };
            var retired = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), byCaApproved);
            await signer.RetireKeyAsync(retired.Key, byCaApproved);

            var approved = stated with { CeremonyId = approvedId };
            var generated = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), approved);
            var (_, certificateId, _) = await SeedGeneratedCaAsync(world, signer, generated, approved);
            var unapproved = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.CommitKeyAsync(generated.Key, certificateId, stated));
            Assert.Equal(SigningRefusalReason.CeremonyRequired, unapproved.Reason);
            await signer.CommitKeyAsync(generated.Key, certificateId, approved);
        }
        else
        {
            var byCaKey = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), byCa);
            await signer.RetireKeyAsync(byCaKey.Key, byCa);
            var generated = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), stated);
            var (_, certificateId, _) = await SeedGeneratedCaAsync(world, signer, generated, stated);
            await signer.CommitKeyAsync(generated.Key, certificateId, stated);
        }
    }

    /// <summary>
    /// A ceremony context with no space, no instance marker and no CA states no scope. That is
    /// what an older client sends, and it is never read as the instance, whatever the instance's
    /// policy or a ceremony it names; a context that states both scopes is refused too.
    /// </summary>
    [Fact]
    public async Task A_ceremony_context_that_states_no_scope_is_refused_even_where_the_instance_waives_ceremonies()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        SeedInstance(world, requireKeyCeremony: false);
        var instanceCeremony = SeedCeremony(world, "Approved", null);

        foreach (var context in new[]
                 {
                     Context(SigningPurpose.Ceremony, null, null),
                     Context(SigningPurpose.Ceremony, null, null) with { CeremonyId = instanceCeremony },
                     Context(SigningPurpose.Ceremony, null, world.SpaceA) with { InstanceScope = true },
                 })
        {
            var refused = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), context));
            Assert.Equal(SigningRefusalReason.ContextRequired, refused.Reason);
        }
        Assert.All(await ReadAuditAsync(world), r => Assert.Equal(SignerAuditEntity.RefusedOutcome, r.Outcome));
    }

    /// <summary>
    /// A ceremony licenses key operations in exactly its own scope, null equal only to null, and
    /// only when it is a ceremony that manages a key; a key generated in one scope is not
    /// committed or retired from another.
    /// </summary>
    [Fact]
    public async Task A_ceremony_does_not_cross_scopes_or_operations()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        SeedInstance(world, requireKeyCeremony: true);
        var spaceACeremony = SeedCeremony(world, "Approved", world.SpaceA);
        var instanceCeremony = SeedCeremony(world, "Approved", null);
        var revocation = SeedCeremony(world, "Approved", null, operationType: "RevokeCa");

        async Task NotApproved(SigningContext context)
        {
            var ex = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), context));
            Assert.Equal(SigningRefusalReason.CeremonyNotApproved, ex.Reason);
        }
        await NotApproved(InstanceContext(SigningPurpose.Ceremony) with { CeremonyId = spaceACeremony });
        await NotApproved(Context(SigningPurpose.Ceremony, null, world.SpaceA) with { CeremonyId = instanceCeremony });
        await NotApproved(Context(SigningPurpose.Ceremony, world.CaRsaId, null) with { CeremonyId = instanceCeremony });
        await NotApproved(InstanceContext(SigningPurpose.Ceremony) with { CeremonyId = revocation });

        var instanceKey = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), InstanceContext(SigningPurpose.Ceremony) with { CeremonyId = instanceCeremony });
        var inSpaceA = Context(SigningPurpose.Ceremony, null, world.SpaceA) with { CeremonyId = spaceACeremony };
        var retire = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.RetireKeyAsync(instanceKey.Key, inSpaceA));
        Assert.Equal(SigningRefusalReason.TenantMismatch, retire.Reason);
        var (_, certificateId, _) = await SeedGeneratedCaAsync(world, signer, instanceKey, InstanceContext(SigningPurpose.Ceremony) with { CeremonyId = instanceCeremony });
        var commit = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.CommitKeyAsync(instanceKey.Key, certificateId, inSpaceA));
        Assert.Equal(SigningRefusalReason.TenantMismatch, commit.Reason);
        Assert.Empty(world.Persistence.Appended);
    }

    /// <summary>
    /// A commit is held to the policy of the CA that owns the certificate, not to the scope the
    /// committing context states: a key generated where ceremonies are waived is not committed
    /// to a certificate of a CA whose scope requires one, and a context that states no scope is
    /// held to the owning CA's.
    /// </summary>
    [Fact]
    public async Task A_commit_is_held_to_the_policy_of_the_ca_that_owns_the_certificate()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        var (strict, _) = SeedSpace(world, requireKeyCeremony: true);
        var (waived, _) = SeedSpace(world, requireKeyCeremony: false);

        var byWaived = Context(SigningPurpose.Ceremony, null, waived);
        var smuggled = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), byWaived);
        var (_, strictCertificate, _) = await SeedGeneratedCaAsync(world, signer, smuggled, byWaived, (strict, true));
        var mismatch = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.CommitKeyAsync(smuggled.Key, strictCertificate, byWaived));
        Assert.Equal(SigningRefusalReason.TenantMismatch, mismatch.Reason);

        var strictCeremony = SeedCeremony(world, "Approved", strict);
        var approved = Context(SigningPurpose.Ceremony, null, strict) with { CeremonyId = strictCeremony };
        var generated = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), approved);
        var (_, certificateId, _) = await SeedGeneratedCaAsync(world, signer, generated, approved);
        var unstated = Context(SigningPurpose.Ceremony, null, null);
        var required = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.CommitKeyAsync(generated.Key, certificateId, unstated));
        Assert.Equal(SigningRefusalReason.CeremonyRequired, required.Reason);
        Assert.Empty(world.Persistence.Appended);

        await signer.CommitKeyAsync(generated.Key, certificateId, unstated with { CeremonyId = strictCeremony });
        Assert.Single(world.Persistence.Appended);
    }

    /// <summary>Seeds the instance's policy row and an instance CA (no space), and returns the CA's id.</summary>
    private static Guid SeedInstance(SignerTestWorld world, bool requireKeyCeremony)
    {
        var instanceCa = Guid.NewGuid();
        using var db = world.OpenDb();
        db.SecurityPolicies.Add(new SecurityPolicyEntity { RequireKeyCeremony = requireKeyCeremony });
        db.CertificateAuthorities.Add(new CertificateAuthorityEntity { Id = instanceCa, Name = "System Signing CA", Label = $"system-signing-ca-{instanceCa:N}", SpaceId = null });
        db.SaveChanges();
        return instanceCa;
    }

    /// <summary>A context that states the instance as its scope.</summary>
    private static SigningContext InstanceContext(SigningPurpose purpose, Guid? caId = null)
        => Context(purpose, caId, null) with { InstanceScope = true };

    [Fact]
    public async Task A_space_that_does_not_require_ceremonies_manages_keys_without_one()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        var (waived, waivedCa) = SeedSpace(world, requireKeyCeremony: false);

        // Named by space, and named only by a CA the signer resolves the space through.
        var bySpace = Context(SigningPurpose.Ceremony, null, waived);
        var generated = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), bySpace);
        var (_, certificateId, _) = await SeedGeneratedCaAsync(world, signer, generated, bySpace);
        await signer.CommitKeyAsync(generated.Key, certificateId, bySpace);
        var byCa = Context(SigningPurpose.Ceremony, waivedCa, null);
        var second = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), byCa);
        await signer.RetireKeyAsync(second.Key, byCa);

        var keyless = world["keyless"];
        Assert.Equal(keyless.Ref, await signer.ImportKeyAsync(
            new KeyMaterial((byte[])keyless.PrivateKeyPkcs8.Clone(), KeyMaterial.Pkcs8, keyless.Ref.CertificateId),
            Context(SigningPurpose.Ceremony, world.KeylessCaId, world.SpaceA)));

        var rows = await ReadAuditAsync(world);
        Assert.All(rows, r => Assert.Equal(SignerAuditEntity.AllowedOutcome, r.Outcome));
        Assert.All(rows, r => Assert.Null(r.CeremonyId));
        Assert.Equal(2, world.Persistence.Appended.Count);
    }

    [Fact]
    public async Task Every_decision_under_a_ceremony_records_the_ceremony_it_was_told()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        var approvedId = SeedCeremony(world, "Approved", world.SpaceA);
        var approved = Context(SigningPurpose.Ceremony, null, world.SpaceA) with { CeremonyId = approvedId };

        var generated = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), approved);
        var (_, certificateId, _) = await SeedGeneratedCaAsync(world, signer, generated, approved);
        await signer.CommitKeyAsync(generated.Key, certificateId, approved);
        var keyless = world["keyless"];
        await signer.ImportKeyAsync(
            new KeyMaterial((byte[])keyless.PrivateKeyPkcs8.Clone(), KeyMaterial.Pkcs8, keyless.Ref.CertificateId),
            Context(SigningPurpose.Ceremony, world.KeylessCaId, world.SpaceA) with { CeremonyId = approvedId });

        var rows = await ReadAuditAsync(world);
        Assert.Contains(rows, r => r.Operation == "GenerateKey");
        Assert.Contains(rows, r => r.Operation == "Sign");
        Assert.Contains(rows, r => r.Operation == "CommitKey");
        Assert.Contains(rows, r => r.Operation == "ImportKey");
        Assert.All(rows, r => Assert.Equal(SignerAuditEntity.AllowedOutcome, r.Outcome));
        Assert.All(rows, r => Assert.Equal(approvedId, r.CeremonyId));

        // A refusal records the ceremony it could not verify, so the record says what was claimed.
        var missing = Guid.NewGuid();
        await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), approved with { CeremonyId = missing }));
        var last = (await ReadAuditAsync(world)).Last();
        Assert.Equal(SignerAuditEntity.RefusedOutcome, last.Outcome);
        Assert.Equal(missing, last.CeremonyId);
    }

    [Fact]
    public async Task Every_decision_records_the_peer_the_signer_admitted()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);

        await signer.SignAsync(world["ca-rsa"].Ref, AlgorithmFor(world, "ca-rsa"), Typed(world, "ca-rsa", SigningPurpose.Certificate), ContextFor(world, "ca-rsa", SigningPurpose.Certificate));
        await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.SignAsync(world["ca-rsa"].Ref, AlgorithmFor(world, "ca-rsa"), Tbs, Context(SigningPurpose.Certificate, world.CaEcId, world.SpaceB)));
        await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), Context(SigningPurpose.Ceremony, null, world.SpaceA));

        var rows = await ReadAuditAsync(world);
        Assert.Equal(3, rows.Count);
        Assert.All(rows, r => Assert.Equal(ExpectedPeerIdentity, r.PeerIdentity));
    }

    [Fact]
    public async Task Keys_are_generated_committed_and_imported_under_a_ceremony_the_signer_verified()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        var approved = SeedCeremony(world, "Approved", world.SpaceA);
        var ceremony = Context(SigningPurpose.Ceremony, null, world.SpaceA) with { CeremonyId = approved };

        var generated = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), ceremony);
        var (_, certificateId, caId) = await SeedGeneratedCaAsync(world, signer, generated, ceremony);
        await signer.CommitKeyAsync(generated.Key, certificateId, ceremony);
        Assert.Contains(await signer.ListKeysAsync(Context(SigningPurpose.Ceremony, caId, world.SpaceA)), k => k.Key.CertificateId == certificateId);

        var keyless = world["keyless"];
        var imported = await signer.ImportKeyAsync(
            new KeyMaterial((byte[])keyless.PrivateKeyPkcs8.Clone(), KeyMaterial.Pkcs8, keyless.Ref.CertificateId),
            Context(SigningPurpose.Ceremony, world.KeylessCaId, world.SpaceA) with { CeremonyId = approved });
        Assert.Equal(keyless.Ref, imported);
    }

    /// <summary>
    /// The ceremonies the signer cannot verify: none by that id, one not approved in any of its
    /// other states, one approved but past its expiry, one approved for another space, one
    /// targeting another CA.
    /// </summary>
    public static IEnumerable<object[]> UnverifiableCeremonyRows()
    {
        yield return new object[] { "missing" };
        yield return new object[] { "expired-by-time" };
        yield return new object[] { "Pending" };
        yield return new object[] { "Rejected" };
        yield return new object[] { "Executed" };
        yield return new object[] { "Expired" };
        yield return new object[] { "Cancelled" };
        yield return new object[] { "other-space" };
        yield return new object[] { "other-ca" };
    }

    [Theory]
    [MemberData(nameof(UnverifiableCeremonyRows))]
    public async Task Key_management_under_a_ceremony_the_signer_cannot_verify_is_refused(string kind)
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        var ceremonyId = kind switch
        {
            "missing" => Guid.NewGuid(),
            "expired-by-time" => SeedCeremony(world, "Approved", world.SpaceA, expiresAt: DateTime.UtcNow.AddMinutes(-1)),
            "other-space" => SeedCeremony(world, "Approved", world.SpaceB),
            "other-ca" => SeedCeremony(world, "Approved", world.SpaceA, world.CaEcId.ToString()),
            _ => SeedCeremony(world, kind, world.SpaceA),
        };
        var caId = kind == "other-ca" ? world.CaRsaId : (Guid?)null;
        var context = Context(SigningPurpose.Ceremony, caId, world.SpaceA) with { CeremonyId = ceremonyId };

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
        var approved = Context(SigningPurpose.Ceremony, caId, world.SpaceA) with { CeremonyId = SeedCeremony(world, "Approved", world.SpaceA) };
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

    private static readonly byte[] WrappableSecret = Encoding.UTF8.GetBytes("a-cmp-pbmac-shared-secret-0123456789");

    [Fact]
    public async Task A_wrapped_secret_comes_back_and_the_blob_never_holds_it()
    {
        var signer = await CreateSignerAsync(SharedWorld);
        var context = Context(SigningPurpose.Cmp, null, null);

        var blob = await signer.WrapSecretAsync(SecretKind.CmpSharedSecret, WrappableSecret, context);

        Assert.NotEqual(WrappableSecret, blob);
        Assert.DoesNotContain(Convert.ToHexStringLower(WrappableSecret), Convert.ToHexStringLower(blob));
        Assert.Equal(WrappableSecret, await signer.UnwrapSecretAsync(blob, context));

        // Two wraps of the same secret differ: the salt and the nonce are per blob.
        Assert.NotEqual(blob, await signer.WrapSecretAsync(SecretKind.CmpSharedSecret, WrappableSecret, context));
    }

    [Fact]
    public async Task A_wrapped_secret_names_its_kind_and_the_key_that_wrapped_it()
    {
        var world = SharedWorld;
        var signer = await CreateSignerAsync(world);

        var blob = await signer.WrapSecretAsync(SecretKind.CmpSharedSecret, WrappableSecret, Context(SigningPurpose.Cmp, null, null));

        Assert.True(WrappedSecretEnvelope.TryRead(blob, out var header));
        Assert.Equal(SecretKind.CmpSharedSecret, header.Kind);
        Assert.Equal(WrappedSecretEnvelope.KeyIdLength, header.KeyId.Length);
        Assert.NotEqual(new byte[WrappedSecretEnvelope.KeyIdLength], header.KeyId);

        // The id is the SPKI digest of a key the signer actually holds, which is what makes a
        // rotation resolvable: the blob is unwrapped by the key it names, not by the current one.
        var held = world.Keystore.GetSigners()
            .Select(s => SHA256.HashData(SubjectPublicKeyInfoFactory
                .CreateSubjectPublicKeyInfo(s.PublicCertificate.GetPublicKey()).GetDerEncoded()))
            .ToList();
        Assert.Contains(held, id => id.AsSpan().SequenceEqual(header.KeyId));
    }

    [Fact]
    public async Task A_blob_whose_key_id_the_signer_does_not_hold_is_refused_rather_than_failing_to_decrypt()
    {
        var signer = await CreateSignerAsync(SharedWorld);
        var context = Context(SigningPurpose.Cmp, null, null);
        var blob = await signer.WrapSecretAsync(SecretKind.CmpSharedSecret, WrappableSecret, context);

        // What a blob written under a key that has since left the keystore looks like.
        RandomNumberGenerator.Fill(blob.AsSpan(6, WrappedSecretEnvelope.KeyIdLength));

        var ex = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.UnwrapSecretAsync(blob, context));
        Assert.Equal(SigningRefusalReason.UnknownKey, ex.Reason);
    }

    [Fact]
    public async Task Only_the_purposes_the_policy_names_wrap_a_kind()
    {
        var signer = await CreateSignerAsync(SharedWorld);

        await signer.WrapSecretAsync(SecretKind.CmpSharedSecret, WrappableSecret, Context(SigningPurpose.Cmp, null, null));
        await signer.WrapSecretAsync(SecretKind.HeldPrivateKey, WrappableSecret, Context(SigningPurpose.Certificate, null, null));

        async Task Refused(SecretKind kind, SigningPurpose purpose)
        {
            var ex = await Assert.ThrowsAsync<SigningRefusedException>(
                () => signer.WrapSecretAsync(kind, WrappableSecret, Context(purpose, null, null)));
            Assert.Equal(SigningRefusalReason.PurposeNotPermitted, ex.Reason);
        }

        // Each purpose wraps its own kind and no other, and most purposes wrap nothing.
        await Refused(SecretKind.HeldPrivateKey, SigningPurpose.Cmp);
        await Refused(SecretKind.CmpSharedSecret, SigningPurpose.Certificate);
        await Refused(SecretKind.CmpSharedSecret, SigningPurpose.Export);
        foreach (var purpose in new[] { SigningPurpose.Ocsp, SigningPurpose.Crl, SigningPurpose.Backup, SigningPurpose.Ceremony, SigningPurpose.Bootstrap })
            await Refused(SecretKind.CmpSharedSecret, purpose);

        // A Kerberos realm key has no purpose at all until the design says how it is cached.
        foreach (var purpose in Enum.GetValues<SigningPurpose>())
            await Refused(SecretKind.KerberosRealmKey, purpose);
    }

    [Fact]
    public async Task A_caller_that_may_unwrap_one_kind_cannot_unwrap_another()
    {
        var signer = await CreateSignerAsync(SharedWorld);
        var cmp = Context(SigningPurpose.Cmp, null, null);
        var issuance = Context(SigningPurpose.Certificate, null, null);
        var export = Context(SigningPurpose.Export, null, null);

        var cmpSecret = await signer.WrapSecretAsync(SecretKind.CmpSharedSecret, WrappableSecret, cmp);
        var heldKey = await signer.WrapSecretAsync(SecretKind.HeldPrivateKey, WrappableSecret, issuance);

        // What each may read.
        Assert.Equal(WrappableSecret, await signer.UnwrapSecretAsync(cmpSecret, cmp));
        Assert.Equal(WrappableSecret, await signer.UnwrapSecretAsync(heldKey, export));

        async Task Refused(byte[] blob, SigningContext context)
        {
            var ex = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.UnwrapSecretAsync(blob, context));
            Assert.Equal(SigningRefusalReason.PurposeNotPermitted, ex.Reason);
        }

        // And what neither may: the CMP caller cannot read a held private key, and the issuance
        // path that wrote one cannot read it back, which is the export right and a person's.
        await Refused(heldKey, cmp);
        await Refused(heldKey, issuance);
        await Refused(cmpSecret, export);
    }

    /// <summary>
    /// A backup wraps the configuration secrets its archive carries (the Data Protection key
    /// ring, the SSH CA keys) and only a restore reads them back: the backup that wrote one
    /// cannot, and no other purpose wraps or reads that kind.
    /// </summary>
    [Fact]
    public async Task A_backup_wraps_its_configuration_secrets_and_only_a_restore_reads_them_back()
    {
        var signer = await CreateSignerAsync(SharedWorld);
        var backup = Context(SigningPurpose.Backup, null, null);
        var restore = Context(SigningPurpose.Restore, null, null);

        var blob = await signer.WrapSecretAsync(SecretKind.BackupConfigSecret, WrappableSecret, backup);
        Assert.DoesNotContain(Convert.ToHexStringLower(WrappableSecret), Convert.ToHexStringLower(blob));
        Assert.Equal(WrappableSecret, await signer.UnwrapSecretAsync(blob, restore));

        foreach (var purpose in Enum.GetValues<SigningPurpose>().Where(p => p != SigningPurpose.Restore))
        {
            var ex = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.UnwrapSecretAsync(blob, Context(purpose, null, null)));
            Assert.Equal(SigningRefusalReason.PurposeNotPermitted, ex.Reason);
        }
        foreach (var purpose in Enum.GetValues<SigningPurpose>().Where(p => p != SigningPurpose.Backup))
        {
            var ex = await Assert.ThrowsAsync<SigningRefusedException>(
                () => signer.WrapSecretAsync(SecretKind.BackupConfigSecret, WrappableSecret, Context(purpose, null, null)));
            Assert.Equal(SigningRefusalReason.PurposeNotPermitted, ex.Reason);
        }
        var other = await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.WrapSecretAsync(SecretKind.HeldPrivateKey, WrappableSecret, backup));
        Assert.Equal(SigningRefusalReason.PurposeNotPermitted, other.Reason);
    }

    [Fact]
    public async Task A_blob_relabelled_as_another_kind_does_not_authenticate()
    {
        var signer = await CreateSignerAsync(SharedWorld);
        var blob = await signer.WrapSecretAsync(SecretKind.CmpSharedSecret, WrappableSecret, Context(SigningPurpose.Cmp, null, null));

        // The kind is in the associated data and in the key derivation, so relabelling a blob to
        // a kind the caller may read does not make it readable: the policy would now allow it and
        // the cryptography still refuses.
        blob[5] = (byte)SecretKind.HeldPrivateKey;

        var ex = await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.UnwrapSecretAsync(blob, Context(SigningPurpose.Export, null, null)));
        Assert.Equal(SigningRefusalReason.IntegrityFailure, ex.Reason);
    }

    [Fact]
    public async Task A_setting_secret_is_wrapped_for_its_setting_and_comes_back_only_there()
    {
        var signer = await CreateSignerAsync(SharedWorld);
        var context = Context(SigningPurpose.Configuration, null, null);

        var blob = await signer.WrapBoundSecretAsync(SecretKind.SettingSecret, "setting:JWT_Secret", WrappableSecret, context);

        Assert.True(WrappedSecretEnvelope.TryRead(blob, out var header));
        Assert.Equal((SecretKind.SettingSecret, "setting:JWT_Secret"), (header.Kind, header.Binding));
        Assert.Equal(WrappedSecretEnvelope.Version2, blob[4]);
        Assert.DoesNotContain(Convert.ToHexStringLower(WrappableSecret), Convert.ToHexStringLower(blob));
        Assert.Equal(WrappableSecret, await signer.UnwrapBoundSecretAsync(blob, "setting:JWT_Secret", context));

        // The same blob read from another setting's row, which is what copying it there would be.
        var moved = await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.UnwrapBoundSecretAsync(blob, "setting:LdapAuth_BindPassword", context));
        Assert.Equal(SigningRefusalReason.IntegrityFailure, moved.Reason);

        // And asked for as a secret that belongs nowhere.
        var unnamed = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.UnwrapSecretAsync(blob, context));
        Assert.Equal(SigningRefusalReason.OperationUnsupported, unnamed.Reason);
    }

    [Fact]
    public async Task A_blob_whose_binding_was_rewritten_does_not_authenticate()
    {
        var signer = await CreateSignerAsync(SharedWorld);
        var context = Context(SigningPurpose.Configuration, null, null);
        var blob = await signer.WrapBoundSecretAsync(SecretKind.SettingSecret, "setting:Email_Password", WrappableSecret, context);

        // The binding sits in the clear in the header. Editing it to the row the blob was moved
        // to makes the names agree, and the decryption still refuses: the binding is in the
        // associated data and in the key derivation.
        var rewritten = Encoding.ASCII.GetBytes("setting:Email_Passw0rd");
        Assert.Equal(Encoding.ASCII.GetByteCount("setting:Email_Password"), rewritten.Length);
        rewritten.CopyTo(blob, WrappedSecretEnvelope.HeaderLength + 2);

        var ex = await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.UnwrapBoundSecretAsync(blob, "setting:Email_Passw0rd", context));
        Assert.Equal(SigningRefusalReason.IntegrityFailure, ex.Reason);
    }

    [Fact]
    public async Task Only_the_configuration_purpose_handles_setting_secrets_and_it_handles_nothing_else()
    {
        var signer = await CreateSignerAsync(SharedWorld);
        var configuration = Context(SigningPurpose.Configuration, null, null);
        var blob = await signer.WrapBoundSecretAsync(SecretKind.SettingSecret, "setting:JWT_Secret", WrappableSecret, configuration);

        foreach (var purpose in new[] { SigningPurpose.Cmp, SigningPurpose.Certificate, SigningPurpose.Backup, SigningPurpose.Restore, SigningPurpose.Export })
        {
            var wrap = await Assert.ThrowsAsync<SigningRefusedException>(
                () => signer.WrapBoundSecretAsync(SecretKind.SettingSecret, "setting:JWT_Secret", WrappableSecret, Context(purpose, null, null)));
            Assert.Equal(SigningRefusalReason.PurposeNotPermitted, wrap.Reason);
            var unwrap = await Assert.ThrowsAsync<SigningRefusedException>(
                () => signer.UnwrapBoundSecretAsync(blob, "setting:JWT_Secret", Context(purpose, null, null)));
            Assert.Equal(SigningRefusalReason.PurposeNotPermitted, unwrap.Reason);
        }

        var otherKind = await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.WrapSecretAsync(SecretKind.CmpSharedSecret, WrappableSecret, configuration));
        Assert.Equal(SigningRefusalReason.PurposeNotPermitted, otherKind.Reason);
    }

    [Fact]
    public async Task A_setting_secret_is_never_wrapped_without_a_binding_and_other_kinds_never_with_one()
    {
        var signer = await CreateSignerAsync(SharedWorld);

        var unbound = await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.WrapSecretAsync(SecretKind.SettingSecret, WrappableSecret, Context(SigningPurpose.Configuration, null, null)));
        Assert.Equal(SigningRefusalReason.OperationUnsupported, unbound.Reason);

        var bound = await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.WrapBoundSecretAsync(SecretKind.CmpSharedSecret, "token:1", WrappableSecret, Context(SigningPurpose.Cmp, null, null)));
        Assert.Equal(SigningRefusalReason.OperationUnsupported, bound.Reason);

        var tooLong = await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.WrapBoundSecretAsync(SecretKind.SettingSecret, new string('k', WrappedSecretEnvelope.MaxBindingLength + 1),
                WrappableSecret, Context(SigningPurpose.Configuration, null, null)));
        Assert.Equal(SigningRefusalReason.OperationUnsupported, tooLong.Reason);
    }

    [Fact]
    public async Task A_tampered_or_malformed_blob_is_refused()
    {
        var signer = await CreateSignerAsync(SharedWorld);
        var context = Context(SigningPurpose.Cmp, null, null);
        var blob = await signer.WrapSecretAsync(SecretKind.CmpSharedSecret, WrappableSecret, context);

        var flipped = (byte[])blob.Clone();
        flipped[^1] ^= 0xFF;
        var tampered = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.UnwrapSecretAsync(flipped, context));
        Assert.Equal(SigningRefusalReason.IntegrityFailure, tampered.Reason);

        foreach (var nonsense in new[] { Array.Empty<byte>(), new byte[] { 1, 2, 3 }, Encoding.ASCII.GetBytes("not a wrapped secret at all, but long enough to be one") })
        {
            var ex = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.UnwrapSecretAsync(nonsense, context));
            Assert.Equal(SigningRefusalReason.OperationUnsupported, ex.Reason);
        }
    }

    [Fact]
    public async Task A_wrap_and_an_unwrap_are_audited_with_the_kind_the_wrapping_key_and_the_hash_of_the_blob()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        var context = Context(SigningPurpose.Cmp, world.CaRsaId, world.SpaceA);

        var blob = await signer.WrapSecretAsync(SecretKind.CmpSharedSecret, WrappableSecret, context);
        await signer.UnwrapSecretAsync(blob, context);

        Assert.True(WrappedSecretEnvelope.TryRead(blob, out var header));
        var rows = await ReadAuditAsync(world);
        Assert.Equal(new[] { "WrapSecret", "UnwrapSecret" }, rows.Select(r => r.Operation));
        Assert.All(rows, row =>
        {
            Assert.Equal(SignerAuditEntity.AllowedOutcome, row.Outcome);
            Assert.Equal(Caller, row.Caller);
            Assert.Equal(nameof(SigningPurpose.Cmp), row.Purpose);
            Assert.Equal(world.CaRsaId, row.CaId);
            Assert.Equal(world.SpaceA, row.SpaceId);
            Assert.Equal(ExpectedPeerIdentity, row.PeerIdentity);
            Assert.Equal(nameof(SecretKind.CmpSharedSecret), row.SecretKind);
            Assert.Equal(WrappedSecretEnvelope.KeyIdText(header.KeyId), row.WrappingKeyId);
            // The hash is of the blob, never of the secret: an audit row must not be an oracle
            // for the thing the wrap exists to protect.
            Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(blob)), row.DataHash);
            Assert.NotEqual(Convert.ToHexStringLower(SHA256.HashData(WrappableSecret)), row.DataHash);
            Assert.Null(row.KeyCertificateId);
        });
    }

    [Fact]
    public async Task A_refused_unwrap_is_audited_with_what_it_was_told()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        var blob = await signer.WrapSecretAsync(SecretKind.HeldPrivateKey, WrappableSecret, Context(SigningPurpose.Certificate, null, null));

        await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.UnwrapSecretAsync(blob, Context(SigningPurpose.Cmp, null, null)));

        Assert.True(WrappedSecretEnvelope.TryRead(blob, out var header));
        var row = (await ReadAuditAsync(world)).Last();
        Assert.Equal("UnwrapSecret", row.Operation);
        Assert.Equal(SignerAuditEntity.RefusedOutcome, row.Outcome);
        Assert.Equal(nameof(SecretKind.HeldPrivateKey), row.SecretKind);
        Assert.Equal(WrappedSecretEnvelope.KeyIdText(header.KeyId), row.WrappingKeyId);
        Assert.Contains("does not unwrap", row.Reason);
    }

    // ------------------------------------------------------------------ Typed signing

    /// <summary>
    /// A named structure, built for <paramref name="key"/> where it names an issuer, responder or
    /// algorithm, so that only the structure itself is wrong when it is offered under another purpose.
    /// </summary>
    private static byte[] Structure(SignerTestWorld world, string key, string name)
    {
        var k = world[key];
        var algorithm = AlgorithmFor(world, key);
        return name switch
        {
            "tbs" => TypedSigningData.Certificate(k.Certificate.SubjectDN, LeafKey.Public, algorithm),
            "crl" => TypedSigningData.Crl(k.Certificate.SubjectDN, algorithm),
            "ocsp" => TypedSigningData.OcspResponse(k.PublicKey, world["ca-rsa"].Certificate, algorithm),
            "scep" => TypedSigningData.ScepAttributes(),
            "tsa" => TypedSigningData.TimestampAttributes(),
            "cmp" => TypedSigningData.CmpProtectedPart(algorithm),
            "csr" => TypedSigningData.CertificationRequest(k.PublicKey),
            "v1" => TypedSigningData.V1Certificate(k.Certificate.SubjectDN, LeafKey.Public, algorithm),
            "trailing" => TypedSigningData.Certificate(k.Certificate.SubjectDN, LeafKey.Public, algorithm).Concat(new byte[] { 0 }).ToArray(),
            "ssh" => SshCertificateBlob,
            _ => Tbs,
        };
    }

    /// <summary>The start of an OpenSSH certificate blob: a length-prefixed key type name.</summary>
    private static readonly byte[] SshCertificateBlob =
        new byte[] { 0, 0, 0, 32 }.Concat(Encoding.ASCII.GetBytes("ssh-ed25519-cert-v01@openssh.com")).Concat(new byte[64]).ToArray();

    /// <summary>
    /// Every purpose signs one structure and nothing else: the key, purpose and CA are ones the
    /// policy table allows, and only the bytes are wrong, so the refusal is the typing's.
    /// </summary>
    public static IEnumerable<object[]> WrongStructureRows()
    {
        foreach (var s in new[] { "crl", "ocsp", "scep", "tsa", "cmp", "csr", "junk", "v1", "trailing", "ssh" })
            yield return new object[] { "ca-rsa", SigningPurpose.Certificate, s };
        foreach (var s in new[] { "tbs", "ocsp", "cmp", "junk", "ssh" })
            yield return new object[] { "ca-rsa", SigningPurpose.Crl, s };
        foreach (var s in new[] { "tbs", "crl", "cmp", "scep", "junk" })
            yield return new object[] { "ca-rsa", SigningPurpose.Ocsp, s };
        foreach (var s in new[] { "tbs", "crl", "ocsp", "tsa", "junk" })
            yield return new object[] { "ca-rsa", SigningPurpose.Scep, s };
        foreach (var s in new[] { "tbs", "crl", "ocsp", "scep", "junk", "ssh" })
            yield return new object[] { "ca-ec", SigningPurpose.Cmp, s };
        foreach (var s in new[] { "tbs", "crl", "junk" })
            yield return new object[] { "ocsp", SigningPurpose.Ocsp, s };
        foreach (var s in new[] { "tbs", "scep", "ocsp", "junk" })
            yield return new object[] { "tsa", SigningPurpose.Tsa, s };
        foreach (var s in new[] { "tbs", "ocsp", "junk" })
            yield return new object[] { "cmp", SigningPurpose.Cmp, s };
    }

    [Theory]
    [MemberData(nameof(WrongStructureRows))]
    public async Task A_purpose_signs_only_its_own_structure(string key, SigningPurpose purpose, string structure)
    {
        var world = SharedWorld;
        var signer = await CreateSignerAsync(world);

        var ex = await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.SignAsync(world[key].Ref, AlgorithmFor(world, key), Structure(world, key, structure), ContextFor(world, key, purpose)));

        Assert.Equal(SigningRefusalReason.UntypedData, ex.Reason);
    }

    [Fact]
    public async Task A_typed_refusal_is_audited_with_its_reason_and_the_hash_of_what_was_offered()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        var tbs = Structure(world, "ca-rsa", "tbs");

        await Assert.ThrowsAsync<SigningRefusedException>(
            () => signer.SignAsync(world["ca-rsa"].Ref, AlgorithmFor(world, "ca-rsa"), tbs, ContextFor(world, "ca-rsa", SigningPurpose.Ocsp)));

        var row = Assert.Single(await ReadAuditAsync(world));
        Assert.Equal(SignerAuditEntity.RefusedOutcome, row.Outcome);
        Assert.Equal("Ocsp", row.Purpose);
        Assert.Contains("ResponseData", row.Reason);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(tbs)), row.DataHash);
    }

    [Fact]
    public async Task An_issuer_or_responder_other_than_the_signing_certificate_is_refused()
    {
        var world = SharedWorld;
        var signer = await CreateSignerAsync(world);
        var rsa = AlgorithmFor(world, "ca-rsa");
        var otherIssuer = world["ca-ec"].Certificate.SubjectDN;

        async Task Refused(string key, SigningPurpose purpose, byte[] data)
        {
            var ex = await Assert.ThrowsAsync<SigningRefusedException>(
                () => signer.SignAsync(world[key].Ref, AlgorithmFor(world, key), data, ContextFor(world, key, purpose)));
            Assert.Equal(SigningRefusalReason.IssuerMismatch, ex.Reason);
        }
        await Refused("ca-rsa", SigningPurpose.Certificate, TypedSigningData.Certificate(otherIssuer, LeafKey.Public, rsa));
        await Refused("ca-rsa", SigningPurpose.Crl, TypedSigningData.Crl(otherIssuer, rsa));
        await Refused("ca-rsa", SigningPurpose.Ocsp, TypedSigningData.OcspResponse(world["ca-ec"].PublicKey, world["ca-rsa"].Certificate, rsa));
        // The responder signs as itself, never in its CA's name.
        await Refused("ocsp", SigningPurpose.Ocsp, TypedSigningData.OcspResponse(world["ca-rsa"].PublicKey, world["ca-rsa"].Certificate, AlgorithmFor(world, "ocsp")));
    }

    [Fact]
    public async Task A_structure_that_names_another_algorithm_is_refused()
    {
        var world = SharedWorld;
        var signer = await CreateSignerAsync(world);
        var named = SignatureAlgorithm.FromName("SHA384withRSA");
        var requested = SignatureAlgorithm.FromName("SHA256withRSA");
        var issuer = world["ca-rsa"].Certificate.SubjectDN;

        async Task Refused(SigningPurpose purpose, byte[] data)
        {
            var ex = await Assert.ThrowsAsync<SigningRefusedException>(
                () => signer.SignAsync(world["ca-rsa"].Ref, requested, data, ContextFor(world, "ca-rsa", purpose)));
            Assert.Equal(SigningRefusalReason.AlgorithmMismatch, ex.Reason);
        }
        await Refused(SigningPurpose.Certificate, TypedSigningData.Certificate(issuer, LeafKey.Public, named));
        await Refused(SigningPurpose.Crl, TypedSigningData.Crl(issuer, named));
        await Refused(SigningPurpose.Cmp, TypedSigningData.CmpProtectedPart(named));
    }

    /// <summary>
    /// The extensions only a CA may carry are refused on any other certificate, and a
    /// <c>cA=TRUE</c> certificate for a key the signer did not generate is refused without evidence.
    /// </summary>
    [Fact]
    public async Task A_ca_certificate_needs_evidence_and_ca_extensions_need_ca()
    {
        var world = SharedWorld;
        var signer = await CreateSignerAsync(world);
        var issuer = world["ca-rsa"].Certificate.SubjectDN;
        var rsa = AlgorithmFor(world, "ca-rsa");
        var context = ContextFor(world, "ca-rsa", SigningPurpose.Certificate);

        async Task Refused(byte[] data, SigningRefusalReason reason)
        {
            var ex = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.SignAsync(world["ca-rsa"].Ref, rsa, data, context));
            Assert.Equal(reason, ex.Reason);
        }

        // A rogue subordinate: cA=TRUE for a key the node holds, with no ceremony at all.
        await Refused(TypedSigningData.CaCertificate(issuer, LeafKey.Public, rsa, new X509Name("CN=Rogue Sub CA")), SigningRefusalReason.EvidenceRequired);
        await Refused(TypedSigningData.CaCertificate(issuer, LeafKey.Public, rsa, new X509Name("CN=Rogue Sub CA"), pathLength: 0), SigningRefusalReason.EvidenceRequired);
        // A certificate for the CA's own key, as a renewal over the existing key would be.
        await Refused(TypedSigningData.CaCertificate(issuer, world["ca-rsa"].PublicKey, rsa, issuer), SigningRefusalReason.EvidenceRequired);

        await Refused(TypedSigningData.Certificate(issuer, LeafKey.Public, rsa, gen =>
        {
            gen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
            gen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.DigitalSignature));
        }), SigningRefusalReason.PurposeNotPermitted);
        await Refused(TypedSigningData.Certificate(issuer, LeafKey.Public, rsa, gen =>
            gen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.CrlSign))), SigningRefusalReason.PurposeNotPermitted);
        await Refused(TypedSigningData.Certificate(issuer, LeafKey.Public, rsa, gen =>
            gen.AddExtension(X509Extensions.BasicConstraints, true, new Org.BouncyCastle.Asn1.DerSequence(new Org.BouncyCastle.Asn1.DerInteger(0)))), SigningRefusalReason.PurposeNotPermitted);
        await Refused(TypedSigningData.Certificate(issuer, LeafKey.Public, rsa, gen =>
        {
            gen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
            gen.AddExtension(X509Extensions.NameConstraints, true, new NameConstraints(
                new[] { new GeneralSubtree(new GeneralName(GeneralName.DnsName, "example.test")) }, null));
        }), SigningRefusalReason.PurposeNotPermitted);

        // A leaf with any other EKU is signed as before.
        var leaf = TypedSigningData.Certificate(issuer, LeafKey.Public, rsa, gen =>
        {
            gen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
            gen.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeID.id_kp_timeStamping));
        });
        Assert.True(Verify(world, "ca-rsa", await signer.SignAsync(world["ca-rsa"].Ref, rsa, leaf, context), data: leaf));
    }

    /// <summary>
    /// The intermediate path: a key the signer generated under a ceremony context for a new CA
    /// is certified as a CA by an existing CA, once.
    /// </summary>
    [Fact]
    public async Task A_ca_certificate_for_a_key_the_signer_generated_for_a_new_ca_is_signed_once()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        var issuer = world["ca-rsa"].Certificate.SubjectDN;
        var rsa = AlgorithmFor(world, "ca-rsa");
        var context = ContextFor(world, "ca-rsa", SigningPurpose.Certificate);

        var newCa = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), Context(SigningPurpose.Ceremony, null, world.SpaceA));
        var newCaKey = PublicKeyFactory.CreateKey(newCa.PublicKeyDer);
        var tbs = TypedSigningData.CaCertificate(issuer, newCaKey, rsa, new X509Name("CN=New Intermediate"), pathLength: 0);
        Assert.True(Verify(world, "ca-rsa", await signer.SignAsync(world["ca-rsa"].Ref, rsa, tbs, context), data: tbs));

        var again = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.SignAsync(world["ca-rsa"].Ref, rsa,
            TypedSigningData.CaCertificate(issuer, newCaKey, rsa, new X509Name("CN=Another Name For It")), context));
        Assert.Equal(SigningRefusalReason.EvidenceRequired, again.Reason);

        // A delegated key never becomes a CA, whoever certifies it.
        var delegated = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), ContextFor(world, "ca-rsa", SigningPurpose.Infrastructure));
        var asCa = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.SignAsync(world["ca-rsa"].Ref, rsa,
            TypedSigningData.CaCertificate(issuer, PublicKeyFactory.CreateKey(delegated.PublicKeyDer), rsa, new X509Name("CN=Delegated As CA")), context));
        Assert.Equal(SigningRefusalReason.EvidenceRequired, asCa.Reason);
    }

    /// <summary>
    /// The root path: a key generated for a new CA self-signs its CA certificate once, then
    /// signs the delegated certificates of the keys generated under the same ceremony, naming
    /// itself as issuer, and nothing else; the delegated keys sign their own requests only.
    /// </summary>
    [Fact]
    public async Task A_new_root_self_signs_once_then_certifies_only_its_own_delegated_keys()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        var ceremony = Context(SigningPurpose.Ceremony, null, world.SpaceA);
        var root = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), ceremony);
        var rootKey = PublicKeyFactory.CreateKey(root.PublicKeyDer);
        var alg = SignatureAlgorithm.ForPublicKey(rootKey);
        var rootName = new X509Name("CN=New Root, O=ModularCA");

        async Task Refused(KeyRef key, byte[] data, SigningContext context, SigningRefusalReason reason)
        {
            var ex = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.SignAsync(key, alg, data, context));
            Assert.Equal(reason, ex.Reason);
        }

        // Before it is certified it signs no one else's certificate.
        var responder = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), Context(SigningPurpose.Ceremony, Guid.NewGuid(), world.SpaceA));
        var responderKey = PublicKeyFactory.CreateKey(responder.PublicKeyDer);
        await Refused(root.Key, TypedSigningData.OcspSigningCertificate(rootName, responderKey, alg), ceremony, SigningRefusalReason.PurposeNotPermitted);

        await Refused(root.Key, TypedSigningData.CaCertificate(new X509Name("CN=Someone Else"), rootKey, alg, rootName), ceremony, SigningRefusalReason.IssuerMismatch);
        await Refused(root.Key, TypedSigningData.Certificate(rootName, rootKey, alg, subject: rootName), ceremony, SigningRefusalReason.PurposeNotPermitted);
        var self = TypedSigningData.CaCertificate(rootName, rootKey, alg, rootName);
        Assert.True(VerifyWith(rootKey, alg.Name, await signer.SignAsync(root.Key, alg, self, ceremony), self));
        await Refused(root.Key, TypedSigningData.CaCertificate(rootName, rootKey, alg, rootName), ceremony, SigningRefusalReason.EvidenceRequired);

        // Its responder, generated under the same ceremony: signed, naming the root as issuer.
        var responderTbs = TypedSigningData.OcspSigningCertificate(rootName, responderKey, alg);
        Assert.True(VerifyWith(rootKey, alg.Name, await signer.SignAsync(root.Key, alg, responderTbs, ceremony), responderTbs));
        await Refused(root.Key, TypedSigningData.OcspSigningCertificate(new X509Name("CN=Another Issuer"), responderKey, alg), ceremony, SigningRefusalReason.IssuerMismatch);
        await Refused(root.Key, TypedSigningData.OcspSigningCertificate(rootName, LeafKey.Public, alg), ceremony, SigningRefusalReason.EvidenceRequired);
        await Refused(root.Key, TypedSigningData.CaCertificate(rootName, responderKey, alg, new X509Name("CN=Sub")), ceremony, SigningRefusalReason.EvidenceRequired);
        await Refused(root.Key, TypedSigningData.Crl(rootName, alg), ceremony, SigningRefusalReason.UntypedData);

        // The delegated key signs its own request, and nothing about any other key or itself.
        var responderAlg = SignatureAlgorithm.ForPublicKey(responderKey);
        var request = TypedSigningData.CertificationRequest(responderKey);
        var responderCeremony = Context(SigningPurpose.Ceremony, null, world.SpaceA);
        Assert.True(VerifyWith(responderKey, responderAlg.Name, await signer.SignAsync(responder.Key, responderAlg, request, responderCeremony), request));
        var other = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.SignAsync(responder.Key, responderAlg, TypedSigningData.CertificationRequest(rootKey), responderCeremony));
        Assert.Equal(SigningRefusalReason.PurposeNotPermitted, other.Reason);
        var itself = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.SignAsync(responder.Key, responderAlg,
            TypedSigningData.CaCertificate(new X509Name("CN=Self"), responderKey, responderAlg, new X509Name("CN=Self")), responderCeremony));
        Assert.Equal(SigningRefusalReason.PurposeNotPermitted, itself.Reason);
    }

    [Fact]
    public async Task An_ocsp_signing_certificate_needs_a_delegated_key_the_signer_holds_for_the_ca()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        var issuer = world["ca-rsa"].Certificate.SubjectDN;
        var rsa = AlgorithmFor(world, "ca-rsa");
        var context = ContextFor(world, "ca-rsa", SigningPurpose.Certificate);

        var outside = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.SignAsync(world["ca-rsa"].Ref, rsa,
            TypedSigningData.OcspSigningCertificate(issuer, LeafKey.Public, rsa), context));
        Assert.Equal(SigningRefusalReason.EvidenceRequired, outside.Reason);

        var forOther = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), ContextFor(world, "ca-ec", SigningPurpose.Infrastructure));
        var otherCa = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.SignAsync(world["ca-rsa"].Ref, rsa,
            TypedSigningData.OcspSigningCertificate(issuer, PublicKeyFactory.CreateKey(forOther.PublicKeyDer), rsa), context));
        Assert.Equal(SigningRefusalReason.EvidenceRequired, otherCa.Reason);

        var forOwn = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), ContextFor(world, "ca-rsa", SigningPurpose.Infrastructure));
        var tbs = TypedSigningData.OcspSigningCertificate(issuer, PublicKeyFactory.CreateKey(forOwn.PublicKeyDer), rsa);
        Assert.True(Verify(world, "ca-rsa", await signer.SignAsync(world["ca-rsa"].Ref, rsa, tbs, context), data: tbs));
    }

    /// <summary>
    /// A ceremony row is not evidence for a signature: the node writes it. An approved ceremony
    /// naming the signing CA, whatever its operation type, licenses neither a <c>cA=TRUE</c> nor an
    /// OCSP-signing certificate for a key from outside the signer.
    /// </summary>
    [Theory]
    [InlineData("CreateIntermediateCA")]
    [InlineData("CreateRootCA")]
    [InlineData("CrossCertifyCA")]
    [InlineData("IssueExternalOcspResponder")]
    public async Task An_approved_ceremony_row_licenses_no_certificate_for_an_outside_key(string operation)
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        var issuer = world["ca-rsa"].Certificate.SubjectDN;
        var rsa = AlgorithmFor(world, "ca-rsa");
        var spkiHash = Convert.ToHexString(SHA256.HashData(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(LeafKey.Public).GetDerEncoded()));
        var ceremonyId = SeedCeremony(world, "Approved", world.SpaceA, world.CaRsaId.ToString(), operationType: operation,
            parametersJson: $"{{\"SubjectPublicKeySha256\":\"{spkiHash}\"}}");
        var context = ContextFor(world, "ca-rsa", SigningPurpose.Certificate) with { CeremonyId = ceremonyId };

        foreach (var tbs in new[]
        {
            TypedSigningData.CaCertificate(issuer, LeafKey.Public, rsa, new X509Name("CN=Cross Certified CA")),
            TypedSigningData.OcspSigningCertificate(issuer, LeafKey.Public, rsa),
        })
        {
            var ex = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.SignAsync(world["ca-rsa"].Ref, rsa, tbs, context));
            Assert.Equal(SigningRefusalReason.EvidenceRequired, ex.Reason);
        }
        var rows = await ReadAuditAsync(world);
        Assert.Equal(2, rows.Count);
        Assert.All(rows, r => Assert.Equal(SignerAuditEntity.RefusedOutcome, r.Outcome));
        Assert.All(rows, r => Assert.Equal(ceremonyId, r.CeremonyId));
    }

    /// <summary>A CA's path length binds the CA certificates it signs, even for a key the signer generated.</summary>
    [Theory]
    [InlineData(0, 0, SigningRefusalReason.PurposeNotPermitted)]
    [InlineData(1, 1, SigningRefusalReason.PurposeNotPermitted)]
    [InlineData(1, null, SigningRefusalReason.PurposeNotPermitted)]
    [InlineData(1, 0, null)]
    public async Task A_ca_certifies_another_ca_only_within_its_path_length(int issuerPathLength, int? childPathLength, SigningRefusalReason? expected)
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        var (certificateId, caId, issuerName, publicKey) = await SeedImportedCaAsync(world, signer, issuerPathLength);
        var alg = SignatureAlgorithm.ForPublicKey(publicKey);
        var child = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), Context(SigningPurpose.Ceremony, null, world.SpaceA));
        var tbs = TypedSigningData.CaCertificate(issuerName, PublicKeyFactory.CreateKey(child.PublicKeyDer), alg, new X509Name("CN=Child"), childPathLength);
        var context = Context(SigningPurpose.Certificate, caId, world.SpaceA);

        if (expected == null)
        {
            Assert.True(VerifyWith(publicKey, alg.Name, await signer.SignAsync(new KeyRef(certificateId), alg, tbs, context), tbs));
            return;
        }
        var ex = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.SignAsync(new KeyRef(certificateId), alg, tbs, context));
        Assert.Equal(expected, ex.Reason);
    }

    /// <summary>Seeds a CA in space A whose certificate carries <paramref name="pathLength"/>, and imports its key under a ceremony context.</summary>
    private async Task<(Guid CertificateId, Guid CaId, X509Name Subject, Org.BouncyCastle.Crypto.AsymmetricKeyParameter PublicKey)> SeedImportedCaAsync(
        SignerTestWorld world, ISigningService signer, int pathLength)
    {
        var keyPair = ModularCA.Shared.Utils.KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-256");
        var subject = new X509Name($"CN=Path Length {pathLength} CA");
        var gen = new X509V3CertificateGenerator();
        gen.SetSerialNumber(BigInteger.ValueOf(DateTime.UtcNow.Ticks));
        gen.SetIssuerDN(subject);
        gen.SetSubjectDN(subject);
        gen.SetNotBefore(DateTime.UtcNow.AddMinutes(-1));
        gen.SetNotAfter(DateTime.UtcNow.AddDays(1));
        gen.SetPublicKey(keyPair.Public);
        gen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(pathLength));
        var cert = gen.Generate(new Org.BouncyCastle.Crypto.Operators.Asn1SignatureFactory("SHA256withECDSA", keyPair.Private, new SecureRandom()));

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
                Id = caId, Name = "path-length", Label = $"path-length-{caId:N}", SpaceId = world.SpaceA, CertificateId = certificateId,
            });
            await db.SaveChangesAsync();
        }
        await signer.ImportKeyAsync(new KeyMaterial(Org.BouncyCastle.Pkcs.PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private).GetDerEncoded(),
            KeyMaterial.Pkcs8, certificateId), Context(SigningPurpose.Ceremony, caId, world.SpaceA));
        return (certificateId, caId, subject, keyPair.Public);
    }

    /// <summary>
    /// SSH keys sign nothing through the raw path: a reference into the SSH keystore is refused
    /// for every purpose, whatever the bytes, and an SSH blob is no structure any purpose signs.
    /// </summary>
    [Fact]
    public async Task An_ssh_key_signs_nothing_through_the_raw_path()
    {
        var world = SharedWorld;
        var signer = await CreateSignerAsync(world);
        var sshRef = new KeyRef(world["ca-rsa"].Ref.CertificateId, KeyRef.SshKeystore);

        foreach (var purpose in Enum.GetValues<SigningPurpose>())
        {
            var ex = await Assert.ThrowsAsync<SigningRefusedException>(() => signer.SignAsync(sshRef, AlgorithmFor(world, "ca-rsa"),
                Typed(world, "ca-rsa", purpose), ContextFor(world, "ca-rsa", purpose)));
            Assert.Equal(SigningRefusalReason.PurposeNotPermitted, ex.Reason);
        }
    }

    private static bool VerifyWith(Org.BouncyCastle.Crypto.AsymmetricKeyParameter publicKey, string algorithm, byte[] signature, byte[] data)
    {
        var verifier = SignerUtilities.GetSigner(algorithm);
        verifier.Init(false, publicKey);
        verifier.BlockUpdate(data, 0, data.Length);
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
