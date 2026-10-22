using System.Security;
using System.Security.Cryptography;
using System.Text;
using ModularCA.Keystore.Config;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Signing;
using ModularCA.Shared.Utils;
using ModularCA.Ssh;
using ModularCA.Tests.Ssh;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Xunit;

namespace ModularCA.Tests.Signer;

/// <summary>
/// The SSH keystore's part of the signing contract (<c>docs/architecture/ssh-keystore.md</c>,
/// stage 2): the lifecycle of an SSH CA key, and everything such a key must never do. Each test
/// runs on both bindings, like the rest of the suite. The tests over
/// <see cref="SignerTestWorld.CreateWithKeystoreFiles"/> use real keystore files, since what they
/// prove is about the file: when it appears, what a restart loads from it, and that it does not
/// load once altered.
/// </summary>
public abstract partial class SigningServiceContractTests
{
    /// <summary>A ceremony context for an SSH CA key: the instance as its scope, the SSH CA once there is one, the ceremony when one is named.</summary>
    private static SigningContext SshCeremony(Guid? caId = null, Guid? ceremonyId = null)
        => InstanceContext(SigningPurpose.Ceremony, caId) with { CeremonyId = ceremonyId };

    /// <summary>The context the startup migration imports a key under.</summary>
    private static SigningContext SshMigration(Guid? caId)
        => InstanceContext(SigningPurpose.SshKeyMigration, caId);

    private static KeySpec SshSpec(string algorithm = "Ed25519", string sizeOrCurve = "")
        => new(algorithm, sizeOrCurve, Usage: KeySpec.SshUsage);

    private static SshPublicKey SshKeyOf(byte[] publicKeyDer)
        => SshPublicKey.FromKeyParameter(PublicKeyFactory.CreateKey(publicKeyDer));

    /// <summary>A public key as an <c>SshCaKeys</c> row carries it: an authorized_keys line with a comment.</summary>
    private static string AuthorizedKey(AsymmetricKeyParameter publicKey)
        => SshPublicKey.FromKeyParameter(publicKey).ToAuthorizedKey("signer-contract@test");

    private static string AuthorizedKey(GeneratedKey generated)
        => AuthorizedKey(PublicKeyFactory.CreateKey(generated.PublicKeyDer));

    private static byte[] Pkcs8(AsymmetricKeyParameter privateKey)
        => PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey).GetDerEncoded();

    /// <summary>The public half of a private key of one of the SSH key types.</summary>
    private static AsymmetricKeyParameter PublicOf(AsymmetricKeyParameter privateKey) => privateKey switch
    {
        Ed25519PrivateKeyParameters ed => ed.GeneratePublicKey(),
        ECPrivateKeyParameters ec => new ECPublicKeyParameters("EC", ec.Parameters.G.Multiply(ec.D).Normalize(), ec.Parameters),
        RsaPrivateCrtKeyParameters rsa => new RsaKeyParameters(false, rsa.Modulus, rsa.PublicExponent),
        _ => throw new NotSupportedException(privateKey.GetType().Name),
    };

    /// <summary>
    /// Seeds an SSH CA as the node writes one: an instance CA row marked as an SSH CA, and the
    /// <c>SshCaKeys</c> row that carries <paramref name="authorizedKey"/>. The arguments bend
    /// either row out of shape for the tests that need a refusal.
    /// </summary>
    private static (Guid CaId, Guid KeyId) SeedSshCa(SignerTestWorld world, string authorizedKey, string storage = SshCaKeyStorage.Signer,
        bool enabled = true, bool caEnabled = true, bool caDeleted = false, bool isSshCa = true, Guid? spaceId = null)
    {
        var caId = Guid.NewGuid();
        using (var db = world.OpenDb())
        {
            db.CertificateAuthorities.Add(new CertificateAuthorityEntity
            {
                Id = caId, Name = $"ssh-{caId:N}", Label = $"ssh-{caId:N}", Type = "SSH", SpaceId = spaceId,
                IsSshCa = isSshCa, IsEnabled = caEnabled, IsDeleted = caDeleted,
            });
            db.SaveChanges();
        }
        return (caId, SeedSshKeyRow(world, caId, authorizedKey, storage, enabled));
    }

    /// <summary>Seeds one more <c>SshCaKeys</c> row under an existing CA row, and returns its id.</summary>
    private static Guid SeedSshKeyRow(SignerTestWorld world, Guid caId, string authorizedKey, string storage = SshCaKeyStorage.Signer, bool enabled = true)
    {
        var keyId = Guid.NewGuid();
        using var db = world.OpenDb();
        db.SshCaKeys.Add(new SshCaKeyEntity
        {
            Id = keyId, Name = $"ssh-key-{keyId:N}", KeyType = "ed25519", PublicKey = authorizedKey, CertificateAuthorityId = caId,
            KeyStorage = storage, PrivateKeyPath = storage == SshCaKeyStorage.LegacyFile ? $"config/ssh-ca-keys/{keyId}" : null,
            IsEnabled = enabled,
        });
        db.SaveChanges();
        return keyId;
    }

    /// <summary>Rewrites what an <c>SshCaKeys</c> row says, as a node with database write could.</summary>
    private static void AlterSshKeyRow(SignerTestWorld world, Guid keyId, Action<SshCaKeyEntity> change)
    {
        using var db = world.OpenDb();
        change(db.SshCaKeys.Single(k => k.Id == keyId));
        db.SaveChanges();
    }

    /// <summary>
    /// Generates an SSH CA key through the signer, seeds its SSH CA and commits the key, on an
    /// instance that waives ceremonies. Returns what a caller holds afterwards.
    /// </summary>
    private static async Task<(GeneratedKey Generated, Guid CaId, Guid KeyId, KeyRef Ref)> CommitSshKeyAsync(
        SignerTestWorld world, ISigningService signer, string algorithm = "Ed25519", string sizeOrCurve = "")
    {
        var generated = await signer.GenerateKeyAsync(SshSpec(algorithm, sizeOrCurve), SshCeremony());
        var (caId, keyId) = SeedSshCa(world, AuthorizedKey(generated));
        await signer.CommitKeyAsync(generated.Key, keyId, SshCeremony(caId));
        return (generated, caId, keyId, new KeyRef(keyId, KeyRef.SshKeystore));
    }

    private static async Task RefusedAsync(SigningRefusalReason expected, Func<Task> operation, string what)
    {
        var ex = await Assert.ThrowsAsync<SigningRefusedException>(operation);
        Assert.True(expected == ex.Reason, $"{what}: expected {expected}, got {ex.Reason} ({ex.Message})");
    }

    /// <summary>The SSH CA keys a signer lists, by <c>SshCaKeys</c> row id.</summary>
    private static async Task<Dictionary<Guid, KeyInfo>> ListedSshKeysAsync(ISigningService signer, Guid? caId = null)
        => (await signer.ListKeysAsync(InstanceContext(SigningPurpose.Ceremony, caId)))
            .Where(k => k.Kind == KeyKind.SshCa)
            .ToDictionary(k => k.Key.CertificateId);

    // ---- Generate ----------------------------------------------------------------------------

    [Fact]
    public async Task An_ssh_key_is_generated_pending_in_the_ssh_keystore_for_each_ssh_algorithm()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        SeedInstance(world, requireKeyCeremony: false);
        var specs = new (string Algorithm, string SizeOrCurve, string KeyType)[]
        {
            ("Ed25519", "", SshKeyTypes.Ed25519),
            ("ECDSA", "P-256", SshKeyTypes.EcdsaP256),
            ("ECDSA", "P-384", SshKeyTypes.EcdsaP384),
            ("ECDSA", "P-521", SshKeyTypes.EcdsaP521),
            ("RSA", "2048", SshKeyTypes.Rsa),
        };

        var generated = new List<GeneratedKey>();
        foreach (var (algorithm, sizeOrCurve, keyType) in specs)
        {
            var key = await signer.GenerateKeyAsync(SshSpec(algorithm, sizeOrCurve), SshCeremony());
            Assert.Equal(KeyRef.SshKeystore, key.Key.Keystore);
            Assert.NotEqual(Guid.Empty, key.Key.CertificateId);
            Assert.Equal(keyType, SshKeyOf(key.PublicKeyDer).KeyType);
            generated.Add(key);
        }

        // Pending means written nowhere and listed nowhere.
        Assert.Empty(world.Persistence.SshAppended);
        Assert.Empty(world.Persistence.Appended);
        Assert.Empty(await ListedSshKeysAsync(signer));

        var rows = await ReadAuditAsync(world);
        Assert.Equal(specs.Length, rows.Count);
        Assert.All(rows.Zip(generated), pair =>
        {
            var (row, key) = pair;
            Assert.Equal("GenerateKey", row.Operation);
            Assert.Equal(SignerAuditEntity.AllowedOutcome, row.Outcome);
            Assert.Equal(KeyRef.SshKeystore, row.Keystore);
            Assert.Equal(key.Key.CertificateId, row.KeyCertificateId);
            Assert.Equal(SignerAuditEntity.InstanceScope, row.EffectiveScope);
            Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(key.PublicKeyDer)), row.DataHash);
        });
    }

    /// <summary>
    /// The X.509 key policy allows more than SSH can sign with (Ed448, ML-DSA, SLH-DSA); none of
    /// it becomes an SSH CA key, nor does an RSA key below 2048 bits or a usage the signer does
    /// not know.
    /// </summary>
    [Fact]
    public async Task An_ssh_key_of_another_algorithm_or_usage_is_not_generated()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        SeedInstance(world, requireKeyCeremony: false);
        var refused = new (string Algorithm, string SizeOrCurve, string Usage)[]
        {
            ("Ed448", "", KeySpec.SshUsage),
            ("ML-DSA-65", "", KeySpec.SshUsage),
            ("SLH-DSA-SHA2-128F", "", KeySpec.SshUsage),
            ("DSA", "2048", KeySpec.SshUsage),
            ("RSA", "1024", KeySpec.SshUsage),
            ("RSA", "2047", KeySpec.SshUsage),
            ("RSA", "", KeySpec.SshUsage),
            ("ECDSA", "secp256k1", KeySpec.SshUsage),
            ("", "", KeySpec.SshUsage),
            ("Ed25519", "", "SSH"),
            ("Ed25519", "", "tls"),
        };

        foreach (var (algorithm, sizeOrCurve, usage) in refused)
            await RefusedAsync(SigningRefusalReason.OperationUnsupported,
                () => signer.GenerateKeyAsync(new KeySpec(algorithm, sizeOrCurve, Usage: usage), SshCeremony()), $"{algorithm} {sizeOrCurve} for usage '{usage}'");

        var rows = await ReadAuditAsync(world);
        Assert.Equal(refused.Length, rows.Count);
        Assert.All(rows, row =>
        {
            Assert.Equal(SignerAuditEntity.RefusedOutcome, row.Outcome);
            Assert.Null(row.KeyCertificateId);
        });
    }

    [Fact]
    public async Task An_ssh_key_is_generated_only_under_a_ceremony_context_that_states_the_instance()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        SeedInstance(world, requireKeyCeremony: false);

        // An infrastructure context is held to no ceremony, so it never makes an SSH CA key.
        foreach (var purpose in Enum.GetValues<SigningPurpose>().Where(p => p != SigningPurpose.Ceremony))
            await RefusedAsync(SigningRefusalReason.PurposeNotPermitted,
                () => signer.GenerateKeyAsync(SshSpec(), InstanceContext(purpose)), $"generate under {purpose}");

        await RefusedAsync(SigningRefusalReason.TenantMismatch,
            () => signer.GenerateKeyAsync(SshSpec(), Context(SigningPurpose.Ceremony, null, world.SpaceA)), "generate for a space");
        await RefusedAsync(SigningRefusalReason.ContextRequired,
            () => signer.GenerateKeyAsync(SshSpec(), Context(SigningPurpose.Ceremony, null, null)), "generate with no stated scope");
        await RefusedAsync(SigningRefusalReason.OperationUnsupported,
            () => signer.GenerateKeyAsync(SshSpec() with { Label = "hsm-object" }, SshCeremony()), "generate a labelled key");

        Assert.All(await ReadAuditAsync(world), r => Assert.Equal(SignerAuditEntity.RefusedOutcome, r.Outcome));
    }

    // ---- A pending key, and a raw signature ---------------------------------------------------

    /// <summary>
    /// A pending X.509 key signs its own request and, generated for a new CA, its own CA
    /// certificate. A pending SSH key signs neither, under no purpose and under no keystore
    /// name, and no CA certifies it as a CA.
    /// </summary>
    [Fact]
    public async Task A_pending_ssh_key_signs_nothing_decrypts_nothing_and_is_certified_as_nothing()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        SeedInstance(world, requireKeyCeremony: false);
        var generating = SshCeremony();
        var generated = await signer.GenerateKeyAsync(SshSpec("ECDSA", "P-256"), generating);
        var publicKey = PublicKeyFactory.CreateKey(generated.PublicKeyDer);
        var algorithm = SignatureAlgorithm.ForPublicKey(publicKey);
        var subject = new X509Name("CN=An SSH Key Passed Off As A CA");
        var underTheDefaultKeystore = new KeyRef(generated.Key.CertificateId);
        var offered = new (string Name, byte[] Data)[]
        {
            ("its own certification request", TypedSigningData.CertificationRequest(publicKey)),
            ("its own CA certificate", TypedSigningData.CaCertificate(subject, publicKey, algorithm, subject)),
            ("an SSH certificate blob", SshCertificateBlob),
            ("bytes", Tbs),
        };

        foreach (var purpose in Enum.GetValues<SigningPurpose>())
        {
            var context = generating with { Purpose = purpose };
            foreach (var (name, data) in offered)
            {
                await RefusedAsync(SigningRefusalReason.PurposeNotPermitted,
                    () => signer.SignAsync(generated.Key, algorithm, data, context), $"sign {name} under {purpose}");
                await RefusedAsync(SigningRefusalReason.UnknownKey,
                    () => signer.SignAsync(underTheDefaultKeystore, algorithm, data, context), $"sign {name} under {purpose} as a key of {KeyRef.DefaultKeystore}");
            }
            await RefusedAsync(SigningRefusalReason.PurposeNotPermitted,
                () => signer.DecryptAsync(generated.Key, EnvelopeTo(world["ca-rsa"].Certificate, Secret), context), $"decrypt under {purpose}");
        }

        var caAlgorithm = AlgorithmFor(world, "ca-rsa");
        await RefusedAsync(SigningRefusalReason.EvidenceRequired,
            () => signer.SignAsync(world["ca-rsa"].Ref, caAlgorithm,
                TypedSigningData.CaCertificate(world["ca-rsa"].Certificate.SubjectDN, publicKey, caAlgorithm, subject),
                ContextFor(world, "ca-rsa", SigningPurpose.Certificate)), "a CA certifying the pending SSH key as a CA");

        Assert.Empty(await ListedSshKeysAsync(signer));
        Assert.Empty(world.Persistence.SshAppended);
        Assert.All((await ReadAuditAsync(world)).Skip(1), r => Assert.Equal(SignerAuditEntity.RefusedOutcome, r.Outcome));
    }

    [Fact]
    public async Task A_committed_ssh_key_signs_no_raw_bytes_for_any_purpose()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        SeedInstance(world, requireKeyCeremony: false);
        var (generated, caId, keyId, sshRef) = await CommitSshKeyAsync(world, signer);
        var publicKey = PublicKeyFactory.CreateKey(generated.PublicKeyDer);
        var algorithm = SignatureAlgorithm.ForPublicKey(publicKey);
        var before = (await ReadAuditAsync(world)).Count;

        var attempts = 0;
        foreach (var purpose in Enum.GetValues<SigningPurpose>())
        {
            var data = new[] { Typed(world, "ca-rsa", purpose), SshCertificateBlob, TypedSigningData.CertificationRequest(publicKey), Tbs };
            foreach (var context in new[] { InstanceContext(purpose, caId), InstanceContext(purpose), Context(purpose, caId, null) })
            {
                foreach (var bytes in data)
                {
                    await RefusedAsync(SigningRefusalReason.PurposeNotPermitted,
                        () => signer.SignAsync(sshRef, algorithm, bytes, context), $"sign under {purpose}");
                    // Named as a key of the certificate keystore, the row id reaches no key at all.
                    await RefusedAsync(SigningRefusalReason.UnknownKey,
                        () => signer.SignAsync(new KeyRef(keyId), algorithm, bytes, context), $"sign under {purpose} as a key of {KeyRef.DefaultKeystore}");
                    attempts += 2;
                }
            }
        }

        var rows = (await ReadAuditAsync(world)).Skip(before).ToList();
        Assert.Equal(attempts, rows.Count);
        Assert.All(rows, r =>
        {
            Assert.Equal("Sign", r.Operation);
            Assert.Equal(SignerAuditEntity.RefusedOutcome, r.Outcome);
        });
    }

    // ---- Commit -------------------------------------------------------------------------------

    [Fact]
    public async Task A_committed_ssh_key_is_listed_as_an_ssh_ca_key_and_written_to_the_ssh_keystore_only()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        SeedInstance(world, requireKeyCeremony: false);

        var (generated, caId, keyId, sshRef) = await CommitSshKeyAsync(world, signer, "ECDSA", "P-384");

        var listed = Assert.Single(await ListedSshKeysAsync(signer));
        Assert.Equal(keyId, listed.Key);
        Assert.Equal(sshRef, listed.Value.Key);
        Assert.Equal(KeyKind.SshCa, listed.Value.Kind);
        Assert.Equal(caId, listed.Value.CaId);
        Assert.Null(listed.Value.SpaceId);
        Assert.Equal(ExpectedBackend, listed.Value.Backend);
        Assert.Equal(generated.PublicKeyDer, listed.Value.PublicKeyDer);
        // A context naming the SSH CA lists its key alone; one naming another CA does not list it.
        Assert.Equal(keyId, Assert.Single(await signer.ListKeysAsync(InstanceContext(SigningPurpose.Ceremony, caId))).Key.CertificateId);
        Assert.DoesNotContain(await signer.ListKeysAsync(Context(SigningPurpose.Ocsp, world.CaRsaId, world.SpaceA)), k => k.Kind == KeyKind.SshCa);
        // It is not one of the certificate keys: the health count is theirs.
        Assert.Equal(world.HeldKeys.Count(), (await signer.HealthAsync()).KeyCount);

        // One PKCS#8 entry in the SSH keystore, whose public half is the key's; no certificate anywhere.
        var appended = Assert.Single(world.Persistence.SshAppended);
        Assert.Equal(SshKeyOf(generated.PublicKeyDer), SshPublicKey.FromKeyParameter(PublicOf(PrivateKeyFactory.CreateKey(appended))));
        Assert.Empty(world.Persistence.Appended);

        // The generated reference is spent.
        await RefusedAsync(SigningRefusalReason.UnknownKey, () => signer.CommitKeyAsync(generated.Key, keyId, SshCeremony(caId)), "commit again");

        var commit = Assert.Single(await ReadAuditAsync(world), r => r.Operation == "CommitKey" && r.Outcome == SignerAuditEntity.AllowedOutcome);
        Assert.Equal(keyId, commit.KeyCertificateId);
        Assert.Equal(KeyRef.SshKeystore, commit.Keystore);
        Assert.Equal(caId, commit.CaId);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(generated.PublicKeyDer)), commit.DataHash);
    }

    [Fact]
    public async Task An_ssh_commit_is_refused_unless_the_row_carries_the_key_and_belongs_to_the_enabled_ssh_ca_the_context_names()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        SeedInstance(world, requireKeyCeremony: false);
        var generated = await signer.GenerateKeyAsync(SshSpec(), SshCeremony());
        var line = AuthorizedKey(generated);
        var otherLine = AuthorizedKey(KeyAlgorithmPolicy.GenerateKeyPair("Ed25519", "").Public);

        var (caId, keyId) = SeedSshCa(world, line);
        var (otherCa, _) = SeedSshCa(world, otherLine);
        var (_, differentKey) = SeedSshCa(world, otherLine);
        var (notSshCa, notSshKey) = SeedSshCa(world, line, isSshCa: false);
        var (disabledRowCa, disabledRow) = SeedSshCa(world, line, enabled: false);
        var (disabledCa, disabledCaRow) = SeedSshCa(world, line, caEnabled: false);
        var (deletedCa, deletedCaRow) = SeedSshCa(world, line, caDeleted: true);
        var (legacyCa, legacyRow) = SeedSshCa(world, line, storage: SshCaKeyStorage.LegacyFile);
        var (tokenCa, tokenRow) = SeedSshCa(world, line, storage: SshCaKeyStorage.Pkcs11);
        var (spaceCa, spaceRow) = SeedSshCa(world, line, spaceId: world.SpaceA);
        var unreadable = SeedSshKeyRow(world, caId, "ssh-ed25519 AAAA");

        Task Refused(SigningRefusalReason reason, Guid row, SigningContext context, string what)
            => RefusedAsync(reason, () => signer.CommitKeyAsync(generated.Key, row, context), what);

        await Refused(SigningRefusalReason.CertificateMismatch, Guid.NewGuid(), SshCeremony(caId), "no such row");
        await Refused(SigningRefusalReason.CertificateMismatch, differentKey, SshCeremony(caId), "a row carrying another public key");
        await Refused(SigningRefusalReason.CertificateMismatch, unreadable, SshCeremony(caId), "a row whose public key does not parse");
        await Refused(SigningRefusalReason.PurposeNotPermitted, notSshKey, SshCeremony(notSshCa), "a row of a CA that is not an SSH CA");
        await Refused(SigningRefusalReason.CaMismatch, keyId, SshCeremony(otherCa), "a row of another CA than the context names");
        await Refused(SigningRefusalReason.ContextRequired, keyId, SshCeremony(), "a context that names no CA");
        await Refused(SigningRefusalReason.OperationUnsupported, disabledRow, SshCeremony(disabledRowCa), "a disabled row");
        await Refused(SigningRefusalReason.OperationUnsupported, disabledCaRow, SshCeremony(disabledCa), "a row of a disabled CA");
        await Refused(SigningRefusalReason.OperationUnsupported, deletedCaRow, SshCeremony(deletedCa), "a row of a deleted CA");
        await Refused(SigningRefusalReason.OperationUnsupported, legacyRow, SshCeremony(legacyCa), "a row whose key is a file on the node");
        await Refused(SigningRefusalReason.OperationUnsupported, tokenRow, SshCeremony(tokenCa), "a row whose key is on a token");
        await Refused(SigningRefusalReason.TenantMismatch, spaceRow, SshCeremony(spaceCa), "a row of an SSH CA that belongs to a space");
        await Refused(SigningRefusalReason.TenantMismatch, keyId, Context(SigningPurpose.Ceremony, caId, world.SpaceA), "a context that names a space");
        await Refused(SigningRefusalReason.ContextRequired, keyId, Context(SigningPurpose.Ceremony, caId, null), "a context that does not state the instance");
        foreach (var purpose in Enum.GetValues<SigningPurpose>().Where(p => p != SigningPurpose.Ceremony))
            await Refused(SigningRefusalReason.PurposeNotPermitted, keyId, InstanceContext(purpose, caId), $"a {purpose} context");
        await RefusedAsync(SigningRefusalReason.UnknownKey,
            () => signer.CommitKeyAsync(new KeyRef(Guid.NewGuid(), KeyRef.SshKeystore), keyId, SshCeremony(caId)), "a reference no key waits under");

        // None of it wrote or bound anything, and the key is still pending: it commits now.
        Assert.Empty(world.Persistence.SshAppended);
        Assert.Empty(await ListedSshKeysAsync(signer));
        await signer.CommitKeyAsync(generated.Key, keyId, SshCeremony(caId));
        Assert.Equal(keyId, Assert.Single(await ListedSshKeysAsync(signer)).Key);
        Assert.Single(world.Persistence.SshAppended);

        // A row that has its key takes no other, even once it is rewritten to carry the other's public key.
        var second = await signer.GenerateKeyAsync(SshSpec(), SshCeremony());
        await RefusedAsync(SigningRefusalReason.CertificateMismatch, () => signer.CommitKeyAsync(second.Key, keyId, SshCeremony(caId)), "a second key for a row that has one");
        AlterSshKeyRow(world, keyId, row => row.PublicKey = AuthorizedKey(second));
        await RefusedAsync(SigningRefusalReason.OperationUnsupported, () => signer.CommitKeyAsync(second.Key, keyId, SshCeremony(caId)), "a second key for a rewritten row");
        Assert.Single(world.Persistence.SshAppended);
    }

    /// <summary>
    /// The two kinds of pending key never cross: a key generated for X.509 is not committed to
    /// an SSH CA key row that carries its public key, and an SSH key is not committed to a
    /// certificate that carries its public key, whichever keystore the reference names.
    /// </summary>
    [Fact]
    public async Task An_x509_key_is_not_committed_to_an_ssh_row_nor_an_ssh_key_to_a_certificate()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        SeedInstance(world, requireKeyCeremony: false);
        var instance = InstanceContext(SigningPurpose.Ceremony);

        var x509 = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), instance);
        Assert.Equal(KeyRef.DefaultKeystore, x509.Key.Keystore);
        var (sshCa, sshRow) = SeedSshCa(world, AuthorizedKey(x509));
        await RefusedAsync(SigningRefusalReason.CertificateMismatch,
            () => signer.CommitKeyAsync(x509.Key, sshRow, SshCeremony(sshCa)), "an X.509 key onto an SSH row");
        await RefusedAsync(SigningRefusalReason.UnknownKey,
            () => signer.CommitKeyAsync(new KeyRef(x509.Key.CertificateId, KeyRef.SshKeystore), sshRow, SshCeremony(sshCa)), "an X.509 key renamed into the SSH keystore");

        var ssh = await signer.GenerateKeyAsync(SshSpec("ECDSA", "P-256"), SshCeremony());
        var (_, certificateId, caId) = await SeedOutsideCaAsync(world, PublicKeyFactory.CreateKey(ssh.PublicKeyDer));
        await RefusedAsync(SigningRefusalReason.CertificateMismatch,
            () => signer.CommitKeyAsync(ssh.Key, certificateId, InstanceContext(SigningPurpose.Ceremony, caId)), "an SSH key onto a certificate");
        await RefusedAsync(SigningRefusalReason.UnknownKey,
            () => signer.CommitKeyAsync(new KeyRef(ssh.Key.CertificateId), certificateId, InstanceContext(SigningPurpose.Ceremony, caId)), "an SSH key renamed into the certificate keystore");

        Assert.Empty(world.Persistence.Appended);
        Assert.Empty(world.Persistence.SshAppended);
        Assert.Empty(await ListedSshKeysAsync(signer));
        Assert.DoesNotContain(await signer.ListKeysAsync(instance), k => k.Key.CertificateId == certificateId);
    }

    /// <summary>
    /// Seeds a CA certificate made outside the signer over <paramref name="publicKey"/>, and the
    /// instance CA row that names it: the rows an X.509 commit would bind a key to.
    /// </summary>
    private static async Task<(X509Certificate Certificate, Guid CertificateId, Guid CaId)> SeedOutsideCaAsync(SignerTestWorld world, AsymmetricKeyParameter publicKey)
    {
        var cert = TypedSigningData.OutsideCertificate(publicKey, new X509Name("CN=A Certificate Over An SSH Key"), isCa: true);
        var certificateId = Guid.NewGuid();
        var caId = Guid.NewGuid();
        using var db = world.OpenDb();
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
        db.CertificateAuthorities.Add(new CertificateAuthorityEntity { Id = caId, Name = $"outside-{caId:N}", Label = $"outside-{caId:N}", SpaceId = null, CertificateId = certificateId });
        await db.SaveChangesAsync();
        return (cert, certificateId, caId);
    }

    // ---- Ceremonies ---------------------------------------------------------------------------

    /// <summary>
    /// SSH CA keys are held to the instance's ceremony policy at the signer: refused without a
    /// ceremony where the instance requires one, allowed under an approved <c>CreateSshCa</c>
    /// ceremony of the instance, and refused under any other ceremony, an X.509 CA ceremony
    /// included. Where the instance waives ceremonies, none is needed.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task An_ssh_ca_key_is_held_to_the_instances_ceremony_policy(bool instanceRequiresCeremony)
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        SeedInstance(world, instanceRequiresCeremony);

        if (!instanceRequiresCeremony)
        {
            var (_, _, waivedKey, _) = await CommitSshKeyAsync(world, signer);
            Assert.Contains(waivedKey, (await ListedSshKeysAsync(signer)).Keys);
            return;
        }

        var approved = SeedCeremony(world, "Approved", null, operationType: "CreateSshCa");
        var notApproved = new (string Name, Guid Id)[]
        {
            ("a root CA ceremony", SeedCeremony(world, "Approved", null, operationType: "CreateRootCA")),
            ("an intermediate CA ceremony", SeedCeremony(world, "Approved", null, operationType: "CreateIntermediateCA")),
            ("a ceremony that deletes an SSH CA", SeedCeremony(world, "Approved", null, operationType: "DeleteSshCa")),
            ("a ceremony that manages no key", SeedCeremony(world, "Approved", null, operationType: "RevokeCa")),
            ("a pending SSH CA ceremony", SeedCeremony(world, "Pending", null, operationType: "CreateSshCa")),
            ("an executed SSH CA ceremony", SeedCeremony(world, "Executed", null, operationType: "CreateSshCa")),
            ("an expired SSH CA ceremony", SeedCeremony(world, "Approved", null, operationType: "CreateSshCa", expiresAt: DateTime.UtcNow.AddMinutes(-1))),
            ("an SSH CA ceremony of a space", SeedCeremony(world, "Approved", world.SpaceA, operationType: "CreateSshCa")),
            ("a ceremony that does not exist", Guid.NewGuid()),
        };

        await RefusedAsync(SigningRefusalReason.CeremonyRequired, () => signer.GenerateKeyAsync(SshSpec(), SshCeremony()), "generate with no ceremony");
        foreach (var (name, id) in notApproved)
            await RefusedAsync(SigningRefusalReason.CeremonyNotApproved, () => signer.GenerateKeyAsync(SshSpec(), SshCeremony(ceremonyId: id)), $"generate under {name}");

        var generated = await signer.GenerateKeyAsync(SshSpec(), SshCeremony(ceremonyId: approved));
        var (caId, keyId) = SeedSshCa(world, AuthorizedKey(generated));
        await RefusedAsync(SigningRefusalReason.CeremonyRequired, () => signer.CommitKeyAsync(generated.Key, keyId, SshCeremony(caId)), "commit with no ceremony");
        foreach (var (name, id) in notApproved)
            await RefusedAsync(SigningRefusalReason.CeremonyNotApproved, () => signer.CommitKeyAsync(generated.Key, keyId, SshCeremony(caId, id)), $"commit under {name}");
        Assert.Empty(world.Persistence.SshAppended);

        await signer.CommitKeyAsync(generated.Key, keyId, SshCeremony(caId, approved));
        Assert.Contains(keyId, (await ListedSshKeysAsync(signer)).Keys);

        // The licence does not run the other way either: an SSH CA ceremony makes no X.509 CA key.
        await RefusedAsync(SigningRefusalReason.CeremonyNotApproved,
            () => signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), InstanceContext(SigningPurpose.Ceremony) with { CeremonyId = approved }), "an X.509 key under an SSH CA ceremony");

        var rows = await ReadAuditAsync(world);
        Assert.Equal(2, rows.Count(r => r.Outcome == SignerAuditEntity.AllowedOutcome));
        Assert.All(rows.Where(r => r.Outcome == SignerAuditEntity.AllowedOutcome), r => Assert.Equal(approved, r.CeremonyId));
    }

    // ---- Retire -------------------------------------------------------------------------------

    [Fact]
    public async Task A_pending_ssh_key_is_retired_and_a_committed_one_is_not()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        SeedInstance(world, requireKeyCeremony: false);
        var generated = await signer.GenerateKeyAsync(SshSpec(), SshCeremony());
        var (caId, keyId) = SeedSshCa(world, AuthorizedKey(generated));

        await RefusedAsync(SigningRefusalReason.PurposeNotPermitted, () => signer.RetireKeyAsync(generated.Key, InstanceContext(SigningPurpose.Infrastructure)), "retire under an infrastructure context");
        await RefusedAsync(SigningRefusalReason.TenantMismatch, () => signer.RetireKeyAsync(generated.Key, Context(SigningPurpose.Ceremony, null, world.SpaceA)), "retire for a space");
        await RefusedAsync(SigningRefusalReason.UnknownKey, () => signer.RetireKeyAsync(new KeyRef(generated.Key.CertificateId), SshCeremony()), "retire as a key of the certificate keystore");

        await signer.RetireKeyAsync(generated.Key, SshCeremony());
        await RefusedAsync(SigningRefusalReason.UnknownKey, () => signer.RetireKeyAsync(generated.Key, SshCeremony()), "retire again");
        await RefusedAsync(SigningRefusalReason.UnknownKey, () => signer.CommitKeyAsync(generated.Key, keyId, SshCeremony(caId)), "commit a retired key");

        var (_, committedCa, committedKey, committedRef) = await CommitSshKeyAsync(world, signer);
        await RefusedAsync(SigningRefusalReason.OperationUnsupported, () => signer.RetireKeyAsync(committedRef, SshCeremony(committedCa)), "retire a committed key");
        Assert.Contains(committedKey, (await ListedSshKeysAsync(signer)).Keys);
    }

    // ---- Import: the migration of a key file --------------------------------------------------

    /// <summary>
    /// The migration's own input: a key file as <c>ssh-keygen</c> wrote it, converted to PKCS#8
    /// by <see cref="SshPrivateKeyFile"/>, and the <c>.pub</c> line beside it on the row.
    /// </summary>
    [Fact]
    public async Task The_ssh_key_migration_imports_a_key_file_for_its_legacy_row_and_can_be_repeated()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        // The instance requires ceremonies, and the migration needs none.
        SeedInstance(world, requireKeyCeremony: true);

        var count = 0;
        foreach (var fixture in new[] { "ed25519", "p256", "p384", "p521", "rsa" })
        {
            var file = SshFixtures.CaPrivate(fixture);
            var (caId, keyId) = SeedSshCa(world, SshFixtures.Text($"ca-{fixture}.pub"), storage: SshCaKeyStorage.LegacyFile);
            var material = new KeyMaterial(file.ToPkcs8(), KeyMaterial.Pkcs8, keyId, KeyRef.SshKeystore);

            var imported = await signer.ImportKeyAsync(material, SshMigration(caId));

            count++;
            Assert.Equal(new KeyRef(keyId, KeyRef.SshKeystore), imported);
            Assert.All(material.Wrapped, b => Assert.Equal(0, b));
            var listed = Assert.Single(await ListedSshKeysAsync(signer, caId)).Value;
            Assert.Equal(KeyKind.SshCa, listed.Kind);
            Assert.Equal(file.PublicKey, SshKeyOf(listed.PublicKeyDer));
            Assert.Equal(count, world.Persistence.SshAppended.Count);

            // A migration that crashed after the import offers the key again: it succeeds and writes nothing.
            Assert.Equal(imported, await signer.ImportKeyAsync(new KeyMaterial(file.ToPkcs8(), KeyMaterial.Pkcs8, keyId, KeyRef.SshKeystore), SshMigration(caId)));
            Assert.Equal(count, world.Persistence.SshAppended.Count);

            var rows = (await ReadAuditAsync(world)).Where(r => r.Operation == "ImportKey" && r.KeyCertificateId == keyId).ToList();
            Assert.Equal(2, rows.Count);
            Assert.All(rows, r =>
            {
                Assert.Equal(SignerAuditEntity.AllowedOutcome, r.Outcome);
                Assert.Equal("SshKeyMigration", r.Purpose);
                Assert.Equal(KeyRef.SshKeystore, r.Keystore);
                Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(listed.PublicKeyDer)), r.DataHash);
            });

            // The imported key signs no raw bytes either.
            await RefusedAsync(SigningRefusalReason.PurposeNotPermitted,
                () => signer.SignAsync(imported, SignatureAlgorithm.ForPublicKey(file.PublicKey.KeyParameter), Tbs, InstanceContext(SigningPurpose.SshCertificate, caId)), $"a raw signature with the imported {fixture} key");
        }
        Assert.Empty(world.Persistence.Appended);
    }

    [Fact]
    public async Task The_ssh_key_migration_imports_for_a_disabled_ssh_ca_and_never_a_second_key_for_a_row()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        var first = KeyAlgorithmPolicy.GenerateKeyPair("Ed25519", "");
        var second = KeyAlgorithmPolicy.GenerateKeyPair("Ed25519", "");
        // Disabled, key and CA both: the key still comes off the node.
        var (caId, keyId) = SeedSshCa(world, AuthorizedKey(first.Public), storage: SshCaKeyStorage.LegacyFile, enabled: false, caEnabled: false, caDeleted: true);
        KeyMaterial Material(AsymmetricCipherKeyPair pair) => new(Pkcs8(pair.Private), KeyMaterial.Pkcs8, keyId, KeyRef.SshKeystore);

        await signer.ImportKeyAsync(Material(first), SshMigration(caId));
        Assert.Single(world.Persistence.SshAppended);

        // Another key for the row is not the row's key...
        await RefusedAsync(SigningRefusalReason.CertificateMismatch, () => signer.ImportKeyAsync(Material(second), SshMigration(caId)), "another key for the row");
        // ...and stays refused once the row is rewritten to carry it: the row already has its key.
        AlterSshKeyRow(world, keyId, row => row.PublicKey = AuthorizedKey(second.Public));
        await RefusedAsync(SigningRefusalReason.OperationUnsupported, () => signer.ImportKeyAsync(Material(second), SshMigration(caId)), "another key for a rewritten row");
        await RefusedAsync(SigningRefusalReason.CertificateMismatch, () => signer.ImportKeyAsync(Material(first), SshMigration(caId)), "the first key once the row carries another");

        Assert.Single(world.Persistence.SshAppended);
        // The row no longer carries the key the signer holds for it, so the key is not listed.
        Assert.Empty(await ListedSshKeysAsync(signer));
    }

    [Fact]
    public async Task An_ssh_key_import_is_refused_unless_it_is_the_migration_of_a_legacy_rows_own_key()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        SeedInstance(world, requireKeyCeremony: false);
        var approved = SeedCeremony(world, "Approved", null, operationType: "CreateSshCa");
        var pair = KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-256");
        var line = AuthorizedKey(pair.Public);
        var other = KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-256");

        var (caId, keyId) = SeedSshCa(world, line, storage: SshCaKeyStorage.LegacyFile);
        var (otherCa, differentKey) = SeedSshCa(world, AuthorizedKey(other.Public), storage: SshCaKeyStorage.LegacyFile);
        var (signerCa, signerRow) = SeedSshCa(world, line, storage: SshCaKeyStorage.Signer);
        var (tokenCa, tokenRow) = SeedSshCa(world, line, storage: SshCaKeyStorage.Pkcs11);
        var (notSshCa, notSshRow) = SeedSshCa(world, line, storage: SshCaKeyStorage.LegacyFile, isSshCa: false);
        var (spaceCa, spaceRow) = SeedSshCa(world, line, storage: SshCaKeyStorage.LegacyFile, spaceId: world.SpaceA);

        KeyMaterial Material(Guid row, AsymmetricKeyParameter? key = null, string format = KeyMaterial.Pkcs8, string keystore = KeyRef.SshKeystore)
            => new(Pkcs8(key ?? pair.Private), format, row, keystore);
        Task Refused(SigningRefusalReason reason, KeyMaterial material, SigningContext context, string what)
            => RefusedAsync(reason, () => signer.ImportKeyAsync(material, context), what);

        // Only the migration purpose imports into the SSH keystore: not a ceremony, approved or waived.
        foreach (var purpose in Enum.GetValues<SigningPurpose>().Where(p => p != SigningPurpose.SshKeyMigration))
            await Refused(SigningRefusalReason.PurposeNotPermitted, Material(keyId), InstanceContext(purpose, caId), $"import under {purpose}");
        await Refused(SigningRefusalReason.PurposeNotPermitted, Material(keyId), SshCeremony(caId, approved), "import under an approved SSH CA ceremony");

        await Refused(SigningRefusalReason.PurposeNotPermitted, Material(signerRow), SshMigration(signerCa), "a row whose key the signer is to hold already");
        await Refused(SigningRefusalReason.PurposeNotPermitted, Material(tokenRow), SshMigration(tokenCa), "a row whose key is on a token");
        await Refused(SigningRefusalReason.CertificateMismatch, Material(differentKey), SshMigration(otherCa), "a row carrying another public key");
        await Refused(SigningRefusalReason.CertificateMismatch, Material(Guid.NewGuid()), SshMigration(caId), "no such row");
        await Refused(SigningRefusalReason.CertificateMismatch, Material(world["ca-rsa"].Ref.CertificateId), SshMigration(caId), "a certificate id");
        await Refused(SigningRefusalReason.PurposeNotPermitted, Material(notSshRow), SshMigration(notSshCa), "a row of a CA that is not an SSH CA");
        await Refused(SigningRefusalReason.TenantMismatch, Material(spaceRow), SshMigration(spaceCa), "a row of an SSH CA that belongs to a space");
        await Refused(SigningRefusalReason.CaMismatch, Material(keyId), SshMigration(otherCa), "a row of another CA than the context names");
        await Refused(SigningRefusalReason.ContextRequired, Material(keyId), SshMigration(null), "a context that names no CA");
        await Refused(SigningRefusalReason.TenantMismatch, Material(keyId), Context(SigningPurpose.SshKeyMigration, caId, world.SpaceA), "a context that names a space");
        await Refused(SigningRefusalReason.ContextRequired, Material(keyId), Context(SigningPurpose.SshKeyMigration, caId, null), "a context that does not state the instance");
        await Refused(SigningRefusalReason.OperationUnsupported, Material(keyId, format: "openssh"), SshMigration(caId), "a format that is not PKCS#8");
        await Refused(SigningRefusalReason.OperationUnsupported, new KeyMaterial(new byte[] { 1, 2, 3 }, KeyMaterial.Pkcs8, keyId, KeyRef.SshKeystore), SshMigration(caId), "bytes that are no key");

        // The key itself is held to the SSH algorithms, whatever a row says.
        var weak = new RsaKeyPairGenerator();
        weak.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(65537), new SecureRandom(), 1024, 80));
        var weakPair = weak.GenerateKeyPair();
        var (weakCa, weakRow) = SeedSshCa(world, AuthorizedKey(weakPair.Public), storage: SshCaKeyStorage.LegacyFile);
        await Refused(SigningRefusalReason.OperationUnsupported, Material(weakRow, weakPair.Private), SshMigration(weakCa), "an RSA key below 2048 bits");
        await Refused(SigningRefusalReason.OperationUnsupported, Material(keyId, KeyAlgorithmPolicy.GenerateKeyPair("Ed448", "").Private), SshMigration(caId), "an Ed448 key");

        // The migration purpose imports into no other keystore: not a CA key for its certificate.
        var keyless = world["keyless"];
        await Refused(SigningRefusalReason.PurposeNotPermitted,
            new KeyMaterial((byte[])keyless.PrivateKeyPkcs8.Clone(), KeyMaterial.Pkcs8, keyless.Ref.CertificateId),
            Context(SigningPurpose.SshKeyMigration, world.KeylessCaId, world.SpaceA), "a CA key into the certificate keystore");

        Assert.Empty(world.Persistence.SshAppended);
        Assert.Empty(world.Persistence.Appended);
        Assert.Empty(await ListedSshKeysAsync(signer));
        Assert.All((await ReadAuditAsync(world)).Where(r => r.Operation == "ImportKey"), r => Assert.Equal(SignerAuditEntity.RefusedOutcome, r.Outcome));

        // The same key for its own legacy row goes through.
        await signer.ImportKeyAsync(Material(keyId), SshMigration(caId));
        Assert.Equal(keyId, Assert.Single(await ListedSshKeysAsync(signer)).Key);
    }

    /// <summary>
    /// The two SSH purposes permit nothing but what they are for: the migration purpose only the
    /// import above, and the certificate purpose only <c>SignSshCertificate</c>, whose own tests
    /// are in <c>SigningServiceContractTests.SshCertificates.cs</c>. Neither permits the other's.
    /// </summary>
    [Theory]
    [InlineData(SigningPurpose.SshKeyMigration)]
    [InlineData(SigningPurpose.SshCertificate)]
    public async Task An_ssh_purpose_permits_no_other_operation(SigningPurpose purpose)
    {
        var world = SignerTestWorld.Create();
        world.Persistence.KeystoreFiles[KeyRef.DefaultKeystore] = (byte[])CertsFile.Clone();
        var signer = await CreateSignerAsync(world);
        SeedInstance(world, requireKeyCeremony: false);
        var (_, sshCa, sshRow, sshRef) = await CommitSshKeyAsync(world, signer);
        var pendingSsh = await signer.GenerateKeyAsync(SshSpec(), SshCeremony());
        var (pendingCa, pendingRow) = SeedSshCa(world, AuthorizedKey(pendingSsh));
        var pendingX509 = await signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), Context(SigningPurpose.Ceremony, null, world.SpaceA));
        var blob = await signer.WrapSecretAsync(SecretKind.CmpSharedSecret, WrappableSecret, Context(SigningPurpose.Cmp, null, null));
        var before = (await ReadAuditAsync(world)).Count;

        var caRsa = world["ca-rsa"];
        var forCa = Context(purpose, world.CaRsaId, world.SpaceA);
        var forInstance = InstanceContext(purpose);
        var operations = new (string Name, Func<Task> Run)[]
        {
            ("sign with a CA key", () => signer.SignAsync(caRsa.Ref, AlgorithmFor(world, "ca-rsa"), Typed(world, "ca-rsa", SigningPurpose.Certificate), forCa)),
            ("sign with the SSH key", () => signer.SignAsync(sshRef, SignatureAlgorithm.FromName("Ed25519"), Tbs, InstanceContext(purpose, sshCa))),
            ("decrypt with a CA key", () => signer.DecryptAsync(caRsa.Ref, EnvelopeTo(caRsa.Certificate, Secret), forCa)),
            ("decrypt with the SSH key", () => signer.DecryptAsync(sshRef, EnvelopeTo(caRsa.Certificate, Secret), InstanceContext(purpose, sshCa))),
            ("generate an X.509 key", () => signer.GenerateKeyAsync(new KeySpec("ECDSA", "P-256"), forInstance)),
            ("generate an SSH key", () => signer.GenerateKeyAsync(SshSpec(), forInstance)),
            ("commit an SSH key", () => signer.CommitKeyAsync(pendingSsh.Key, pendingRow, InstanceContext(purpose, pendingCa))),
            ("commit an X.509 key", () => signer.CommitKeyAsync(pendingX509.Key, world["leaf"].Ref.CertificateId, Context(purpose, null, world.SpaceA))),
            ("retire an SSH key", () => signer.RetireKeyAsync(pendingSsh.Key, forInstance)),
            ("retire an X.509 key", () => signer.RetireKeyAsync(pendingX509.Key, Context(purpose, null, world.SpaceA))),
            ("export an end-entity key", () => signer.ExportKeyAsync(world["leaf"].Ref, new ExportWrap(ExportWrap.Pkcs12, "pw"), forCa)),
            ("export the SSH key", () => signer.ExportKeyAsync(sshRef, new ExportWrap(ExportWrap.Pkcs12, "pw"), InstanceContext(purpose, sshCa))),
            ("export a keystore file", () => signer.ExportKeyAsync(KeyRef.ForKeystore(KeyRef.DefaultKeystore), ExportWrap.ForKeystoreFile(), forInstance)),
            ("import a keystore file", () => signer.ImportKeyAsync(new KeyMaterial(new byte[] { 1 }, KeyMaterial.KeystoreFile, Guid.Empty, KeyRef.SshKeystore), forInstance)),
            ("unwrap a secret", () => signer.UnwrapSecretAsync(blob, forInstance)),
        };
        foreach (var (name, run) in operations)
            await RefusedAsync(SigningRefusalReason.PurposeNotPermitted, run, $"{name} under {purpose}");
        foreach (var kind in Enum.GetValues<SecretKind>())
        {
            await RefusedAsync(SigningRefusalReason.PurposeNotPermitted, () => signer.WrapSecretAsync(kind, WrappableSecret, forInstance), $"wrap a {kind} under {purpose}");
            await RefusedAsync(SigningRefusalReason.PurposeNotPermitted, () => signer.WrapBoundSecretAsync(kind, "setting:Example", WrappableSecret, forInstance), $"wrap a bound {kind} under {purpose}");
        }
        if (purpose == SigningPurpose.SshCertificate)
            await RefusedAsync(SigningRefusalReason.PurposeNotPermitted,
                () => signer.ImportKeyAsync(new KeyMaterial(Pkcs8(KeyAlgorithmPolicy.GenerateKeyPair("Ed25519", "").Private), KeyMaterial.Pkcs8, sshRow, KeyRef.SshKeystore), InstanceContext(purpose, sshCa)),
                "import an SSH key under SshCertificate");
        else
            await RefusedAsync(SigningRefusalReason.PurposeNotPermitted,
                () => signer.SignSshCertificateAsync(UserRequest(sshRef), InstanceContext(purpose, sshCa)), "sign an SSH certificate under SshKeyMigration");

        var rows = (await ReadAuditAsync(world)).Skip(before).ToList();
        Assert.All(rows, r => Assert.Equal(SignerAuditEntity.RefusedOutcome, r.Outcome));
        Assert.Equal(CertsFile, world.Persistence.KeystoreFiles[KeyRef.DefaultKeystore]);
        Assert.Single(world.Persistence.SshAppended);
        Assert.Empty(world.Persistence.Appended);
    }

    // ---- Decrypt and export -------------------------------------------------------------------

    [Fact]
    public async Task An_ssh_key_decrypts_nothing_and_is_never_exported()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        SeedInstance(world, requireKeyCeremony: false);
        var (_, caId, keyId, sshRef) = await CommitSshKeyAsync(world, signer, "RSA", "2048");
        var envelope = EnvelopeTo(world["ca-rsa"].Certificate, Secret);
        var pkcs12 = new ExportWrap(ExportWrap.Pkcs12, "export-password");

        foreach (var purpose in Enum.GetValues<SigningPurpose>())
        {
            await RefusedAsync(SigningRefusalReason.PurposeNotPermitted, () => signer.DecryptAsync(sshRef, envelope, InstanceContext(purpose, caId)), $"decrypt under {purpose}");
            await RefusedAsync(SigningRefusalReason.PurposeNotPermitted, () => signer.ExportKeyAsync(sshRef, pkcs12, InstanceContext(purpose, caId)), $"export under {purpose}");
            await RefusedAsync(SigningRefusalReason.UnknownKey, () => signer.DecryptAsync(new KeyRef(keyId), envelope, InstanceContext(purpose, caId)), $"decrypt under {purpose} as a key of {KeyRef.DefaultKeystore}");
        }
        // One key never takes the wrap of a whole keystore, under Backup or anything else.
        await RefusedAsync(SigningRefusalReason.OperationUnsupported, () => signer.ExportKeyAsync(sshRef, ExportWrap.ForKeystoreFile(), InstanceContext(SigningPurpose.Backup, caId)), "the keystore-file wrap for one key");
        await RefusedAsync(SigningRefusalReason.UnknownKey, () => signer.ExportKeyAsync(new KeyRef(keyId), pkcs12, InstanceContext(SigningPurpose.Export, caId)), $"export as a key of {KeyRef.DefaultKeystore}");

        var export = (await ReadAuditAsync(world)).Last(r => r.Operation == "ExportKey" && r.Purpose == "Export" && r.Keystore == KeyRef.SshKeystore);
        Assert.Equal(SignerAuditEntity.RefusedOutcome, export.Outcome);
        Assert.Contains("SSH CA key", export.Reason);
    }

    /// <summary>
    /// The database only chooses among the keys the SSH keystore holds. A row that carries the
    /// public key of an X.509 CA key gets no key, so an X.509 key never becomes an SSH key by a
    /// row being written.
    /// </summary>
    [Fact]
    public async Task A_row_that_carries_the_public_key_of_an_x509_ca_key_is_served_no_key()
    {
        var world = SignerTestWorld.Create();
        var signer = await CreateSignerAsync(world);
        SeedInstance(world, requireKeyCeremony: false);
        var caKey = world["ca-ec"];
        var (caId, keyId) = SeedSshCa(world, AuthorizedKey(caKey.PublicKey));
        var asSsh = new KeyRef(keyId, KeyRef.SshKeystore);

        Assert.Empty(await ListedSshKeysAsync(signer));
        await RefusedAsync(SigningRefusalReason.UnknownKey, () => signer.RetireKeyAsync(asSsh, SshCeremony(caId)), "retire");
        foreach (var purpose in Enum.GetValues<SigningPurpose>())
            await RefusedAsync(SigningRefusalReason.PurposeNotPermitted, () => signer.SignAsync(asSsh, AlgorithmFor(world, "ca-ec"), Tbs, InstanceContext(purpose, caId)), $"sign under {purpose}");
        // The CA key itself is untouched: still a CA key, of its own CA.
        var tbs = Typed(world, "ca-ec", SigningPurpose.Certificate);
        Assert.True(Verify(world, "ca-ec", await signer.SignAsync(caKey.Ref, AlgorithmFor(world, "ca-ec"), tbs, ContextFor(world, "ca-ec", SigningPurpose.Certificate)), data: tbs));
    }

    // ---- The file: created on first use, loaded at unlock, refused when altered ---------------

    /// <summary>The <c>Keystores</c> rows of a world, by name.</summary>
    private static Dictionary<string, KeystoreEntryEntity> KeystoreRows(SignerTestWorld world)
    {
        using var db = world.OpenDb();
        return db.Keystores.ToDictionary(k => k.Name);
    }

    [Theory]
    [InlineData("commit")]
    [InlineData("import")]
    public async Task The_ssh_keystore_does_not_exist_until_the_first_ssh_key_is_committed_or_imported(string firstUse)
    {
        var world = SignerTestWorld.CreateWithKeystoreFiles();
        var signer = await CreateSignerAsync(world);
        var files = world.Files!;
        var sshPath = files.Path(KeyRef.SshKeystore);
        var certsBefore = File.ReadAllBytes(files.Path(KeyRef.DefaultKeystore));
        var trustBefore = File.ReadAllBytes(files.Path(KeyRef.TrustKeystore));
        var backup = new SigningContext(Caller, SigningPurpose.Backup, null, null);

        // An install with no SSH CA has no file, no row, and nothing for a backup to take.
        Assert.False(File.Exists(sshPath));
        Assert.DoesNotContain(KeyRef.SshKeystore, KeystoreRows(world).Keys);
        await RefusedAsync(SigningRefusalReason.UnknownKey, () => signer.ExportKeyAsync(KeyRef.ForKeystore(KeyRef.SshKeystore), ExportWrap.ForKeystoreFile(), backup), "export a keystore that is not there");

        // Generating does not create it; nor does a commit or an import that is refused.
        var generated = await signer.GenerateKeyAsync(SshSpec("ECDSA", "P-256"), SshCeremony());
        var (caId, keyId) = SeedSshCa(world, AuthorizedKey(generated));
        var legacy = SshFixtures.CaPrivate("ed25519");
        var (legacyCa, legacyRow) = SeedSshCa(world, SshFixtures.Text("ca-ed25519.pub"), storage: SshCaKeyStorage.LegacyFile);
        await RefusedAsync(SigningRefusalReason.CaMismatch, () => signer.CommitKeyAsync(generated.Key, keyId, SshCeremony(legacyCa)), "a refused commit");
        await RefusedAsync(SigningRefusalReason.CaMismatch,
            () => signer.ImportKeyAsync(new KeyMaterial(legacy.ToPkcs8(), KeyMaterial.Pkcs8, legacyRow, KeyRef.SshKeystore), SshMigration(caId)), "a refused import");
        Assert.False(File.Exists(sshPath));

        if (firstUse == "commit")
            await signer.CommitKeyAsync(generated.Key, keyId, SshCeremony(caId));
        else
            await signer.ImportKeyAsync(new KeyMaterial(legacy.ToPkcs8(), KeyMaterial.Pkcs8, legacyRow, KeyRef.SshKeystore), SshMigration(legacyCa));

        // The file, and a row of its own: its own salt and wrapped main passphrase, pinned to the
        // system signer the other files are pinned to, the pin authenticated.
        Assert.True(File.Exists(sshPath));
        var rows = KeystoreRows(world);
        var ssh = rows[KeyRef.SshKeystore];
        var certs = rows[KeyRef.DefaultKeystore];
        Assert.Equal(3, rows.Count);
        Assert.NotEqual(certs.Salt, ssh.Salt);
        Assert.NotEqual(rows[KeyRef.TrustKeystore].Salt, ssh.Salt);
        Assert.NotEqual(certs.Passblob, ssh.Passblob);
        Assert.True(ssh.ScryptN >= 1 << 14);
        Assert.Equal(certs.SigningCaSpkiSha256, ssh.SigningCaSpkiSha256);
        Assert.NotNull(ssh.SigningCaSpkiSha256Mac);
        // It shares the secondary passphrase of ca-certs.keystore, and no other.
        Assert.Equal(SignerKeystoreFiles.CertsSecondary, KeystoreYamlLoader.LoadSecondaryPassphrase(files.YamlPath, KeyRef.SshKeystore));
        Assert.Equal(ModularCA.Keystore.Services.KeystoreService.ComputeSpkiPinMac(ssh.SigningCaSpkiSha256!, SignerKeystoreFiles.CertsSecondary), ssh.SigningCaSpkiSha256Mac);

        // Nothing went into the other two files: no certificate, no trust anchor.
        Assert.Equal(certsBefore, File.ReadAllBytes(files.Path(KeyRef.DefaultKeystore)));
        Assert.Equal(trustBefore, File.ReadAllBytes(files.Path(KeyRef.TrustKeystore)));
        Assert.Equal(world.HeldKeys.Count(), (await signer.HealthAsync()).KeyCount);

        // The second key is appended to the same file under the same row.
        var first = File.ReadAllBytes(sshPath);
        if (firstUse == "commit")
            await signer.ImportKeyAsync(new KeyMaterial(legacy.ToPkcs8(), KeyMaterial.Pkcs8, legacyRow, KeyRef.SshKeystore), SshMigration(legacyCa));
        else
            await signer.CommitKeyAsync(generated.Key, keyId, SshCeremony(caId));
        var second = File.ReadAllBytes(sshPath);
        Assert.NotEqual(first, second);
        Assert.Equal(3, KeystoreRows(world).Count);
        Assert.Equal(new[] { keyId, legacyRow }.OrderBy(id => id), (await ListedSshKeysAsync(signer)).Keys.OrderBy(id => id));

        // A backup takes the file as it is kept, and a restore puts back only one that verifies.
        var exported = await signer.ExportKeyAsync(KeyRef.ForKeystore(KeyRef.SshKeystore), ExportWrap.ForKeystoreFile(), backup);
        Assert.Equal(second, exported);
        var restore = new SigningContext(Caller, SigningPurpose.Restore, null, null);
        var tampered = (byte[])exported.Clone();
        tampered[^20] ^= 0x01;
        await RefusedAsync(SigningRefusalReason.IntegrityFailure,
            () => signer.ImportKeyAsync(new KeyMaterial(tampered, KeyMaterial.KeystoreFile, Guid.Empty, KeyRef.SshKeystore), restore), "restore an altered SSH keystore");
        Assert.Equal(second, File.ReadAllBytes(sshPath));
        await signer.ImportKeyAsync(new KeyMaterial(first, KeyMaterial.KeystoreFile, Guid.Empty, KeyRef.SshKeystore), restore);
        Assert.Equal(first, File.ReadAllBytes(sshPath));
    }

    [Fact]
    public async Task After_a_restart_an_ssh_key_is_loaded_from_the_ssh_keystore_and_served_only_while_its_row_carries_it()
    {
        var world = SignerTestWorld.CreateWithKeystoreFiles();
        var signer = await CreateSignerAsync(world);
        var (generated, committedCa, committedKey, committedRef) = await CommitSshKeyAsync(world, signer, "ECDSA", "P-521");
        var legacy = SshFixtures.CaPrivate("rsa");
        var (importedCa, importedKey) = SeedSshCa(world, SshFixtures.Text("ca-rsa.pub"), storage: SshCaKeyStorage.LegacyFile, enabled: false);
        await signer.ImportKeyAsync(new KeyMaterial(legacy.ToPkcs8(), KeyMaterial.Pkcs8, importedKey, KeyRef.SshKeystore), SshMigration(importedCa));
        var sshPath = world.Files!.Path(KeyRef.SshKeystore);
        var fileBytes = File.ReadAllBytes(sshPath);

        // A new signer over the same files and database.
        var restarted = world.Restart();
        var second = await CreateSignerAsync(restarted);

        var listed = await ListedSshKeysAsync(second);
        Assert.Equal(new[] { committedKey, importedKey }.OrderBy(id => id), listed.Keys.OrderBy(id => id));
        Assert.All(listed.Values, k =>
        {
            Assert.Equal(KeyKind.SshCa, k.Kind);
            Assert.Equal(KeyRef.SshKeystore, k.Key.Keystore);
            Assert.Null(k.SpaceId);
        });
        Assert.Equal(SshKeyOf(generated.PublicKeyDer), SshKeyOf(listed[committedKey].PublicKeyDer));
        Assert.Equal(legacy.PublicKey, SshKeyOf(listed[importedKey].PublicKeyDer));
        Assert.Equal(committedCa, listed[committedKey].CaId);
        // Loaded as SSH keys and as nothing else: not among the certificate keys, which still sign.
        Assert.Equal(world.HeldKeys.Count(), (await second.HealthAsync()).KeyCount);
        Assert.DoesNotContain(await second.ListKeysAsync(Context(SigningPurpose.Ceremony, null, null)), k => k.Kind != KeyKind.SshCa && k.Key.Keystore == KeyRef.SshKeystore);
        var tbs = Typed(world, "ca-rsa", SigningPurpose.Certificate);
        Assert.True(Verify(world, "ca-rsa", await second.SignAsync(world["ca-rsa"].Ref, AlgorithmFor(world, "ca-rsa"), tbs, ContextFor(world, "ca-rsa", SigningPurpose.Certificate)), data: tbs));
        foreach (var purpose in Enum.GetValues<SigningPurpose>())
            await RefusedAsync(SigningRefusalReason.PurposeNotPermitted,
                () => second.SignAsync(committedRef, SignatureAlgorithm.FromName("SHA512withECDSA"), Tbs, InstanceContext(purpose, committedCa)), $"a raw signature under {purpose} after a restart");
        await RefusedAsync(SigningRefusalReason.OperationUnsupported, () => second.RetireKeyAsync(committedRef, SshCeremony(committedCa)), "retire a loaded key");

        // The migration that crashed before it marked the row runs again after the restart: held already, nothing written.
        await second.ImportKeyAsync(new KeyMaterial(legacy.ToPkcs8(), KeyMaterial.Pkcs8, importedKey, KeyRef.SshKeystore), SshMigration(importedCa));
        Assert.Equal(fileBytes, File.ReadAllBytes(sshPath));

        // A row rewritten to another key stops being served at once...
        AlterSshKeyRow(world, committedKey, row => row.PublicKey = AuthorizedKey(KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-521").Public));
        Assert.Equal(importedKey, Assert.Single(await ListedSshKeysAsync(second)).Key);
        // ...and a key whose row no longer carries it is not bound to that row by the next unlock.
        using (var db = world.OpenDb())
        {
            db.SshCaKeys.Remove(db.SshCaKeys.Single(k => k.Id == importedKey));
            db.SaveChanges();
        }
        var third = await CreateSignerAsync(restarted.Restart());
        Assert.Empty(await ListedSshKeysAsync(third));
        await RefusedAsync(SigningRefusalReason.UnknownKey, () => third.RetireKeyAsync(committedRef, SshCeremony(committedCa)), "retire a key the unlock did not bind");
        await RefusedAsync(SigningRefusalReason.PurposeNotPermitted,
            () => third.SignAsync(committedRef, SignatureAlgorithm.FromName("SHA512withECDSA"), Tbs, InstanceContext(SigningPurpose.SshCertificate, committedCa)), "a raw signature with an unbound key");
        Assert.Equal(fileBytes, File.ReadAllBytes(sshPath));
    }

    /// <summary>
    /// What an SSH keystore that does not verify does to the unlock: it fails, as it does for the
    /// other two files, with one of the failures the node and the signer role treat as fatal.
    /// </summary>
    [Fact]
    public async Task A_tampered_ssh_keystore_does_not_load()
    {
        var world = SignerTestWorld.CreateWithKeystoreFiles();
        var signer = await CreateSignerAsync(world);
        var files = world.Files!;
        var sshPath = files.Path(KeyRef.SshKeystore);
        await CommitSshKeyAsync(world, signer);
        await CommitSshKeyAsync(world, signer);
        var good = File.ReadAllBytes(sshPath);
        var goodRow = KeystoreRows(world)[KeyRef.SshKeystore];

        void AlterRow(Action<KeystoreEntryEntity> change)
        {
            using var db = world.OpenDb();
            change(db.Keystores.Single(k => k.Name == KeyRef.SshKeystore));
            db.SaveChanges();
        }
        byte[] Flipped(int offset)
        {
            var bytes = (byte[])good.Clone();
            bytes[offset] ^= 0x01;
            return bytes;
        }
        var tamperings = new (string Name, Action Apply)[]
        {
            ("a flipped byte in an entry", () => File.WriteAllBytes(sshPath, Flipped(good.Length / 3))),
            ("a flipped byte in the file signature", () => File.WriteAllBytes(sshPath, Flipped(good.Length - 20))),
            ("a truncated file", () => File.WriteAllBytes(sshPath, good[..(good.Length / 2)])),
            // Signed by the same system signer, but not the SSH keystore: it does not decrypt as one.
            ("the certificate keystore in its place", () => File.Copy(files.Path(KeyRef.DefaultKeystore), sshPath, overwrite: true)),
            ("the pin replaced", () => AlterRow(row => row.SigningCaSpkiSha256 = ModularCA.Keystore.Services.KeystoreService.ComputeSpkiSha256Hex(world["ca-ec"].Certificate))),
            ("the pin MAC removed", () => AlterRow(row => row.SigningCaSpkiSha256Mac = null)),
            ("the pin removed", () => AlterRow(row => { row.SigningCaSpkiSha256 = null; row.SigningCaSpkiSha256Mac = null; })),
        };

        // Untouched, it loads; each failure below is the tampering's.
        Assert.True(world.Restart().Files!.Bootstrap.Unlocked);
        foreach (var (name, apply) in tamperings)
        {
            Assert.Equal(good, File.ReadAllBytes(sshPath));
            Assert.Equal(goodRow.SigningCaSpkiSha256Mac, KeystoreRows(world)[KeyRef.SshKeystore].SigningCaSpkiSha256Mac);
            apply();

            var failure = Assert.ThrowsAny<Exception>(() => world.Restart());
            Assert.True(failure is SecurityException or CryptographicException or InvalidDataException,
                $"{name}: the unlock failed with {failure.GetType().Name} ({failure.Message}), which is not an integrity failure.");

            File.WriteAllBytes(sshPath, good);
            AlterRow(row => { row.SigningCaSpkiSha256 = goodRow.SigningCaSpkiSha256; row.SigningCaSpkiSha256Mac = goodRow.SigningCaSpkiSha256Mac; });
        }

        Assert.Equal(2, (await ListedSshKeysAsync(await CreateSignerAsync(world.Restart()))).Count);
    }

    /// <summary>
    /// An earlier version of the file is still a file the system signer signed, so the format
    /// does not tell it from the current one, for this keystore or the other two. What holds is
    /// that a key the file no longer contains is not served, whatever its row says.
    /// </summary>
    [Fact]
    public async Task An_ssh_keystore_rolled_back_to_an_earlier_version_serves_no_key_it_does_not_hold()
    {
        var world = SignerTestWorld.CreateWithKeystoreFiles();
        var signer = await CreateSignerAsync(world);
        var sshPath = world.Files!.Path(KeyRef.SshKeystore);
        var (_, _, kept, _) = await CommitSshKeyAsync(world, signer);
        var earlier = File.ReadAllBytes(sshPath);
        var (_, lostCa, lost, lostRef) = await CommitSshKeyAsync(world, signer);

        File.WriteAllBytes(sshPath, earlier);
        var restarted = await CreateSignerAsync(world.Restart());

        Assert.Equal(kept, Assert.Single(await ListedSshKeysAsync(restarted)).Key);
        await RefusedAsync(SigningRefusalReason.UnknownKey, () => restarted.RetireKeyAsync(lostRef, SshCeremony(lostCa)), "retire the key the file lost");
        Assert.DoesNotContain(lost, (await ListedSshKeysAsync(restarted)).Keys);
    }

    /// <summary>
    /// The file and its row exist together or not at all. One without the other is not read and
    /// not written over: the unlock fails, and so does the next SSH commit.
    /// </summary>
    [Theory]
    [InlineData("the file is gone", typeof(FileNotFoundException))]
    [InlineData("the row is gone", typeof(InvalidOperationException))]
    public async Task An_ssh_keystore_without_its_row_or_a_row_without_its_file_is_neither_loaded_nor_replaced(string state, Type failure)
    {
        var world = SignerTestWorld.CreateWithKeystoreFiles();
        var signer = await CreateSignerAsync(world);
        var sshPath = world.Files!.Path(KeyRef.SshKeystore);
        await CommitSshKeyAsync(world, signer);
        var good = File.ReadAllBytes(sshPath);

        if (state == "the file is gone")
        {
            File.Delete(sshPath);
        }
        else
        {
            using var db = world.OpenDb();
            db.Keystores.Remove(db.Keystores.Single(k => k.Name == KeyRef.SshKeystore));
            db.SaveChanges();
        }

        Assert.Throws(failure, () => world.Restart());

        // The running signer does not start a new keystore over the gap either.
        var generated = await signer.GenerateKeyAsync(SshSpec(), SshCeremony());
        var (caId, keyId) = SeedSshCa(world, AuthorizedKey(generated));
        await Assert.ThrowsAnyAsync<Exception>(() => signer.CommitKeyAsync(generated.Key, keyId, SshCeremony(caId)));
        Assert.DoesNotContain(keyId, (await ListedSshKeysAsync(signer)).Keys);
        if (state == "the file is gone")
            Assert.False(File.Exists(sshPath));
        else
            Assert.Equal(good, File.ReadAllBytes(sshPath));
    }
}
