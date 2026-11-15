using Xunit;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Core.Services.Hub;
using ModularCA.Core.Services.Journal;
using ModularCA.HubConnection.Contract;
using ModularCA.Journal;
using ModularCA.Keystore.Adapters;
using ModularCA.Keystore.Services;
using ModularCA.Keystore.Signing;
using ModularCA.Shared.Signing;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Signer;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;

namespace ModularCA.Tests.Journal;

/// <summary>
/// The checkpoint key as the signer keeps it, over real keystore files; the families a
/// checkpoint key is made in; and what the instance reports of the journal to its own health
/// answer and to the hub.
/// </summary>
public class JournalKeystoreAndHubTests
{
    private static ISigningService Signer(SignerTestWorld world, string journalDirectory)
        => world.Files!.Bootstrap.CreateSigner(world.Files.Directory, world.Files.YamlPath, world.Scopes,
            new DatabaseSignerAuditSink(world.Scopes), NullLogger<InProcessSigningService>.Instance, keyWrapping: null,
            journal: new SignerJournalSettings(journalDirectory, true, "0.0.0-test", new byte[32]));

    private static void Issue(ISigningService signer, SignerTestKey ca, int serial)
    {
        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(BigInteger.ValueOf(serial));
        generator.SetIssuerDN(ca.Certificate.SubjectDN);
        generator.SetSubjectDN(new Org.BouncyCastle.Asn1.X509.X509Name($"CN=leaf-{serial}"));
        generator.SetNotBefore(DateTime.UtcNow.AddMinutes(-5));
        generator.SetNotAfter(DateTime.UtcNow.AddDays(1));
        generator.SetPublicKey(KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-256").Public);
        generator.Generate(new SigningServiceSignatureFactory(signer, ca.Ref, SignatureAlgorithm.ForPublicKey(ca.PublicKey),
            SigningContext.ForCa("journal-test", SigningPurpose.Certificate, ca.CaId!.Value, ca.SpaceId)));
    }

    [Fact]
    public async Task The_checkpoint_key_is_a_key_of_its_own_in_its_own_keystore_signed_by_the_system_key()
    {
        var world = SignerTestWorld.CreateWithKeystoreFiles();
        using var sandbox = new JournalSandbox();
        var system = world["ca-rsa"];
        string pin;
        using (var db = world.OpenDb())
            pin = KeystoreService.GetPinnedSignerSpki(db, KeyRef.DefaultKeystore)!;

        var signer = Signer(world, sandbox.Home);
        Issue(signer, world["ca-ec"], 1);
        await ((IAsyncDisposable)signer).DisposeAsync();

        // A keystore file of its own, with its own row, pinned to the system signer like the others.
        Assert.True(File.Exists(world.Files!.Path(KeyRef.JournalKeystore)));
        using (var db = world.OpenDb())
            Assert.Equal(pin, db.Keystores.Single(k => k.Name == KeyRef.JournalKeystore).SigningCaSpkiSha256);
        // A backup does not carry it.
        Assert.DoesNotContain(KeyRef.JournalKeystore, KeyRef.BackupKeystores);

        var verification = sandbox.Verify();
        Assert.Null(verification.Fault);
        Assert.Empty(verification.Notes);
        Assert.True(verification.Checkpoints >= 1);
        var block = verification.Head!.Key!;
        var systemSpki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(system.PublicKey).GetDerEncoded();
        // The system key is the one pinned for the keystores: what hello answers as systemKey.
        Assert.Equal(pin, Convert.ToHexStringLower(block.SystemKey));
        Assert.Equal(pin, Convert.ToHexStringLower(JournalSignatures.KeyHash(systemSpki)));
        Assert.True(JournalSignatures.VerifyKeyBlock(block, verification.Head.InstanceId, systemSpki));
        // The instance identifier is the one the node stores: the first keystore pin.
        Assert.Equal(pin, verification.Head.InstanceId);
        // Of the system key's family, and no key the signer serves for anything else.
        var checkpointKey = Org.BouncyCastle.Security.PublicKeyFactory.CreateKey(block.Key);
        Assert.IsType<Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters>(checkpointKey);
        Assert.DoesNotContain(world.Keys.Values, k => SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(k.PublicKey).GetDerEncoded().AsSpan().SequenceEqual(block.Key));

        // A restart loads the same key: no key change is recorded.
        var restarted = world.Restart();
        var again = Signer(restarted, sandbox.Home);
        Issue(again, restarted["ca-ec"], 2);
        await ((IAsyncDisposable)again).DisposeAsync();
        Assert.DoesNotContain(sandbox.Records(), r => r.Record.Type == RecordType.CheckpointKeyChanged);
        Assert.Equal(2, sandbox.Records().Count(r => r.Record.Type == RecordType.Start));
        Assert.Null(sandbox.Verify().Fault);
    }

    [Fact]
    public async Task A_database_from_before_the_checkpoint_key_gets_a_new_key_that_the_system_key_vouches_for()
    {
        var world = SignerTestWorld.CreateWithKeystoreFiles();
        using var sandbox = new JournalSandbox();
        var first = Signer(world, sandbox.Home);
        Issue(first, world["ca-ec"], 1);
        await ((IAsyncDisposable)first).DisposeAsync();
        var oldKey = sandbox.Verify().Head!.Key!.Key;

        // A restore put back a database that never heard of the journal's keystore; the file stays.
        using (var db = world.OpenDb())
        {
            db.Keystores.Remove(db.Keystores.Single(k => k.Name == KeyRef.JournalKeystore));
            db.SaveChanges();
        }
        var restarted = world.Restart();
        var second = Signer(restarted, sandbox.Home);
        Issue(second, restarted["ca-ec"], 2);
        await ((IAsyncDisposable)second).DisposeAsync();

        // The file that could not be opened was moved aside, never deleted; a new one took its place.
        Assert.Single(Directory.GetFiles(world.Files!.Directory, KeyRef.JournalKeystore + ".bak.*"));
        Assert.True(File.Exists(world.Files.Path(KeyRef.JournalKeystore)));
        var changed = CheckpointKeyChangedPayload.Decode(sandbox.Records().Single(r => r.Record.Type == RecordType.CheckpointKeyChanged).Record.Payload);
        Assert.NotEqual(oldKey, changed.NewKey.Key);
        Assert.Null(changed.OldKeySignature);
        Assert.Null(changed.Explains);
        // The same system key signed the new block: the change is vouched for, and the journal verifies whole.
        var verification = sandbox.Verify();
        Assert.Null(verification.Fault);
        Assert.Empty(verification.Unvouched);
        Assert.Equal(changed.NewKey.Key, verification.Head!.Key!.Key);
    }

    [Fact]
    public async Task A_checkpoint_keystore_that_is_not_this_databases_is_set_aside_and_never_loaded()
    {
        // Two installs, each with a checkpoint key of its own.
        var host = SignerTestWorld.CreateWithKeystoreFiles();
        using var sandbox = new JournalSandbox();
        var first = Signer(host, sandbox.Home);
        Issue(first, host["ca-ec"], 1);
        await ((IAsyncDisposable)first).DisposeAsync();
        var other = SignerTestWorld.CreateWithKeystoreFiles();
        using var otherSandbox = new JournalSandbox();
        var theirs = Signer(other, otherSandbox.Home);
        Issue(theirs, other["ca-ec"], 1);
        await ((IAsyncDisposable)theirs).DisposeAsync();

        // The other install's file lies where this database's row expects its own: what a restore
        // of this instance's archive onto a host that ran the other leaves.
        var foreign = File.ReadAllBytes(other.Files!.Path(KeyRef.JournalKeystore));
        File.WriteAllBytes(host.Files!.Path(KeyRef.JournalKeystore), foreign);
        var oldKey = sandbox.Verify().Head!.Key!.Key;

        var restarted = host.Restart();
        var again = Signer(restarted, sandbox.Home);
        Issue(again, restarted["ca-ec"], 2);
        await ((IAsyncDisposable)again).DisposeAsync();

        // Kept aside, byte for byte; a new key in its place; the journal goes on and verifies.
        var aside = Assert.Single(Directory.GetFiles(host.Files.Directory, KeyRef.JournalKeystore + ".bak.*"));
        Assert.Equal(foreign, File.ReadAllBytes(aside));
        var verification = sandbox.Verify();
        Assert.Null(verification.Fault);
        Assert.Empty(verification.Unvouched);
        var newKey = verification.Head!.Key!.Key;
        Assert.NotEqual(oldKey, newKey);
        Assert.NotEqual(otherSandbox.Verify().Head!.Key!.Key, newKey);
        Assert.Single(sandbox.Records(), r => r.Record.Type == RecordType.CheckpointKeyChanged);
    }

    [Fact]
    public async Task A_keystores_directory_put_back_to_an_older_state_gets_a_checkpoint_key_the_system_key_vouches_for()
    {
        var world = SignerTestWorld.CreateWithKeystoreFiles();
        using var sandbox = new JournalSandbox();
        var path = world.Files!.Path(KeyRef.JournalKeystore);
        var first = Signer(world, sandbox.Home);
        Issue(first, world["ca-ec"], 1);
        await ((IAsyncDisposable)first).DisposeAsync();
        // The keystores volume as a snapshot took it.
        var snapshot = File.ReadAllBytes(path);
        var snapshotKey = sandbox.Verify().Head!.Key!.Key;

        // After the snapshot the checkpoint key is replaced (its file was lost, and the signer made another).
        File.Delete(path);
        var second = world.Restart();
        var replaced = Signer(second, sandbox.Home);
        Issue(replaced, second["ca-ec"], 2);
        await ((IAsyncDisposable)replaced).DisposeAsync();
        var currentKey = sandbox.Verify().Head!.Key!.Key;
        Assert.NotEqual(snapshotKey, currentKey);

        // The volume is rolled back beside a journal whose current checkpoint key is the newer one.
        File.WriteAllBytes(path, snapshot);
        var third = second.Restart();
        var rolledBack = Signer(third, sandbox.Home);
        Issue(rolledBack, third["ca-ec"], 3);
        await ((IAsyncDisposable)rolledBack).DisposeAsync();

        // The signer goes on: a key that is not the journal's current one, in a change the same system key signed.
        var verification = sandbox.Verify();
        Assert.Null(verification.Fault);
        Assert.Empty(verification.Unvouched);
        var changes = sandbox.Records().Where(r => r.Record.Type == RecordType.CheckpointKeyChanged).Select(r => CheckpointKeyChangedPayload.Decode(r.Record.Payload)).ToList();
        Assert.Equal(2, changes.Count);
        Assert.NotEqual(currentKey, verification.Head!.Key!.Key);
        Assert.Equal(changes[1].NewKey.Key, verification.Head.Key.Key);
        Assert.Null(changes[1].Explains);
        Assert.Null(changes[1].OldSystemKeySignature);
        Assert.Equal(changes[0].NewKey.SystemKey, changes[1].NewKey.SystemKey);
        Assert.Equal(3, sandbox.Records().Count(r => r.Record.Type == RecordType.Certificate));
    }

    [Theory]
    [InlineData("RSA", "2048", "RSA")]
    [InlineData("ECDSA", "P-256", "ECDSA")]
    [InlineData("ECDSA", "P-384", "ECDSA")]
    [InlineData("Ed25519", "", "Ed25519")]
    [InlineData("ML-DSA-65", "", "ML-DSA-65")]
    public void A_checkpoint_key_is_of_the_system_keys_family_and_both_sign_what_the_verifier_checks(string algorithm, string size, string family)
    {
        var system = KeyAlgorithmPolicy.GenerateKeyPair(algorithm, size);
        var checkpoint = SignerJournalKeys.Generate(system.Public);
        IJournalSigningKey systemKey = new HandleJournalKey(new SoftwarePrivateKeyHandle(system.Private), system.Public);
        IJournalSigningKey checkpointKey = new HandleJournalKey(new SoftwarePrivateKeyHandle(checkpoint.Private), checkpoint.Public);

        Assert.Equal(family, KeyAlgorithmPolicy.DetectKeyAlgorithm(checkpoint.Public));
        Assert.Equal(checkpoint.Public.GetType(), system.Public.GetType());
        if (system.Public is Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters ec)
            Assert.Equal(ec.Parameters.Curve.FieldSize, ((Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters)checkpoint.Public).Parameters.Curve.FieldSize);
        Assert.True(JournalSignatures.IsKnownAlgorithm(systemKey.Algorithm), systemKey.Algorithm);

        var block = JournalSignatures.MakeKeyBlock("instance", checkpointKey.PublicKey, systemKey);
        Assert.True(JournalSignatures.VerifyKeyBlock(block, "instance", systemKey.PublicKey));
        var message = JournalSignatures.CheckpointMessage("instance", 7, new byte[32]);
        var signature = checkpointKey.Sign(message);
        Assert.True(JournalSignatures.Verify(checkpointKey.PublicKey, checkpointKey.Algorithm, message, signature));
        Assert.False(JournalSignatures.Verify(checkpointKey.PublicKey, checkpointKey.Algorithm, JournalSignatures.CheckpointMessage("instance", 8, new byte[32]), signature));
        Assert.False(JournalSignatures.Verify(systemKey.PublicKey, systemKey.Algorithm, message, signature));
    }

    [Fact]
    public void A_hash_based_system_key_gets_a_lattice_checkpoint_key()
    {
        var system = KeyAlgorithmPolicy.GenerateKeyPair("SLH-DSA-SHA2-128F", "");

        Assert.Equal("ML-DSA-65", KeyAlgorithmPolicy.DetectKeyAlgorithm(SignerJournalKeys.Generate(system.Public).Public));
    }

    [Fact]
    public void The_journals_home_is_signer_journal_outside_the_keystores_unless_a_setting_names_another()
    {
        var root = Path.Combine(Path.GetTempPath(), "mca-paths-" + Guid.NewGuid().ToString("N"));
        var shared = ModularCA.Shared.Models.Config.SignerPaths.Shared(root);
        var signer = new ModularCA.Shared.Models.Config.SignerConfig();

        // The default, on one process: <base>/signer/journal, and not in the keystores directory.
        Assert.Equal("signer/journal", signer.Journal.Directory);
        Assert.Equal(Path.Combine(root, "signer", "journal"), shared.JournalDirectory(signer));
        Assert.DoesNotContain(shared.KeystoresDirectory, shared.JournalDirectory(signer), StringComparison.OrdinalIgnoreCase);
        Assert.True(signer.Journal.Enforces);

        // A relative path is taken from the application directory; an absolute one is used as it is; blank is the default.
        signer.Journal.Directory = "elsewhere";
        Assert.Equal(Path.Combine(root, "elsewhere"), shared.JournalDirectory(signer));
        var absolute = Path.Combine(Path.GetTempPath(), "journal-volume");
        signer.Journal.Directory = absolute;
        Assert.Equal(absolute, shared.JournalDirectory(signer));
        signer.Journal.Directory = "  ";
        Assert.Equal(Path.Combine(root, "signer", "journal"), shared.JournalDirectory(signer));

        // A signer with its own directory keeps it there. For the packaged split install and the
        // pod that directory is <base>/signer, so the default is the same path as on one process.
        var packaged = ModularCA.Shared.Models.Config.SignerPaths.Dedicated(root, Path.Combine(root, "signer"));
        Assert.Equal(Path.Combine(root, "signer", "journal"), packaged.JournalDirectory(new ModularCA.Shared.Models.Config.SignerConfig()));
        // A signer directory elsewhere: journal/ inside it; other relative paths are taken from it too.
        var own = Path.Combine(Path.GetTempPath(), "mca-signer-own");
        var dedicated = ModularCA.Shared.Models.Config.SignerPaths.Dedicated(root, own);
        Assert.Equal(Path.Combine(own, "journal"), dedicated.JournalDirectory(new ModularCA.Shared.Models.Config.SignerConfig()));
        signer.Journal.Directory = "./ledger";
        Assert.Equal(Path.Combine(own, "ledger"), dedicated.JournalDirectory(signer));
        signer.Journal.Directory = absolute;
        Assert.Equal(absolute, dedicated.JournalDirectory(signer));

        signer.Journal.Checks = " WARN ";
        Assert.False(signer.Journal.Enforces);
        signer.Journal.Checks = "anything else";
        Assert.True(signer.Journal.Enforces);
        Assert.Equal("MODULARCA__SIGNER__JOURNAL__DIRECTORY", EnvVarConfigOverlay.SignerJournalDirectoryVariable);
    }

    [Fact]
    public async Task A_factory_reset_sets_the_old_instances_journal_aside_inside_its_home_and_keeps_it()
    {
        using var sandbox = new JournalSandbox();
        // The install's directory, with keystores/ and the default home signer/journal beside it.
        var keystores = Path.Combine(sandbox.Root, "keystores");
        Directory.CreateDirectory(keystores);
        sandbox.Home = Path.Combine(sandbox.Root, "signer", "journal");
        await using (var writer = sandbox.Open())
            await writer.AppendAsync(RecordType.Disabled, 1, new DisabledPayload(DisabledKind.Space, "s", 1).Encode());
        var segment = Directory.GetFiles(sandbox.Directory).Single();
        var bytes = File.ReadAllBytes(segment);
        File.WriteAllText(Path.Combine(keystores, KeyRef.JournalKeystore), "the old instance's checkpoint key");

        ModularCA.Bootstrap.BootstrapModularCA.SetJournalAside(keystores);

        // current/ was renamed inside the home; the home itself is where it was.
        Assert.False(Directory.Exists(sandbox.Directory));
        Assert.False(File.Exists(Path.Combine(keystores, KeyRef.JournalKeystore)));
        var aside = Assert.Single(Directory.GetDirectories(sandbox.Home));
        Assert.Matches(@"^set-aside-reset-\d{8}-\d{6}-\d{3}$", Path.GetFileName(aside));
        Assert.Equal(bytes, File.ReadAllBytes(Path.Combine(aside, Path.GetFileName(segment))));
        Assert.Single(Directory.GetFiles(keystores, KeyRef.JournalKeystore + ".reset-*"));
        // The set-aside journal still verifies where it lies.
        Assert.Null(JournalVerifier.Verify(aside).Fault);
        Assert.Equal((1, (long)bytes.Length), JournalLayout.SetAside(sandbox.Home));
        // A new instance begins its own in a new current/.
        sandbox.InstanceId = new string('b', 64);
        await using (sandbox.Open()) { }
        Assert.Null(sandbox.Verify().Fault);
        // With nothing to set aside it does nothing.
        ModularCA.Bootstrap.BootstrapModularCA.SetJournalAside(Path.Combine(keystores, "no-such-directory"));
        ModularCA.Bootstrap.BootstrapModularCA.SetJournalAside(keystores + "-none");
    }

    private static SignerJournalInfo Info(bool available = true, long? free = 50L << 30, long uncheckpointed = 0, DateTime? checkpointAt = null, string? fault = null)
        => new(available, fault, 100, new string('a', 64), checkpointAt ?? Now.AddSeconds(-2), uncheckpointed, 3L << 20, free);

    private static readonly DateTime Now = new(2026, 11, 13, 9, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void The_journal_is_reported_before_a_full_volume_stops_issuance()
    {
        Assert.Equal((SignerJournalState.None, (string?)null), SignerJournalState.Assess(null, Now));
        Assert.Equal((SignerJournalState.Ok, (string?)null), SignerJournalState.Assess(Info(), Now));
        // The free space could not be read: nothing is claimed.
        Assert.Equal(SignerJournalState.Ok, SignerJournalState.Assess(Info(free: null), Now).Status);

        var low = SignerJournalState.Assess(Info(free: 700L << 20), Now);
        Assert.Equal(SignerJournalState.LowSpace, low.Status);
        Assert.Contains("700 MiB free", low.Message!, StringComparison.Ordinal);
        Assert.Contains("A full volume stops issuance", low.Message!, StringComparison.Ordinal);

        var critical = SignerJournalState.Assess(Info(free: 20L << 20), Now);
        Assert.Equal(SignerJournalState.CriticalSpace, critical.Status);
        Assert.Contains("issues no certificate and signs no CRL", critical.Message!, StringComparison.Ordinal);

        var down = SignerJournalState.Assess(Info(available: false, fault: "There is not enough space on the disk."), Now);
        Assert.Equal(SignerJournalState.Unavailable, down.Status);
        Assert.Contains("There is not enough space on the disk.", down.Message!, StringComparison.Ordinal);

        // Records waiting for a checkpoint that does not come.
        Assert.Equal(SignerJournalState.Ok, SignerJournalState.Assess(Info(uncheckpointed: 3, checkpointAt: Now.AddSeconds(-5)), Now).Status);
        Assert.Equal(SignerJournalState.StaleCheckpoint, SignerJournalState.Assess(Info(uncheckpointed: 3, checkpointAt: Now.AddMinutes(-5)), Now).Status);
        // An idle journal's last checkpoint may be as old as its last record.
        Assert.Equal(SignerJournalState.Ok, SignerJournalState.Assess(Info(uncheckpointed: 0, checkpointAt: Now.AddDays(-3)), Now).Status);
    }

    [Fact]
    public async Task The_inventory_carries_the_journal_as_the_readiness_check_last_read_it()
    {
        using var db = InMemoryDbContextFactory.Create($"journal-inventory-{Guid.NewGuid():N}");
        var state = new SignerJournalState();
        NodeInventoryReader Reader() => new(db, null, new SignerContactState(), new ApiCertificateProvider(),
            Path.Combine(Path.GetTempPath(), "mhi-none-" + Guid.NewGuid().ToString("N")), "0.4.5-test", NullLogger.Instance, journal: state);

        // Not asked yet, and a signer that keeps none: null.
        Assert.Null((await Reader().ReadAsync(CancellationToken.None)).Journal);
        state.Observe(null, Now);
        Assert.Null((await Reader().ReadAsync(CancellationToken.None)).Journal);

        state.Observe(Info(checkpointAt: Now.AddSeconds(-42)), Now);
        var inventory = await Reader().ReadAsync(CancellationToken.None);

        Assert.Equal(new HubInventoryJournal(true, 100, 3L << 20, 50L << 30, Now.AddSeconds(-42), 42, Now, 0, 0), inventory.Journal);
        using var json = JsonDocument.Parse(JsonSerializer.Serialize(inventory, HubLocalContract.Json));
        var journal = json.RootElement.GetProperty("journal");
        Assert.Equal(["available", "seq", "sizeBytes", "freeBytes", "lastCheckpointAtUtc", "lastCheckpointAgeSeconds", "checkedAtUtc", "setAsideJournals", "setAsideBytes"],
            journal.EnumerateObject().Select(p => p.Name));
        Assert.Equal(0, journal.GetProperty("setAsideJournals").GetInt32());

        // Journals of other instances set aside beside it: how many, and what they take of the volume.
        state.Observe(Info() with { SetAsideJournals = 2, SetAsideBytes = 7L << 20 }, Now);
        var beside = (await Reader().ReadAsync(CancellationToken.None)).Journal!;
        Assert.Equal((2, 7L << 20), (beside.SetAsideJournals, beside.SetAsideBytes));
        Assert.Equal(42, journal.GetProperty("lastCheckpointAgeSeconds").GetInt64());
        // No record, serial, hash or key is in it.
        Assert.DoesNotContain(new string('a', 64), json.RootElement.GetRawText(), StringComparison.Ordinal);

        // What the signer could not say is sent as null, like every other part of the inventory.
        state.Observe(Info(free: null) with { LastCheckpointAtUtc = null }, Now);
        using var sparse = JsonDocument.Parse(JsonSerializer.Serialize(await Reader().ReadAsync(CancellationToken.None), HubLocalContract.Json));
        Assert.Equal(JsonValueKind.Null, sparse.RootElement.GetProperty("journal").GetProperty("freeBytes").ValueKind);
        Assert.Equal(JsonValueKind.Null, sparse.RootElement.GetProperty("journal").GetProperty("lastCheckpointAtUtc").ValueKind);
        Assert.Equal(JsonValueKind.Null, sparse.RootElement.GetProperty("journal").GetProperty("lastCheckpointAgeSeconds").ValueKind);
    }

    [Fact]
    public void A_restore_marker_says_what_the_archives_manifest_says_of_itself()
    {
        var hash = new string('c', 64);
        var manifest = "{\"Version\":\"1.0\",\"Timestamp\":\"2026-11-12T01:00:07Z\",\"InstanceId\":\"" + new string('9', 64)
            + "\",\"JournalHead\":{\"Seq\":18231,\"Hash\":\"" + hash + "\"}}";

        var marker = RestoreMarkerPayload.Decode(ModularCA.Bootstrap.BackupRestore.RestoreMarkerPayload("modularca-backup-20261112-010000.enc", manifest, new DateTimeOffset(Now)));

        Assert.Equal("modularca-backup-20261112-010000.enc", marker.Archive);
        Assert.Equal(new string('9', 64), marker.ArchiveInstanceId);
        Assert.Equal(JournalFormat.ToMicros(new DateTimeOffset(2026, 11, 12, 1, 0, 7, TimeSpan.Zero)), marker.ArchiveCreatedAt);
        Assert.Equal(18231ul, marker.ArchiveHead!.Seq);
        Assert.Equal(Convert.FromHexString(hash), marker.ArchiveHead.Hash);
        Assert.Equal(JournalFormat.ToMicros(new DateTimeOffset(Now)), marker.Time);
        // The signer accepts it as the fact it is.
        Assert.Equal(marker.Encode(), NodeFacts.Normalize(RecordType.RestoreMarker, marker.Encode()));

        // An archive from before the journal names itself and nothing of a journal.
        var old = RestoreMarkerPayload.Decode(ModularCA.Bootstrap.BackupRestore.RestoreMarkerPayload("old.zip", """{"Version":"1.0","Timestamp":"2026-01-01T00:00:00Z"}""", new DateTimeOffset(Now)));
        Assert.Null(old.ArchiveHead);
        Assert.Null(old.ArchiveInstanceId);
        Assert.Equal("old.zip", old.Archive);
    }
}
