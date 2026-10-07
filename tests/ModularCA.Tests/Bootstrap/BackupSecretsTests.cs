using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Bootstrap;
using ModularCA.Bootstrap.Crypto;
using ModularCA.Keystore.Signing;
using ModularCA.Shared.Signing;
using ModularCA.Tests.Signer;
using Xunit;

namespace ModularCA.Tests.Bootstrap;

/// <summary>
/// The backup archive carries the Data Protection key ring and the SSH CA keys only wrapped by
/// the signer, and a restore writes them back through the signer at the next start. Before this,
/// both were copied into the archive in the clear with the rest of <c>config/</c>.
/// </summary>
public sealed class BackupWrappedSecretsTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"mca-backup-secrets-{Guid.NewGuid():N}");

    private static readonly byte[] RingKey = Encoding.UTF8.GetBytes("<key id=\"1\"><masterKey>c2VjcmV0LWRwLWtleS1tYXRlcmlhbA==</masterKey></key>");
    private static readonly byte[] SshKey = Encoding.UTF8.GetBytes("-----BEGIN OPENSSH PRIVATE KEY-----\nunencrypted-ssh-ca-key\n-----END OPENSSH PRIVATE KEY-----\n");

    public void Dispose()
    {
        try { Directory.Delete(_root, true); } catch { }
    }

    /// <summary>A config directory as a node keeps it: config.yaml, a policy, the key ring and SSH CA keys.</summary>
    private string SourceConfig()
    {
        var config = Path.Combine(_root, "src", "config");
        Directory.CreateDirectory(Path.Combine(config, "dp-keys"));
        Directory.CreateDirectory(Path.Combine(config, "ssh-ca-keys", "ca1"));
        Directory.CreateDirectory(Path.Combine(config, "policies"));
        File.WriteAllText(Path.Combine(config, "config.yaml"), "JWT: {}\n");
        File.WriteAllText(Path.Combine(config, "policies", "p.json"), "{}");
        File.WriteAllBytes(Path.Combine(config, "dp-keys", "key-11111111-1111-1111-1111-111111111111.xml"), RingKey);
        File.WriteAllBytes(Path.Combine(config, "ssh-ca-keys", "ca1", "ssh_ca"), SshKey);
        return config;
    }

    private static InProcessSigningService Signer(SignerTestWorld world, bool unlocked = true) => new(
        world.Keystore, world.Scopes, new DatabaseSignerAuditSink(world.Scopes), world.Persistence,
        NullLogger<InProcessSigningService>.Instance, unlocked: unlocked);

    private static bool Contains(byte[] haystack, byte[] needle) => haystack.AsSpan().IndexOf(needle) >= 0;

    [Fact]
    public void The_config_copy_leaves_the_key_ring_and_ssh_ca_keys_out()
    {
        var source = SourceConfig();
        var destination = Path.Combine(_root, "archive", "config");

        BackupRestore.CopyDirectoryFiltered(source, destination, BackupWrappedSecrets.Targets(source, null), out _);

        Assert.True(File.Exists(Path.Combine(destination, "config.yaml")));
        Assert.True(File.Exists(Path.Combine(destination, "policies", "p.json")));
        Assert.False(Directory.Exists(Path.Combine(destination, "dp-keys")));
        Assert.False(Directory.Exists(Path.Combine(destination, "ssh-ca-keys")));
        foreach (var file in Directory.GetFiles(destination, "*", SearchOption.AllDirectories))
        {
            var bytes = File.ReadAllBytes(file);
            Assert.False(Contains(bytes, RingKey) || Contains(bytes, SshKey), $"{file} carries a secret in the clear.");
        }
    }

    [Fact]
    public async Task The_wrapped_secrets_restore_onto_a_new_host_through_the_signer_at_the_next_start()
    {
        var world = SignerTestWorld.Create();
        var signer = Signer(world);
        var source = SourceConfig();
        var restoreDir = Path.Combine(_root, "extracted");

        var wrapped = await BackupWrappedSecrets.WrapAsync(signer, source, BackupWrappedSecrets.Targets(source, null),
            Path.Combine(restoreDir, BackupWrappedSecrets.ArchiveDirectory), "backup");

        Assert.Equal(new[] { "dp-keys", "ssh-ca-keys" }, wrapped);
        foreach (var blob in Directory.GetFiles(Path.Combine(restoreDir, BackupWrappedSecrets.ArchiveDirectory)))
        {
            var bytes = File.ReadAllBytes(blob);
            Assert.False(Contains(bytes, RingKey) || Contains(bytes, SshKey), $"{blob} carries a secret in the clear.");
            Assert.False(Contains(bytes, Encoding.UTF8.GetBytes("key-11111111")), $"{blob} names its files in the clear.");
        }

        // A new host: its own ring already in place, nothing of the old one.
        var target = Path.Combine(_root, "new", "config");
        Directory.CreateDirectory(Path.Combine(target, "dp-keys"));
        File.WriteAllText(Path.Combine(target, "dp-keys", "key-22222222-2222-2222-2222-222222222222.xml"), "<key id=\"2\"/>");

        Assert.Equal(2, BackupWrappedSecrets.StagePending(restoreDir, target));
        var result = await BackupWrappedSecrets.ApplyPendingAsync(signer, target);

        Assert.Empty(result.Failed);
        Assert.Equal(new[] { "dp-keys", "ssh-ca-keys" }, result.Applied.OrderBy(t => t, StringComparer.Ordinal));
        Assert.Equal(RingKey, File.ReadAllBytes(Path.Combine(target, "dp-keys", "key-11111111-1111-1111-1111-111111111111.xml")));
        Assert.True(File.Exists(Path.Combine(target, "dp-keys", "key-22222222-2222-2222-2222-222222222222.xml")));
        Assert.Equal(SshKey, File.ReadAllBytes(Path.Combine(target, "ssh-ca-keys", "ca1", "ssh_ca")));
        Assert.False(Directory.Exists(Path.Combine(target, BackupWrappedSecrets.PendingDirectoryName)));
    }

    [Fact]
    public async Task A_signer_that_cannot_wrap_fails_the_backup_rather_than_carrying_the_ring_in_the_clear()
    {
        var world = SignerTestWorld.Create();
        var source = SourceConfig();

        var ex = await Assert.ThrowsAsync<SigningRefusedException>(() => BackupWrappedSecrets.WrapAsync(
            Signer(world, unlocked: false), source, BackupWrappedSecrets.Targets(source, null), Path.Combine(_root, "out"), "backup"));

        Assert.Equal(SigningRefusalReason.SignerLocked, ex.Reason);
        Assert.False(Directory.Exists(Path.Combine(_root, "out")) && Directory.EnumerateFiles(Path.Combine(_root, "out")).Any());
    }

    [Fact]
    public async Task A_pending_secret_the_signer_cannot_unwrap_stays_for_the_next_start()
    {
        var world = SignerTestWorld.Create();
        var source = SourceConfig();
        var restoreDir = Path.Combine(_root, "extracted");
        await BackupWrappedSecrets.WrapAsync(Signer(world), source, new[] { "dp-keys" },
            Path.Combine(restoreDir, BackupWrappedSecrets.ArchiveDirectory), "backup");
        var target = Path.Combine(_root, "new", "config");
        BackupWrappedSecrets.StagePending(restoreDir, target);

        var result = await BackupWrappedSecrets.ApplyPendingAsync(Signer(world, unlocked: false), target);

        Assert.Empty(result.Applied);
        Assert.Single(result.Failed);
        Assert.Single(Directory.GetFiles(Path.Combine(target, BackupWrappedSecrets.PendingDirectoryName)));
        Assert.False(Directory.Exists(Path.Combine(target, "dp-keys")));
    }

    [Theory]
    [InlineData("../outside", "key.xml")]
    [InlineData("dp-keys", "../../escape.xml")]
    [InlineData("dp-keys", "keystore.yaml")]
    [InlineData(".", "config.yaml")]
    public void A_bundle_that_would_write_outside_its_directory_or_a_denied_file_is_refused(string target, string file)
    {
        var config = Path.Combine(_root, "cfg");
        Directory.CreateDirectory(config);
        var payload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            Version = 1,
            Target = target,
            Files = new Dictionary<string, string> { [file] = Convert.ToBase64String(new byte[] { 1 }) },
        });

        Assert.Throws<InvalidDataException>(() => BackupWrappedSecrets.Unpack(payload, config));
        Assert.Empty(Directory.GetFiles(_root, "*", SearchOption.AllDirectories));
    }

    /// <summary>
    /// The directories that hold SSH CA key files are the directories of the key files the key
    /// rows name, wherever inside config/ the retired key path setting once put them, plus the
    /// default one. Nothing is read from configuration.
    /// </summary>
    [Fact]
    public void The_ssh_key_directories_come_from_the_key_rows_and_travel_wrapped_wherever_they_sit_inside_config()
    {
        var app = Path.Combine(_root, "app");
        var config = Path.Combine(app, "config");
        var absolute = Path.Combine(config, "ssh", "keys", "11111111-1111-1111-1111-111111111111");

        // No row: the key ring and the default key directory, as before.
        Assert.Equal(new[] { "dp-keys", "ssh-ca-keys" }, BackupWrappedSecrets.Targets(config, null));
        // An absolute path, as the old service wrote it, and a relative one, as the application directory resolves it.
        Assert.Equal(new[] { "dp-keys", "ssh-ca-keys", "ssh/keys" }, BackupWrappedSecrets.Targets(config, [absolute]));
        Assert.Equal(new[] { "dp-keys", "ssh-ca-keys", "custom" }, BackupWrappedSecrets.Targets(config, ["config/custom/22222222-2222-2222-2222-222222222222"]));
        // Two rows in one directory, a row in the default directory and one below it: each directory once, an inner one inside its outer.
        Assert.Equal(new[] { "dp-keys", "ssh-ca-keys", "ssh/keys" }, BackupWrappedSecrets.Targets(config,
            [absolute, Path.Combine(config, "ssh", "keys", "other"), "config/ssh-ca-keys/a", "config/ssh-ca-keys/deeper/b"]));
        Assert.Equal(new[] { "dp-keys", "ssh-ca-keys", "ssh" }, BackupWrappedSecrets.Targets(config, [absolute, Path.Combine(config, "ssh", "top")]));
        // Outside config/ nothing is copied, so nothing is wrapped; an empty path names nothing.
        Assert.Equal(new[] { "dp-keys", "ssh-ca-keys" }, BackupWrappedSecrets.Targets(config, [Path.Combine(app, "keys-elsewhere", "k"), "", "../outside/k"]));
        // A key file directly in config/ has no directory of its own: it is named, to be left out of the copy.
        Assert.Equal(new[] { "dp-keys", "ssh-ca-keys" }, BackupWrappedSecrets.Targets(config, ["config/loose-key"]));
        Assert.Equal(new[] { "loose-key", "loose-key.pub" }, BackupWrappedSecrets.LooseLegacyKeyFiles(config, ["config/loose-key", absolute]));
    }

    /// <summary>
    /// With a key directory the old setting named, the archive carries its files wrapped and the
    /// config copy carries none of them: the gap between stage 3 and stage 4, closed.
    /// </summary>
    [Fact]
    public async Task Key_files_in_a_directory_only_a_row_names_are_wrapped_and_left_out_of_the_config_copy()
    {
        var world = SignerTestWorld.Create();
        var source = SourceConfig();
        Directory.CreateDirectory(Path.Combine(source, "custom", "ssh"));
        var keyFile = Path.Combine(source, "custom", "ssh", "33333333-3333-3333-3333-333333333333");
        File.WriteAllBytes(keyFile, SshKey);
        File.WriteAllText(keyFile + ".pub", "ssh-ed25519 AAAA custom");
        File.WriteAllBytes(Path.Combine(source, "loose"), SshKey);
        string[] rows = [keyFile, "config/loose"];

        var targets = BackupWrappedSecrets.Targets(source, rows);
        Assert.Equal(new[] { "dp-keys", "ssh-ca-keys", "custom/ssh" }, targets);
        var archive = Path.Combine(_root, "archive");
        var wrapped = await BackupWrappedSecrets.WrapAsync(Signer(world), source, targets, Path.Combine(archive, BackupWrappedSecrets.ArchiveDirectory), "backup");
        BackupRestore.CopyDirectoryFiltered(source, Path.Combine(archive, "config"), targets, out _, BackupWrappedSecrets.LooseLegacyKeyFiles(source, rows));

        Assert.Equal(new[] { "dp-keys", "ssh-ca-keys", "custom/ssh" }, wrapped);
        Assert.False(Directory.Exists(Path.Combine(archive, "config", "custom", "ssh")));
        Assert.False(File.Exists(Path.Combine(archive, "config", "loose")));
        Assert.True(File.Exists(Path.Combine(archive, "config", "config.yaml")));
        foreach (var file in Directory.GetFiles(archive, "*", SearchOption.AllDirectories))
            Assert.False(Contains(File.ReadAllBytes(file), SshKey), $"{file} carries an SSH CA key in the clear.");

        // Without the row, which is what the backup knew between stage 3 and stage 4, the same copy carries the key in the clear.
        var blind = Path.Combine(_root, "blind");
        BackupRestore.CopyDirectoryFiltered(source, blind, BackupWrappedSecrets.Targets(source, null), out _);
        Assert.Contains(Directory.GetFiles(blind, "*", SearchOption.AllDirectories), f => Contains(File.ReadAllBytes(f), SshKey));

        // The wrapped directory comes back whole on the next start after a restore.
        var target = Path.Combine(_root, "new", "config");
        BackupWrappedSecrets.StagePending(archive, target);
        var applied = await BackupWrappedSecrets.ApplyPendingAsync(Signer(world), target);
        Assert.Empty(applied.Failed);
        Assert.Equal(SshKey, File.ReadAllBytes(Path.Combine(target, "custom", "ssh", "33333333-3333-3333-3333-333333333333")));
    }

    /// <summary>
    /// An older archive's SSH CA key files are found by how they begin, wherever in its config/
    /// they lie, so the restore can say it carries them in the clear.
    /// </summary>
    [Fact]
    public void An_archives_plaintext_ssh_key_files_are_recognised_by_content_wherever_they_lie()
    {
        var source = SourceConfig();
        Directory.CreateDirectory(Path.Combine(source, "elsewhere"));
        File.WriteAllBytes(Path.Combine(source, "elsewhere", "key"), SshKey);
        File.WriteAllText(Path.Combine(source, "elsewhere", "key.pub"), "ssh-ed25519 AAAA");
        File.WriteAllBytes(Path.Combine(source, "at-the-top"), SshKey);

        Assert.Equal(new[] { ".", "elsewhere", "ssh-ca-keys/ca1" }, BackupWrappedSecrets.PlaintextSshKeyDirectoriesIn(source));
        Assert.Empty(BackupWrappedSecrets.PlaintextSshKeyDirectoriesIn(Path.Combine(_root, "no-such-directory")));
    }

    /// <summary>
    /// The restore of an archive from before the SSH keystore, on a host whose signer has one:
    /// the archive carries the key files (here under the interim wrap) and no
    /// <c>ssh-ca.keystore</c>, and its database has <c>LegacyFile</c> rows and no
    /// <c>Keystores</c> row for one. The live keystore is moved aside through the signer, the
    /// wrapped key directory is unwrapped at the next start, and only then can the import take
    /// the files: restoring an old backup is just another migration.
    /// </summary>
    [Fact]
    public async Task An_older_archive_restores_its_key_files_moves_the_live_ssh_keystore_aside_and_the_next_start_imports_them()
    {
        var world = SignerTestWorld.Create();
        var signer = Signer(world);
        var keyId = Guid.NewGuid();

        // The archive: the old host's key directory, wrapped, and no SSH keystore.
        var oldConfig = Path.Combine(_root, "old-host", "config");
        Directory.CreateDirectory(Path.Combine(oldConfig, "ssh-ca-keys"));
        File.Copy(ModularCA.Tests.Ssh.SshFixtures.PathOf("ca-ed25519.testkey"), Path.Combine(oldConfig, "ssh-ca-keys", keyId.ToString()));
        File.Copy(ModularCA.Tests.Ssh.SshFixtures.PathOf("ca-ed25519.pub"), Path.Combine(oldConfig, "ssh-ca-keys", keyId + ".pub"));
        var restoreDir = Path.Combine(_root, "extracted");
        Directory.CreateDirectory(Path.Combine(restoreDir, "keystores"));
        File.WriteAllText(Path.Combine(restoreDir, "keystores", KeyRef.DefaultKeystore), "the archive's certificate keystore");
        await BackupWrappedSecrets.WrapAsync(signer, oldConfig, BackupWrappedSecrets.Targets(oldConfig, null),
            Path.Combine(restoreDir, BackupWrappedSecrets.ArchiveDirectory), "backup");

        // The restored database: the row is still a legacy file, naming the old host's path.
        using (var db = world.OpenDb())
        {
            var ca = new ModularCA.Shared.Entities.CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Old SSH", Label = "old-ssh", Type = "SSH", IsSshCa = true, IsEnabled = true };
            db.CertificateAuthorities.Add(ca);
            db.SshCaKeys.Add(new ModularCA.Shared.Entities.SshCaKeyEntity
            {
                Id = keyId, Name = "Old SSH", KeyType = "ed25519", CertificateAuthorityId = ca.Id,
                PublicKey = ModularCA.Tests.Ssh.SshFixtures.Text("ca-ed25519.pub").Trim(), KeyStorage = ModularCA.Shared.Entities.SshCaKeyStorage.LegacyFile,
                PrivateKeyPath = Path.Combine(oldConfig, "ssh-ca-keys", keyId.ToString()).Replace("old-host", "a-host-that-is-gone"),
                IsUserCa = true, MaxValidityHours = 24,
            });
            db.SaveChanges();
        }

        // The host being restored onto has an SSH keystore of its own, from the state the restore replaces.
        var live = Encoding.ASCII.GetBytes("the live ssh-ca.keystore");
        world.Persistence.KeystoreFiles[KeyRef.SshKeystore] = (byte[])live.Clone();

        var line = await BackupRestore.ReconcileAbsentSshKeystoreAsync(signer, restoreDir);

        Assert.Contains("moved aside", line);
        Assert.DoesNotContain("⚠", line);
        Assert.False(world.Persistence.KeystoreFiles.ContainsKey(KeyRef.SshKeystore));
        var (name, movedTo) = Assert.Single(world.Persistence.MovedAside);
        Assert.Equal(KeyRef.SshKeystore, name);
        Assert.Equal(live, world.Persistence.KeystoreFiles[movedTo]);

        // The new host: the wrapped key directory is staged, and until the next start unwraps it there is no file to import.
        var app = Path.Combine(_root, "new-host");
        var config = Path.Combine(app, "config");
        Directory.CreateDirectory(config);
        BackupWrappedSecrets.StagePending(restoreDir, config);
        var state = new ModularCA.Core.Services.SshKeyImportState();
        ModularCA.Core.Services.SshKeyFileImport Import() => new(world.OpenDb(), signer, new ModularCA.Tests.Core.Services.SshAuditLog(), state,
            NullLogger<ModularCA.Core.Services.SshKeyFileImport>.Instance, app);
        var early = await Import().RunAsync();
        Assert.Equal(ModularCA.Core.Services.SshKeyImportReasons.FileMissing, Assert.Single(early.Awaiting).Code);

        // The next start: unwrap first, then import. The file is found by its name under config/ssh-ca-keys, whatever host the row names.
        var applied = await BackupWrappedSecrets.ApplyPendingAsync(signer, config);
        Assert.Equal(new[] { "ssh-ca-keys" }, applied.Applied);
        var restoredFile = Path.Combine(config, "ssh-ca-keys", keyId.ToString());
        Assert.True(File.Exists(restoredFile));

        var imported = await Import().RunAsync();

        Assert.Equal(new[] { keyId }, imported.Imported);
        Assert.False(File.Exists(restoredFile));
        Assert.Single(world.Persistence.SshAppended);
        using var read = world.OpenDb();
        Assert.Equal(ModularCA.Shared.Entities.SshCaKeyStorage.Signer, read.SshCaKeys.Single(k => k.Id == keyId).KeyStorage);
    }

    [Fact]
    public async Task A_restore_asks_the_signer_to_move_its_ssh_keystore_aside_only_when_the_archive_has_none_and_a_refusal_is_a_warning()
    {
        var world = SignerTestWorld.Create();
        var signer = Signer(world);
        world.Persistence.KeystoreFiles[KeyRef.SshKeystore] = Encoding.ASCII.GetBytes("the live ssh-ca.keystore");

        // The archive carries an SSH keystore: it is restored like the other files, and nothing is moved aside.
        var withKeystore = Path.Combine(_root, "with");
        Directory.CreateDirectory(Path.Combine(withKeystore, "keystores"));
        File.WriteAllText(Path.Combine(withKeystore, "keystores", KeyRef.SshKeystore), "the archive's");
        Assert.Null(await BackupRestore.ReconcileAbsentSshKeystoreAsync(signer, withKeystore));
        Assert.True(world.Persistence.KeystoreFiles.ContainsKey(KeyRef.SshKeystore));

        // The restored database does know an SSH keystore, and the archive carries none: the
        // signer refuses to move the file aside, and the restore says what to look at.
        using (var db = world.OpenDb())
        {
            db.Keystores.Add(new ModularCA.Shared.Entities.KeystoreEntryEntity
            {
                Name = KeyRef.SshKeystore, Passblob = new byte[32], Salt = "c2FsdA==", ScryptN = 1 << 14, ScryptR = 8, ScryptP = 1, Enabled = true,
            });
            db.SaveChanges();
        }
        var without = Path.Combine(_root, "without");
        Directory.CreateDirectory(without);
        var refused = await BackupRestore.ReconcileAbsentSshKeystoreAsync(signer, without);
        Assert.Contains("⚠", refused);
        Assert.Contains("did not move a live one aside", refused);
        Assert.Contains("has a Keystores row", refused);
        Assert.True(world.Persistence.KeystoreFiles.ContainsKey(KeyRef.SshKeystore));
        Assert.Empty(world.Persistence.MovedAside);
    }

    [Fact]
    public void An_archive_with_the_ring_in_the_clear_is_recognised_so_the_restore_can_warn()
    {
        var source = SourceConfig();
        Assert.Equal(new[] { "dp-keys", "ssh-ca-keys" }, BackupWrappedSecrets.PlaintextTargetsIn(source, BackupWrappedSecrets.Targets(source, null)));
    }
}

/// <summary>
/// The password-mode archive KDF and password floor. An archive can be guessed at offline without
/// limit, so new ones are derived with scrypt N = 2^17, r = 8; older headers still read, and a
/// header asking for absurd parameters is refused before scrypt allocates anything.
/// </summary>
public sealed class BackupKeyManagerTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"mca-backup-kdf-{Guid.NewGuid():N}");

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { }
    }

    [Fact]
    public void A_newly_set_password_is_derived_at_offline_attack_cost_and_records_it()
    {
        Assert.True(BackupKeyManager.DefaultScryptN >= 1L << 17);
        Assert.True(BackupKeyManager.DefaultScryptR >= 8);

        var path = Path.Combine(_dir, "backup-password.key");
        BackupKeyManager.WritePasswordKeyFile(path, "correct horse battery staple");
        var (kek, salt, n, r, p) = BackupKeyManager.ReadPasswordKeyFile(path);

        Assert.Equal(BackupKeyManager.DefaultScryptN, n);
        Assert.Equal(BackupKeyManager.DefaultScryptR, r);
        Assert.Equal(kek, BackupKeyManager.DeriveKey("correct horse battery staple", salt, n, r, p));
        Assert.False(BackupKeyManager.IsBelowDefaultCost(n, r));
    }

    [Fact]
    public void An_archive_header_from_before_the_raise_still_derives()
    {
        var salt = new byte[16];
        var key = BackupKeyManager.DeriveKey("an older password", salt, 32768, 8, 1);

        Assert.Equal(32, key.Length);
        Assert.True(BackupKeyManager.IsBelowDefaultCost(32768, 8));
    }

    [Theory]
    [InlineData(1L << 30, 8, 1)]
    [InlineData(1L << 20, 32, 1)]
    [InlineData(100000, 8, 1)]
    [InlineData(1L << 12, 8, 1)]
    [InlineData(1L << 17, 0, 1)]
    [InlineData(1L << 17, 8, 64)]
    public void A_header_asking_for_out_of_range_scrypt_parameters_is_refused(long n, int r, int p)
    {
        Assert.Throws<InvalidDataException>(() => BackupKeyManager.DeriveKey("whatever", new byte[16], n, r, p));
    }

    [Theory]
    [InlineData("Abcdefghij12")]
    [InlineData("Tr0ub4dor&3xyz")]
    [InlineData("aaaaaaaaaaaaaaa1")]
    [InlineData("abababababababab12")]
    public void A_short_or_repetitive_password_is_refused_for_a_new_archive(string password)
    {
        Assert.NotNull(BackupKeyManager.ValidatePassword(password));
    }

    [Theory]
    [InlineData("correct horse battery staple")]
    [InlineData("Xk9#mQ2$vL7!pR4@")]
    public void A_long_password_is_accepted(string password)
    {
        Assert.Null(BackupKeyManager.ValidatePassword(password));
    }
}
