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

    [Fact]
    public void The_ssh_key_directory_travels_wrapped_wherever_it_sits_inside_config()
    {
        var config = Path.Combine(_root, "app", "config");
        Assert.Equal(new[] { "dp-keys", "ssh/keys" }, BackupWrappedSecrets.Targets(config, "config/ssh/keys"));
        Assert.Equal(new[] { "dp-keys" }, BackupWrappedSecrets.Targets(config, "ssh-keys-elsewhere"));
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
