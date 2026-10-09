using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Keystore.Signing;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Signing;
using ModularCA.Ssh;
using ModularCA.Tests.Ssh;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// An install from before the SSH keystore, as stage 4 of <c>docs/architecture/ssh-keystore.md</c>
/// finds one: SSH CA key rows whose storage is <c>LegacyFile</c>, each with an OpenSSH private
/// key file and its <c>.pub</c> under an application directory of the test's own. The key files
/// are the fixtures <c>ssh-keygen</c> wrote; no program runs here. The signer is the real
/// in-process one, behind a relay a test can bend.
/// </summary>
internal sealed class LegacySshInstall : IDisposable
{
    public SshNode Node { get; }
    public string BaseDirectory { get; } = Path.Combine(Path.GetTempPath(), $"mca-ssh-import-{Guid.NewGuid():N}");
    public SshKeyImportState State { get; private set; } = new();
    public CollectingLogger Log { get; } = new();

    public LegacySshInstall(bool requireKeyCeremony = false)
    {
        Node = new SshNode(requireKeyCeremony);
        Directory.CreateDirectory(DefaultKeyDirectory);
    }

    /// <summary>The directory the old service wrote key files to by default.</summary>
    public string DefaultKeyDirectory => Path.Combine(BaseDirectory, "config", "ssh-ca-keys");

    /// <summary>
    /// Seeds one SSH CA whose key is the fixture <paramref name="fixture"/> (<c>ed25519</c>,
    /// <c>p256</c>, <c>p384</c>, <c>p521</c>, <c>rsa</c>), with its key file and <c>.pub</c> in
    /// <paramref name="directory"/> (the default one when null), named by the row id as the old
    /// service named them. <paramref name="path"/> turns the file's full path into what the row
    /// records; by default the full path, as the old service recorded it.
    /// </summary>
    public SshCaKeyEntity Seed(string name, string fixture = "ed25519", string? directory = null, Func<string, Guid, string>? path = null,
        bool enabled = true, bool writeFile = true)
    {
        directory ??= DefaultKeyDirectory;
        Directory.CreateDirectory(directory);
        var id = Guid.NewGuid();
        var file = Path.Combine(directory, id.ToString());
        if (writeFile)
        {
            File.Copy(SshFixtures.PathOf($"ca-{fixture}.testkey"), file);
            File.Copy(SshFixtures.PathOf($"ca-{fixture}.pub"), file + ".pub");
        }

        var ca = new CertificateAuthorityEntity
        {
            Id = Guid.NewGuid(), Name = name, Label = name.ToLowerInvariant().Replace(' ', '-'), Type = "SSH", IsSshCa = true, IsEnabled = enabled, SpaceId = null,
        };
        var key = new SshCaKeyEntity
        {
            Id = id, Name = name, KeyType = fixture == "ed25519" ? "ed25519" : fixture == "rsa" ? "rsa" : "ecdsa", CertificateAuthorityId = ca.Id,
            PublicKey = SshFixtures.Text($"ca-{fixture}.pub").Trim(), KeyStorage = SshCaKeyStorage.LegacyFile,
            PrivateKeyPath = path?.Invoke(file, id) ?? file, IsUserCa = true, IsHostCa = true, MaxValidityHours = 24, IsEnabled = enabled,
        };
        // Through a context of its own: the node's context must not hold a copy of the row that
        // goes stale when the import switches it.
        using var db = Node.Reopen();
        db.CertificateAuthorities.Add(ca);
        db.SshCaKeys.Add(key);
        db.SaveChanges();
        return key;
    }

    /// <summary>The key file of a seeded row.</summary>
    public string FileOf(SshCaKeyEntity key, string? directory = null) => Path.Combine(directory ?? DefaultKeyDirectory, key.Id.ToString());

    /// <summary>
    /// An import over this install, in a database context of its own as the node gives it one,
    /// asking <paramref name="signer"/> (the relay when null) and writing to <paramref name="audit"/>
    /// (the node's when null).
    /// </summary>
    public SshKeyFileImport Import(ISigningService? signer = null, IAuditService? audit = null)
        => new(Node.Reopen(), signer ?? Node.Relay, audit ?? Node.Audit, State, Log, BaseDirectory);

    /// <summary>Forgets what the last pass left, as a restarted process has.</summary>
    public void Restart() => State = new SshKeyImportState();

    /// <summary>A signer over the same keys and database that has not unlocked its keystore.</summary>
    public InProcessSigningService LockedSigner()
    {
        var scopes = TestSigner.ScopesFor(Node.DatabaseName);
        return new InProcessSigningService(Node.Keystore, scopes, new DatabaseSignerAuditSink(scopes), Node.Persistence,
            NullLogger<InProcessSigningService>.Instance, unlocked: false);
    }

    /// <summary>The row as the database has it now.</summary>
    public SshCaKeyEntity Row(Guid id)
    {
        using var db = Node.Reopen();
        return db.SshCaKeys.AsNoTracking().Single(k => k.Id == id);
    }

    /// <summary>The import record of a key, or null when there is none.</summary>
    public SshKeyImportEntity? Record(Guid id)
    {
        using var db = Node.Reopen();
        return db.SshKeyImports.AsNoTracking().SingleOrDefault(i => i.SshCaKeyId == id);
    }

    public void Dispose()
    {
        Node.Dispose();
        try { Directory.Delete(BaseDirectory, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }
}

/// <summary>Keeps every line logged, rendered, so a test can read what an operator would.</summary>
internal sealed class CollectingLogger : ILogger<SshKeyFileImport>
{
    private readonly List<(LogLevel Level, string Text)> _lines = [];

    public IReadOnlyList<(LogLevel Level, string Text)> Lines
    {
        get { lock (_lines) return _lines.ToList(); }
    }

    public string Text => string.Join("\n", Lines.Select(l => l.Text));

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        lock (_lines) _lines.Add((logLevel, formatter(state, exception) + (exception == null ? string.Empty : " " + exception)));
    }
}

/// <summary>One signer or another behind the same reference, so a test can unlock "the" signer.</summary>
internal sealed class SwappableSigner(ISigningService current) : ISigningService
{
    public ISigningService Current { get; set; } = current;

    public Task<byte[]> SignAsync(KeyRef key, SignatureAlgorithm algorithm, byte[] data, SigningContext context, CancellationToken cancellationToken = default) => Current.SignAsync(key, algorithm, data, context, cancellationToken);
    public Task<byte[]> SignSshCertificateAsync(SshCertificateRequest request, SigningContext context, CancellationToken cancellationToken = default) => Current.SignSshCertificateAsync(request, context, cancellationToken);
    public Task<byte[]> DecryptAsync(KeyRef key, byte[] enveloped, SigningContext context, CancellationToken cancellationToken = default) => Current.DecryptAsync(key, enveloped, context, cancellationToken);
    public Task<GeneratedKey> GenerateKeyAsync(KeySpec spec, SigningContext context, CancellationToken cancellationToken = default) => Current.GenerateKeyAsync(spec, context, cancellationToken);
    public Task<KeyRef> ImportKeyAsync(KeyMaterial material, SigningContext context, CancellationToken cancellationToken = default) => Current.ImportKeyAsync(material, context, cancellationToken);
    public Task CommitKeyAsync(KeyRef key, Guid certificateId, SigningContext context, CancellationToken cancellationToken = default) => Current.CommitKeyAsync(key, certificateId, context, cancellationToken);
    public Task<byte[]> ExportKeyAsync(KeyRef key, ExportWrap wrap, SigningContext context, CancellationToken cancellationToken = default) => Current.ExportKeyAsync(key, wrap, context, cancellationToken);
    public Task<byte[]> WrapSecretAsync(SecretKind kind, byte[] secret, SigningContext context, CancellationToken cancellationToken = default) => Current.WrapSecretAsync(kind, secret, context, cancellationToken);
    public Task<byte[]> UnwrapSecretAsync(byte[] wrapped, SigningContext context, CancellationToken cancellationToken = default) => Current.UnwrapSecretAsync(wrapped, context, cancellationToken);
    public Task<byte[]> WrapBoundSecretAsync(SecretKind kind, string binding, byte[] secret, SigningContext context, CancellationToken cancellationToken = default) => Current.WrapBoundSecretAsync(kind, binding, secret, context, cancellationToken);
    public Task<byte[]> UnwrapBoundSecretAsync(byte[] wrapped, string binding, SigningContext context, CancellationToken cancellationToken = default) => Current.UnwrapBoundSecretAsync(wrapped, binding, context, cancellationToken);
    public Task<IReadOnlyList<KeyInfo>> ListKeysAsync(SigningContext context, CancellationToken cancellationToken = default) => Current.ListKeysAsync(context, cancellationToken);
    public Task RetireKeyAsync(KeyRef key, SigningContext context, CancellationToken cancellationToken = default) => Current.RetireKeyAsync(key, context, cancellationToken);
    public Task<SignerHealth> HealthAsync(CancellationToken cancellationToken = default) => Current.HealthAsync(cancellationToken);
}

/// <summary>An audit that cannot be written until a test lets it.</summary>
internal sealed class FailingAudit(IAuditService inner) : IAuditService
{
    public bool Fail { get; set; } = true;

    public Task LogAsync(string actionType, Guid? actorUserId, string? actorUsername, string? targetEntityType = null,
        string? targetEntityId = null, object? details = null, string? sourceIp = null, bool success = true,
        string? errorMessage = null, Guid? certificateAuthorityId = null, Guid? spaceId = null)
        => Fail
            ? throw new AuditWriteFailedException(actionType, new InvalidOperationException("The audit database is down."))
            : inner.LogAsync(actionType, actorUserId, actorUsername, targetEntityType, targetEntityId, details, sourceIp, success, errorMessage, certificateAuthorityId, spaceId);
}

/// <summary>
/// Stage 4 of <c>docs/architecture/ssh-keystore.md</c>, "The import": the plaintext SSH CA key
/// files of an older install are imported into the signer and removed, key by key, in steps
/// that can each be repeated.
/// </summary>
public class SshKeyFileImportTests
{
    /// <summary>The fixture CA keys, one of every type an SSH CA key can have.</summary>
    public static TheoryData<string, string> Fixtures => new()
    {
        { "ed25519", SshKeyTypes.Ed25519 },
        { "p256", SshKeyTypes.EcdsaP256 },
        { "p384", SshKeyTypes.EcdsaP384 },
        { "p521", SshKeyTypes.EcdsaP521 },
        { "rsa", SshKeyTypes.Rsa },
    };

    private static JsonElement Details(SshAuditLog.Entry entry)
        => JsonDocument.Parse(AuditJsonScrubber.SerializeAndScrub(entry.Details)!).RootElement;

    private static bool IsAllZeros(string path) => File.ReadAllBytes(path).All(b => b == 0);

    // ---- The import, key type by key type ---------------------------------------------------------

    [Theory]
    [MemberData(nameof(Fixtures))]
    public async Task A_key_file_is_imported_into_the_signer_its_row_switched_and_the_file_overwritten_and_deleted(string fixture, string sshKeyType)
    {
        using var install = new LegacySshInstall();
        var key = install.Seed("Fleet SSH", fixture);
        var file = install.FileOf(key);
        var original = File.ReadAllBytes(file);
        var publicKey = SshFixtures.CaPublic(fixture);
        Assert.Equal(sshKeyType, publicKey.KeyType);

        // What the file holds at the moment before it is deleted, and whether it was still whole before the overwrite.
        byte[]? beforeOverwrite = null, beforeDelete = null;
        var import = install.Import();
        import.FileStep = (step, path) =>
        {
            Assert.Equal(file, path);
            if (step == "overwrite") beforeOverwrite = File.ReadAllBytes(path);
            if (step == "delete") beforeDelete = File.ReadAllBytes(path);
        };

        var report = await import.RunAsync();

        Assert.Equal(new[] { key.Id }, report.Imported);
        Assert.Empty(report.Awaiting);
        Assert.False(report.WorkRemains);

        // The row is the signer's, and no longer names a file.
        var row = install.Row(key.Id);
        Assert.Equal(SshCaKeyStorage.Signer, row.KeyStorage);
        Assert.Null(row.PrivateKeyPath);
        Assert.Equal(key.PublicKey, row.PublicKey);

        // The file was whole until the row had been switched, was nothing but zeros of the same
        // length before it was deleted, and is gone with its .pub and the emptied directory.
        Assert.Equal(original, beforeOverwrite);
        Assert.NotNull(beforeDelete);
        Assert.Equal(original.Length, beforeDelete!.Length);
        Assert.All(beforeDelete, b => Assert.Equal(0, b));
        Assert.False(File.Exists(file));
        Assert.False(File.Exists(file + ".pub"));
        Assert.False(Directory.Exists(install.DefaultKeyDirectory));

        // The signer holds exactly that key, in the SSH keystore, under the row's id.
        Assert.Single(install.Node.Persistence.SshAppended);
        Assert.Empty(install.Node.Persistence.Appended);
        var listed = Assert.Single(await install.Node.RealSigner.ListKeysAsync(
            SigningContext.ForCa("test", SigningPurpose.Certificate, key.CertificateAuthorityId, null)));
        Assert.Equal(KeyKind.SshCa, listed.Kind);
        Assert.Equal(new KeyRef(key.Id, KeyRef.SshKeystore), listed.Key);
        Assert.Equal(publicKey, SshPublicKey.FromKeyParameter(Org.BouncyCastle.Security.PublicKeyFactory.CreateKey(listed.PublicKeyDer)));

        // What the node asked: one PKCS#8 import into the SSH keystore, under the migration purpose, naming the SSH CA at instance scope.
        var asked = Assert.Single(install.Node.Relay.Imported);
        Assert.Equal((key.Id, KeyRef.SshKeystore, KeyMaterial.Pkcs8), (asked.RowId, asked.Keystore, asked.Format));
        Assert.Equal(SigningPurpose.SshKeyMigration, asked.Context.Purpose);
        Assert.Equal(key.CertificateAuthorityId, asked.Context.CaId);
        Assert.True(asked.Context.InstanceScope);
        Assert.Null(asked.Context.CeremonyId);

        // The record that keeps the path the row gave up, and the audit entry, once.
        var record = install.Record(key.Id)!;
        Assert.Equal(("Fleet SSH", publicKey.Fingerprint, file), (record.Name, record.Fingerprint, record.FilePath));
        Assert.NotNull(record.FileRemovedAt);
        Assert.NotNull(record.AuditedAt);
        var audit = Assert.Single(install.Node.Audit.Of(AuditActionType.SshCaKeyImported));
        Assert.True(audit.Success);
        Assert.Equal((key.Id.ToString(), "SshCaKey", key.CertificateAuthorityId), (audit.TargetId, audit.TargetType, audit.CaId));
        var details = Details(audit);
        Assert.Equal("Fleet SSH", details.GetProperty("Name").GetString());
        Assert.Equal(publicKey.Fingerprint, details.GetProperty("Fingerprint").GetString());
        Assert.Equal(file, details.GetProperty("File").GetString());
        Assert.True(details.GetProperty("FileRemoved").GetBoolean());

        // And the imported key signs: a certificate through the service, verified under the row's public key.
        var certificate = SshCertificate.ParseOpenSsh((await install.Node.Service.SignUserKeyAsync(
            key.Id, SshNode.SubjectKey(), SshNode.Ci, ["alice"], 1, ["permit-pty"], install.Node.Actor)).SignedCertificate);
        Assert.Equal(publicKey, certificate.SignatureKey);
        Assert.True(certificate.VerifySignature());
        var host = SshCertificate.ParseOpenSsh((await install.Node.Service.SignHostKeyAsync(
            key.Id, SshNode.SubjectKey("ECDSA", "P-256", "host1"), ["host1.example.com"], 1, install.Node.Actor)).SignedCertificate);
        Assert.Equal(publicKey, host.SignatureKey);
        Assert.True(host.VerifySignature());

        // A second pass finds nothing to do and asks the signer nothing.
        var again = await install.Import().RunAsync();
        Assert.Empty(again.Imported);
        Assert.False(again.WorkRemains);
        Assert.Single(install.Node.Relay.Imported);
        Assert.Single(install.Node.Audit.Of(AuditActionType.SshCaKeyImported));
    }

    [Fact]
    public async Task Before_the_import_a_legacy_key_signs_nothing_and_after_it_the_same_request_is_served()
    {
        using var install = new LegacySshInstall();
        var key = install.Seed("Old SSH");

        await Assert.ThrowsAsync<SshCaKeyUnavailableException>(() =>
            install.Node.Service.SignUserKeyAsync(key.Id, SshNode.SubjectKey(), SshNode.Ci, ["alice"], 1, null, install.Node.Actor));
        Assert.Empty(install.Node.Relay.SshSigned);

        await install.Import().RunAsync();

        using var node = install.Node.Reopen();
        var service = SshServices.Ca(node, install.Node.Relay, install.Node.Audit);
        var signed = await service.SignUserKeyAsync(key.Id, SshNode.SubjectKey(), SshNode.Ci, ["alice"], 1, null, install.Node.Actor);
        Assert.True(SshCertificate.ParseOpenSsh(signed.SignedCertificate).VerifySignature());
    }

    [Fact]
    public async Task The_migration_needs_no_ceremony_on_an_instance_that_requires_them_and_takes_a_disabled_ssh_ca_too()
    {
        using var install = new LegacySshInstall(requireKeyCeremony: true);
        var enabled = install.Seed("Enabled SSH", "p256");
        var disabled = install.Seed("Disabled SSH", "ed25519", enabled: false);

        var report = await install.Import().RunAsync();

        Assert.Equal(2, report.Imported.Count);
        Assert.Equal(SshCaKeyStorage.Signer, install.Row(enabled.Id).KeyStorage);
        Assert.Equal(SshCaKeyStorage.Signer, install.Row(disabled.Id).KeyStorage);
        Assert.False(File.Exists(install.FileOf(disabled)), "The point is to take the key off the node, in service or not.");
        Assert.Equal(2, install.Node.Persistence.SshAppended.Count);
    }

    // ---- Where the file is ---------------------------------------------------------------------

    [Fact]
    public async Task A_relative_path_is_relative_to_the_application_directory_and_an_absolute_one_is_taken_as_it_is()
    {
        using var install = new LegacySshInstall();
        var custom = Path.Combine(install.BaseDirectory, "config", "keys", "ssh");
        // As the upgrade harness seeds it, and as an install whose key path setting was relative would resolve.
        var relative = install.Seed("Relative SSH", "ed25519", path: (_, id) => $"config/ssh-ca-keys/{id}");
        // As the old service recorded it, in a directory its setting named.
        var absolute = install.Seed("Absolute SSH", "p256", directory: custom);
        var backslashes = install.Seed("Windows SSH", "p384", path: (_, id) => $@"config\ssh-ca-keys\{id}");

        Assert.Equal(new[] { Path.Combine(install.DefaultKeyDirectory, relative.Id.ToString()) },
            SshKeyFileImport.Candidates($"config/ssh-ca-keys/{relative.Id}", install.BaseDirectory));

        var report = await install.Import().RunAsync();

        // The backslash path is a relative path on Windows and a file name on Linux; either way the file is found by its name.
        Assert.Equal(3, report.Imported.Count);
        Assert.Equal(Path.Combine(install.DefaultKeyDirectory, relative.Id.ToString()), install.Record(relative.Id)!.FilePath);
        Assert.Equal(Path.Combine(custom, absolute.Id.ToString()), install.Record(absolute.Id)!.FilePath);
        Assert.False(Directory.Exists(custom), "The custom key directory is removed once it is empty.");
        Assert.False(Directory.Exists(install.DefaultKeyDirectory));
        Assert.True(Directory.Exists(Path.Combine(install.BaseDirectory, "config", "keys")), "Only the directory the key was in is removed.");
        _ = backslashes;
    }

    [Fact]
    public async Task A_row_that_names_another_hosts_directory_finds_its_file_by_name_in_the_default_directory()
    {
        // A restore onto a new host: the row still names the old host's path, the file came back under config/ssh-ca-keys.
        using var install = new LegacySshInstall();
        var elsewhere = OperatingSystem.IsWindows() ? @"Q:\opt\old-host\config\ssh-ca-keys" : "/opt/old-host-that-is-not-here/config/ssh-ca-keys";
        var key = install.Seed("Restored SSH", "ed25519", path: (_, id) => Path.Combine(elsewhere, id.ToString()));

        var report = await install.Import().RunAsync();

        Assert.Equal(new[] { key.Id }, report.Imported);
        Assert.Equal(install.FileOf(key), install.Record(key.Id)!.FilePath);
        Assert.False(File.Exists(install.FileOf(key)));
    }

    [Fact]
    public async Task Only_the_key_file_and_its_own_pub_are_removed_and_a_directory_with_anything_else_in_it_stays()
    {
        using var install = new LegacySshInstall();
        var key = install.Seed("Fleet SSH");
        var other = install.Seed("Other SSH", "p256");
        var bystander = Path.Combine(install.DefaultKeyDirectory, "notes.txt");
        File.WriteAllText(bystander, "not a key");
        // A .pub beside the first key that is some other key's: not this row's to delete.
        File.Copy(SshFixtures.PathOf("ca-rsa.pub"), install.FileOf(key) + ".pub", overwrite: true);

        await install.Import().RunAsync();

        Assert.False(File.Exists(install.FileOf(key)));
        Assert.True(File.Exists(install.FileOf(key) + ".pub"), "A .pub that does not hold the row's key is left.");
        Assert.False(File.Exists(install.FileOf(other) + ".pub"));
        Assert.Equal("not a key", File.ReadAllText(bystander));
        Assert.Contains(install.Log.Lines, l => l.Level == LogLevel.Warning && l.Text.Contains("does not hold the public key"));
    }

    // ---- Files that cannot be imported -----------------------------------------------------------

    /// <summary>An <c>openssh-key-v1</c> file whose header names a cipher and a KDF: a key under a passphrase.</summary>
    private static string EncryptedKeyFile(SshPublicKey publicKey)
    {
        var writer = new MemoryStream();
        void Bytes(byte[] b) { writer.Write(BitConverter.IsLittleEndian ? BitConverter.GetBytes(b.Length).Reverse().ToArray() : BitConverter.GetBytes(b.Length)); writer.Write(b); }
        writer.Write(Encoding.ASCII.GetBytes("openssh-key-v1\0"));
        Bytes(Encoding.ASCII.GetBytes("aes256-ctr"));
        Bytes(Encoding.ASCII.GetBytes("bcrypt"));
        Bytes(new byte[24]);
        writer.Write([0, 0, 0, 1]);
        Bytes(publicKey.Blob);
        Bytes(new byte[128]);
        return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + Convert.ToBase64String(writer.ToArray(), Base64FormattingOptions.InsertLineBreaks)
            + "\n-----END OPENSSH PRIVATE KEY-----\n";
    }

    [Fact]
    public async Task A_missing_encrypted_mismatching_or_garbage_file_leaves_its_row_as_it_is_with_a_reason_and_stops_no_other_key()
    {
        using var install = new LegacySshInstall();
        var missing = install.Seed("A Missing", "ed25519", writeFile: false);
        var encrypted = install.Seed("B Encrypted", "p256");
        File.WriteAllText(install.FileOf(encrypted), EncryptedKeyFile(SshFixtures.CaPublic("p256")));
        var mismatch = install.Seed("C Mismatch", "p384");
        File.Copy(SshFixtures.PathOf("ca-p521.testkey"), install.FileOf(mismatch), overwrite: true);
        var garbage = install.Seed("D Garbage", "p521");
        File.WriteAllBytes(install.FileOf(garbage), [0x01, 0x02, 0xFF, 0xFE, 0x00, 0x7F]);
        var publicOnly = install.Seed("E Public Only", "rsa");
        File.Copy(SshFixtures.PathOf("ca-rsa.pub"), install.FileOf(publicOnly), overwrite: true);
        var good = install.Seed("Z Good", "rsa");
        var untouched = new[] { encrypted, mismatch, garbage, publicOnly }.ToDictionary(k => k.Id, k => File.ReadAllBytes(install.FileOf(k)));

        var report = await install.Import().RunAsync();

        // The one good key, last by name, was imported behind five that could not be.
        Assert.Equal(new[] { good.Id }, report.Imported);
        Assert.Equal(SshCaKeyStorage.Signer, install.Row(good.Id).KeyStorage);
        Assert.Single(install.Node.Persistence.SshAppended);
        Assert.True(report.WorkRemains);
        Assert.False(report.WaitingOnSigner);

        var reasons = report.Awaiting.ToDictionary(a => a.KeyId);
        Assert.Equal(5, reasons.Count);
        Assert.Equal(SshKeyImportReasons.FileMissing, reasons[missing.Id].Code);
        Assert.Equal(SshKeyImportReasons.FileEncrypted, reasons[encrypted.Id].Code);
        Assert.Equal(SshKeyImportReasons.KeyMismatch, reasons[mismatch.Id].Code);
        Assert.Equal(SshKeyImportReasons.FileNotAKey, reasons[garbage.Id].Code);
        Assert.Equal(SshKeyImportReasons.FileNotAKey, reasons[publicOnly.Id].Code);

        // Each reason is one an operator can act on: it names the file, and what is wrong with it.
        Assert.Contains(install.FileOf(missing), reasons[missing.Id].Detail);
        Assert.Contains("disable this SSH CA", reasons[missing.Id].Detail);
        Assert.Contains("passphrase", reasons[encrypted.Id].Detail);
        Assert.Contains(SshFixtures.CaPublic("p521").Fingerprint, reasons[mismatch.Id].Detail);
        Assert.Contains(SshFixtures.CaPublic("p384").Fingerprint, reasons[mismatch.Id].Detail);
        Assert.Equal(install.FileOf(encrypted), reasons[encrypted.Id].KeyFile);
        // The sentence shown where paths do not belong names none.
        Assert.All(reasons.Values, a => Assert.DoesNotContain(install.BaseDirectory, a.Reason));

        // Nothing of the five was changed: row, path, file, and the signer was not asked about them.
        foreach (var bad in new[] { missing, encrypted, mismatch, garbage, publicOnly })
        {
            var row = install.Row(bad.Id);
            Assert.Equal(SshCaKeyStorage.LegacyFile, row.KeyStorage);
            Assert.Equal(bad.PrivateKeyPath, row.PrivateKeyPath);
            Assert.Null(install.Record(bad.Id));
        }
        foreach (var (id, bytes) in untouched)
            Assert.Equal(bytes, File.ReadAllBytes(Path.Combine(install.DefaultKeyDirectory, id.ToString())));
        Assert.Equal(new[] { good.Id }, install.Node.Relay.Imported.Select(i => i.RowId));
        Assert.Single(install.Node.Audit.Of(AuditActionType.SshCaKeyImported));

        // The state the readiness page reads has the same five, and they are logged once each, not again on the next pass.
        Assert.Equal(SshKeyImportReasons.FileEncrypted, install.State.Of(encrypted.Id)!.Code);
        Assert.Null(install.State.Of(good.Id));
        var warned = install.Log.Lines.Count(l => l.Text.Contains("is still a key file on this node"));
        Assert.Equal(5, warned);
        await install.Import().RunAsync();
        Assert.Equal(5, install.Log.Lines.Count(l => l.Text.Contains("is still a key file on this node")));

        // The operator puts the right file in place: the next pass takes it, without a restart.
        File.Copy(SshFixtures.PathOf("ca-p384.testkey"), install.FileOf(mismatch), overwrite: true);
        var later = await install.Import().RunAsync();
        Assert.Equal(new[] { mismatch.Id }, later.Imported);
        Assert.Equal(4, later.Awaiting.Count);
    }

    [Fact]
    public async Task A_row_whose_public_key_cannot_be_read_and_a_row_with_no_path_stay_as_they_are()
    {
        using var install = new LegacySshInstall();
        var unreadable = install.Seed("Unreadable Row");
        var noPath = install.Seed("No Path", "p256", path: (_, _) => "");
        using (var db = install.Node.Reopen())
        {
            db.SshCaKeys.Single(k => k.Id == unreadable.Id).PublicKey = "ssh-ed25519 not-base64!";
            db.SaveChanges();
        }

        var report = await install.Import().RunAsync();

        Assert.Empty(report.Imported);
        Assert.Equal(SshKeyImportReasons.RowUnreadable, report.Awaiting.Single(a => a.KeyId == unreadable.Id).Code);
        Assert.Equal(SshKeyImportReasons.FileMissing, report.Awaiting.Single(a => a.KeyId == noPath.Id).Code);
        Assert.Empty(install.Node.Relay.Imported);
        Assert.True(File.Exists(install.FileOf(unreadable)));
    }

    // ---- Nothing of the key is logged or left in a buffer ----------------------------------------

    [Fact]
    public async Task No_key_material_is_logged_and_the_pkcs8_the_import_held_is_zeroed_even_when_the_signer_refuses_it()
    {
        using var install = new LegacySshInstall();
        var refused = install.Seed("A Refused", "ed25519");
        var taken = install.Seed("B Taken", "p256");
        var secretLines = new[] { "ed25519", "p256" }
            .SelectMany(f => SshFixtures.Text($"ca-{f}.testkey").Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Where(l => !l.StartsWith("-----", StringComparison.Ordinal)).Skip(2).ToList();
        var pkcs8 = SshFixtures.CaPrivate("ed25519").ToPkcs8();

        // A signer that refuses the first key without ever touching the buffer it was handed.
        byte[]? handed = null;
        install.Node.Relay.OnImport = (material, context) =>
        {
            if (material.CertificateId != refused.Id)
                return install.Node.RealSigner.ImportKeyAsync(material, context);
            handed = material.Wrapped;
            Assert.Equal(pkcs8, handed);
            throw new SigningRefusedException(SigningRefusalReason.CertificateMismatch, "The row does not carry the key.");
        };

        var report = await install.Import().RunAsync();

        Assert.Equal(new[] { taken.Id }, report.Imported);
        Assert.Equal(SshKeyImportReasons.SignerRefused, Assert.Single(report.Awaiting).Code);
        Assert.NotNull(handed);
        Assert.All(handed!, b => Assert.Equal(0, b));

        var logged = install.Log.Text + string.Join("\n", report.Awaiting.Select(a => a.Detail + a.Reason));
        Assert.NotEmpty(secretLines);
        Assert.All(secretLines, line => Assert.DoesNotContain(line, logged));
        Assert.DoesNotContain("BEGIN OPENSSH", logged);
        Assert.DoesNotContain(Convert.ToBase64String(pkcs8), logged);
        Assert.DoesNotContain(Convert.ToHexString(pkcs8), logged, StringComparison.OrdinalIgnoreCase);
        // The public half may be named: the fingerprint is how an operator tells keys apart.
        Assert.Contains(SshFixtures.CaPublic("p256").Fingerprint, logged);
    }

    // ---- Every step can be repeated ---------------------------------------------------------------

    [Fact]
    public async Task A_stop_after_the_signer_took_the_key_and_before_the_row_was_switched_is_finished_by_the_next_pass()
    {
        using var install = new LegacySshInstall();
        var key = install.Seed("Fleet SSH", "p384");
        var file = install.FileOf(key);
        var original = File.ReadAllBytes(file);

        // The signer takes the key; the node stops before it hears so.
        install.Node.Relay.AfterImport = _ => throw new IOException("The node stopped here.");
        var first = await install.Import().RunAsync();

        Assert.Empty(first.Imported);
        Assert.Equal(SshKeyImportReasons.Failed, Assert.Single(first.Awaiting).Code);
        Assert.Single(install.Node.Persistence.SshAppended);
        var row = install.Row(key.Id);
        Assert.Equal((SshCaKeyStorage.LegacyFile, key.PrivateKeyPath), (row.KeyStorage, row.PrivateKeyPath));
        Assert.Equal(original, File.ReadAllBytes(file));
        Assert.Null(install.Record(key.Id));
        Assert.Empty(install.Node.Audit.Of(AuditActionType.SshCaKeyImported));

        // The next start offers the key again: the signer answers that it holds it and writes nothing more.
        install.Node.Relay.AfterImport = null;
        install.Restart();
        var second = await install.Import().RunAsync();

        Assert.Equal(new[] { key.Id }, second.Imported);
        Assert.Single(install.Node.Persistence.SshAppended);
        Assert.Equal(2, install.Node.Relay.Imported.Count);
        Assert.Equal(SshCaKeyStorage.Signer, install.Row(key.Id).KeyStorage);
        Assert.False(File.Exists(file));
        Assert.Single(install.Node.Audit.Of(AuditActionType.SshCaKeyImported));
        Assert.True(SshCertificate.ParseOpenSsh((await install.Node.Service.SignUserKeyAsync(
            key.Id, SshNode.SubjectKey(), SshNode.Ci, ["alice"], 1, null, install.Node.Actor)).SignedCertificate).VerifySignature());
    }

    [Fact]
    public async Task A_key_the_signer_took_and_does_not_list_is_not_switched_and_its_file_stays()
    {
        using var install = new LegacySshInstall();
        var key = install.Seed("Fleet SSH");
        var original = File.ReadAllBytes(install.FileOf(key));
        install.Node.Relay.RewriteListed = _ => [];

        var report = await install.Import().RunAsync();

        Assert.Equal(SshKeyImportReasons.NotConfirmed, Assert.Single(report.Awaiting).Code);
        Assert.Equal(SshCaKeyStorage.LegacyFile, install.Row(key.Id).KeyStorage);
        Assert.Equal(original, File.ReadAllBytes(install.FileOf(key)));
        Assert.Null(install.Record(key.Id));

        // A list that shows another key under the row's id is no confirmation either.
        var other = Org.BouncyCastle.X509.SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(SshFixtures.CaPublic("p256").KeyParameter).GetDerEncoded();
        install.Node.Relay.RewriteListed = listed => listed.Select(k => k with { PublicKeyDer = other }).ToList();
        Assert.Equal(SshKeyImportReasons.NotConfirmed, Assert.Single((await install.Import().RunAsync()).Awaiting).Code);
        Assert.Equal(SshCaKeyStorage.LegacyFile, install.Row(key.Id).KeyStorage);

        install.Node.Relay.RewriteListed = null;
        Assert.Equal(new[] { key.Id }, (await install.Import().RunAsync()).Imported);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task A_stop_after_the_row_was_switched_and_before_the_file_was_removed_is_finished_from_the_import_record(bool signerUnlockedAtRestart)
    {
        using var install = new LegacySshInstall();
        var key = install.Seed("Fleet SSH", "p521");
        var file = install.FileOf(key);
        var original = File.ReadAllBytes(file);

        var import = install.Import();
        import.FileStep = (step, _) => { if (step == "overwrite") throw new InvalidOperationException("The node stopped here."); };
        var first = await import.RunAsync();

        // The row is switched and no longer has the path; the file is still whole; the record has the path.
        Assert.Equal(new[] { key.Id }, first.Imported);
        Assert.Equal(1, first.FilesPending);
        Assert.True(first.WorkRemains);
        var row = install.Row(key.Id);
        Assert.Equal(SshCaKeyStorage.Signer, row.KeyStorage);
        Assert.Null(row.PrivateKeyPath);
        Assert.Equal(original, File.ReadAllBytes(file));
        var record = install.Record(key.Id)!;
        Assert.Equal(file, record.FilePath);
        Assert.Null(record.FileRemovedAt);
        Assert.Contains(install.Log.Lines, l => l.Level == LogLevel.Error && l.Text.Contains(file) && l.Text.Contains("could not be removed"));

        // The next start finds the file through the record and removes it, zeros first. It needs
        // nothing from the signer for that, so a signer still locked does not hold it up.
        install.Restart();
        byte[]? beforeDelete = null;
        var restarted = install.Import(signerUnlockedAtRestart ? null : install.LockedSigner());
        restarted.FileStep = (step, path) => { if (step == "delete") beforeDelete = File.ReadAllBytes(path); };
        var second = await restarted.RunAsync();

        Assert.Empty(second.Imported);
        Assert.False(second.WorkRemains);
        Assert.NotNull(beforeDelete);
        Assert.Equal(original.Length, beforeDelete!.Length);
        Assert.All(beforeDelete, b => Assert.Equal(0, b));
        Assert.False(File.Exists(file));
        Assert.False(File.Exists(file + ".pub"));
        Assert.NotNull(install.Record(key.Id)!.FileRemovedAt);
        Assert.Single(install.Node.Persistence.SshAppended);
        // The audit entry was written by the first pass, with the file still there, and is not written twice.
        var audit = Assert.Single(install.Node.Audit.Of(AuditActionType.SshCaKeyImported));
        Assert.False(Details(audit).GetProperty("FileRemoved").GetBoolean());
    }

    [Fact]
    public async Task A_stop_between_the_overwrite_and_the_delete_leaves_zeros_which_the_next_pass_deletes()
    {
        using var install = new LegacySshInstall();
        var key = install.Seed("Fleet SSH", "rsa");
        var file = install.FileOf(key);
        var length = new FileInfo(file).Length;

        var import = install.Import();
        import.FileStep = (step, _) => { if (step == "delete") throw new InvalidOperationException("The node stopped here."); };
        await import.RunAsync();

        Assert.True(File.Exists(file));
        Assert.Equal(length, new FileInfo(file).Length);
        Assert.True(IsAllZeros(file));
        Assert.Null(install.Record(key.Id)!.FileRemovedAt);

        install.Restart();
        var second = await install.Import().RunAsync();

        Assert.False(second.WorkRemains);
        Assert.False(File.Exists(file));
        Assert.False(File.Exists(file + ".pub"));
        Assert.NotNull(install.Record(key.Id)!.FileRemovedAt);
    }

    [Fact]
    public async Task A_stop_after_the_key_file_was_deleted_still_removes_its_pub_and_a_file_that_is_no_longer_the_key_is_left_alone()
    {
        using var install = new LegacySshInstall();
        var gone = install.Seed("A Gone", "ed25519");
        var replaced = install.Seed("B Replaced", "p256");
        var import = install.Import();
        import.FileStep = (step, _) => { if (step == "overwrite") throw new InvalidOperationException("The node stopped here."); };
        await import.RunAsync();

        // The first key's file was deleted and the node stopped before its .pub; at the second
        // key's path now sits something that is not that key.
        File.Delete(install.FileOf(gone));
        File.WriteAllText(install.FileOf(replaced), "an operator's notes, not a key");

        install.Restart();
        var second = await install.Import().RunAsync();

        Assert.False(second.WorkRemains);
        Assert.False(File.Exists(install.FileOf(gone) + ".pub"));
        Assert.NotNull(install.Record(gone.Id)!.FileRemovedAt);
        Assert.Equal("an operator's notes, not a key", File.ReadAllText(install.FileOf(replaced)));
        Assert.NotNull(install.Record(replaced.Id)!.FileRemovedAt);
        Assert.Contains(install.Log.Lines, l => l.Level == LogLevel.Warning && l.Text.Contains("no longer holds SSH CA key"));
    }

    [Fact]
    public async Task An_audit_entry_that_could_not_be_written_is_written_by_a_later_pass_and_the_file_is_removed_meanwhile()
    {
        using var install = new LegacySshInstall();
        var key = install.Seed("Fleet SSH");
        var audit = new FailingAudit(install.Node.Audit);

        var first = await install.Import(audit: audit).RunAsync();

        Assert.Equal(new[] { key.Id }, first.Imported);
        Assert.Equal(1, first.AuditsPending);
        Assert.Equal(0, first.FilesPending);
        Assert.False(File.Exists(install.FileOf(key)), "A key file is not kept on disk for want of an audit entry.");
        Assert.Null(install.Record(key.Id)!.AuditedAt);
        Assert.Empty(install.Node.Audit.Of(AuditActionType.SshCaKeyImported));

        audit.Fail = false;
        var second = await install.Import(audit: audit).RunAsync();

        Assert.False(second.WorkRemains);
        Assert.NotNull(install.Record(key.Id)!.AuditedAt);
        var entry = Assert.Single(install.Node.Audit.Of(AuditActionType.SshCaKeyImported));
        Assert.True(Details(entry).GetProperty("FileRemoved").GetBoolean());
        await install.Import(audit: audit).RunAsync();
        Assert.Single(install.Node.Audit.Of(AuditActionType.SshCaKeyImported));
    }

    [Fact]
    public async Task A_row_another_process_switched_meanwhile_is_left_to_it_and_not_imported_twice()
    {
        using var install = new LegacySshInstall();
        var key = install.Seed("Fleet SSH");
        // Another control process finishes its import between this one's read of the rows and its own import.
        install.Node.Relay.OnImport = async (material, context) =>
        {
            install.Node.Relay.OnImport = null;
            await install.Import().RunAsync();
            return await install.Node.RealSigner.ImportKeyAsync(material, context);
        };

        var report = await install.Import().RunAsync();

        Assert.Empty(report.Awaiting);
        Assert.False(report.WorkRemains);
        Assert.Equal(SshCaKeyStorage.Signer, install.Row(key.Id).KeyStorage);
        Assert.Single(install.Node.Persistence.SshAppended);
        Assert.Single(install.Node.Audit.Of(AuditActionType.SshCaKeyImported));
        Assert.False(File.Exists(install.FileOf(key)));
    }

    // ---- The signer's state -----------------------------------------------------------------------

    [Fact]
    public async Task A_signer_that_predates_the_ssh_keystore_leaves_every_row_as_it_is_and_is_named_as_one_to_upgrade_first()
    {
        using var install = new LegacySshInstall();
        var keys = new[] { install.Seed("A SSH", "ed25519"), install.Seed("B SSH", "p256"), install.Seed("C SSH", "p384") };
        var files = keys.ToDictionary(k => k.Id, k => File.ReadAllBytes(install.FileOf(k)));
        install.Node.Relay.OnImport = (_, _) => throw new SigningRefusedException(SigningRefusalReason.OperationUnsupported,
            "The signer at https://signer:8444 predates the SSH keystore: it does not take the import of an SSH CA key. Upgrade the signer first, then the node.");

        var report = await install.Import().RunAsync();

        Assert.Empty(report.Imported);
        Assert.Equal(3, report.Awaiting.Count);
        Assert.All(report.Awaiting, a =>
        {
            Assert.Equal(SshKeyImportReasons.SignerUpgradeRequired, a.Code);
            Assert.Contains(SshCaKeyUnavailableException.SignerPredatesSshKeystore, a.Detail);
            Assert.Contains("must be upgraded first", a.Reason);
        });
        // After the second such answer no further key is read or sent: the third was not offered.
        Assert.Equal(keys.Take(2).Select(k => k.Id), install.Node.Relay.Imported.Select(i => i.RowId));
        Assert.False(report.WaitingOnSigner);
        foreach (var key in keys)
        {
            var row = install.Row(key.Id);
            Assert.Equal((SshCaKeyStorage.LegacyFile, key.PrivateKeyPath), (row.KeyStorage, row.PrivateKeyPath));
            Assert.Equal(files[key.Id], File.ReadAllBytes(install.FileOf(key)));
            Assert.Null(install.Record(key.Id));
        }
        Assert.Empty(install.Node.Persistence.SshAppended);
        Assert.Empty(install.Node.Audit.Of(AuditActionType.SshCaKeyImported));

        // The signer is upgraded: the next pass imports all three, with no restart of the node.
        install.Node.Relay.OnImport = null;
        Assert.Equal(SshKeyImportNext.Run, install.State.Next(DateTime.UtcNow.AddHours(1), TimeSpan.FromMinutes(5)));
        Assert.Equal(3, (await install.Import().RunAsync()).Imported.Count);
    }

    [Fact]
    public async Task A_signer_that_answers_with_a_key_outside_the_ssh_keystore_stops_the_pass_at_once_and_no_row_is_switched()
    {
        using var install = new LegacySshInstall();
        var keys = new[] { install.Seed("A SSH", "ed25519"), install.Seed("B SSH", "p256") };
        install.Node.Relay.OnImport = (material, _) => Task.FromResult(new KeyRef(material.CertificateId, KeyRef.DefaultKeystore));

        var report = await install.Import().RunAsync();

        Assert.Empty(report.Imported);
        Assert.All(report.Awaiting, a => Assert.Equal(SshKeyImportReasons.SignerUpgradeRequired, a.Code));
        Assert.Equal(2, report.Awaiting.Count);
        Assert.Single(install.Node.Relay.Imported);
        Assert.All(keys, k =>
        {
            Assert.Equal(SshCaKeyStorage.LegacyFile, install.Row(k.Id).KeyStorage);
            Assert.True(File.Exists(install.FileOf(k)));
        });
        Assert.Contains(install.Log.Lines, l => l.Level == LogLevel.Error && l.Text.Contains(KeyRef.DefaultKeystore));
    }

    [Fact]
    public async Task One_key_the_signer_cannot_hold_does_not_stop_the_keys_after_it()
    {
        using var install = new LegacySshInstall();
        var first = install.Seed("A SSH", "ed25519");
        var odd = install.Seed("B SSH", "p256");
        var last = install.Seed("C SSH", "p384");
        install.Node.Relay.OnImport = (material, context) => material.CertificateId == odd.Id
            ? throw new SigningRefusedException(SigningRefusalReason.OperationUnsupported, $"The signer already holds a different key for SSH CA key row {odd.Id}; a row never changes key.")
            : install.Node.RealSigner.ImportKeyAsync(material, context);

        var report = await install.Import().RunAsync();

        Assert.Equal(new[] { first.Id, last.Id }, report.Imported);
        var awaiting = Assert.Single(report.Awaiting);
        Assert.Equal(odd.Id, awaiting.KeyId);
        Assert.Contains("already holds a different key", awaiting.Detail);
        Assert.Equal(SshCaKeyStorage.LegacyFile, install.Row(odd.Id).KeyStorage);
        Assert.True(File.Exists(install.FileOf(odd)));
    }

    [Fact]
    public async Task With_the_signer_locked_nothing_is_read_or_changed_and_once_it_is_unlocked_the_same_process_imports()
    {
        using var install = new LegacySshInstall();
        var keys = new[] { install.Seed("A SSH", "ed25519"), install.Seed("B SSH", "rsa") };
        var signer = new SwappableSigner(install.LockedSigner());

        var locked = await install.Import(signer).RunAsync();

        Assert.Empty(locked.Imported);
        Assert.True(locked.WaitingOnSigner);
        Assert.All(locked.Awaiting, a => Assert.Equal(SshKeyImportReasons.SignerLocked, a.Code));
        Assert.Equal(2, locked.Awaiting.Count);
        Assert.All(keys, k => Assert.Equal(SshCaKeyStorage.LegacyFile, install.Row(k.Id).KeyStorage));
        Assert.All(keys, k => Assert.True(File.Exists(install.FileOf(k))));
        Assert.Empty(install.Node.Persistence.SshAppended);
        // The retry waits for the signer, and for nothing else.
        Assert.Equal(SshKeyImportNext.RunWhenSignerUnlocked, install.State.Next(DateTime.UtcNow, TimeSpan.FromMinutes(5)));

        // The signer is unlocked. No restart: the same state, the next pass.
        signer.Current = install.Node.RealSigner;
        var unlocked = await install.Import(signer).RunAsync();

        Assert.Equal(keys.Select(k => k.Id), unlocked.Imported);
        Assert.False(unlocked.WorkRemains);
        Assert.Equal(SshKeyImportNext.Nothing, install.State.Next(DateTime.UtcNow, TimeSpan.FromMinutes(5)));
        Assert.All(keys, k => Assert.False(File.Exists(install.FileOf(k))));
    }

    [Fact]
    public async Task A_signer_that_locks_or_drops_out_during_the_pass_stops_it_and_the_rest_wait_on_the_signer()
    {
        using var install = new LegacySshInstall();
        var first = install.Seed("A SSH", "ed25519");
        var second = install.Seed("B SSH", "p256");
        var third = install.Seed("C SSH", "p384");
        install.Node.Relay.OnImport = (material, context) => material.CertificateId == second.Id
            ? throw new SigningRefusedException(SigningRefusalReason.SignerUnavailable, "The signer at https://signer:8444 is unreachable: connection refused")
            : install.Node.RealSigner.ImportKeyAsync(material, context);

        var report = await install.Import().RunAsync();

        Assert.Equal(new[] { first.Id }, report.Imported);
        Assert.True(report.WaitingOnSigner);
        Assert.Equal(new[] { second.Id, third.Id }, report.Awaiting.Select(a => a.KeyId));
        Assert.All(report.Awaiting, a => Assert.Equal(SshKeyImportReasons.SignerUnreachable, a.Code));
        Assert.Equal(new[] { first.Id, second.Id }, install.Node.Relay.Imported.Select(i => i.RowId));
        Assert.True(File.Exists(install.FileOf(third)));
    }

    // ---- When the retry runs ----------------------------------------------------------------------

    [Fact]
    public void The_retry_runs_at_once_with_no_pass_yet_waits_for_the_signer_or_the_interval_and_ends_when_nothing_is_left()
    {
        var state = new SshKeyImportState();
        var now = DateTime.UtcNow;
        var settled = TimeSpan.FromMinutes(5);
        SshKeyAwaitingImport Awaiting(string code) => new(Guid.NewGuid(), "k", code, SshKeyImportReasons.Sentence(code), "detail", null, now);

        Assert.Equal(SshKeyImportNext.Run, state.Next(now, settled));

        state.Record(new SshKeyImportReport([], [Awaiting(SshKeyImportReasons.SignerLocked)], 0, 0, WaitingOnSigner: true));
        Assert.Equal(SshKeyImportNext.RunWhenSignerUnlocked, state.Next(now.AddDays(1), settled));

        state.Record(new SshKeyImportReport([], [Awaiting(SshKeyImportReasons.FileMissing)], 0, 0, WaitingOnSigner: false));
        Assert.Equal(SshKeyImportNext.Wait, state.Next(DateTime.UtcNow.AddMinutes(4), settled));
        Assert.Equal(SshKeyImportNext.Run, state.Next(DateTime.UtcNow.AddMinutes(6), settled));

        state.Record(new SshKeyImportReport([], [], FilesPending: 1, AuditsPending: 0, WaitingOnSigner: false));
        Assert.Equal(SshKeyImportNext.Run, state.Next(DateTime.UtcNow.AddMinutes(6), settled));

        state.Record(new SshKeyImportReport([Guid.NewGuid()], [], 0, 0, false));
        Assert.Equal(SshKeyImportNext.Nothing, state.Next(DateTime.UtcNow.AddDays(1), settled));
        Assert.Equal(SshKeyImportNext.Nothing, new SshKeyImportState().Also(s => s.Record(SshKeyImportReport.Nothing)).Next(now, settled));
    }
}

internal static class SshKeyImportStateTestExtensions
{
    /// <summary>Runs <paramref name="action"/> on the state and returns the state.</summary>
    public static SshKeyImportState Also(this SshKeyImportState state, Action<SshKeyImportState> action)
    {
        action(state);
        return state;
    }
}
