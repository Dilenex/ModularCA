using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Keystore.Crypto;
using ModularCA.Keystore.KeystoreFormat;
using ModularCA.Keystore.Services;
using ModularCA.Keystore.Utils;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Signing;
using Xunit;

namespace ModularCA.Tests.Signer;

/// <summary>
/// A keystore unlock that fails to decrypt (a wrong secondary passphrase, a wrong main
/// passphrase) used to leave nothing in the audit trail: only verification failures were
/// recorded. It is now a <c>KeystoreUnlockFailed</c> event, in the journal of a signer that runs
/// apart and in the replayed file of a single process, and from either it becomes an audit row.
/// The tests fail the unlock for real, with passphrases they can recognise, and then look for
/// those passphrases, and their hex and base64 forms, in everything that was written: the
/// journal or file, the wire, the audit rows, the console and the exception.
/// </summary>
[Collection(KeystoreAuditLogCollection.Name)]
public sealed class KeystoreUnlockFailureAuditTests : IDisposable
{
    private const string WrongSecondary = "WRONG-secondary-passphrase-7f3a91";
    private const string WrongMain = "WRONG-main-passphrase-c04de2";

    private readonly string _root = Path.Combine(Path.GetTempPath(), "mca-unlock-failed-" + Guid.NewGuid().ToString("N"));
    private readonly string _auditName = $"audit-{Guid.NewGuid():N}";

    /// <summary>Creates the directory the test's journal, logs and position file live in.</summary>
    public KeystoreUnlockFailureAuditTests() => Directory.CreateDirectory(_root);

    /// <summary>Gives the keystore service its default file back and removes the directory.</summary>
    public void Dispose()
    {
        KeystoreService.AuditLogDirectory = null;
        KeystoreService.AuditLogFilePrefix = KeystoreAuditJournal.SharedFilePrefix;
        try { Directory.Delete(_root, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private AuditDbContext AuditDb()
        => new(new DbContextOptionsBuilder<AuditDbContext>().UseInMemoryDatabase(_auditName).Options);

    /// <summary>Every form of a passphrase the tests look for: the text of each, and its UTF-8 bytes in hex and base64.</summary>
    private static List<string> SecretForms()
    {
        var secrets = new List<string>
        {
            WrongSecondary, WrongMain, SignerKeystoreFiles.CertsSecondary, SignerKeystoreFiles.TrustSecondary, "main-passphrase-of-",
        };
        foreach (var secret in new[] { WrongSecondary, WrongMain, SignerKeystoreFiles.CertsSecondary, SignerKeystoreFiles.TrustSecondary })
        {
            var bytes = Encoding.UTF8.GetBytes(secret);
            secrets.Add(Convert.ToHexString(bytes));
            secrets.Add(Convert.ToHexString(bytes).ToLowerInvariant());
            secrets.Add(Convert.ToBase64String(bytes));
        }
        return secrets;
    }

    private static void AssertHoldsNoSecret(IEnumerable<string> secrets, string? written, string where)
        => Assert.All(secrets, secret => Assert.False(
            (written ?? string.Empty).Contains(secret, StringComparison.Ordinal), $"{where} holds a passphrase or a form of one"));

    /// <summary>
    /// Makes <c>ca-certs.keystore</c> a row from before pins had a MAC and gives the passphrase
    /// file a wrong secondary passphrase for it: the pin cannot notice, and the unlock fails when
    /// the wrong passphrase does not unwrap the main one.
    /// </summary>
    private static void GiveWrongSecondary(SignerTestWorld world)
    {
        using (var db = world.OpenDb())
        {
            db.Keystores.Single(k => k.Name == KeyRef.DefaultKeystore).SigningCaSpkiSha256Mac = null;
            db.SaveChanges();
        }
        File.WriteAllLines(world.Files!.YamlPath,
        [
            $"{KeyRef.DefaultKeystore}: {WrongSecondary}",
            $"{KeyRef.TrustKeystore}: {SignerKeystoreFiles.TrustSecondary}",
        ]);
    }

    /// <summary>Puts the passphrase file back as the world wrote it.</summary>
    private static void GiveRightSecondary(SignerTestWorld world)
    {
        using (var db = world.OpenDb())
        {
            var row = db.Keystores.Single(k => k.Name == KeyRef.DefaultKeystore);
            row.SigningCaSpkiSha256Mac = KeystoreService.ComputeSpkiPinMac(row.SigningCaSpkiSha256!, SignerKeystoreFiles.CertsSecondary);
            db.SaveChanges();
        }
        File.WriteAllLines(world.Files!.YamlPath,
        [
            $"{KeyRef.DefaultKeystore}: {SignerKeystoreFiles.CertsSecondary}",
            $"{KeyRef.TrustKeystore}: {SignerKeystoreFiles.TrustSecondary}",
        ]);
    }

    /// <summary>
    /// Replaces the wrapped main passphrase of <c>ca-trust.keystore</c> with a wrong one, wrapped
    /// correctly under the right secondary passphrase: it unwraps, and then opens no entry.
    /// </summary>
    private static void GiveWrongMain(SignerTestWorld world)
    {
        using var db = world.OpenDb();
        var row = db.Keystores.Single(k => k.Name == KeyRef.TrustKeystore);
        var kek = ScryptKeyDeriver.DeriveFileKey(KeystorePasswordWrapping.WrapDomainTag, SignerKeystoreFiles.TrustSecondary, new KeystoreFile
        {
            ScryptSalt = row.Salt, ScryptN = row.ScryptN, ScryptR = row.ScryptR, ScryptP = row.ScryptP,
        });
        var (nonce, ciphertext, tag) = AesGcmEncryptor.Encrypt(Encoding.UTF8.GetBytes(WrongMain), kek);
        row.Passblob = nonce.Concat(ciphertext).Concat(tag).ToArray();
        db.SaveChanges();
    }

    /// <summary>Runs the unlock, which must fail, and returns the exception and everything written to the console meanwhile.</summary>
    private static (Exception Failure, string Console) FailedUnlock(SignerTestWorld world)
    {
        var originalOut = Console.Out;
        var originalError = Console.Error;
        var captured = new StringWriter();
        Console.SetOut(captured);
        Console.SetError(captured);
        try
        {
            var failure = Record.Exception(() => world.Restart());
            Assert.NotNull(failure);
            return (failure!, captured.ToString());
        }
        finally
        {
            Console.SetOut(originalOut);
            Console.SetError(originalError);
        }
    }

    [Fact]
    public async Task A_failed_unlock_on_a_separate_signer_is_journalled_and_reaches_the_audit_trail_without_the_passphrase()
    {
        var paths = SignerPaths.Dedicated(Path.Combine(_root, "app"), Directory.CreateDirectory(Path.Combine(_root, "signer")).FullName);
        var journal = KeystoreAuditJournal.Open(paths.AuditJournalDirectory!, paths.LogsDirectory);
        var world = SignerTestWorld.CreateWithKeystoreFiles();
        var secrets = SecretForms();

        // A wrong secondary passphrase: the main passphrase of ca-certs.keystore does not unwrap.
        GiveWrongSecondary(world);
        var wrongSecondary = FailedUnlock(world);
        GiveRightSecondary(world);
        // A wrong main passphrase: ca-certs.keystore loads, ca-trust.keystore opens no entry.
        GiveWrongMain(world);
        var wrongMain = FailedUnlock(world);

        foreach (var (failure, console) in new[] { wrongSecondary, wrongMain })
        {
            Assert.IsAssignableFrom<System.Security.Cryptography.CryptographicException>(failure);
            AssertHoldsNoSecret(secrets, failure.ToString(), "the exception");
            AssertHoldsNoSecret(secrets, console, "the console");
        }

        // The journal: one event for each failed unlock, naming the keystore and nothing secret.
        var lines = Directory.GetFiles(journal.Directory).Order(StringComparer.Ordinal).SelectMany(File.ReadAllLines).ToList();
        Assert.All(lines, line => AssertHoldsNoSecret(secrets, line, "the journal"));
        var failed = lines.Select(l => JsonDocument.Parse(l).RootElement)
            .Where(e => e.GetProperty("action").GetString() == AuditActionType.KeystoreUnlockFailed).ToList();
        Assert.Equal([KeyRef.DefaultKeystore, KeyRef.TrustKeystore], failed.Select(e => e.GetProperty("keystoreName").GetString()));
        Assert.All(failed, e =>
        {
            Assert.False(e.GetProperty("success").GetBoolean());
            Assert.Contains("could not be decrypted", e.GetProperty("detail").GetString());
        });

        // The node reads the journal over the channel and records the events.
        await using var host = await HostedSigner.StartAsync(world, journal: journal);
        using var node = host.Connect();
        var page = await node.ReadAfterAsync(null, 0, ISignerEventJournal.MaxPageSize);
        Assert.All(page.Entries, entry => AssertHoldsNoSecret(secrets, entry.Json, "the wire"));
        await using (var auditDb = AuditDb())
        {
            var audit = new AuditService(NullLogger<AuditService>.Instance, auditDb, hashChain: new AuditHashChainService());
            var replay = new BootstrapAuditReplayService(audit, NullLogger<BootstrapAuditReplayService>.Instance, auditDb);
            var result = await new SignerKeystoreEventDelivery(
                node, replay, new SignerJournalCursorFile(Path.Combine(_root, SignerJournalCursorFile.FileName)),
                NullLogger<SignerKeystoreEventDelivery>.Instance).DeliverAsync();
            Assert.Null(result.Failure);
            Assert.Equal(page.Entries.Count, result.Recorded);
        }

        List<AuditLogEntity> rows;
        await using (var auditDb = AuditDb())
            rows = await auditDb.AuditLogs.AsNoTracking().ToListAsync();
        Assert.All(rows, row => AssertHoldsNoSecret(secrets, JsonSerializer.Serialize(row), "an audit row"));
        var failedRows = rows.Where(r => r.ActionType == AuditActionType.KeystoreUnlockFailed).ToList();
        Assert.Equal(
            new[] { KeyRef.DefaultKeystore, KeyRef.TrustKeystore }.Order(),
            failedRows.Select(r => r.TargetEntityId!).Order());
        Assert.All(failedRows, row =>
        {
            Assert.False(row.Success);
            Assert.Equal("Keystore", row.TargetEntityType);
            Assert.Equal(BootstrapAuditReplayService.SignerActor, row.ActorUsername);
            Assert.Contains("could not be decrypted", row.ErrorMessage);
            Assert.Contains("\"DeliveredBySigner\":true", row.DetailsJson);
        });
    }

    [Fact]
    public async Task A_failed_unlock_in_a_single_process_reaches_the_audit_trail_without_the_passphrase()
    {
        // One process: the keystore events go to logs/bootstrap-audit-*.jsonl, which the node replays.
        var logs = Path.Combine(_root, "logs");
        KeystoreService.AuditLogDirectory = logs;
        KeystoreService.AuditLogFilePrefix = KeystoreAuditJournal.SharedFilePrefix;
        var world = SignerTestWorld.CreateWithKeystoreFiles();
        var secrets = SecretForms();

        GiveWrongSecondary(world);
        var (failure, console) = FailedUnlock(world);

        Assert.IsAssignableFrom<System.Security.Cryptography.CryptographicException>(failure);
        AssertHoldsNoSecret(secrets, failure.ToString(), "the exception");
        AssertHoldsNoSecret(secrets, console, "the console");
        var file = Assert.Single(Directory.GetFiles(logs, "bootstrap-audit-*.jsonl"));
        var written = File.ReadAllText(file);
        AssertHoldsNoSecret(secrets, written, "the file");
        Assert.Contains(AuditActionType.KeystoreUnlockFailed, written);

        await using (var auditDb = AuditDb())
        {
            var audit = new AuditService(NullLogger<AuditService>.Instance, auditDb, hashChain: new AuditHashChainService());
            var result = await new BootstrapAuditReplayService(audit, NullLogger<BootstrapAuditReplayService>.Instance, auditDb)
                .ReplayPendingAsync(logs);
            Assert.Empty(result.Failures);
        }

        List<AuditLogEntity> rows;
        await using (var auditDb = AuditDb())
            rows = await auditDb.AuditLogs.AsNoTracking().ToListAsync();
        Assert.All(rows, row => AssertHoldsNoSecret(secrets, JsonSerializer.Serialize(row), "an audit row"));
        var failed = Assert.Single(rows, r => r.ActionType == AuditActionType.KeystoreUnlockFailed);
        Assert.False(failed.Success);
        Assert.Equal("Keystore", failed.TargetEntityType);
        Assert.Equal(KeyRef.DefaultKeystore, failed.TargetEntityId);
        Assert.Equal(BootstrapAuditReplayService.Actor, failed.ActorUsername);
        Assert.Contains("could not be decrypted", failed.ErrorMessage);
    }

    /// <summary>
    /// What is not a failure to decrypt records no such event: a passphrase file that is missing
    /// (the node of a split install runs the command-line backup without one, and falls back to
    /// a locked signer) says nothing was tried against the keystore.
    /// </summary>
    [Fact]
    public void A_missing_passphrase_file_is_not_recorded_as_a_failed_unlock()
    {
        var logs = Path.Combine(_root, "logs");
        KeystoreService.AuditLogDirectory = logs;
        KeystoreService.AuditLogFilePrefix = KeystoreAuditJournal.SharedFilePrefix;
        var world = SignerTestWorld.CreateWithKeystoreFiles();
        File.Delete(world.Files!.YamlPath);

        var (failure, _) = FailedUnlock(world);

        Assert.IsType<FileNotFoundException>(failure);
        Assert.DoesNotContain(AuditActionType.KeystoreUnlockFailed,
            string.Concat(Directory.GetFiles(logs, "bootstrap-audit-*.jsonl").Select(File.ReadAllText)));
    }
}
