using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Keystore.Services;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Signing;
using ModularCA.Signer.Client;
using ModularCA.Ssh;
using Org.BouncyCastle.Security;
using Xunit;

namespace ModularCA.Tests.Signer;

/// <summary>
/// A signer that runs apart from the node cannot reach the audit database, so its keystore
/// events (loaded, created, a key appended, a verification failure) used to stay in its own
/// <c>logs/</c> and never reach the audit trail. They are now kept in a journal in the signer's
/// directory and read by the node over the signer channel. These tests run the split end to
/// end: real keystore files unlocked and written through the keystore service, the real signer
/// host behind mutual TLS with the pins, the node's client, and the audit service on its hash
/// chain. An event appears in the trail once; what was emitted while the node or the signer was
/// away arrives later, in order; a second delivery adds nothing; nothing the node can send
/// changes the journal; and no row, wire message or journal line holds a secret.
/// </summary>
[Collection(KeystoreAuditLogCollection.Name)]
public sealed class SignerKeystoreEventDeliveryTests : IDisposable
{
    private const string Caller = "delivery-test";

    private readonly string _root = Path.Combine(Path.GetTempPath(), "mca-signer-journal-" + Guid.NewGuid().ToString("N"));
    private readonly string _auditName = $"audit-{Guid.NewGuid():N}";
    private readonly SignerPaths _paths;
    private readonly KeystoreAuditJournal _journal;

    /// <summary>Points the keystore service's events at a journal in a signer directory of this test's own, as the signer role does.</summary>
    public SignerKeystoreEventDeliveryTests()
    {
        var signerDir = Path.Combine(_root, "signer");
        Directory.CreateDirectory(signerDir);
        Directory.CreateDirectory(Path.Combine(_root, "node", "config"));
        _paths = SignerPaths.Dedicated(Path.Combine(_root, "app"), signerDir);
        _journal = KeystoreAuditJournal.Open(_paths.AuditJournalDirectory!, _paths.LogsDirectory);
    }

    /// <summary>Gives the keystore service its default file back and removes the directories.</summary>
    public void Dispose()
    {
        KeystoreService.AuditLogDirectory = null;
        KeystoreService.AuditLogFilePrefix = KeystoreAuditJournal.SharedFilePrefix;
        try { Directory.Delete(_root, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private string CursorPath => Path.Combine(_root, "node", "config", SignerJournalCursorFile.FileName);

    private AuditDbContext AuditDb()
        => new(new DbContextOptionsBuilder<AuditDbContext>().UseInMemoryDatabase(_auditName).Options);

    /// <summary>One pass of the node's delivery over <paramref name="journal"/>, on the real audit service unless another is given.</summary>
    private async Task<SignerEventDeliveryResult> DeliverAsync(ISignerEventJournal journal, IAuditService? audit = null)
    {
        await using var auditDb = AuditDb();
        audit ??= new AuditService(NullLogger<AuditService>.Instance, auditDb, hashChain: new AuditHashChainService());
        var replay = new BootstrapAuditReplayService(audit, NullLogger<BootstrapAuditReplayService>.Instance, auditDb);
        return await new SignerKeystoreEventDelivery(
            journal, replay, new SignerJournalCursorFile(CursorPath), NullLogger<SignerKeystoreEventDelivery>.Instance).DeliverAsync();
    }

    /// <summary>The audit rows in the order of the hash chain: each row after the one whose hash it carries as its previous.</summary>
    private List<AuditLogEntity> Rows()
    {
        using var auditDb = AuditDb();
        var all = auditDb.AuditLogs.AsNoTracking().ToList();
        var byPrevious = all.Where(r => r.PreviousRecordHash != null).ToDictionary(r => r.PreviousRecordHash!);
        var hashes = all.Select(r => r.RecordHash).ToHashSet();
        var ordered = new List<AuditLogEntity>();
        var next = all.SingleOrDefault(r => r.PreviousRecordHash == null || !hashes.Contains(r.PreviousRecordHash));
        while (next != null)
        {
            ordered.Add(next);
            next = byPrevious.GetValueOrDefault(next.RecordHash!);
        }
        Assert.Equal(all.Count, ordered.Count);
        return ordered;
    }

    private static (string File, int Line) Position(AuditLogEntity row)
    {
        using var details = JsonDocument.Parse(row.DetailsJson!);
        return (details.RootElement.GetProperty("JournalFile").GetString()!, details.RootElement.GetProperty("JournalLine").GetInt32());
    }

    private Dictionary<string, byte[]> JournalFiles()
        => Directory.GetFiles(_journal.Directory).ToDictionary(f => Path.GetFileName(f), File.ReadAllBytes);

    /// <summary>
    /// Has the signer generate an SSH CA key and commit it, over the wire: the first commit
    /// creates <c>ssh-ca.keystore</c>, a later one appends to it.
    /// </summary>
    private static async Task CommitSshKeyAsync(SignerTestWorld world, ISigningService signer)
    {
        SigningContext Ceremony(Guid? caId) => new SigningContext(Caller, SigningPurpose.Ceremony, null, caId) { InstanceScope = true };

        var generated = await signer.GenerateKeyAsync(new KeySpec("Ed25519", "", Usage: KeySpec.SshUsage), Ceremony(null));
        var authorizedKey = SshPublicKey.FromKeyParameter(PublicKeyFactory.CreateKey(generated.PublicKeyDer)).ToAuthorizedKey("delivery@test");
        var caId = Guid.NewGuid();
        var keyId = Guid.NewGuid();
        using (var db = world.OpenDb())
        {
            db.CertificateAuthorities.Add(new CertificateAuthorityEntity
            {
                Id = caId, Name = $"ssh-{caId:N}", Label = $"ssh-{caId:N}", Type = "SSH", IsSshCa = true, IsEnabled = true,
            });
            db.SshCaKeys.Add(new SshCaKeyEntity
            {
                Id = keyId, Name = $"ssh-key-{keyId:N}", KeyType = "ed25519", PublicKey = authorizedKey, CertificateAuthorityId = caId,
                KeyStorage = SshCaKeyStorage.Signer, IsEnabled = true,
            });
            db.SaveChanges();
        }
        await signer.CommitKeyAsync(generated.Key, keyId, Ceremony(caId));
    }

    [Fact]
    public async Task A_keystore_event_on_the_signer_appears_once_in_the_audit_trail()
    {
        // The signer starts: it unlocks ca-certs.keystore and ca-trust.keystore.
        var world = SignerTestWorld.CreateWithKeystoreFiles();
        await using var host = await HostedSigner.StartAsync(world, journal: _journal);
        using var node = host.Connect();

        // At runtime the node has it create an SSH CA key: the signer creates ssh-ca.keystore.
        await CommitSshKeyAsync(world, node);
        var journalBefore = JournalFiles();

        var first = await DeliverAsync(node);

        Assert.Null(first.Failure);
        Assert.Equal((3, 0), (first.Recorded, first.AlreadyRecorded));
        var rows = Rows();
        Assert.Equal(
            [
                (AuditActionType.KeystoreLoaded, "ca-certs.keystore"),
                (AuditActionType.KeystoreLoaded, "ca-trust.keystore"),
                (AuditActionType.KeystoreInitialized, KeyRef.SshKeystore),
            ],
            rows.Select(r => (r.ActionType, r.TargetEntityId!)));
        Assert.All(rows, row =>
        {
            Assert.Equal("Keystore", row.TargetEntityType);
            Assert.Equal(BootstrapAuditReplayService.Actor, row.ActorUsername);
            Assert.True(row.Success);
            Assert.False(string.IsNullOrEmpty(row.RecordHash));
            Assert.Equal(AuditHashChainService.CurrentHashVersion, row.HashVersion);
            using var details = JsonDocument.Parse(row.DetailsJson!);
            Assert.True(details.RootElement.GetProperty("DeliveredBySigner").GetBoolean());
            Assert.Equal(32, details.RootElement.GetProperty(BootstrapAuditReplayService.EntryIdProperty).GetString()!.Length);
            Assert.False(string.IsNullOrEmpty(details.RootElement.GetProperty("BootstrapTimestamp").GetString()));
        });

        // A second pass, and a pass by a node that lost its note of how far it had read, add nothing.
        var second = await DeliverAsync(node);
        Assert.Equal((0, 0), (second.Recorded, second.AlreadyRecorded));
        File.Delete(CursorPath);
        var third = await DeliverAsync(node);
        Assert.Null(third.Failure);
        Assert.Equal((0, 3), (third.Recorded, third.AlreadyRecorded));
        Assert.Equal(3, Rows().Count);

        // Reading took nothing from the signer: its journal is byte for byte what it was.
        var journalAfter = JournalFiles();
        Assert.Equal(journalBefore.Keys.Order(), journalAfter.Keys.Order());
        Assert.All(journalBefore, file => Assert.Equal(file.Value, journalAfter[file.Key]));
    }

    [Fact]
    public async Task Events_emitted_while_the_node_or_the_signer_was_away_are_delivered_later_in_order()
    {
        var world = SignerTestWorld.CreateWithKeystoreFiles();
        await using var relay = new LoopbackRelay();
        var host = await HostedSigner.StartAsync(world, journal: _journal);
        relay.Target = host.Endpoint;
        using var node = HostedSigner.ConnectTo(relay.Endpoint);

        Assert.Equal(2, (await DeliverAsync(node)).Recorded);

        // The node is away. The signer restarts (both keystores loaded again) and, back in
        // service, creates ssh-ca.keystore and appends a second key to it.
        await host.DisposeAsync();
        relay.Target = null;
        relay.Drop();
        var restarted = world.Restart();
        host = await HostedSigner.StartAsync(restarted, journal: _journal);
        try
        {
            using (var other = host.Connect())
            {
                await CommitSshKeyAsync(restarted, other);
                await CommitSshKeyAsync(restarted, other);
            }

            // The node is back before it can reach the signer: nothing is recorded, nothing is lost.
            var unreachable = await DeliverAsync(node);
            Assert.True(unreachable.SignerUnreachable);
            Assert.Equal(0, unreachable.Recorded);
            Assert.Equal(2, Rows().Count);

            relay.Target = host.Endpoint;
            var delivered = await DeliverAsync(node);

            Assert.Null(delivered.Failure);
            Assert.Equal(4, delivered.Recorded);
            var rows = Rows();
            Assert.Equal(
                [
                    AuditActionType.KeystoreLoaded, AuditActionType.KeystoreLoaded,
                    AuditActionType.KeystoreLoaded, AuditActionType.KeystoreLoaded,
                    AuditActionType.KeystoreInitialized, AuditActionType.KeystoreAppended,
                ],
                rows.Select(r => r.ActionType));
            // The trail's order is the journal's order.
            var positions = rows.Select(Position).ToList();
            Assert.Equal(positions.OrderBy(p => p.File, StringComparer.Ordinal).ThenBy(p => p.Line), positions);
            Assert.Equal(positions.Count, positions.Distinct().Count());
        }
        finally
        {
            await host.DisposeAsync();
        }
    }

    /// <summary>
    /// The audit database goes away part of the way through. The position moves only past what
    /// is in the trail, and the next pass records the rest, each event once and still in order.
    /// </summary>
    [Fact]
    public async Task An_audit_database_that_refuses_part_way_leaves_the_rest_on_the_signer_for_the_next_pass()
    {
        var world = SignerTestWorld.CreateWithKeystoreFiles();
        await using var host = await HostedSigner.StartAsync(world, journal: _journal);
        using var node = host.Connect();
        await CommitSshKeyAsync(world, node);

        SignerEventDeliveryResult partial;
        await using (var auditDb = AuditDb())
        {
            var real = new AuditService(NullLogger<AuditService>.Instance, auditDb, hashChain: new AuditHashChainService());
            partial = await DeliverAsync(node, new FailingFromAuditService(real, failFromCall: 2));
        }
        Assert.NotNull(partial.Failure);
        Assert.False(partial.SignerUnreachable);
        Assert.Single(Rows());

        // One that swallows the failed write, as the node's audit service does by default.
        var swallowed = await DeliverAsync(node, new ModularCA.Tests.TestUtils.RecordingAuditService());
        Assert.Contains("did not reach the audit database", swallowed.Failure);
        Assert.Single(Rows());

        var finished = await DeliverAsync(node);
        Assert.Null(finished.Failure);
        Assert.Equal(2, finished.Recorded);
        var rows = Rows();
        Assert.Equal([AuditActionType.KeystoreLoaded, AuditActionType.KeystoreLoaded, AuditActionType.KeystoreInitialized], rows.Select(r => r.ActionType));
        Assert.Equal(3, rows.Select(Position).Distinct().Count());
    }

    /// <summary>
    /// The signer's directory was restored from a copy: the journal no longer holds the event
    /// the node last recorded where the node recorded it. The node reads from the beginning and
    /// records only what the trail lacks.
    /// </summary>
    [Fact]
    public async Task A_journal_that_is_not_the_one_read_before_is_read_again_without_duplicates()
    {
        var world = SignerTestWorld.CreateWithKeystoreFiles();
        await using var host = await HostedSigner.StartAsync(world, journal: _journal);
        using var node = host.Connect();
        Assert.Equal(2, (await DeliverAsync(node)).Recorded);

        var cursor = new SignerJournalCursorFile(CursorPath);
        var saved = cursor.Load()!;
        cursor.Save(saved with { Line = saved.Line + 40, EntryId = new string('0', 32) });
        await CommitSshKeyAsync(world, node);

        var result = await DeliverAsync(node);

        Assert.Null(result.Failure);
        Assert.True(result.StartedOver);
        Assert.Equal((1, 2), (result.Recorded, result.AlreadyRecorded));
        Assert.Equal(3, Rows().Count);
        Assert.False((await DeliverAsync(node)).StartedOver);
        Assert.Equal(3, Rows().Count);
    }

    /// <summary>
    /// A real failure, and a journal line carrying what no keystore event has: the wire takes the
    /// six fields of an event and nothing else, and no row, wire message or journal file holds a
    /// passphrase.
    /// </summary>
    [Fact]
    public async Task No_row_and_no_wire_message_holds_a_secret()
    {
        var world = SignerTestWorld.CreateWithKeystoreFiles();
        await using var host = await HostedSigner.StartAsync(world, journal: _journal);
        using var node = host.Connect();

        // The trust keystore is altered on disk: the next unlock refuses it and says so.
        var trust = world.Files!.Path(KeyRef.TrustKeystore);
        var bytes = File.ReadAllBytes(trust);
        bytes[^10] ^= 0x5A;
        File.WriteAllBytes(trust, bytes);
        Assert.NotNull(Record.Exception(() => world.Restart()));

        // And a line no code writes, with fields an event does not have.
        var today = Directory.GetFiles(_journal.Directory).Order(StringComparer.Ordinal).Last();
        File.AppendAllText(today, JsonSerializer.Serialize(new
        {
            timestamp = DateTime.UtcNow.ToString("o"),
            action = AuditActionType.KeystoreAppended,
            keystoreName = "ca-certs.keystore",
            success = true,
            detail = "added=1 total=9",
            mainPassphrase = "hunter2-main-passphrase",
            pin = "4321-token-pin",
            privateKeyPkcs8 = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC",
            details = new { password = "nested-password-value" },
        }) + Environment.NewLine);

        var page = await node.ReadAfterAsync(null, 0, ISignerEventJournal.MaxPageSize);
        var result = await DeliverAsync(node);
        Assert.Null(result.Failure);

        string[] secrets =
        [
            "hunter2-main-passphrase", "4321-token-pin", "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC", "nested-password-value",
            SignerKeystoreFiles.CertsSecondary, SignerKeystoreFiles.TrustSecondary, "main-passphrase-of-",
        ];
        Assert.NotEmpty(page.Entries);
        Assert.All(page.Entries, entry =>
        {
            Assert.All(secrets, secret => Assert.DoesNotContain(secret, entry.Json));
            using var json = JsonDocument.Parse(entry.Json);
            Assert.All(json.RootElement.EnumerateObject(), property =>
                Assert.Contains(property.Name, new[] { "timestamp", "action", "keystoreName", "success", "detail", "instanceId" }));
        });

        var rows = Rows();
        Assert.Equal(page.Entries.Count, rows.Count);
        Assert.All(rows, row =>
        {
            Assert.All(secrets, secret => Assert.DoesNotContain(secret, row.DetailsJson));
            Assert.All(secrets, secret => Assert.DoesNotContain(secret, row.ErrorMessage ?? string.Empty));
            Assert.DoesNotContain("***", row.DetailsJson);
        });
        Assert.Contains(rows, r => r.ActionType == AuditActionType.KeystoreAppended && r.DetailsJson!.Contains("added=1 total=9"));
        var failure = Assert.Single(rows, r => !r.Success);
        Assert.Contains(failure.ActionType, new[] { AuditActionType.KeystoreSignatureFailed, AuditActionType.KeystorePinMacFailed });
        Assert.Equal(KeyRef.TrustKeystore, failure.TargetEntityId);
        Assert.False(string.IsNullOrEmpty(failure.ErrorMessage));

        // What the keystore service itself wrote to the journal never held one either.
        foreach (var file in Directory.GetFiles(_journal.Directory))
        {
            var lines = File.ReadAllLines(file).Where(l => !l.Contains("hunter2-main-passphrase"));
            Assert.All(lines, line => Assert.All(secrets, secret => Assert.DoesNotContain(secret, line)));
        }
    }

    /// <summary>
    /// The call reads. The position it is given is compared with the journal's file names and
    /// never opened, a host with no journal answers with nothing, and a signer that predates the
    /// call is read as one with nothing to hand over.
    /// </summary>
    [Fact]
    public async Task The_call_only_reads_and_a_signer_with_no_journal_hands_over_nothing()
    {
        var world = SignerTestWorld.CreateWithKeystoreFiles();
        await using var host = await HostedSigner.StartAsync(world, journal: _journal);
        using var node = host.Connect();
        var outside = Path.Combine(_root, "outside.jsonl");
        File.WriteAllText(outside, "{\"action\":\"KeystoreLoaded\",\"keystoreName\":\"not-in-the-journal\"}\n");
        var before = JournalFiles();

        foreach (var position in new[] { outside, "../outside.jsonl", "..\\outside.jsonl", "keystore-audit-00000000.jsonl", "zzz" })
        {
            var page = await node.ReadAfterAsync(position, 0, 10);
            Assert.DoesNotContain(page.Entries, e => e.Json.Contains("not-in-the-journal"));
            Assert.All(page.Entries, e => Assert.StartsWith(KeystoreAuditJournal.FilePrefix + "-", e.File));
        }
        var afterEverything = await node.ReadAfterAsync("zzz", 0, 10);
        Assert.Empty(afterEverything.Entries);
        var paged = await node.ReadAfterAsync(null, 0, 1);
        Assert.Single(paged.Entries);
        Assert.True(paged.More);
        var rest = await node.ReadAfterAsync(paged.Entries[0].File, paged.Entries[0].Line, 10);
        Assert.Equal(paged.Entries[0].Json, rest.Anchor);
        Assert.Single(rest.Entries);
        Assert.False(rest.More);

        var after = JournalFiles();
        Assert.Equal(before.Keys.Order(), after.Keys.Order());
        Assert.All(before, file => Assert.Equal(file.Value, after[file.Key]));

        // The shared layout registers no journal: the node replays that signer's file itself.
        await using var shared = await HostedSigner.StartAsync(world);
        using var sharedNode = shared.Connect();
        Assert.Empty((await sharedNode.ReadAfterAsync(null, 0, 10)).Entries);
        var nothing = await DeliverAsync(sharedNode);
        Assert.Null(nothing.Failure);
        Assert.Equal(0, nothing.Recorded);
    }

    /// <summary>
    /// The keystore events an earlier build left in the signer's <c>logs/</c>, which nothing
    /// read, are moved into the journal when the signer starts, ahead of the events of this run;
    /// a last line still being written is left for the next read.
    /// </summary>
    [Fact]
    public async Task Events_an_earlier_build_left_in_the_signers_logs_are_brought_into_the_journal()
    {
        var dir = Path.Combine(_root, "upgraded");
        var paths = SignerPaths.Dedicated(Path.Combine(_root, "app"), dir);
        Directory.CreateDirectory(paths.LogsDirectory);
        var legacy = Path.Combine(paths.LogsDirectory, "bootstrap-audit-20261101.jsonl");
        File.WriteAllText(legacy,
            "{\"timestamp\":\"2026-11-01T08:00:00Z\",\"action\":\"KeystoreLoaded\",\"keystoreName\":\"ca-certs.keystore\",\"success\":true,\"detail\":\"entries=4 format=v4\",\"instanceId\":\"a\"}\n"
            + "{\"timestamp\":\"2026-11-01T09:00:00Z\",\"action\":\"KeystoreAppended\",\"keystoreName\":\"ca-certs.keystore\",\"success\":true,\"detail\":\"added=1 total=5\",\"instanceId\":\"a\"}\n"
            + "{\"timestamp\":\"2026-11-01T09:30:00Z\",\"action\":\"KeystoreApp");
        File.WriteAllText(Path.Combine(paths.LogsDirectory, "modularca-20261101.log"), "not an event file\n");

        var journal = KeystoreAuditJournal.Open(paths.AuditJournalDirectory!, paths.LogsDirectory);

        Assert.False(File.Exists(legacy));
        Assert.True(File.Exists(Path.Combine(paths.LogsDirectory, "modularca-20261101.log")));
        Assert.Equal(paths.AuditJournalDirectory, KeystoreService.AuditLogDirectory);
        Assert.Equal(KeystoreAuditJournal.FilePrefix, KeystoreService.AuditLogFilePrefix);
        var page = await journal.ReadAfterAsync(null, 0, 10);
        Assert.Equal(["KeystoreLoaded", "KeystoreAppended"],
            page.Entries.Select(e => JsonDocument.Parse(e.Json).RootElement.GetProperty("action").GetString()));
        Assert.All(page.Entries, e => Assert.Equal("keystore-audit-20261101.jsonl", e.File));

        // Opened again, as at the next start, it changes nothing.
        KeystoreAuditJournal.Open(paths.AuditJournalDirectory!, paths.LogsDirectory);
        Assert.Equal(2, (await journal.ReadAfterAsync(null, 0, 10)).Entries.Count);
    }

    /// <summary>
    /// The node runs the delivery where the audit trail is written from, the control role, and
    /// only for a remote signer with an audit database; the signer role serves its journal only
    /// from its own directory.
    /// </summary>
    [Fact]
    public void The_control_role_of_a_node_with_a_remote_signer_runs_the_delivery()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !dir.EnumerateFiles("ModularCA.sln").Any())
            dir = dir.Parent;
        Assert.NotNull(dir);
        var startup = File.ReadAllText(Path.Combine(dir!.FullName, "ModularCA.API", "StartModularCA.cs"));
        var guard = startup.IndexOf("if (!isSetupMode && controlActive && signerIsRemote && !string.IsNullOrWhiteSpace(config.DB.Audit.Database))", StringComparison.Ordinal);
        var hosted = startup.IndexOf("AddHostedService<ModularCA.API.Services.SignerKeystoreEventDeliveryService>()", StringComparison.Ordinal);
        Assert.True(guard > 0 && hosted > guard && hosted - guard < 1200, "the delivery must be registered behind its guard");

        var role = File.ReadAllText(Path.Combine(dir.FullName, "ModularCA.API", "Startup", "SignerRole.cs"));
        Assert.Contains("if (journal != null)", role);
        Assert.Contains("builder.Services.AddSingleton<ISignerEventJournal>(journal);", role);
    }

    /// <summary>Passes calls to <paramref name="inner"/> until call number <paramref name="failFromCall"/>, then throws.</summary>
    private sealed class FailingFromAuditService(IAuditService inner, int failFromCall) : IAuditService
    {
        private int _calls;

        public Task LogAsync(string actionType, Guid? actorUserId, string? actorUsername, string? targetEntityType = null,
            string? targetEntityId = null, object? details = null, string? sourceIp = null, bool success = true,
            string? errorMessage = null, Guid? certificateAuthorityId = null, Guid? spaceId = null)
            => ++_calls >= failFromCall
                ? throw new InvalidOperationException("the audit database went away")
                : inner.LogAsync(actionType, actorUserId, actorUsername, targetEntityType, targetEntityId, details,
                    sourceIp, success, errorMessage, certificateAuthorityId, spaceId);
    }
}

/// <summary>
/// Runs alone, after every other collection: <see cref="SignerKeystoreEventDeliveryTests"/> points
/// <see cref="KeystoreService.AuditLogDirectory"/>, which is one for the process, at its own
/// journal and counts the events in it, so a keystore opened or written by any other test while
/// it runs would land in the journal it reads.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class KeystoreAuditLogCollection
{
    /// <summary>The collection's name.</summary>
    public const string Name = "Keystore audit log";
}
