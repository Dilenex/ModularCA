using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using ModularCA.Core.Services.Journal;
using ModularCA.Database;
using ModularCA.Journal;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Signing;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Journal;

/// <summary>
/// What the hub's review of the journal asked for: a start that records nothing leaves no
/// segment, a sealed list from a sequence on, what the instance does while it waits for a
/// restore marker, a checkpoint key put back to an older one, which journal statuses leave the
/// node ready, the free-space levels, and the refused CRL in the health answer with its list.
/// </summary>
public class JournalHubReviewTests
{
    private static Task<JournalAppended> AppendFact(JournalWriter writer, int i)
        => writer.AppendAsync(RecordType.Disabled, JournalFormat.FlagNodeAsserted, new DisabledPayload(DisabledKind.Space, "space-" + i, i).Encode());

    /// <summary>Every file of a directory by name, with the hash of its bytes.</summary>
    private static Dictionary<string, string> Fingerprint(string directory)
        => Directory.Exists(directory)
            ? Directory.GetFiles(directory, "*", SearchOption.AllDirectories)
                .ToDictionary(f => Path.GetRelativePath(directory, f), f => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(f))), StringComparer.Ordinal)
            : new Dictionary<string, string>(StringComparer.Ordinal);

    [Fact]
    public async Task Starts_that_record_nothing_leave_the_directory_as_one_start_left_it()
    {
        using var sandbox = new JournalSandbox();
        // The first start of all makes the journal: its first segment, with Genesis.
        await using (sandbox.Open()) { }
        var afterOne = Fingerprint(sandbox.Directory);
        Assert.Single(afterOne);
        var head = sandbox.Verify().Head!;

        // Starts that stop in order, with nothing signed.
        for (var i = 0; i < 6; i++)
        {
            await using var writer = sandbox.Open();
            // It can take a record, knows the chain's tail, and has begun nothing.
            Assert.True(writer.Status.Available);
            Assert.Null(writer.Status.Fault);
            Assert.Null(writer.Status.OpenSegment);
            Assert.Equal(head.Seq, writer.Status.Seq);
            Assert.Equal(head.Hash, writer.Status.Hash);
        }
        Assert.Equal(afterOne, Fingerprint(sandbox.Directory));

        // Starts that die without warning.
        for (var i = 0; i < 6; i++)
            await sandbox.Open().CrashAsync();
        Assert.Equal(afterOne, Fingerprint(sandbox.Directory));

        // The first record of a start begins its segment: SegmentStart, this start's Start, a Checkpoint, then the record.
        await using (var writer = sandbox.Open())
        {
            var appended = await AppendFact(writer, 1);
            Assert.Equal(head.Seq + 4, appended.Seq);
            Assert.Equal(JournalFormat.OpenName(head.Seq + 1), writer.Status.OpenSegment);
        }
        Assert.Equal(2, sandbox.Names().Length);
        var second = sandbox.Records().Where(r => r.Segment == sandbox.Names()[1]).Select(r => r.Record.Type).Take(4);
        Assert.Equal(new[] { RecordType.SegmentStart, RecordType.Start, RecordType.Checkpoint, RecordType.Disabled }, second);
        // One Start for the first start and one for the start that recorded: the twelve between left none.
        Assert.Equal(2, sandbox.Records().Count(r => r.Record.Type == RecordType.Start));
        var verification = sandbox.Verify();
        Assert.Null(verification.Fault);
        Assert.Equal(2, verification.Segments.Count);
    }

    [Fact]
    public async Task A_start_that_has_recorded_nothing_yet_still_knows_the_last_checkpoint_on_disk()
    {
        using var sandbox = new JournalSandbox();
        await using (sandbox.Open()) { }
        var head = sandbox.Verify().Head!;
        var onDisk = head.Checkpoint;
        Assert.NotNull(onDisk);

        // The next start reads the journal and begins nothing. Its last checkpoint is the one it found.
        await using var writer = sandbox.Open();
        Assert.Null(writer.Status.OpenSegment);
        Assert.Equal(onDisk!.Seq, writer.Status.LastCheckpointSeq);
        Assert.Equal(JournalFormat.FromMicros(onDisk.At), writer.Status.LastCheckpointAt);
        Assert.Equal(0, writer.Status.Uncheckpointed);

        // Once this start records something, the checkpoint is its own, and later than the one on disk.
        await AppendFact(writer, 1);
        await writer.DisposeAsync();
        var after = sandbox.Verify().Head!.Checkpoint!;
        Assert.True(after.Seq > onDisk.Seq);
    }

    [Fact]
    public async Task A_start_on_a_journal_whose_directory_takes_no_new_file_fails_at_the_open()
    {
        using var sandbox = new JournalSandbox();
        await using (sandbox.Open()) { }
        var before = Directory.GetFiles(sandbox.Directory).Select(Path.GetFileName).Order().ToList();

        // The directory refuses a new file, as one mounted or set read-only does.
        var files = new RecordingJournalFiles { FailProbe = _ => new UnauthorizedAccessException("Access to the path is denied.") };
        var refused = Assert.Throws<JournalUnavailableException>(() => sandbox.Open(files));
        Assert.Contains("could not be opened", refused.Message);
        Assert.Contains("denied", refused.Message);
        Assert.Equal(before, Directory.GetFiles(sandbox.Directory).Select(Path.GetFileName).Order().ToList());

        // Once it takes one again the journal opens, and the probe leaves nothing behind.
        files.FailProbe = null;
        await using (var writer = sandbox.Open(files))
        {
            Assert.True(writer.Status.Available);
            Assert.Null(writer.Status.OpenSegment);
            Assert.Equal(before, Directory.GetFiles(sandbox.Directory).Select(Path.GetFileName).Order().ToList());
        }
    }

    [Fact]
    public async Task A_probe_file_left_by_a_killed_start_does_not_stop_the_next()
    {
        using var sandbox = new JournalSandbox();
        await using (sandbox.Open()) { }
        File.WriteAllBytes(Path.Combine(sandbox.Directory, JournalFiles.ProbeName), new byte[] { 1, 2, 3 });

        await using var writer = sandbox.Open();
        Assert.True(writer.Status.Available);
        Assert.False(File.Exists(Path.Combine(sandbox.Directory, JournalFiles.ProbeName)));
        Assert.Null(sandbox.Verify().Fault);
    }

    [Fact]
    public async Task A_signer_killed_in_a_loop_from_its_first_start_on_makes_one_file()
    {
        using var sandbox = new JournalSandbox();
        // The very first start dies after its opening records: an open segment with no Seal.
        await sandbox.Open().CrashAsync();
        var one = Fingerprint(sandbox.Directory);
        Assert.Equal(new[] { "00000000000000000001.open.mcaj" }, sandbox.Names());

        for (var i = 0; i < 25; i++)
            await sandbox.Open().CrashAsync();

        // Not appended to, not renamed, and nothing beside it.
        Assert.Equal(one, Fingerprint(sandbox.Directory));

        // The start that at last records something applies the start-up rule: the file is renamed as it is.
        await using (var writer = sandbox.Open())
            await AppendFact(writer, 1);
        Assert.Equal(2, sandbox.Names().Length);
        Assert.Equal(one.Values.Single(), Fingerprint(sandbox.Directory)["00000000000000000001.mcaj"]);
        var start = sandbox.Records().Last(r => r.Record.Type == RecordType.Start);
        Assert.True(StartPayload.Decode(start.Record.Payload).PreviousUnsealed);
        Assert.Null(sandbox.Verify().Fault);
    }

    [Fact]
    public async Task The_head_lists_the_sealed_segments_from_a_sequence_on_and_reads_no_older_one()
    {
        using var sandbox = new JournalSandbox();
        for (var run = 0; run < 4; run++)
        {
            await using var writer = sandbox.Open();
            await AppendFact(writer, run);
        }
        var segments = sandbox.Verify().Segments;
        Assert.Equal(4, segments.Count);
        var all = JournalHead.Read(sandbox.Directory, includeSealed: true);

        string[] Sealed(JournalHead head)
        {
            Assert.Equal(JournalHead.ExitOk, head.ExitCode);
            using var json = JsonDocument.Parse(head.Json!);
            return json.RootElement.GetProperty("sealed").EnumerateArray().Select(s => s.GetProperty("segment").GetString()!).ToArray();
        }

        // From the third segment's first sequence: the third and the fourth, each as --sealed lists it.
        var fromThird = JournalHead.Read(sandbox.Directory, sealedFrom: segments[2].FirstSeq);
        Assert.Equal(new[] { segments[2].Name, segments[3].Name }, Sealed(fromThird));
        using (var some = JsonDocument.Parse(fromThird.Json!))
        using (var whole = JsonDocument.Parse(all.Json!))
        {
            Assert.Equal(whole.RootElement.GetProperty("sealed").EnumerateArray().Skip(2).Select(e => e.GetRawText()),
                some.RootElement.GetProperty("sealed").EnumerateArray().Select(e => e.GetRawText()));
            Assert.Equal(new[] { "segment", "wholeBytes", "lastSeq", "lastHash", "torn" },
                some.RootElement.GetProperty("sealed")[0].EnumerateObject().Select(p => p.Name));
            // The head itself is the same whichever way it is asked for.
            foreach (var name in new[] { "seq", "hash", "checkpoint", "checkpointKey", "open" })
                Assert.Equal(whole.RootElement.GetProperty(name).GetRawText(), some.RootElement.GetProperty(name).GetRawText());
        }
        // A sequence inside a segment lists from the next segment that begins at or after it.
        Assert.Equal(new[] { segments[3].Name }, Sealed(JournalHead.Read(sandbox.Directory, sealedFrom: segments[2].FirstSeq + 1)));
        // From the beginning it is the whole list; past the head it is empty, and still the head.
        Assert.Equal(segments.Select(s => s.Name), Sealed(JournalHead.Read(sandbox.Directory, sealedFrom: 0)));
        Assert.Empty(Sealed(JournalHead.Read(sandbox.Directory, sealedFrom: segments[3].LastSeq + 1)));
        // Without either flag there is no list at all.
        using (var plain = JsonDocument.Parse(JournalHead.Read(sandbox.Directory).Json!))
            Assert.False(plain.RootElement.TryGetProperty("sealed", out _));

        // Only those are read: a changed bit in the oldest segment is seen by --sealed and not from the third on.
        var oldest = Path.Combine(sandbox.Directory, segments[0].Name);
        var bytes = File.ReadAllBytes(oldest);
        bytes[bytes.Length / 2] ^= 0x10;
        File.WriteAllBytes(oldest, bytes);
        Assert.Equal(JournalHead.ExitBrokenChain, JournalHead.Read(sandbox.Directory, includeSealed: true).ExitCode);
        Assert.Equal(new[] { segments[2].Name, segments[3].Name }, Sealed(JournalHead.Read(sandbox.Directory, sealedFrom: segments[2].FirstSeq)));
    }

    [Fact]
    public async Task While_it_waits_for_a_restore_marker_the_writer_takes_records_and_says_until_when()
    {
        using var sandbox = new JournalSandbox();
        await using (var writer = sandbox.Open())
            await AppendFact(writer, 1);
        var before = Fingerprint(sandbox.Directory);
        // The keystores were put back to another system key, the old one is not held, and no restore said so.
        sandbox.SystemKey = new TestJournalKey();
        sandbox.CheckpointKey = new TestJournalKey();

        var opened = DateTimeOffset.UtcNow;
        await using (var writer = sandbox.Open(change: o => o.CheckpointInterval = TimeSpan.FromMilliseconds(100)))
        {
            // Known from the start, before anything is recorded and with nothing written.
            var until = writer.Status.AwaitingRestoreMarkerUntil;
            Assert.NotNull(until);
            Assert.InRange((until!.Value - opened).TotalMinutes, 9.9, 10.1);
            Assert.True(writer.Status.Available);
            Assert.Equal(before, Fingerprint(sandbox.Directory));

            // The signer serves: a record is taken and flushed while the wait goes on.
            var appended = await AppendFact(writer, 2);
            Assert.True(appended.Seq > 0);
            Assert.True(writer.Status.Available);
            // The wait is counted once, from the start, not again when the segment begins.
            Assert.Equal(until, writer.Status.AwaitingRestoreMarkerUntil);
            await Task.Delay(300);
            Assert.DoesNotContain(sandbox.Records().Where(r => r.Segment == sandbox.Names()[^1]), r => r.Record.Type == RecordType.Checkpoint);

            // The marker ends it.
            await writer.AppendAsync(RecordType.RestoreMarker, JournalFormat.FlagNodeAsserted,
                new RestoreMarkerPayload("modularca-backup-20261112-010000.enc", sandbox.InstanceId, 1_700_000_000_000_000, null).Encode());
            Assert.Null(writer.Status.AwaitingRestoreMarkerUntil);
        }
        Assert.Null(sandbox.Verify().Fault);
    }

    [Fact]
    public async Task A_checkpoint_key_put_back_to_an_older_one_is_recorded_as_a_change_the_system_key_vouches_for()
    {
        using var sandbox = new JournalSandbox();
        var older = sandbox.CheckpointKey;
        await using (var writer = sandbox.Open())
            await AppendFact(writer, 1);
        // The key was replaced since.
        var newer = sandbox.CheckpointKey = new TestJournalKey();
        await using (var writer = sandbox.Open())
            await AppendFact(writer, 2);
        Assert.Equal(newer.PublicKey, sandbox.Verify().Head!.Key!.Key);

        // The keystores volume is rolled back beside the journal: the signer holds the older key again, and not the newer.
        sandbox.CheckpointKey = older;
        await using (var writer = sandbox.Open())
        {
            // No waiting: the system key is the same, so it signs for the key at once.
            Assert.Null(writer.Status.AwaitingRestoreMarkerUntil);
            await AppendFact(writer, 3);
        }

        var changes = sandbox.Records().Where(r => r.Record.Type == RecordType.CheckpointKeyChanged).Select(r => CheckpointKeyChangedPayload.Decode(r.Record.Payload)).ToList();
        Assert.Equal(2, changes.Count);
        var back = changes[1];
        Assert.Equal(older.PublicKey, back.NewKey.Key);
        Assert.Null(back.OldKeySignature);
        Assert.Null(back.OldSystemKeySignature);
        Assert.Null(back.Explains);
        Assert.True(JournalSignatures.VerifyKeyBlock(back.NewKey, sandbox.InstanceId, sandbox.SystemKey.PublicKey));
        var verification = sandbox.Verify();
        Assert.Null(verification.Fault);
        Assert.Empty(verification.Unvouched);
        Assert.Equal(older.PublicKey, verification.Head!.Key!.Key);
        // The checkpoints after the change are the older key's again.
        var last = sandbox.Records().Last(r => r.Record.Type == RecordType.Checkpoint);
        Assert.Equal(JournalSignatures.KeyHash(older.PublicKey), CheckpointPayload.Decode(last.Record.Payload).KeyHash);
    }

    private static readonly DateTime Now = new(2026, 11, 13, 9, 0, 0, DateTimeKind.Utc);

    private static SignerJournalInfo Info(bool available = true, long? free = 50L << 30, long uncheckpointed = 0, DateTime? checkpointAt = null, string? fault = null)
        => new(available, fault, 100, new string('a', 64), checkpointAt ?? Now.AddSeconds(-2), uncheckpointed, 3L << 20, free);

    [Fact]
    public void The_free_space_levels_are_the_signers_settings_and_the_defaults_without_them()
    {
        // A signer that does not say: 1 GiB and 128 MiB.
        Assert.Equal((1L << 30, 128L << 20), SignerJournalState.Levels(Info()));
        Assert.Equal(SignerJournalState.LowSpace, SignerJournalState.Assess(Info(free: 900L << 20), Now).Status);
        Assert.Equal(SignerJournalState.CriticalSpace, SignerJournalState.Assess(Info(free: 100L << 20), Now).Status);

        // The signer's own levels are the ones applied.
        var raised = Info(free: 5L << 30) with { LowSpaceBytes = 10L << 30, CriticalSpaceBytes = 6L << 30 };
        Assert.Equal(SignerJournalState.CriticalSpace, SignerJournalState.Assess(raised, Now).Status);
        Assert.Equal(SignerJournalState.LowSpace, SignerJournalState.Assess(raised with { FreeBytes = 8L << 30 }, Now).Status);
        Assert.Equal(SignerJournalState.Ok, SignerJournalState.Assess(raised with { FreeBytes = 11L << 30 }, Now).Status);

        // Zero is "never": no warning however little is left.
        var off = Info(free: 1) with { LowSpaceBytes = 0, CriticalSpaceBytes = 0 };
        Assert.Equal(SignerJournalState.Ok, SignerJournalState.Assess(off, Now).Status);

        // The settings and their defaults.
        var settings = new ModularCA.Shared.Models.Config.SignerJournalConfig();
        Assert.Equal((1024, 128), (settings.LowSpaceMiB, settings.CriticalSpaceMiB));
        var paths = ModularCA.Shared.Models.Config.SignerPaths.Shared(Path.Combine(Path.GetTempPath(), "mca-levels-" + Guid.NewGuid().ToString("N")));
        var config = new ModularCA.Shared.Models.Config.SystemConfig();
        config.Signer.Journal.LowSpaceMiB = 4096;
        config.Signer.Journal.CriticalSpaceMiB = 512;
        var resolved = (ModularCA.Keystore.Signing.SignerJournalSettings)ApiAssembly.TypeNamed("ModularCA.API.Startup.SignerRole")
            .GetMethod("JournalSettings")!.Invoke(null, [paths, config])!;
        Assert.Equal((4096L << 20, 512L << 20), (resolved.LowSpaceBytes, resolved.CriticalSpaceBytes));
        // At critical_space the message says what happens: issuance goes on until a write fails.
        Assert.Contains("goes on issuing until a write to the journal fails", SignerJournalState.Assess(Info(free: 1L << 20), Now).Message!, StringComparison.Ordinal);
    }

    /// <summary>A signer that answers the two journal questions with what a test gives it and nothing else.</summary>
    public class JournalAnswers : DispatchProxy
    {
        /// <summary>What <c>JournalInfoAsync</c> answers.</summary>
        public SignerJournalInfo? Info { get; set; }

        /// <summary>True for a signer that does not answer: asking it about its journal fails.</summary>
        public bool Unreachable { get; set; }

        /// <summary>What <c>JournalMissingRevocationsAsync</c> answers.</summary>
        public SignerJournalMissingRevocations? Missing { get; set; }

        /// <inheritdoc />
        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args) => targetMethod!.Name switch
        {
            nameof(ISigningService.JournalInfoAsync) when Unreachable => Task.FromException<SignerJournalInfo?>(new InvalidOperationException("The signer is not reachable.")),
            nameof(ISigningService.JournalInfoAsync) => Task.FromResult(Info),
            nameof(ISigningService.JournalMissingRevocationsAsync) => Task.FromResult(Missing),
            _ => throw new NotSupportedException(targetMethod.Name),
        };

        /// <summary>Makes one, as the signer the node asks and as the object a test sets.</summary>
        public static (ISigningService Signer, JournalAnswers Answers) Create()
        {
            var signer = DispatchProxy.Create<ISigningService, JournalAnswers>();
            return (signer, (JournalAnswers)(object)signer);
        }
    }

    [Fact]
    public async Task A_signer_that_has_not_answered_is_not_known_and_a_signer_with_no_journal_is_none()
    {
        // The signer answers and keeps no journal: none.
        var (keepsNone, none) = await CheckAsync(null);
        Assert.Equal(("none", HealthStatus.Healthy), (none.GetProperty("status").GetString(), keepsNone));
        Assert.Equal(JsonValueKind.Null, none.GetProperty("message").ValueKind);

        // The signer does not answer: not_known, with a message that says to ask again, and the node stays ready.
        var (silent, notKnown) = await CheckAsync(null, unreachable: true);
        Assert.Equal(("not_known", HealthStatus.Healthy), (notKnown.GetProperty("status").GetString(), silent));
        Assert.Contains("has not answered", notKnown.GetProperty("message").GetString()!, StringComparison.Ordinal);
        Assert.False(SignerJournalState.FailsReadiness(SignerJournalState.NotKnown));
        Assert.Equal(CheckMembers, notKnown.EnumerateObject().Select(p => p.Name));

        // A merge this process knows of does not hide that the signer cannot be asked.
        var (_, withMerge) = await CheckAsync(null, merge: MergeIn(JournalMergeState.Running, 1, 2), unreachable: true);
        Assert.Equal("not_known", withMerge.GetProperty("status").GetString());
    }

    private static async Task<(HealthStatus Health, JsonElement Journal)> CheckAsync(SignerJournalInfo? info, ModularCADbContext? db = null, JournalMergeState? merge = null, bool unreachable = false)
    {
        var (signer, answers) = JournalAnswers.Create();
        answers.Info = info;
        answers.Unreachable = unreachable;
        var services = new ServiceCollection().AddSingleton(signer);
        if (merge != null)
            services.AddSingleton(merge);
        if (db != null)
            services.AddSingleton(db);
        var check = (IHealthCheck)Activator.CreateInstance(ApiAssembly.TypeNamed("ModularCA.API.HealthChecks.JournalHealthCheck"),
            services.BuildServiceProvider(), new SignerJournalState())!;
        var result = await check.CheckHealthAsync(new HealthCheckContext());
        var journal = JsonSerializer.SerializeToElement(result.Data["journal"], new JsonSerializerOptions(JsonSerializerDefaults.Web));
        return (result.Status, journal);
    }

    private static readonly string[] CheckMembers =
    [
        "status", "message", "available", "seq", "hash", "sizeBytes", "freeBytes", "lowSpaceBytes", "criticalSpaceBytes",
        "lastCheckpointAtUtc", "lastCheckpointAgeSeconds", "uncheckpointedRecords", "queuedFacts",
        "awaitingRestoreMarkerUntilUtc", "awaitingRestoreMarkerSecondsLeft", "setAsideJournals", "setAsideBytes", "refusedCrls",
        "verified", "verificationFault", "verifiedBytes", "verifyTotalBytes", "merge",
    ];

    /// <summary>A merge state with one CA in <paramref name="state"/>, set as the merge sets it.</summary>
    private static JournalMergeState MergeIn(string state, int merged, int remaining, string? message = null)
    {
        var merge = new JournalMergeState();
        typeof(JournalMergeState).GetMethod("Set", BindingFlags.Instance | BindingFlags.NonPublic)!
            .Invoke(merge, [new CaMergeStatus(Guid.NewGuid(), "Alpha Issuing", state, merged, remaining, merged + remaining, DateTime.UtcNow, message)]);
        return merge;
    }

    [Fact]
    public async Task Only_a_journal_that_cannot_be_written_makes_the_node_not_ready()
    {
        var now = DateTime.UtcNow;
        var fine = new SignerJournalInfo(true, null, 100, new string('a', 64), now.AddSeconds(-2), 0, 3L << 20, 50L << 30);
        var refusal = new SignerJournalRefusedCrl(Guid.NewGuid(), new string('c', 64), 3, now.AddMinutes(-1), 12);
        var cases = new (string Status, SignerJournalInfo? Info, HealthStatus Health, JournalMergeState? Merge)[]
        {
            (SignerJournalState.None, null, HealthStatus.Healthy, null),
            (SignerJournalState.Ok, fine, HealthStatus.Healthy, MergeIn(JournalMergeState.Done, 4, 0)),
            (SignerJournalState.NotVerified, fine with { Verified = false, VerificationFault = "The journal does not verify: 00000000000000000001.mcaj at sequence 9." }, HealthStatus.Healthy, null),
            (SignerJournalState.MergePending, fine, HealthStatus.Healthy, MergeIn(JournalMergeState.Pending, 0, 12)),
            (SignerJournalState.MergeRunning, fine, HealthStatus.Healthy, MergeIn(JournalMergeState.Running, 500, 1500)),
            (SignerJournalState.LowSpace, fine with { FreeBytes = 700L << 20 }, HealthStatus.Healthy, null),
            (SignerJournalState.CriticalSpace, fine with { FreeBytes = 20L << 20 }, HealthStatus.Healthy, null),
            (SignerJournalState.StaleCheckpoint, fine with { UncheckpointedRecords = 3, LastCheckpointAtUtc = now.AddMinutes(-5) }, HealthStatus.Healthy, null),
            (SignerJournalState.AwaitingRestoreMarker, fine with { AwaitingRestoreMarkerUntilUtc = now.AddMinutes(9), UncheckpointedRecords = 40, LastCheckpointAtUtc = now.AddMinutes(-5) }, HealthStatus.Healthy, null),
            (SignerJournalState.CrlRefused, fine with { RefusedCrls = [refusal] }, HealthStatus.Healthy, MergeIn(JournalMergeState.Pending, 0, 3)),
            (SignerJournalState.Unavailable, fine with { Available = false, Fault = "There is not enough space on the disk." }, HealthStatus.Degraded, MergeIn(JournalMergeState.Running, 1, 2)),
        };

        foreach (var (status, info, health, merge) in cases)
        {
            var (reported, journal) = await CheckAsync(info, merge: merge);

            Assert.Equal(status, journal.GetProperty("status").GetString());
            Assert.True(health == reported, $"{status} was reported as {reported}");
            Assert.Equal(status == SignerJournalState.Unavailable, SignerJournalState.FailsReadiness(status));
            // One shape whatever the status.
            Assert.Equal(CheckMembers, journal.EnumerateObject().Select(p => p.Name));
        }
    }

    [Fact]
    public async Task The_merge_is_shown_while_it_runs_and_while_it_waits_with_its_counts_for_each_ca()
    {
        var now = DateTime.UtcNow;
        var fine = new SignerJournalInfo(true, null, 100, new string('a', 64), now.AddSeconds(-2), 0, 3L << 20, 50L << 30, Verified: true);

        var (health, running) = await CheckAsync(fine, merge: MergeIn(JournalMergeState.Running, 500, 1500));
        Assert.Equal(HealthStatus.Healthy, health);
        Assert.Equal("merge_running", running.GetProperty("status").GetString());
        Assert.Contains("500 made, 1500 journal entries still to look at", running.GetProperty("message").GetString()!, StringComparison.Ordinal);
        var one = Assert.Single(running.GetProperty("merge").EnumerateArray());
        Assert.Equal(new[] { "caId", "caName", "state", "merged", "remaining", "journalEntries", "atUtc", "message" }, one.EnumerateObject().Select(p => p.Name));
        Assert.Equal(("Alpha Issuing", "running", 500, 1500, 2000),
            (one.GetProperty("caName").GetString(), one.GetProperty("state").GetString(), one.GetProperty("merged").GetInt32(), one.GetProperty("remaining").GetInt32(), one.GetProperty("journalEntries").GetInt32()));
        Assert.True(running.GetProperty("verified").GetBoolean());

        // How far the verification at the signer's start has got: null before it begins, then bytes of the total, equal at the end.
        var (_, notBegun) = await CheckAsync(fine with { Verified = null });
        Assert.Equal(JsonValueKind.Null, notBegun.GetProperty("verifiedBytes").ValueKind);
        Assert.Equal(JsonValueKind.Null, notBegun.GetProperty("verifyTotalBytes").ValueKind);
        var (_, partWay) = await CheckAsync(fine with { Verified = null, VerifiedBytes = 300L << 20, VerifyTotalBytes = 1L << 30 });
        Assert.Equal(JsonValueKind.Null, partWay.GetProperty("verified").ValueKind);
        Assert.Equal((300L << 20, 1L << 30), (partWay.GetProperty("verifiedBytes").GetInt64(), partWay.GetProperty("verifyTotalBytes").GetInt64()));
        var (_, read) = await CheckAsync(fine with { VerifiedBytes = 1L << 30, VerifyTotalBytes = 1L << 30 });
        Assert.Equal(read.GetProperty("verifyTotalBytes").GetInt64(), read.GetProperty("verifiedBytes").GetInt64());

        // In DR mode: pending, with how many wait.
        var (_, pending) = await CheckAsync(fine, merge: MergeIn(JournalMergeState.Pending, 0, 12));
        Assert.Equal("merge_pending", pending.GetProperty("status").GetString());
        Assert.Contains("12 revocation(s)", pending.GetProperty("message").GetString()!, StringComparison.Ordinal);
        Assert.Contains("DR mode", pending.GetProperty("message").GetString()!, StringComparison.Ordinal);

        // Done: no status of its own; the standing notice is the continuity check's.
        var (_, done) = await CheckAsync(fine, merge: MergeIn(JournalMergeState.Done, 4, 0, "4 revocation(s) were restored from the signer's journal."));
        Assert.Equal("ok", done.GetProperty("status").GetString());
        Assert.Equal(4, done.GetProperty("merge")[0].GetProperty("merged").GetInt32());

        // A journal that did not verify, with a refused CRL: the louder status, and the message says nothing was restored.
        var (_, unverified) = await CheckAsync(fine with { Verified = false, VerificationFault = "The journal does not verify: x." },
            merge: MergeIn(JournalMergeState.NotTrusted, 0, 0, "The signer does not answer from its journal for this CA."));
        Assert.Equal("not_verified", unverified.GetProperty("status").GetString());
        Assert.Contains("restored only from records that a checkpoint", unverified.GetProperty("message").GetString()!, StringComparison.Ordinal);
        Assert.False(unverified.GetProperty("verified").GetBoolean());
        Assert.Equal("The journal does not verify: x.", unverified.GetProperty("verificationFault").GetString());
        Assert.False(SignerJournalState.FailsReadiness(SignerJournalState.NotVerified));
        Assert.False(SignerJournalState.FailsReadiness(SignerJournalState.MergePending));
        Assert.False(SignerJournalState.FailsReadiness(SignerJournalState.MergeRunning));
    }

    [Fact]
    public async Task The_wait_for_a_restore_marker_is_a_status_of_its_own_with_the_time_left()
    {
        var now = DateTime.UtcNow;
        var until = now.AddMinutes(7).AddSeconds(20);
        var waiting = new SignerJournalInfo(true, null, 100, new string('a', 64), now.AddMinutes(-3), 12, 3L << 20, 50L << 30, AwaitingRestoreMarkerUntilUtc: until);

        var (health, journal) = await CheckAsync(waiting);

        Assert.Equal(HealthStatus.Healthy, health);
        Assert.Equal("awaiting_restore_marker", journal.GetProperty("status").GetString());
        Assert.True(journal.GetProperty("available").GetBoolean());
        Assert.InRange(journal.GetProperty("awaitingRestoreMarkerSecondsLeft").GetInt64(), 430, 441);
        Assert.Equal(until, journal.GetProperty("awaitingRestoreMarkerUntilUtc").GetDateTime().ToUniversalTime());
        var message = journal.GetProperty("message").GetString()!;
        Assert.Contains("8 minute(s) more", message, StringComparison.Ordinal);
        Assert.Contains("signs and records meanwhile", message, StringComparison.Ordinal);

        // A wait that is over is no status: the change is then written with the next record.
        var (_, over) = await CheckAsync(waiting with { AwaitingRestoreMarkerUntilUtc = now.AddSeconds(-1), UncheckpointedRecords = 0 });
        Assert.Equal("ok", over.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, over.GetProperty("awaitingRestoreMarkerSecondsLeft").ValueKind);
    }

    [Fact]
    public async Task A_refused_crl_is_in_the_health_answer_with_its_ca_its_count_and_when_the_published_crl_runs_out()
    {
        var now = DateTime.UtcNow;
        using var db = InMemoryDbContextFactory.Create($"journal-refused-{Guid.NewGuid():N}");
        var caId = Guid.NewGuid();
        var certificateId = Guid.NewGuid();
        var nextUpdate = new DateTime(2026, 11, 20, 8, 30, 0, DateTimeKind.Utc);
        db.Certificates.Add(new CertificateEntity
        {
            CertificateId = certificateId, SerialNumber = "0A", SubjectDN = "CN=Alpha Issuing", Issuer = "CN=Root", IsCA = true,
            NotBefore = now.AddYears(-1), NotAfter = now.AddYears(5), Pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----", RawCertificate = [0x30],
        });
        db.CertificateAuthorities.Add(new CertificateAuthorityEntity { Id = caId, Name = "Alpha Issuing", Label = "alpha", Type = "Issuing", IsEnabled = true, CertificateId = certificateId });
        var task = new CrlConfigurationEntity { Name = "alpha", CaCertificateId = certificateId, IssuerDN = "CN=Alpha Issuing", UpdateInterval = "0 */6 * * *", LastCrlNumber = 12 };
        db.CrlConfigurations.Add(task);
        CrlEntity Crl(long number, bool delta, DateTime next) => new()
        {
            Id = Guid.NewGuid(), IssuerName = "CN=Alpha Issuing", CrlNumber = number, IsDelta = delta, TaskId = task.TaskId,
            ThisUpdate = next.AddHours(-6), NextUpdate = next, GeneratedAt = next.AddHours(-6), PemData = "x", RawData = [0x30],
        };
        db.Crls.AddRange(Crl(11, false, nextUpdate.AddHours(-6)), Crl(12, false, nextUpdate), Crl(13, true, nextUpdate.AddHours(3)));
        await db.SaveChangesAsync();
        var info = new SignerJournalInfo(true, null, 100, new string('a', 64), now.AddSeconds(-2), 0, 3L << 20, 50L << 30,
            RefusedCrls: [new SignerJournalRefusedCrl(caId, new string('c', 64), 3, now.AddMinutes(-1), 12), new SignerJournalRefusedCrl(null, new string('d', 64), 1, now, 4)]);

        var (health, journal) = await CheckAsync(info, db);

        // Seen, and the node still serves.
        Assert.Equal(HealthStatus.Healthy, health);
        Assert.Equal("crl_refused", journal.GetProperty("status").GetString());
        var message = journal.GetProperty("message").GetString()!;
        Assert.Contains("refuses to sign a new CRL for 2 CA(s)", message, StringComparison.Ordinal);
        Assert.Contains("4 serial(s)", message, StringComparison.Ordinal);
        Assert.Contains("revoked-serials/missing-from-crl", message, StringComparison.Ordinal);
        Assert.Contains("runs out at 2026-11-20 08:30:00 UTC", message, StringComparison.Ordinal);

        var refused = journal.GetProperty("refusedCrls");
        Assert.Equal(2, refused.GetArrayLength());
        Assert.Equal(new[] { "caId", "caName", "caKey", "missingSerials", "refusedAtUtc", "journaledCrlNumber", "publishedCrlExpiresAtUtc", "serialsAt", "consolePath" },
            refused[0].EnumerateObject().Select(p => p.Name));
        // The page a person follows a link to, beside the API path.
        Assert.Equal($"/admin/authorities/manage/{caId:D}#missing-from-crl", refused[0].GetProperty("consolePath").GetString());
        Assert.Equal(JsonValueKind.Null, refused[1].GetProperty("consolePath").ValueKind);
        Assert.Equal(caId, refused[0].GetProperty("caId").GetGuid());
        Assert.Equal("Alpha Issuing", refused[0].GetProperty("caName").GetString());
        Assert.Equal(3, refused[0].GetProperty("missingSerials").GetInt32());
        Assert.Equal(12, refused[0].GetProperty("journaledCrlNumber").GetInt64());
        // The newest full CRL's nextUpdate, not the delta's.
        Assert.Equal(nextUpdate, refused[0].GetProperty("publishedCrlExpiresAtUtc").GetDateTime().ToUniversalTime());
        Assert.Equal($"/api/v1/admin/authorities/{caId:D}/revoked-serials/missing-from-crl", refused[0].GetProperty("serialsAt").GetString());
        // A key with no registered CA is still counted; there is nothing to look up for it.
        Assert.Equal(JsonValueKind.Null, refused[1].GetProperty("caId").ValueKind);
        Assert.Equal(JsonValueKind.Null, refused[1].GetProperty("publishedCrlExpiresAtUtc").ValueKind);
        Assert.Equal(JsonValueKind.Null, refused[1].GetProperty("serialsAt").ValueKind);

        // A journal that cannot be written is still the louder status.
        var (down, both) = await CheckAsync(info with { Available = false, Fault = "full" }, db);
        Assert.Equal(HealthStatus.Degraded, down);
        Assert.Equal("unavailable", both.GetProperty("status").GetString());
        Assert.Equal(2, both.GetProperty("refusedCrls").GetArrayLength());
    }

    [Fact]
    public async Task The_missing_serials_of_a_ca_are_read_whole_in_the_form_revocation_by_serial_takes()
    {
        var caId = Guid.NewGuid();
        var refusedAt = new DateTime(2026, 11, 13, 8, 0, 0, DateTimeKind.Utc);
        var revokedAt = new DateTime(2026, 11, 12, 17, 45, 0, DateTimeKind.Utc);
        var (signer, answers) = JournalAnswers.Create();
        var type = ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Admin.AdminRevokedSerialController");
        var method = type.GetMethod("MissingFromCrl")!;
        var controller = (ControllerBase)Activator.CreateInstance(type, null, null, null, null, null, signer)!;
        controller.ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() };
        async Task<JsonElement> ReadAsync()
        {
            var result = await (Task<IActionResult>)method.Invoke(controller, [caId])!;
            return JsonSerializer.SerializeToElement(Assert.IsType<OkObjectResult>(result).Value, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        }

        // No refusal stands.
        var none = await ReadAsync();
        Assert.False(none.GetProperty("refused").GetBoolean());
        Assert.Equal(0, none.GetProperty("count").GetInt32());
        Assert.Equal(0, none.GetProperty("serials").GetArrayLength());

        // Thirty of them: every one is returned, not the first five.
        answers.Missing = new SignerJournalMissingRevocations(caId, refusedAt, 12,
            Enumerable.Range(1, 30).Select(i => new SignerJournalMissingSerial((0xA000 + i).ToString("X"), i == 1 ? 1 : i == 2 ? 99 : 4, revokedAt)).ToList());
        var listed = await ReadAsync();

        Assert.Equal(new[] { "caId", "refused", "refusedAtUtc", "journaledCrlNumber", "count", "consolePath", "serials" }, listed.EnumerateObject().Select(p => p.Name));
        Assert.Equal($"/admin/authorities/manage/{caId:D}#missing-from-crl", listed.GetProperty("consolePath").GetString());
        Assert.True(listed.GetProperty("refused").GetBoolean());
        Assert.Equal(caId, listed.GetProperty("caId").GetGuid());
        Assert.Equal(12, listed.GetProperty("journaledCrlNumber").GetInt64());
        Assert.Equal(30, listed.GetProperty("count").GetInt32());
        var serials = listed.GetProperty("serials");
        Assert.Equal(30, serials.GetArrayLength());
        Assert.Equal(new[] { "serialNumber", "reason", "reasonCode", "revocationDate", "certificateHeld" }, serials[0].EnumerateObject().Select(p => p.Name));
        Assert.Equal("A001", serials[0].GetProperty("serialNumber").GetString());
        // The reason by the name the revocation request takes; a code it has no name for is Unspecified, with the code kept.
        Assert.Equal("KeyCompromise", serials[0].GetProperty("reason").GetString());
        Assert.Equal("Unspecified", serials[1].GetProperty("reason").GetString());
        Assert.Equal(99, serials[1].GetProperty("reasonCode").GetInt32());
        Assert.Equal("Superseded", serials[2].GetProperty("reason").GetString());
        Assert.Equal(revokedAt, serials[0].GetProperty("revocationDate").GetDateTime().ToUniversalTime());

        // Each entry is one the revocation of a serial alone accepts as it stands.
        foreach (var serial in serials.EnumerateArray())
        {
            var request = new ModularCA.Shared.Models.Revocation.RecordRevokedSerialRequest
            {
                SerialNumber = serial.GetProperty("serialNumber").GetString()!,
                Reason = Enum.Parse<ModularCA.Shared.Enums.RevocationReason>(serial.GetProperty("reason").GetString()!),
                Note = "Revoked again after the database was taken back.",
            };
            Assert.Equal(request.SerialNumber, ModularCA.Core.Services.RevokedSerialService.NormalizeSerial(request.SerialNumber));
        }

        // It is a read under the capability revocation needs, on the CA in the route.
        Assert.Contains(method.GetCustomAttributes(true), a => a is HttpGetAttribute { Template: "revoked-serials/missing-from-crl" });
        Assert.Contains(method.GetCustomAttributes(true), a => a.GetType().Name == "RequireCaCapabilityAttribute");
    }
}
