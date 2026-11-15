using Xunit;
using Xunit.Abstractions;
using System.Diagnostics;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Journal;
using ModularCA.Keystore.Signing;
using ModularCA.Shared.Signing;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Signer;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;

namespace ModularCA.Tests.Journal;

/// <summary>
/// The two commands of the real program that read a journal from its files:
/// <c>--role signer --journal-head</c> and <c>--role signer --journal-verify</c>. The built
/// program is started as an operator or a hub's runner starts it, with a directory it is given
/// and nothing else: no configuration, no database, no keystore.
/// </summary>
public class JournalCommandTests(ITestOutputHelper output)
{
    private static Task<JournalAppended> AppendFact(JournalWriter writer, int i)
        => writer.AppendAsync(RecordType.Disabled, JournalFormat.FlagNodeAsserted, new DisabledPayload(DisabledKind.Space, "space-" + i, i).Encode());

    private static string Program()
    {
        var testDir = new DirectoryInfo(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        var repo = testDir;
        while (repo != null && !Directory.Exists(Path.Combine(repo.FullName, "ModularCA.API")))
            repo = repo.Parent;
        var build = Path.Combine(repo!.FullName, "ModularCA.API", "bin", testDir.Parent!.Name, testDir.Name);
        Assert.True(File.Exists(Path.Combine(build, "ModularCA.API.dll")), $"Build ModularCA.API before this test: {build} holds no program.");
        return build;
    }

    /// <summary>The journal directory the program is told of through its environment, as a container is; none unless a test sets it.</summary>
    private string? _journalDirectoryVariable;

    private async Task<(int Exit, string Out, string Error)> RunAsync(params string[] arguments)
    {
        var build = Program();
        var executable = Path.Combine(build, OperatingSystem.IsWindows() ? "ModularCA.API.exe" : "ModularCA.API");
        var start = File.Exists(executable)
            ? new ProcessStartInfo(executable)
            : new ProcessStartInfo("dotnet") { ArgumentList = { Path.Combine(build, "ModularCA.API.dll") } };
        foreach (var argument in arguments)
            start.ArgumentList.Add(argument);
        start.RedirectStandardOutput = true;
        start.RedirectStandardError = true;
        start.UseShellExecute = false;
        start.WorkingDirectory = Path.GetTempPath();
        // Nothing of the test host's environment names a journal or a database for it.
        start.Environment.Remove(EnvVarConfigOverlay.SignerJournalDirectoryVariable);
        if (_journalDirectoryVariable != null)
            start.Environment[EnvVarConfigOverlay.SignerJournalDirectoryVariable] = _journalDirectoryVariable;
        using var process = Process.Start(start)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var limit = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await process.WaitForExitAsync(limit.Token);
        output.WriteLine($"{string.Join(' ', arguments)} -> {process.ExitCode}\n{await stdout}{await stderr}");
        return (process.ExitCode, (await stdout).Trim(), (await stderr).Trim());
    }

    private static Dictionary<string, long> Snapshot(string directory)
        => Directory.Exists(directory) ? Directory.GetFiles(directory).ToDictionary(f => Path.GetFileName(f), f => new FileInfo(f).Length) : new();

    [Fact]
    public async Task The_head_command_prints_one_line_beside_a_writer_and_creates_nothing()
    {
        using var sandbox = new JournalSandbox();
        await using (var first = sandbox.Open())
            await AppendFact(first, 1);
        await using var writer = sandbox.Open();
        await AppendFact(writer, 2);
        // Let the checkpoint that follows the record be written, so the head stands still while it is read twice.
        var deadline = DateTime.UtcNow.AddSeconds(20);
        while (writer.Status.Uncheckpointed > 0 && DateTime.UtcNow < deadline)
            await Task.Delay(50);
        var before = Snapshot(sandbox.Directory);

        var head = await RunAsync("--role", "signer", "--journal-head", "--journal-directory", sandbox.Directory);
        var withSealed = await RunAsync("--role", "signer", "--journal-head", "--journal-directory", sandbox.Directory, "--sealed");

        Assert.Equal(0, head.Exit);
        Assert.Equal(string.Empty, head.Error);
        Assert.DoesNotContain('\n', head.Out);
        Assert.Equal(JournalHead.Read(sandbox.Directory).Json, head.Out);
        using var json = JsonDocument.Parse(head.Out);
        Assert.Equal(sandbox.InstanceId, json.RootElement.GetProperty("instanceId").GetString());
        Assert.Equal(sandbox.Names()[^1], json.RootElement.GetProperty("open").GetProperty("segment").GetString());
        Assert.False(json.RootElement.TryGetProperty("sealed", out _));

        Assert.Equal(0, withSealed.Exit);
        Assert.Equal(JournalHead.Read(sandbox.Directory, includeSealed: true).Json, withSealed.Out);
        Assert.Single(JsonDocument.Parse(withSealed.Out).RootElement.GetProperty("sealed").EnumerateArray());
        // It read; it created, renamed and wrote nothing.
        Assert.Equal(before, Snapshot(sandbox.Directory));
    }

    [Fact]
    public async Task The_head_command_answers_3_for_no_journal_and_4_for_a_broken_chain()
    {
        using var sandbox = new JournalSandbox();

        var missing = await RunAsync("--role", "signer", "--journal-head", "--journal-directory", sandbox.Directory);
        Assert.Equal(3, missing.Exit);
        Assert.Equal(string.Empty, missing.Out);
        Assert.Contains("holds no journal", missing.Error, StringComparison.Ordinal);
        Assert.False(Directory.Exists(sandbox.Directory));

        await using (var writer = sandbox.Open())
            for (var i = 0; i < 3; i++)
                await AppendFact(writer, i);
        var name = sandbox.Names()[0];
        var records = sandbox.Records().Select(r => r.Record).ToList();
        File.WriteAllBytes(Path.Combine(sandbox.Directory, name),
            records.Where((_, i) => i != 4).SelectMany(r => JournalRecord.Encode(r.Type, r.Flags, r.Seq, r.At, r.Term, r.Incarnation, r.Prev, r.Payload).Bytes).ToArray());

        var broken = await RunAsync("--role", "signer", "--journal-head", "--journal-directory", sandbox.Directory);
        Assert.Equal(4, broken.Exit);
        Assert.Equal(string.Empty, broken.Out);
        Assert.Contains(name, broken.Error, StringComparison.Ordinal);
        Assert.Contains($"sequence {records[4].Seq}", broken.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_verify_command_checks_the_whole_journal_and_names_the_first_fault()
    {
        using var sandbox = new JournalSandbox();
        for (var run = 0; run < 2; run++)
        {
            await using var writer = sandbox.Open();
            for (var i = 0; i < 3; i++)
                await AppendFact(writer, i);
        }

        var whole = await RunAsync("--role", "signer", "--journal-verify", "--journal-directory", sandbox.Directory,
            "--system-key", Convert.ToHexStringLower(JournalSignatures.KeyHash(sandbox.SystemKey.PublicKey)));
        Assert.Equal(0, whole.Exit);
        var report = JsonDocument.Parse(whole.Out).RootElement;
        Assert.True(report.GetProperty("ok").GetBoolean());
        Assert.Equal(2, report.GetProperty("segments").GetInt32());
        Assert.Equal(sandbox.Records().Count, report.GetProperty("records").GetInt32());
        Assert.Equal(sandbox.Records().Count(r => r.Record.Type == RecordType.Checkpoint), report.GetProperty("checkpoints").GetInt32());
        Assert.Equal(0, report.GetProperty("unvouched").GetArrayLength());

        // Another system key than the one expected is a fault, though the journal is whole.
        var other = await RunAsync("--role", "signer", "--journal-verify", "--journal-directory", sandbox.Directory, "--system-key", new string('0', 64));
        Assert.Equal(4, other.Exit);

        // A changed bit in the older segment.
        var name = sandbox.Names()[0];
        var bytes = File.ReadAllBytes(Path.Combine(sandbox.Directory, name));
        bytes[bytes.Length / 2] ^= 0x20;
        File.WriteAllBytes(Path.Combine(sandbox.Directory, name), bytes);
        var broken = await RunAsync("--role", "signer", "--journal-verify", "--journal-directory", sandbox.Directory);
        Assert.Equal(4, broken.Exit);
        var fault = JsonDocument.Parse(broken.Out).RootElement;
        Assert.False(fault.GetProperty("ok").GetBoolean());
        Assert.Equal(name, fault.GetProperty("fault").GetProperty("segment").GetString());
        Assert.True(fault.GetProperty("fault").GetProperty("seq").GetUInt64() > 0);
        Assert.Contains(name, broken.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_commands_are_the_signer_roles_and_say_so_when_asked_otherwise()
    {
        using var sandbox = new JournalSandbox();

        var noRole = await RunAsync("--journal-head", "--journal-directory", sandbox.Directory);
        var both = await RunAsync("--role", "signer", "--journal-head", "--journal-verify", "--journal-directory", sandbox.Directory);
        var noValue = await RunAsync("--role", "signer", "--journal-head", "--journal-directory");

        Assert.All(new[] { noRole, both, noValue }, r => { Assert.Equal(1, r.Exit); Assert.Equal(string.Empty, r.Out); Assert.NotEqual(string.Empty, r.Error); });
        Assert.Contains("--role signer", noRole.Error, StringComparison.Ordinal);
    }

    /// <summary>Every file under a directory by its relative name, with its length, the hash of its bytes and when it was last written.</summary>
    private static Dictionary<string, string> Fingerprint(string directory)
        => Directory.Exists(directory)
            ? Directory.GetFileSystemEntries(directory, "*", SearchOption.AllDirectories).ToDictionary(
                f => Path.GetRelativePath(directory, f),
                f => Directory.Exists(f) ? "directory" : $"{new FileInfo(f).Length} {Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(f)))} {File.GetLastWriteTimeUtc(f):O}",
                StringComparer.Ordinal)
            : new Dictionary<string, string>(StringComparer.Ordinal);

    /// <summary>
    /// The one-off commands a hub's runner starts in a container of the signer's image beside
    /// the signer service, or in place of it. None of them is the signer service, so none opens
    /// the journal for writing: whatever each answers here, with no settings to read, it leaves
    /// the journal directory it is told of exactly as it found it, and makes none where there
    /// is none.
    /// </summary>
    [Fact]
    public async Task One_off_commands_of_the_signer_role_begin_no_segment_and_write_nothing_to_the_journal_directory()
    {
        using var sandbox = new JournalSandbox();
        // A journal a signer left without warning: an open segment, which a start of the signer service would rename.
        var writer = sandbox.Open();
        await AppendFact(writer, 1);
        await writer.CrashAsync();
        var volume = sandbox.Root;
        var absent = Path.Combine(Path.GetTempPath(), "mca-journal-absent-" + Guid.NewGuid().ToString("N"), "journal");
        var noSettings = Path.Combine(Path.GetTempPath(), "mca-no-settings-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(noSettings);
        var before = Fingerprint(volume);
        Assert.Single(before, f => f.Key.EndsWith(JournalFormat.OpenSuffix, StringComparison.Ordinal));

        string[][] commands =
        [
            ["--role", "signer", "--journal-head"],
            ["--role", "signer", "--journal-head", "--sealed"],
            ["--role", "signer", "--journal-verify"],
            ["--role", "signer", "--upgrade-check", "--config-dir", noSettings],
            ["--role", "signer", "--upgrade-check", "--read-only", "--config-dir", noSettings],
            ["--role", "signer", "--check-ready"],
            ["--role", "signer", "--backup-manifest", Path.Combine(noSettings, "modularca-backup-none.enc")],
        ];
        try
        {
            foreach (var command in commands)
            {
                // The home, as the signer's settings name it: the commands read its current/.
                _journalDirectoryVariable = sandbox.Home;
                var there = await RunAsync(command);
                Assert.True(before.SequenceEqual(Fingerprint(volume)), $"{string.Join(' ', command)} changed the journal's volume");

                _journalDirectoryVariable = absent;
                await RunAsync(command);
                Assert.False(Directory.Exists(Path.GetDirectoryName(absent)), $"{string.Join(' ', command)} made a journal directory");

                // The two that read the journal did read it, from the directory the environment names.
                if (command.Contains("--journal-head") || command.Contains("--journal-verify"))
                    Assert.Equal(0, there.Exit);
            }
        }
        finally
        {
            _journalDirectoryVariable = null;
            Directory.Delete(noSettings, recursive: true);
        }
    }

    /// <summary>
    /// The same, from the program's own text, for the commands that stop above for want of
    /// settings before they would reach a signer: the journal is opened for writing in one
    /// place, a signer is given a journal in two (the signer service, and the node that signs
    /// in its own process), and every one-off command has exited before the second of them.
    /// The backup and the restore make their signer without one.
    /// </summary>
    [Fact]
    public void Only_the_signer_service_and_a_node_that_signs_in_process_are_given_a_journal()
    {
        var repo = new DirectoryInfo(AppContext.BaseDirectory);
        while (repo != null && !Directory.Exists(Path.Combine(repo.FullName, "ModularCA.API")))
            repo = repo.Parent;
        string[] projects = ["ModularCA.API", "ModularCA.Bootstrap", "ModularCA.Keystore", "ModularCA.Core", "ModularCA.Signer", "ModularCA.Auth"];
        var sources = projects
            .SelectMany(p => Directory.GetFiles(Path.Combine(repo!.FullName, p), "*.cs", SearchOption.AllDirectories))
            .Where(f => !f.Contains(Path.DirectorySeparatorChar + "obj" + Path.DirectorySeparatorChar, StringComparison.Ordinal)
                && !f.Contains(Path.DirectorySeparatorChar + "bin" + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            .ToDictionary(f => Path.GetRelativePath(repo!.FullName, f).Replace('\\', '/'), File.ReadAllText, StringComparer.Ordinal);

        // The writer is opened by the signer's journal alone, and that is made in one place.
        Assert.Equal(new[] { "ModularCA.Keystore/Signing/SignerJournal.cs" }, sources.Where(s => s.Value.Contains("JournalWriter.Open(", StringComparison.Ordinal)).Select(s => s.Key));
        Assert.Equal(new[] { "ModularCA.Keystore/Signing/SignerBootstrap.cs" }, sources.Where(s => s.Value.Contains("new SignerJournal(", StringComparison.Ordinal)).Select(s => s.Key));
        // A signer is made with a journal where its settings are resolved: two places.
        var given = sources.Where(s => System.Text.RegularExpressions.Regex.IsMatch(s.Value, @"(?<!Signer)JournalSettings\(")).Select(s => s.Key).OrderBy(k => k, StringComparer.Ordinal).ToList();
        Assert.Equal(new[] { "ModularCA.API/StartModularCA.cs", "ModularCA.API/Startup/SignerRole.cs" }, given);
        Assert.DoesNotContain("journal", sources["ModularCA.Keystore/Signing/MaintenanceSigner.cs"], StringComparison.OrdinalIgnoreCase);

        // In the program's start, each one-off command has exited before a signer with a journal is made.
        var start = sources["ModularCA.API/StartModularCA.cs"];
        var withJournal = start.IndexOf("SignerRole.JournalSettings(", StringComparison.Ordinal);
        var service = start.IndexOf("SignerRole.RunAsync(", StringComparison.Ordinal);
        Assert.True(withJournal > 0 && service > 0);
        foreach (var command in new[]
                 {
                     "SignerReadinessCheck.RunAsync(", "NodeReadinessCheck.RunAsync(", "BackupManifestCommand.Run(", "JournalCommands.Run(",
                     "BackupRestore.Backup(", "RestoreCommand.RunAsync(", "UpgradeCheckCommand.RunAsync(",
                 })
        {
            var at = start.IndexOf(command, StringComparison.Ordinal);
            Assert.True(at > 0, $"{command} is not in the program's start");
            Assert.True(at < service && at < withJournal, $"{command} runs after a signer with a journal is made");
            // Its result is the process's exit status: the exit is on the same statement or the next.
            var exitBefore = start.LastIndexOf("Environment.Exit(", at, StringComparison.Ordinal);
            var exitAfter = start.IndexOf("Environment.Exit(", at, StringComparison.Ordinal);
            Assert.True((exitBefore >= 0 && at - exitBefore < 120) || (exitAfter >= 0 && exitAfter - at < 400), $"{command} does not end the process");
        }
    }

    [Fact]
    public async Task The_commands_take_a_home_or_a_directory_of_segments()
    {
        using var sandbox = new JournalSandbox();
        await using (var writer = sandbox.Open())
            await AppendFact(writer, 1);
        // A journal of another instance, set aside in the home, and a bare copy of the segments elsewhere.
        var aside = Path.Combine(sandbox.Home, JournalLayout.SetAsideInstanceName(new string('b', 64), DateTime.UtcNow));
        Directory.Move(sandbox.Directory, aside);
        sandbox.InstanceId = new string('c', 64);
        await using (var writer = sandbox.Open())
            await AppendFact(writer, 2);
        var copy = Path.Combine(sandbox.Root, "copy");
        Directory.CreateDirectory(copy);
        foreach (var file in Directory.GetFiles(sandbox.Directory))
            File.Copy(file, Path.Combine(copy, Path.GetFileName(file)));

        string? Instance((int Exit, string Out, string Error) run)
            => run.Exit == 0 ? JsonDocument.Parse(run.Out).RootElement.GetProperty("instanceId").GetString() : null;

        // The home is read through its current/; current/ itself, a set-aside directory and a bare copy are read as they are.
        Assert.Equal(sandbox.InstanceId, Instance(await RunAsync("--role", "signer", "--journal-head", "--journal-directory", sandbox.Home)));
        Assert.Equal(sandbox.InstanceId, Instance(await RunAsync("--role", "signer", "--journal-head", "--journal-directory", sandbox.Directory)));
        Assert.Equal(new string('a', 64), Instance(await RunAsync("--role", "signer", "--journal-head", "--journal-directory", aside)));
        Assert.Equal(sandbox.InstanceId, Instance(await RunAsync("--role", "signer", "--journal-head", "--journal-directory", copy)));
        Assert.Equal(0, (await RunAsync("--role", "signer", "--journal-verify", "--journal-directory", sandbox.Home)).Exit);
        Assert.Equal(0, (await RunAsync("--role", "signer", "--journal-verify", "--journal-directory", aside)).Exit);

        // A home with an empty current/, and one with none: no journal, exit 3, and nothing is made.
        var emptyCurrent = Path.Combine(sandbox.Root, "home-empty");
        Directory.CreateDirectory(Path.Combine(emptyCurrent, "current"));
        var noCurrent = Path.Combine(sandbox.Root, "home-none");
        Directory.CreateDirectory(Path.Combine(noCurrent, "set-aside-reset-20261113-000000-000"));
        Assert.Equal(3, (await RunAsync("--role", "signer", "--journal-head", "--journal-directory", emptyCurrent)).Exit);
        Assert.Equal(3, (await RunAsync("--role", "signer", "--journal-head", "--journal-directory", noCurrent)).Exit);
        Assert.Equal(3, (await RunAsync("--role", "signer", "--journal-verify", "--journal-directory", noCurrent)).Exit);
        Assert.False(Directory.Exists(Path.Combine(noCurrent, "current")));
    }

    [Fact]
    public async Task The_head_command_lists_sealed_segments_from_a_sequence_on()
    {
        using var sandbox = new JournalSandbox();
        for (var run = 0; run < 3; run++)
        {
            await using var writer = sandbox.Open();
            await AppendFact(writer, run);
        }
        var segments = sandbox.Verify().Segments;
        var from = segments[1].FirstSeq;

        var listed = await RunAsync("--role", "signer", "--journal-head", "--journal-directory", sandbox.Directory, "--sealed-from", from.ToString(System.Globalization.CultureInfo.InvariantCulture));
        var notANumber = await RunAsync("--role", "signer", "--journal-head", "--journal-directory", sandbox.Directory, "--sealed-from", "newest");
        var noValue = await RunAsync("--role", "signer", "--journal-head", "--journal-directory", sandbox.Directory, "--sealed-from");

        Assert.Equal(0, listed.Exit);
        Assert.Equal(JournalHead.Read(sandbox.Directory, sealedFrom: from).Json, listed.Out);
        Assert.Equal(new[] { segments[1].Name, segments[2].Name },
            JsonDocument.Parse(listed.Out).RootElement.GetProperty("sealed").EnumerateArray().Select(s => s.GetProperty("segment").GetString()));
        Assert.All(new[] { notANumber, noValue }, r => { Assert.Equal(1, r.Exit); Assert.Equal(string.Empty, r.Out); Assert.Contains("--sealed-from", r.Error, StringComparison.Ordinal); });
    }

    [Fact]
    public async Task The_verify_command_works_on_a_bare_copy_that_cannot_be_written_and_changes_nothing()
    {
        using var sandbox = new JournalSandbox();
        for (var run = 0; run < 2; run++)
        {
            await using var writer = sandbox.Open();
            await AppendFact(writer, run);
        }
        // A third start that stopped without warning: the copy holds an open segment, as a copy taken beside a running signer does.
        var last = sandbox.Open();
        await AppendFact(last, 9);
        await last.CrashAsync();

        // A bare copy: the segment files and nothing else, no settings, no keystore, no database; and read-only.
        var copy = Path.Combine(sandbox.Root, "copy");
        Directory.CreateDirectory(copy);
        foreach (var file in Directory.GetFiles(sandbox.Directory))
        {
            var target = Path.Combine(copy, Path.GetFileName(file));
            File.Copy(file, target);
            File.SetAttributes(target, File.GetAttributes(target) | FileAttributes.ReadOnly);
        }
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(copy, UnixFileMode.UserRead | UnixFileMode.UserExecute);
        var before = Fingerprint(copy);
        try
        {
            var verified = await RunAsync("--role", "signer", "--journal-verify", "--journal-directory", copy);
            var head = await RunAsync("--role", "signer", "--journal-head", "--journal-directory", copy, "--sealed");

            Assert.Equal(0, verified.Exit);
            Assert.Equal(string.Empty, verified.Error);
            Assert.DoesNotContain('\n', verified.Out);
            var report = JsonDocument.Parse(verified.Out).RootElement;
            Assert.True(report.GetProperty("ok").GetBoolean());
            Assert.Equal(3, report.GetProperty("segments").GetInt32());
            Assert.Equal(sandbox.Records().Count, report.GetProperty("records").GetInt32());
            Assert.Equal(0, head.Exit);
            // Nothing created, renamed, locked away or touched: the open segment still has its open name.
            Assert.True(before.SequenceEqual(Fingerprint(copy)), "the commands changed the copy");
            Assert.Single(Directory.GetFiles(copy), f => f.EndsWith(JournalFormat.OpenSuffix, StringComparison.Ordinal));
            // In process, the same.
            Assert.Null(JournalVerifier.Verify(copy).Fault);
            Assert.True(before.SequenceEqual(Fingerprint(copy)));

            // Its exit statuses: 3 for a directory with no journal, 4 for a chain that does not hold, 1 for a command line it cannot read.
            var empty = Path.Combine(sandbox.Root, "empty");
            Directory.CreateDirectory(empty);
            Assert.Equal(3, (await RunAsync("--role", "signer", "--journal-verify", "--journal-directory", empty)).Exit);
            Assert.Equal(3, (await RunAsync("--role", "signer", "--journal-verify", "--journal-directory", Path.Combine(sandbox.Root, "none"))).Exit);
            Assert.False(Directory.Exists(Path.Combine(sandbox.Root, "none")));
            Assert.Equal(4, (await RunAsync("--role", "signer", "--journal-verify", "--journal-directory", copy, "--system-key", new string('0', 64))).Exit);
            Assert.Equal(1, (await RunAsync("--role", "signer", "--journal-verify", "--journal-directory", copy, "--system-key", "xyz")).Exit);
        }
        finally
        {
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(copy, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    /// <summary>
    /// A measurement, not a check: certificates a second through the in-process signer with and
    /// without the journal, one caller and several. It runs only when
    /// <c>MODULARCA_MEASURE_JOURNAL</c> names a directory, where it leaves the journal it wrote.
    /// </summary>
    [Fact]
    public async Task Measure_issuance_with_and_without_the_journal()
    {
        var keep = Environment.GetEnvironmentVariable("MODULARCA_MEASURE_JOURNAL");
        if (string.IsNullOrWhiteSpace(keep))
            return;

        static X509Certificate Issue(ISigningService signer, SignerTestKey ca, long serial)
        {
            var generator = new X509V3CertificateGenerator();
            generator.SetSerialNumber(BigInteger.ValueOf(serial));
            generator.SetIssuerDN(ca.Certificate.SubjectDN);
            generator.SetSubjectDN(new Org.BouncyCastle.Asn1.X509.X509Name($"CN=measured-{serial}"));
            generator.SetNotBefore(DateTime.UtcNow.AddMinutes(-5));
            generator.SetNotAfter(DateTime.UtcNow.AddDays(30));
            generator.SetPublicKey(SubjectKey.Public);
            return generator.Generate(new SigningServiceSignatureFactory(signer, ca.Ref, SignatureAlgorithm.ForPublicKey(ca.PublicKey),
                SigningContext.ForCa("measure", SigningPurpose.Certificate, ca.CaId!.Value, ca.SpaceId)));
        }

        async Task<double> RateAsync(ISigningService signer, SignerTestKey ca, int callers, int perCaller, long firstSerial)
        {
            var clock = Stopwatch.StartNew();
            await Task.WhenAll(Enumerable.Range(0, callers).Select(c => Task.Run(() =>
            {
                for (var i = 0; i < perCaller; i++)
                    Issue(signer, ca, firstSerial + c * 1_000_000L + i);
            })));
            return callers * perCaller / clock.Elapsed.TotalSeconds;
        }

        var world = SignerTestWorld.Create();
        var ca = world["ca-ec"];
        var sandbox = new JournalSandbox();
        var journal = new SignerJournal(() => sandbox.Options(), new SignerJournalSettings(sandbox.Home, true, "measure", new byte[32]), NullLogger.Instance);
        var with = TestSigner.Over(world.Keystore, world.DatabaseName, world.Persistence, journal);
        var without = TestSigner.Over(world.Keystore, world.DatabaseName, world.Persistence);
        Issue(with, ca, 1);
        Issue(without, ca, 2);

        foreach (var (callers, perCaller) in new[] { (1, 300), (8, 150), (32, 60) })
        {
            var plain = await RateAsync(without, ca, callers, perCaller, 10_000_000_000);
            var journaled = await RateAsync(with, ca, callers, perCaller, 20_000_000_000);
            output.WriteLine($"MEASURE callers={callers} certificates={callers * perCaller}: without journal {plain:0} /s, with journal {journaled:0} /s");
        }
        await journal.DisposeAsync();
        var verification = sandbox.Verify();
        output.WriteLine($"MEASURE journal: {verification.Records} records, {verification.Checkpoints} checkpoints, {verification.Segments.Sum(s => s.WholeBytes)} bytes, fault: {verification.Fault?.ToString() ?? "none"}");

        Directory.CreateDirectory(keep);
        foreach (var file in Directory.GetFiles(sandbox.Directory))
            File.Copy(file, Path.Combine(keep, Path.GetFileName(file)), overwrite: true);
        sandbox.Dispose();
    }

    private static readonly Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair SubjectKey = KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-256");
}
