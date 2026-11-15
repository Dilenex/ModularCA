using ModularCA.Shared.Modes;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Modes;

/// <summary>
/// The mode's table, its record on disk and the start rules: with no hub socket and no file the
/// instance is full; with a hub socket and no file it starts in the start mode, restricted when
/// none is named; a recorded mode survives a restart; the last writer wins.
/// </summary>
public sealed class InstanceModeStoreTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "mca-mode-" + Guid.NewGuid().ToString("N"));
    private readonly FixedTimeProvider _clock = new(new DateTimeOffset(2026, 11, 11, 9, 0, 0, TimeSpan.Zero));

    public InstanceModeStoreTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private string ConfigDir => Path.Combine(_dir, "config");
    private string HubSocket => Path.Combine(_dir, "hub", "hub.sock");

    [Theory]
    [InlineData(InstanceMode.Full, ModeOperation.Fact, true)]
    [InlineData(InstanceMode.Full, ModeOperation.Restriction, true)]
    [InlineData(InstanceMode.Full, ModeOperation.Frozen, true)]
    [InlineData(InstanceMode.Full, ModeOperation.Manage, true)]
    [InlineData(InstanceMode.Full, ModeOperation.Issue, true)]
    [InlineData(InstanceMode.Restricted, ModeOperation.Issue, true)]
    // Maintenance: nothing is issued and nothing is reconfigured; revoking and the other facts go on.
    [InlineData(InstanceMode.Maintenance, ModeOperation.Issue, false)]
    [InlineData(InstanceMode.Maintenance, ModeOperation.Frozen, false)]
    [InlineData(InstanceMode.Maintenance, ModeOperation.Restriction, true)]
    [InlineData(InstanceMode.Maintenance, ModeOperation.Fact, true)]
    [InlineData(InstanceMode.Maintenance, ModeOperation.Manage, true)]
    [InlineData(InstanceMode.DisasterRecovery, ModeOperation.Issue, false)]
    [InlineData(InstanceMode.Restricted, ModeOperation.Fact, true)]
    [InlineData(InstanceMode.Restricted, ModeOperation.Restriction, true)]
    [InlineData(InstanceMode.Restricted, ModeOperation.Frozen, false)]
    [InlineData(InstanceMode.Restricted, ModeOperation.Manage, true)]
    [InlineData(InstanceMode.DisasterRecovery, ModeOperation.Fact, false)]
    [InlineData(InstanceMode.DisasterRecovery, ModeOperation.Restriction, false)]
    [InlineData(InstanceMode.DisasterRecovery, ModeOperation.Frozen, false)]
    [InlineData(InstanceMode.DisasterRecovery, ModeOperation.Manage, true)]
    public void The_table(InstanceMode mode, ModeOperation operation, bool allowed)
        => Assert.Equal(allowed, InstanceModeGate.Allows(mode, operation));

    [Fact]
    public void With_no_gate_and_with_the_default_gate_nothing_is_refused()
    {
        foreach (var operation in Enum.GetValues<ModeOperation>())
        {
            Assert.Null(InstanceModeGate.Require(null, operation, "Anything"));
            Assert.Null(InstanceModeGate.Require(FullInstanceModeGate.Instance, operation, "Anything"));
        }
    }

    [Fact]
    public void A_refusal_names_the_mode_says_what_still_works_and_carries_its_code()
    {
        var store = new InstanceModeStore(Path.Combine(_dir, "m.json"), new InstanceModeRecord(InstanceMode.Restricted, InstanceModeSource.Start));
        var refusal = InstanceModeGate.Require(store, ModeOperation.Frozen, "Creating a role");

        Assert.NotNull(refusal);
        Assert.Equal(503, refusal!.Status);
        Assert.Equal("MCA-MOD-001", refusal.Code);
        Assert.StartsWith("Creating a role is not available while this instance is in restricted mode.", refusal.Message);
        Assert.Contains("Issuing, revoking", refusal.Message);

        store.Set(InstanceMode.DisasterRecovery, InstanceModeSource.Hub, null, null);
        var dr = InstanceModeGate.Require(store, ModeOperation.Fact, "Issuing a certificate")!;
        Assert.Equal("MCA-MOD-002", dr.Code);
        Assert.Contains("DR mode", dr.Message);
        Assert.Contains("Signing in", dr.Message);
    }

    [Fact]
    public void No_hub_socket_and_no_file_is_full_and_writes_nothing()
    {
        var store = InstanceModeStore.Open(null, null, ConfigDir, _clock);

        Assert.Equal(InstanceModeRecord.DefaultFull, store.Current);
        Assert.Equal(Path.Combine(ConfigDir, InstanceModeStore.FileName), store.FilePath);
        Assert.False(Directory.Exists(ConfigDir));
    }

    [Fact]
    public void A_start_mode_without_a_hub_socket_is_ignored()
        => Assert.Equal(InstanceMode.Full, InstanceModeStore.Open("  ", "dr", ConfigDir, _clock).Current.Mode);

    [Fact]
    public void A_hub_socket_and_no_file_starts_restricted_beside_the_socket()
    {
        var store = InstanceModeStore.Open(HubSocket, null, ConfigDir, _clock);

        Assert.Equal(InstanceMode.Restricted, store.Current.Mode);
        Assert.Equal(InstanceModeSource.Start, store.Current.Source);
        Assert.Equal(Path.Combine(_dir, "hub", InstanceModeStore.FileName), store.FilePath);
        Assert.False(File.Exists(store.FilePath));
    }

    [Theory]
    [InlineData("full", InstanceMode.Full)]
    [InlineData(" Restricted ", InstanceMode.Restricted)]
    [InlineData("DR", InstanceMode.DisasterRecovery)]
    [InlineData("Maintenance", InstanceMode.Maintenance)]
    public void A_hub_socket_and_no_file_starts_in_the_start_mode(string startMode, InstanceMode expected)
        => Assert.Equal(expected, InstanceModeStore.Open(HubSocket, startMode, ConfigDir, _clock).Current.Mode);

    [Theory]
    [InlineData("standby")]
    [InlineData("paused")]
    [InlineData("1")]
    public void A_start_mode_that_is_not_a_mode_stops_the_start(string startMode)
    {
        var ex = Assert.Throws<ArgumentException>(() => InstanceModeStore.Open(HubSocket, startMode, ConfigDir, _clock));
        Assert.Contains(InstanceModeStore.HubStartModeVariable, ex.Message);
    }

    [Fact]
    public void A_set_mode_survives_a_restart_and_beats_the_start_mode()
    {
        var first = InstanceModeStore.Open(HubSocket, "full", ConfigDir, _clock);
        first.Set(InstanceMode.DisasterRecovery, InstanceModeSource.Hub, "alice", "failing over");

        var restarted = InstanceModeStore.Open(HubSocket, "full", ConfigDir, _clock);

        var record = restarted.Current;
        Assert.Equal(InstanceMode.DisasterRecovery, record.Mode);
        Assert.Equal(InstanceModeSource.Hub, record.Source);
        Assert.Equal("alice", record.SetBy);
        Assert.Equal("failing over", record.Reason);
        Assert.Equal(_clock.Now.UtcDateTime, record.SetAtUtc);
    }

    [Fact]
    public void Without_a_hub_a_mode_set_by_hand_survives_a_restart_in_the_config_directory()
    {
        InstanceModeStore.Open(null, null, ConfigDir, _clock).Set(InstanceMode.Restricted, InstanceModeSource.Administrator, "root", "maintenance window");

        var record = InstanceModeStore.Open(null, null, ConfigDir, _clock).Current;

        Assert.Equal(InstanceMode.Restricted, record.Mode);
        Assert.Equal(InstanceModeSource.Administrator, record.Source);
        Assert.True(File.Exists(Path.Combine(ConfigDir, InstanceModeStore.FileName)));
    }

    [Fact]
    public void The_last_writer_wins_and_the_record_says_who()
    {
        var store = InstanceModeStore.Open(HubSocket, null, ConfigDir, _clock);
        store.Set(InstanceMode.DisasterRecovery, InstanceModeSource.Hub, "alice", null);
        _clock.Now += TimeSpan.FromMinutes(5);
        store.Set(InstanceMode.Full, InstanceModeSource.Administrator, "bob", "the hub is gone");

        Assert.Equal(new InstanceModeRecord(InstanceMode.Full, InstanceModeSource.Administrator, "bob", "the hub is gone", _clock.Now.UtcDateTime), store.Current);
        Assert.False(File.Exists(store.FilePath + ".tmp"));
    }

    [Fact]
    public void A_change_made_by_another_process_is_seen_after_the_recheck_interval()
    {
        var mine = InstanceModeStore.Open(HubSocket, "full", ConfigDir, _clock);
        var other = InstanceModeStore.Open(HubSocket, "full", ConfigDir, _clock);
        Assert.Equal(InstanceMode.Full, mine.Current.Mode);

        other.Set(InstanceMode.DisasterRecovery, InstanceModeSource.Hub, null, null);
        _clock.Now += InstanceModeStore.RecheckInterval;

        Assert.Equal(InstanceMode.DisasterRecovery, mine.Current.Mode);
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("{\"version\":1,\"mode\":\"standby\",\"source\":\"hub\"}")]
    [InlineData("{\"version\":1,\"mode\":\"full\"}")]
    [InlineData("")]
    public void A_record_that_cannot_be_read_holds_the_instance_restricted_until_a_mode_is_set(string contents)
    {
        Directory.CreateDirectory(ConfigDir);
        File.WriteAllText(Path.Combine(ConfigDir, InstanceModeStore.FileName), contents);

        var store = InstanceModeStore.Open(null, null, ConfigDir, _clock);

        Assert.Equal(InstanceMode.Restricted, store.Current.Mode);
        Assert.Equal(InstanceModeSource.Unreadable, store.Current.Source);

        store.Set(InstanceMode.Full, InstanceModeSource.Administrator, "root", "repaired");
        Assert.Equal(InstanceMode.Full, InstanceModeStore.Open(null, null, ConfigDir, _clock).Current.Mode);
    }

    [Fact]
    public void The_record_is_readable_by_its_owner_only()
    {
        if (OperatingSystem.IsWindows()) return;
        var store = InstanceModeStore.Open(HubSocket, null, ConfigDir, _clock);
        store.Set(InstanceMode.Full, InstanceModeSource.Hub, null, null);

        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(store.FilePath));
    }
}
