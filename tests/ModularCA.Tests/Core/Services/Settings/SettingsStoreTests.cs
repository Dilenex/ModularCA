using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services.Settings;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Settings;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services.Settings;

/// <summary>
/// The settings store: instance-wide settings as rows keyed by their catalog name, each change
/// under a revision, in a history and in the audit log. What two writers do to each other is in
/// <c>PostgresSettingsStoreTests</c>: the in-memory provider saves row by row, so it cannot show
/// a write that is all or nothing.
/// </summary>
public class SettingsStoreTests
{
    private static readonly SettingsActor Alice = new(Guid.NewGuid(), "alice", "203.0.113.7");

    private sealed class World
    {
        public string DatabaseName { get; } = $"settings-{Guid.NewGuid():N}";
        public RecordingAuditService Audit { get; } = new();

        /// <summary>A store over its own context, as each request has.</summary>
        public SettingsStore Store(IAuditService? audit = null) =>
            new(InMemoryDbContextFactory.Create(DatabaseName), audit ?? Audit, NullLogger<SettingsStore>.Instance);

        public ModularCADbContext Db() => InMemoryDbContextFactory.Create(DatabaseName);
    }

    private static SettingsChange Set(string key, JsonNode? value, IReadOnlyDictionary<string, int>? expected = null) => new()
    {
        Set = new Dictionary<string, JsonNode?> { [key] = value },
        ExpectedVersions = expected ?? new Dictionary<string, int>(),
        Actor = Alice,
        Source = SettingsSource.Api,
    };

    [Fact]
    public async Task A_setting_is_stored_under_its_key_with_a_revision_a_history_row_and_an_audit_record()
    {
        var world = new World();

        var result = await world.Store().WriteAsync(new SettingsChange
        {
            Set = new Dictionary<string, JsonNode?> { ["Acme_Http01_MaxAddresses"] = JsonValue.Create(8) },
            Actor = Alice, Source = SettingsSource.Api, Reason = "more mirrors",
        });

        Assert.Equal(1, result.Revision);
        Assert.Equal(["Acme_Http01_MaxAddresses"], result.ChangedKeys);

        var snapshot = await world.Store().LoadAsync();
        Assert.Equal(1, snapshot.Revision);
        var stored = Assert.Single(snapshot.Settings.Values);
        Assert.Equal(("Acme_Http01_MaxAddresses", "8", 1, 1L, "alice", "Api"),
            (stored.Key, stored.ValueJson, stored.Version, stored.Revision, stored.ActorName, stored.Source));

        var history = Assert.Single(await world.Store().HistoryAsync("Acme_Http01_MaxAddresses"));
        Assert.Equal((1L, 1, "8", null, "more mirrors"),
            (history.Revision, history.Version, history.ValueJson, history.PreviousValueJson, history.Reason));

        var audited = Assert.Single(world.Audit.Entries);
        Assert.Equal((AuditActionType.ConfigUpdated, "1"), (audited.Action, audited.TargetId));
    }

    [Fact]
    public async Task Settings_written_together_share_one_revision()
    {
        var world = new World();

        var result = await world.Store().WriteAsync(new SettingsChange
        {
            Set = new Dictionary<string, JsonNode?>
            {
                ["Acme_Http01_MaxAddresses"] = JsonValue.Create(8),
                ["Acme_Http01_TimeoutSeconds"] = JsonValue.Create(20),
                ["IpWhitelist_ExemptPaths"] = new JsonArray("/health", "/metrics"),
            },
            Actor = Alice, Source = SettingsSource.Api,
        });

        Assert.Equal(1, result.Revision);
        Assert.Equal(3, result.ChangedKeys.Count);
        var snapshot = await world.Store().LoadAsync();
        Assert.All(snapshot.Settings.Values, s => Assert.Equal((1L, 1), (s.Revision, s.Version)));
        Assert.Equal("[\"/health\",\"/metrics\"]", snapshot.Settings["IpWhitelist_ExemptPaths"].ValueJson);
        Assert.Single(world.Audit.Entries);

        // A later change to one of them moves that one only.
        var second = await world.Store().WriteAsync(Set("Acme_Http01_TimeoutSeconds", JsonValue.Create(30)));
        Assert.Equal(2, second.Revision);
        snapshot = await world.Store().LoadAsync();
        Assert.Equal((2L, 2), (snapshot.Settings["Acme_Http01_TimeoutSeconds"].Revision, snapshot.Settings["Acme_Http01_TimeoutSeconds"].Version));
        Assert.Equal((1L, 1), (snapshot.Settings["Acme_Http01_MaxAddresses"].Revision, snapshot.Settings["Acme_Http01_MaxAddresses"].Version));
        var history = await world.Store().HistoryAsync("Acme_Http01_TimeoutSeconds");
        Assert.Equal(["30", "20"], history.Select(h => h.ValueJson));
        Assert.Equal("20", history[0].PreviousValueJson);
    }

    [Fact]
    public async Task Writing_the_value_a_setting_already_has_changes_nothing_and_takes_no_revision()
    {
        var world = new World();
        await world.Store().WriteAsync(Set("IpWhitelist_ExemptPaths", new JsonArray("/health")));

        // The same list, spelled with different whitespace.
        var again = await world.Store().WriteAsync(Set("IpWhitelist_ExemptPaths", JsonNode.Parse("[ \"/health\" ]")));

        Assert.Equal(1, again.Revision);
        Assert.Empty(again.ChangedKeys);
        Assert.Single(await world.Store().HistoryAsync("IpWhitelist_ExemptPaths"));
        Assert.Single(world.Audit.Entries);
    }

    [Fact]
    public async Task A_cleared_setting_goes_back_to_its_default_and_keeps_counting_versions()
    {
        var world = new World();
        await world.Store().WriteAsync(Set("Acme_Http01_MaxAddresses", JsonValue.Create(8)));

        var cleared = await world.Store().WriteAsync(new SettingsChange
        {
            Clear = ["Acme_Http01_MaxAddresses"], Actor = Alice, Source = SettingsSource.Api,
        });

        Assert.Equal(2, cleared.Revision);
        var snapshot = await world.Store().LoadAsync();
        var stored = snapshot.Settings["Acme_Http01_MaxAddresses"];
        Assert.Null(stored.ValueJson);
        Assert.Equal(2, stored.Version);

        var config = new SystemConfig();
        Assert.Empty(snapshot.ApplyTo(config));
        Assert.Equal(new SystemConfig().Acme.Http01.MaxAddresses, config.Acme.Http01.MaxAddresses);

        var history = await world.Store().HistoryAsync("Acme_Http01_MaxAddresses");
        Assert.Equal([null, "8"], history.Select(h => h.ValueJson));
    }

    [Theory]
    [InlineData("Acme_Http01_Bogus", SettingsRefusal.UnknownKey)]
    [InlineData("acme_http01_maxaddresses", SettingsRefusal.UnknownKey)]
    [InlineData("DB_App_Host", SettingsRefusal.NotStoredInDatabase)]
    [InlineData("Https_Port", SettingsRefusal.NotStoredInDatabase)]
    [InlineData("Hsm_Pin", SettingsRefusal.NotStoredInDatabase)]
    [InlineData("JWT_Secret", SettingsRefusal.SecretNotSupported)]
    [InlineData("IntegrationApi_ApiKey", SettingsRefusal.SecretNotSupported)]
    public async Task A_setting_that_does_not_belong_in_the_database_is_refused_and_nothing_is_written(string key, SettingsRefusal reason)
    {
        var world = new World();

        var refused = await Assert.ThrowsAsync<SettingsRefusedException>(() =>
            world.Store().WriteAsync(new SettingsChange
            {
                Set = new Dictionary<string, JsonNode?>
                {
                    ["Acme_Http01_MaxAddresses"] = JsonValue.Create(8),
                    [key] = JsonValue.Create("x"),
                },
                Actor = Alice, Source = SettingsSource.Api,
            }));

        Assert.Equal(reason, refused.Reason);
        Assert.Equal(key, refused.Key);
        Assert.Empty((await world.Store().LoadAsync()).Settings);
        Assert.Empty(world.Audit.Entries);
    }

    [Fact]
    public async Task A_value_of_the_wrong_type_is_refused()
    {
        var world = new World();

        var wrongType = await Assert.ThrowsAsync<SettingsRefusedException>(() =>
            world.Store().WriteAsync(Set("Acme_Http01_MaxAddresses", JsonValue.Create("eight"))));
        var nullWhereNotAllowed = await Assert.ThrowsAsync<SettingsRefusedException>(() =>
            world.Store().WriteAsync(Set("Acme_Http01_MaxAddresses", null)));

        Assert.Equal(SettingsRefusal.InvalidValue, wrongType.Reason);
        Assert.Equal(SettingsRefusal.InvalidValue, nullWhereNotAllowed.Reason);
        Assert.Empty((await world.Store().LoadAsync()).Settings);
    }

    [Fact]
    public async Task A_null_is_a_value_where_the_setting_allows_one()
    {
        var world = new World();
        await world.Store().WriteAsync(Set("Http_PublicPort", JsonValue.Create(8080)));

        await world.Store().WriteAsync(Set("Http_PublicPort", null));

        var snapshot = await world.Store().LoadAsync();
        Assert.Equal("null", snapshot.Settings["Http_PublicPort"].ValueJson);
        var config = new SystemConfig { Http = { PublicPort = 1 } };
        Assert.Empty(snapshot.ApplyTo(config));
        Assert.Null(config.Http.PublicPort);
    }

    [Fact]
    public async Task A_write_that_expects_a_version_the_setting_is_not_at_is_refused()
    {
        var world = new World();
        await world.Store().WriteAsync(Set("Tokens_RefreshTokenDays", JsonValue.Create(7),
            expected: new Dictionary<string, int> { ["Tokens_RefreshTokenDays"] = 0 }));

        var stale = await Assert.ThrowsAsync<SettingsRefusedException>(() =>
            world.Store().WriteAsync(Set("Tokens_RefreshTokenDays", JsonValue.Create(14),
                expected: new Dictionary<string, int> { ["Tokens_RefreshTokenDays"] = 0 })));

        Assert.Equal(SettingsRefusal.VersionConflict, stale.Reason);
        Assert.Equal("7", (await world.Store().LoadAsync()).Settings["Tokens_RefreshTokenDays"].ValueJson);

        var current = await world.Store().WriteAsync(Set("Tokens_RefreshTokenDays", JsonValue.Create(14),
            expected: new Dictionary<string, int> { ["Tokens_RefreshTokenDays"] = 1 }));
        Assert.Equal(2, current.Revision);
    }

    [Fact]
    public async Task A_snapshot_sets_the_stored_values_on_a_configuration_and_reports_rows_it_cannot_use()
    {
        var world = new World();
        await world.Store().WriteAsync(new SettingsChange
        {
            Set = new Dictionary<string, JsonNode?>
            {
                ["Acme_Http01_MaxAddresses"] = JsonValue.Create(8),
                ["Audit_FailMode"] = JsonValue.Create(nameof(AuditFailMode.FailClosed)),
                ["CertExpiryNotification_WarningDaysBeforeExpiry"] = new JsonArray(60, 14),
            },
            Actor = Alice, Source = SettingsSource.Api,
        });
        using (var db = world.Db())
        {
            // Rows no write through the store could have produced.
            db.Settings.Add(new SettingEntity { Key = "Gone_In_This_Build", ValueJson = "1", Version = 1, Revision = 1 });
            db.Settings.Add(new SettingEntity { Key = "Https_Port", ValueJson = "1", Version = 1, Revision = 1 });
            db.Settings.Add(new SettingEntity { Key = "Tokens_RefreshTokenDays", ValueJson = "\"soon\"", Version = 1, Revision = 1 });
            await db.SaveChangesAsync();
        }

        var config = new SystemConfig();
        var httpsPort = config.Https.Port;
        var refreshDays = config.Tokens.RefreshTokenDays;
        var problems = (await world.Store().LoadAsync()).ApplyTo(config);

        Assert.Equal(8, config.Acme.Http01.MaxAddresses);
        Assert.Equal(AuditFailMode.FailClosed, config.Audit.FailMode);
        Assert.Equal([60, 14], config.CertExpiryNotification.WarningDaysBeforeExpiry);
        Assert.Equal(httpsPort, config.Https.Port);
        Assert.Equal(refreshDays, config.Tokens.RefreshTokenDays);
        Assert.Equal(3, problems.Count);
        Assert.Contains(problems, p => p.StartsWith("Gone_In_This_Build"));
        Assert.Contains(problems, p => p.StartsWith("Https_Port"));
        Assert.Contains(problems, p => p.StartsWith("Tokens_RefreshTokenDays"));
    }
}
