using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Auth.Services;
using ModularCA.Bootstrap;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Utils;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Bootstrap;

/// <summary>
/// The claim the headless bootstrap creates for the first administrator is in the audit trail:
/// one hash-chained record by <c>bootstrap</c>, without the token or its hash, written straight
/// into the audit database; nothing for a generated password; and when the audit database
/// refuses the write, the record is queued and reaches the trail at the node's first start.
/// </summary>
[Collection(BootstrapAuditLogCollection.Name)]
public sealed class InitialAdminClaimAuditTests : IDisposable
{
    private static readonly DateTime Now = new(2026, 11, 9, 12, 0, 0, DateTimeKind.Utc);
    private readonly string _logs = Path.Combine(Path.GetTempPath(), $"mca-claim-audit-{Guid.NewGuid():N}");
    private readonly string _configDir = Directory.CreateTempSubdirectory("mca-claim-audit-config-").FullName;
    private readonly string _auditName = $"audit-{Guid.NewGuid():N}";

    public InitialAdminClaimAuditTests() => BootstrapAuditLog.LogDirectory = _logs;

    public void Dispose()
    {
        BootstrapAuditLog.LogDirectory = null;
        if (Directory.Exists(_logs))
            Directory.Delete(_logs, recursive: true);
        try { Directory.Delete(_configDir, recursive: true); } catch { /* best effort */ }
    }

    private AuditDbContext AuditDb()
        => new(new DbContextOptionsBuilder<AuditDbContext>().UseInMemoryDatabase(_auditName).Options);

    /// <summary>Creates the first administrator as the bootstrap does, by claim when <paramref name="token"/> is given.</summary>
    private InitialAdminHandover Handover(string? token)
    {
        using var db = InMemoryDbContextFactory.Create();
        db.CaGroups.AddRange(
            new CaGroupEntity { Name = "system-super", DisplayName = "system-super", IsSystemGroup = true, IsSystemTierSuper = true },
            new CaGroupEntity { Name = "system-admin", DisplayName = "system-admin", IsSystemGroup = true });
        db.SaveChanges();
        var administration = token == null
            ? null
            : new YamlBootstrapLoader.AdministrationConfig { ClaimTokenSha256 = AccountClaims.HashHex(token), ClaimTokenLifetimeHours = 48 };
        var handover = BootstrapProfileSeeder.CreateInitialUser(db, _configDir, administration, TextWriter.Null, Now);
        Assert.Equal(db.Users.Single().Id, handover.UserId);
        return handover;
    }

    [Fact]
    public async Task A_claim_is_recorded_once_by_bootstrap_on_the_hash_chain_without_the_token_or_its_hash()
    {
        var token = AccountClaims.NewToken();
        var handover = Handover(token);
        var output = new StringWriter();

        Assert.True(await InitialAdminClaimAudit.RecordAsync(AuditDb, handover, output));

        using var auditDb = AuditDb();
        var record = Assert.Single(auditDb.AuditLogs);
        Assert.Equal(AuditActionType.UserClaimTokenIssuedAtBootstrap, record.ActionType);
        Assert.Equal("bootstrap", record.ActorUsername);
        Assert.Null(record.ActorUserId);
        Assert.Equal(("User", handover.UserId.ToString()), (record.TargetEntityType, record.TargetEntityId));
        Assert.True(record.Success);

        using var details = JsonDocument.Parse(record.DetailsJson!);
        Assert.Equal(BootstrapProfileSeeder.InitialUsername, details.RootElement.GetProperty("Username").GetString());
        Assert.Equal(Now.AddHours(48), details.RootElement.GetProperty("ExpiresAt").GetDateTime().ToUniversalTime());
        Assert.Equal(Environment.MachineName, details.RootElement.GetProperty("Host").GetString());
        Assert.DoesNotContain("***", record.DetailsJson);

        // Neither the token nor its hash, in either case, anywhere in the record or the output.
        foreach (var secret in new[] { token, AccountClaims.HashHex(token), AccountClaims.HashHex(token).ToUpperInvariant(), Convert.ToBase64String(AccountClaims.Hash(token)) })
        {
            Assert.DoesNotContain(secret, record.DetailsJson);
            Assert.DoesNotContain(secret, output.ToString());
        }

        // Through the hash chain every other record goes through.
        Assert.False(string.IsNullOrEmpty(record.RecordHash));
        Assert.Equal(AuditHashChainService.CurrentHashVersion, record.HashVersion);
        Assert.Contains("recorded in the audit trail", output.ToString());
        Assert.False(Directory.Exists(_logs) && Directory.GetFiles(_logs).Length > 0, "nothing is queued when the write succeeds");
    }

    [Fact]
    public async Task A_generated_password_records_no_claim()
    {
        var handover = Handover(token: null);
        var output = new StringWriter();

        Assert.False(await InitialAdminClaimAudit.RecordAsync(AuditDb, handover, output));

        using var auditDb = AuditDb();
        Assert.Empty(auditDb.AuditLogs);
        Assert.Equal(string.Empty, output.ToString());
        Assert.False(Directory.Exists(_logs) && Directory.GetFiles(_logs).Length > 0);
    }

    [Fact]
    public async Task When_the_audit_database_refuses_the_write_the_record_is_queued_for_the_nodes_first_start()
    {
        var token = AccountClaims.NewToken();
        var handover = Handover(token);
        var output = new StringWriter();

        var recorded = await InitialAdminClaimAudit.RecordAsync(
            () => throw new InvalidOperationException("the audit database is away"), handover, output);

        // The bootstrap goes on, and says what happened.
        Assert.False(recorded);
        Assert.Contains("[WARNING]", output.ToString());
        Assert.Contains("the audit database is away", output.ToString());

        var queued = Assert.Single(Directory.GetFiles(_logs, "bootstrap-audit-*.jsonl"));
        var line = Assert.Single(File.ReadAllLines(queued));
        Assert.DoesNotContain(token, line);
        Assert.DoesNotContain(AccountClaims.HashHex(token), line, StringComparison.OrdinalIgnoreCase);

        // The node's first start replays it into the trail, against the same account.
        var audit = new RecordingAuditService();
        await new BootstrapAuditReplayService(audit, NullLogger<BootstrapAuditReplayService>.Instance).ReplayPendingAsync(_logs);
        var entry = Assert.Single(audit.Entries, e => e.Action == AuditActionType.UserClaimTokenIssuedAtBootstrap);
        Assert.Equal(handover.UserId.ToString(), entry.TargetId);
        var scrubbed = AuditJsonScrubber.SerializeAndScrub(entry.Details)!;
        Assert.DoesNotContain("***", scrubbed);
        using var details = JsonDocument.Parse(scrubbed);
        Assert.Equal(BootstrapProfileSeeder.InitialUsername, details.RootElement.GetProperty("Decision").GetProperty("Username").GetString());
    }
}
