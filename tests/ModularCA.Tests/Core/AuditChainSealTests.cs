using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using Xunit;

namespace ModularCA.Tests.Core;

/// <summary>
/// 0.4.0 S3 retires the per-space audit chains: new records go to the instance chain, and each
/// retired chain is sealed once, with its final hash anchored in the instance chain, so deleting
/// its tail (which no link would otherwise reveal) is detected.
/// </summary>
public class AuditChainSealTests
{
    private static readonly Guid Space = Guid.Parse("11111111-2222-3333-4444-555555555555");

    private static AuditDbContext Context() =>
        new(new DbContextOptionsBuilder<AuditDbContext>()
            .UseInMemoryDatabase($"seal-{Guid.NewGuid():N}")
            .Options);

    private static async Task<AuditLogEntity> WriteAsync(AuditDbContext db, AuditHashChainService chain, Guid? spaceId, string action = "Issued")
    {
        var entry = new AuditLogEntity { ActionType = action, ActorUsername = "admin", Success = true, TenantId = spaceId };
        await chain.AppendAsync(db, entry);
        return entry;
    }

    [Fact]
    public async Task A_new_record_goes_to_the_instance_chain_and_keeps_the_space_the_caller_names()
    {
        await using var db = Context();
        var chain = new AuditHashChainService();
        var audit = new AuditService(NullLogger<AuditService>.Instance, db, hashChain: chain);

        await audit.LogAsync("KerberosRealmCreated", Guid.NewGuid(), "admin", spaceId: Space);
        await audit.LogAsync("UserLogin", Guid.NewGuid(), "admin");

        var rows = await db.AuditLogs.OrderBy(a => a.Timestamp).ToListAsync();
        Assert.All(rows, r => Assert.Null(r.TenantId));
        Assert.Equal([Space, null], rows.Select(r => r.SpaceId));
        Assert.Empty((await chain.VerifyAsync(db, null)).Breaks);

        // The space is hashed: moving a record to another space breaks the chain.
        rows[0].SpaceId = Guid.NewGuid();
        await db.SaveChangesAsync();
        Assert.Contains((await chain.VerifyAsync(db, null)).Breaks, b => b.RecordId == rows[0].Id && b.Issue.StartsWith("RecordHash tampered"));
    }

    [Fact]
    public async Task Sealing_is_idempotent_and_a_sealed_chain_verifies()
    {
        await using var db = Context();
        var chain = new AuditHashChainService();
        await WriteAsync(db, chain, Space);
        var last = await WriteAsync(db, chain, Space);
        await WriteAsync(db, chain, null);

        Assert.Equal([Space], await chain.SealRetiredChainsAsync(db));
        Assert.Empty(await chain.SealRetiredChainsAsync(db));

        Assert.Equal(1, await db.AuditLogs.CountAsync(a => a.ActionType == AuditHashChainService.ChainSealedAction));
        var succession = await db.AuditLogs.SingleAsync(a => a.ActionType == AuditHashChainService.ChainSuccessionAction);
        Assert.Null(succession.TenantId);
        var seal = await db.AuditLogs.SingleAsync(a => a.ActionType == AuditHashChainService.ChainSealedAction);
        Assert.Equal(Space, seal.TenantId);
        Assert.Equal(last.RecordHash, seal.PreviousRecordHash);
        Assert.Contains(last.RecordHash!, seal.DetailsJson);
        Assert.Contains(AuditHashChainService.FoldMigrationId, seal.DetailsJson);
        Assert.Contains(seal.RecordHash!, succession.DetailsJson);

        var retired = await chain.VerifyAsync(db, Space);
        Assert.Empty(retired.Breaks);
        Assert.True(retired.Sealed);
        Assert.Empty((await chain.VerifyAsync(db, null)).Breaks);
        Assert.Equal(RetiredChainState.Sealed, (await chain.CheckRetiredChainAsync(db, Space)).State);
    }

    [Fact]
    public async Task Deleting_the_sealed_tail_is_detected_through_the_succession_record()
    {
        await using var db = Context();
        var chain = new AuditHashChainService();
        await WriteAsync(db, chain, Space);
        await chain.SealRetiredChainsAsync(db);

        db.AuditLogs.Remove(await db.AuditLogs.SingleAsync(a => a.ActionType == AuditHashChainService.ChainSealedAction));
        await db.SaveChangesAsync();

        // Its own links cannot tell: the tail is gone and what is left is a consistent chain.
        Assert.Empty((await chain.VerifyAsync(db, Space)).Breaks);
        var status = await chain.CheckRetiredChainAsync(db, Space);
        Assert.Equal(RetiredChainState.TailMissing, status.State);
        Assert.NotNull(status.Issue);
    }

    [Fact]
    public async Task A_record_after_the_seal_is_a_break_but_a_prune_marker_is_not()
    {
        await using var db = Context();
        var chain = new AuditHashChainService();
        await WriteAsync(db, chain, Space);
        await chain.SealRetiredChainsAsync(db);

        await chain.RecordPruneAsync(db, Space, DateTime.UtcNow.AddYears(-1));
        Assert.Empty((await chain.VerifyAsync(db, Space)).Breaks);

        var late = await WriteAsync(db, chain, Space);
        var result = await chain.VerifyAsync(db, Space);
        Assert.Contains(result.Breaks, b => b.RecordId == late.Id);
    }

    [Fact]
    public async Task A_seal_that_retention_pruned_is_not_replaced_by_a_fresh_one()
    {
        await using var db = Context();
        var chain = new AuditHashChainService();
        await WriteAsync(db, chain, Space);
        await WriteAsync(db, chain, Space);
        await chain.SealRetiredChainsAsync(db);

        db.AuditLogs.Remove(await db.AuditLogs.SingleAsync(a => a.ActionType == AuditHashChainService.ChainSealedAction));
        await db.SaveChangesAsync();

        Assert.Empty(await chain.SealRetiredChainsAsync(db));
        Assert.Equal(0, await db.AuditLogs.CountAsync(a => a.ActionType == AuditHashChainService.ChainSealedAction));
        Assert.Equal(1, await db.AuditLogs.CountAsync(a => a.ActionType == AuditHashChainService.ChainSuccessionAction));
    }

    [Fact]
    public async Task A_retired_chain_deleted_outright_is_still_listed_and_reported_broken()
    {
        await using var db = Context();
        var chain = new AuditHashChainService();
        await WriteAsync(db, chain, Space);
        await WriteAsync(db, chain, null);
        await chain.SealRetiredChainsAsync(db);

        db.AuditLogs.RemoveRange(await db.AuditLogs.Where(a => a.TenantId == Space).ToListAsync());
        await db.SaveChangesAsync();

        Assert.Contains(Space, await chain.ListRetiredChainsAsync(db));
        Assert.Equal(RetiredChainState.TailMissing, (await chain.CheckRetiredChainAsync(db, Space)).State);

        using var mainDb = ModularCA.Tests.TestUtils.InMemoryDbContextFactory.Create();
        var controller = Activator.CreateInstance(
            ModularCA.Tests.Roles.ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Admin.AdminAuditController"),
            mainDb, null, null, db, chain)!;
        var verify = (Task<Microsoft.AspNetCore.Mvc.IActionResult>)controller.GetType().GetMethod("VerifyAllChains")!.Invoke(controller, [10000])!;
        var ok = Assert.IsType<Microsoft.AspNetCore.Mvc.OkObjectResult>(await verify);
        using var report = System.Text.Json.JsonDocument.Parse(System.Text.Json.JsonSerializer.Serialize(ok.Value));
        var chains = report.RootElement.EnumerateArray().ToList();
        Assert.Equal(2, chains.Count);
        Assert.Equal("Valid", chains[0].GetProperty("Integrity").GetString());
        var retired = chains[1];
        Assert.Equal("retired", retired.GetProperty("Chain").GetString());
        Assert.Equal(Space, retired.GetProperty("ChainId").GetGuid());
        Assert.False(retired.TryGetProperty("TenantId", out _));
        Assert.Equal("TAMPERED", retired.GetProperty("Integrity").GetString());
        Assert.Equal(nameof(RetiredChainState.TailMissing), retired.GetProperty("TailState").GetString());
    }

    private sealed class NoUser : ModularCA.Auth.Interfaces.ICurrentUserService
    {
        public Guid? UserId => null;
        public UserEntity? User => null;
        public bool IsAuthenticated => false;
        public Task EnsureLoadedAsync() => Task.CompletedTask;
    }

    /// <summary>
    /// A space's audit view finds the records stamped with the space, and those about one of its
    /// CAs, the space itself, or one of its groups; nothing of another space. Each item carries its space.
    /// </summary>
    [Fact]
    public async Task A_spaces_audit_view_finds_new_records_about_the_space_and_its_groups()
    {
        await using var db = Context();
        using var mainDb = ModularCA.Tests.TestUtils.InMemoryDbContextFactory.Create();
        var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Space CA", Label = "space-ca", SpaceId = Space };
        var group = new CaGroupEntity { Id = Guid.NewGuid(), Name = "org-space-operator", SpaceId = Space };
        var otherGroup = new CaGroupEntity { Id = Guid.NewGuid(), Name = "org-other-operator", SpaceId = Guid.NewGuid() };
        mainDb.CertificateAuthorities.Add(ca);
        mainDb.CaGroups.AddRange(group, otherGroup);
        await mainDb.SaveChangesAsync();

        AuditLogEntity Row(string action, string? type = null, string? target = null, Guid? caId = null) =>
            new() { ActionType = action, ActorUsername = "admin", Success = true, TargetEntityType = type, TargetEntityId = target, CertificateAuthorityId = caId };
        var stamped = Row("KerberosRealmCreated", "KerberosRealm", Guid.NewGuid().ToString());
        stamped.SpaceId = Space;
        var otherStamped = Row("KerberosRealmCreated", "KerberosRealm", Guid.NewGuid().ToString());
        otherStamped.SpaceId = Guid.NewGuid();
        db.AuditLogs.AddRange(
            stamped,
            otherStamped,
            Row("TenantUpdated", "Tenant", Space.ToString()),
            Row("GroupUpdated", "CaGroup", group.Id.ToString()),
            Row("CertificateIssued", caId: ca.Id),
            Row("TenantUpdated", "Tenant", Guid.NewGuid().ToString()),
            Row("GroupUpdated", "CaGroup", otherGroup.Id.ToString()));
        await db.SaveChangesAsync();

        var controller = Activator.CreateInstance(
            ModularCA.Tests.Roles.ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Admin.AdminAuditController"),
            mainDb, null, new NoUser(), db, new AuditHashChainService())!;
        var list = (Task<Microsoft.AspNetCore.Mvc.IActionResult>)controller.GetType().GetMethod("GetAuditLogs")!
            .Invoke(controller, [null, null, null, null, null, 1, 50, Space, null, null, null])!;
        var ok = Assert.IsType<Microsoft.AspNetCore.Mvc.OkObjectResult>(await list);
        using var page = System.Text.Json.JsonDocument.Parse(System.Text.Json.JsonSerializer.Serialize(ok.Value));
        Assert.Equal(4, page.RootElement.GetProperty("total").GetInt32());
        var items = page.RootElement.GetProperty("items").EnumerateArray().ToList();
        var actions = items.Select(i => i.GetProperty("ActionType").GetString()).OrderBy(a => a).ToList();
        Assert.Equal(["CertificateIssued", "GroupUpdated", "KerberosRealmCreated", "TenantUpdated"], actions);
        Assert.Equal(Space, items.Single(i => i.GetProperty("ActionType").GetString() == "KerberosRealmCreated").GetProperty("SpaceId").GetGuid());
    }

    [Fact]
    public async Task Verifying_a_chain_that_never_existed_is_404_not_valid()
    {
        await using var db = Context();
        var chain = new AuditHashChainService();
        await WriteAsync(db, chain, Space);
        await WriteAsync(db, chain, null);
        await chain.SealRetiredChainsAsync(db);
        using var mainDb = ModularCA.Tests.TestUtils.InMemoryDbContextFactory.Create();
        var controller = Activator.CreateInstance(
            ModularCA.Tests.Roles.ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Admin.AdminAuditController"),
            mainDb, null, null, db, chain)!;
        Task<Microsoft.AspNetCore.Mvc.IActionResult> Verify(Guid? chainId) =>
            (Task<Microsoft.AspNetCore.Mvc.IActionResult>)controller.GetType().GetMethod("VerifyHashChain")!.Invoke(controller, [chainId, 10000])!;

        Assert.IsType<Microsoft.AspNetCore.Mvc.NotFoundObjectResult>(await Verify(Guid.NewGuid()));
        Assert.IsType<Microsoft.AspNetCore.Mvc.OkObjectResult>(await Verify(null));
        var retired = Assert.IsType<Microsoft.AspNetCore.Mvc.OkObjectResult>(await Verify(Space));
        using var report = System.Text.Json.JsonDocument.Parse(System.Text.Json.JsonSerializer.Serialize(retired.Value));
        Assert.Equal("Valid", report.RootElement.GetProperty("Integrity").GetString());

        // A retired chain deleted outright is still known through its succession record: verified, and broken.
        db.AuditLogs.RemoveRange(await db.AuditLogs.Where(a => a.TenantId == Space).ToListAsync());
        await db.SaveChangesAsync();
        var deleted = Assert.IsType<Microsoft.AspNetCore.Mvc.OkObjectResult>(await Verify(Space));
        using var broken = System.Text.Json.JsonDocument.Parse(System.Text.Json.JsonSerializer.Serialize(deleted.Value));
        Assert.Equal("TAMPERED", broken.RootElement.GetProperty("Integrity").GetString());
    }

    [Fact]
    public async Task A_chain_without_a_succession_is_reported_unsealed()
    {
        await using var db = Context();
        var chain = new AuditHashChainService();
        await WriteAsync(db, chain, Space);

        Assert.Equal(RetiredChainState.Unsealed, (await chain.CheckRetiredChainAsync(db, Space)).State);
    }

    /// <summary>
    /// Review 2, 1(a): with its seal deleted, a retired chain is still pruned no further than the
    /// seal the instance chain anchors, and a prune marker past the seal does not account for it.
    /// </summary>
    [Fact]
    public async Task A_deleted_seal_bounds_retention_at_the_anchored_seal_and_reads_missing_despite_a_prune_marker()
    {
        await using var db = Context();
        var chain = new AuditHashChainService();
        await WriteAsync(db, chain, Space);
        await WriteAsync(db, chain, Space);
        await chain.SealRetiredChainsAsync(db);
        var seal = await db.AuditLogs.SingleAsync(a => a.ActionType == AuditHashChainService.ChainSealedAction);
        var sealedAt = seal.Timestamp;
        var cutoff = DateTime.UtcNow.AddDays(1);

        db.AuditLogs.Remove(seal);
        await db.SaveChangesAsync();
        Assert.Equal(sealedAt, await chain.PruneCutoffAsync(db, Space, cutoff));

        db.AuditLogs.RemoveRange(await db.AuditLogs.Where(a => a.TenantId == Space).ToListAsync());
        await db.SaveChangesAsync();
        await chain.RecordPruneAsync(db, Space, cutoff);

        var status = await chain.CheckRetiredChainAsync(db, Space);
        Assert.Equal(RetiredChainState.TailMissing, status.State);
        Assert.Empty(await chain.SealRetiredChainsAsync(db));
        Assert.Equal(0, await db.AuditLogs.CountAsync(a => a.ActionType == AuditHashChainService.ChainSealedAction));
    }

    [Fact]
    public async Task Successions_that_disagree_about_the_seal_read_altered()
    {
        await using var db = Context();
        var chain = new AuditHashChainService();
        await WriteAsync(db, chain, Space);
        await chain.SealRetiredChainsAsync(db);
        var original = await db.AuditLogs.SingleAsync(a => a.ActionType == AuditHashChainService.ChainSuccessionAction);
        var seal = await db.AuditLogs.SingleAsync(a => a.ActionType == AuditHashChainService.ChainSealedAction);

        await chain.AppendAsync(db, new AuditLogEntity
        {
            ActionType = AuditHashChainService.ChainSuccessionAction, ActorUsername = "system", Success = true,
            TargetEntityType = "AuditChain", TargetEntityId = original.TargetEntityId,
            DetailsJson = original.DetailsJson!.Replace(seal.RecordHash!, new string('0', 64)),
        });
        Assert.Equal(RetiredChainState.TailAltered, (await chain.CheckRetiredChainAsync(db, Space)).State);
        Assert.Contains("disagree", (await chain.CheckRetiredChainAsync(db, Space)).Issue);
    }

    [Fact]
    public async Task A_seal_whose_succession_is_gone_reads_altered_and_is_not_anchored_again()
    {
        await using var db = Context();
        var chain = new AuditHashChainService();
        var other = Guid.NewGuid();
        await WriteAsync(db, chain, Space);
        await WriteAsync(db, chain, other);
        await chain.SealRetiredChainsAsync(db);

        var target = Space.ToString();
        db.AuditLogs.Remove(await db.AuditLogs.SingleAsync(a => a.ActionType == AuditHashChainService.ChainSuccessionAction && a.TargetEntityId == target));
        await db.SaveChangesAsync();

        Assert.Equal(RetiredChainState.TailAltered, (await chain.CheckRetiredChainAsync(db, Space)).State);
        Assert.Empty(await chain.SealRetiredChainsAsync(db));
        Assert.Equal(1, await db.AuditLogs.CountAsync(a => a.ActionType == AuditHashChainService.ChainSuccessionAction));
        Assert.Null(await chain.PruneCutoffAsync(db, Space, DateTime.UtcNow));

        // Its seal deleted too, the chain is still not sealed afresh: the retired chains were sealed.
        db.AuditLogs.Remove(await db.AuditLogs.SingleAsync(a => a.ActionType == AuditHashChainService.ChainSealedAction && a.TenantId == Space));
        await db.SaveChangesAsync();
        Assert.Empty(await chain.SealRetiredChainsAsync(db));
        Assert.Equal(RetiredChainState.TailAltered, (await chain.CheckRetiredChainAsync(db, Space)).State);
        Assert.Equal(RetiredChainState.Sealed, (await chain.CheckRetiredChainAsync(db, other)).State);
    }

    /// <summary>
    /// A seal written by a sealing that stopped before its succession (possible before sealing was
    /// one step) is anchored as it stands while nothing has been anchored yet.
    /// </summary>
    [Fact]
    public async Task A_seal_left_unanchored_by_an_interrupted_first_sealing_is_anchored()
    {
        await using var db = Context();
        var chain = new AuditHashChainService();
        await WriteAsync(db, chain, Space);
        await chain.SealRetiredChainsAsync(db);
        var seal = await db.AuditLogs.SingleAsync(a => a.ActionType == AuditHashChainService.ChainSealedAction);
        db.AuditLogs.Remove(await db.AuditLogs.SingleAsync(a => a.ActionType == AuditHashChainService.ChainSuccessionAction));
        await db.SaveChangesAsync();

        Assert.Empty(await chain.SealRetiredChainsAsync(db));
        var succession = await db.AuditLogs.SingleAsync(a => a.ActionType == AuditHashChainService.ChainSuccessionAction);
        Assert.Contains(seal.RecordHash!, succession.DetailsJson);
        Assert.Equal(RetiredChainState.Sealed, (await chain.CheckRetiredChainAsync(db, Space)).State);
    }
}
