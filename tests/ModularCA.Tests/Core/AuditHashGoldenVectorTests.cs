using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Licensing;
using Xunit;

namespace ModularCA.Tests.Core;

/// <summary>
/// The audit hash's canonical input and the strings that recorded audit rows carry, pinned by
/// value. Every stored record was hashed from these, so a rename that reaches any of them breaks
/// every chain written before it. The hex values were captured from
/// <see cref="AuditHashChainService.ComputeHash"/> and cross-checked by an independent SHA-256 of
/// the documented pipe-joined form.
/// </summary>
public class AuditHashGoldenVectorTests
{
    private static AuditLogEntity Record(Guid? tenantId, Guid? caId) => new()
    {
        Id = Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e"),
        Timestamp = new DateTime(2026, 9, 30, 14, 15, 16, DateTimeKind.Utc).AddTicks(1234567),
        ActorUserId = Guid.Parse("7c9e6679-7425-40de-944b-e07fc1f90ae7"),
        ActorUsername = "alice",
        ActionType = "CertificateIssued",
        TargetEntityType = "Certificate",
        TargetEntityId = "5f3b2a1c-0000-4000-8000-000000000001",
        DetailsJson = """{"serial":"0A1B","profile":"TLS Server"}""",
        SourceIp = "192.0.2.44",
        Success = true,
        ErrorMessage = "none",
        CertificateAuthorityId = caId,
        TenantId = tenantId,
        AccessBadgeId = Guid.Parse("11111111-2222-4333-8444-555555555555"),
        AccessBadgeName = "Night shift",
        HashVersion = 2,
    };

    private static readonly Guid Tenant = Guid.Parse("3d2c1b0a-9f8e-4d7c-b6a5-948372615a40");
    private static readonly Guid Ca = Guid.Parse("9b2e4f8a-1c3d-4e5f-8a7b-6c5d4e3f2a1b");

    private const string GenesisHash = "8337b6606a173d3465a2a91bf7e2e56c76b7aa3d1678876bcbb2311c1740bfe0";
    private const string ChainedHash = "e835d003ed7f3b126b18ffdc6610eaffe4c0310edb75195f67ecd76b309a2cab";
    private const string InstanceHash = "c79815e244fffd35689ecfa2949845fe2fc093f6e15a74046a8dd4e7110b5299";

    [Fact]
    public void A_tenant_record_at_the_head_of_its_chain_hashes_to_the_golden_value()
    {
        Assert.Equal(2, AuditHashChainService.CurrentHashVersion);
        Assert.Equal(GenesisHash, AuditHashChainService.ComputeHash(Record(Tenant, Ca), null));
    }

    [Fact]
    public void A_chained_record_hashes_to_the_golden_value()
    {
        Assert.Equal(ChainedHash, AuditHashChainService.ComputeHash(Record(Tenant, Ca), GenesisHash));
    }

    [Fact]
    public void A_record_with_no_tenant_or_ca_hashes_them_as_empty_fields()
    {
        Assert.Equal(InstanceHash, AuditHashChainService.ComputeHash(Record(null, null), null));
    }

    [Fact]
    public void Fields_outside_the_canonical_form_do_not_change_the_hash()
    {
        var record = Record(Tenant, Ca);
        record.AccessBadgeId = null;
        record.AccessBadgeName = null;
        record.RecordHash = "x";
        record.PreviousRecordHash = "y";
        Assert.Equal(GenesisHash, AuditHashChainService.ComputeHash(record, null));
    }

    [Fact]
    public void The_chain_record_strings_are_pinned()
    {
        Assert.Equal("AuditChainRestarted", AuditHashChainService.ChainRestartAction);
        Assert.Equal("AuditChainPruned", AuditHashChainService.ChainPrunedAction);
        Assert.Equal("AuditChainSealed", AuditHashChainService.ChainSealedAction);
        Assert.Equal("AuditChainSuccession", AuditHashChainService.ChainSuccessionAction);
        Assert.Equal("system", AuditHashChainService.SystemActor);
        Assert.Equal("20260929051025_FoldSystemTenant", AuditHashChainService.FoldMigrationId);
    }

    [Fact]
    public async Task The_instance_chain_lock_key_and_target_type_are_pinned()
    {
        await using var db = Context();
        var marker = await new AuditHashChainService().RestartChainAsync(db, null, null, "system", "pin");
        Assert.Equal("__system__", marker.TargetEntityId);
        Assert.Equal("AuditChain", marker.TargetEntityType);
    }

    [Fact]
    public async Task The_seal_and_succession_details_are_pinned_by_value_and_member_name()
    {
        await using var db = Context();
        var chain = new AuditHashChainService();
        await chain.AppendAsync(db, new AuditLogEntity { ActionType = "Issued", ActorUsername = "admin", Success = true, TenantId = Tenant });
        await chain.SealRetiredChainsAsync(db);

        var seal = await db.AuditLogs.SingleAsync(a => a.ActionType == AuditHashChainService.ChainSealedAction);
        Assert.Equal("AuditChain", seal.TargetEntityType);
        Assert.Equal(Tenant.ToString(), seal.TargetEntityId);
        using var sealJson = JsonDocument.Parse(seal.DetailsJson!);
        Assert.Equal(["Reason", "Migration", "FinalRecordId", "FinalRecordHash"], sealJson.RootElement.EnumerateObject().Select(p => p.Name));
        Assert.Equal(
            "Release 0.4.0 folded the tenants' audit chains into the single instance chain. "
            + "This chain is retired; its records stay as recorded and verify as an earlier epoch.",
            sealJson.RootElement.GetProperty("Reason").GetString());
        Assert.Equal("20260929051025_FoldSystemTenant", sealJson.RootElement.GetProperty("Migration").GetString());

        var succession = await db.AuditLogs.SingleAsync(a => a.ActionType == AuditHashChainService.ChainSuccessionAction);
        using var successionJson = JsonDocument.Parse(succession.DetailsJson!);
        Assert.Equal(["Reason", "Migration", "SealedChain", "SealRecordId", "SealRecordHash", "SealTimestamp"],
            successionJson.RootElement.EnumerateObject().Select(p => p.Name));

        var prune = await chain.RecordPruneAsync(db, Tenant, DateTime.UtcNow.AddYears(-1));
        using var pruneJson = JsonDocument.Parse(prune.DetailsJson!);
        Assert.Equal(["Reason", "Cutoff", "AnchorRecordId", "AnchorPreviousHash"], pruneJson.RootElement.EnumerateObject().Select(p => p.Name));
    }

    [Fact]
    public void Retired_audit_action_types_keep_their_recorded_values()
    {
        Assert.Equal("TenantCreated", AuditActionType.TenantCreated);
        Assert.Equal("TenantUpdated", AuditActionType.TenantUpdated);
        Assert.Equal("TenantDisabled", AuditActionType.TenantDisabled);
        Assert.Equal("TenantPolicyChangeApplied", AuditActionType.TenantPolicyChangeApplied);
        Assert.Equal("TenantHostnameCreated", AuditActionType.TenantHostnameCreated);
        Assert.Equal("TenantHostnameDeleted", AuditActionType.TenantHostnameDeleted);
        Assert.Equal("TenantHostnameCertificateIssued", AuditActionType.TenantHostnameCertificateIssued);
        Assert.Equal("TenantHostnameUpstreamChanged", AuditActionType.TenantHostnameUpstreamChanged);
    }

    [Fact]
    public void Licence_keys_signed_into_issued_licences_are_pinned()
    {
        Assert.Equal("tenancy.multi", FeatureKeys.MultiTenancy);
        Assert.Equal("maxTenants", LicenseLimits.MaxTenants);
    }

    [Fact]
    public void Signer_audit_scope_tokens_are_pinned()
    {
        Assert.Equal("tenant", SignerAuditEntity.TenantScope);
        Assert.Equal("instance", SignerAuditEntity.InstanceScope);
        Assert.Equal("none", SignerAuditEntity.NoScope);
    }

    private static AuditDbContext Context() =>
        new(new DbContextOptionsBuilder<AuditDbContext>()
            .UseInMemoryDatabase($"golden-{Guid.NewGuid():N}")
            .Options);
}
