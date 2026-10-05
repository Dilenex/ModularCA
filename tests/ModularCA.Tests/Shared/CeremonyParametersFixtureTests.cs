using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Models;
using ModularCA.Tests.TestUtils;
using Xunit;
using F = ModularCA.Tests.Shared.CeremonyParametersFixtures;

namespace ModularCA.Tests.Shared;

/// <summary>
/// The stored ceremony parameter shapes in <see cref="CeremonyParametersFixtures"/>: each is what
/// its production writer emits today, and each reads back through the production read paths with
/// its space ids preserved. A null space means the instance, so a space id lost on read widens
/// the ceremony's scope; a pre-0.4.0 shape therefore fails closed instead of reading.
/// </summary>
public class CeremonyParametersFixtureTests
{
    public static TheoryData<string, string> Written() => new()
    {
        { F.ControlledUserChange, F.Writers.ControlledUserChange() },
        { F.KeyCeremony, F.Writers.KeyCeremony() },
        { F.SshKeyCeremony, F.Writers.SshKeyCeremony() },
        { F.RevokeCa, F.Writers.RevokeCa() },
        { F.SpacePolicyChange, F.Writers.SpacePolicyChange() },
        { F.InstancePolicyChange, F.Writers.InstancePolicyChange() },
        { F.CaUserQuorumChange, F.Writers.CaUserQuorumChange() },
    };

    [Theory]
    [MemberData(nameof(Written))]
    public void Each_fixture_is_what_its_writer_emits(string fixture, string written) => Assert.Equal(fixture, written);

    public static TheoryData<string, Type> LegacyShapes() => new()
    {
        { F.Legacy.ControlledUserChange, typeof(ControlledUserChangeParameters) },
        { F.Legacy.KeyCeremony, typeof(KeyCeremonyParameters) },
        { F.Legacy.SshKeyCeremony, typeof(SshKeyCeremonyParameters) },
        { F.Legacy.RevokeCa, typeof(RevokeCaCeremonyParameters) },
        { F.Legacy.TenantPolicyChange, typeof(SpacePolicyChangeCeremonyParameters) },
        { F.Legacy.InstancePolicyChange, typeof(SpacePolicyChangeCeremonyParameters) },
        { F.Legacy.CaUserQuorumChange, typeof(SpacePolicyChangeCeremonyParameters) },
    };

    /// <summary>A shape the migration did not rename throws on every read path rather than reading as the instance.</summary>
    [Theory]
    [MemberData(nameof(LegacyShapes))]
    public void A_legacy_shape_fails_closed_on_read(string legacy, Type type)
    {
        var read = typeof(CeremonyParametersJson).GetMethod(nameof(CeremonyParametersJson.Read))!.MakeGenericMethod(type);
        var thrown = Assert.Throws<System.Reflection.TargetInvocationException>(() => read.Invoke(null, [legacy]));
        Assert.IsAssignableFrom<System.Text.Json.JsonException>(thrown.InnerException);
        Assert.Throws<System.Text.Json.JsonException>(() => CeremonyParametersJson.ReadSpaceId(legacy));
    }

    [Theory]
    [InlineData("""{"TENANTID":"6d1f3c2a-4b5e-4f60-8a71-0b2c3d4e5f60"}""")]
    [InlineData("""{"tenantid":null}""")]
    [InlineData("""{"SpaceId":null,"mintedTierTenantId":"6d1f3c2a-4b5e-4f60-8a71-0b2c3d4e5f60"}""")]
    public void A_legacy_key_in_any_case_fails_closed(string json)
    {
        var ex = Assert.Throws<System.Text.Json.JsonException>(() => CeremonyParametersJson.Read<ControlledUserChangeParameters>(json));
        Assert.Contains("RenameTenantToSpace", ex.Message);
    }

    /// <summary>
    /// The migration's key map (<c>TenantId</c>, <c>MintedTierTenantId</c>, any case, to the space
    /// name in the casing of its first letter) turns each legacy shape into its 0.4.0 shape, up to
    /// key order, which jsonb does not keep.
    /// </summary>
    [Theory]
    [MemberData(nameof(F.LegacyAndCurrent), MemberType = typeof(F))]
    public void The_migrations_key_map_turns_each_legacy_shape_into_its_current_one(string legacy, string current)
    {
        var renamed = new System.Text.Json.Nodes.JsonObject();
        foreach (var (key, value) in System.Text.Json.Nodes.JsonNode.Parse(legacy)!.AsObject())
        {
            var camel = char.IsLower(key[0]);
            var name = key.ToLowerInvariant() switch
            {
                "tenantid" => camel ? "spaceId" : "SpaceId",
                "mintedtiertenantid" => camel ? "mintedTierSpaceId" : "MintedTierSpaceId",
                _ => key,
            };
            renamed[name] = value?.DeepClone();
        }
        Assert.True(System.Text.Json.Nodes.JsonNode.DeepEquals(renamed, System.Text.Json.Nodes.JsonNode.Parse(current)));
    }

    /// <summary>
    /// The SSH shape's null <c>KeySize</c> does not bind to <see cref="KeyCeremonyParameters"/>, so
    /// its scope is read through <see cref="CeremonyParametersJson.ReadSpaceId"/>, which binds only the space.
    /// </summary>
    [Fact]
    public void The_ssh_shape_with_a_null_key_size_reads_its_space()
    {
        Assert.Equal(F.SpaceA, CeremonyParametersJson.ReadSpaceId(F.SshKeyCeremony));
        Assert.Throws<System.Text.Json.JsonException>(() => CeremonyParametersJson.Read<KeyCeremonyParameters>(F.SshKeyCeremony));
    }

    [Theory]
    [MemberData(nameof(Initiated))]
    public void Every_current_shape_reads_its_space(string operation, string fixture, Guid? expected)
    {
        _ = operation;
        Assert.Equal(expected, CeremonyParametersJson.ReadSpaceId(fixture));
    }

    [Fact]
    public void A_controlled_user_change_keeps_both_space_ids()
    {
        var p = CeremonyParametersJson.Read<ControlledUserChangeParameters>(F.ControlledUserChange)!;
        Assert.Equal(F.SpaceA, p.SpaceId);
        Assert.Equal(F.SpaceB, p.MintedTierSpaceId);
        Assert.Equal(F.CaA, p.CertificateAuthorityId);
        Assert.Equal(6, p.MintedTierLevel);
        Assert.Equal(F.User, Assert.Single(p.CredentialSnapshots!).UserId);
    }

    [Fact]
    public void A_ca_ceremony_keeps_its_space()
    {
        var p = CeremonyParametersJson.Read<KeyCeremonyParameters>(F.KeyCeremony)!;
        Assert.Equal(F.SpaceA, p.SpaceId);
        Assert.Equal(F.ParentCa, p.ParentCaId);
        Assert.Equal("acme-issuing", p.Label);
    }

    [Fact]
    public void An_ssh_ceremony_keeps_its_space()
    {
        var p = CeremonyParametersJson.Read<SshKeyCeremonyParameters>(F.SshKeyCeremony)!;
        Assert.Equal(F.SpaceA, p.SpaceId);
        Assert.Equal(F.SshKey, p.SshCaKeyId);
    }

    [Fact]
    public void A_camel_case_revocation_keeps_its_space()
    {
        var p = CeremonyParametersJson.Read<RevokeCaCeremonyParameters>(F.RevokeCa)!;
        Assert.Equal(F.SpaceA, p.SpaceId);
        Assert.Equal(F.Certificate, p.CertificateId);
        Assert.Equal("KeyCompromise", p.Reason);
    }

    [Theory]
    [InlineData(F.SpacePolicyChange, true)]
    [InlineData(F.CaUserQuorumChange, true)]
    [InlineData(F.InstancePolicyChange, false)]
    public void A_policy_change_keeps_its_scope_and_ca_quorums(string fixture, bool space)
    {
        var p = CeremonyParametersJson.Read<SpacePolicyChangeCeremonyParameters>(fixture)!;
        Assert.Equal(space ? F.SpaceA : null, p.SpaceId);
        Assert.Equal(space ? F.CaA : F.InstanceCa, Assert.Single(p.CaUserQuorums).CaId);
    }

    public static TheoryData<string, string, Guid?> Initiated() => new()
    {
        { "ControlledUserChange", F.ControlledUserChange, F.SpaceA },
        { "CreateIntermediateCA", F.KeyCeremony, F.SpaceA },
        { "CreateSshCa", F.SshKeyCeremony, F.SpaceA },
        { "DeleteSshCa", F.SshKeyCeremony, F.SpaceA },
        { "RevokeCa", F.RevokeCa, F.SpaceA },
        { "SpacePolicyChange", F.SpacePolicyChange, F.SpaceA },
        { "SpacePolicyChange", F.CaUserQuorumChange, F.SpaceA },
        { "InstancePolicyChange", F.InstancePolicyChange, null },
    };

    /// <summary><see cref="KeyCeremonyService.InitiateAsync"/> refuses a legacy shape and records no ceremony.</summary>
    [Theory]
    [MemberData(nameof(LegacyShapes))]
    public async Task Initiation_refuses_a_legacy_shape(string legacy, Type type)
    {
        _ = type;
        using var db = InMemoryDbContextFactory.Create();
        await Assert.ThrowsAsync<System.Text.Json.JsonException>(() => new KeyCeremonyService(db, new RecordingAuditService(), quorumGuard: new OpenQuorumGuard())
            .InitiateAsync("RevokeCa", "x", "", F.Admin, "carol", legacy));
        Assert.Empty(db.KeyCeremonies);
    }

    /// <summary><see cref="KeyCeremonyService.InitiateAsync"/> stamps the ceremony's space from the stored parameters, in either casing.</summary>
    [Theory]
    [MemberData(nameof(Initiated))]
    public async Task Initiation_stamps_the_space_the_parameters_name(string operation, string fixture, Guid? expected)
    {
        using var db = InMemoryDbContextFactory.Create();
        db.SecurityPolicies.Add(new SecurityPolicyEntity { CeremonyRequiredApprovals = 3 });
        db.Spaces.Add(new SpaceEntity { Id = F.SpaceA, Name = "Acme", Slug = "acme", CeremonyRequiredApprovals = 2 });
        await db.SaveChangesAsync();

        var ceremony = await new KeyCeremonyService(db, new RecordingAuditService(), quorumGuard: new OpenQuorumGuard())
            .InitiateAsync(operation, "x", "", F.Admin, "carol", fixture);

        Assert.Equal(expected, ceremony.SpaceId);
        Assert.Equal(fixture, ceremony.ParametersJson);
    }

    public static TheoryData<string, CeremonyType> Applied() => new()
    {
        { F.SpacePolicyChange, CeremonyType.SpacePolicyChange },
        { F.CaUserQuorumChange, CeremonyType.SpacePolicyChange },
        { F.InstancePolicyChange, CeremonyType.InstancePolicyChange },
    };

    /// <summary><see cref="SpacePolicyChangeService.ApplyApprovedChangeAsync"/> applies each stored policy change to the scope it names.</summary>
    [Theory]
    [MemberData(nameof(Applied))]
    public async Task An_approved_policy_change_applies_to_the_scope_its_parameters_name(string fixture, CeremonyType type)
    {
        var name = $"fixture-{Guid.NewGuid():N}";
        using var db = InMemoryDbContextFactory.Create(name);
        var expected = CeremonyParametersJson.Read<SpacePolicyChangeCeremonyParameters>(fixture)!;
        var quorum = Assert.Single(expected.CaUserQuorums);
        db.SecurityPolicies.Add(new SecurityPolicyEntity
        {
            RequireKeyCeremony = expected.CurrentRequireKeyCeremony,
            CeremonyRequiredApprovals = expected.CurrentCeremonyRequiredApprovals,
            UserCeremonyRequiredApprovals = expected.CurrentUserQuorum,
        });
        db.Spaces.Add(new SpaceEntity
        {
            Id = F.SpaceA, Name = "Acme", Slug = "acme",
            RequireKeyCeremony = expected.CurrentRequireKeyCeremony,
            CeremonyRequiredApprovals = expected.CurrentCeremonyRequiredApprovals,
            UserCeremonyRequiredApprovals = expected.CurrentUserQuorum,
        });
        db.CertificateAuthorities.Add(new CertificateAuthorityEntity
        {
            Id = quorum.CaId, Name = "CA", Label = "ca", SpaceId = expected.SpaceId,
            UserCeremonyRequiredApprovals = quorum.CurrentQuorum,
        });
        var ceremony = new KeyCeremonyEntity
        {
            OperationType = type.ToString(), CeremonyType = type, Status = "Approved",
            ParametersJson = fixture, ExpiresAt = DateTime.UtcNow.AddHours(1),
        };
        db.KeyCeremonies.Add(ceremony);
        await db.SaveChangesAsync();
        var changes = new SpacePolicyChangeService(db, new KeyCeremonyService(db, new RecordingAuditService(), quorumGuard: new OpenQuorumGuard()),
            NullLogger<SpacePolicyChangeService>.Instance);

        var result = await changes.ApplyApprovedChangeAsync(ceremony.Id);

        Assert.Equal(expected.SpaceId, result.SpaceId);
        using var check = InMemoryDbContextFactory.Create(name);
        Assert.Equal(quorum.ProposedQuorum, (await check.CertificateAuthorities.SingleAsync()).UserCeremonyRequiredApprovals);
        var approvals = expected.ProposedCeremonyRequiredApprovals ?? expected.CurrentCeremonyRequiredApprovals;
        if (expected.SpaceId is null)
        {
            Assert.Equal(approvals, (await check.SecurityPolicies.SingleAsync()).CeremonyRequiredApprovals);
            Assert.Equal(expected.CurrentCeremonyRequiredApprovals, (await check.Spaces.SingleAsync()).CeremonyRequiredApprovals);
        }
        else
        {
            Assert.Equal(approvals, (await check.Spaces.SingleAsync()).CeremonyRequiredApprovals);
            Assert.Equal(expected.CurrentCeremonyRequiredApprovals, (await check.SecurityPolicies.SingleAsync()).CeremonyRequiredApprovals);
        }
    }
}
