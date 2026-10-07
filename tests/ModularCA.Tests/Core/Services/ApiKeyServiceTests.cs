using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Utils;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Named API keys: an integration had one key, typed by an administrator and kept in
/// <c>config.yaml</c>, so replacing it broke every client at once. Each client can now hold its
/// own, generated here, shown once and stored as a hash.
/// </summary>
public class ApiKeyServiceTests
{
    private static readonly ApiKeyActor Alice = new(Guid.NewGuid(), "alice", "203.0.113.7");

    private sealed class World
    {
        public string DatabaseName { get; } = $"apikeys-{Guid.NewGuid():N}";
        public RecordingAuditService Audit { get; } = new();
        public ModularCADbContext Db() => InMemoryDbContextFactory.Create(DatabaseName);
        public ApiKeyService Service(ModularCADbContext? db = null) => new(db ?? Db(), Audit, NullLogger<ApiKeyService>.Instance);
    }

    [Fact]
    public async Task A_key_is_returned_once_and_only_its_hash_is_kept()
    {
        var world = new World();

        var (key, plaintext) = await world.Service().CreateAsync(ApiKeyIntegrations.Infrastructure, " terraform-prod ", null, null, Alice);

        Assert.StartsWith("mca_", plaintext);
        Assert.Equal(4 + 43, plaintext.Length);
        Assert.Equal("terraform-prod", key.Name);
        Assert.Equal(plaintext[^4..], key.Hint);

        using var db = world.Db();
        var stored = await db.ApiKeys.SingleAsync();
        Assert.Equal(ApiKeyService.Hash(plaintext), stored.KeyHash);
        Assert.Equal(32, stored.KeyHash.Length);
        Assert.Equal(("alice", Alice.UserId), (stored.CreatedByName, stored.CreatedByUserId));

        var audited = Assert.Single(world.Audit.Entries);
        Assert.Equal((AuditActionType.ApiKeyCreated, key.Id.ToString()), (audited.Action, audited.TargetId));
        Assert.DoesNotContain(plaintext, System.Text.Json.JsonSerializer.Serialize(audited.Details));

        // Two keys are never the same.
        var (_, other) = await world.Service().CreateAsync(ApiKeyIntegrations.Infrastructure, "ansible", null, null, Alice);
        Assert.NotEqual(plaintext, other);
    }

    [Fact]
    public async Task A_key_opens_its_own_integration_and_no_other()
    {
        var world = new World();
        var (key, plaintext) = await world.Service().CreateAsync(ApiKeyIntegrations.Infrastructure, "terraform", null, null, Alice);

        var admitted = await world.Service().AuthenticateAsync(ApiKeyIntegrations.Infrastructure, plaintext);

        Assert.Equal(key.Id, admitted!.Id);
        Assert.Null(await world.Service().AuthenticateAsync(ApiKeyIntegrations.CertManager, plaintext));
        Assert.Null(await world.Service().AuthenticateAsync(ApiKeyIntegrations.Infrastructure, plaintext + "x"));
        Assert.Null(await world.Service().AuthenticateAsync(ApiKeyIntegrations.Infrastructure, "not-one-of-ours"));
        Assert.Null(await world.Service().AuthenticateAsync(ApiKeyIntegrations.Infrastructure, ""));
        Assert.Null(await world.Service().AuthenticateAsync(ApiKeyIntegrations.Infrastructure, null));
    }

    [Fact]
    public async Task Revoking_one_key_leaves_the_others_working()
    {
        var world = new World();
        var (terraform, terraformKey) = await world.Service().CreateAsync(ApiKeyIntegrations.Infrastructure, "terraform", null, null, Alice);
        var (_, ansibleKey) = await world.Service().CreateAsync(ApiKeyIntegrations.Infrastructure, "ansible", null, null, Alice);

        Assert.True(await world.Service().RevokeAsync(terraform.Id, Alice));

        Assert.Null(await world.Service().AuthenticateAsync(ApiKeyIntegrations.Infrastructure, terraformKey));
        Assert.NotNull(await world.Service().AuthenticateAsync(ApiKeyIntegrations.Infrastructure, ansibleKey));
        Assert.True(await world.Service().AnyWorkingAsync(ApiKeyIntegrations.Infrastructure));

        // The revoked key stays in the list, as the record of what it was.
        var listed = await world.Service().ListAsync(ApiKeyIntegrations.Infrastructure);
        Assert.Equal(2, listed.Count);
        var revoked = listed.Single(k => k.Id == terraform.Id);
        Assert.NotNull(revoked.RevokedAt);
        Assert.Equal("alice", revoked.RevokedByName);
        Assert.Contains(world.Audit.Entries, e => e.Action == AuditActionType.ApiKeyRevoked && e.TargetId == terraform.Id.ToString());

        // Revoking it again says it is revoked and writes nothing more; an unknown key is not found.
        var audits = world.Audit.Entries.Count;
        Assert.True(await world.Service().RevokeAsync(terraform.Id, Alice));
        Assert.Equal(audits, world.Audit.Entries.Count);
        Assert.False(await world.Service().RevokeAsync(Guid.NewGuid(), Alice));
    }

    [Fact]
    public async Task An_expired_key_stops_working_and_its_name_can_be_used_again()
    {
        var world = new World();
        var (key, plaintext) = await world.Service().CreateAsync(ApiKeyIntegrations.CertManager, "cluster-a", null, DateTime.UtcNow.AddDays(30), Alice);
        Assert.NotNull(await world.Service().AuthenticateAsync(ApiKeyIntegrations.CertManager, plaintext));

        using (var db = world.Db())
        {
            (await db.ApiKeys.SingleAsync(k => k.Id == key.Id)).ExpiresAt = DateTime.UtcNow.AddMinutes(-1);
            await db.SaveChangesAsync();
        }

        Assert.Null(await world.Service().AuthenticateAsync(ApiKeyIntegrations.CertManager, plaintext));
        Assert.False(await world.Service().AnyWorkingAsync(ApiKeyIntegrations.CertManager));
        await world.Service().CreateAsync(ApiKeyIntegrations.CertManager, "cluster-a", null, null, Alice);
    }

    [Fact]
    public async Task A_use_is_noted_but_not_on_every_request()
    {
        var world = new World();
        var (key, plaintext) = await world.Service().CreateAsync(ApiKeyIntegrations.Infrastructure, "terraform", null, null, Alice);

        await world.Service().AuthenticateAsync(ApiKeyIntegrations.Infrastructure, plaintext);
        DateTime first;
        using (var db = world.Db())
            first = (await db.ApiKeys.SingleAsync(k => k.Id == key.Id)).LastUsedAt!.Value;

        await world.Service().AuthenticateAsync(ApiKeyIntegrations.Infrastructure, plaintext);
        using (var db = world.Db())
            Assert.Equal(first, (await db.ApiKeys.SingleAsync(k => k.Id == key.Id)).LastUsedAt);
    }

    [Fact]
    public async Task A_key_that_cannot_be_what_was_asked_for_is_not_created()
    {
        var world = new World();
        var space = new SpaceEntity { Id = Guid.NewGuid(), Name = "Customer A" };
        using (var db = world.Db())
        {
            db.Spaces.Add(space);
            await db.SaveChangesAsync();
        }
        await world.Service().CreateAsync(ApiKeyIntegrations.Infrastructure, "terraform", null, null, Alice);

        async Task Refused(string integration, string name, string? scope, DateTime? expires, string says)
        {
            var ex = await Assert.ThrowsAsync<ApiKeyRefusedException>(() => world.Service().CreateAsync(integration, name, scope, expires, Alice));
            Assert.Contains(says, ex.Message);
        }

        await Refused("webhooks", "x", null, null, "not an integration");
        await Refused(ApiKeyIntegrations.Infrastructure, "  ", null, null, "needs a name");
        await Refused(ApiKeyIntegrations.Infrastructure, new string('n', 101), null, null, "needs a name");
        await Refused(ApiKeyIntegrations.Infrastructure, "Terraform", null, null, "already named");
        await Refused(ApiKeyIntegrations.Infrastructure, "past", null, DateTime.UtcNow.AddDays(-1), "in the past");
        await Refused(ApiKeyIntegrations.Infrastructure, "typo", "everything", null, "space id or 'instance'");
        await Refused(ApiKeyIntegrations.Infrastructure, "nowhere", Guid.NewGuid().ToString(), null, "no space");

        // The same name is free in the other integration, and a scope is stored in one spelling.
        await world.Service().CreateAsync(ApiKeyIntegrations.CertManager, "terraform", null, null, Alice);
        var (scoped, _) = await world.Service().CreateAsync(ApiKeyIntegrations.Infrastructure, "customer-a", space.Id.ToString().ToUpperInvariant(), null, Alice);
        Assert.Equal(space.Id.ToString(), scoped.SpaceScope);
        var (instance, _) = await world.Service().CreateAsync(ApiKeyIntegrations.Infrastructure, "instance-only", "INSTANCE", null, Alice);
        Assert.Equal("instance", instance.SpaceScope);
        Assert.Equal(3, (await world.Service().ListAsync(ApiKeyIntegrations.Infrastructure)).Count);
    }

    // ---- the decision both integrations' filters ask for --------------------------------------

    private static Task<IntegrationAdmission> AdmitAsync(World world, string? presented,
        bool enabled = true, string? configuredKey = null, string? integrationScope = null) =>
        world.Service().AdmitAsync(ApiKeyIntegrations.Infrastructure, enabled, configuredKey,
            IntegrationSpaceScope.Parse(integrationScope), presented);

    [Fact]
    public async Task A_named_key_admits_a_request_under_its_own_name()
    {
        var world = new World();
        var (key, plaintext) = await world.Service().CreateAsync(ApiKeyIntegrations.Infrastructure, "terraform", null, null, Alice);

        var admission = await AdmitAsync(world, plaintext);

        Assert.Equal(IntegrationAdmissionStatus.Admitted, admission.Status);
        var caller = admission.Caller!;
        Assert.Equal((key.Id, "terraform"), (caller.KeyId, caller.KeyName));
        Assert.Equal("integration:terraform", caller.Actor("integration"));
        Assert.False(caller.Scope.IsRestricted);
    }

    [Fact]
    public async Task The_key_in_the_configuration_keeps_working_beside_the_named_ones()
    {
        var world = new World();
        var (_, plaintext) = await world.Service().CreateAsync(ApiKeyIntegrations.Infrastructure, "terraform", null, null, Alice);

        var configured = await AdmitAsync(world, "the-key-in-config-yaml", configuredKey: "the-key-in-config-yaml");
        var named = await AdmitAsync(world, plaintext, configuredKey: "the-key-in-config-yaml");
        var wrong = await AdmitAsync(world, "the-key-in-config-yamL", configuredKey: "the-key-in-config-yaml");

        Assert.Equal(IntegrationAdmissionStatus.Admitted, configured.Status);
        Assert.Null(configured.Caller!.KeyName);
        Assert.Equal("integration", configured.Caller.Actor("integration"));
        Assert.Equal("terraform", named.Caller!.KeyName);
        Assert.Equal(IntegrationAdmissionStatus.InvalidKey, wrong.Status);
        Assert.Null(wrong.Caller);
    }

    [Fact]
    public async Task The_gate_says_why_a_request_is_turned_away()
    {
        var world = new World();

        Assert.Equal(IntegrationAdmissionStatus.Disabled, (await AdmitAsync(world, "anything", enabled: false, configuredKey: "k")).Status);
        // Switched on with no key at all, in the configuration or named.
        Assert.Equal(IntegrationAdmissionStatus.Unconfigured, (await AdmitAsync(world, "anything")).Status);

        var (terraform, plaintext) = await world.Service().CreateAsync(ApiKeyIntegrations.Infrastructure, "terraform", null, null, Alice);
        Assert.Equal(IntegrationAdmissionStatus.MissingKey, (await AdmitAsync(world, null)).Status);
        Assert.Equal(IntegrationAdmissionStatus.MissingKey, (await AdmitAsync(world, " ")).Status);
        Assert.Equal(IntegrationAdmissionStatus.InvalidKey, (await AdmitAsync(world, "mca_not-a-key-anyone-was-given")).Status);

        await world.Service().RevokeAsync(terraform.Id, Alice);
        // The only key is revoked: the integration is back to having none.
        Assert.Equal(IntegrationAdmissionStatus.Unconfigured, (await AdmitAsync(world, plaintext)).Status);
        Assert.Equal(IntegrationAdmissionStatus.InvalidKey, (await AdmitAsync(world, plaintext, configuredKey: "another")).Status);
    }

    [Fact]
    public async Task A_keys_scope_narrows_the_integrations_and_never_widens_it()
    {
        var world = new World();
        var spaceA = new SpaceEntity { Id = Guid.NewGuid(), Name = "Customer A" };
        var spaceB = new SpaceEntity { Id = Guid.NewGuid(), Name = "Customer B" };
        using (var db = world.Db())
        {
            db.Spaces.AddRange(spaceA, spaceB);
            await db.SaveChangesAsync();
        }
        var (_, forA) = await world.Service().CreateAsync(ApiKeyIntegrations.Infrastructure, "customer-a", spaceA.Id.ToString(), null, Alice);
        var (_, unscoped) = await world.Service().CreateAsync(ApiKeyIntegrations.Infrastructure, "everything", null, null, Alice);

        // An unrestricted integration: the key's own scope applies.
        var narrowed = (await AdmitAsync(world, forA)).Caller!;
        Assert.True(narrowed.Scope.Allows(spaceA.Id));
        Assert.False(narrowed.Scope.Allows(spaceB.Id));
        Assert.False(narrowed.Scope.Allows(null));

        // An integration limited to A: a key for A works, and a key with no scope gets A.
        Assert.Equal(IntegrationAdmissionStatus.Admitted, (await AdmitAsync(world, forA, integrationScope: spaceA.Id.ToString())).Status);
        var inherited = (await AdmitAsync(world, unscoped, integrationScope: spaceA.Id.ToString())).Caller!;
        Assert.True(inherited.Scope.Allows(spaceA.Id));
        Assert.False(inherited.Scope.Allows(spaceB.Id));

        // An integration limited to B: the key for A has nowhere it may reach.
        var outside = await AdmitAsync(world, forA, integrationScope: spaceB.Id.ToString());
        Assert.Equal(IntegrationAdmissionStatus.OutOfScope, outside.Status);
        Assert.Null(outside.Caller);
        Assert.Contains("outside what the integration is allowed", outside.Detail);
    }
}
