using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.AspNetCore.DataProtection;
using ModularCA.Core.Services.Msae.Kerberos;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Msae.Kerberos;

/// <summary>
/// Realm bindings and their keys, end to end: a key imported from a password or a keytab must
/// accept a ticket a forest actually sealed with that account's password, a rotation keeps the
/// old version through the grace window and no longer, disabled realms vanish from the acceptor,
/// and nothing that goes in ever comes back out.
/// </summary>
public class KerberosRealmServiceTests
{
    private sealed class World
    {
        public ModularCADbContext Db { get; } = InMemoryDbContextFactory.Create();
        public FixedTimeProvider Clock { get; } = new(new DateTimeOffset(2026, 9, 15, 12, 0, 0, TimeSpan.Zero));
        public KerberosRealmService Service { get; }
        public Guid TenantId { get; } = Guid.NewGuid();
        public UserEntity EnrollmentUser { get; }

        public World()
        {
            Service = new KerberosRealmService(Db, new EphemeralDataProtectionProvider(), Clock);
            Db.Tenants.Add(new TenantEntity { Id = TenantId, Name = "Customer A", Slug = "customer-a" });
            EnrollmentUser = new UserEntity { Id = Guid.NewGuid(), Username = "svc-enroll-a", Email = "svc@customer-a.example" };
            Db.Users.Add(EnrollmentUser);
            Db.SaveChanges();
        }

        public Task<KerberosRealmEntity> Bind(InProcessKdc forest, bool enabled = true)
            => Service.CreateAsync(TenantId, new KerberosRealmSpec(forest.Realm, null, InProcessKdc.ServicePrincipal, EnrollmentUser.Id, IsEnabled: enabled));

        public async Task<KerberosAcceptResult> Accept(byte[] ticket)
            => await new KerberosAcceptor(Service, new InMemoryReplayValidator()).AcceptAsync(ticket, TenantId);
    }

    /// <summary>A keytab as ktpass would write it: the SPN as principal, one entry per type.</summary>
    private static byte[] Keytab(InProcessKdc forest, int kvno, params EncryptionType[] types)
    {
        var principal = new PrincipalName(PrincipalNameType.NT_SRV_INST, forest.Realm, InProcessKdc.ServicePrincipal.Split('/'));
        var keys = types.Select(t => new KerberosKey(
            key: t == forest.ServiceKey.EncryptionType ? forest.ServiceKey.GetKey().ToArray() : new byte[t == EncryptionType.RC4_HMAC_NT ? 16 : 32],
            principal: principal, etype: t, kvno: kvno)).ToArray();
        using var ms = new MemoryStream();
        using (var writer = new BinaryWriter(ms, System.Text.Encoding.UTF8, leaveOpen: true))
            new KeyTable(keys).Write(writer);
        return ms.ToArray();
    }

    [Fact]
    public async Task A_key_derived_from_the_account_password_accepts_the_forests_tickets()
    {
        var w = new World();
        var forest = new InProcessKdc("corp.customer-a.local", servicePassword: "Svc-P@ss-Derived-9");
        forest.AddAccount("WS-042$", "Machine-P@ss-1");
        var realm = await w.Bind(forest);

        var result = await w.Service.ImportPasswordAsync(realm.Id, "svc-enroll", KerberosAccountKind.User, "Svc-P@ss-Derived-9", kvno: 2);
        Assert.Equal(2, result.Kvno);
        Assert.Equal(new[] { "AES256_CTS_HMAC_SHA1_96", "AES128_CTS_HMAC_SHA1_96" }, result.EncryptionTypes);

        var accepted = await w.Accept(await forest.ServiceTicketAsync("WS-042$", "Machine-P@ss-1"));
        Assert.True(accepted.Accepted, accepted.Refusal.ToString());
        Assert.Equal("svc-enroll-a", accepted.Caller!.Binding.EnrollmentUsername);
        Assert.Equal(w.TenantId, accepted.Caller.Binding.TenantId);

        // The wrong password derives a key that decrypts nothing.
        var other = new World();
        var otherRealm = await other.Bind(forest);
        await other.Service.ImportPasswordAsync(otherRealm.Id, "svc-enroll", KerberosAccountKind.User, "Not-The-Password", kvno: 2);
        Assert.Equal(KerberosRefusal.Invalid, (await other.Accept(await forest.ServiceTicketAsync("WS-042$", "Machine-P@ss-1"))).Refusal);
    }

    [Fact]
    public async Task A_keytab_import_keeps_the_aes_entries_for_this_realm_and_spn_only()
    {
        var w = new World();
        var forest = new InProcessKdc("corp.customer-a.local");
        forest.AddAccount("alice", "Alice-P@ss-1");
        var realm = await w.Bind(forest);

        var mixed = Keytab(forest, 5, EncryptionType.AES256_CTS_HMAC_SHA1_96, EncryptionType.RC4_HMAC_NT);
        var result = await w.Service.ImportKeytabAsync(realm.Id, mixed);
        Assert.Equal(5, result.Kvno);
        Assert.Equal(new[] { "AES256_CTS_HMAC_SHA1_96" }, result.EncryptionTypes);
        Assert.Equal(1, result.Dropped);
        Assert.True((await w.Accept(await forest.ServiceTicketAsync("alice", "Alice-P@ss-1"))).Accepted);

        var rc4Only = Keytab(forest, 6, EncryptionType.RC4_HMAC_NT);
        await Assert.ThrowsAsync<InvalidOperationException>(() => w.Service.ImportKeytabAsync(realm.Id, rc4Only));

        var otherForest = new InProcessKdc("corp.customer-b.local");
        await Assert.ThrowsAsync<InvalidOperationException>(() => w.Service.ImportKeytabAsync(realm.Id, Keytab(otherForest, 1, EncryptionType.AES256_CTS_HMAC_SHA1_96)));
        await Assert.ThrowsAsync<InvalidOperationException>(() => w.Service.ImportKeytabAsync(realm.Id, new byte[] { 9, 9, 9 }));
    }

    [Fact]
    public async Task A_rotation_keeps_the_old_version_through_the_grace_window_and_no_longer()
    {
        var w = new World();
        var forest = new InProcessKdc("corp.customer-a.local", servicePassword: "Old-P@ss-1");
        forest.AddAccount("alice", "Alice-P@ss-1");
        var realm = await w.Bind(forest);
        await w.Service.ImportPasswordAsync(realm.Id, "svc-enroll", KerberosAccountKind.User, "Old-P@ss-1", kvno: 1);

        var rotated = await w.Service.ImportPasswordAsync(realm.Id, "svc-enroll", KerberosAccountKind.User, "New-P@ss-2", kvno: 2);
        Assert.Equal(2, rotated.Retired); // both types of kvno 1

        // Still inside the grace window: a ticket under the old key is accepted.
        var ticket = await forest.ServiceTicketAsync("alice", "Alice-P@ss-1");
        Assert.True((await w.Accept(ticket)).Accepted);
        var live = await w.Service.FindAsync(forest.Realm);
        Assert.Equal(new int?[] { 2, 2, 1, 1 }, live!.Keys.Select(k => k.Version));

        // Past it: only version 2 remains, and the old ticket is refused.
        w.Clock.Now += KerberosRealmService.RotationGrace + TimeSpan.FromMinutes(1);
        live = await w.Service.FindAsync(forest.Realm);
        Assert.Equal(new int?[] { 2, 2 }, live!.Keys.Select(k => k.Version));
        Assert.Equal(KerberosRefusal.Invalid, (await w.Accept(await forest.ServiceTicketAsync("alice", "Alice-P@ss-1"))).Refusal);
        Assert.Equal(2, await w.Service.SweepRetiredKeysAsync());
    }

    [Fact]
    public async Task Retiring_a_version_by_hand_and_disabling_the_realm_both_close_the_door()
    {
        var w = new World();
        var forest = new InProcessKdc("corp.customer-a.local", servicePassword: "Svc-P@ss-1");
        forest.AddAccount("alice", "Alice-P@ss-1");
        var realm = await w.Bind(forest);
        await w.Service.ImportPasswordAsync(realm.Id, "svc-enroll", KerberosAccountKind.User, "Svc-P@ss-1", kvno: 1);
        Assert.True((await w.Accept(await forest.ServiceTicketAsync("alice", "Alice-P@ss-1"))).Accepted);

        await w.Service.RetireKeyAsync(realm.Id, 1);
        Assert.Equal(KerberosRefusal.Invalid, (await w.Accept(await forest.ServiceTicketAsync("alice", "Alice-P@ss-1"))).Refusal);
        await Assert.ThrowsAsync<KeyNotFoundException>(() => w.Service.RetireKeyAsync(realm.Id, 1));

        await w.Service.ImportPasswordAsync(realm.Id, "svc-enroll", KerberosAccountKind.User, "Svc-P@ss-1", kvno: 2);
        await w.Service.UpdateAsync(realm.Id, new KerberosRealmSpec(forest.Realm, null, InProcessKdc.ServicePrincipal, w.EnrollmentUser.Id, IsEnabled: false));
        Assert.Equal(KerberosRefusal.UnknownRealm, (await w.Accept(await forest.ServiceTicketAsync("alice", "Alice-P@ss-1"))).Refusal);
    }

    [Fact]
    public async Task A_generated_password_is_returned_once_and_the_setup_script_carries_no_secret_unless_asked()
    {
        var w = new World();
        var forest = new InProcessKdc("corp.customer-a.local");
        var realm = await w.Bind(forest);

        var (result, password) = await w.Service.GeneratePasswordAsync(realm.Id, "svc-modularca-enroll", KerberosAccountKind.User, kvno: 1);
        Assert.Equal(32, password.Length);
        Assert.Equal(1, result.Kvno);
        var stored = await w.Service.GetAsync(realm.Id);
        Assert.All(stored!.Keys, k => Assert.Equal(KerberosKeySource.Generated, k.Source));
        Assert.All(stored.Keys, k => Assert.DoesNotContain(password, k.ProtectedKey));

        var script = KerberosRealmService.SetupScript(stored, "Customer A", "https://ca4.example/msae/customer-a/cep", "svc-modularca-enroll", null);
        Assert.Contains("setspn -S HTTP/ca4.maroongang.net svc-modularca-enroll", script);
        Assert.Contains("CORP.CUSTOMER-A.LOCAL", script);
        Assert.Contains("https://ca4.example/msae/customer-a/cep", script);
        Assert.DoesNotContain(password, script);
        Assert.Contains(password, KerberosRealmService.SetupScript(stored, "Customer A", null, "svc-modularca-enroll", password));
    }

    [Fact]
    public async Task Bindings_are_validated_unique_and_protected_from_deletion_while_a_ca_relies_on_them()
    {
        var w = new World();
        var forest = new InProcessKdc("corp.customer-a.local");
        var realm = await w.Bind(forest);

        await Assert.ThrowsAsync<InvalidOperationException>(() => w.Bind(forest)); // same realm twice
        await Assert.ThrowsAsync<InvalidOperationException>(() => w.Service.CreateAsync(w.TenantId, new KerberosRealmSpec("no dots", null, "HTTP/x", w.EnrollmentUser.Id)));
        await Assert.ThrowsAsync<InvalidOperationException>(() => w.Service.CreateAsync(w.TenantId, new KerberosRealmSpec("B.LOCAL", null, "not-an-spn", w.EnrollmentUser.Id)));
        await Assert.ThrowsAsync<InvalidOperationException>(() => w.Service.CreateAsync(w.TenantId, new KerberosRealmSpec("B.LOCAL", null, "HTTP/x.example", Guid.NewGuid())));

        var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Issuing", Label = "customer-a-issuing", TenantId = w.TenantId };
        w.Db.CertificateAuthorities.Add(ca);
        w.Db.CaProtocolConfigs.Add(new CaProtocolConfigEntity { Id = Guid.NewGuid(), CaId = ca.Id, Protocol = "MSAE", IsEnabled = true, MsaeAllowKerberos = true });
        await w.Db.SaveChangesAsync();

        await Assert.ThrowsAsync<InvalidOperationException>(() => w.Service.DeleteAsync(realm.Id));

        var second = await w.Service.CreateAsync(w.TenantId, new KerberosRealmSpec("CORP.CUSTOMER-A2.LOCAL", null, "HTTP/ca4.maroongang.net", w.EnrollmentUser.Id));
        await w.Service.DeleteAsync(realm.Id); // another enabled realm now covers the CA
        Assert.Null(await w.Service.GetAsync(realm.Id));
        Assert.NotNull(await w.Service.GetAsync(second.Id));
    }
}
