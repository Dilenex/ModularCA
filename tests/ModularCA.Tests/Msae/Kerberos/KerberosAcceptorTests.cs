using Kerberos.NET.Crypto;
using ModularCA.Core.Services.Msae.Kerberos;
using Xunit;

namespace ModularCA.Tests.Msae.Kerberos;

/// <summary>
/// The acceptor takes real tickets from in-process forests and proves the isolation rule: a
/// ticket is accepted only for the tenant its realm is bound to, only when it names the bound
/// service principal, only once, and only with that realm's own key. Nothing here touches the
/// operating system's Kerberos stack.
/// </summary>
public class KerberosAcceptorTests
{
    private static readonly Guid TenantA = Guid.NewGuid();
    private static readonly Guid TenantB = Guid.NewGuid();
    private static readonly Guid EnrollmentUser = Guid.NewGuid();

    private sealed class Realms : IKerberosRealmKeyProvider
    {
        private readonly Dictionary<string, KerberosRealmKeys> _map = new(StringComparer.OrdinalIgnoreCase);

        public Realms Bind(InProcessKdc forest, Guid tenantId, bool machines = true, bool users = true, string? spn = null, params KerberosKey[] keys)
        {
            _map[forest.Realm] = new KerberosRealmKeys(forest.Realm, tenantId, spn ?? InProcessKdc.ServicePrincipal, forest.DnsDomain, EnrollmentUser, "svc-enroll-user",
                machines, users, keys.Length > 0 ? keys : new[] { forest.ServiceKey });
            return this;
        }

        public Task<KerberosRealmKeys?> FindAsync(string realm, CancellationToken cancellation = default)
            => Task.FromResult(_map.TryGetValue(realm, out var r) ? r : null);
    }

    private static KerberosAcceptor Acceptor(IKerberosRealmKeyProvider realms) => new(realms, new InMemoryReplayValidator());

    [Fact]
    public async Task A_ticket_from_a_bound_forest_is_accepted_for_its_tenant_and_names_the_caller()
    {
        var forest = new InProcessKdc("corp.customer-a.local");
        forest.AddAccount("alice", "Alice-P@ss-1");
        forest.AddAccount("WS-042$", "Machine-P@ss-1");
        var acceptor = Acceptor(new Realms().Bind(forest, TenantA));

        var user = await acceptor.AcceptAsync(await forest.ServiceTicketAsync("alice", "Alice-P@ss-1"), TenantA);
        Assert.True(user.Accepted, user.Refusal.ToString());
        Assert.Equal("alice", user.Caller!.Principal);
        Assert.Equal("CORP.CUSTOMER-A.LOCAL", user.Caller.Realm);
        Assert.False(user.Caller.IsMachine);
        Assert.Equal("alice@corp.customer-a.local", user.Caller.Upn);
        Assert.Null(user.Caller.DnsHostName);
        Assert.False(user.Caller.ApRep.IsEmpty);

        var machine = await acceptor.AcceptAsync(await forest.ServiceTicketAsync("WS-042$", "Machine-P@ss-1"), TenantA);
        Assert.True(machine.Accepted, machine.Refusal.ToString());
        Assert.True(machine.Caller!.IsMachine);
        Assert.Equal("ws-042.corp.customer-a.local", machine.Caller.DnsHostName);
        Assert.Equal("WS-042$@CORP.CUSTOMER-A.LOCAL", machine.Caller.FullName);
    }

    [Fact]
    public async Task A_valid_ticket_is_refused_for_another_tenants_ca_before_any_key_is_used()
    {
        var forest = new InProcessKdc("corp.customer-a.local");
        forest.AddAccount("alice", "Alice-P@ss-1");
        var acceptor = Acceptor(new Realms().Bind(forest, TenantA));

        var result = await acceptor.AcceptAsync(await forest.ServiceTicketAsync("alice", "Alice-P@ss-1"), TenantB);

        Assert.False(result.Accepted);
        Assert.Equal(KerberosRefusal.WrongTenant, result.Refusal);
        Assert.Equal("CORP.CUSTOMER-A.LOCAL", result.Realm);
        Assert.Equal(InProcessKdc.ServicePrincipal, result.ServicePrincipal);
    }

    [Fact]
    public async Task An_unbound_realm_and_an_unexpected_service_principal_are_refused()
    {
        var forest = new InProcessKdc("corp.customer-a.local");
        forest.AddAccount("alice", "Alice-P@ss-1");
        var ticket = await forest.ServiceTicketAsync("alice", "Alice-P@ss-1");

        var unbound = await Acceptor(new Realms()).AcceptAsync(ticket, TenantA);
        Assert.Equal(KerberosRefusal.UnknownRealm, unbound.Refusal);

        var otherSpn = await Acceptor(new Realms().Bind(forest, TenantA, spn: "HTTP/other.example")).AcceptAsync(ticket, TenantA);
        Assert.Equal(KerberosRefusal.WrongServicePrincipal, otherSpn.Refusal);
    }

    [Fact]
    public async Task Only_the_realms_own_key_decrypts_and_a_replay_is_refused()
    {
        var forestA = new InProcessKdc("corp.customer-a.local");
        var forestB = new InProcessKdc("corp.customer-b.local", servicePassword: "Different-P@ss-2");
        forestA.AddAccount("alice", "Alice-P@ss-1");
        var ticket = await forestA.ServiceTicketAsync("alice", "Alice-P@ss-1");

        // Realm A bound, but with forest B's key: the wrong key must not decrypt.
        var wrongKey = await Acceptor(new Realms().Bind(forestA, TenantA, keys: forestB.ServiceKey)).AcceptAsync(ticket, TenantA);
        Assert.Equal(KerberosRefusal.Invalid, wrongKey.Refusal);

        // Right key, twice: the second presentation of the same authenticator is a replay.
        var acceptor = Acceptor(new Realms().Bind(forestA, TenantA));
        Assert.True((await acceptor.AcceptAsync(ticket, TenantA)).Accepted);
        Assert.Equal(KerberosRefusal.Invalid, (await acceptor.AcceptAsync(ticket, TenantA)).Refusal);
    }

    [Fact]
    public async Task A_rotated_key_is_accepted_alongside_the_old_one_and_kinds_can_be_disallowed()
    {
        var forest = new InProcessKdc("corp.customer-a.local");
        forest.AddAccount("WS-042$", "Machine-P@ss-1");
        var ticket = await forest.ServiceTicketAsync("WS-042$", "Machine-P@ss-1");
        var unrelated = new InProcessKdc("corp.customer-a.local", servicePassword: "Next-P@ss-3").ServiceKey;

        // Newest first, old key still present: the ticket sealed under the old key is accepted.
        var rotated = await Acceptor(new Realms().Bind(forest, TenantA, keys: new[] { unrelated, forest.ServiceKey })).AcceptAsync(ticket, TenantA);
        Assert.True(rotated.Accepted, rotated.Refusal.ToString());

        var noMachines = await Acceptor(new Realms().Bind(forest, TenantA, machines: false)).AcceptAsync(await forest.ServiceTicketAsync("WS-042$", "Machine-P@ss-1"), TenantA);
        Assert.Equal(KerberosRefusal.PrincipalKindNotAllowed, noMachines.Refusal);
    }

    [Fact]
    public async Task Garbage_is_malformed_not_an_exception()
    {
        var result = await Acceptor(new Realms()).AcceptAsync(new byte[] { 1, 2, 3, 4 }, TenantA);
        Assert.Equal(KerberosRefusal.Malformed, result.Refusal);
    }
}
