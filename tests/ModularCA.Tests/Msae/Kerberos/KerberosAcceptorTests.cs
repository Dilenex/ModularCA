using System.Security.Cryptography;
using Kerberos.NET;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
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
    public async Task Keys_of_another_encryption_type_are_not_tried_and_the_detail_says_so()
    {
        var forest = new InProcessKdc("corp.customer-a.local");
        forest.AddAccount("alice", "Alice-P@ss-1");
        var ticket = await forest.ServiceTicketAsync("alice", "Alice-P@ss-1");   // sealed with AES256
        var name = new PrincipalName(PrincipalNameType.NT_PRINCIPAL, forest.Realm, new[] { "svc-enroll" });
        var aes128 = new KerberosKey("Other-P@ss-9", name, etype: EncryptionType.AES128_CTS_HMAC_SHA1_96, saltType: SaltType.ActiveDirectoryUser);
        var wrongAes256 = new KerberosKey("Other-P@ss-9", name, etype: EncryptionType.AES256_CTS_HMAC_SHA1_96, saltType: SaltType.ActiveDirectoryUser);

        // A wrong AES256 key is attempted and reported; the AES128 key is counted, not attempted.
        var mixed = await Acceptor(new Realms().Bind(forest, TenantA, keys: new[] { aes128, wrongAes256 })).AcceptAsync(ticket, TenantA);
        Assert.Equal(KerberosRefusal.Invalid, mixed.Refusal);
        Assert.Contains("ticket kvno", mixed.Detail);
        Assert.Contains("AES256_CTS_HMAC_SHA1_96: SecurityException", mixed.Detail);
        Assert.Contains("1 key(s) of other types not tried", mixed.Detail);
        Assert.DoesNotContain("must match the encrypted data", mixed.Detail);

        // Only keys of the wrong type: nothing is attempted and the detail names the gap.
        var none = await Acceptor(new Realms().Bind(forest, TenantA, keys: aes128)).AcceptAsync(await forest.ServiceTicketAsync("alice", "Alice-P@ss-1"), TenantA);
        Assert.Equal(KerberosRefusal.Invalid, none.Refusal);
        Assert.Contains("none of the 1 live keys is AES256_CTS_HMAC_SHA1_96", none.Detail);

        // The right key among wrong-typed ones still wins.
        var right = await Acceptor(new Realms().Bind(forest, TenantA, keys: new[] { aes128, forest.ServiceKey })).AcceptAsync(await forest.ServiceTicketAsync("alice", "Alice-P@ss-1"), TenantA);
        Assert.True(right.Accepted, right.Detail);
    }

    [Fact]
    public async Task Garbage_is_malformed_not_an_exception()
    {
        var result = await Acceptor(new Realms()).AcceptAsync(new byte[] { 1, 2, 3, 4 }, TenantA);
        Assert.Equal(KerberosRefusal.Malformed, result.Refusal);
    }

    [Fact]
    public async Task The_client_can_verify_our_mutual_authentication_token()
    {
        var forest = new InProcessKdc("corp.customer-a.local");
        forest.AddAccount("WS-042$", "Machine-P@ss-1");
        var acceptor = Acceptor(new Realms().Bind(forest, TenantA));
        var (token, clientContext) = await forest.ServiceTicketContextAsync("WS-042$", "Machine-P@ss-1");

        var result = await acceptor.AcceptAsync(token, TenantA);
        Assert.True(result.Accepted, result.Refusal.ToString());
        var mutual = result.Caller!.MutualAuthToken;
        Assert.False(mutual.IsEmpty);

        // The raw AP-REP verifies against the client's session key: the server proved it holds the service key.
        var sessionKey = clientContext.AuthenticateServiceResponse(result.Caller.ApRep);
        Assert.NotNull(sessionKey);

        // And it went out framed the way the client sent its token: a SPNEGO accept-completed
        // naming the same mechanism, wrapping a GSS-API context token that carries the AP-REP.
        var response = NegotiationToken.Decode(mutual);
        Assert.NotNull(response.ResponseToken);
        Assert.Equal(NegotiateState.AcceptCompleted, response.ResponseToken!.State);
        var inner = response.ResponseToken.ResponseToken!.Value;
        Assert.Equal(0x60, inner.Span[0]); // [APPLICATION 0]
        Assert.True(inner.Span.IndexOf(new byte[] { 0x02, 0x00 }) > 0); // AP-REP token id after the OID
        var request = MessageParser.ParseNegotiate(token).Token;
        Assert.Equal(request.InitialToken!.MechTypes![0].Value, response.ResponseToken.SupportedMech.Value);
    }

    [Fact]
    public async Task A_bare_ap_req_from_a_ws_security_header_is_framed_and_accepted()
    {
        var forest = new InProcessKdc("corp.customer-a.local");
        forest.AddAccount("WS-042$", "Machine-P@ss-1");
        var acceptor = Acceptor(new Realms().Bind(forest, TenantA));

        // What a #Kerberosv5_AP_REQ token carries: the AP-REQ without GSS-API framing.
        var gss = await forest.ServiceTicketAsync("WS-042$", "Machine-P@ss-1");
        var raw = MessageParser.ParseNegotiate(gss).Token.InitialToken!.MechToken!.Value;
        var bare = MessageParser.ParseKerberos(raw).KrbApReq.EncodeApplication();

        var framed = await acceptor.AcceptAsync(KerberosAcceptor.FrameApReq(bare), TenantA);
        Assert.True(framed.Accepted, framed.Refusal.ToString());
        Assert.Equal("WS-042$", framed.Caller!.Principal);

        // The parser also takes the bare AP-REQ as it is; a fresh acceptor, since the authenticator was just used.
        var unframed = await Acceptor(new Realms().Bind(forest, TenantA)).AcceptAsync(bare, TenantA);
        Assert.True(unframed.Accepted, unframed.Refusal.ToString());
    }

    [Fact]
    public async Task An_ntlm_fallback_is_named_as_such_and_every_unusable_token_is_described()
    {
        var forest = new InProcessKdc("corp.customer-a.local");
        var acceptor = Acceptor(new Realms().Bind(forest, TenantA));

        // What a client sends when its SSPI could not get a service ticket: SPNEGO whose
        // mechanism token is an NTLMSSP negotiate message rather than a Kerberos AP-REQ.
        var ntlm = GssApiToken.Encode(new Oid("1.3.6.1.5.5.2"), new NegotiationToken
        {
            InitialToken = new NegTokenInit
            {
                MechTypes = [new Oid("1.3.6.1.4.1.311.2.2.10")],
                MechToken = "NTLMSSP "u8.ToArray().Concat(new byte[] { 1, 0, 0, 0 }).ToArray(),
            },
        });

        var result = await acceptor.AcceptAsync(ntlm, TenantA);
        Assert.Equal(KerberosRefusal.NtlmOffered, result.Refusal);
        Assert.Contains("NTLMSSP", result.Detail);
        Assert.Contains("1.3.6.1.4.1.311.2.2.10", result.Detail);

        // Garbage is still malformed, but now says so with its leading bytes.
        var garbage = await acceptor.AcceptAsync(new byte[] { 1, 2, 3, 4 }, TenantA);
        Assert.Equal(KerberosRefusal.Malformed, garbage.Refusal);
        Assert.Contains("01020304", garbage.Detail);

        // A real ticket is unaffected by any of this.
        forest.AddAccount("alice", "Alice-P@ss-1");
        var good = await acceptor.AcceptAsync(await forest.ServiceTicketAsync("alice", "Alice-P@ss-1"), TenantA);
        Assert.True(good.Accepted, good.Refusal.ToString());
    }
}
