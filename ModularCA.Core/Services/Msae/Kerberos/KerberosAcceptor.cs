using Kerberos.NET;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.Extensions.Logging;

namespace ModularCA.Core.Services.Msae.Kerberos;

/// <summary>
/// A tenant's Active Directory forest as ModularCA knows it: the realm, whose tenant it is, the
/// service principal its tickets must name, and the AES keys that seal them. Produced by
/// <see cref="IKerberosRealmKeyProvider"/> from the realm bindings; the acceptor never sees the
/// database.
/// </summary>
/// <param name="Realm">Upper-case Kerberos realm, e.g. <c>CORP.CUSTOMER-A.LOCAL</c>.</param>
/// <param name="TenantId">The tenant the forest belongs to; the isolation boundary.</param>
/// <param name="ServicePrincipal">The SPN registered in the forest, e.g. <c>HTTP/ca4.maroongang.net</c>. Tickets for any other name are refused.</param>
/// <param name="DnsDomain">Lower-case DNS domain used to build machine names and UPNs.</param>
/// <param name="EnrollmentUserId">The ModularCA user whose capabilities the forest's principals act with.</param>
/// <param name="EnrollmentUsername">That user's username, which the capability checks are made for.</param>
/// <param name="AllowMachines">Whether machine principals (<c>name$</c>) may enroll.</param>
/// <param name="AllowUsers">Whether user principals may enroll.</param>
/// <param name="Keys">Every live key version for the service principal, newest first.</param>
public sealed record KerberosRealmKeys(
    string Realm,
    Guid TenantId,
    string ServicePrincipal,
    string DnsDomain,
    Guid EnrollmentUserId,
    string EnrollmentUsername,
    bool AllowMachines,
    bool AllowUsers,
    IReadOnlyList<KerberosKey> Keys);

/// <summary>Looks up an enabled realm binding by the realm a ticket names. Null when the realm is unknown or disabled.</summary>
public interface IKerberosRealmKeyProvider
{
    /// <summary>Finds the enabled binding for <paramref name="realm"/>, compared case-insensitively.</summary>
    Task<KerberosRealmKeys?> FindAsync(string realm, CancellationToken cancellation = default);
}

/// <summary>Why a Kerberos token was refused. Each maps to one audit reason and one log line.</summary>
public enum KerberosRefusal
{
    /// <summary>Accepted.</summary>
    None,
    /// <summary>The bytes are not a SPNEGO or Kerberos context token.</summary>
    Malformed,
    /// <summary>SPNEGO offered NTLM only. NTLM is never accepted.</summary>
    NtlmOffered,
    /// <summary>The ticket's realm has no enabled binding.</summary>
    UnknownRealm,
    /// <summary>The realm is bound to a different tenant than the CA being addressed.</summary>
    WrongTenant,
    /// <summary>The ticket names a service principal other than the binding's.</summary>
    WrongServicePrincipal,
    /// <summary>The ticket could not be decrypted with any live key, or failed validation (time, replay, PAC).</summary>
    Invalid,
    /// <summary>The principal kind (machine or user) is not allowed by the binding.</summary>
    PrincipalKindNotAllowed,
    /// <summary>The ticket was sealed by the bound realm for a client of another realm (a cross-realm referral). Bindings hold no trusts.</summary>
    ForeignClientRealm,
}

/// <summary>What an accepted ticket says about the caller.</summary>
/// <param name="Principal">The client principal without realm, e.g. <c>WS-042$</c> or <c>alice</c>.</param>
/// <param name="Realm">The realm that issued the ticket, as bound.</param>
/// <param name="IsMachine">True for a computer account (name ends in <c>$</c>).</param>
/// <param name="Binding">The realm binding the ticket was accepted under.</param>
/// <param name="ApRep">The AP-REP proving the server's identity, for a mutual-authentication response header.</param>
public sealed record KerberosCaller(string Principal, string Realm, bool IsMachine, KerberosRealmKeys Binding, ReadOnlyMemory<byte> ApRep)
{
    /// <summary><c>principal@REALM</c>, as recorded in the audit trail.</summary>
    public string FullName => $"{Principal}@{Realm}";

    /// <summary>The host name of a machine principal: <c>ws-042.corp.customer-a.local</c>. Null for users.</summary>
    public string? DnsHostName => IsMachine ? $"{Principal.TrimEnd('$').ToLowerInvariant()}.{Binding.DnsDomain}" : null;

    /// <summary>The user principal name of a user principal: <c>alice@corp.customer-a.local</c>. Null for machines.</summary>
    public string? Upn => IsMachine ? null : $"{Principal}@{Binding.DnsDomain}";
}

/// <summary>The outcome of <see cref="KerberosAcceptor.AcceptAsync"/>: a caller, or a refusal with the realm it concerned.</summary>
public sealed record KerberosAcceptResult(KerberosCaller? Caller, KerberosRefusal Refusal, string? Realm, string? ServicePrincipal)
{
    /// <summary>True when a caller was established.</summary>
    public bool Accepted => Caller != null;
}

/// <summary>
/// Accepts SPNEGO/Kerberos tokens from many forests without the operating system's Kerberos
/// stack. The ticket's realm and service name travel in the clear, so the acceptor reads them
/// first, finds the one realm binding they belong to, checks it against the tenant being
/// addressed, and only then decrypts with that binding's keys. Keys of other tenants are never
/// tried: a <see cref="KeyTable"/> is built per request from one realm, because the library's
/// lookup would otherwise fall back across entries.
/// </summary>
public sealed class KerberosAcceptor(
    IKerberosRealmKeyProvider realms,
    ITicketReplayValidator replayCache,
    ILoggerFactory? loggerFactory = null)
{
    /// <summary>The SPNEGO mechanism OID for NTLMSSP, which is refused.</summary>
    private const string NtlmMechanism = "1.3.6.1.4.1.311.2.2.10";

    /// <summary>
    /// Accepts <paramref name="token"/> (the bytes after <c>Negotiate </c> in the Authorization
    /// header) for a request addressed to a CA of <paramref name="tenantId"/>.
    /// </summary>
    public async Task<KerberosAcceptResult> AcceptAsync(ReadOnlyMemory<byte> token, Guid tenantId, CancellationToken cancellation = default)
    {
        KrbApReq apReq;
        try
        {
            var peeked = PeekApReq(token);
            if (peeked == null)
                return new KerberosAcceptResult(null, KerberosRefusal.NtlmOffered, null, null);
            apReq = peeked;
        }
        catch (Exception)
        {
            return new KerberosAcceptResult(null, KerberosRefusal.Malformed, null, null);
        }

        var realm = apReq.Ticket.Realm;
        var sname = apReq.Ticket.SName.FullyQualifiedName;

        var binding = await realms.FindAsync(realm, cancellation);
        if (binding == null)
            return new KerberosAcceptResult(null, KerberosRefusal.UnknownRealm, realm, sname);
        if (binding.TenantId != tenantId)
            return new KerberosAcceptResult(null, KerberosRefusal.WrongTenant, realm, sname);
        if (!string.Equals(sname, binding.ServicePrincipal, StringComparison.OrdinalIgnoreCase))
            return new KerberosAcceptResult(null, KerberosRefusal.WrongServicePrincipal, realm, sname);

        // Every live key version is tried, the one whose version the ticket names first. The
        // library validates against one table, and a table with several keys is not tried in
        // turn, so rotation means one table per key. Replay is recorded only on success, so a
        // failed key never poisons the cache for the next.
        var ticketKvno = apReq.Ticket.EncryptedPart?.KeyVersionNumber;
        DecryptedKrbApReq? decrypted = null;
        foreach (var key in binding.Keys.OrderByDescending(k => k.Version == ticketKvno))
        {
            try
            {
                var validator = new KerberosValidator(new KeyTable(key), loggerFactory, replayCache)
                {
                    ValidateAfterDecrypt = ValidationActions.All,
                };
                decrypted = await validator.Validate(token);
                break;
            }
            catch (Exception)
            {
                // Wrong key version, or a real validation failure; the next key gets its turn.
            }
        }
        if (decrypted == null)
            return new KerberosAcceptResult(null, KerberosRefusal.Invalid, realm, sname);

        // A ticket sealed by this realm for a client of another realm would be a cross-realm
        // referral. Bindings hold no trusts, so the client must belong to the bound realm.
        if (!string.Equals(decrypted.Ticket.CRealm, binding.Realm, StringComparison.OrdinalIgnoreCase))
            return new KerberosAcceptResult(null, KerberosRefusal.ForeignClientRealm, realm, sname);

        var principal = decrypted.Ticket.CName.FullyQualifiedName;
        var at = principal.IndexOf('@');
        if (at >= 0) principal = principal[..at];
        var isMachine = principal.EndsWith('$');
        if (isMachine ? !binding.AllowMachines : !binding.AllowUsers)
            return new KerberosAcceptResult(null, KerberosRefusal.PrincipalKindNotAllowed, realm, sname);

        var apRep = decrypted.CreateResponseMessage().EncodeApplication();
        return new KerberosAcceptResult(new KerberosCaller(principal, binding.Realm, isMachine, binding, apRep), KerberosRefusal.None, realm, sname);
    }

    /// <summary>
    /// The AP-REQ inside a SPNEGO or raw Kerberos context token, read without any key. Null when
    /// SPNEGO carries no Kerberos token (NTLM only). Throws on anything that is not a token.
    /// </summary>
    internal static KrbApReq? PeekApReq(ReadOnlyMemory<byte> token)
    {
        var context = MessageParser.ParseContext(token);
        switch (context)
        {
            case KerberosContextToken kerberos:
                return kerberos.KrbApReq ?? throw new InvalidOperationException("Kerberos token without AP-REQ");
            case NegotiateContextToken negotiate:
            {
                var init = negotiate.Token?.InitialToken;
                if (init?.MechToken is not { } mechToken)
                {
                    if (init?.MechTypes?.Any(o => o.Value == NtlmMechanism) == true)
                        return null;
                    throw new InvalidOperationException("SPNEGO token without a mechanism token");
                }
                var inner = MessageParser.ParseKerberos(mechToken);
                return inner.KrbApReq ?? throw new InvalidOperationException("SPNEGO mechanism token is not an AP-REQ");
            }
            default:
                throw new InvalidOperationException("Not a GSS-API context token");
        }
    }
}
