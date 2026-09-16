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
/// <param name="ApRep">The bare AP-REP proving the server's identity.</param>
/// <param name="MutualAuthToken">
/// The AP-REP framed the way the client's token was: a SPNEGO <c>NegTokenResp</c> (accept-completed)
/// for a SPNEGO request, a GSS-API context token otherwise. Sent back as
/// <c>WWW-Authenticate: Negotiate &lt;base64&gt;</c> on the success response, which a client that
/// asked for mutual authentication requires before it trusts the reply.
/// </param>
public sealed record KerberosCaller(string Principal, string Realm, bool IsMachine, KerberosRealmKeys Binding, ReadOnlyMemory<byte> ApRep, ReadOnlyMemory<byte> MutualAuthToken)
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

    /// <summary>
    /// For <see cref="KerberosRefusal.Invalid"/>: the ticket's key version and type, and what
    /// each live key attempt reported. Operator-facing; names no secret.
    /// </summary>
    public string? Detail { get; init; }
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
        string? spnegoMech;
        try
        {
            var peeked = PeekApReq(token, out spnegoMech);
            if (peeked == null)
                return new KerberosAcceptResult(null, KerberosRefusal.NtlmOffered, null, null) { Detail = Describe(token) };
            apReq = peeked;
        }
        catch (Exception)
        {
            return new KerberosAcceptResult(null, KerberosRefusal.Malformed, null, null) { Detail = Describe(token) };
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
        var ticketEType = apReq.Ticket.EncryptedPart?.EType;
        DecryptedKrbApReq? decrypted = null;
        var attempts = new List<string>();
        // A key of another encryption type cannot decrypt this ticket, so trying it only adds
        // noise to the detail. The keys that are skipped for that reason are named once.
        var candidates = binding.Keys.Where(k => ticketEType == null || k.EncryptionType == ticketEType).ToList();
        var skipped = binding.Keys.Count - candidates.Count;
        foreach (var key in candidates.OrderByDescending(k => k.Version == ticketKvno))
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
            catch (Exception ex)
            {
                // Wrong key version, or a real validation failure; the next key gets its turn.
                // The reason is kept for the operator: a wrong key reads differently from a
                // stale clock or a rejected PAC, and only the message tells them apart.
                attempts.Add($"kvno {key.Version?.ToString() ?? "?"} {key.EncryptionType}: {ex.GetType().Name}: {ex.Message}");
            }
        }
        if (decrypted == null)
        {
            if (binding.Keys.Count == 0) attempts.Add("the realm has no live key");
            else if (candidates.Count == 0) attempts.Add($"none of the {binding.Keys.Count} live keys is {ticketEType}");
            else if (skipped > 0) attempts.Add($"{skipped} key(s) of other types not tried");
            var detail = $"ticket kvno {ticketKvno?.ToString() ?? "?"} {ticketEType}; " + string.Join(" | ", attempts);
            return new KerberosAcceptResult(null, KerberosRefusal.Invalid, realm, sname) { Detail = detail };
        }

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
        var mutual = MutualAuthToken(apRep, spnegoMech);
        return new KerberosAcceptResult(new KerberosCaller(principal, binding.Realm, isMachine, binding, apRep, mutual), KerberosRefusal.None, realm, sname);
    }

    /// <summary>The standard Kerberos v5 GSS-API mechanism OID.</summary>
    internal const string Krb5Mechanism = "1.2.840.113554.1.2.2";

    /// <summary>NTLMSSP messages begin with the signature "NTLMSSP ".</summary>
    private static bool IsNtlm(ReadOnlyMemory<byte> token)
        => token.Length >= 8 && token.Span[..8].SequenceEqual("NTLMSSP "u8);

    /// <summary>
    /// A best-effort description of a token the acceptor could not use, for the operator: the
    /// SPNEGO mechanisms the client offered, and what its mechanism token looks like. This is
    /// what separates "the client sent NTLM because it could not get a ticket" from "these bytes
    /// are not a token at all". Never throws; a diagnostic must not fail a request.
    /// </summary>
    internal static string Describe(ReadOnlyMemory<byte> token)
    {
        try
        {
            if (MessageParser.ParseContext(token) is NegotiateContextToken negotiate)
            {
                var init = negotiate.Token?.InitialToken;
                var mechs = init?.MechTypes == null || init.MechTypes.Length == 0
                    ? "none"
                    : string.Join(" ", init.MechTypes.Select(o => o.Value));
                var mechToken = init?.MechToken;
                var inner = mechToken == null ? "absent"
                    : IsNtlm(mechToken.Value) ? $"NTLMSSP, {mechToken.Value.Length} bytes"
                    : $"{mechToken.Value.Length} bytes starting {Hex(mechToken.Value, 8)}";
                return $"SPNEGO, {token.Length} bytes; mechTypes: {mechs}; mechToken: {inner}";
            }
            return $"not SPNEGO, {token.Length} bytes starting {Hex(token, 16)}";
        }
        catch (Exception ex)
        {
            return $"unparsable, {token.Length} bytes starting {Hex(token, 16)}: {ex.GetType().Name}";
        }
    }

    private static string Hex(ReadOnlyMemory<byte> value, int count)
        => Convert.ToHexString(value.Span[..Math.Min(count, value.Length)]);

    /// <summary>
    /// Frames the AP-REP for the response header. Inside SPNEGO the client expects a NegTokenResp
    /// naming the mechanism it used and carrying the mechanism's own context token; outside it,
    /// the bare GSS-API context token. The context token is the RFC 1964 framing: APPLICATION 0
    /// around the mechanism OID, the AP-REP token id (0x02 0x00) and the AP-REP.
    /// </summary>
    internal static ReadOnlyMemory<byte> MutualAuthToken(ReadOnlyMemory<byte> apRep, string? spnegoMech)
    {
        var mech = spnegoMech ?? Krb5Mechanism;
        var framed = GssContextToken(mech, apRep);
        if (spnegoMech == null)
            return framed;
        var response = new NegotiationToken
        {
            ResponseToken = new NegTokenResp
            {
                State = NegotiateState.AcceptCompleted,
                SupportedMech = new System.Security.Cryptography.Oid(mech),
                ResponseToken = framed,
            },
        };
        return response.Encode();
    }

    /// <summary>
    /// Frames a bare AP-REQ (WS-Security <c>#Kerberosv5_AP_REQ</c>) as the RFC 1964 GSS-API
    /// context token the acceptor parses, with token id 0x01 0x00.
    /// </summary>
    public static ReadOnlyMemory<byte> FrameApReq(ReadOnlyMemory<byte> rawApReq)
        => GssContextToken(Krb5Mechanism, rawApReq, tokenId: 0x01);

    private static ReadOnlyMemory<byte> GssContextToken(string mechOid, ReadOnlyMemory<byte> apRep)
        => GssContextToken(mechOid, apRep, tokenId: 0x02);

    private static ReadOnlyMemory<byte> GssContextToken(string mechOid, ReadOnlyMemory<byte> apRep, byte tokenId)
    {
        // The content is not one ASN.1 value (an OID, two raw token-id bytes, then the AP-REP),
        // so the [APPLICATION 0] wrapper is assembled by hand: tag 0x60, DER length, content.
        var oid = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
        oid.WriteObjectIdentifier(mechOid);
        var oidDer = oid.Encode();
        var contentLength = oidDer.Length + 2 + apRep.Length;
        var length = DerLength(contentLength);
        var token = new byte[1 + length.Length + contentLength];
        token[0] = 0x60;
        length.CopyTo(token, 1);
        var at = 1 + length.Length;
        oidDer.CopyTo(token, at); at += oidDer.Length;
        token[at++] = tokenId; // TOK_ID: 0x01 AP-REQ, 0x02 AP-REP
        token[at++] = 0x00;
        apRep.CopyTo(token.AsMemory(at));
        return token;
    }

    private static byte[] DerLength(int n)
    {
        if (n < 0x80) return [(byte)n];
        var bytes = new List<byte>();
        for (var v = n; v > 0; v >>= 8) bytes.Insert(0, (byte)(v & 0xFF));
        bytes.Insert(0, (byte)(0x80 | bytes.Count));
        return bytes.ToArray();
    }

    /// <summary>
    /// The AP-REQ inside a SPNEGO or raw Kerberos context token, read without any key. Null when
    /// SPNEGO carries no Kerberos token (NTLM only). Throws on anything that is not a token.
    /// </summary>
    internal static KrbApReq? PeekApReq(ReadOnlyMemory<byte> token, out string? spnegoMech)
    {
        spnegoMech = null;
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
                // A client whose SSPI could not get a service ticket falls back to NTLM inside
                // SPNEGO. That is a client-side outcome, not a malformed token, and it is worth
                // naming: it usually means the SPN the client computed has no ticket.
                if (IsNtlm(mechToken))
                    return null;

                // The optimistic mechToken belongs to the first mechanism offered.
                spnegoMech = init.MechTypes?.FirstOrDefault()?.Value ?? Krb5Mechanism;
                var inner = MessageParser.ParseKerberos(mechToken);
                return inner.KrbApReq ?? throw new InvalidOperationException("SPNEGO mechanism token is not an AP-REQ");
            }
            default:
                throw new InvalidOperationException("Not a GSS-API context token");
        }
    }
}
