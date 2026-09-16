using System.Xml;
using System.Xml.Linq;

namespace ModularCA.Core.Services.Msae;

/// <summary>
/// The SOAP wire format for Windows certificate enrollment over WS-Trust: parsing the client's
/// <c>RequestSecurityToken</c> (RST) and building the <c>RequestSecurityTokenResponseCollection</c>
/// (RSTRC) that carries the issued certificate.
/// </summary>
/// <remarks>
/// <para>
/// This is the interop-critical core of Microsoft autoenrollment (MS-WSTEP, layered on WS-Trust
/// 1.3 and WS-Security). A Windows client — the Group Policy autoenrollment engine, or
/// <c>certreq</c> — POSTs a SOAP 1.2 envelope whose body is an <c>Issue</c> request carrying a
/// PKCS#10 in a <c>BinarySecurityToken</c>; the server answers with the certificate in a
/// <c>BinarySecurityToken</c> of its own. Everything else in the feature (policy, authentication,
/// template mapping) sits on top of getting these two envelopes exactly right, so the format lives
/// on its own, as pure functions, and is tested without a controller or a network.
/// </para>
/// <para>
/// Parsing is deliberately lenient about namespace prefixes and about which of several
/// <c>BinarySecurityToken</c> elements carries the request — a Windows client and a hand-built
/// <c>certreq</c> envelope differ in incidental ways — but strict about the one thing that matters:
/// a PKCS#10 must be present and decodable. Parsing is also hardened against hostile XML: DTDs are
/// prohibited and no external entities or resolvers are ever consulted, because this envelope
/// arrives from the network before the caller is authenticated.
/// </para>
/// </remarks>
public static class WstepMessages
{
    // Namespaces, from the WS-* specifications and MS-WSTEP.
    public const string Soap12 = "http://www.w3.org/2003/05/soap-envelope";
    public const string Wsa = "http://www.w3.org/2005/08/addressing";
    public const string WsTrust = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
    public const string Wsse = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    public const string Enrollment = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment";
    public const string Wsu = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

    // How long a response's WS-Security Timestamp is marked valid for. The client checks that
    // "now" falls inside the window, with its own clock-skew allowance; five minutes is what a
    // WCF server emits.
    private static readonly TimeSpan TimestampValidity = TimeSpan.FromMinutes(5);

    public const string IssueRequestType = WsTrust + "/Issue";

    /// <summary>MS-WSTEP request type for asking after a request submitted earlier.</summary>
    public const string QueryTokenStatusRequestType = Enrollment + "/QueryTokenStatus";

    /// <summary>The disposition Microsoft's CES reports for a request awaiting approval.</summary>
    public const string PendingDisposition = "Taken Under Submission";
    public const string ResponseAction = Enrollment + "/RSTRC/wstep";
    public const string X509TokenType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";
    public const string EncodingBase64 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";

    /// <summary>
    /// The EncodingType MS-WSTEP prescribes for the tokens in this exchange (section 3.1.4.1.3.4),
    /// and the one Windows clients expect on the issued certificate. Requests are accepted with
    /// either spelling; responses always use this one.
    /// </summary>
    public const string ResponseEncodingBase64 = Wsse + "#base64binary";

    // The ValueType suffixes are matched rather than the full URIs: a client may namespace the
    // PKCS#10 token under the enrollment URI or the older WSS X.509 profile, and only the kind
    // matters here.
    private const string Pkcs10Suffix = "#PKCS10";
    private const string Pkcs7Suffix = "#PKCS7";
    public const string Pkcs7ValueType = Enrollment + Pkcs7Suffix;

    /// <summary>A parsed enrollment request.</summary>
    /// <param name="Pkcs10Der">The DER-encoded PKCS#10 the client wants signed.</param>
    /// <param name="MessageId">The client's <c>wsa:MessageID</c>, echoed as <c>RelatesTo</c>, or null.</param>
    /// <param name="RequestId">The MS-WSTEP <c>RequestID</c>, echoed in the response, or null.</param>
    /// <param name="FromCmc">
    /// True when the PKCS#10 was unwrapped from a CMC request (a <c>#PKCS7</c> token), which is
    /// how the autoenrollment engine and the PowerShell cmdlets submit; false for the bare
    /// <c>#PKCS10</c> token <c>certreq -submit</c> sends. Both are issued the same way.
    /// </param>
    /// <param name="UsernameToken">
    /// The WS-Security <c>UsernameToken</c> from the SOAP header, when the client authenticated at
    /// the message level with a clear-text password, or null. A digest-typed password is reported
    /// as null too: it cannot be verified against a stored hash.
    /// </param>
    public sealed record WstepIssueRequest(
        byte[] Pkcs10Der,
        string? MessageId,
        string? RequestId,
        bool FromCmc,
        WstepUsernameToken? UsernameToken = null,
        WstepKerberosToken? KerberosToken = null)
    {
        /// <summary>The renewal evidence a CMC request carried, or null for a first enrollment.</summary>
        public MsaeRenewal? Renewal { get; init; }

        /// <summary>True for a QueryTokenStatus request: <see cref="RequestId"/> names the request, and there is no PKCS#10.</summary>
        public bool IsStatusQuery { get; init; }
    }

    /// <summary>A WS-Security <c>UsernameToken</c> carrying a clear-text password.</summary>
    public sealed record WstepUsernameToken(string Username, string Password);

    /// <summary>
    /// A WS-Security Kerberos token (Kerberos Token Profile 1.1): the client's AP-REQ as a
    /// <c>BinarySecurityToken</c> in the <c>Security</c> header. This is how the Windows
    /// enrollment engine authenticates when its policy server is set to Kerberos: at the message
    /// level, not with an HTTP Negotiate header.
    /// </summary>
    /// <param name="Token">The decoded token bytes.</param>
    /// <param name="GssFramed">True for <c>#GSS_Kerberosv5_AP_REQ</c> (RFC 1964 context token); false for a bare <c>#Kerberosv5_AP_REQ</c>.</param>
    public sealed record WstepKerberosToken(byte[] Token, bool GssFramed);

    /// <summary>Raised when a SOAP body is not a usable enrollment request.</summary>
    public sealed class WstepParseException(string message) : Exception(message);

    /// <summary>
    /// Parses a SOAP <c>Issue</c> request, returning the PKCS#10 and the fields the response must
    /// echo. Throws <see cref="WstepParseException"/> when no decodable PKCS#10 is present.
    /// </summary>
    public static WstepIssueRequest ParseIssueRequest(string soapXml)
    {
        var doc = LoadHardened(soapXml);

        // Every BinarySecurityToken in the message, regardless of prefix or the section it sits in.
        var tokens = doc.Descendants(XName.Get("BinarySecurityToken", Wsse)).ToList();

        var requestId = doc.Descendants(XName.Get("RequestID", Enrollment)).FirstOrDefault()?.Value?.Trim();

        // A status query names a request and carries no PKCS#10; anything else is an Issue.
        var requestType = doc.Descendants(XName.Get("RequestType", WsTrust)).FirstOrDefault()?.Value?.Trim();
        if (string.Equals(requestType, QueryTokenStatusRequestType, StringComparison.Ordinal))
        {
            if (string.IsNullOrEmpty(requestId))
                throw new WstepParseException("A QueryTokenStatus request must name the RequestID it asks after.");
            return new WstepIssueRequest([], ReadMessageId(doc), requestId, false,
                ReadUsernameToken(doc), ReadKerberosToken(doc)) { IsStatusQuery = true };
        }
        if (requestType != null && !string.Equals(requestType, IssueRequestType, StringComparison.Ordinal))
            throw new WstepParseException($"Request type '{requestType}' is not supported; expected Issue or QueryTokenStatus.");

        // certreq -submit sends the PKCS#10 itself. The autoenrollment engine, Get-Certificate and
        // the Certificates snap-in send a CMC request instead: the PKCS#10 wrapped in a PKIData
        // and signed with the new key, as a #PKCS7 token. Both end in the same PKCS#10.
        var fromCmc = false;
        MsaeRenewal? renewal = null;
        var pkcs10 = FirstTokenBytesByValueType(tokens, Pkcs10Suffix);
        if (pkcs10 == null)
        {
            var pkcs7 = FirstTokenBytesByValueType(tokens, Pkcs7Suffix)
                ?? throw new WstepParseException(
                    "No certificate request found. Expected a PKCS#10 or CMC (PKCS#7) BinarySecurityToken.");
            var unwrapped = CmcRequests.Unwrap(pkcs7);
            pkcs10 = unwrapped.Pkcs10Der;
            renewal = unwrapped.Renewal;
            fromCmc = true;
        }

        return new WstepIssueRequest(pkcs10, ReadMessageId(doc), EmptyToNull(requestId), fromCmc,
            ReadUsernameToken(doc), ReadKerberosToken(doc)) { Renewal = renewal };
    }

    /// <summary>
    /// Parses SOAP text with hostile-input hardening: no DTD, no resolver, no entity expansion.
    /// Shared by every message parser on the MSAE endpoints, all of which run before the caller
    /// is authenticated. Throws <see cref="WstepParseException"/> for empty or malformed input.
    /// </summary>
    internal static XDocument LoadHardened(string soapXml)
    {
        if (string.IsNullOrWhiteSpace(soapXml))
            throw new WstepParseException("Empty request body.");

        try
        {
            // An XML parser that fetches a URL or expands a billion-laughs entity is a
            // denial-of-service and an SSRF surface, not a convenience.
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersFromEntities = 0,
            };
            using var stringReader = new StringReader(soapXml);
            using var xmlReader = XmlReader.Create(stringReader, settings);
            return XDocument.Load(xmlReader);
        }
        catch (XmlException ex)
        {
            throw new WstepParseException($"Request is not well-formed XML: {ex.Message}");
        }
    }

    /// <summary>The <c>wsa:MessageID</c> of a parsed envelope, or null when absent or empty.</summary>
    internal static string? ReadMessageId(XDocument doc)
        => EmptyToNull(doc.Descendants(XName.Get("MessageID", Wsa)).FirstOrDefault()?.Value?.Trim());

    // WS-Security UsernameToken profile 1.0: a Username and a Password whose Type is absent or
    // #PasswordText. A Windows CES client configured for username authentication sends exactly
    // this over TLS (WCF TransportWithMessageCredential). #PasswordDigest is a hash over a nonce
    // and the clear password, which cannot be checked against a stored password hash, so it is
    // treated as absent rather than silently accepted.
    internal static WstepUsernameToken? ReadUsernameToken(XDocument doc)
    {
        var token = doc.Descendants(XName.Get("UsernameToken", Wsse)).FirstOrDefault();
        if (token == null) return null;

        var username = token.Element(XName.Get("Username", Wsse))?.Value?.Trim();
        var passwordElement = token.Element(XName.Get("Password", Wsse));
        var password = passwordElement?.Value;
        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            return null;

        var type = (string?)passwordElement!.Attribute("Type");
        if (type != null && !type.EndsWith("#PasswordText", StringComparison.OrdinalIgnoreCase))
            return null;

        return new WstepUsernameToken(username, password);
    }

    /// <summary>
    /// The Kerberos token in the <c>wsse:Security</c> header, or null. Only tokens inside the
    /// Security header count, so the PKCS#10 and CMC tokens in the body are never mistaken for
    /// one. The ValueType decides whether the bytes are GSS-API framed.
    /// </summary>
    public static WstepKerberosToken? ReadKerberosToken(XDocument doc)
    {
        foreach (var security in doc.Descendants(XName.Get("Security", Wsse)))
        {
            foreach (var token in security.Descendants(XName.Get("BinarySecurityToken", Wsse)))
            {
                var valueType = (string?)token.Attribute("ValueType") ?? string.Empty;
                if (valueType.IndexOf("Kerberosv5_AP_REQ", StringComparison.OrdinalIgnoreCase) < 0)
                    continue;
                var text = string.Concat(token.Value.Where(c => !char.IsWhiteSpace(c)));
                if (text.Length == 0) continue;
                try
                {
                    var bytes = Convert.FromBase64String(text);
                    var gss = valueType.IndexOf("GSS_", StringComparison.OrdinalIgnoreCase) >= 0;
                    return new WstepKerberosToken(bytes, gss);
                }
                catch (FormatException)
                {
                    throw new WstepParseException("The Kerberos BinarySecurityToken is not base64.");
                }
            }
        }
        return null;
    }

    /// <summary>
    /// Builds the RSTRC carrying an issued certificate, echoing the request's correlation fields.
    /// </summary>
    /// <param name="issuedPkcs7Der">The issued certificate as a certs-only PKCS#7 (DER).</param>
    /// <param name="relatesToMessageId">The request's <c>wsa:MessageID</c>, or null to omit RelatesTo.</param>
    /// <param name="requestId">The request's MS-WSTEP <c>RequestID</c>, or null to omit it.</param>
    public static string BuildIssueResponse(byte[] issuedPkcs7Der, string? relatesToMessageId, string? requestId)
    {
        ArgumentNullException.ThrowIfNull(issuedPkcs7Der);
        if (issuedPkcs7Der.Length == 0)
            throw new ArgumentException("Issued certificate bytes are empty.", nameof(issuedPkcs7Der));

        var certB64 = Convert.ToBase64String(issuedPkcs7Der);

        XNamespace s = Soap12, a = Wsa, t = WsTrust, o = Wsse, e = Enrollment;

        var header = new XElement(s + "Header",
            new XElement(a + "Action", new XAttribute(s + "mustUnderstand", "1"), ResponseAction));
        if (!string.IsNullOrEmpty(relatesToMessageId))
            header.Add(new XElement(a + "RelatesTo", relatesToMessageId));
        // A Windows client authenticates at the message level (UsernameToken over TLS) and, on
        // that binding, WCF expects the reply to carry a WS-Security header with a Timestamp;
        // Microsoft's own CES emits one. Without it a client can reject an otherwise correct reply.
        header.Add(SecurityTimestamp(DateTime.UtcNow));

        // The issued certificate appears twice, on purpose: MS-WSTEP places it in a
        // wst:RequestedSecurityToken, and Windows clients also read it from a token directly
        // under the response. Both tokens are wsse:BinarySecurityToken with the EncodingType
        // MS-WSTEP prescribes for this exchange (the secext "#base64binary" URI, not the
        // WS-Security "#Base64Binary" one). certreq's reader (WWSAPI) is strict about both: a
        // token in the WS-Trust namespace, or the other EncodingType, is WS_E_INVALID_FORMAT.
        XElement IssuedToken() => new(o + "BinarySecurityToken",
            new XAttribute("ValueType", Pkcs7ValueType),
            new XAttribute("EncodingType", ResponseEncodingBase64),
            certB64);

        var rstr = new XElement(t + "RequestSecurityTokenResponse",
            new XElement(t + "TokenType", X509TokenType),
            new XElement(e + "DispositionMessage", new XAttribute(XNamespace.Xml + "lang", "en-US"), "Issued"),
            IssuedToken(),
            new XElement(t + "RequestedSecurityToken", IssuedToken()));
        if (!string.IsNullOrEmpty(requestId))
            rstr.Add(new XElement(e + "RequestID", requestId));

        var envelope = new XElement(s + "Envelope",
            new XAttribute(XNamespace.Xmlns + "s", Soap12),
            new XAttribute(XNamespace.Xmlns + "a", Wsa),
            new XAttribute(XNamespace.Xmlns + "wst", WsTrust),
            new XAttribute(XNamespace.Xmlns + "wsse", Wsse),
            new XAttribute(XNamespace.Xmlns + "wsu", Wsu),
            new XAttribute(XNamespace.Xmlns + "enr", Enrollment),
            header,
            new XElement(s + "Body",
                new XElement(t + "RequestSecurityTokenResponseCollection", rstr)));

        return Serialize(envelope);
    }

    /// <summary>
    /// Builds the response for a request taken under submission, shaped the way Microsoft's CES
    /// shapes it and the Windows client insists on: the pending disposition, a <c>#PKCS7</c> token
    /// carrying a CMC full PKI response with status pending, a <c>RequestedSecurityToken</c> whose
    /// <c>SecurityTokenReference</c> points back at the service where the request can be
    /// collected, and the request id the client must quote when it asks again. A reply without the
    /// token is refused by the client as <c>WS_E_INVALID_FORMAT</c>.
    /// </summary>
    /// <param name="relatesToMessageId">The request's <c>wsa:MessageID</c>, or null to omit RelatesTo.</param>
    /// <param name="requestId">The id the client must quote in QueryTokenStatus.</param>
    /// <param name="cesUrl">This service's URL, where the pended request is collected.</param>
    public static string BuildPendingResponse(string? relatesToMessageId, string requestId, string cesUrl)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(requestId);
        ArgumentException.ThrowIfNullOrWhiteSpace(cesUrl);
        XNamespace s = Soap12, a = Wsa, t = WsTrust, o = Wsse, e = Enrollment;

        var header = new XElement(s + "Header",
            new XElement(a + "Action", new XAttribute(s + "mustUnderstand", "1"), ResponseAction));
        if (!string.IsNullOrEmpty(relatesToMessageId))
            header.Add(new XElement(a + "RelatesTo", relatesToMessageId));
        header.Add(SecurityTimestamp(DateTime.UtcNow));

        var cmc = Convert.ToBase64String(CmcResponses.BuildPending(requestId, DateTime.UtcNow));
        var rstr = new XElement(t + "RequestSecurityTokenResponse",
            new XElement(t + "TokenType", X509TokenType),
            new XElement(e + "DispositionMessage", new XAttribute(XNamespace.Xml + "lang", "en-US"), PendingDisposition),
            new XElement(o + "BinarySecurityToken",
                new XAttribute("ValueType", Pkcs7ValueType),
                new XAttribute("EncodingType", ResponseEncodingBase64),
                cmc),
            new XElement(t + "RequestedSecurityToken",
                new XElement(o + "SecurityTokenReference",
                    new XElement(o + "Reference", new XAttribute("URI", cesUrl)))),
            new XElement(e + "RequestID", requestId));

        var envelope = new XElement(s + "Envelope",
            new XAttribute(XNamespace.Xmlns + "s", Soap12),
            new XAttribute(XNamespace.Xmlns + "a", Wsa),
            new XAttribute(XNamespace.Xmlns + "wst", WsTrust),
            new XAttribute(XNamespace.Xmlns + "wsse", Wsse),
            new XAttribute(XNamespace.Xmlns + "wsu", Wsu),
            new XAttribute(XNamespace.Xmlns + "enr", Enrollment),
            header,
            new XElement(s + "Body",
                new XElement(t + "RequestSecurityTokenResponseCollection", rstr)));

        return Serialize(envelope);
    }

    /// <summary>
    /// Builds a SOAP 1.2 fault, so a refused or failed enrollment answers with a fault a client can
    /// surface rather than a bare 500.
    /// </summary>
    /// <param name="reason">Human-readable reason, placed in <c>Reason/Text</c>.</param>
    /// <param name="relatesToMessageId">The request's <c>wsa:MessageID</c>, or null to omit RelatesTo.</param>
    /// <param name="senderFault">
    /// True for a fault the client caused (malformed request, bad credentials, refused policy),
    /// which SOAP 1.2 codes as <c>Sender</c>; false for a server-side failure (<c>Receiver</c>).
    /// </param>
    public static string BuildFault(string reason, string? relatesToMessageId = null, bool senderFault = false)
    {
        XNamespace s = Soap12, a = Wsa;

        var header = new XElement(s + "Header",
            new XElement(a + "Action", "http://www.w3.org/2005/08/addressing/soap/fault"));
        if (!string.IsNullOrEmpty(relatesToMessageId))
            header.Add(new XElement(a + "RelatesTo", relatesToMessageId));

        var envelope = new XElement(s + "Envelope",
            new XAttribute(XNamespace.Xmlns + "s", Soap12),
            new XAttribute(XNamespace.Xmlns + "a", Wsa),
            header,
            new XElement(s + "Body",
                new XElement(s + "Fault",
                    new XElement(s + "Code",
                        new XElement(s + "Value", senderFault ? "s:Sender" : "s:Receiver")),
                    new XElement(s + "Reason",
                        new XElement(s + "Text",
                            new XAttribute(XNamespace.Xml + "lang", "en"), reason)))));

        return Serialize(envelope);
    }

    /// <summary>
    /// Builds the <c>wsse:Security</c> header carrying a <c>wsu:Timestamp</c> whose window opens at
    /// <paramref name="createdUtc"/>. Public so the window can be pinned by tests with a fixed
    /// instant; callers in the response builders pass the current time.
    /// </summary>
    public static XElement SecurityTimestamp(DateTime createdUtc)
    {
        XNamespace s = Soap12, o = Wsse, u = Wsu;
        const string format = "yyyy-MM-dd'T'HH:mm:ss.fff'Z'";
        var created = DateTime.SpecifyKind(createdUtc, DateTimeKind.Utc);
        return new XElement(o + "Security",
            new XAttribute(s + "mustUnderstand", "1"),
            new XElement(u + "Timestamp",
                new XAttribute(u + "Id", "_0"),
                new XElement(u + "Created", created.ToString(format, System.Globalization.CultureInfo.InvariantCulture)),
                new XElement(u + "Expires", created.Add(TimestampValidity).ToString(format, System.Globalization.CultureInfo.InvariantCulture))));
    }

    private static byte[]? FirstTokenBytesByValueType(IEnumerable<XElement> tokens, string valueTypeSuffix)
    {
        foreach (var token in tokens)
        {
            if (!ValueTypeEndsWith(token, valueTypeSuffix))
                continue;
            var text = token.Value?.Trim();
            if (string.IsNullOrEmpty(text))
                continue;
            try
            {
                return Convert.FromBase64String(text);
            }
            catch (FormatException)
            {
                // A token that claims to be PKCS#10 but is not base64 is not a candidate; keep
                // looking rather than failing, in case a well-formed one follows.
            }
        }
        return null;
    }

    private static bool ValueTypeEndsWith(XElement token, string suffix)
    {
        var valueType = (string?)token.Attribute("ValueType");
        return valueType != null && valueType.EndsWith(suffix, StringComparison.OrdinalIgnoreCase);
    }

    private static string? EmptyToNull(string? value) => string.IsNullOrEmpty(value) ? null : value;

    internal static string Serialize(XElement envelope)
    {
        var settings = new XmlWriterSettings
        {
            Encoding = new System.Text.UTF8Encoding(false),
            OmitXmlDeclaration = false,
            Indent = false,
        };
        using var buffer = new MemoryStream();
        using (var writer = XmlWriter.Create(buffer, settings))
        {
            envelope.Save(writer);
        }
        return settings.Encoding.GetString(buffer.ToArray());
    }
}
