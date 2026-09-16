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
    public const string ResponseAction = Enrollment + "/RSTRC/wstep";
    public const string X509TokenType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";
    public const string EncodingBase64 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";

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
    /// <param name="IsRenewal">
    /// True when the request also carries a previously issued certificate (a renewal, "on behalf
    /// of" the old certificate). The renewal proof itself is validated elsewhere; this only records
    /// that the shape is a renewal.
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
        bool IsRenewal,
        WstepUsernameToken? UsernameToken = null);

    /// <summary>A WS-Security <c>UsernameToken</c> carrying a clear-text password.</summary>
    public sealed record WstepUsernameToken(string Username, string Password);

    /// <summary>Raised when a SOAP body is not a usable enrollment request.</summary>
    public sealed class WstepParseException(string message) : Exception(message);

    /// <summary>
    /// Parses a SOAP <c>Issue</c> request, returning the PKCS#10 and the fields the response must
    /// echo. Throws <see cref="WstepParseException"/> when no decodable PKCS#10 is present.
    /// </summary>
    public static WstepIssueRequest ParseIssueRequest(string soapXml)
    {
        if (string.IsNullOrWhiteSpace(soapXml))
            throw new WstepParseException("Empty request body.");

        XDocument doc;
        try
        {
            // Hardened: no DTD, no resolver, no external entities. This runs on unauthenticated
            // input, so an XML parser that fetches a URL or expands a billion-laughs entity is a
            // denial-of-service and an SSRF surface, not a convenience.
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersFromEntities = 0,
            };
            using var stringReader = new StringReader(soapXml);
            using var xmlReader = XmlReader.Create(stringReader, settings);
            doc = XDocument.Load(xmlReader);
        }
        catch (XmlException ex)
        {
            throw new WstepParseException($"Request is not well-formed XML: {ex.Message}");
        }

        // Every BinarySecurityToken in the message, regardless of prefix or the section it sits in.
        var tokens = doc.Descendants(XName.Get("BinarySecurityToken", Wsse)).ToList();

        var pkcs10 = FirstTokenBytesByValueType(tokens, Pkcs10Suffix)
            ?? throw new WstepParseException(
                "No PKCS#10 BinarySecurityToken found. Expected a token with a ValueType ending in '#PKCS10'.");

        // A PKCS#7 alongside the PKCS#10 marks a renewal — the client presents the certificate it
        // is renewing so the CA can process a "renewal on behalf of" request.
        var isRenewal = tokens.Any(t => ValueTypeEndsWith(t, Pkcs7Suffix));

        var messageId = doc.Descendants(XName.Get("MessageID", Wsa)).FirstOrDefault()?.Value?.Trim();
        var requestId = doc.Descendants(XName.Get("RequestID", Enrollment)).FirstOrDefault()?.Value?.Trim();

        return new WstepIssueRequest(pkcs10, EmptyToNull(messageId), EmptyToNull(requestId), isRenewal,
            ReadUsernameToken(doc));
    }

    // WS-Security UsernameToken profile 1.0: a Username and a Password whose Type is absent or
    // #PasswordText. A Windows CES client configured for username authentication sends exactly
    // this over TLS (WCF TransportWithMessageCredential). #PasswordDigest is a hash over a nonce
    // and the clear password, which cannot be checked against a stored password hash, so it is
    // treated as absent rather than silently accepted.
    private static WstepUsernameToken? ReadUsernameToken(XDocument doc)
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
        // wst:RequestedSecurityToken, and Windows clients also read it from the top-level
        // wst:BinarySecurityToken. Emitting both is what the various client versions accept.
        var issuedToken = new XElement(o + "BinarySecurityToken",
            new XAttribute("ValueType", Pkcs7ValueType),
            new XAttribute("EncodingType", EncodingBase64),
            certB64);

        var rstr = new XElement(t + "RequestSecurityTokenResponse",
            new XElement(t + "TokenType", X509TokenType),
            new XElement(e + "DispositionMessage", "Issued"),
            new XElement(t + "BinarySecurityToken",
                new XAttribute("ValueType", Pkcs7ValueType),
                new XAttribute("EncodingType", EncodingBase64),
                certB64),
            new XElement(t + "RequestedSecurityToken", issuedToken));
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

    private static string Serialize(XElement envelope)
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
