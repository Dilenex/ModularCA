using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;
using ModularCA.Core.Services.Msae;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services.Msae;

/// <summary>
/// Pins the MS-WSTEP wire format ModularCA must speak for Windows autoenrollment: parsing the
/// client's RequestSecurityToken and building the response that carries the issued certificate.
/// </summary>
/// <remarks>
/// This is the interop core of the feature. It cannot be exercised against a real Windows client
/// from here, so these tests do the next best thing: build the exact envelope shapes a client
/// sends, prove the PKCS#10 comes back out, and prove the response is well-formed with the
/// certificate in the elements a client reads. The parser's hostile-XML hardening is pinned too,
/// because this runs on unauthenticated network input.
/// </remarks>
public class WstepMessagesTests
{
    private static byte[] SamplePkcs10(string cn = "CN=device-01.example.test")
    {
        using var key = RSA.Create(2048);
        var req = new CertificateRequest(cn, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return req.CreateSigningRequest();
    }

    private static string RstEnvelope(string pkcs10B64, string? messageId, string? requestId,
        string pkcs10ValueType = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10",
        string? extraPkcs7B64 = null, string? securityHeader = null)
    {
        var header = (messageId == null ? "" : $"<a:MessageID>{messageId}</a:MessageID>") + (securityHeader ?? "");
        var reqId = requestId == null ? "" : $"<enr:RequestID>{requestId}</enr:RequestID>";
        var renewal = extraPkcs7B64 == null ? "" :
            $"<wsse:BinarySecurityToken ValueType=\"http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS7\" " +
            $"EncodingType=\"{WstepMessages.EncodingBase64}\">{extraPkcs7B64}</wsse:BinarySecurityToken>";
        return $@"<s:Envelope xmlns:s=""{WstepMessages.Soap12}"" xmlns:a=""{WstepMessages.Wsa}""
                   xmlns:wst=""{WstepMessages.WsTrust}"" xmlns:wsse=""{WstepMessages.Wsse}""
                   xmlns:enr=""{WstepMessages.Enrollment}"">
  <s:Header>
    <a:Action>{WstepMessages.Enrollment}/RST/wstep</a:Action>
    {header}
    {reqId}
  </s:Header>
  <s:Body>
    <wst:RequestSecurityToken>
      <wst:TokenType>{WstepMessages.X509TokenType}</wst:TokenType>
      <wst:RequestType>{WstepMessages.IssueRequestType}</wst:RequestType>
      <wsse:BinarySecurityToken ValueType=""{pkcs10ValueType}"" EncodingType=""{WstepMessages.EncodingBase64}"">{pkcs10B64}</wsse:BinarySecurityToken>
      {renewal}
    </wst:RequestSecurityToken>
  </s:Body>
</s:Envelope>";
    }

    [Fact]
    public void Parses_the_pkcs10_and_echoes_the_correlation_fields()
    {
        var der = SamplePkcs10();
        var soap = RstEnvelope(Convert.ToBase64String(der), messageId: "urn:uuid:abc-123", requestId: "42");

        var parsed = WstepMessages.ParseIssueRequest(soap);

        Assert.Equal(der, parsed.Pkcs10Der);
        Assert.Equal("urn:uuid:abc-123", parsed.MessageId);
        Assert.Equal("42", parsed.RequestId);
        Assert.False(parsed.FromCmc);
        // The DER round-trips into a real CSR, so what the parser hands the issuer is enrollable.
        var csr = CertificateRequest.LoadSigningRequest(parsed.Pkcs10Der, HashAlgorithmName.SHA256);
        Assert.Equal("CN=device-01.example.test", csr.SubjectName.Name);
    }

    [Fact]
    public void Recognises_the_older_WSS_X509_pkcs10_value_type_too()
    {
        // A client may namespace the PKCS#10 under the WSS X.509 token profile rather than the
        // enrollment URI. Only the "#PKCS10" suffix is meaningful.
        var der = SamplePkcs10();
        var soap = RstEnvelope(Convert.ToBase64String(der), null, null,
            pkcs10ValueType: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#PKCS10");

        Assert.Equal(der, WstepMessages.ParseIssueRequest(soap).Pkcs10Der);
    }

    [Fact]
    public void A_pkcs10_token_wins_over_a_pkcs7_beside_it()
    {
        var der = SamplePkcs10();
        var soap = RstEnvelope(Convert.ToBase64String(der), null, null,
            extraPkcs7B64: Convert.ToBase64String(new byte[] { 1, 2, 3, 4 }));

        var parsed = WstepMessages.ParseIssueRequest(soap);
        Assert.False(parsed.FromCmc);
        Assert.Equal(der, parsed.Pkcs10Der);
    }

    [Fact]
    public void A_cmc_request_from_a_windows_client_unwraps_to_its_pkcs10()
    {
        // Captured from Get-Certificate on Windows 11 against a stand-in policy server: a
        // #PKCS7 token holding a CMS SignedData over a PKIData, signed with the new key and
        // identified by subject key identifier, with no certificate. This is what the
        // autoenrollment engine sends, and it is not a bare PKCS#10.
        var soap = RstEnvelope(CmcRequestsTests.WindowsCmcRequestBase64, null, null,
            pkcs10ValueType: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#PKCS7");

        var parsed = WstepMessages.ParseIssueRequest(soap);

        Assert.True(parsed.FromCmc);
        var csr = CertificateRequest.LoadSigningRequest(parsed.Pkcs10Der, HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);
        Assert.Equal("", csr.SubjectName.Name);   // the client left the subject for the CA to fill in
        Assert.Contains(csr.CertificateExtensions, e => e.Oid?.Value == "1.3.6.1.4.1.311.21.7");
    }

    [Fact]
    public void A_pkcs7_that_is_not_a_cmc_request_is_refused()
    {
        // A certs-only PKCS#7, the shape the server itself returns, carries no request.
        using var cert = TestCertificates.CreateCa();
        var certsOnly = ModularCA.Shared.Utils.Pkcs7Util.BuildCertsOnly(
            [new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(cert.RawData)]);
        var soap = RstEnvelope(Convert.ToBase64String(certsOnly), null, null,
            pkcs10ValueType: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#PKCS7");

        var ex = Assert.Throws<WstepMessages.WstepParseException>(() => WstepMessages.ParseIssueRequest(soap));
        Assert.Contains("PKIData", ex.Message);
    }

    [Fact]
    public void Absent_correlation_fields_come_back_null_not_empty()
    {
        var soap = RstEnvelope(Convert.ToBase64String(SamplePkcs10()), messageId: null, requestId: null);
        var parsed = WstepMessages.ParseIssueRequest(soap);
        Assert.Null(parsed.MessageId);
        Assert.Null(parsed.RequestId);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void An_empty_body_is_refused(string soap)
    {
        Assert.Throws<WstepMessages.WstepParseException>(() => WstepMessages.ParseIssueRequest(soap));
    }

    [Fact]
    public void A_request_with_no_pkcs10_is_refused()
    {
        var soap = $@"<s:Envelope xmlns:s=""{WstepMessages.Soap12}""><s:Body>
            <wst:RequestSecurityToken xmlns:wst=""{WstepMessages.WsTrust}"">
              <wst:RequestType>{WstepMessages.IssueRequestType}</wst:RequestType>
            </wst:RequestSecurityToken></s:Body></s:Envelope>";
        var ex = Assert.Throws<WstepMessages.WstepParseException>(() => WstepMessages.ParseIssueRequest(soap));
        Assert.Contains("PKCS#10", ex.Message);
    }

    [Fact]
    public void A_doctype_is_refused_even_when_the_rest_of_the_request_is_valid()
    {
        // Pins DtdProcessing.Prohibit specifically, independent of the entity-expansion limit: this
        // envelope carries a perfectly good PKCS#10 and would parse if DTDs were merely allowed
        // through, so the only reason to reject it is that a DOCTYPE appeared at all. A parser that
        // tolerates the DTD here would accept a document type declaration on unauthenticated input.
        var der = SamplePkcs10();
        var body = RstEnvelope(Convert.ToBase64String(der), null, null);
        var withDoctype = "<?xml version=\"1.0\"?>\n<!DOCTYPE s:Envelope>\n" + body;
        Assert.Throws<WstepMessages.WstepParseException>(() => WstepMessages.ParseIssueRequest(withDoctype));
    }

    [Fact]
    public void A_pkcs10_token_that_is_not_base64_is_refused()
    {
        var soap = RstEnvelope("!!! not base64 !!!", null, null);
        Assert.Throws<WstepMessages.WstepParseException>(() => WstepMessages.ParseIssueRequest(soap));
    }

    [Fact]
    public void A_dtd_is_refused_rather_than_processed()
    {
        // Hostile XML on unauthenticated input. A parser that expands entities or fetches a DTD is
        // a denial-of-service and SSRF surface; this must refuse, not resolve.
        var soap = $@"<?xml version=""1.0""?>
            <!DOCTYPE Envelope [ <!ENTITY xxe ""boom""> ]>
            <s:Envelope xmlns:s=""{WstepMessages.Soap12}""><s:Body>&xxe;</s:Body></s:Envelope>";
        Assert.Throws<WstepMessages.WstepParseException>(() => WstepMessages.ParseIssueRequest(soap));
    }

    [Fact]
    public void The_response_carries_the_certificate_where_a_client_reads_it()
    {
        var cert = new byte[] { 9, 8, 7, 6, 5 };  // stands in for a certs-only PKCS#7
        var xml = WstepMessages.BuildIssueResponse(cert, relatesToMessageId: "urn:uuid:abc-123", requestId: "42");

        var doc = XDocument.Parse(xml);
        XNamespace t = WstepMessages.WsTrust, o = WstepMessages.Wsse, a = WstepMessages.Wsa, e = WstepMessages.Enrollment;

        // The collection wrapper and a single response inside it.
        Assert.NotNull(doc.Descendants(t + "RequestSecurityTokenResponseCollection").SingleOrDefault());
        var b64 = Convert.ToBase64String(cert);

        // Present as a wsse:BinarySecurityToken directly under the response and again inside
        // RequestedSecurityToken, both with the EncodingType MS-WSTEP prescribes. certreq
        // rejected a response whose direct token sat in the WS-Trust namespace with the
        // WS-Security "#Base64Binary" encoding URI as WS_E_INVALID_FORMAT; this pins the fix.
        var rstr = doc.Descendants(t + "RequestSecurityTokenResponse").Single();
        var direct = Assert.Single(rstr.Elements(o + "BinarySecurityToken"));
        Assert.Equal(b64, direct.Value.Trim());
        Assert.Equal(WstepMessages.ResponseEncodingBase64, (string?)direct.Attribute("EncodingType"));
        Assert.Equal(WstepMessages.Pkcs7ValueType, (string?)direct.Attribute("ValueType"));
        Assert.Empty(doc.Descendants(t + "BinarySecurityToken"));
        var requested = doc.Descendants(t + "RequestedSecurityToken").Single();
        var inner = requested.Descendants(o + "BinarySecurityToken").Single();
        Assert.Equal(b64, inner.Value.Trim());
        Assert.Equal(WstepMessages.ResponseEncodingBase64, (string?)inner.Attribute("EncodingType"));

        // Elements in the order Microsoft's CES emits them; a positional reader depends on it.
        Assert.Equal(["TokenType", "DispositionMessage", "BinarySecurityToken", "RequestedSecurityToken", "RequestID"],
            rstr.Elements().Select(el => el.Name.LocalName).ToArray());
        Assert.Equal("en-US", (string?)doc.Descendants(e + "DispositionMessage").Single().Attribute(XNamespace.Xml + "lang"));

        // Correlation echoed, disposition stated, response action set.
        Assert.Equal("urn:uuid:abc-123", doc.Descendants(a + "RelatesTo").Single().Value);
        Assert.Equal("42", doc.Descendants(e + "RequestID").Single().Value);
        Assert.Equal("Issued", doc.Descendants(e + "DispositionMessage").Single().Value);
        Assert.Equal(WstepMessages.ResponseAction, doc.Descendants(a + "Action").Single().Value);
    }

    [Fact]
    public void The_response_carries_a_security_timestamp_that_is_valid_now()
    {
        // WCF on the UserName-over-transport binding expects a wsse:Security header with a
        // wsu:Timestamp in the reply and checks that the current time is inside its window.
        var before = DateTime.UtcNow.AddSeconds(-1);
        var xml = WstepMessages.BuildIssueResponse(new byte[] { 1 }, null, null);
        var after = DateTime.UtcNow.AddSeconds(1);

        var doc = XDocument.Parse(xml);
        XNamespace s = WstepMessages.Soap12, o = WstepMessages.Wsse, u = WstepMessages.Wsu;
        var security = doc.Root!.Element(s + "Header")!.Element(o + "Security");
        Assert.NotNull(security);
        Assert.Equal("1", (string?)security!.Attribute(s + "mustUnderstand"));

        var timestamp = security.Element(u + "Timestamp")!;
        var created = DateTime.Parse(timestamp.Element(u + "Created")!.Value, null, System.Globalization.DateTimeStyles.AdjustToUniversal);
        var expires = DateTime.Parse(timestamp.Element(u + "Expires")!.Value, null, System.Globalization.DateTimeStyles.AdjustToUniversal);
        Assert.InRange(created, before, after);
        Assert.True(expires > created, "Expires must be after Created");
        Assert.InRange(expires - created, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(15));
    }

    [Fact]
    public void The_security_timestamp_is_formatted_as_utc_xsd_datetime()
    {
        // WS-Security utility says xsd:dateTime in UTC with a trailing Z; WCF is strict about it.
        var fixedInstant = new DateTime(2026, 9, 13, 14, 30, 5, 250, DateTimeKind.Utc);
        var element = WstepMessages.SecurityTimestamp(fixedInstant);
        XNamespace u = WstepMessages.Wsu;
        Assert.Equal("2026-09-13T14:30:05.250Z", element.Descendants(u + "Created").Single().Value);
        Assert.Equal("2026-09-13T14:35:05.250Z", element.Descendants(u + "Expires").Single().Value);
    }

    [Fact]
    public void The_response_omits_correlation_when_the_request_had_none()
    {
        var xml = WstepMessages.BuildIssueResponse(new byte[] { 1 }, relatesToMessageId: null, requestId: null);
        var doc = XDocument.Parse(xml);
        Assert.Empty(doc.Descendants(XName.Get("RelatesTo", WstepMessages.Wsa)));
        Assert.Empty(doc.Descendants(XName.Get("RequestID", WstepMessages.Enrollment)));
    }

    [Fact]
    public void An_empty_certificate_is_a_programming_error_not_a_response()
    {
        Assert.Throws<ArgumentException>(() => WstepMessages.BuildIssueResponse([], null, null));
    }

    [Fact]
    public void A_round_trip_request_then_response_is_coherent()
    {
        var der = SamplePkcs10();
        var request = WstepMessages.ParseIssueRequest(RstEnvelope(Convert.ToBase64String(der), "mid-9", "rid-9"));
        var responseXml = WstepMessages.BuildIssueResponse(new byte[] { 42 }, request.MessageId, request.RequestId);
        var doc = XDocument.Parse(responseXml);
        Assert.Equal("mid-9", doc.Descendants(XName.Get("RelatesTo", WstepMessages.Wsa)).Single().Value);
        Assert.Equal("rid-9", doc.Descendants(XName.Get("RequestID", WstepMessages.Enrollment)).Single().Value);
    }

    [Fact]
    public void A_fault_is_well_formed_soap_with_the_reason()
    {
        var xml = WstepMessages.BuildFault("template not permitted", relatesToMessageId: "mid-1");
        var doc = XDocument.Parse(xml);
        XNamespace s = WstepMessages.Soap12;
        Assert.NotNull(doc.Descendants(s + "Fault").SingleOrDefault());
        Assert.Contains("template not permitted", doc.Descendants(s + "Text").Single().Value);
        Assert.Equal("mid-1", doc.Descendants(XName.Get("RelatesTo", WstepMessages.Wsa)).Single().Value);
    }

    [Fact]
    public void A_fault_is_coded_receiver_by_default_and_sender_when_the_client_caused_it()
    {
        // SOAP 1.2 section 5.4.6: Sender means "do not resend without change", Receiver means
        // "the server could not process it right now". A client's retry behaviour follows the code,
        // so a refused policy must not be reported as a transient server failure.
        XNamespace s = WstepMessages.Soap12;
        var receiver = XDocument.Parse(WstepMessages.BuildFault("boom"));
        Assert.Equal("s:Receiver", receiver.Descendants(s + "Value").Single().Value);

        var sender = XDocument.Parse(WstepMessages.BuildFault("bad credentials", senderFault: true));
        Assert.Equal("s:Sender", sender.Descendants(s + "Value").Single().Value);
    }

    // The WS-Security header a Windows client sends when CES is configured for username
    // authentication (WCF TransportWithMessageCredential with UserName client credentials).
    private static string UsernameTokenHeader(string username, string password, string? passwordType)
    {
        var typeAttr = passwordType == null ? "" : $" Type=\"{passwordType}\"";
        return $@"<wsse:Security s:mustUnderstand=""1"">
              <wsse:UsernameToken>
                <wsse:Username>{username}</wsse:Username>
                <wsse:Password{typeAttr}>{password}</wsse:Password>
              </wsse:UsernameToken>
            </wsse:Security>";
    }

    private const string PasswordText =
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText";
    private const string PasswordDigest =
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest";

    [Theory]
    [InlineData(PasswordText)]
    [InlineData(null)]
    public void A_clear_text_username_token_is_returned_as_the_credential(string? passwordType)
    {
        // The Type attribute is optional in the profile and defaults to PasswordText; both
        // spellings of "clear text" must yield the credential.
        var soap = RstEnvelope(Convert.ToBase64String(SamplePkcs10()), null, null,
            securityHeader: UsernameTokenHeader("svc-enroll", "hunter2", passwordType));

        var parsed = WstepMessages.ParseIssueRequest(soap);

        Assert.NotNull(parsed.UsernameToken);
        Assert.Equal("svc-enroll", parsed.UsernameToken!.Username);
        Assert.Equal("hunter2", parsed.UsernameToken.Password);
    }

    [Fact]
    public void A_digest_password_is_not_treated_as_a_credential()
    {
        // A digest cannot be verified against a stored password hash. Reporting it as a
        // credential would hand a base64 digest to the password check as if it were the
        // password, which fails, but fails after a lockout counter increments for the user.
        var soap = RstEnvelope(Convert.ToBase64String(SamplePkcs10()), null, null,
            securityHeader: UsernameTokenHeader("svc-enroll", "c2FsdGVkLWRpZ2VzdA==", PasswordDigest));

        Assert.Null(WstepMessages.ParseIssueRequest(soap).UsernameToken);
    }

    [Fact]
    public void A_username_token_missing_either_field_is_ignored()
    {
        var noPassword = RstEnvelope(Convert.ToBase64String(SamplePkcs10()), null, null,
            securityHeader: @"<wsse:Security><wsse:UsernameToken><wsse:Username>svc</wsse:Username></wsse:UsernameToken></wsse:Security>");
        Assert.Null(WstepMessages.ParseIssueRequest(noPassword).UsernameToken);

        var noUsername = RstEnvelope(Convert.ToBase64String(SamplePkcs10()), null, null,
            securityHeader: @"<wsse:Security><wsse:UsernameToken><wsse:Password>pw</wsse:Password></wsse:UsernameToken></wsse:Security>");
        Assert.Null(WstepMessages.ParseIssueRequest(noUsername).UsernameToken);
    }

    [Fact]
    public void No_security_header_means_no_username_token()
    {
        var parsed = WstepMessages.ParseIssueRequest(RstEnvelope(Convert.ToBase64String(SamplePkcs10()), null, null));
        Assert.Null(parsed.UsernameToken);
    }

    [Fact]
    public void The_kerberos_token_is_read_from_the_security_header_only()
    {
        const string wsse = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
        var bytes = new byte[] { 0x60, 0x05, 1, 2, 3, 4, 5 };
        var b64 = Convert.ToBase64String(bytes);
        string Envelope(string valueType, string bodyToken) => $@"<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope' xmlns:o='{wsse}'>
  <s:Header><o:Security><o:BinarySecurityToken ValueType='{valueType}' EncodingType='x#Base64Binary'>{b64}</o:BinarySecurityToken></o:Security></s:Header>
  <s:Body><o:BinarySecurityToken ValueType='http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10'>{bodyToken}</o:BinarySecurityToken></s:Body>
</s:Envelope>";

        var gss = WstepMessages.ReadKerberosToken(XDocument.Parse(Envelope("http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#GSS_Kerberosv5_AP_REQ", "QUJD")));
        Assert.NotNull(gss);
        Assert.True(gss!.GssFramed);
        Assert.Equal(bytes, gss.Token);

        var bare = WstepMessages.ReadKerberosToken(XDocument.Parse(Envelope("http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#Kerberosv5_AP_REQ", "QUJD")));
        Assert.False(bare!.GssFramed);

        // A PKCS#10 token in the body is never taken for a Kerberos token, and a header without one yields null.
        Assert.Null(WstepMessages.ReadKerberosToken(XDocument.Parse(Envelope("x#SomethingElse", b64))));
    }

    [Fact]
    public void A_status_query_names_its_request_and_carries_no_pkcs10()
    {
        var soap = """
            <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">
              <s:Header><a:MessageID>urn:uuid:11111111-2222-3333-4444-555555555555</a:MessageID></s:Header>
              <s:Body>
                <wst:RequestSecurityToken xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512" xmlns:enr="http://schemas.microsoft.com/windows/pki/2009/01/enrollment">
                  <wst:TokenType>http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3</wst:TokenType>
                  <wst:RequestType>http://schemas.microsoft.com/windows/pki/2009/01/enrollment/QueryTokenStatus</wst:RequestType>
                  <enr:RequestID>7d3d2d8e-9d3a-4a0c-9d0a-0f9a1b2c3d4e</enr:RequestID>
                </wst:RequestSecurityToken>
              </s:Body>
            </s:Envelope>
            """;
        var request = WstepMessages.ParseIssueRequest(soap);
        Assert.True(request.IsStatusQuery);
        Assert.Equal("7d3d2d8e-9d3a-4a0c-9d0a-0f9a1b2c3d4e", request.RequestId);
        Assert.Equal("urn:uuid:11111111-2222-3333-4444-555555555555", request.MessageId);
        Assert.Empty(request.Pkcs10Der);

        // Without an id there is nothing to ask after.
        var withoutId = soap.Replace("<enr:RequestID>7d3d2d8e-9d3a-4a0c-9d0a-0f9a1b2c3d4e</enr:RequestID>", "");
        Assert.Throws<WstepMessages.WstepParseException>(() => WstepMessages.ParseIssueRequest(withoutId));

        // An unknown request type is refused rather than treated as an Issue.
        var odd = soap.Replace("enrollment/QueryTokenStatus", "enrollment/Renew");
        Assert.Throws<WstepMessages.WstepParseException>(() => WstepMessages.ParseIssueRequest(odd));
    }

    [Fact]
    public void A_pending_response_carries_the_disposition_a_cmc_pending_status_the_collection_point_and_the_request_id()
    {
        var xml = WstepMessages.BuildPendingResponse("urn:uuid:abc", "7d3d2d8e-9d3a-4a0c-9d0a-0f9a1b2c3d4e", "https://ca.example.test/msae/lab/ces");
        var doc = System.Xml.Linq.XDocument.Parse(xml);
        System.Xml.Linq.XNamespace t = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
        System.Xml.Linq.XNamespace e = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment";
        System.Xml.Linq.XNamespace a = "http://www.w3.org/2005/08/addressing";
        System.Xml.Linq.XNamespace o = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
        var rstr = Assert.Single(doc.Descendants(t + "RequestSecurityTokenResponse"));
        Assert.Equal(WstepMessages.PendingDisposition, rstr.Element(e + "DispositionMessage")!.Value);
        Assert.Equal("7d3d2d8e-9d3a-4a0c-9d0a-0f9a1b2c3d4e", rstr.Element(e + "RequestID")!.Value);
        Assert.Equal("urn:uuid:abc", doc.Descendants(a + "RelatesTo").Single().Value);

        // Where to collect: the service itself.
        var reference = rstr.Element(t + "RequestedSecurityToken")!.Element(o + "SecurityTokenReference")!.Element(o + "Reference")!;
        Assert.Equal("https://ca.example.test/msae/lab/ces", reference.Attribute("URI")!.Value);

        // The CMC full PKI response: status pending, body part 1, pend token = the request id.
        var token = Assert.Single(rstr.Elements(o + "BinarySecurityToken"));
        Assert.Equal(WstepMessages.Pkcs7ValueType, token.Attribute("ValueType")!.Value);
        var cms = new Org.BouncyCastle.Cms.CmsSignedData(Convert.FromBase64String(token.Value));
        Assert.Equal(CmcResponses.PkiResponseOid, cms.SignedContentType.Id);
        using var buffer = new MemoryStream();
        cms.SignedContent!.Write(buffer);
        var response = Org.BouncyCastle.Asn1.Asn1Sequence.GetInstance(Org.BouncyCastle.Asn1.Asn1Object.FromByteArray(buffer.ToArray()));
        var control = Org.BouncyCastle.Asn1.Asn1Sequence.GetInstance(Org.BouncyCastle.Asn1.Asn1Sequence.GetInstance(response[0])[0]);
        Assert.Equal(CmcResponses.StatusInfoV2Oid, Org.BouncyCastle.Asn1.DerObjectIdentifier.GetInstance(control[1]).Id);
        var status = Org.BouncyCastle.Asn1.Asn1Sequence.GetInstance(Org.BouncyCastle.Asn1.Asn1Set.GetInstance(control[2])[0]);
        Assert.Equal(CmcResponses.StatusPending, Org.BouncyCastle.Asn1.DerInteger.GetInstance(status[0]).IntValueExact);
        Assert.Equal(CmcResponses.RequestBodyPartId, Org.BouncyCastle.Asn1.DerInteger.GetInstance(Org.BouncyCastle.Asn1.Asn1Sequence.GetInstance(status[1])[0]).IntValueExact);
        var pendInfo = Org.BouncyCastle.Asn1.Asn1Sequence.GetInstance(status[3]);
        Assert.Equal("7d3d2d8e-9d3a-4a0c-9d0a-0f9a1b2c3d4e", System.Text.Encoding.UTF8.GetString(Org.BouncyCastle.Asn1.Asn1OctetString.GetInstance(pendInfo[0]).GetOctets()));
    }
}
