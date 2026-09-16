using System.Xml.Linq;
using ModularCA.Core.Services.Msae;
using Xunit;

namespace ModularCA.Tests.Core.Services.Msae;

/// <summary>
/// Pins the MS-XCEP wire format: what is read from a client's GetPolicies request and the exact
/// shape of the GetPoliciesResponse, including element order and the OID reference table, which
/// a WCF client deserialises positionally.
/// </summary>
public class XcepMessagesTests
{
    private static readonly XNamespace X = XcepMessages.Xcep;
    private static readonly XNamespace Xsi = XcepMessages.Xsi;

    private static string GetPoliciesEnvelope(string? messageId = null, string? lastUpdate = null,
        string? language = "en-US", string? securityHeader = null)
    {
        var mid = messageId == null ? "" : $"<a:MessageID>{messageId}</a:MessageID>";
        var last = lastUpdate == null
            ? "<lastUpdate xsi:nil=\"true\"/>"
            : $"<lastUpdate>{lastUpdate}</lastUpdate>";
        var lang = language == null ? "<preferredLanguage xsi:nil=\"true\"/>" : $"<preferredLanguage>{language}</preferredLanguage>";
        return $@"<s:Envelope xmlns:s=""{WstepMessages.Soap12}"" xmlns:a=""{WstepMessages.Wsa}""
                   xmlns:wsse=""{WstepMessages.Wsse}"" xmlns:xsi=""{XcepMessages.Xsi}"">
  <s:Header>
    <a:Action s:mustUnderstand=""1"">{XcepMessages.GetPoliciesAction}</a:Action>
    {mid}{securityHeader}
  </s:Header>
  <s:Body>
    <GetPolicies xmlns=""{XcepMessages.Xcep}"">
      <client>{last}{lang}</client>
      <requestFilter xsi:nil=""true""/>
    </GetPolicies>
  </s:Body>
</s:Envelope>";
    }

    private static XcepMessages.PolicySet SamplePolicy(bool enroll = true) => new(
        PolicyId: new Guid("11111111-2222-3333-4444-555555555555"),
        FriendlyName: "Lab CA (ModularCA)",
        NextUpdateHours: 8,
        Cas: [new XcepMessages.PolicyCa(0, "https://ca.example.test/msae/lab/ces", [0x30, 0x03, 0x02, 0x01, 0x01], enroll)],
        Templates:
        [
            new XcepMessages.PolicyTemplate(
                Name: "LabDevice", Oid: "2.25.100", MajorVersion: 100, MinorVersion: 3,
                ValiditySeconds: 31_536_000, RenewalSeconds: 6_307_200,
                Enroll: enroll, AutoEnroll: false, CaBuiltSubject: false, MinimalKeyLength: 2048, MachineType: true, ExportableKey: false,
                HashAlgorithmOid: "2.16.840.1.101.3.4.2.1", HashAlgorithmName: "sha256", PublicKeyAlgorithmOid: "1.2.840.113549.1.1.1", PublicKeyAlgorithmName: "RSA",
                Extensions:
                [
                    new XcepMessages.PolicyExtension("2.5.29.15", "Key Usage", true, [0x03, 0x02, 0x05, 0xA0]),
                    new XcepMessages.PolicyExtension("2.5.29.37", "Enhanced Key Usage", false, [0x30, 0x00]),
                ],
                CaReferenceIds: [0]),
            new XcepMessages.PolicyTemplate(
                Name: "LabUser", Oid: "2.25.200", MajorVersion: 100, MinorVersion: 0,
                ValiditySeconds: 7_776_000, RenewalSeconds: 1_555_200,
                Enroll: enroll, AutoEnroll: false, CaBuiltSubject: false, MinimalKeyLength: 3072, MachineType: false, ExportableKey: false,
                HashAlgorithmOid: "2.16.840.1.101.3.4.2.1", HashAlgorithmName: "sha256", PublicKeyAlgorithmOid: "1.2.840.113549.1.1.1", PublicKeyAlgorithmName: "RSA",
                Extensions: [new XcepMessages.PolicyExtension("2.5.29.37", "Enhanced Key Usage", false, [0x30, 0x00])],
                CaReferenceIds: [0]),
        ]);

    [Fact]
    public void Parses_the_client_fields_and_correlation_id()
    {
        var soap = GetPoliciesEnvelope(messageId: "urn:uuid:9", lastUpdate: "2026-09-13T10:00:00Z");
        var parsed = XcepMessages.ParseGetPolicies(soap);

        Assert.Equal("urn:uuid:9", parsed.MessageId);
        Assert.Equal(new DateTime(2026, 9, 13, 10, 0, 0, DateTimeKind.Utc), parsed.LastUpdate);
        Assert.Equal("en-US", parsed.PreferredLanguage);
        Assert.Null(parsed.UsernameToken);
    }

    [Fact]
    public void A_first_fetch_has_no_last_update()
    {
        var parsed = XcepMessages.ParseGetPolicies(GetPoliciesEnvelope(language: null));
        Assert.Null(parsed.LastUpdate);
        Assert.Null(parsed.PreferredLanguage);
        Assert.Null(parsed.MessageId);
    }

    [Fact]
    public void The_username_token_is_read_from_the_security_header()
    {
        var security = @"<wsse:Security s:mustUnderstand=""1""><wsse:UsernameToken>
            <wsse:Username>svc-enroll</wsse:Username><wsse:Password>hunter2</wsse:Password>
            </wsse:UsernameToken></wsse:Security>";
        var parsed = XcepMessages.ParseGetPolicies(GetPoliciesEnvelope(securityHeader: security));
        Assert.Equal(new WstepMessages.WstepUsernameToken("svc-enroll", "hunter2"), parsed.UsernameToken);
    }

    [Fact]
    public void A_body_without_GetPolicies_is_refused()
    {
        var soap = $@"<s:Envelope xmlns:s=""{WstepMessages.Soap12}""><s:Body><Other/></s:Body></s:Envelope>";
        var ex = Assert.Throws<WstepMessages.WstepParseException>(() => XcepMessages.ParseGetPolicies(soap));
        Assert.Contains("GetPolicies", ex.Message);
    }

    [Fact]
    public void Hostile_xml_is_refused_the_same_way_as_on_the_enrollment_endpoint()
    {
        var withDoctype = "<?xml version=\"1.0\"?>\n<!DOCTYPE s:Envelope>\n" + GetPoliciesEnvelope();
        Assert.Throws<WstepMessages.WstepParseException>(() => XcepMessages.ParseGetPolicies(withDoctype));
        Assert.Throws<WstepMessages.WstepParseException>(() => XcepMessages.ParseGetPolicies("  "));
    }

    [Fact]
    public void The_response_names_the_policy_and_correlates_to_the_request()
    {
        var doc = XDocument.Parse(XcepMessages.BuildGetPoliciesResponse(SamplePolicy(), "urn:uuid:9"));
        XNamespace a = WstepMessages.Wsa;

        Assert.Equal(XcepMessages.GetPoliciesResponseAction, doc.Descendants(a + "Action").Single().Value);
        Assert.Equal("urn:uuid:9", doc.Descendants(a + "RelatesTo").Single().Value);
        Assert.NotNull(doc.Descendants(XName.Get("Timestamp", WstepMessages.Wsu)).SingleOrDefault());

        var response = doc.Descendants(X + "GetPoliciesResponse").Single().Element(X + "response")!;
        Assert.Equal("{11111111-2222-3333-4444-555555555555}", response.Element(X + "policyID")!.Value);
        Assert.Equal("Lab CA (ModularCA)", response.Element(X + "policyFriendlyName")!.Value);
        Assert.Equal("8", response.Element(X + "nextUpdateHours")!.Value);
        Assert.Equal("true", (string?)response.Element(X + "policiesNotChanged")!.Attribute(Xsi + "nil"));
    }

    [Fact]
    public void Each_template_is_a_policy_whose_attributes_are_in_schema_order()
    {
        var doc = XDocument.Parse(XcepMessages.BuildGetPoliciesResponse(SamplePolicy(), null));
        var policies = doc.Descendants(X + "policy").ToList();
        Assert.Equal(2, policies.Count);

        var device = policies[0].Element(X + "attributes")!;
        Assert.Equal(
            ["commonName", "policySchema", "certificateValidity", "permission", "privateKeyAttributes", "revision",
             "supersededPolicies", "privateKeyFlags", "subjectNameFlags", "enrollmentFlags", "generalFlags",
             "hashAlgorithmOIDReference", "rARequirements", "keyArchivalAttributes", "extensions"],
            device.Elements().Select(e => e.Name.LocalName).ToArray());

        Assert.Equal("LabDevice", device.Element(X + "commonName")!.Value);
        Assert.Equal("3", device.Element(X + "policySchema")!.Value);   // CNG template: names hash and key algorithm
        Assert.Equal("31536000", device.Element(X + "certificateValidity")!.Element(X + "validityPeriodSeconds")!.Value);
        Assert.Equal("6307200", device.Element(X + "certificateValidity")!.Element(X + "renewalPeriodSeconds")!.Value);
        Assert.Equal("true", device.Element(X + "permission")!.Element(X + "enroll")!.Value);
        Assert.Equal("false", device.Element(X + "permission")!.Element(X + "autoEnroll")!.Value);
        Assert.Equal("2048", device.Element(X + "privateKeyAttributes")!.Element(X + "minimalKeyLength")!.Value);
        Assert.Equal("1", device.Element(X + "privateKeyAttributes")!.Element(X + "keySpec")!.Value);
        Assert.Equal("100", device.Element(X + "revision")!.Element(X + "majorRevision")!.Value);
        Assert.Equal("3", device.Element(X + "revision")!.Element(X + "minorRevision")!.Value);
        Assert.Equal("0", device.Element(X + "privateKeyFlags")!.Value);
        Assert.Equal("1", device.Element(X + "subjectNameFlags")!.Value);     // enrollee supplies subject
        Assert.Equal("0", device.Element(X + "enrollmentFlags")!.Value);
        Assert.Equal("64", device.Element(X + "generalFlags")!.Value);        // CT_FLAG_MACHINE_TYPE
        // A schema-3 template names its hash algorithm; a schema-2 one signed with SHA-1, which
        // the certificate profiles refuse. The reference resolves in the OID table below.
        Assert.False(string.IsNullOrEmpty(device.Element(X + "hashAlgorithmOIDReference")!.Value));
        Assert.False(string.IsNullOrEmpty(device.Element(X + "privateKeyAttributes")!.Element(X + "algorithmOIDReference")!.Value));

        var user = policies[1].Element(X + "attributes")!;
        Assert.Equal("0", user.Element(X + "generalFlags")!.Value);           // a user template
        Assert.Equal("3072", user.Element(X + "privateKeyAttributes")!.Element(X + "minimalKeyLength")!.Value);
    }

    [Fact]
    public void Every_reference_resolves_to_one_row_in_the_oid_table_with_the_right_group()
    {
        var doc = XDocument.Parse(XcepMessages.BuildGetPoliciesResponse(SamplePolicy(), null));
        var rows = doc.Descendants(X + "oID").ToDictionary(
            o => int.Parse(o.Element(X + "oIDReferenceID")!.Value),
            o => (Value: o.Element(X + "value")!.Value, Group: int.Parse(o.Element(X + "group")!.Value), Name: o.Element(X + "defaultName")!.Value));

        // Ids are dense from 1 and each OID appears once even when several templates use it.
        Assert.Equal(Enumerable.Range(1, rows.Count), rows.Keys.Order());
        Assert.Equal(rows.Count, rows.Values.Select(r => r.Value).Distinct().Count());

        var policies = doc.Descendants(X + "policy").ToList();
        var deviceRef = int.Parse(policies[0].Element(X + "policyOIDReference")!.Value);
        Assert.Equal(("2.25.100", XcepMessages.OidGroupTemplate, "LabDevice"), rows[deviceRef]);
        var userRef = int.Parse(policies[1].Element(X + "policyOIDReference")!.Value);
        Assert.Equal(("2.25.200", XcepMessages.OidGroupTemplate, "LabUser"), rows[userRef]);

        var hashRef = int.Parse(policies[0].Element(X + "attributes")!.Element(X + "hashAlgorithmOIDReference")!.Value);
        Assert.Equal(("2.16.840.1.101.3.4.2.1", XcepMessages.OidGroupHashAlgorithm, "sha256"), rows[hashRef]);
        var keyAlgRef = int.Parse(policies[0].Element(X + "attributes")!.Element(X + "privateKeyAttributes")!.Element(X + "algorithmOIDReference")!.Value);
        Assert.Equal(("1.2.840.113549.1.1.1", XcepMessages.OidGroupPublicKeyAlgorithm, "RSA"), rows[keyAlgRef]);

        var extRefs = doc.Descendants(X + "extension").Select(e => int.Parse(e.Element(X + "oIDReference")!.Value)).ToList();
        Assert.Equal(3, extRefs.Count);
        Assert.All(extRefs, r => Assert.Equal(XcepMessages.OidGroupExtension, rows[r].Group));
        // The EKU extension on both templates points at the same row.
        Assert.Equal(extRefs[1], extRefs[2]);
        Assert.Equal("2.5.29.37", rows[extRefs[1]].Value);
    }

    [Fact]
    public void Extensions_carry_their_value_and_criticality()
    {
        var doc = XDocument.Parse(XcepMessages.BuildGetPoliciesResponse(SamplePolicy(), null));
        var keyUsage = doc.Descendants(X + "extension").First();
        Assert.Equal("true", keyUsage.Element(X + "critical")!.Value);
        Assert.Equal(Convert.ToBase64String([0x03, 0x02, 0x05, 0xA0]), keyUsage.Element(X + "value")!.Value);
    }

    [Fact]
    public void The_ca_is_advertised_with_its_certificate_and_a_username_password_ces_url()
    {
        var doc = XDocument.Parse(XcepMessages.BuildGetPoliciesResponse(SamplePolicy(enroll: false), null));
        var ca = doc.Descendants(X + "cA").Single();
        var uri = ca.Element(X + "uris")!.Element(X + "cAURI")!;
        Assert.Equal(XcepMessages.AuthUsernamePassword.ToString(), uri.Element(X + "clientAuthentication")!.Value);
        Assert.Equal("https://ca.example.test/msae/lab/ces", uri.Element(X + "uri")!.Value);
        Assert.Equal("1", uri.Element(X + "priority")!.Value);
        Assert.Equal("false", uri.Element(X + "renewalOnly")!.Value);
        Assert.Equal(Convert.ToBase64String([0x30, 0x03, 0x02, 0x01, 0x01]), ca.Element(X + "certificate")!.Value);
        Assert.Equal("false", ca.Element(X + "enrollPermission")!.Value);
        Assert.Equal("0", ca.Element(X + "cAReferenceID")!.Value);

        // And each policy points at that CA by reference.
        Assert.All(doc.Descendants(X + "cAReference"), r => Assert.Equal("0", r.Value));
        Assert.All(doc.Descendants(X + "enroll"), e => Assert.Equal("false", e.Value));
    }

    [Fact]
    public void A_ca_with_no_offered_templates_still_answers()
    {
        var empty = SamplePolicy() with { Templates = [] };
        var doc = XDocument.Parse(XcepMessages.BuildGetPoliciesResponse(empty, null));
        Assert.Empty(doc.Descendants(X + "policy"));
        Assert.NotNull(doc.Descendants(X + "policies").SingleOrDefault());
        Assert.Empty(doc.Descendants(X + "oID"));
    }
}
