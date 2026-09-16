using System.Xml.Linq;

namespace ModularCA.Core.Services.Msae;

/// <summary>
/// The SOAP wire format of the Certificate Enrollment Policy Web Service (MS-XCEP): parsing a
/// client's <c>GetPolicies</c> request and building the <c>GetPoliciesResponse</c> that tells it
/// which templates exist, what they contain, and where to enroll.
/// </summary>
/// <remarks>
/// <para>
/// A Windows client asks the policy service before it enrolls, whether driven by Group Policy
/// autoenrollment or by <c>certreq -PolicyServer</c>. The response is the client's whole view of
/// this CA: the templates it may request (each identified by OID, with the key, validity and
/// extensions the certificate will carry), the CAs that issue them with the enrollment URL and
/// authentication type of each, and a table of every OID the response refers to. The client
/// caches it by <c>policyID</c> and re-asks after <c>nextUpdateHours</c>.
/// </para>
/// <para>
/// The element order inside each structure follows the MS-XCEP schema exactly. A WCF client
/// deserialises by order, not by name, so a misplaced element does not produce an error; it
/// produces a template with the wrong values. Absent optional elements are written with
/// <c>xsi:nil</c> rather than omitted, for the same reason.
/// </para>
/// </remarks>
public static class XcepMessages
{
    public const string Xcep = "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy";
    public const string Xsi = "http://www.w3.org/2001/XMLSchema-instance";
    public const string GetPoliciesAction = Xcep + "/IPolicy/GetPolicies";
    public const string GetPoliciesResponseAction = Xcep + "/IPolicy/GetPoliciesResponse";

    // CAURI.clientAuthentication (MS-XCEP 3.1.4.1.3.2).
    public const int AuthAnonymous = 1;
    public const int AuthKerberos = 2;
    public const int AuthUsernamePassword = 4;
    public const int AuthCertificate = 8;

    // OID.group (MS-XCEP 3.1.4.1.3.16).
    public const int OidGroupHashAlgorithm = 1;
    public const int OidGroupPublicKeyAlgorithm = 3;
    public const int OidGroupExtension = 6;
    public const int OidGroupTemplate = 9;

    /// <summary>
    /// Templates are described as schema 3 (the CNG template format, Windows Server 2008 and
    /// later). Schema 2 leaves the hash algorithm unspecified and a Windows client then signs
    /// its request with SHA-1, which the certificate profiles refuse; schema 3 names the hash
    /// and the public key algorithm and the client follows them.
    /// </summary>
    public const int PolicySchema = 3;

    // Template flag bits the response carries (MS-CRTD).
    private const int SubjectNameFlagEnrolleeSuppliesSubject = 0x00000001;
    // CA-built subjects (MS-CRTD msPKI-Certificate-Name-Flag): the CA names the certificate from the
    // caller's Kerberos identity and the client sends no subject of its own.
    private const int SubjectNameFlagRequireCommonName = 0x40000000;
    private const int SubjectNameFlagRequireDnsAsCn = 0x10000000;
    private const int SubjectNameFlagAltRequireDns = 0x08000000;
    private const int SubjectNameFlagAltRequireUpn = 0x02000000;
    private const int GeneralFlagMachineType = 0x00000040;
    private const int PrivateKeyFlagExportable = 0x00000010;
    private const int EnrollmentFlagAutoEnrollment = 0x00000020;
    private const int KeySpecKeyExchange = 1;

    /// <summary>
    /// The subject name flags a template advertises: enrollee-supplied for a credential caller,
    /// CA-built from the DNS name (machines) or the common name plus UPN (users) for a caller
    /// whose identity the CA knows. Windows then sends no subject and expects the CA's.
    /// </summary>
    internal static int SubjectNameFlags(PolicyTemplate template)
        => !template.CaBuiltSubject ? SubjectNameFlagEnrolleeSuppliesSubject
            : template.MachineType ? SubjectNameFlagRequireDnsAsCn | SubjectNameFlagAltRequireDns
            : SubjectNameFlagRequireCommonName | SubjectNameFlagAltRequireUpn;

    /// <summary>A parsed <c>GetPolicies</c> request.</summary>
    /// <param name="MessageId">The client's <c>wsa:MessageID</c>, echoed as <c>RelatesTo</c>, or null.</param>
    /// <param name="LastUpdate">When the client last fetched policy, or null for a first fetch.</param>
    /// <param name="PreferredLanguage">The client's language tag, or null.</param>
    /// <param name="UsernameToken">The WS-Security credential, or null. See <see cref="WstepMessages.WstepIssueRequest"/>.</param>
    public sealed record GetPoliciesRequest(
        string? MessageId,
        DateTime? LastUpdate,
        string? PreferredLanguage,
        WstepMessages.WstepUsernameToken? UsernameToken,
        WstepMessages.WstepKerberosToken? KerberosToken = null);

    /// <summary>An issuing CA as advertised to the client.</summary>
    /// <param name="ReferenceId">The id templates refer to it by.</param>
    /// <param name="CesUri">The enrollment (CES) URL, absolute.</param>
    /// <param name="CertificateDer">The CA certificate, DER.</param>
    /// <param name="EnrollPermission">Whether the asking caller may enroll at this CA.</param>
    /// <param name="ClientAuthentication">
    /// How the client must authenticate to CES: <see cref="AuthKerberos"/> for a caller that
    /// arrived with a ticket, so the enrollment engine keeps using it, else <see cref="AuthUsernamePassword"/>.
    /// </param>
    public sealed record PolicyCa(int ReferenceId, string CesUri, byte[] CertificateDer, bool EnrollPermission, int ClientAuthentication = AuthUsernamePassword);

    /// <summary>An extension the issued certificate will carry, offered so the client can put it in its CSR.</summary>
    public sealed record PolicyExtension(string Oid, string FriendlyName, bool Critical, byte[] Value);

    /// <summary>A template as advertised to the client.</summary>
    public sealed record PolicyTemplate(
        string Name,
        string Oid,
        int MajorVersion,
        int MinorVersion,
        long ValiditySeconds,
        long RenewalSeconds,
        bool Enroll,
        bool AutoEnroll,
        bool CaBuiltSubject,
        int MinimalKeyLength,
        bool MachineType,
        bool ExportableKey,
        string HashAlgorithmOid,
        string HashAlgorithmName,
        string PublicKeyAlgorithmOid,
        string PublicKeyAlgorithmName,
        IReadOnlyList<PolicyExtension> Extensions,
        IReadOnlyList<int> CaReferenceIds);

    /// <summary>Everything one <c>GetPoliciesResponse</c> says.</summary>
    /// <param name="PolicyId">Stable id the client caches the policy under.</param>
    /// <param name="FriendlyName">Shown to the operator in the client's certificate UI.</param>
    /// <param name="NextUpdateHours">How long the client keeps the policy before asking again.</param>
    public sealed record PolicySet(
        Guid PolicyId,
        string FriendlyName,
        int NextUpdateHours,
        IReadOnlyList<PolicyCa> Cas,
        IReadOnlyList<PolicyTemplate> Templates);

    /// <summary>
    /// Parses a SOAP <c>GetPolicies</c> request. Throws <see cref="WstepMessages.WstepParseException"/>
    /// when the body carries no <c>GetPolicies</c> element or the XML is unusable.
    /// </summary>
    public static GetPoliciesRequest ParseGetPolicies(string soapXml)
    {
        var doc = WstepMessages.LoadHardened(soapXml);
        XNamespace x = Xcep;

        var body = doc.Descendants(x + "GetPolicies").FirstOrDefault()
            ?? throw new WstepMessages.WstepParseException("No GetPolicies element found in the request body.");

        var client = body.Element(x + "client");
        DateTime? lastUpdate = null;
        var lastUpdateText = client?.Element(x + "lastUpdate")?.Value?.Trim();
        if (!string.IsNullOrEmpty(lastUpdateText)
            && DateTime.TryParse(lastUpdateText, null, System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal, out var parsed))
        {
            lastUpdate = parsed;
        }
        var language = client?.Element(x + "preferredLanguage")?.Value?.Trim();

        return new GetPoliciesRequest(
            WstepMessages.ReadMessageId(doc),
            lastUpdate,
            string.IsNullOrEmpty(language) ? null : language,
            WstepMessages.ReadUsernameToken(doc),
            WstepMessages.ReadKerberosToken(doc));
    }

    /// <summary>Builds the SOAP <c>GetPoliciesResponse</c> for <paramref name="policy"/>.</summary>
    public static string BuildGetPoliciesResponse(PolicySet policy, string? relatesToMessageId)
    {
        ArgumentNullException.ThrowIfNull(policy);
        XNamespace s = WstepMessages.Soap12, a = WstepMessages.Wsa, x = Xcep, xsi = Xsi;

        // Every OID the response mentions gets one row in the oIDs table and is referred to by
        // its row id everywhere else. Rows are allocated in first-use order.
        var oids = new OidTable();

        var policies = new XElement(x + "policies");
        foreach (var template in policy.Templates)
            policies.Add(BuildPolicy(template, oids));

        var response = new XElement(x + "response",
            // Braced, upper-case GUID: the form Windows' own policy service emits and the client
            // stores as the policy's identity. The schema calls it an opaque string.
            new XElement(x + "policyID", policy.PolicyId.ToString("B").ToUpperInvariant()),
            new XElement(x + "policyFriendlyName", policy.FriendlyName),
            new XElement(x + "nextUpdateHours", policy.NextUpdateHours),
            Nil(x + "policiesNotChanged"),
            policies);

        var cas = new XElement(x + "cAs");
        foreach (var ca in policy.Cas)
        {
            cas.Add(new XElement(x + "cA",
                new XElement(x + "uris",
                    new XElement(x + "cAURI",
                        new XElement(x + "clientAuthentication", ca.ClientAuthentication),
                        new XElement(x + "uri", ca.CesUri),
                        new XElement(x + "priority", 1),
                        new XElement(x + "renewalOnly", false))),
                new XElement(x + "certificate", Convert.ToBase64String(ca.CertificateDer)),
                new XElement(x + "enrollPermission", ca.EnrollPermission),
                new XElement(x + "cAReferenceID", ca.ReferenceId)));
        }

        var header = new XElement(s + "Header",
            new XElement(a + "Action", new XAttribute(s + "mustUnderstand", "1"), GetPoliciesResponseAction));
        if (!string.IsNullOrEmpty(relatesToMessageId))
            header.Add(new XElement(a + "RelatesTo", relatesToMessageId));
        header.Add(WstepMessages.SecurityTimestamp(DateTime.UtcNow));

        var envelope = new XElement(s + "Envelope",
            new XAttribute(XNamespace.Xmlns + "s", WstepMessages.Soap12),
            new XAttribute(XNamespace.Xmlns + "a", WstepMessages.Wsa),
            new XAttribute(XNamespace.Xmlns + "xsi", Xsi),
            header,
            new XElement(s + "Body",
                new XElement(x + "GetPoliciesResponse",
                    response,
                    cas,
                    oids.ToElement())));

        return WstepMessages.Serialize(envelope);
    }

    private static XElement BuildPolicy(PolicyTemplate template, OidTable oids)
    {
        XNamespace x = Xcep;

        var caRefs = new XElement(x + "cAs");
        foreach (var id in template.CaReferenceIds)
            caRefs.Add(new XElement(x + "cAReference", id));

        var extensions = new XElement(x + "extensions");
        foreach (var ext in template.Extensions)
        {
            extensions.Add(new XElement(x + "extension",
                new XElement(x + "oIDReference", oids.Reference(ext.Oid, OidGroupExtension, ext.FriendlyName)),
                new XElement(x + "critical", ext.Critical),
                new XElement(x + "value", Convert.ToBase64String(ext.Value))));
        }

        var generalFlags = template.MachineType ? GeneralFlagMachineType : 0;
        var enrollmentFlags = template.AutoEnroll ? EnrollmentFlagAutoEnrollment : 0;
        var privateKeyFlags = template.ExportableKey ? PrivateKeyFlagExportable : 0;

        var attributes = new XElement(x + "attributes",
            new XElement(x + "commonName", template.Name),
            new XElement(x + "policySchema", PolicySchema),
            new XElement(x + "certificateValidity",
                new XElement(x + "validityPeriodSeconds", template.ValiditySeconds),
                new XElement(x + "renewalPeriodSeconds", template.RenewalSeconds)),
            new XElement(x + "permission",
                new XElement(x + "enroll", template.Enroll),
                new XElement(x + "autoEnroll", template.AutoEnroll)),
            new XElement(x + "privateKeyAttributes",
                new XElement(x + "minimalKeyLength", template.MinimalKeyLength),
                new XElement(x + "keySpec", KeySpecKeyExchange),
                Nil(x + "keyUsageProperty"),
                Nil(x + "permissions"),
                new XElement(x + "algorithmOIDReference",
                    oids.Reference(template.PublicKeyAlgorithmOid, OidGroupPublicKeyAlgorithm, template.PublicKeyAlgorithmName)),
                Nil(x + "cryptoProviders")),
            new XElement(x + "revision",
                new XElement(x + "majorRevision", template.MajorVersion),
                new XElement(x + "minorRevision", template.MinorVersion)),
            Nil(x + "supersededPolicies"),
            new XElement(x + "privateKeyFlags", privateKeyFlags),
            new XElement(x + "subjectNameFlags", SubjectNameFlags(template)),
            new XElement(x + "enrollmentFlags", enrollmentFlags),
            new XElement(x + "generalFlags", generalFlags),
            // MS-XCEP 3.1.4.1.3.1: a schema-3 template names its hash algorithm here; for schema 1
            // or 2 this must be nil. Naming it is what makes the client sign with SHA-256.
            new XElement(x + "hashAlgorithmOIDReference",
                oids.Reference(template.HashAlgorithmOid, OidGroupHashAlgorithm, template.HashAlgorithmName)),
            Nil(x + "rARequirements"),
            Nil(x + "keyArchivalAttributes"),
            extensions);

        return new XElement(x + "policy",
            new XElement(x + "policyOIDReference", oids.Reference(template.Oid, OidGroupTemplate, template.Name)),
            caRefs,
            attributes);
    }

    private static XElement Nil(XName name) => new(name, new XAttribute(XName.Get("nil", Xsi), "true"));

    /// <summary>The response's OID table: one row per distinct OID, referenced by row id.</summary>
    private sealed class OidTable
    {
        private readonly List<(string Oid, int Group, string Name)> _rows = [];

        public int Reference(string oid, int group, string defaultName)
        {
            var index = _rows.FindIndex(r => r.Oid == oid);
            if (index < 0)
            {
                _rows.Add((oid, group, defaultName));
                index = _rows.Count - 1;
            }
            return index + 1;
        }

        public XElement ToElement()
        {
            XNamespace x = Xcep;
            var element = new XElement(x + "oIDs");
            for (var i = 0; i < _rows.Count; i++)
            {
                element.Add(new XElement(x + "oID",
                    new XElement(x + "value", _rows[i].Oid),
                    new XElement(x + "group", _rows[i].Group),
                    new XElement(x + "oIDReferenceID", i + 1),
                    new XElement(x + "defaultName", _rows[i].Name)));
            }
            return element;
        }
    }
}
