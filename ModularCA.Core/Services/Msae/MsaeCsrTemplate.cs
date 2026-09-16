using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkcs;

namespace ModularCA.Core.Services.Msae;

/// <summary>
/// Reads the certificate template a Windows client asked for out of its PKCS#10.
/// </summary>
/// <remarks>
/// <para>
/// A Windows enrollment request names its template inside the CSR's extension request, in one of
/// two Microsoft extensions: <c>szOID_ENROLL_CERTTYPE_EXTENSION</c> (1.3.6.1.4.1.311.20.2), a
/// BMPString holding the template's name, used by version 1 templates and by <c>certreq</c>
/// <c>.inf</c> files; or <c>szOID_CERTIFICATE_TEMPLATE</c> (1.3.6.1.4.1.311.21.7), a sequence of
/// the template's OID and version, used by version 2 and later templates. Autoenrollment sends
/// the second; hand-built requests usually send the first. Both are read, and either may be
/// absent.
/// </para>
/// <para>
/// This only reports what the client asked for. Whether that template exists here, is enabled,
/// and may be used by the caller is the enrollment service's decision.
/// </para>
/// </remarks>
public static class MsaeCsrTemplate
{
    /// <summary>szOID_ENROLL_CERTTYPE_EXTENSION: template name as a BMPString.</summary>
    public const string TemplateNameOid = "1.3.6.1.4.1.311.20.2";

    /// <summary>szOID_CERTIFICATE_TEMPLATE: template OID plus major and minor version.</summary>
    public const string TemplateInfoOid = "1.3.6.1.4.1.311.21.7";

    /// <summary>The template a request named, by name and/or OID. Either field may be null.</summary>
    public sealed record TemplateReference(string? Name, string? Oid);

    /// <summary>
    /// Returns the template reference carried in <paramref name="pkcs10Der"/>, or null when the
    /// request names no template. Returns null rather than throwing for an unreadable request:
    /// the caller parses the CSR properly on its own and reports that failure itself.
    /// </summary>
    public static TemplateReference? TryRead(byte[] pkcs10Der)
    {
        if (pkcs10Der == null || pkcs10Der.Length == 0) return null;

        X509Extensions? extensions;
        try
        {
            extensions = ReadRequestedExtensions(new Pkcs10CertificationRequest(pkcs10Der));
        }
        catch (Exception)
        {
            return null;
        }
        if (extensions == null) return null;

        string? name = null, oid = null;

        var nameExt = extensions.GetExtension(new DerObjectIdentifier(TemplateNameOid));
        if (nameExt != null && Asn1Object.FromByteArray(nameExt.Value.GetOctets()) is IAsn1String nameString)
            name = nameString.GetString().Trim();

        var infoExt = extensions.GetExtension(new DerObjectIdentifier(TemplateInfoOid));
        if (infoExt != null
            && Asn1Object.FromByteArray(infoExt.Value.GetOctets()) is Asn1Sequence info
            && info.Count > 0
            && info[0] is DerObjectIdentifier templateOid)
        {
            oid = templateOid.Id;
        }

        if (string.IsNullOrEmpty(name)) name = null;
        return name == null && oid == null ? null : new TemplateReference(name, oid);
    }

    private static X509Extensions? ReadRequestedExtensions(Pkcs10CertificationRequest request)
    {
        var attributes = request.GetCertificationRequestInfo().Attributes;
        if (attributes == null) return null;

        foreach (var entry in attributes)
        {
            var attribute = AttributePkcs.GetInstance(entry);
            if (!attribute.AttrType.Equals(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest)) continue;
            if (attribute.AttrValues.Count == 0) continue;
            return X509Extensions.GetInstance(attribute.AttrValues[0]);
        }
        return null;
    }
}
