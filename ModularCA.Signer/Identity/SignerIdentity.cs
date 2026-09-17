using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ModularCA.Signer.Identity;

/// <summary>
/// The identities on the signer channel. The signer creates and holds a dedicated identity CA,
/// self-signed and unrelated to any tenant CA, which issues one server certificate to the
/// signer and one client certificate to the node. Neither side ever validates a chain: each
/// pins the other's public key, so the CA exists to make the two certificates and to reissue
/// the node's when it expires, and for nothing else. Every key is ECDSA P-256.
/// </summary>
public static class SignerIdentity
{
    /// <summary>The identity CA's subject.</summary>
    public const string IdentityCaSubject = "CN=ModularCA Signer Identity CA";

    /// <summary>The signer's server certificate subject.</summary>
    public const string ServerSubject = "CN=ModularCA Signer";

    /// <summary>The node's client certificate subject.</summary>
    public const string NodeSubject = "CN=ModularCA Node";

    /// <summary>How long the identity CA lives.</summary>
    public static readonly TimeSpan CaValidity = TimeSpan.FromDays(365 * 10);

    /// <summary>
    /// How long the signer's server certificate lives: as long as the CA. The node pins the
    /// key, so an expiring server certificate would only break the channel on a date; the pin
    /// is rotated by issuing a new identity, not by a calendar.
    /// </summary>
    public static readonly TimeSpan ServerValidity = TimeSpan.FromDays(365 * 10);

    /// <summary>How long a node's client certificate lives before it is reissued.</summary>
    public static readonly TimeSpan ClientValidity = TimeSpan.FromDays(365);

    private const string ServerAuthEku = "1.3.6.1.5.5.7.3.1";
    private const string ClientAuthEku = "1.3.6.1.5.5.7.3.2";
    private static readonly TimeSpan BackDate = TimeSpan.FromMinutes(5);

    /// <summary>Creates the self-signed identity CA with its private key.</summary>
    public static X509Certificate2 CreateIdentityCa(DateTimeOffset now)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(IdentityCaSubject, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: true, pathLengthConstraint: 0, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature, critical: true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));
        using var created = request.CreateSelfSigned(now - BackDate, now + CaValidity);
        return Persisted(created);
    }

    /// <summary>
    /// Issues the signer's server certificate under <paramref name="identityCa"/>, with
    /// <paramref name="host"/> as its subject alternative name: the address the node dials,
    /// an IP address or a DNS name.
    /// </summary>
    public static X509Certificate2 IssueServerCertificate(X509Certificate2 identityCa, string host, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(identityCa);
        if (string.IsNullOrWhiteSpace(host)) throw new ArgumentException("The server certificate needs the host the node dials.", nameof(host));
        var san = new SubjectAlternativeNameBuilder();
        if (IPAddress.TryParse(host.Trim('[', ']'), out var address))
            san.AddIpAddress(address);
        else
            san.AddDnsName(host);
        if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase))
        {
            san.AddIpAddress(IPAddress.Loopback);
            san.AddIpAddress(IPAddress.IPv6Loopback);
        }
        return Issue(identityCa, ServerSubject, ServerAuthEku, san.Build(), now, ServerValidity);
    }

    /// <summary>Issues a node's client certificate under <paramref name="identityCa"/>.</summary>
    public static X509Certificate2 IssueClientCertificate(X509Certificate2 identityCa, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(identityCa);
        return Issue(identityCa, NodeSubject, ClientAuthEku, null, now, ClientValidity);
    }

    /// <summary>Issues one end-entity certificate with a fresh P-256 key and returns it with the key.</summary>
    private static X509Certificate2 Issue(X509Certificate2 issuer, string subject, string eku, X509Extension? san, DateTimeOffset now, TimeSpan validity)
    {
        if (!issuer.HasPrivateKey)
            throw new ArgumentException("The identity CA has no private key; it cannot issue.", nameof(issuer));
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: false, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(eku) }, critical: false));
        if (san != null)
            request.CertificateExtensions.Add(san);
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuer, includeKeyIdentifier: true, includeIssuerAndSerial: false));

        var notAfter = now + validity;
        if (notAfter > issuer.NotAfter)
            notAfter = issuer.NotAfter;
        var serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7F;
        using var issued = request.Create(issuer, now - BackDate, notAfter, serial);
        using var withKey = issued.CopyWithPrivateKey(key);
        return Persisted(withKey);
    }

    /// <summary>
    /// Round-trips a certificate through PKCS#12 so its private key is one the platform TLS
    /// stack can use: an ephemeral key, which is what the request API creates, cannot be on
    /// Windows.
    /// </summary>
    private static X509Certificate2 Persisted(X509Certificate2 certificate)
        => Pkcs12Files.Load(certificate.Export(X509ContentType.Pkcs12, string.Empty), string.Empty, exportable: true);
}
