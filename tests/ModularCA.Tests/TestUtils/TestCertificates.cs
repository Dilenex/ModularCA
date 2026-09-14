using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ModularCA.Tests.TestUtils;

/// <summary>
/// Builds throwaway X.509 material for tests that need to prove something about issuance.
/// <para>
/// The important member here is <see cref="ForgedIssuer"/>. Several places in this codebase have
/// tried to establish "this certificate was issued by our CA" by comparing the leaf's Issuer DN
/// against the CA's Subject DN as strings. That proves nothing: the Issuer field is just text in
/// a certificate the attacker generates and signs with their own key. This helper produces
/// exactly that certificate so a test can assert the codebase rejects it.
/// </para>
/// </summary>
internal static class TestCertificates
{
    private static readonly DateTimeOffset NotBefore = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset NotAfter = new(2027, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>Creates a self-signed CA certificate (basicConstraints cA=TRUE, keyCertSign).</summary>
    public static X509Certificate2 CreateCa(string subject = "CN=Test Root CA, O=ModularCA")
    {
        using var key = RSA.Create(2048);
        var req = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
        return req.CreateSelfSigned(NotBefore, NotAfter);
    }

    /// <summary>
    /// Issues a subordinate CA certificate signed by <paramref name="issuer"/>, returned with its
    /// private key so it can sign in turn.
    /// </summary>
    /// <remarks>
    /// Needed because a CA that has a protocol enabled is usually an intermediate, not a root, and
    /// trust decisions that look right against a one-level hierarchy fall apart at two.
    /// </remarks>
    public static X509Certificate2 IssueIntermediate(
        X509Certificate2 issuer, string subject = "CN=Test Issuing CA, O=ModularCA")
    {
        using var key = RSA.Create(2048);
        var req = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));

        var serial = new byte[16];
        RandomNumberGenerator.Fill(serial);
        serial[0] &= 0x7F;

        using var signed = req.Create(issuer, NotBefore.AddHours(1), NotAfter.AddHours(-1), serial);
        return signed.CopyWithPrivateKey(key);
    }

    /// <summary>Issues a genuine leaf certificate signed by <paramref name="ca"/>'s private key.</summary>
    public static X509Certificate2 IssueLeaf(X509Certificate2 ca, string subject = "CN=client.example.test")
        => IssueLeaf(ca, subject, ekuOids: null);

    /// <summary>
    /// Issues a genuine leaf carrying the given Extended Key Usage OIDs. Pass an empty array for
    /// an EKU extension that permits nothing; pass null for no EKU extension at all, which RFC
    /// 5280 treats as unrestricted.
    /// </summary>
    public static X509Certificate2 IssueLeaf(X509Certificate2 ca, string subject, string[]? ekuOids)
    {
        using var leafKey = RSA.Create(2048);
        var req = new CertificateRequest(subject, leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        if (ekuOids != null)
        {
            var oids = new OidCollection();
            foreach (var oid in ekuOids)
                oids.Add(new Oid(oid));
            req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(oids, false));
        }

        var serial = new byte[16];
        RandomNumberGenerator.Fill(serial);
        serial[0] &= 0x7F; // keep the DER INTEGER positive

        // Sign with the CA's key, then drop the leaf's own private key — callers only need the
        // public certificate, and chain building never wants it.
        using var signed = req.Create(ca, NotBefore.AddDays(1), NotAfter.AddDays(-1), serial);
        return X509CertificateLoader.LoadCertificate(signed.Export(X509ContentType.Cert));
    }

    /// <summary>
    /// Issues a leaf whose validity period has already ended, signed genuinely by
    /// <paramref name="ca"/>.
    /// </summary>
    public static X509Certificate2 IssueExpiredLeaf(
        X509Certificate2 ca, string subject = "CN=expired.example.test")
    {
        using var leafKey = RSA.Create(2048);
        var req = new CertificateRequest(subject, leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));

        var serial = new byte[16];
        RandomNumberGenerator.Fill(serial);
        serial[0] &= 0x7F;

        // Inside the CA's own validity window, but ended before the CA's notAfter, so the only
        // thing wrong with the chain is this certificate's expiry.
        using var signed = req.Create(ca, NotBefore.AddDays(1), NotBefore.AddDays(2), serial);
        return X509CertificateLoader.LoadCertificate(signed.Export(X509ContentType.Cert));
    }

    /// <summary>
    /// Creates the forgery: a certificate whose Issuer field carries <paramref name="ca"/>'s exact
    /// Subject DN, but which is signed by a key the "attacker" generated. Any check that compares
    /// issuer strings accepts it; any real chain build rejects it.
    /// </summary>
    public static X509Certificate2 ForgedIssuer(X509Certificate2 ca, string subject = "CN=victim.example.test")
    {
        using var attackerKey = RSA.Create(2048);
        var req = new CertificateRequest(subject, attackerKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));

        var serial = new byte[16];
        RandomNumberGenerator.Fill(serial);
        serial[0] &= 0x7F;

        // The issuer NAME is the CA's; the SIGNATURE is the attacker's own.
        var generator = X509SignatureGenerator.CreateForRSA(attackerKey, RSASignaturePadding.Pkcs1);
        using var forged = req.Create(ca.SubjectName, generator, NotBefore.AddDays(1), NotAfter.AddDays(-1), serial);
        return X509CertificateLoader.LoadCertificate(forged.Export(X509ContentType.Cert));
    }
}
