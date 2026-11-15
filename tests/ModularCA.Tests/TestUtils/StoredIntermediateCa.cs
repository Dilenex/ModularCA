using System.Security.Cryptography.X509Certificates;
using ModularCA.Database;
using ModularCA.Shared.Entities;

namespace ModularCA.Tests.TestUtils;

/// <summary>
/// A root CA and an issuing CA beneath it, with real certificates, stored the way the product
/// stores them (certificate rows linked by <c>IssuerCertificateId</c>, CA rows linked by
/// <c>ParentCaId</c>, a signing profile naming the issuing CA's certificate), plus a
/// <see cref="LocalCrlServer"/> the issuing CA's leaves name as their distribution point. For the
/// callers that prove issuance against a stored CA and may be asked to check revocation online.
/// </summary>
internal sealed class StoredIntermediateCa : IDisposable
{
    private readonly List<X509Certificate2> _owned = [];

    /// <summary>Creates the certificates and stores both CAs in <paramref name="db"/>.</summary>
    /// <param name="db">The database to seed.</param>
    /// <param name="storeRoot">
    /// False to leave the root out of the database altogether, as for an issuing CA under an
    /// external root that was never imported: the issuing CA's row then has no issuer link.
    /// </param>
    public StoredIntermediateCa(ModularCADbContext db, bool storeRoot = true)
    {
        var tag = Guid.NewGuid().ToString("N");
        Root = Own(TestCertificates.CreateCa($"CN=Stored Root {tag}, O=ModularCA"));
        Issuing = Own(TestCertificates.IssueIntermediateWithCrl(Root, $"CN=Stored Issuing CA {tag}, O=ModularCA", crlUrl: null));

        RootCertificateId = Guid.NewGuid();
        IssuingCertificateId = Guid.NewGuid();
        IssuingCaId = Guid.NewGuid();
        var rootCaId = Guid.NewGuid();

        if (storeRoot)
        {
            db.Certificates.Add(Row(RootCertificateId, Root, isCa: true, issuerId: RootCertificateId));
            db.CertificateAuthorities.Add(new CertificateAuthorityEntity
            {
                Id = rootCaId, Name = $"Root {tag}", Label = $"root-{tag}", Type = "Root", CertificateId = RootCertificateId,
            });
        }
        db.Certificates.Add(Row(IssuingCertificateId, Issuing, isCa: true, issuerId: storeRoot ? RootCertificateId : null));
        db.CertificateAuthorities.Add(new CertificateAuthorityEntity
        {
            Id = IssuingCaId, Name = $"Issuing {tag}", Label = $"issuing-{tag}", Type = "Issuing",
            CertificateId = IssuingCertificateId, ParentCaId = storeRoot ? rootCaId : null,
        });
        SigningProfile = new SigningProfileEntity { Name = $"profile-{tag}", IssuerId = IssuingCertificateId };
        db.SigningProfiles.Add(SigningProfile);
        db.SaveChanges();
    }

    /// <summary>Where the issuing CA's CRL is served.</summary>
    public LocalCrlServer Crls { get; } = new();

    /// <summary>The self-signed root, with its key.</summary>
    public X509Certificate2 Root { get; }

    /// <summary>The issuing CA under the root, with its key.</summary>
    public X509Certificate2 Issuing { get; }

    /// <summary>The root's certificate row id.</summary>
    public Guid RootCertificateId { get; }

    /// <summary>The issuing CA's certificate row id.</summary>
    public Guid IssuingCertificateId { get; }

    /// <summary>The issuing CA's CA row id.</summary>
    public Guid IssuingCaId { get; }

    /// <summary>A signing profile whose issuer is the issuing CA's certificate.</summary>
    public SigningProfileEntity SigningProfile { get; }

    /// <summary>
    /// Issues a client certificate from the issuing CA and publishes the CA's CRL where the
    /// certificate says to look: empty, or listing it when <paramref name="revoked"/>.
    /// </summary>
    /// <param name="revoked">Whether the published CRL lists the new certificate.</param>
    /// <returns>The certificate and its distribution point URL.</returns>
    public (X509Certificate2 Leaf, string CrlUrl) IssueClient(bool revoked = false)
    {
        var url = Crls.NewUrl();
        var leaf = Own(TestCertificates.IssueLeafWithCrl(Issuing, $"CN=client {Guid.NewGuid():N}", url));
        Crls.Publish(url, revoked ? TestCertificates.BuildCrl(Issuing, leaf) : TestCertificates.BuildCrl(Issuing));
        return (leaf, url);
    }

    /// <summary>A certificate row for <paramref name="certificate"/>, carrying both its DER and its PEM.</summary>
    public static CertificateEntity Row(Guid id, X509Certificate2 certificate, bool isCa, Guid? issuerId) => new()
    {
        CertificateId = id,
        SerialNumber = certificate.SerialNumber,
        SubjectDN = certificate.Subject,
        Issuer = certificate.Issuer,
        Pem = certificate.ExportCertificatePem(),
        RawCertificate = certificate.RawData,
        NotBefore = certificate.NotBefore.ToUniversalTime(),
        NotAfter = certificate.NotAfter.ToUniversalTime(),
        IsCA = isCa,
        IssuerCertificateId = issuerId,
        SubjectAlternativeNamesJson = "[]",
        KeyUsagesJson = "[]",
        ExtendedKeyUsagesJson = "[]",
    };

    private X509Certificate2 Own(X509Certificate2 certificate)
    {
        _owned.Add(certificate);
        return certificate;
    }

    /// <summary>Disposes the certificates and stops the CRL server.</summary>
    public void Dispose()
    {
        foreach (var certificate in _owned)
            certificate.Dispose();
        Crls.Dispose();
    }
}
