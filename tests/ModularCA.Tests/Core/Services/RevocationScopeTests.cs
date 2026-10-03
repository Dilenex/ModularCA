using ModularCA.Core.Helpers;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Utils;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Which CA certificates a CRL or OCSP response covers. The issuer backfill links a legacy row to
/// the exact CA certificate that signed it, which may be a superseded one; the CRL and OCSP
/// lookups must follow it there when that certificate carries the signing key, and only then.
/// </summary>
public class RevocationScopeTests
{
    private static CertificateEntity Row(X509Certificate cert) => new()
    {
        CertificateId = Guid.NewGuid(),
        SerialNumber = CertificateUtil.FormatSerialNumber(cert.SerialNumber),
        SubjectDN = cert.SubjectDN.ToString(),
        Issuer = cert.IssuerDN.ToString(),
        IsCA = true,
        Pem = CertificateUtil.ConvertDerToPem(cert.GetEncoded(), "CERTIFICATE"),
        RawCertificate = cert.GetEncoded(),
        NotBefore = cert.NotBefore,
        NotAfter = cert.NotAfter,
    };

    private static CertificateAuthorityEntity Authority(CertificateEntity current, Guid space, string label) => new()
    {
        Id = Guid.NewGuid(), Name = label, Label = label, SpaceId = space, IsEnabled = true, CertificateId = current.CertificateId,
    };

    [Fact]
    public async Task A_superseded_certificate_with_the_same_key_is_in_scope()
    {
        using var db = InMemoryDbContextFactory.Create();
        var ca = TestCaMaterial.CreateCa("CN=Scope CA");
        var current = Row(ca.Certificate);
        var superseded = Row(ca.Issue(BigInteger.ValueOf(7), ca.SubjectDn, ca.KeyPair.Public, isCa: true));
        db.Certificates.AddRange(current, superseded);
        db.CertificateAuthorities.Add(Authority(current, Guid.NewGuid(), "scope"));
        db.SaveChanges();

        var scope = await IssuerChainResolver.SameKeyCaCertificateIdsAsync(db, current.CertificateId, ca.Certificate);

        Assert.Equal(new[] { current.CertificateId, superseded.CertificateId }.OrderBy(x => x), scope.OrderBy(x => x));
    }

    [Fact]
    public async Task A_superseded_certificate_with_a_different_key_is_out_of_scope()
    {
        using var db = InMemoryDbContextFactory.Create();
        var oldKey = TestCaMaterial.CreateCa("CN=Rekeyed CA");
        var newKey = TestCaMaterial.CreateCa("CN=Rekeyed CA");
        var current = Row(newKey.Certificate);
        var superseded = Row(oldKey.Certificate);
        db.Certificates.AddRange(current, superseded);
        db.CertificateAuthorities.Add(Authority(current, Guid.NewGuid(), "rekeyed"));
        db.SaveChanges();

        var scope = await IssuerChainResolver.SameKeyCaCertificateIdsAsync(db, current.CertificateId, newKey.Certificate);

        Assert.Equal(new[] { current.CertificateId }, scope);
    }

    [Fact]
    public async Task Another_cas_certificate_with_the_same_name_and_key_is_out_of_scope()
    {
        using var db = InMemoryDbContextFactory.Create();
        var ca = TestCaMaterial.CreateCa("CN=Twin CA");
        var mine = Row(ca.Certificate);
        var theirs = Row(ca.Issue(BigInteger.ValueOf(8), ca.SubjectDn, ca.KeyPair.Public, isCa: true));
        db.Certificates.AddRange(mine, theirs);
        db.CertificateAuthorities.AddRange(Authority(mine, Guid.NewGuid(), "mine"), Authority(theirs, Guid.NewGuid(), "theirs"));
        db.SaveChanges();

        var scope = await IssuerChainResolver.SameKeyCaCertificateIdsAsync(db, mine.CertificateId, ca.Certificate);

        Assert.Equal(new[] { mine.CertificateId }, scope);
    }
}
