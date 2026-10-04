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

    /// <summary>Records the CA certificates a CRL is regenerated for.</summary>
    private sealed class RecordingCrls : ModularCA.Shared.Interfaces.ICrlService
    {
        public List<Guid> Generated { get; } = [];
        public Task<string> GenerateCrlAsync(Guid caCertificateId, CancellationToken cancellationToken = default)
        {
            Generated.Add(caCertificateId);
            return Task.FromResult("");
        }
        public Task<string> GenerateDeltaCrlAsync(Guid caCertificateId, CancellationToken cancellationToken = default) => Task.FromResult("");
        public Task<string?> GetLatestCrlAsync(Guid caCertificateId, CancellationToken cancellationToken = default) => Task.FromResult<string?>(null);
        public Task<string?> GetLatestDeltaCrlAsync(Guid caCertificateId, CancellationToken cancellationToken = default) => Task.FromResult<string?>(null);
        public Task<ModularCA.Shared.Interfaces.CrlBlob?> GetLatestCrlRawAsync(Guid caCertificateId, CancellationToken cancellationToken = default)
            => Task.FromResult<ModularCA.Shared.Interfaces.CrlBlob?>(null);
        public Task<ModularCA.Shared.Interfaces.CrlBlob?> GetLatestDeltaCrlRawAsync(Guid caCertificateId, CancellationToken cancellationToken = default)
            => Task.FromResult<ModularCA.Shared.Interfaces.CrlBlob?>(null);
    }

    /// <summary>
    /// Places a legacy leaf (no issuer link, no signing profile) issued by <paramref name="signer"/>
    /// on hold and returns the CA certificates whose CRL was regenerated.
    /// </summary>
    private static async Task<List<Guid>> RegeneratedForLegacyLeafAsync(ModularCADbContext db, TestCaMaterial signer)
    {
        var leaf = Row(signer.Issue(BigInteger.ValueOf(4242), "CN=leaf.example.com"));
        leaf.IsCA = false;
        db.Certificates.Add(leaf);
        db.SaveChanges();

        var crls = new RecordingCrls();
        var service = new ModularCA.Core.Services.CertificateRevocationService(db,
            System.Reflection.DispatchProxy.Create<ModularCA.Shared.Interfaces.IKeystoreCertificates, ModularCA.Tests.Api.SpaceIsolationMatrixTests.NoOpProxy>(),
            System.Reflection.DispatchProxy.Create<ModularCA.Shared.Interfaces.ICertificateStore, ModularCA.Tests.Api.SpaceIsolationMatrixTests.NoOpProxy>(),
            new NoopNotificationService(), crls,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<ModularCA.Core.Services.CertificateRevocationService>.Instance);
        await service.HoldCertificateAsync(leaf.CertificateId, null);
        return crls.Generated;
    }

    /// <summary>
    /// The finding: a renewed CA's old and new certificates share the issuer DN, so the "exactly
    /// one CA certificate with this DN" fallback found two and regenerated no CRL. With the same
    /// key kept, the CRL regenerated is the current certificate's, which covers both.
    /// </summary>
    [Fact]
    public async Task A_legacy_leaf_of_a_renewed_ca_regenerates_the_current_certificates_crl()
    {
        using var db = InMemoryDbContextFactory.Create();
        var ca = TestCaMaterial.CreateCa("CN=Renewed CA");
        var superseded = Row(ca.Certificate);
        var current = Row(ca.Issue(BigInteger.ValueOf(9), ca.SubjectDn, ca.KeyPair.Public, isCa: true));
        db.Certificates.AddRange(current, superseded);
        db.CertificateAuthorities.Add(Authority(current, Guid.NewGuid(), "renewed"));
        db.SaveChanges();

        Assert.Equal([current.CertificateId], await RegeneratedForLegacyLeafAsync(db, ca));
    }

    /// <summary>
    /// A re-keyed CA: the old key signed the leaf, so the old certificate's CRL is the one that
    /// can list it; the current certificate's key cannot.
    /// </summary>
    [Fact]
    public async Task A_legacy_leaf_of_a_rekeyed_ca_regenerates_the_crl_of_the_key_that_signed_it()
    {
        using var db = InMemoryDbContextFactory.Create();
        var oldKey = TestCaMaterial.CreateCa("CN=Rekeyed Issuing CA");
        var newKey = TestCaMaterial.CreateCa("CN=Rekeyed Issuing CA");
        var current = Row(newKey.Certificate);
        var superseded = Row(oldKey.Certificate);
        db.Certificates.AddRange(current, superseded);
        db.CertificateAuthorities.Add(Authority(current, Guid.NewGuid(), "rekeyed-issuing"));
        db.SaveChanges();

        Assert.Equal([superseded.CertificateId], await RegeneratedForLegacyLeafAsync(db, oldKey));
    }

    /// <summary>Two CAs sharing the DN and the key: which one issued cannot be told, so no CRL is guessed at.</summary>
    [Fact]
    public async Task A_legacy_leaf_whose_dn_and_key_two_cas_share_regenerates_nothing()
    {
        using var db = InMemoryDbContextFactory.Create();
        var ca = TestCaMaterial.CreateCa("CN=Twin Issuing CA");
        var mine = Row(ca.Certificate);
        var theirs = Row(ca.Issue(BigInteger.ValueOf(8), ca.SubjectDn, ca.KeyPair.Public, isCa: true));
        db.Certificates.AddRange(mine, theirs);
        db.CertificateAuthorities.AddRange(Authority(mine, Guid.NewGuid(), "mine-issuing"), Authority(theirs, Guid.NewGuid(), "theirs-issuing"));
        db.SaveChanges();

        Assert.Empty(await RegeneratedForLegacyLeafAsync(db, ca));
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
