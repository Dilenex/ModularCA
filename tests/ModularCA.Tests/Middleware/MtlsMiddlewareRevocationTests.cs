using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Roles;
using Xunit;

namespace ModularCA.Tests.Middleware;

/// <summary>
/// The <c>Mtls.RequiredPaths</c> gate in <c>MtlsMiddleware</c> refuses a client certificate that
/// chains to a trusted anchor but that this instance's records show as revoked or on hold, that
/// one of this instance's CAs issued yet has no record, or whose issuing CA is revoked or
/// disabled. It used to accept any certificate that chained, checking revocation only against the
/// local CRL cache, which holds nothing this instance revoked. A certificate from an external
/// anchor, which this instance keeps no record of, still passes on its chain alone; with no
/// database to check against, the gate refuses.
/// </summary>
public sealed class MtlsMiddlewareRevocationTests : IDisposable
{
    private const string Ns = "ModularCA.API.";

    private readonly X509Certificate2 _ca;
    private readonly X509Certificate2 _leaf;
    private readonly Guid _caCertificateId = Guid.NewGuid();
    private readonly Guid _caId = Guid.NewGuid();
    private readonly Guid _leafId = Guid.NewGuid();
    private readonly ModularCADbContext _db;

    /// <summary>A CA of this instance, on record with its CA row, and a client certificate it issued.</summary>
    public MtlsMiddlewareRevocationTests()
    {
        (_ca, _leaf) = Issue("CN=Instance mTLS CA");
        _db = new ModularCADbContext(new DbContextOptionsBuilder<ModularCADbContext>()
            .UseInMemoryDatabase($"mtls-required-paths-{Guid.NewGuid():N}").Options);
        _db.Certificates.Add(Row(_caCertificateId, _ca, isCa: true, issuerId: null));
        _db.CertificateAuthorities.Add(new CertificateAuthorityEntity { Id = _caId, Name = "Instance mTLS CA", Label = "instance-mtls", CertificateId = _caCertificateId });
        _db.Certificates.Add(Row(_leafId, _leaf, isCa: false, issuerId: _caCertificateId));
        _db.SaveChanges();
    }

    /// <summary>Disposes the certificates and the context.</summary>
    public void Dispose()
    {
        _ca.Dispose();
        _leaf.Dispose();
        _db.Dispose();
    }

    private static (X509Certificate2 Ca, X509Certificate2 Leaf) Issue(string caSubject)
    {
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var caRequest = new CertificateRequest(caSubject, caKey, HashAlgorithmName.SHA256);
        caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        var ca = caRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));

        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var leafRequest = new CertificateRequest("CN=operator", leafKey, HashAlgorithmName.SHA256);
        leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        var leaf = leafRequest.Create(ca, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddDays(7), RandomNumberGenerator.GetBytes(12));
        return (ca, leaf);
    }

    private static CertificateEntity Row(Guid id, X509Certificate2 cert, bool isCa, Guid? issuerId) => new()
    {
        CertificateId = id,
        SerialNumber = CertificateUtil.NormalizeSerialForLookup(cert.SerialNumber),
        SubjectDN = cert.Subject,
        Issuer = cert.Issuer,
        Pem = cert.ExportCertificatePem(),
        RawCertificate = cert.RawData,
        NotBefore = cert.NotBefore.ToUniversalTime(),
        NotAfter = cert.NotAfter.ToUniversalTime(),
        IsCA = isCa,
        IssuerCertificateId = issuerId,
        SubjectAlternativeNamesJson = "[]",
        KeyUsagesJson = "[]",
        ExtendedKeyUsagesJson = "[]",
    };

    private static object Anchors(params X509Certificate2[] certificates)
    {
        var anchors = Activator.CreateInstance(ApiAssembly.TypeNamed(Ns + "Startup.MtlsTrustAnchors"))!;
        var list = (List<X509Certificate2>)anchors.GetType().GetProperty("Certificates")!.GetValue(anchors)!;
        list.AddRange(certificates);
        return anchors;
    }

    /// <summary>
    /// Sends a request to a required path presenting <paramref name="clientCert"/>, with
    /// <paramref name="anchor"/> trusted and <paramref name="db"/> as the request's database.
    /// </summary>
    private static async Task<(int Status, int Reached)> Send(X509Certificate2 anchor, X509Certificate2 clientCert, ModularCADbContext? db)
    {
        var reached = 0;
        RequestDelegate next = _ => { reached++; return Task.CompletedTask; };
        var config = new SystemConfig { Mtls = { Enabled = true, RequiredPaths = ["/api/v1/admin"] } };
        var middleware = Activator.CreateInstance(ApiAssembly.TypeNamed(Ns + "Middleware.MtlsMiddleware"), [next, config, Anchors(anchor)])!;

        var services = new ServiceCollection();
        if (db != null)
            services.AddSingleton(db);
        var context = new DefaultHttpContext { RequestServices = services.BuildServiceProvider() };
        context.Request.Path = "/api/v1/admin/users";
        context.Connection.RemoteIpAddress = IPAddress.Loopback;
        context.Connection.ClientCertificate = clientCert;
        await (Task)middleware.GetType().GetMethod("InvokeAsync")!.Invoke(middleware, [context])!;
        return (context.Response.StatusCode, reached);
    }

    private void UpdateCertificate(Guid id, Action<CertificateEntity> change)
    {
        change(_db.Certificates.Single(c => c.CertificateId == id));
        _db.SaveChanges();
    }

    private void UpdateCa(Guid id, Action<CertificateAuthorityEntity> change)
    {
        change(_db.CertificateAuthorities.IgnoreQueryFilters().Single(c => c.Id == id));
        _db.SaveChanges();
    }

    [Fact]
    public async Task A_good_certificate_issued_here_passes()
    {
        var (status, reached) = await Send(_ca, _leaf, _db);

        Assert.Equal(1, reached);
        Assert.Equal(200, status);
    }

    [Theory]
    [InlineData(RevocationReason.KeyCompromise)]
    [InlineData(RevocationReason.CertificateHold)]
    public async Task A_revoked_or_held_certificate_issued_here_is_refused(RevocationReason reason)
    {
        UpdateCertificate(_leafId, c => { c.Revoked = true; c.RevocationReason = reason.ToString(); c.RevocationDate = DateTime.UtcNow; });

        var (status, reached) = await Send(_ca, _leaf, _db);

        Assert.Equal(0, reached);
        Assert.Equal(403, status);
    }

    [Fact]
    public async Task A_certificate_whose_issuing_CA_is_revoked_is_refused()
    {
        UpdateCertificate(_caCertificateId, c => { c.Revoked = true; c.RevocationReason = nameof(RevocationReason.CACompromise); });

        var (status, reached) = await Send(_ca, _leaf, _db);

        Assert.Equal(0, reached);
        Assert.Equal(403, status);
    }

    [Fact]
    public async Task A_certificate_whose_issuing_CA_is_disabled_is_refused()
    {
        UpdateCa(_caId, ca => ca.IsEnabled = false);

        var (status, reached) = await Send(_ca, _leaf, _db);

        Assert.Equal(0, reached);
        Assert.Equal(403, status);
    }

    [Fact]
    public async Task A_certificate_a_CA_here_issued_but_with_no_record_is_refused()
    {
        _db.Certificates.Remove(_db.Certificates.Single(c => c.CertificateId == _leafId));
        _db.SaveChanges();

        var (status, reached) = await Send(_ca, _leaf, _db);

        Assert.Equal(0, reached);
        Assert.Equal(403, status);
    }

    [Fact]
    public async Task A_certificate_from_an_external_anchor_passes_on_its_chain()
    {
        var (externalCa, externalLeaf) = Issue("CN=External mTLS CA");
        using (externalCa)
        using (externalLeaf)
        {
            var (status, reached) = await Send(externalCa, externalLeaf, _db);

            Assert.Equal(1, reached);
            Assert.Equal(200, status);
        }
    }

    [Fact]
    public async Task Without_a_database_a_trusted_certificate_is_refused()
    {
        var (status, reached) = await Send(_ca, _leaf, db: null);

        Assert.Equal(0, reached);
        Assert.Equal(403, status);
    }
}
