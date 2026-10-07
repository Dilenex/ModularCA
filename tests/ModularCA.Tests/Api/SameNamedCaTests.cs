using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Api;

/// <summary>
/// Two CAs in different spaces with the same subject DN. What one CA issued is found by issuer
/// identity, never by the shared DN: the certificate impact view, the integration API's chain and
/// the compliance report's CA filter.
/// </summary>
public sealed class SameNamedCaTests
{
    private const string SharedDn = "CN=Shared Issuing CA";
    private static readonly Guid Viewer = Guid.NewGuid();

    private sealed record Side(CertificateEntity Root, CertificateEntity Issuing, CertificateEntity Leaf, CertificateAuthorityEntity Ca);

    private static CertificateEntity Entity(X509Certificate2 cert, bool isCa, Guid? issuerId) => new()
    {
        CertificateId = Guid.NewGuid(),
        SerialNumber = cert.SerialNumber,
        Pem = cert.ExportCertificatePem(),
        SubjectDN = cert.Subject,
        Issuer = cert.Issuer,
        NotBefore = cert.NotBefore.ToUniversalTime(),
        NotAfter = cert.NotAfter.ToUniversalTime(),
        IsCA = isCa,
        IssuerCertificateId = issuerId,
    };

    private static byte[] Serial()
    {
        var serial = new byte[12];
        RandomNumberGenerator.Fill(serial);
        serial[0] &= 0x7F;
        return serial;
    }

    /// <summary>A root, an issuing CA named <see cref="SharedDn"/> under it, and a leaf, in its own space.</summary>
    private static Side Seed(ModularCADbContext db, string name)
    {
        var from = DateTimeOffset.UtcNow.AddDays(-1);
        var to = DateTimeOffset.UtcNow.AddYears(1);
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rootReq = new CertificateRequest($"CN={name} Root", rootKey, HashAlgorithmName.SHA256);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var root = rootReq.CreateSelfSigned(from, to);

        using var issuingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var issuingReq = new CertificateRequest(SharedDn, issuingKey, HashAlgorithmName.SHA256);
        issuingReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var issuing = issuingReq.Create(root, from, to, Serial()).CopyWithPrivateKey(issuingKey);

        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var leaf = new CertificateRequest($"CN={name.ToLowerInvariant()}.example", leafKey, HashAlgorithmName.SHA256)
            .Create(issuing, from, to, Serial());

        var rootEntity = Entity(root, isCa: true, issuerId: null);
        rootEntity.IssuerCertificateId = rootEntity.CertificateId;
        var issuingEntity = Entity(issuing, isCa: true, rootEntity.CertificateId);
        var leafEntity = Entity(leaf, isCa: false, issuingEntity.CertificateId);
        var space = Guid.NewGuid();
        db.Spaces.Add(new SpaceEntity { Id = space, Name = name, Slug = name.ToLowerInvariant() });
        var rootCa = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = $"{name} Root", Label = $"{name.ToLowerInvariant()}-root", SpaceId = space, CertificateId = rootEntity.CertificateId };
        var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = $"{name} Issuing", Label = $"{name.ToLowerInvariant()}-issuing", SpaceId = space, CertificateId = issuingEntity.CertificateId, ParentCaId = rootCa.Id };
        db.Certificates.AddRange(rootEntity, issuingEntity, leafEntity);
        db.CertificateAuthorities.AddRange(rootCa, ca);
        db.SaveChanges();
        return new Side(rootEntity, issuingEntity, leafEntity, ca);
    }

    /// <summary>A leaf stored before issuer links existed: no <c>IssuerCertificateId</c>, issuer by DN only.</summary>
    private static CertificateEntity LegacyLeaf(ModularCADbContext db, string cn)
    {
        var leaf = new CertificateEntity
        {
            CertificateId = Guid.NewGuid(), SerialNumber = Convert.ToHexString(Serial()), Pem = "legacy", SubjectDN = $"CN={cn}",
            Issuer = SharedDn, NotBefore = DateTime.UtcNow.AddDays(-1), NotAfter = DateTime.UtcNow.AddYears(1),
        };
        db.Certificates.Add(leaf);
        db.SaveChanges();
        return leaf;
    }

    // ---- certificate impact ------------------------------------------------------------------

    private sealed class CurrentUserStub(Guid id) : ICurrentUserService
    {
        public Guid? UserId => id;
        public UserEntity? User { get; } = new UserEntity { Id = id, Username = "viewer" };
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync() => Task.CompletedTask;
    }

    private sealed class AccessStub(Func<Guid, bool> canView) : ICertificateAccessEvaluator
    {
        public bool CanViewCertificate(Guid userId, Guid certificateId) => canView(certificateId);
        public bool CanManageCertificate(Guid userId, Guid certificateId) => false;
    }

    private static async Task<string> ImpactAsync(ModularCADbContext db, Func<Guid, bool> canView, string serial)
    {
        var controller = (ControllerBase)Activator.CreateInstance(
            ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Admin.AdminCertificateController"),
            new CertificateStore(db), new CurrentUserStub(Viewer), new AccessStub(canView), db, null,
            new RecordingAlertService(), null, new RecordingAuditService(), null)!;
        controller.ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() };
        var result = await (Task<IActionResult>)controller.GetType().GetMethod("GetCertificateImpact")!.Invoke(controller, [serial])!;
        return JsonSerializer.Serialize(Assert.IsType<OkObjectResult>(result).Value);
    }

    /// <summary>
    /// The impact view of a CA certificate lists the certificates issued under it, not those of a
    /// same-named CA in another space, nor a legacy row matched only by the shared DN, nor one the
    /// caller may not view.
    /// </summary>
    [Fact]
    public async Task The_impact_view_lists_what_this_ca_certificate_issued_and_the_caller_may_view()
    {
        using var db = InMemoryDbContextFactory.Create();
        var a = Seed(db, "Alpha");
        var b = Seed(db, "Bravo");
        var legacy = LegacyLeaf(db, "legacy.example");

        var json = await ImpactAsync(db, _ => true, a.Issuing.SerialNumber);
        Assert.Contains(a.Leaf.SerialNumber, json);
        Assert.DoesNotContain(b.Leaf.SerialNumber, json);
        Assert.DoesNotContain(legacy.SerialNumber, json);

        var hidden = await ImpactAsync(db, id => id != a.Leaf.CertificateId, a.Issuing.SerialNumber);
        Assert.DoesNotContain(a.Leaf.SerialNumber, hidden);
    }

    /// <summary>With only one CA carrying the DN, a legacy row matched by it is still listed.</summary>
    [Fact]
    public async Task The_impact_view_still_lists_a_legacy_row_when_the_dn_is_unambiguous()
    {
        using var db = InMemoryDbContextFactory.Create();
        var a = Seed(db, "Alpha");
        var legacy = LegacyLeaf(db, "legacy.example");

        var json = await ImpactAsync(db, _ => true, a.Issuing.SerialNumber);
        Assert.Contains(a.Leaf.SerialNumber, json);
        Assert.Contains(legacy.SerialNumber, json);
    }

    // ---- integration API chain ---------------------------------------------------------------

    /// <summary>
    /// The integration API returns a certificate's own issuer chain, up to its root, even when a
    /// CA in another space with the same DN was stored first.
    /// </summary>
    [Fact]
    public async Task The_integration_chain_is_the_certificates_own_issuer_not_a_same_named_ca()
    {
        using var db = InMemoryDbContextFactory.Create();
        var a = Seed(db, "Alpha");
        var b = Seed(db, "Bravo");

        var type = ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Integration.InfraController");
        var controller = (ControllerBase)Activator.CreateInstance(type, null, null, new CertificateStore(db), null, null, null, null, db, new SystemConfig())!;
        controller.ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() };
        var result = await (Task<IActionResult>)type.GetMethod("GetCertificate")!.Invoke(controller, [b.Leaf.SerialNumber])!;
        var chain = (string)Assert.IsType<OkObjectResult>(result).Value!.GetType().GetProperty("ChainPem")!.GetValue(Assert.IsType<OkObjectResult>(result).Value)!;

        Assert.Equal(b.Issuing.Pem.Trim() + "\n" + b.Root.Pem.Trim() + "\n", chain);
        Assert.DoesNotContain(a.Issuing.Pem.Trim(), chain);
        Assert.DoesNotContain(a.Root.Pem.Trim(), chain);
    }

    // ---- compliance report -------------------------------------------------------------------

    /// <summary>
    /// A compliance report filtered to one CA counts that CA's certificates, not those of a
    /// same-named CA, and a CA that cannot be resolved reports nothing rather than everything.
    /// </summary>
    [Fact]
    public async Task A_compliance_report_for_one_ca_counts_only_its_certificates()
    {
        // The report sets a command timeout, which needs a relational provider.
        using var connection = new Microsoft.Data.Sqlite.SqliteConnection("DataSource=:memory:");
        connection.Open();
        using var db = new ModularCADbContext(new DbContextOptionsBuilder<ModularCADbContext>().UseSqlite(connection).Options);
        db.Database.EnsureCreated();
        var a = Seed(db, "Alpha");
        Seed(db, "Bravo");
        LegacyLeaf(db, "legacy.example");
        var service = new ComplianceReportService(db, null!, NullLogger<ComplianceReportService>.Instance);
        ComplianceReportRequest For(Guid caId) => new() { CaId = caId, FromDate = DateTime.UtcNow.AddYears(-1), ToDate = DateTime.UtcNow.AddDays(1) };

        var report = await service.GenerateReportAsync(For(a.Ca.Id));
        Assert.Equal(1, report.Inventory.Total);

        var unknown = await service.GenerateReportAsync(For(Guid.NewGuid()));
        Assert.Equal(0, unknown.Inventory.Total);
    }
}
