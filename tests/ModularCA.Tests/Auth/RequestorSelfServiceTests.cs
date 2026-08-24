using Microsoft.EntityFrameworkCore;
using ModularCA.Auth.Implementations;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using Xunit;

namespace ModularCA.Tests.Auth;

/// <summary>
/// Covers self-service rights over a certificate you requested.
/// <para>
/// <c>CanViewCertificate</c> has always granted the original requestor access;
/// <c>CanManageCertificate</c> did not. Since Manage gates all three self-service endpoints —
/// PFX export, renew, and one literally named <c>RevokeOwnCertificate</c> — a user who
/// requested a certificate with a CA-generated key could see it but never export the key,
/// leaving that key permanently unreachable by the only person who needed it.
/// </para>
/// <para>
/// The grant stops at the CA's own machinery: requesting a CA certificate or an infrastructure
/// (OCSP/TSA responder) certificate must not confer control over it, because revoking a
/// responder takes out the CA.
/// </para>
/// </summary>
public class RequestorSelfServiceTests
{
    /// <summary>System-admin-off tenant context, so the global filter behaves like a normal user session.</summary>
    private sealed class NoTenantContext : ITenantContext
    {
        public bool HasContext => true;
        public bool IsSystemAdmin => true;   // bypass the tenant filter; this suite is about capability, not tenancy
        public IReadOnlySet<Guid> AccessibleTenantIds => new HashSet<Guid>();
        public Guid? UserId => null;
        public void Set(Guid? userId, IReadOnlySet<Guid> accessibleTenantIds, bool isSystemAdmin) { }
    }

    private static readonly Guid Requestor = Guid.Parse("11111111-0000-0000-0000-000000000001");
    private static readonly Guid Stranger = Guid.Parse("22222222-0000-0000-0000-000000000002");

    private static ModularCADbContext BuildContext(string dbName)
    {
        var options = new DbContextOptionsBuilder<ModularCADbContext>()
            .UseInMemoryDatabase(dbName)
            .ConfigureWarnings(w => w.Ignore(
                Microsoft.EntityFrameworkCore.Diagnostics.InMemoryEventId.TransactionIgnoredWarning))
            .Options;
        return new ModularCADbContext(options, new NoTenantContext());
    }

    /// <summary>Seeds one certificate plus the request that produced it, and returns its id.</summary>
    private static Guid Seed(ModularCADbContext db, Guid requestorId, bool isCa = false, bool isInfrastructure = false)
    {
        var certId = Guid.NewGuid();
        db.Certificates.Add(new CertificateEntity
        {
            CertificateId = certId,
            SerialNumber = certId.ToString("N"),
            SubjectDN = "CN=self-service.test",
            Issuer = "CN=Test CA",
            Pem = "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----",
            IsCA = isCa,
        });
        db.CertificateRequests.Add(new CertRequestEntity
        {
            Id = Guid.NewGuid(),
            CSR = "stub",
            Subject = "CN=self-service.test",
            Status = "Issued",
            IssuedCertificateId = certId,
            RequestorUserId = requestorId,
            IsInfrastructureCert = isInfrastructure,
        });
        db.SaveChanges();
        return certId;
    }

    [Fact]
    public void The_requestor_can_manage_the_certificate_they_asked_for()
    {
        using var db = BuildContext(nameof(The_requestor_can_manage_the_certificate_they_asked_for));
        var certId = Seed(db, Requestor);

        Assert.True(new CertificateAccessEvaluator(db).CanManageCertificate(Requestor, certId));
    }

    [Fact]
    public void Someone_who_did_not_request_it_still_cannot_manage_it()
    {
        // The grant is requestor-scoped, not "any authenticated user".
        using var db = BuildContext(nameof(Someone_who_did_not_request_it_still_cannot_manage_it));
        var certId = Seed(db, Requestor);

        Assert.False(new CertificateAccessEvaluator(db).CanManageCertificate(Stranger, certId));
    }

    [Fact]
    public void Requesting_a_CA_certificate_does_not_confer_manage_over_it()
    {
        using var db = BuildContext(nameof(Requesting_a_CA_certificate_does_not_confer_manage_over_it));
        var certId = Seed(db, Requestor, isCa: true);

        Assert.False(new CertificateAccessEvaluator(db).CanManageCertificate(Requestor, certId));
    }

    [Fact]
    public void Requesting_an_infrastructure_certificate_does_not_confer_manage_over_it()
    {
        // OCSP/TSA responders: revoking one takes out the CA's responder for every relying
        // party, so requestor status must not be enough.
        using var db = BuildContext(nameof(Requesting_an_infrastructure_certificate_does_not_confer_manage_over_it));
        var certId = Seed(db, Requestor, isInfrastructure: true);

        Assert.False(new CertificateAccessEvaluator(db).CanManageCertificate(Requestor, certId));
    }

    [Fact]
    public void View_access_for_the_requestor_is_unchanged()
    {
        // Guards against "fixing" Manage by loosening or reshaping the View clause.
        using var db = BuildContext(nameof(View_access_for_the_requestor_is_unchanged));
        var certId = Seed(db, Requestor);
        var evaluator = new CertificateAccessEvaluator(db);

        Assert.True(evaluator.CanViewCertificate(Requestor, certId));
        Assert.False(evaluator.CanViewCertificate(Stranger, certId));
    }
}
