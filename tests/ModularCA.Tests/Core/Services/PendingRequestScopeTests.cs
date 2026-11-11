using Microsoft.AspNetCore.DataProtection;
using ModularCA.Core.Services;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// The pending-request list's CA scoping. An empty accessible set used to be read as "no
/// scoping" and returned every request in the system; it must mean "no CA at all".
/// </summary>
public class PendingRequestScopeTests
{

    private static (CsrService Service, Guid CaId, Guid OtherCaId) Seed(ModularCA.Database.ModularCADbContext db)
    {
        var certA = new CertificateEntity { CertificateId = Guid.NewGuid(), SerialNumber = "01", SubjectDN = "CN=A", Issuer = "CN=A", Pem = "x" };
        var certB = new CertificateEntity { CertificateId = Guid.NewGuid(), SerialNumber = "02", SubjectDN = "CN=B", Issuer = "CN=B", Pem = "x" };
        var caA = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "A", Label = "a", CertificateId = certA.CertificateId };
        var caB = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "B", Label = "b", CertificateId = certB.CertificateId };
        var spA = new SigningProfileEntity { Id = Guid.NewGuid(), Name = "sp-a", IssuerId = certA.CertificateId };
        var spB = new SigningProfileEntity { Id = Guid.NewGuid(), Name = "sp-b", IssuerId = certB.CertificateId };
        db.Certificates.AddRange(certA, certB);
        db.CertificateAuthorities.AddRange(caA, caB);
        db.SigningProfiles.AddRange(spA, spB);
        db.CertificateRequests.AddRange(
            new CertRequestEntity { Id = Guid.NewGuid(), Subject = "CN=one", CSR = "-", SigningProfileId = spA.Id },
            new CertRequestEntity { Id = Guid.NewGuid(), Subject = "CN=two", CSR = "-", SigningProfileId = spB.Id });
        db.SaveChanges();
        return (new CsrService(db, new HeldKeyService(db, new EphemeralDataProtectionProvider(), new RecordingAuditService())), caA.Id, caB.Id);
    }

    [Fact]
    public async Task Null_means_everything_and_a_ca_list_means_only_those_cas()
    {
        using var db = InMemoryDbContextFactory.Create();
        var (service, caA, _) = Seed(db);

        var all = await service.GetPendingRequests(null);
        var onlyA = await service.GetPendingRequests([caA]);

        Assert.Equal(2, all.Count);
        Assert.Equal("CN=one", Assert.Single(onlyA).SubjectName);
    }

    [Fact]
    public async Task An_empty_ca_list_yields_nothing()
    {
        using var db = InMemoryDbContextFactory.Create();
        var (service, _, _) = Seed(db);

        var none = await service.GetPendingRequests([]);

        Assert.Empty(none);
    }

    /// <summary>
    /// A requester whose account was deleted and retained is hidden from ordinary queries. Its
    /// request stays in the list and still says who made it.
    /// </summary>
    [Fact]
    public async Task A_request_whose_requester_was_deleted_still_names_them()
    {
        using var db = InMemoryDbContextFactory.Create();
        var (service, _, _) = Seed(db);
        var gone = new UserEntity { Id = Guid.NewGuid(), Username = "left-the-company", Email = "gone@x", IsDeleted = true, IsActive = false };
        var here = new UserEntity { Id = Guid.NewGuid(), Username = "still-here", Email = "here@x" };
        db.Users.AddRange(gone, here);
        db.CertificateRequests.AddRange(
            new CertRequestEntity { Id = Guid.NewGuid(), Subject = "CN=by-gone", CSR = "-", RequestorUserId = gone.Id },
            new CertRequestEntity { Id = Guid.NewGuid(), Subject = "CN=by-here", CSR = "-", RequestorUserId = here.Id });
        db.SaveChanges();
        db.ChangeTracker.Clear();

        var all = await service.GetPendingRequests(null);

        Assert.Equal("left-the-company (deleted)", all.Single(r => r.SubjectName == "CN=by-gone").RequestorUsername);
        Assert.Equal("still-here", all.Single(r => r.SubjectName == "CN=by-here").RequestorUsername);
        Assert.Null(all.Single(r => r.SubjectName == "CN=one").RequestorUsername);
    }

}
