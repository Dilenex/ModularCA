using Microsoft.EntityFrameworkCore;
using ModularCA.Auth.Services;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Auth.Services;

/// <summary>
/// Tests for <see cref="CertificateAccessService.UpdatePermissionsOntoReissuedCertificate"/>.
/// <para>
/// This method used to FIND the predecessor itself, by <c>SubjectDN</c> string equality across
/// the whole Certificates table, ordered by NotBefore — and <c>CertificateEntity</c> carries no
/// tenant query filter, so the search spanned every CA in every tenant. Any certificate anywhere
/// sharing the subject, with a newer NotBefore, donated its ACL rows to this one. Two tenants
/// both issuing <c>CN=vpn.example.com</c> cross-pollinated permissions on every renewal with no
/// attacker involved; a user able to get a certificate issued with a chosen subject on any CA
/// could plant a Manage grant that landed on someone else's production certificate at its next
/// reissue, and Manage is what PFX export checks before handing over the private key.
/// </para>
/// <para>
/// The predecessor is now passed in by the caller, which always knows it: every reissue entry
/// point resolves to a CSR whose <c>IssuedCertificateId</c> is the certificate being replaced.
/// The tests that used to pin the search behaviour (most-recent-NotBefore wins, exclude self)
/// have been replaced — that behaviour is deliberately gone.
/// </para>
/// </summary>
public class CertificateAccessServiceTests
{
    private static CertificateEntity NewCert(string subjectDn, DateTime notBefore, Guid? id = null) =>
        new CertificateEntity
        {
            CertificateId = id ?? Guid.NewGuid(),
            SerialNumber = Guid.NewGuid().ToString("N"),
            SubjectDN = subjectDn,
            NotBefore = notBefore,
            NotAfter = notBefore.AddYears(1),
        };

    private static readonly DateTime Y2025 = new(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    private static readonly DateTime Y2026 = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    [Fact]
    public async Task Throws_When_NewCert_Does_Not_Exist()
    {
        using var db = InMemoryDbContextFactory.Create();
        var svc = new CertificateAccessService(db);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            svc.UpdatePermissionsOntoReissuedCertificate(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid()));
    }

    [Fact]
    public async Task Copies_permissions_from_the_named_predecessor()
    {
        using var db = InMemoryDbContextFactory.Create();
        var oldCert = NewCert("CN=server.example.com", Y2025);
        var newCert = NewCert("CN=server.example.com", Y2026);
        db.Certificates.AddRange(oldCert, newCert);

        var alice = Guid.NewGuid();
        var bob = Guid.NewGuid();
        db.CertificateAccessLists.AddRange(
            new CertificateAccessListEntity { UserId = alice, CertificateId = oldCert.CertificateId, AccessLevel = CertificateAccessLevel.Manage, GrantedByUserId = Guid.NewGuid() },
            new CertificateAccessListEntity { UserId = bob, CertificateId = oldCert.CertificateId, AccessLevel = CertificateAccessLevel.View, GrantedByUserId = Guid.NewGuid() });
        await db.SaveChangesAsync();

        var operatorId = Guid.NewGuid();
        var svc = new CertificateAccessService(db);
        await svc.UpdatePermissionsOntoReissuedCertificate(newCert.CertificateId, operatorId, oldCert.CertificateId);

        var perms = await db.CertificateAccessLists.Where(p => p.CertificateId == newCert.CertificateId).ToListAsync();
        Assert.Equal(2, perms.Count);
        Assert.Contains(perms, p => p.UserId == alice && p.AccessLevel == CertificateAccessLevel.Manage);
        Assert.Contains(perms, p => p.UserId == bob && p.AccessLevel == CertificateAccessLevel.View);
        // The reissuing operator is the GrantedBy on every copy, preserving who triggered it.
        Assert.All(perms, p => Assert.Equal(operatorId, p.GrantedByUserId));
    }

    [Fact]
    public async Task An_unrelated_certificate_with_the_same_subject_donates_nothing()
    {
        // THE security test. A certificate sharing the subject DN — issued by another CA, in
        // another tenant, by anyone — must not contribute ACL rows just because it exists and
        // sorts newer. Under the old subject-DN search, mallory's row landed on newCert.
        using var db = InMemoryDbContextFactory.Create();
        var realPredecessor = NewCert("CN=vpn.example.com", Y2025);
        var impostor = NewCert("CN=vpn.example.com", new DateTime(2025, 12, 1, 0, 0, 0, DateTimeKind.Utc));
        var newCert = NewCert("CN=vpn.example.com", Y2026);
        db.Certificates.AddRange(realPredecessor, impostor, newCert);

        var legitimate = Guid.NewGuid();
        var mallory = Guid.NewGuid();
        db.CertificateAccessLists.AddRange(
            new CertificateAccessListEntity { UserId = legitimate, CertificateId = realPredecessor.CertificateId, AccessLevel = CertificateAccessLevel.View, GrantedByUserId = Guid.NewGuid() },
            new CertificateAccessListEntity { UserId = mallory, CertificateId = impostor.CertificateId, AccessLevel = CertificateAccessLevel.Manage, GrantedByUserId = Guid.NewGuid() });
        await db.SaveChangesAsync();

        var svc = new CertificateAccessService(db);
        await svc.UpdatePermissionsOntoReissuedCertificate(newCert.CertificateId, Guid.NewGuid(), realPredecessor.CertificateId);

        var perms = await db.CertificateAccessLists.Where(p => p.CertificateId == newCert.CertificateId).ToListAsync();
        Assert.Single(perms);
        Assert.Equal(legitimate, perms[0].UserId);
        Assert.DoesNotContain(perms, p => p.UserId == mallory);
    }

    [Fact]
    public async Task No_predecessor_named_means_nothing_is_inherited()
    {
        // Fails closed. A same-subject certificate is present and would have been picked up by
        // the old search; with no predecessor named, nothing is copied.
        using var db = InMemoryDbContextFactory.Create();
        var other = NewCert("CN=fresh.example.com", Y2025);
        var newCert = NewCert("CN=fresh.example.com", Y2026);
        db.Certificates.AddRange(other, newCert);
        db.CertificateAccessLists.Add(new CertificateAccessListEntity
        {
            UserId = Guid.NewGuid(),
            CertificateId = other.CertificateId,
            AccessLevel = CertificateAccessLevel.Manage,
            GrantedByUserId = Guid.NewGuid()
        });
        await db.SaveChangesAsync();

        var svc = new CertificateAccessService(db);
        await svc.UpdatePermissionsOntoReissuedCertificate(newCert.CertificateId, Guid.NewGuid(), previousCertId: null);

        Assert.Empty(await db.CertificateAccessLists.Where(p => p.CertificateId == newCert.CertificateId).ToListAsync());
    }

    [Fact]
    public async Task A_certificate_named_as_its_own_predecessor_is_a_no_op()
    {
        using var db = InMemoryDbContextFactory.Create();
        var newCert = NewCert("CN=server.example.com", Y2026);
        db.Certificates.Add(newCert);
        await db.SaveChangesAsync();

        var svc = new CertificateAccessService(db);
        await svc.UpdatePermissionsOntoReissuedCertificate(newCert.CertificateId, Guid.NewGuid(), newCert.CertificateId);

        Assert.Empty(await db.CertificateAccessLists.ToListAsync());
    }

    [Fact]
    public async Task A_predecessor_that_no_longer_exists_inherits_nothing()
    {
        using var db = InMemoryDbContextFactory.Create();
        var newCert = NewCert("CN=server.example.com", Y2026);
        db.Certificates.Add(newCert);
        await db.SaveChangesAsync();

        var svc = new CertificateAccessService(db);
        await svc.UpdatePermissionsOntoReissuedCertificate(newCert.CertificateId, Guid.NewGuid(), Guid.NewGuid());

        Assert.Empty(await db.CertificateAccessLists.ToListAsync());
    }

    [Fact]
    public async Task An_existing_grant_on_the_new_certificate_is_not_duplicated()
    {
        // (UserId, CertificateId) is unique; re-inserting the requestor's own issuance-time
        // grant used to throw a duplicate-key DbUpdateException out of the reissue path.
        using var db = InMemoryDbContextFactory.Create();
        var oldCert = NewCert("CN=server.example.com", Y2025);
        var newCert = NewCert("CN=server.example.com", Y2026);
        db.Certificates.AddRange(oldCert, newCert);

        var alice = Guid.NewGuid();
        db.CertificateAccessLists.AddRange(
            new CertificateAccessListEntity { UserId = alice, CertificateId = oldCert.CertificateId, AccessLevel = CertificateAccessLevel.View, GrantedByUserId = Guid.NewGuid() },
            new CertificateAccessListEntity { UserId = alice, CertificateId = newCert.CertificateId, AccessLevel = CertificateAccessLevel.Manage, GrantedByUserId = Guid.NewGuid() });
        await db.SaveChangesAsync();

        var svc = new CertificateAccessService(db);
        await svc.UpdatePermissionsOntoReissuedCertificate(newCert.CertificateId, Guid.NewGuid(), oldCert.CertificateId);

        var perms = await db.CertificateAccessLists.Where(p => p.CertificateId == newCert.CertificateId).ToListAsync();
        Assert.Single(perms);
        // The pre-existing, stronger grant survives; it is not downgraded by the copy.
        Assert.Equal(CertificateAccessLevel.Manage, perms[0].AccessLevel);
    }
}
