using ModularCA.Auth.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Auth;

/// <summary>
/// The self-service "My Certificates" page listed every certificate the caller could view, which
/// for an operator is every certificate of its CAs. An account's own certificates are the ones it
/// requested and the ones shared with it by name.
/// </summary>
public class CertificateOwnershipTests
{
    [Fact]
    public async Task An_accounts_own_certificates_are_those_it_requested_and_those_shared_with_it()
    {
        using var db = InMemoryDbContextFactory.Create();
        var me = Guid.NewGuid();
        var other = Guid.NewGuid();
        Guid requested = Guid.NewGuid(), shared = Guid.NewGuid(), someoneElses = Guid.NewGuid(), sharedWithOther = Guid.NewGuid();

        db.CertificateRequests.AddRange(
            new CertRequestEntity { Subject = "CN=mine", RequestorUserId = me, IssuedCertificateId = requested },
            new CertRequestEntity { Subject = "CN=mine-not-issued", RequestorUserId = me },
            new CertRequestEntity { Subject = "CN=theirs", RequestorUserId = other, IssuedCertificateId = someoneElses },
            new CertRequestEntity { Subject = "CN=device", RequestorUserId = null, IssuedCertificateId = Guid.NewGuid() });
        db.CertificateAccessLists.AddRange(
            new CertificateAccessListEntity { UserId = me, CertificateId = shared, AccessLevel = CertificateAccessLevel.View },
            new CertificateAccessListEntity { UserId = other, CertificateId = sharedWithOther, AccessLevel = CertificateAccessLevel.Manage });
        await db.SaveChangesAsync();

        var own = await CertificateOwnership.OwnedByAsync(db, me);

        Assert.Equal(new HashSet<Guid> { requested, shared }, own);
        Assert.Empty(await CertificateOwnership.OwnedByAsync(db, Guid.NewGuid()));
    }
}
