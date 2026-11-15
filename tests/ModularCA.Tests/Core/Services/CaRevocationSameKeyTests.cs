using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Helpers;
using ModularCA.Core.Services;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Interfaces;
using ModularCA.Tests.Api;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Revoking, holding and releasing a CA whose certificate was renewed: every certificate the CA
/// has over the key is reached by the one action, each with a fact for the signer's journal and
/// an audit row, and a certificate of another key or another CA is not.
/// </summary>
public sealed class CaRevocationSameKeyTests
{
    private static (CertificateRevocationService Service, RecordingAuditService Audit) Revocation(CaCertificateRenewalTests.World world)
    {
        var audit = new RecordingAuditService();
        return (new CertificateRevocationService(world.W.Db, world.W.World.Keystore, new CertificateStore(world.W.Db),
            InstanceCeremonyEndpointTests.Fake<INotificationService>.Create(), world.Crls, NullLogger<CertificateRevocationService>.Instance, null, audit), audit);
    }

    private static List<CertificateEntity> Rows(CaCertificateRenewalTests.World world, params Guid?[] ids)
    {
        using var db = world.W.World.OpenDb();
        return ids.Select(id => db.Certificates.AsNoTracking().Single(c => c.CertificateId == id)).ToList();
    }

    [Theory]
    [InlineData(true)]     // asked for by the current certificate
    [InlineData(false)]    // asked for by the earlier one
    public async Task Revoking_a_renewed_root_revokes_every_certificate_it_has_over_the_key(bool byCurrent)
    {
        await using var world = new CaCertificateRenewalTests.World();
        var w = world.W;
        var root = await w.CreateRootAsync("Compromised Root", null, null);
        var other = await w.CreateRootAsync("Bystander Root", null, null);
        var oldId = root.CertificateId!.Value;
        var newId = (await world.RenewAsync(root)).Renewed.CertificateId;
        var (leafRow, _) = await world.LeafAsync(root, "survivor");
        w.Db.ChangeTracker.Clear();
        var factsBefore = w.Db.SignerFacts.Count();
        var (service, audit) = Revocation(world);

        var result = await service.RevokeCertificateAsync(byCurrent ? newId : oldId, null, RevocationReason.KeyCompromise);

        var rows = Rows(world, oldId, newId);
        Assert.All(rows, r => Assert.True(r.Revoked));
        Assert.All(rows, r => Assert.Equal(nameof(RevocationReason.KeyCompromise), r.RevocationReason));
        Assert.Equal(rows[0].RevocationDate, rows[1].RevocationDate);                    // one date
        Assert.Equal(rows[byCurrent ? 0 : 1].SerialNumber, Assert.Single(result.AlsoSerialNumbers));
        // Each is a fact for the journal, queued in the same save.
        Assert.Equal(factsBefore + 2, w.Db.SignerFacts.AsNoTracking().Count());
        // The caller audits the certificate it named; the service audits the other.
        var audited = Assert.Single(audit.Entries, e => e.Action == AuditActionType.CertificateRevoked);
        Assert.Equal((byCurrent ? oldId : newId).ToString(), audited.TargetId);
        // Nothing else is touched: not a leaf, not another CA.
        Assert.False(Rows(world, leafRow.CertificateId)[0].Revoked);
        Assert.False(Rows(world, other.CertificateId)[0].Revoked);

        // Revoked once: a second revocation of either is refused as already revoked.
        w.Db.ChangeTracker.Clear();
        await Assert.ThrowsAsync<CertificateRevocationStateException>(() => service.RevokeCertificateAsync(oldId, null, RevocationReason.KeyCompromise));
    }

    [Fact]
    public async Task Revoking_a_renewed_intermediate_revokes_both_of_its_certificates_and_neither_of_its_parents()
    {
        await using var world = new CaCertificateRenewalTests.World();
        var w = world.W;
        var root = await w.CreateRootAsync("Standing Root", null, null);
        var issuing = await w.CreateIntermediateAsync(root, "Compromised Issuing", null, null);
        var oldId = issuing.CertificateId!.Value;
        var newId = (await world.RenewAsync(issuing, years: 4)).Renewed.CertificateId;
        w.Db.ChangeTracker.Clear();
        var (service, _) = Revocation(world);

        var result = await service.RevokeCertificateAsync(newId, null, RevocationReason.CACompromise);

        Assert.Single(result.AlsoSerialNumbers);
        Assert.All(Rows(world, oldId, newId), r => Assert.Equal(nameof(RevocationReason.CACompromise), r.RevocationReason));
        Assert.False(Rows(world, root.CertificateId)[0].Revoked);
        // Both name the parent's certificate as their issuer, so the parent's CRL lists both.
        using var db = w.World.OpenDb();
        var parentScope = await IssuerChainResolver.SameKeyScopeAsync(db, root.CertificateId!.Value);
        Assert.All(Rows(world, oldId, newId), r => Assert.Contains(r.IssuerCertificateId!.Value, parentScope));
    }

    [Fact]
    public async Task A_hold_and_its_release_reach_every_certificate_and_a_permanent_revocation_stays()
    {
        await using var world = new CaCertificateRenewalTests.World();
        var w = world.W;
        var root = await w.CreateRootAsync("Held Root", null, null);
        var firstId = root.CertificateId!.Value;
        var secondId = (await world.RenewAsync(root, years: 10)).Renewed.CertificateId;
        var thirdId = (await world.RenewAsync(root, years: 20)).Renewed.CertificateId;
        w.Db.ChangeTracker.Clear();
        var (service, audit) = Revocation(world);

        var held = await service.HoldCertificateAsync(thirdId, null);
        Assert.Equal(2, held.AlsoSerialNumbers.Count);
        Assert.All(Rows(world, firstId, secondId, thirdId), r => Assert.Equal(nameof(RevocationReason.CertificateHold), r.RevocationReason));
        Assert.Equal(2, audit.Entries.Count(e => e.Action == AuditActionType.CertificateHeld));

        w.Db.ChangeTracker.Clear();
        var released = await service.UnholdCertificateAsync(firstId, null);
        Assert.Equal(2, released.AlsoSerialNumbers.Count);
        Assert.All(Rows(world, firstId, secondId, thirdId), r => Assert.False(r.Revoked));
        Assert.Equal(2, audit.Entries.Count(e => e.Action == AuditActionType.CertificateUnheld));

        // One certificate revoked for good on its own row (as an install from before this rule may
        // hold it): a hold reaches the others, and the release does not bring the revoked one back.
        w.Db.ChangeTracker.Clear();
        var alone = w.Db.Certificates.Single(c => c.CertificateId == firstId);
        alone.Revoked = true;
        alone.RevocationReason = nameof(RevocationReason.Superseded);
        alone.RevocationDate = DateTime.UtcNow;
        w.Db.SaveChanges();
        w.Db.ChangeTracker.Clear();
        Assert.Single((await service.HoldCertificateAsync(secondId, null)).AlsoSerialNumbers);
        w.Db.ChangeTracker.Clear();
        Assert.Single((await service.UnholdCertificateAsync(thirdId, null)).AlsoSerialNumbers);
        var after = Rows(world, firstId, secondId, thirdId);
        Assert.Equal(nameof(RevocationReason.Superseded), after[0].RevocationReason);
        Assert.False(after[1].Revoked);
        Assert.False(after[2].Revoked);

        // A hold turned into a permanent revocation turns every held certificate with it.
        w.Db.ChangeTracker.Clear();
        await service.HoldCertificateAsync(secondId, null);
        w.Db.ChangeTracker.Clear();
        var permanent = await service.RevokeCertificateAsync(secondId, null, RevocationReason.KeyCompromise);
        Assert.Equal(RevocationReason.CertificateHold, permanent.PreviousReason);
        var final = Rows(world, firstId, secondId, thirdId);
        Assert.Equal(nameof(RevocationReason.Superseded), final[0].RevocationReason);
        Assert.Equal(nameof(RevocationReason.KeyCompromise), final[1].RevocationReason);
        Assert.Equal(nameof(RevocationReason.KeyCompromise), final[2].RevocationReason);
    }

    [Fact]
    public async Task A_leaf_and_a_ca_that_was_never_renewed_are_revoked_alone()
    {
        await using var world = new CaCertificateRenewalTests.World();
        var w = world.W;
        var root = await w.CreateRootAsync("Single Root", null, null);
        var (first, _) = await world.LeafAsync(root, "one");
        var (second, _) = await world.LeafAsync(root, "two");
        w.Db.ChangeTracker.Clear();
        var (service, audit) = Revocation(world);

        Assert.Empty((await service.RevokeCertificateAsync(first.CertificateId, null, RevocationReason.Superseded)).AlsoSerialNumbers);
        Assert.False(Rows(world, second.CertificateId)[0].Revoked);
        w.Db.ChangeTracker.Clear();
        Assert.Empty((await service.RevokeCertificateAsync(root.CertificateId, null, RevocationReason.CessationOfOperation)).AlsoSerialNumbers);
        Assert.Empty(audit.Entries);
    }
}
