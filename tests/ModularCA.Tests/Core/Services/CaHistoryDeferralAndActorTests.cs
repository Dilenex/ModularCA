using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Helpers;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Modes;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Api;
using ModularCA.Tests.Modes;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// The certificate history's first entries are not written while the instance is in DR mode, and
/// everything that reads the table is right while a CA has no row; and the audit row of every
/// certificate a CA revocation reaches names the person who asked.
/// </summary>
public sealed class CaHistoryDeferralAndActorTests
{
    /// <summary>A CA as an install from before the history table holds it: no row in <c>CaCertificates</c>.</summary>
    private static (string Name, Guid CaId, Guid CertificateId) SeedOlderCa()
    {
        var name = $"older-{Guid.NewGuid():N}";
        using var db = InMemoryDbContextFactory.Create(name);
        var material = TestCaMaterial.CreateCa("CN=Older Root");
        var certificate = new CertificateEntity
        {
            CertificateId = Guid.NewGuid(), SerialNumber = "0B", SubjectDN = material.SubjectDn, Issuer = material.SubjectDn, IsCA = true,
            Pem = CertificateUtil.ConvertDerToPem(material.Certificate.GetEncoded(), "CERTIFICATE"), RawCertificate = material.Certificate.GetEncoded(),
            NotBefore = material.Certificate.NotBefore, NotAfter = material.Certificate.NotAfter,
        };
        certificate.IssuerCertificateId = certificate.CertificateId;
        db.Certificates.Add(certificate);
        var ca = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "Older Root", Label = "older-root", CertificateId = certificate.CertificateId, IsEnabled = true };
        db.CertificateAuthorities.Add(ca);
        db.SaveChanges();
        return (name, ca.Id, certificate.CertificateId);
    }

    private static CaCertificateHistoryService Service(string database, IInstanceModeGate gate)
    {
        var services = new ServiceCollection();
        services.AddScoped(_ => InMemoryDbContextFactory.Create(database));
        return new CaCertificateHistoryService(services.BuildServiceProvider().GetRequiredService<IServiceScopeFactory>(), gate,
            NullLogger<CaCertificateHistoryService>.Instance);
    }

    [Fact]
    public async Task In_dr_mode_nothing_is_written_and_it_is_written_once_the_mode_is_left()
    {
        var (name, caId, certificateId) = SeedOlderCa();
        var gate = new FixedModeGate(InstanceMode.DisasterRecovery);
        var service = Service(name, gate);

        Assert.True(await service.PassAsync(CancellationToken.None));      // comes back later
        Assert.True(await service.PassAsync(CancellationToken.None));
        using (var db = InMemoryDbContextFactory.Create(name))
        {
            Assert.Empty(db.CaCertificates);
            // With no row, every reader takes the CA's one certificate from its own row.
            Assert.Equal(caId, IssuerChainResolver.OwnerOf(db, certificateId)?.CaId);
            Assert.Equal(new[] { certificateId }, await IssuerChainResolver.CaCertificateIdsAsync(db, caId));
            Assert.Equal(new[] { certificateId }, await IssuerChainResolver.SameKeyScopeAsync(db, certificateId));
            Assert.Equal(certificateId, await IssuerChainResolver.CurrentSameKeyCertificateIdAsync(db, certificateId));
            Assert.Equal(0, await CaCertificateHistory.RegisterRenewedAsync(db, new TestKeystore()));
            var ca = db.CertificateAuthorities.Include(c => c.Certificate).Single(c => c.Id == caId);
            var report = (await new CaLifecycleService(db, new SystemConfig()).DescribeAsync([ca], DateTime.UtcNow))[caId];
            Assert.Equal(1, report.Facts.CertificateCount);
        }

        gate.Mode = InstanceMode.Full;
        Assert.False(await service.PassAsync(CancellationToken.None));     // done: no further pass
        using (var db = InMemoryDbContextFactory.Create(name))
            Assert.Equal((caId, certificateId, CaCertificateEntity.OriginInitial),
                db.CaCertificates.AsEnumerable().Select(h => (h.CertificateAuthorityId, h.CertificateId, h.Origin)).Single());
    }

    /// <summary>Restricted and maintenance mode freeze what a person configures; the instance recording a fact about itself goes on, as CRLs do.</summary>
    [Theory]
    [InlineData(InstanceMode.Full)]
    [InlineData(InstanceMode.Restricted)]
    [InlineData(InstanceMode.Maintenance)]
    public async Task Outside_dr_mode_the_first_entry_is_written(InstanceMode mode)
    {
        var (name, _, certificateId) = SeedOlderCa();

        Assert.False(await Service(name, new FixedModeGate(mode)).PassAsync(CancellationToken.None));

        using var db = InMemoryDbContextFactory.Create(name);
        Assert.Equal(certificateId, db.CaCertificates.Single().CertificateId);
    }

    // ── Who revoked ─────────────────────────────────────────────────────────────────────────

    private sealed record Row(string Action, Guid? ActorId, string? ActorName, string? TargetId, string? SourceIp, string Details);

    private sealed class CapturingAudit : IAuditService
    {
        public List<Row> Rows { get; } = [];
        public Task LogAsync(string actionType, Guid? actorUserId, string? actorUsername, string? targetEntityType = null,
            string? targetEntityId = null, object? details = null, string? sourceIp = null, bool success = true,
            string? errorMessage = null, Guid? certificateAuthorityId = null, Guid? spaceId = null)
        {
            Rows.Add(new Row(actionType, actorUserId, actorUsername, targetEntityId, sourceIp, System.Text.Json.JsonSerializer.Serialize(details)));
            return Task.CompletedTask;
        }
    }

    [Fact]
    public async Task The_audit_row_of_each_other_certificate_names_the_person_the_address_and_the_ceremony()
    {
        await using var world = new CaCertificateRenewalTests.World();
        var w = world.W;
        var root = await w.CreateRootAsync("Audited Root", null, null);
        var oldId = root.CertificateId!.Value;
        var newId = (await world.RenewAsync(root)).Renewed.CertificateId;
        var primarySerial = w.Db.Certificates.AsNoTracking().Single(c => c.CertificateId == newId).SerialNumber;
        w.Db.ChangeTracker.Clear();
        var audit = new CapturingAudit();
        var service = new CertificateRevocationService(w.Db, w.World.Keystore, new CertificateStore(w.Db),
            InstanceCeremonyEndpointTests.Fake<INotificationService>.Create(), world.Crls, NullLogger<CertificateRevocationService>.Instance, null, audit);
        var person = new RevocationActor(Guid.NewGuid(), "alice", "203.0.113.7", Guid.NewGuid());

        await service.HoldCertificateAsync(newId, null, person);
        w.Db.ChangeTracker.Clear();
        await service.UnholdCertificateAsync(newId, null, person);
        w.Db.ChangeTracker.Clear();
        await service.RevokeCertificateAsync(newId, null, RevocationReason.KeyCompromise, null, person);

        Assert.Equal(new[] { AuditActionType.CertificateHeld, AuditActionType.CertificateUnheld, AuditActionType.CertificateRevoked }, audit.Rows.Select(r => r.Action).ToArray());
        Assert.All(audit.Rows, row =>
        {
            Assert.Equal((person.UserId, "alice", "203.0.113.7", oldId.ToString()), (row.ActorId, row.ActorName, row.SourceIp, row.TargetId));
            Assert.Contains(person.CeremonyId!.Value.ToString(), row.Details);
            Assert.Contains("SameKeyAs", row.Details);
            Assert.Contains(primarySerial, row.Details, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("system", row.ActorName!, StringComparison.OrdinalIgnoreCase);
        });
    }
}
