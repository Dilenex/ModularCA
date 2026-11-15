using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Helpers;
using ModularCA.Core.Services;
using ModularCA.Core.Services.Journal;
using ModularCA.Database;
using ModularCA.Journal;
using ModularCA.Keystore.Signing;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Modes;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Api;
using ModularCA.Tests.Journal;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// A renewed CA on PostgreSQL, over the real CRL service, signer journal and public endpoints:
/// one CRL for both certificates, served at the old serial, the new serial and the label; the
/// earlier certificate still served at its serial; the journal's CRL stream continuing under the
/// same key; and revocations lost from the database coming back by the merge, whichever
/// certificate their certificates were issued under.
/// </summary>
[Trait("Category", "PostgreSQL")]
[Trait(TestTier.Name, TestTier.Slow)]
[Collection(PostgresLane.Three)]
public class PostgresCaCertificateRenewalTests
{
    private sealed class NoServiceUrls : ICaServiceUrlService
    {
        public Task<CaServiceUrlEntity?> GetByCaCertificateIdAsync(Guid caCertificateId) => Task.FromResult<CaServiceUrlEntity?>(null);
        public Task<List<CaServiceUrlEntity>> GetAllAsync() => Task.FromResult(new List<CaServiceUrlEntity>());
        public Task<CaServiceUrlEntity> CreateOrUpdateAsync(Guid caCertificateId, string? publicBaseUrl) => Task.FromResult(new CaServiceUrlEntity());
        public Task<ModularCA.Shared.Models.ResolvedCaServiceUrls> ResolveForCaAsync(Guid caCertificateId) => Task.FromResult(new ModularCA.Shared.Models.ResolvedCaServiceUrls([], [], []));
        public Task<bool> DeleteAsync(Guid caCertificateId) => Task.FromResult(false);
    }

    private static async Task<(Guid Id, BigInteger Serial)> LeafAsync(string connection, TestCaMaterial ca, long serial, Guid issuerCertificateId, bool revoked)
    {
        var certificate = ca.Issue(BigInteger.ValueOf(serial), $"CN=leaf-{serial}");
        await using var db = PostgresCaFixture.Open(connection);
        var row = new CertificateEntity
        {
            CertificateId = Guid.NewGuid(),
            SerialNumber = CertificateUtil.FormatSerialNumber(certificate.SerialNumber),
            SubjectDN = certificate.SubjectDN.ToString(), Issuer = certificate.IssuerDN.ToString(),
            Pem = CertificateUtil.ConvertDerToPem(certificate.GetEncoded(), "CERTIFICATE"), RawCertificate = certificate.GetEncoded(),
            NotBefore = certificate.NotBefore, NotAfter = certificate.NotAfter,
            IssuerCertificateId = issuerCertificateId,
            Revoked = revoked, RevocationReason = revoked ? "KeyCompromise" : null, RevocationDate = revoked ? DateTime.UtcNow : null,
        };
        db.Certificates.Add(row);
        await db.SaveChangesAsync();
        return (row.CertificateId, certificate.SerialNumber);
    }

    private static byte[] FileOf(IActionResult result) => Assert.IsType<FileContentResult>(result).FileContents;

    /// <summary>
    /// A renewed intermediate, revoked: both of its certificates are revoked by the one action,
    /// the CRL its parent generates lists both, and the signer, whose journal holds the parent's
    /// earlier CRLs, signs that CRL as a continuation of them.
    /// </summary>
    [RequiresEnvironmentFact(PostgresCaFixture.ServerVariable)]
    public Task A_revoked_renewed_intermediate_has_both_certificates_on_its_parents_crl_and_the_journal_accepts_it()
        => PostgresCaFixture.WithDatabaseAsync("modularca_carevoke", async connection =>
        {
            PostgresCaFixture.SeededCa parent;
            var child = TestCaMaterial.CreateCa("CN=renewed-issuing, O=ModularCA");
            var childCaId = Guid.NewGuid();
            var childOldId = Guid.NewGuid();
            X509Certificate childOld;
            await using (var seed = PostgresCaFixture.Open(connection))
            {
                parent = await PostgresCaFixture.SeedCaAsync(seed, "parent-ca");
                var space = await seed.Spaces.SingleAsync();
                space.RequireKeyCeremony = false;
                childOld = parent.Material.Issue(BigInteger.ValueOf(500), child.SubjectDn, child.KeyPair.Public, isCa: true);
                seed.Certificates.Add(new CertificateEntity
                {
                    CertificateId = childOldId, SerialNumber = CertificateUtil.FormatSerialNumber(childOld.SerialNumber),
                    SubjectDN = childOld.SubjectDN.ToString(), Issuer = childOld.IssuerDN.ToString(), IsCA = true,
                    Pem = CertificateUtil.ConvertDerToPem(childOld.GetEncoded(), "CERTIFICATE"), RawCertificate = childOld.GetEncoded(),
                    NotBefore = childOld.NotBefore, NotAfter = childOld.NotAfter, IssuerCertificateId = parent.CaCertificateId,
                });
                await seed.SaveChangesAsync();
                seed.CertificateAuthorities.Add(new CertificateAuthorityEntity
                {
                    Id = childCaId, Name = "renewed-issuing", Label = "renewed-issuing", SpaceId = space.Id, CertificateId = childOldId,
                    ParentCaId = parent.CaId, Type = "Intermediate", IsEnabled = true,
                });
                await seed.SaveChangesAsync();
            }

            using var sandbox = new JournalSandbox();
            var audit = new RecordingAuditService();
            var services = new ServiceCollection();
            services.AddDbContext<ModularCADbContext>(o => o.UseNpgsql(connection));
            services.AddSingleton<IAuditService>(audit);
            var scopes = services.BuildServiceProvider().GetRequiredService<IServiceScopeFactory>();
            var keystore = new TestKeystore(parent.Material.AsSigner(), (childOld, child.AsSigner().Handle));
            await using var journal = new SignerJournal(() => sandbox.Options(), new SignerJournalSettings(sandbox.Home, true, "0.0.0-test", new byte[32]), NullLogger.Instance);
            var signer = new InProcessSigningService(keystore, scopes, new DatabaseSignerAuditSink(scopes),
                new InMemorySignerKeyPersistence(), NullLogger<InProcessSigningService>.Instance, journal: journal);
            CrlService Crls(ModularCADbContext db) => new(db, keystore, NullLogger<CrlService>.Instance, audit,
                new NoServiceUrls(), InstanceCeremonyEndpointTests.Fake<ILdapSecretProtector>.Create(), signer);
            CaCertificateRenewalService Renewal(ModularCADbContext db) => new(db, signer, keystore, new NoServiceUrls(), Crls(db), NullLogger<CaCertificateRenewalService>.Instance);

            // A CRL of the parent before anything happens, so the journal holds one to continue.
            X509Crl before;
            await using (var db = PostgresCaFixture.Open(connection))
                before = PostgresCaFixture.ParseCrl(await Crls(db).GenerateCrlAsync(parent.CaCertificateId));
            Assert.True((before.GetRevokedCertificates()?.Count ?? 0) == 0);

            // The parent's certificate ends when the child's does, so the parent is renewed first; then the child.
            Guid childNewId;
            X509Certificate childNew;
            await using (var db = PostgresCaFixture.Open(connection))
            {
                var parentPlan = await Renewal(db).PlanAsync(parent.CaId, 40, DateTime.UtcNow);
                await Renewal(db).RenewAsync(parent.CaId, parentPlan.NotAfter, null, "tester");
            }
            await using (var db = PostgresCaFixture.Open(connection))
            {
                var plan = await Renewal(db).PlanAsync(childCaId, 30, DateTime.UtcNow);
                var result = await Renewal(db).RenewAsync(childCaId, plan.NotAfter, null, "tester");
                (childNewId, childNew) = (result.Renewed.CertificateId, result.Certificate);
            }

            // Revoked by its current certificate, through the real revocation service: both go.
            ModularCA.Shared.Interfaces.RevocationResult revoked;
            await using (var db = PostgresCaFixture.Open(connection))
            {
                var revocation = new CertificateRevocationService(db, keystore, new CertificateStore(db),
                    InstanceCeremonyEndpointTests.Fake<INotificationService>.Create(), Crls(db), NullLogger<CertificateRevocationService>.Instance, null, audit);
                revoked = await revocation.RevokeCertificateAsync(childNewId, null, ModularCA.Shared.Enums.RevocationReason.CACompromise, null,
                    new RevocationActor(Guid.NewGuid(), "alice", "203.0.113.7"));
            }
            Assert.Equal(CertificateUtil.FormatSerialNumber(childOld.SerialNumber), Assert.Single(revoked.AlsoSerialNumbers));
            // The CRL was generated by the revocation itself: the signer did not refuse it.
            Assert.NotNull(revoked.CrlNumber);

            await using (var db = PostgresCaFixture.Open(connection))
            {
                var parentCurrent = (await db.CertificateAuthorities.AsNoTracking().SingleAsync(c => c.Id == parent.CaId)).CertificateId!.Value;
                var crl = PostgresCaFixture.ParseCrl((await Crls(db).GetLatestCrlAsync(parentCurrent))!);
                crl.Verify(parent.Material.Certificate.GetPublicKey());
                Assert.Equal(revoked.CrlNumber, PostgresCaFixture.CrlNumberOf(crl));
                Assert.True(PostgresCaFixture.CrlNumberOf(crl) > PostgresCaFixture.CrlNumberOf(before));
                Assert.NotNull(crl.GetRevokedCertificate(childOld.SerialNumber));
                Assert.NotNull(crl.GetRevokedCertificate(childNew.SerialNumber));
                // The same CRL at the parent's earlier certificate.
                Assert.Equal(crl.GetEncoded(), (await Crls(db).GetLatestCrlRawAsync(parent.CaCertificateId))!.Der);
                // One reason and one date on both rows, and a fact for the journal for each.
                var rows = await db.Certificates.AsNoTracking().Where(c => c.CertificateId == childOldId || c.CertificateId == childNewId).ToListAsync();
                Assert.All(rows, r => Assert.Equal("CACompromise", r.RevocationReason));
                Assert.Equal(rows[0].RevocationDate, rows[1].RevocationDate);
            }

            // The journal took that CRL in the parent's stream, after the earlier ones.
            var parentKey = SHA256.HashData(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(parent.Material.Certificate.GetPublicKey()).GetDerEncoded());
            var journaled = sandbox.Records().Where(r => r.Record.Type == RecordType.Crl).Select(r => CrlPayload.Decode(r.Record.Payload))
                .Where(c => c.CaKey.AsSpan().SequenceEqual(parentKey)).ToList();
            Assert.Equal((ulong)revoked.CrlNumber!.Value, journaled[^1].CrlNumber);
            Assert.Null(sandbox.Verify().Fault);
            Assert.Equal(2, (await signer.JournaledRevocationsAsync(parent.CaId, 0, 10))!.Total);
        });

    [RequiresEnvironmentFact(PostgresCaFixture.ServerVariable)]
    public Task One_crl_covers_both_certificates_is_served_at_every_address_and_survives_a_lost_database()
        => PostgresCaFixture.WithDatabaseAsync("modularca_carenew", async connection =>
        {
            PostgresCaFixture.SeededCa ca;
            await using (var seed = PostgresCaFixture.Open(connection))
            {
                ca = await PostgresCaFixture.SeedCaAsync(seed, "renewed-ca");
                // The seeded space waives ceremonies, so the renewal runs without one.
                (await seed.Spaces.SingleAsync()).RequireKeyCeremony = false;
                await seed.SaveChangesAsync();
            }
            var oldId = ca.CaCertificateId;
            var oldCertificate = ca.Material.Certificate;

            using var sandbox = new JournalSandbox();
            var audit = new RecordingAuditService();
            var services = new ServiceCollection();
            services.AddDbContext<ModularCADbContext>(o => o.UseNpgsql(connection));
            services.AddSingleton<IAuditService>(audit);
            var scopes = services.BuildServiceProvider().GetRequiredService<IServiceScopeFactory>();
            var keystore = new TestKeystore(ca.Material.AsSigner());
            await using var journal = new SignerJournal(() => sandbox.Options(), new SignerJournalSettings(sandbox.Home, true, "0.0.0-test", new byte[32]), NullLogger.Instance);
            var signer = new InProcessSigningService(keystore, scopes, new DatabaseSignerAuditSink(scopes),
                new InMemorySignerKeyPersistence(), NullLogger<InProcessSigningService>.Instance, journal: journal);
            JournalRevocationMerge Merge() => new(scopes, signer, new JournalMergeState(), FullInstanceModeGate.Instance, NullLogger<JournalRevocationMerge>.Instance);
            CrlService Crls(ModularCADbContext db) => new(db, keystore, NullLogger<CrlService>.Instance, audit,
                new NoServiceUrls(), InstanceCeremonyEndpointTests.Fake<ILdapSecretProtector>.Create(), signer, null, Merge());
            async Task<X509Crl> GenerateAsync(Guid caCertificateId)
            {
                await using var db = PostgresCaFixture.Open(connection);
                return PostgresCaFixture.ParseCrl(await Crls(db).GenerateCrlAsync(caCertificateId));
            }

            // Before the renewal: one revoked leaf, one good one, and a CRL.
            var (_, revokedBefore) = await LeafAsync(connection, ca.Material, 1001, oldId, revoked: true);
            var (_, goodBefore) = await LeafAsync(connection, ca.Material, 1002, oldId, revoked: false);
            var first = await GenerateAsync(oldId);
            Assert.NotNull(first.GetRevokedCertificate(revokedBefore));

            // The renewal, through the real service and signer.
            Guid newId;
            X509Certificate newCertificate;
            await using (var db = PostgresCaFixture.Open(connection))
            {
                var renewal = new CaCertificateRenewalService(db, signer, keystore,
                    new NoServiceUrls(), Crls(db), NullLogger<CaCertificateRenewalService>.Instance);
                var plan = await renewal.PlanAsync(ca.CaId, 30, DateTime.UtcNow);
                var result = await renewal.RenewAsync(ca.CaId, plan.NotAfter, null, "tester");
                (newId, newCertificate) = (result.Renewed.CertificateId, result.Certificate);
            }
            Assert.Equal(oldCertificate.GetPublicKey(), newCertificate.GetPublicKey());
            Assert.NotEqual(oldCertificate.SerialNumber, newCertificate.SerialNumber);

            // After it: a revoked leaf under the new certificate, and one more revoked under the old.
            var (_, revokedAfter) = await LeafAsync(connection, ca.Material, 2001, newId, revoked: true);
            var (_, revokedLateUnderOld) = await LeafAsync(connection, ca.Material, 1003, oldId, revoked: true);

            // Asked for by the old certificate's id, as revoking an old leaf asks: the CA's one CRL.
            var crl = await GenerateAsync(oldId);
            crl.Verify(oldCertificate.GetPublicKey());
            Assert.Equal(newCertificate.SubjectDN.GetEncoded(), crl.IssuerDN.GetEncoded());
            Assert.True(PostgresCaFixture.CrlNumberOf(crl) > PostgresCaFixture.CrlNumberOf(first), "the CRL number continues across the renewal");
            foreach (var serial in new[] { revokedBefore, revokedAfter, revokedLateUnderOld })
                Assert.NotNull(crl.GetRevokedCertificate(serial));
            Assert.Null(crl.GetRevokedCertificate(goodBefore));

            await using (var db = PostgresCaFixture.Open(connection))
            {
                var crls = Crls(db);
                var byNew = await crls.GetLatestCrlRawAsync(newId);
                var byOld = await crls.GetLatestCrlRawAsync(oldId);
                Assert.Equal(crl.GetEncoded(), byNew!.Der);
                Assert.Equal(byNew.Der, byOld!.Der);
                // Every schedule and CRL row is the current certificate's; none is left behind to go stale.
                Assert.Empty(await db.CrlConfigurations.Where(c => c.CaCertificateId == oldId).ToListAsync());

                // The public addresses: the CRL by old serial, new serial and label; each certificate by its serial; the label gives the current one.
                var controller = (ControllerBase)Activator.CreateInstance(ApiAssembly.TypeNamed("ModularCA.API.Controllers.v1.Public.PublicShortUrlController"),
                    new CertificateStore(db), crls, db)!;
                controller.ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() };
                async Task<byte[]> GetAsync(string action, string id)
                    => FileOf(await (Task<IActionResult>)controller.GetType().GetMethod(action)!.Invoke(controller, [id])!);
                var oldSerial = CertificateUtil.FormatSerialNumber(oldCertificate.SerialNumber);
                var newSerial = CertificateUtil.FormatSerialNumber(newCertificate.SerialNumber);
                Assert.Equal(crl.GetEncoded(), await GetAsync("GetCrl", oldSerial));
                Assert.Equal(crl.GetEncoded(), await GetAsync("GetCrl", newSerial));
                Assert.Equal(crl.GetEncoded(), await GetAsync("GetCrl", "renewed-ca"));
                Assert.Equal(oldCertificate.GetEncoded(), await GetAsync("GetCaCert", oldSerial));
                Assert.Equal(newCertificate.GetEncoded(), await GetAsync("GetCaCert", newSerial));
                Assert.Equal(newCertificate.GetEncoded(), await GetAsync("GetCaCert", "renewed-ca"));
            }

            // The journal: one CRL stream under the key, naming the certificate current when each was signed.
            var caKey = SHA256.HashData(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(oldCertificate.GetPublicKey()).GetDerEncoded());
            var crlRecords = sandbox.Records().Where(r => r.Record.Type == RecordType.Crl).Select(r => CrlPayload.Decode(r.Record.Payload)).ToList();
            Assert.True(crlRecords.Count >= 2);
            Assert.All(crlRecords, record => Assert.Equal(caKey, record.CaKey));
            Assert.Equal(SHA256.HashData(oldCertificate.GetEncoded()), crlRecords[0].CaCert);
            Assert.Equal(SHA256.HashData(newCertificate.GetEncoded()), crlRecords[^1].CaCert);
            Assert.Equal(3, (await signer.JournaledRevocationsAsync(ca.CaId, 0, 10))!.Total);

            // The database is taken back to before any of the three was revoked. The merge makes
            // them again from the journal: those issued under the old certificate and the one under the new.
            await using (var db = PostgresCaFixture.Open(connection))
                Assert.Equal(3, await db.Database.ExecuteSqlRawAsync(
                    """UPDATE "Certificates" SET "Revoked" = false, "RevocationReason" = NULL, "RevocationDate" = NULL WHERE "Revoked" """));
            var merged = await Merge().MergeAsync(ca.CaId);
            Assert.Equal((JournalMergeState.Done, 3), (merged.State, merged.Merged));
            await using (var db = PostgresCaFixture.Open(connection))
            {
                var revoked = await db.Certificates.AsNoTracking().Where(c => c.Revoked).Select(c => c.IssuerCertificateId).ToListAsync();
                Assert.Equal(2, revoked.Count(id => id == oldId));
                Assert.Equal(1, revoked.Count(id => id == newId));
                Assert.Equal(new[] { oldId, newId }.OrderBy(x => x), (await IssuerChainResolver.SameKeyScopeAsync(db, oldId)).OrderBy(x => x));
            }
            var after = await GenerateAsync(newId);
            Assert.Equal(3, after.GetRevokedCertificates().Count);
        });
}
