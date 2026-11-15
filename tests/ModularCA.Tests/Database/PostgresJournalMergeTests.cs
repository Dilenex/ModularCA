using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Core.Services.Continuity;
using ModularCA.Core.Services.Journal;
using ModularCA.Database;
using ModularCA.Keystore.Signing;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Modes;
using ModularCA.Shared.Signing;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Api;
using ModularCA.Tests.Journal;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Math;
using Xunit;

namespace ModularCA.Tests.Database;

/// <summary>
/// The merge under the real CRL service on PostgreSQL, with the signer's journal behind the
/// signer: a database that has lost revocations gets them back before its CA's first CRL, the
/// CRL lists them and is signed, and a refusal later in the same process is cured by one more
/// merge and one more generation. Opt-in through <c>MODULARCA_TEST_PG</c>.
/// </summary>
[Trait("Category", "PostgreSQL")]
[Trait(TestTier.Name, TestTier.Slow)]
[Collection(PostgresLane.Four)]
public class PostgresJournalMergeTests
{
    private sealed class NoServiceUrls : ICaServiceUrlService
    {
        public Task<CaServiceUrlEntity?> GetByCaCertificateIdAsync(Guid caCertificateId) => Task.FromResult<CaServiceUrlEntity?>(null);
        public Task<List<CaServiceUrlEntity>> GetAllAsync() => Task.FromResult(new List<CaServiceUrlEntity>());
        public Task<CaServiceUrlEntity> CreateOrUpdateAsync(Guid caCertificateId, string? publicBaseUrl) => Task.FromResult(new CaServiceUrlEntity());
        public Task<ModularCA.Shared.Models.ResolvedCaServiceUrls> ResolveForCaAsync(Guid caCertificateId) => Task.FromResult(new ModularCA.Shared.Models.ResolvedCaServiceUrls([], [], []));
        public Task<bool> DeleteAsync(Guid caCertificateId) => Task.FromResult(false);
    }

    /// <summary>
    /// The sequence the documentation gives for timing a merge on a test instance: serials are
    /// inserted as revoked by one SQL statement, a CRL is generated so that the journal holds
    /// them, the database is taken back, and the merge brings every one of them back.
    /// </summary>
    [RequiresEnvironmentFact(PostgresCaFixture.ServerVariable)]
    public Task Serials_inserted_by_the_documented_statement_reach_the_journal_with_a_crl_and_come_back_by_the_merge()
        => PostgresCaFixture.WithDatabaseAsync("modularca_jsql", async connection =>
        {
            const int count = 3000;
            PostgresCaFixture.SeededCa ca;
            await using (var seed = PostgresCaFixture.Open(connection))
                ca = await PostgresCaFixture.SeedCaAsync(seed, "journal-sql");
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
            async Task<Org.BouncyCastle.X509.X509Crl> GenerateAsync()
            {
                await using var db = PostgresCaFixture.Open(connection);
                return PostgresCaFixture.ParseCrl(await new CrlService(db, keystore, NullLogger<CrlService>.Instance, audit, new NoServiceUrls(),
                    InstanceCeremonyEndpointTests.Fake<ILdapSecretProtector>.Create(), signer, null, Merge()).GenerateCrlAsync(ca.CaCertificateId));
            }

            // 1. The statement, as documented.
            List<string> inserted;
            await using (var db = PostgresCaFixture.Open(connection))
            {
                var rows = await db.Database.ExecuteSqlRawAsync(string.Format(System.Globalization.CultureInfo.InvariantCulture,
                    JournalMeasurementTools.TombstoneInsertSql, ca.CaId.ToString("D"), count));
                Assert.Equal(count, rows);
                inserted = await db.RevokedSerialTombstones.AsNoTracking().Select(t => t.SerialNumber).OrderBy(x => x).ToListAsync();
                // Serials as the product stores them: upper-case hex, no leading zero, at most 32 digits.
                Assert.All(inserted, serial => Assert.Matches("^[1-9A-F][0-9A-F]{0,31}$", serial));
                Assert.Equal(count, inserted.Distinct().Count());
                // It wrote no fact for the journal and no audit row.
                Assert.Equal(0, await db.SignerFacts.CountAsync());
            }
            Assert.Empty(audit.Entries);

            // 2. A CRL for the CA: the journal now holds them.
            var crl = await GenerateAsync();
            Assert.Equal(count, crl.GetRevokedCertificates().Count);
            Assert.Equal(count, (await signer.JournaledRevocationsAsync(ca.CaId, 0, 1))!.Total);

            // 3. The database is taken back.
            await using (var db = PostgresCaFixture.Open(connection))
                Assert.Equal(count, await db.Database.ExecuteSqlRawAsync("""DELETE FROM "RevokedSerialTombstones" """));

            // 4. The merge of a node that starts over it.
            var result = await Merge().MergeAsync(ca.CaId);

            Assert.Equal((JournalMergeState.Done, count), (result.State, result.Merged));
            await using (var db = PostgresCaFixture.Open(connection))
                Assert.Equal(inserted, await db.RevokedSerialTombstones.AsNoTracking().Select(t => t.SerialNumber).OrderBy(x => x).ToListAsync());
            Assert.Equal(count, audit.Entries.Count(e => e.Action == AuditActionType.RevocationMergedFromJournal));
            Assert.Equal(count, (await GenerateAsync()).GetRevokedCertificates().Count);
        });

    [RequiresEnvironmentFact(PostgresCaFixture.ServerVariable)]
    public Task The_crl_service_restores_lost_revocations_before_it_generates_and_again_when_the_signer_refuses()
        => PostgresCaFixture.WithDatabaseAsync("modularca_jmerge", async connection =>
        {
            PostgresCaFixture.SeededCa ca;
            await using (var seed = PostgresCaFixture.Open(connection))
                ca = await PostgresCaFixture.SeedCaAsync(seed, "journal-merge");

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

            // A node process: its own merge state, and the CRL service that asks the merge first.
            JournalRevocationMerge Merge(ISigningService asked) => new(scopes, asked, new JournalMergeState(), FullInstanceModeGate.Instance, NullLogger<JournalRevocationMerge>.Instance);
            async Task<Org.BouncyCastle.X509.X509Crl> GenerateAsync(IJournalRevocationMerge merge)
            {
                await using var db = PostgresCaFixture.Open(connection);
                var crls = new CrlService(db, keystore, NullLogger<CrlService>.Instance, audit, new NoServiceUrls(),
                    InstanceCeremonyEndpointTests.Fake<ILdapSecretProtector>.Create(), signer, null, merge);
                return PostgresCaFixture.ParseCrl(await crls.GenerateCrlAsync(ca.CaCertificateId));
            }

            // Two certificates are issued and revoked, and a CRL lists them.
            var known = BigInteger.ValueOf(0x51AA);
            var lostRow = BigInteger.ValueOf(0x52BB);
            var revokedAt = DateTime.UtcNow.AddHours(-2);
            revokedAt = new DateTime(revokedAt.Ticks - revokedAt.Ticks % TimeSpan.TicksPerSecond, DateTimeKind.Utc);
            await using (var db = PostgresCaFixture.Open(connection))
            {
                foreach (var serial in new[] { known, lostRow })
                    db.Certificates.Add(new CertificateEntity
                    {
                        CertificateId = Guid.NewGuid(), SerialNumber = CertificateUtil.FormatSerialNumber(serial), SubjectDN = $"CN=merge-{serial.ToString(16)}",
                        Issuer = ca.Material.SubjectDn, IssuerCertificateId = ca.CaCertificateId, Pem = "x",
                        NotBefore = DateTime.UtcNow.AddDays(-1), NotAfter = DateTime.UtcNow.AddDays(30),
                        Revoked = true, RevocationReason = "KeyCompromise", RevocationDate = revokedAt,
                    });
                await db.SaveChangesAsync();
            }
            var first = await GenerateAsync(Merge(signer));
            Assert.NotNull(first.GetRevokedCertificate(known));
            Assert.NotNull(first.GetRevokedCertificate(lostRow));
            Assert.DoesNotContain(audit.Entries, e => e.Action == AuditActionType.RevocationMergedFromJournal);

            // The database goes back: one certificate is no longer revoked, the other was issued after the point it went back to.
            async Task LoseAsync(bool alsoTheRow)
            {
                await using var db = PostgresCaFixture.Open(connection);
                db.SuppressSignerFacts = true;
                var row = await db.Certificates.SingleAsync(c => c.SerialNumber == CertificateUtil.FormatSerialNumber(known));
                row.Revoked = false; row.RevocationReason = null; row.RevocationDate = null;
                if (alsoTheRow)
                    db.Certificates.Remove(await db.Certificates.SingleAsync(c => c.SerialNumber == CertificateUtil.FormatSerialNumber(lostRow)));
                await db.SaveChangesAsync();
            }
            await LoseAsync(alsoTheRow: true);

            // The node starts again. Its CA's first CRL waits for the merge, lists both again, and the signer signs it.
            var process = Merge(signer);
            var second = await GenerateAsync(process);
            second.Verify(ca.Material.Certificate.GetPublicKey());
            Assert.Equal(PostgresCaFixture.CrlNumberOf(first) + 1, PostgresCaFixture.CrlNumberOf(second));
            Assert.Equal(revokedAt, second.GetRevokedCertificate(known).RevocationDate.ToUniversalTime());
            Assert.Equal(revokedAt, second.GetRevokedCertificate(lostRow).RevocationDate.ToUniversalTime());
            await using (var db = PostgresCaFixture.Open(connection))
            {
                var row = await db.Certificates.AsNoTracking().SingleAsync(c => c.SerialNumber == CertificateUtil.FormatSerialNumber(known));
                Assert.Equal((true, "KeyCompromise"), (row.Revoked, row.RevocationReason));
                var tombstone = await db.RevokedSerialTombstones.AsNoTracking().SingleAsync();
                Assert.Equal(("52BB", "KeyCompromise", JournalRevocationMerge.Actor), (tombstone.SerialNumber, tombstone.RevocationReason, tombstone.CreatedByUsername));
                Assert.Equal(1, await db.InstanceContinuityEvents.CountAsync(e => e.Kind == ContinuityEventKind.RevocationsMergedFromJournal));
                // Each merged revocation waits in the queue as a fact for the journal, like the two first revocations before it.
                Assert.Equal(4, await db.SignerFacts.CountAsync(f => f.Type == ModularCA.Journal.RecordType.Revocation));
            }
            Assert.Equal(2, audit.Entries.Count(e => e.Action == AuditActionType.RevocationMergedFromJournal));
            Assert.Single(audit.Entries, e => e.Action == AuditActionType.JournalRevocationMergeCompleted);
            Assert.Empty((await signer.JournalInfoAsync())!.RefusedCrls!);

            // Later in the same process a revocation is lost again. The merge has run for the CA, so
            // the CRL is offered, the signer refuses it, the merge runs once more and the CRL is generated again.
            await LoseAsync(alsoTheRow: false);
            var third = await GenerateAsync(process);
            Assert.NotNull(third.GetRevokedCertificate(known));
            Assert.Equal(3, audit.Entries.Count(e => e.Action == AuditActionType.RevocationMergedFromJournal));
            Assert.Empty((await signer.JournalInfoAsync())!.RefusedCrls!);

            // When the merge cannot cure it (here the signer cannot be asked for the list), the refusal is the caller's and stands.
            await LoseAsync(alsoTheRow: false);
            var (unasked, _) = JournalHubReviewTests.JournalAnswers.Create();
            var refused = await Assert.ThrowsAsync<SigningRefusedException>(() => GenerateAsync(Merge(unasked)));
            Assert.Equal(SigningRefusalReason.CrlNotContinuous, refused.Reason);
            var standing = Assert.Single((await signer.JournalInfoAsync())!.RefusedCrls!);
            Assert.Equal((ca.CaId, 1), (standing.CaId, standing.MissingSerials));
            Assert.Equal("51AA", Assert.Single((await signer.JournalMissingRevocationsAsync(ca.CaId))!.Serials).Serial);
        });
}
