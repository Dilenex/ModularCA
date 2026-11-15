using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Errors;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Xunit;
using static ModularCA.Tests.Database.PostgresCaFixture;

namespace ModularCA.Tests.Database;

/// <summary>
/// A serial revoked with no certificate row, on the CRL the service really signs. CRL generation
/// locks its counter with raw SQL, so it never runs on the in-memory provider: this is where a
/// tombstone meets the full and the delta CRL, the unique index beneath the service's own
/// refusal, and the pruning. Opt-in through <c>MODULARCA_TEST_PG</c>.
/// </summary>
[Trait("Category", "PostgreSQL")]
[Trait(TestTier.Name, TestTier.Slow)]
[Collection(PostgresLane.Four)]
public class PostgresRevokedSerialCrlTests
{
    private static int? ReasonOf(X509CrlEntry? entry)
    {
        var value = entry?.GetExtensionValue(X509Extensions.ReasonCode);
        return value == null ? null : DerEnumerated.GetInstance(X509ExtensionUtilities.FromExtensionValue(value)).IntValueExact;
    }

    [RequiresEnvironmentFact(ServerVariable)]
    public Task A_tombstone_is_on_the_full_and_the_delta_crl_with_its_date_and_reason_until_it_is_pruned()
        => WithDatabaseAsync("modularca_tombstone", async connection =>
        {
            await using var db = Open(connection);
            var ca = await SeedCaAsync(db, "tombstone-ca");
            var crls = Crls(db, connection, ca.Material);
            var service = new RevokedSerialService(db, crls, NullLogger<RevokedSerialService>.Instance);
            var lost = new BigInteger("0A1B2C3D4E5F", 16);
            var compromisedAt = new DateTime(2026, 11, 9, 8, 0, 0, DateTimeKind.Utc);

            // A base full CRL first: the serial is not on it.
            var baseCrl = ParseCrl(await crls.GenerateCrlAsync(ca.CaCertificateId));
            Assert.Null(baseCrl.GetRevokedCertificate(lost));

            var recorded = await service.RecordTombstoneAsync(ca.CaId, "0A:1B:2C:3D:4E:5F", RevocationReason.KeyCompromise,
                compromisedAt, "issued after the snapshot that was rolled back to", Guid.NewGuid(), "admin");
            Assert.Equal(CrlNumberOf(baseCrl) + 1, recorded.CrlNumber);

            // Recording regenerated the CRL: the stored full CRL already lists the serial.
            var full = ParseCrl((await crls.GetLatestCrlAsync(ca.CaCertificateId))!);
            full.Verify(ca.Material.Certificate.GetPublicKey());
            var entry = full.GetRevokedCertificate(lost);
            Assert.NotNull(entry);
            Assert.Equal(CrlReason.KeyCompromise, ReasonOf(entry));
            Assert.InRange(Math.Abs((entry.RevocationDate.ToUniversalTime() - recorded.Tombstone.RevocationDate).TotalSeconds), 0.0, 1.0);
            Assert.NotNull(entry.GetExtensionValue(X509Extensions.InvalidityDate));

            // The delta carries what was recorded after its base. Record a second serial, date
            // the base before both, and ask for a delta.
            await service.RecordTombstoneAsync(ca.CaId, "77", RevocationReason.Superseded, null, "second", null, "admin");
            db.ChangeTracker.Clear();
            var fullRow = await db.Crls.SingleAsync(c => !c.IsDelta);
            fullRow.GeneratedAt = DateTime.UtcNow.AddMinutes(-10);
            await db.SaveChangesAsync();
            var delta = ParseCrl(await crls.GenerateDeltaCrlAsync(ca.CaCertificateId));
            delta.Verify(ca.Material.Certificate.GetPublicKey());
            Assert.NotNull(delta.GetExtensionValue(X509Extensions.DeltaCrlIndicator));
            Assert.Equal(CrlReason.KeyCompromise, ReasonOf(delta.GetRevokedCertificate(lost)));
            Assert.Equal(CrlReason.Superseded, ReasonOf(delta.GetRevokedCertificate(BigInteger.ValueOf(0x77))));

            // A second tombstone for the serial is refused by the service, and by the index beneath it.
            // The column is case-insensitive, as the certificates' serial column is.
            await Assert.ThrowsAsync<ResourceConflictException>(() =>
                service.RecordTombstoneAsync(ca.CaId, "A1B2C3D4E5F", RevocationReason.Superseded, null, "again", null, "admin"));
            db.RevokedSerialTombstones.Add(new RevokedSerialTombstoneEntity
            {
                CaCertificateId = ca.CaCertificateId, CertificateAuthorityId = ca.CaId, IssuerDN = ca.Material.SubjectDn, SerialNumber = "a1b2c3d4e5f",
                RevocationDate = DateTime.UtcNow, RevocationReason = "Superseded", ListedUntil = DateTime.UtcNow.AddYears(1), Note = "direct",
            });
            var duplicate = await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
            Assert.True(PostgresErrorUtil.IsUniqueViolation(duplicate));
            db.ChangeTracker.Clear();

            // Past its ListedUntil the entry leaves the CRL, as an expired certificate's does.
            var row = await db.RevokedSerialTombstones.SingleAsync(t => t.SerialNumber == "A1B2C3D4E5F");
            row.ListedUntil = DateTime.UtcNow.AddMinutes(-1);
            await db.SaveChangesAsync();
            var pruned = ParseCrl(await crls.GenerateCrlAsync(ca.CaCertificateId));
            Assert.Null(pruned.GetRevokedCertificate(lost));
            Assert.NotNull(pruned.GetRevokedCertificate(BigInteger.ValueOf(0x77)));
        });

    [RequiresEnvironmentFact(ServerVariable)]
    public Task An_adopted_and_revoked_certificate_is_on_the_crl_as_a_certificate_and_its_tombstone_is_gone()
        => WithDatabaseAsync("modularca_adopt", async connection =>
        {
            await using var db = Open(connection);
            var ca = await SeedCaAsync(db, "adopt-ca");
            var crls = Crls(db, connection, ca.Material);
            var service = new RevokedSerialService(db, crls, NullLogger<RevokedSerialService>.Instance);
            var lost = new BigInteger("0A1B2C3D4E5F", 16);
            var certificate = ca.Material.Issue(lost, "CN=lost.example");
            var pem = ModularCA.Shared.Utils.CertificateUtil.ConvertDerToPem(certificate.GetEncoded(), "CERTIFICATE");

            var tombstone = await service.RecordTombstoneAsync(ca.CaId, "A1B2C3D4E5F", RevocationReason.KeyCompromise, null, "serial only, for now", null, "admin");
            var adopted = await service.AdoptCertificateAsync(ca.CaId, pem, "the subscriber sent it", null, null, "admin");

            Assert.True(adopted.FromTombstone);
            Assert.Empty(await db.RevokedSerialTombstones.AsNoTracking().ToListAsync());
            var row = await db.Certificates.AsNoTracking().SingleAsync(c => c.CertificateId == adopted.Certificate.CertificateId);
            Assert.True(row.Revoked);
            Assert.NotNull(row.AdoptedAt);
            // PostgreSQL keeps microseconds; the date moved across unchanged.
            Assert.InRange(Math.Abs((row.RevocationDate!.Value - tombstone.Tombstone.RevocationDate).TotalMilliseconds), 0.0, 1.0);

            // One entry for the serial, now from the certificate row; and a second adoption is refused.
            var full = ParseCrl(await crls.GenerateCrlAsync(ca.CaCertificateId));
            Assert.Single(full.GetRevokedCertificates());
            Assert.Equal(CrlReason.KeyCompromise, ReasonOf(full.GetRevokedCertificate(lost)));
            await Assert.ThrowsAsync<ResourceConflictException>(() => service.AdoptCertificateAsync(ca.CaId, pem, "again", null, null, "admin"));
        });
}
