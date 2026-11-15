using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ModularCA.Auth.Authorization;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Core.Services.Ocsp;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Shared.Models.Revocation;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Roles;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Revocation of what the database does not hold (rollback-continuity.md, section 5): a serial
/// recorded as revoked with no certificate row, and a certificate supplied from outside adopted
/// once it verifies under the CA's key. Pins the refusals (a serial that has a row, a certificate
/// another key signed), what OCSP answers for a tombstone, how long it stays listed, and that
/// the endpoints ask for <c>cert.revoke</c> on the CA in the route and for step-up.
/// </summary>
public sealed class RevokedSerialServiceTests
{
    /// <summary>Records the CA certificates a CRL is regenerated for.</summary>
    private sealed class RecordingCrls : ICrlService
    {
        public List<Guid> Generated { get; } = [];
        public Task<string> GenerateCrlAsync(Guid caCertificateId, CancellationToken cancellationToken = default)
        {
            Generated.Add(caCertificateId);
            return Task.FromResult("");
        }
        public Task<string> GenerateDeltaCrlAsync(Guid caCertificateId, CancellationToken cancellationToken = default) => Task.FromResult("");
        public Task<string?> GetLatestCrlAsync(Guid caCertificateId, CancellationToken cancellationToken = default) => Task.FromResult<string?>(null);
        public Task<string?> GetLatestDeltaCrlAsync(Guid caCertificateId, CancellationToken cancellationToken = default) => Task.FromResult<string?>(null);
        public Task<CrlBlob?> GetLatestCrlRawAsync(Guid caCertificateId, CancellationToken cancellationToken = default) => Task.FromResult<CrlBlob?>(null);
        public Task<CrlBlob?> GetLatestDeltaCrlRawAsync(Guid caCertificateId, CancellationToken cancellationToken = default) => Task.FromResult<CrlBlob?>(null);
    }

    /// <summary>One CA with real key material in an in-memory database, and the service over it.</summary>
    private sealed class World
    {
        public string DatabaseName { get; } = $"tombstone-{Guid.NewGuid():N}";
        public ModularCADbContext Db { get; }
        public TestCaMaterial Ca { get; }
        public Guid CaId { get; } = Guid.NewGuid();
        public Guid CaCertificateId { get; } = Guid.NewGuid();
        public Guid SpaceId { get; } = Guid.NewGuid();
        public RecordingCrls Crls { get; } = new();
        public RevokedSerialService Service => new(Db, Crls, NullLogger<RevokedSerialService>.Instance);

        public World(string subject = "CN=Tombstone CA, O=ModularCA", string label = "test-ca")
        {
            Db = InMemoryDbContextFactory.Create(DatabaseName);
            Ca = TestCaMaterial.CreateCa(subject);
            AddCa(Db, Ca, CaId, CaCertificateId, SpaceId, label);
            Db.SaveChanges();
        }

        public static void AddCa(ModularCADbContext db, TestCaMaterial ca, Guid caId, Guid caCertificateId, Guid? spaceId, string label)
        {
            db.Certificates.Add(new CertificateEntity
            {
                CertificateId = caCertificateId,
                SerialNumber = CertificateUtil.FormatSerialNumber(ca.Certificate.SerialNumber),
                SubjectDN = ca.SubjectDn,
                Issuer = ca.SubjectDn,
                IsCA = true,
                Pem = CertificateUtil.ConvertDerToPem(ca.Certificate.GetEncoded(), "CERTIFICATE"),
                RawCertificate = ca.Certificate.GetEncoded(),
                NotBefore = ca.Certificate.NotBefore,
                NotAfter = ca.Certificate.NotAfter,
            });
            db.CertificateAuthorities.Add(new CertificateAuthorityEntity
            {
                Id = caId, Name = label, Label = label, IsEnabled = true, CertificateId = caCertificateId, SpaceId = spaceId,
            });
        }

        public CertificateEntity IssuedRow(BigInteger serial, string subject = "CN=known.example")
        {
            var row = new CertificateEntity
            {
                CertificateId = Guid.NewGuid(), SerialNumber = CertificateUtil.FormatSerialNumber(serial), SubjectDN = subject,
                Issuer = Ca.SubjectDn, IssuerCertificateId = CaCertificateId, Pem = "x",
                NotBefore = DateTime.UtcNow.AddDays(-1), NotAfter = DateTime.UtcNow.AddDays(30),
            };
            Db.Certificates.Add(row);
            Db.SaveChanges();
            return row;
        }

        public Task<TombstoneResult> Record(string serial, RevocationReason reason = RevocationReason.KeyCompromise, string note = "issued before the snapshot rollback")
            => Service.RecordTombstoneAsync(CaId, serial, reason, null, note, Guid.NewGuid(), "admin");

        public static string Pem(Org.BouncyCastle.X509.X509Certificate certificate)
            => CertificateUtil.ConvertDerToPem(certificate.GetEncoded(), "CERTIFICATE");
    }

    private static readonly BigInteger LostSerial = new("0A1B2C3D4E5F", 16);

    [Fact]
    public async Task Several_serials_are_recorded_under_one_note_and_the_crl_is_regenerated_once()
    {
        var w = new World();
        var known = w.IssuedRow(new BigInteger("77AA", 16));
        await w.Record("0C0C");
        var generatedBefore = w.Crls.Generated.Count;

        var (outcomes, _) = await w.Service.RecordTombstonesAsync(w.CaId,
            [("0a:01", RevocationReason.KeyCompromise), ("77AA", RevocationReason.Superseded), ("0C0C", RevocationReason.Superseded),
             ("not hex", RevocationReason.Superseded), ("0A02", RevocationReason.CertificateHold), ("0A03", RevocationReason.Superseded)],
            "lost in the roll-back", Guid.NewGuid(), "admin");

        // Two are recorded; the others are refused each for its own reason, and stop nothing.
        Assert.Equal(new[] { "A01", "A03" }, outcomes.Where(o => o.Tombstone != null).Select(o => o.Tombstone!.SerialNumber));
        Assert.Contains("belongs to a certificate this CA holds", outcomes[1].Refusal!, StringComparison.Ordinal);
        Assert.Contains("already recorded", outcomes[2].Refusal!, StringComparison.Ordinal);
        Assert.Contains("hexadecimal", outcomes[3].Refusal!, StringComparison.Ordinal);
        Assert.Contains("cannot be put on hold", outcomes[4].Refusal!, StringComparison.Ordinal);
        var rows = w.Db.RevokedSerialTombstones.AsNoTracking().OrderBy(t => t.SerialNumber).ToList();
        Assert.Equal(new[] { "A01", "A03", "C0C" }, rows.Select(r => r.SerialNumber));
        Assert.Equal(("KeyCompromise", "lost in the roll-back", "admin"), (rows[0].RevocationReason, rows[0].Note, rows[0].CreatedByUsername));
        // One CRL for all of them, not one each.
        Assert.Equal(generatedBefore + 1, w.Crls.Generated.Count);
        Assert.False(w.Db.Certificates.AsNoTracking().Single(c => c.CertificateId == known.CertificateId).Revoked);

        // With nothing recorded no CRL is generated; a missing note is refused before anything.
        var (none, number) = await w.Service.RecordTombstonesAsync(w.CaId, [("77AA", RevocationReason.Superseded)], "note", null, "admin");
        Assert.Null(none[0].Tombstone);
        Assert.Null(number);
        Assert.Equal(generatedBefore + 1, w.Crls.Generated.Count);
        await Assert.ThrowsAsync<InvalidRequestException>(() => w.Service.RecordTombstonesAsync(w.CaId, [("0A09", RevocationReason.Superseded)], " ", null, "admin"));

        // Which serials the CA holds a certificate for, whatever their leading zeros or case.
        Assert.Equal(new[] { "77AA" }, await w.Service.HeldAsync(w.CaId, ["0077aa", "A01", "FFFF"]));
    }

    // ── Tombstones ───────────────────────────────────────────────────────

    [Fact]
    public async Task A_serial_with_no_certificate_is_recorded_as_revoked_and_the_crl_is_regenerated()
    {
        var w = new World();
        var before = DateTime.UtcNow;

        var result = await w.Record("0a:1b:2c:3d:4e:5f");

        var row = Assert.Single(w.Db.RevokedSerialTombstones.AsNoTracking());
        Assert.Equal("A1B2C3D4E5F", row.SerialNumber);
        Assert.Equal(result.Tombstone.Id, row.Id);
        Assert.Equal(w.CaCertificateId, row.CaCertificateId);
        Assert.Equal(w.CaId, row.CertificateAuthorityId);
        Assert.Equal(w.Ca.SubjectDn, row.IssuerDN);
        Assert.Equal(nameof(RevocationReason.KeyCompromise), row.RevocationReason);
        Assert.InRange(row.RevocationDate, before, DateTime.UtcNow);
        Assert.Equal("issued before the snapshot rollback", row.Note);
        Assert.Equal("admin", row.CreatedByUsername);
        Assert.Equal([w.CaCertificateId], w.Crls.Generated);
    }

    [Fact]
    public async Task A_tombstone_for_a_serial_that_has_a_certificate_row_is_refused()
    {
        var w = new World();
        var known = w.IssuedRow(LostSerial);

        var refusal = await Assert.ThrowsAsync<ResourceConflictException>(() => w.Record("0A1B2C3D4E5F"));

        Assert.Equal(409, refusal.Status);
        Assert.Contains("Revoke the certificate instead", refusal.Message);
        Assert.Contains(known.CertificateId.ToString(), refusal.Remediation);
        Assert.Empty(w.Db.RevokedSerialTombstones);
        Assert.Empty(w.Crls.Generated);
    }

    [Fact]
    public async Task The_same_serial_under_another_ca_does_not_stand_in_the_way()
    {
        var w = new World();
        // A certificate of another issuer with the same serial: serials are unique per issuer only.
        w.Db.Certificates.Add(new CertificateEntity
        {
            CertificateId = Guid.NewGuid(), SerialNumber = CertificateUtil.FormatSerialNumber(LostSerial), SubjectDN = "CN=elsewhere",
            Issuer = "CN=Another CA", IssuerCertificateId = Guid.NewGuid(), Pem = "x",
            NotBefore = DateTime.UtcNow.AddDays(-1), NotAfter = DateTime.UtcNow.AddDays(30),
        });
        w.Db.SaveChanges();

        await w.Record("A1B2C3D4E5F");

        Assert.Single(w.Db.RevokedSerialTombstones);
    }

    [Fact]
    public async Task A_serial_is_recorded_once()
    {
        var w = new World();
        await w.Record("A1B2C3D4E5F");

        await Assert.ThrowsAsync<ResourceConflictException>(() => w.Record("0A1B2C3D4E5F"));

        Assert.Single(w.Db.RevokedSerialTombstones);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-hex")]
    [InlineData("0")]
    [InlineData("00:00")]
    [InlineData("112233445566778899AABBCCDDEEFF00112233445566")] // 21 octets
    public async Task A_serial_that_is_not_a_positive_hex_number_of_twenty_octets_is_refused(string serial)
    {
        var w = new World();
        await Assert.ThrowsAsync<InvalidRequestException>(() => w.Record(serial));
        Assert.Empty(w.Db.RevokedSerialTombstones);
    }

    [Fact]
    public async Task A_hold_and_a_missing_note_are_refused()
    {
        var w = new World();
        await Assert.ThrowsAsync<InvalidRequestException>(() => w.Record("A1", RevocationReason.CertificateHold));
        await Assert.ThrowsAsync<InvalidRequestException>(() => w.Record("A1", note: "   "));
        Assert.Empty(w.Db.RevokedSerialTombstones);
    }

    [Fact]
    public async Task An_unknown_ca_is_not_found()
    {
        var w = new World();
        await Assert.ThrowsAsync<ResourceNotFoundException>(() =>
            w.Service.RecordTombstoneAsync(Guid.NewGuid(), "A1", RevocationReason.Superseded, null, "why", null, "admin"));
    }

    [Fact]
    public async Task A_tombstone_stays_listed_for_the_longest_validity_the_cas_profiles_allow()
    {
        var w = new World();
        var otherSpace = Guid.NewGuid();
        w.Db.CertProfiles.AddRange(
            new CertProfileEntity { Id = Guid.NewGuid(), Name = "ca-90d", CertificateAuthorityId = w.CaId, SpaceId = w.SpaceId, ValidityPeriodMax = "P90D" },
            new CertProfileEntity { Id = Guid.NewGuid(), Name = "space-2y", SpaceId = w.SpaceId, ValidityPeriodMax = "P2Y" },
            new CertProfileEntity { Id = Guid.NewGuid(), Name = "instance-3y", ValidityPeriodMax = "P3Y" },
            // Neither of these can issue under this CA, so neither lengthens the stay.
            new CertProfileEntity { Id = Guid.NewGuid(), Name = "other-ca-9y", CertificateAuthorityId = Guid.NewGuid(), SpaceId = w.SpaceId, ValidityPeriodMax = "P9Y" },
            new CertProfileEntity { Id = Guid.NewGuid(), Name = "other-space-8y", SpaceId = otherSpace, ValidityPeriodMax = "P8Y" });
        w.Db.SaveChanges();
        var from = new DateTime(2027, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        var until = await w.Service.ListedUntilAsync(w.CaId, from);

        Assert.Equal(from.Add(Iso8601ParserUtil.ParseIso8601("P3Y")), until);
        var recorded = await w.Record("A1");
        Assert.Equal(recorded.Tombstone.RevocationDate.Add(Iso8601ParserUtil.ParseIso8601("P3Y")), recorded.Tombstone.ListedUntil);
    }

    [Fact]
    public async Task With_no_profile_a_tombstone_stays_a_year_and_never_past_the_cas_own_certificate()
    {
        var w = new World();
        var from = new DateTime(2027, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        Assert.Equal(from.Add(Iso8601ParserUtil.ParseIso8601("P1Y")), await w.Service.ListedUntilAsync(w.CaId, from));

        // The test CA's certificate ends on 2049-01-01: nothing it issued is valid after that.
        w.Db.CertProfiles.Add(new CertProfileEntity { Id = Guid.NewGuid(), Name = "long", CertificateAuthorityId = w.CaId, ValidityPeriodMax = "P10Y" });
        w.Db.SaveChanges();
        var late = new DateTime(2045, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        Assert.Equal(w.Ca.Certificate.NotAfter.ToUniversalTime(), await w.Service.ListedUntilAsync(w.CaId, late));
    }

    // ── OCSP ─────────────────────────────────────────────────────────────

    private static async Task<object?> OcspStatusAsync(World w, BigInteger serial)
    {
        var keystore = new TestKeystore(w.Ca.AsSigner());
        var responder = new OcspResponderService(w.Db, keystore, NullLogger<OcspResponderService>.Instance,
            new StubSecurityPolicyService(new SecurityPolicyEntity { AllowCaDirectSigning = true }), TestSigner.Over(keystore, w.DatabaseName));
        var response = new OcspResp(await responder.ProcessOcspRequestAsync(w.Ca.BuildOcspRequest(serial), "test-ca", new OcspProcessingResult()));
        Assert.Equal(OcspRespStatus.Successful, response.Status);
        return Assert.Single(((BasicOcspResp)response.GetResponseObject()).Responses).GetCertStatus();
    }

    [Fact]
    public async Task Ocsp_answers_a_tombstone_with_its_recorded_date_and_reason()
    {
        var w = new World();

        // Before: the generic answer for a serial the CA does not know.
        var unknown = Assert.IsType<RevokedStatus>(await OcspStatusAsync(w, LostSerial));
        Assert.Equal(new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc), unknown.RevocationTime.ToUniversalTime());
        Assert.Equal(CrlReason.CertificateHold, unknown.RevocationReason);

        var recorded = await w.Record("A1B2C3D4E5F", RevocationReason.KeyCompromise);

        var status = Assert.IsType<RevokedStatus>(await OcspStatusAsync(w, LostSerial));
        Assert.Equal(CrlReason.KeyCompromise, status.RevocationReason);
        // OCSP carries GeneralizedTime to the second.
        Assert.InRange(Math.Abs((status.RevocationTime.ToUniversalTime() - recorded.Tombstone.RevocationDate).TotalSeconds), 0.0, 1.0);
    }

    [Fact]
    public async Task Ocsp_does_not_answer_another_cas_tombstone()
    {
        var w = new World();
        // A tombstone of another CA certificate with the same serial.
        w.Db.RevokedSerialTombstones.Add(new RevokedSerialTombstoneEntity
        {
            CaCertificateId = Guid.NewGuid(), CertificateAuthorityId = Guid.NewGuid(), IssuerDN = "CN=Another CA",
            SerialNumber = CertificateUtil.FormatSerialNumber(LostSerial), RevocationDate = DateTime.UtcNow,
            RevocationReason = nameof(RevocationReason.KeyCompromise), ListedUntil = DateTime.UtcNow.AddYears(1), Note = "n",
        });
        w.Db.SaveChanges();

        var status = Assert.IsType<RevokedStatus>(await OcspStatusAsync(w, LostSerial));

        Assert.Equal(CrlReason.CertificateHold, status.RevocationReason); // still the never-issued answer
    }

    // ── Adoption ─────────────────────────────────────────────────────────

    [Fact]
    public async Task A_certificate_this_ca_signed_is_adopted_as_a_row_marked_adopted_with_no_requester()
    {
        var w = new World();
        var lost = w.Ca.Issue(LostSerial, "CN=lost.example, O=Example");

        var result = await w.Service.AdoptCertificateAsync(w.CaId, World.Pem(lost), "from the subscriber's server", null, null, "admin");

        Assert.False(result.Revoked);
        var row = w.Db.Certificates.AsNoTracking().Single(c => c.CertificateId == result.Certificate.CertificateId);
        Assert.Equal("A1B2C3D4E5F", row.SerialNumber);
        Assert.Equal(lost.SubjectDN.ToString(), row.SubjectDN);
        Assert.Equal(w.Ca.SubjectDn, row.Issuer);
        Assert.Equal(w.CaCertificateId, row.IssuerCertificateId);
        Assert.Equal(lost.GetEncoded(), row.RawCertificate);
        Assert.NotNull(row.AdoptedAt);
        Assert.Equal("admin", row.AdoptedBy);
        Assert.Equal("from the subscriber's server", row.AdoptionNote);
        Assert.Null(row.SigningProfileId);
        Assert.Null(row.CertProfileId);
        Assert.False(row.Revoked);
        Assert.False(row.IsCA);
        Assert.Empty(w.Db.CertificateRequests);
        Assert.Empty(w.Crls.Generated);

        // It is now an ordinary row: OCSP answers good, and the ordinary revocation revokes it.
        Assert.Null(await OcspStatusAsync(w, LostSerial));
        var revocation = new CertificateRevocationService(w.Db,
            System.Reflection.DispatchProxy.Create<IKeystoreCertificates, ModularCA.Tests.Api.SpaceIsolationMatrixTests.NoOpProxy>(),
            System.Reflection.DispatchProxy.Create<ICertificateStore, ModularCA.Tests.Api.SpaceIsolationMatrixTests.NoOpProxy>(),
            new NoopNotificationService(), w.Crls, NullLogger<CertificateRevocationService>.Instance);
        await revocation.RevokeCertificateAsync(row.CertificateId, null, RevocationReason.Superseded);
        Assert.Equal(CrlReason.Superseded, Assert.IsType<RevokedStatus>(await OcspStatusAsync(w, LostSerial)).RevocationReason);
        Assert.Equal([w.CaCertificateId], w.Crls.Generated);
    }

    [Fact]
    public async Task Base64_der_is_accepted_as_well_as_pem()
    {
        var w = new World();
        var lost = w.Ca.Issue(LostSerial, "CN=lost.example");

        var result = await w.Service.AdoptCertificateAsync(w.CaId, Convert.ToBase64String(lost.GetEncoded()), "from a log", null, null, "admin");

        Assert.Equal("A1B2C3D4E5F", result.Certificate.SerialNumber);
    }

    [Fact]
    public async Task A_certificate_another_key_signed_is_refused_even_under_this_cas_name()
    {
        var w = new World();
        // Same subject DN, another key: the name matches and the signature does not.
        var impostor = TestCaMaterial.CreateCa("CN=Tombstone CA, O=ModularCA");
        var forged = impostor.Issue(LostSerial, "CN=forged.example");

        var refusal = await Assert.ThrowsAsync<InvalidRequestException>(() =>
            w.Service.AdoptCertificateAsync(w.CaId, World.Pem(forged), "found", null, null, "admin"));

        Assert.Contains("not signed by the key", refusal.Message);
        Assert.Single(w.Db.Certificates); // the CA's own row only
    }

    [Fact]
    public async Task A_certificate_of_another_issuer_is_refused()
    {
        var w = new World();
        var other = TestCaMaterial.CreateCa("CN=Some Other CA");

        var refusal = await Assert.ThrowsAsync<InvalidRequestException>(() =>
            w.Service.AdoptCertificateAsync(w.CaId, World.Pem(other.Issue(LostSerial, "CN=x")), "found", null, null, "admin"));

        Assert.Contains("another issuer", refusal.Message);
    }

    [Fact]
    public async Task Unreadable_input_a_ca_certificate_and_a_known_serial_are_refused()
    {
        var w = new World();
        await Assert.ThrowsAsync<InvalidRequestException>(() => w.Service.AdoptCertificateAsync(w.CaId, "not a certificate", "n", null, null, "a"));
        await Assert.ThrowsAsync<InvalidRequestException>(() => w.Service.AdoptCertificateAsync(w.CaId, World.Pem(w.Ca.Issue(LostSerial, "CN=x")), " ", null, null, "a"));
        await Assert.ThrowsAsync<InvalidRequestException>(() =>
            w.Service.AdoptCertificateAsync(w.CaId, World.Pem(w.Ca.Issue(BigInteger.ValueOf(77), "CN=Sub CA", isCa: true)), "n", null, null, "a"));

        w.IssuedRow(LostSerial);
        await Assert.ThrowsAsync<ResourceConflictException>(() =>
            w.Service.AdoptCertificateAsync(w.CaId, World.Pem(w.Ca.Issue(LostSerial, "CN=x")), "n", null, null, "a"));
    }

    [Fact]
    public async Task Adoption_can_revoke_in_the_same_step()
    {
        var w = new World();
        var lost = w.Ca.Issue(LostSerial, "CN=lost.example");

        var result = await w.Service.AdoptCertificateAsync(w.CaId, World.Pem(lost), "leaked key", RevocationReason.KeyCompromise, null, "admin");

        Assert.True(result.Revoked);
        Assert.False(result.FromTombstone);
        var row = w.Db.Certificates.AsNoTracking().Single(c => c.CertificateId == result.Certificate.CertificateId);
        Assert.True(row.Revoked);
        Assert.Equal(nameof(RevocationReason.KeyCompromise), row.RevocationReason);
        Assert.NotNull(row.RevocationDate);
        Assert.Equal([w.CaCertificateId], w.Crls.Generated);
    }

    [Fact]
    public async Task Adopting_a_tombstoned_serial_moves_the_revocation_onto_the_row_and_removes_the_tombstone()
    {
        var w = new World();
        var recorded = await w.Record("A1B2C3D4E5F", RevocationReason.CessationOfOperation);
        var lost = w.Ca.Issue(LostSerial, "CN=lost.example");

        var result = await w.Service.AdoptCertificateAsync(w.CaId, World.Pem(lost), "the subscriber sent it", null, null, "admin");

        Assert.True(result.Revoked);
        Assert.True(result.FromTombstone);
        Assert.Empty(w.Db.RevokedSerialTombstones.AsNoTracking());
        var row = w.Db.Certificates.AsNoTracking().Single(c => c.CertificateId == result.Certificate.CertificateId);
        Assert.Equal(nameof(RevocationReason.CessationOfOperation), row.RevocationReason);
        Assert.Equal(recorded.Tombstone.RevocationDate, row.RevocationDate);
        Assert.Equal(CrlReason.CessationOfOperation, Assert.IsType<RevokedStatus>(await OcspStatusAsync(w, LostSerial)).RevocationReason);
    }

    // ── Authorization and step-up at the endpoints ───────────────────────

    private const string ControllerName = "ModularCA.API.Controllers.v1.Admin.AdminRevokedSerialController";

    /// <summary>Two CAs in two spaces and one user, with the real capability resolver over them.</summary>
    private sealed class AuthWorld
    {
        public World W { get; } = new();
        public Guid OtherCaId { get; } = Guid.NewGuid();
        public Guid UserId { get; } = Guid.NewGuid();

        public AuthWorld()
        {
            World.AddCa(W.Db, TestCaMaterial.CreateCa("CN=Other CA"), OtherCaId, Guid.NewGuid(), Guid.NewGuid(), "other-ca");
            W.Db.SaveChanges();
        }

        public void Grant(Guid caId, string capability)
        {
            var group = new CaGroupEntity { Id = Guid.NewGuid(), Name = $"g-{Guid.NewGuid():N}", DisplayName = "g", SpaceId = W.SpaceId, CertificateAuthorityId = caId };
            W.Db.CaGroups.Add(group);
            W.Db.CaGroupMembers.Add(new CaGroupMemberEntity { Id = Guid.NewGuid(), GroupId = group.Id, UserId = UserId });
            W.Db.CapabilityGrants.Add(new CapabilityGrantEntity { Id = Guid.NewGuid(), GroupId = group.Id, Capability = capability });
            W.Db.SaveChanges();
        }

        public DefaultHttpContext Http(IDistributedCache? cache = null)
        {
            var http = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", UserId.ToString()), new Claim(ClaimTypes.NameIdentifier, UserId.ToString())], "test")),
            };
            http.Request.Method = "POST";
            var services = new ServiceCollection();
            services.AddSingleton(W.Db);
            services.AddSingleton<ICaGroupAuthorizationService>(new CaGroupAuthorizationService(W.Db, NullLogger<CaGroupAuthorizationService>.Instance));
            services.AddSingleton(cache ?? new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions())));
            http.RequestServices = services.BuildServiceProvider();
            return http;
        }
    }

    /// <summary>Runs the named filter the action carries; true when it lets the request through to the action.</summary>
    private static async Task<(bool Reached, IActionResult? Result)> RunFilterAsync(string action, string filterName, HttpContext http, Guid caId)
    {
        var method = ApiAssembly.TypeNamed(ControllerName).GetMethod(action)!;
        var filter = Assert.Single(method.GetCustomAttributes(true).OfType<ActionFilterAttribute>(), a => a.GetType().Name == filterName);
        var route = new RouteData();
        route.Values["caId"] = caId.ToString();
        var arguments = new Dictionary<string, object?> { ["caId"] = caId };
        var executing = new ActionExecutingContext(new ActionContext(http, route, new ActionDescriptor()), [], arguments, new object());
        var reached = false;
        await filter.OnActionExecutionAsync(executing, () =>
        {
            reached = true;
            return Task.FromResult(new ActionExecutedContext(executing, [], new object()));
        });
        return (reached, executing.Result);
    }

    [Theory]
    [InlineData("List")]
    [InlineData("Record")]
    [InlineData("Adopt")]
    [InlineData("MissingFromCrl")]
    [InlineData("RecordMany")]
    public async Task Every_action_needs_cert_revoke_on_the_ca_in_the_route_and_on_no_other(string action)
    {
        var a = new AuthWorld();

        // No grant at all: refused.
        var none = await RunFilterAsync(action, "RequireCaCapabilityAttribute", a.Http(), a.W.CaId);
        Assert.False(none.Reached);
        Assert.Equal(403, Assert.IsType<ObjectResult>(none.Result).StatusCode);

        // Another capability on this CA is not cert.revoke.
        a.Grant(a.W.CaId, Capabilities.CertRequest);
        Assert.False((await RunFilterAsync(action, "RequireCaCapabilityAttribute", a.Http(), a.W.CaId)).Reached);

        // cert.revoke on this CA: allowed here, refused on the other CA and on a CA that does not exist.
        a.Grant(a.W.CaId, Capabilities.CertRevoke);
        Assert.True((await RunFilterAsync(action, "RequireCaCapabilityAttribute", a.Http(), a.W.CaId)).Reached);
        Assert.False((await RunFilterAsync(action, "RequireCaCapabilityAttribute", a.Http(), a.OtherCaId)).Reached);
        Assert.False((await RunFilterAsync(action, "RequireCaCapabilityAttribute", a.Http(), Guid.NewGuid())).Reached);
    }

    [Theory]
    [InlineData("Record", StepUpOps.RevokeSerial)]
    [InlineData("RecordMany", StepUpOps.RevokeSerial)]
    [InlineData("Adopt", StepUpOps.AdoptCertificate)]
    public async Task The_mutations_need_a_step_up_token_issued_for_that_operation_and_that_ca(string action, string operation)
    {
        var a = new AuthWorld();
        IDistributedCache cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));

        // No token.
        var refused = await RunFilterAsync(action, "RequireStepUpAttribute", a.Http(cache), a.W.CaId);
        Assert.False(refused.Reached);
        Assert.Equal(403, Assert.IsType<ObjectResult>(refused.Result).StatusCode);

        // A token for another CA does not open this one.
        cache.SetString($"mfa-stepup:{a.UserId}:{operation}:{a.OtherCaId}", "token");
        var http = a.Http(cache);
        http.Request.Headers["X-MFA-Token"] = "token";
        Assert.False((await RunFilterAsync(action, "RequireStepUpAttribute", http, a.W.CaId)).Reached);

        // A token for this operation on this CA does.
        cache.SetString($"mfa-stepup:{a.UserId}:{operation}:{a.W.CaId}", "token");
        http = a.Http(cache);
        http.Request.Headers["X-MFA-Token"] = "token";
        Assert.True((await RunFilterAsync(action, "RequireStepUpAttribute", http, a.W.CaId)).Reached);
    }

    private sealed class CurrentUserStub(Guid id) : ICurrentUserService
    {
        public Guid? UserId => id;
        public UserEntity? User { get; } = new UserEntity { Id = id, Username = "operator" };
        public bool IsAuthenticated => true;
        public Task EnsureLoadedAsync() => Task.CompletedTask;
    }

    private static (ControllerBase Controller, RecordingAuditService Audit) Controller(World w)
    {
        var audit = new RecordingAuditService();
        var controller = (ControllerBase)Activator.CreateInstance(ApiAssembly.TypeNamed(ControllerName),
            w.Service, w.Db, new CurrentUserStub(Guid.NewGuid()), audit, new RecordingAlertService(), new UnaskedSigner())!;
        controller.ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() };
        return (controller, audit);
    }

    private static async Task<JsonElement> OkBodyAsync(object task)
        => JsonDocument.Parse(JsonSerializer.Serialize(Assert.IsType<OkObjectResult>(await (Task<IActionResult>)task).Value)).RootElement;

    [Fact]
    public async Task The_endpoint_records_audits_and_lists_a_tombstone()
    {
        var w = new World();
        var (controller, audit) = Controller(w);

        var body = await OkBodyAsync(controller.GetType().GetMethod("Record")!.Invoke(controller,
            [w.CaId, new RecordRevokedSerialRequest { SerialNumber = "0A1B2C3D4E5F", Reason = RevocationReason.KeyCompromise, Note = "rolled back" }])!);

        Assert.Equal("A1B2C3D4E5F", body.GetProperty("serialNumber").GetString());
        Assert.Equal("KeyCompromise", body.GetProperty("reason").GetString());
        var entry = Assert.Single(audit.Entries);
        Assert.Equal(AuditActionType.RevokedSerialRecorded, entry.Action);
        Assert.Equal("A1B2C3D4E5F", entry.TargetId);
        Assert.Contains("rolled back", JsonSerializer.Serialize(entry.Details));

        var listed = await OkBodyAsync(controller.GetType().GetMethod("List")!.Invoke(controller, [w.CaId])!);
        var row = Assert.Single(listed.EnumerateArray());
        Assert.Equal("A1B2C3D4E5F", row.GetProperty("SerialNumber").GetString());
        Assert.True(row.GetProperty("OnCrl").GetBoolean());
        Assert.Equal("operator", row.GetProperty("RecordedBy").GetString());
    }

    [Fact]
    public async Task A_refused_tombstone_is_audited_as_a_failure()
    {
        var w = new World();
        w.IssuedRow(LostSerial);
        var (controller, audit) = Controller(w);

        await Assert.ThrowsAsync<ResourceConflictException>(() => (Task<IActionResult>)controller.GetType().GetMethod("Record")!.Invoke(controller,
            [w.CaId, new RecordRevokedSerialRequest { SerialNumber = "A1B2C3D4E5F", Reason = RevocationReason.KeyCompromise, Note = "n" }])!);

        Assert.Equal(AuditActionType.RevokedSerialRecorded, Assert.Single(audit.Entries).Action);
        Assert.Empty(w.Db.RevokedSerialTombstones);
    }

    [Fact]
    public async Task The_endpoint_adopts_and_audits_a_certificate_and_its_revocation()
    {
        var w = new World();
        var (controller, audit) = Controller(w);
        var lost = w.Ca.Issue(LostSerial, "CN=lost.example");

        var body = await OkBodyAsync(controller.GetType().GetMethod("Adopt")!.Invoke(controller,
            [w.CaId, new AdoptCertificateRequest { Certificate = World.Pem(lost), Note = "sent by the subscriber", RevokeReason = RevocationReason.Superseded }])!);

        Assert.True(body.GetProperty("revoked").GetBoolean());
        Assert.Equal("Superseded", body.GetProperty("reason").GetString());
        Assert.Equal([AuditActionType.CertificateAdopted, AuditActionType.CertificateRevoked], audit.Entries.Select(e => e.Action).ToArray());
        Assert.Equal(body.GetProperty("certificateId").GetGuid().ToString(), audit.Entries[0].TargetId);
    }

    // ── An adopted certificate under the CA-scoped revocation endpoints ──

    [Fact]
    public async Task An_adopted_certificate_belongs_to_the_ca_that_verified_it_for_the_ca_scoped_policy()
    {
        var a = new AuthWorld();
        var adopted = await a.W.Service.AdoptCertificateAsync(a.W.CaId, World.Pem(a.W.Ca.Issue(LostSerial, "CN=lost.example")), "n", null, null, "admin");

        var scope = await AdoptedCertificateScope.CaOfAsync(a.W.Db, adopted.Certificate);
        Assert.Equal((a.W.CaId, (Guid?)a.W.SpaceId), scope);

        // A row with no signing profile that was not adopted keeps resolving to nothing.
        var legacy = a.W.IssuedRow(BigInteger.ValueOf(4242));
        Assert.Null(await AdoptedCertificateScope.CaOfAsync(a.W.Db, legacy));

        async Task<bool> MayRevoke(Guid certificateId)
        {
            var http = new DefaultHttpContext();
            http.Request.Method = HttpMethods.Post;
            http.Request.Path = $"/api/v1/admin/certificates/{certificateId}/revoke";
            http.Request.RouteValues["certId"] = certificateId.ToString();
            var service = new CaGroupAuthorizationService(a.W.Db, NullLogger<CaGroupAuthorizationService>.Instance);
            var handler = new CaGroupAuthorizationHandler(service, new HttpContextAccessor { HttpContext = http }, a.W.Db, NullLogger<CaGroupAuthorizationHandler>.Instance);
            var user = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, a.UserId.ToString())], "test"));
            var context = new Microsoft.AspNetCore.Authorization.AuthorizationHandlerContext([new CaGroupRequirement(Capabilities.CertRevoke)], user, null);
            await handler.HandleAsync(context);
            return context.HasSucceeded;
        }

        // cert.revoke on the other CA does not reach a certificate adopted under this one.
        a.Grant(a.OtherCaId, Capabilities.CertRevoke);
        Assert.False(await MayRevoke(adopted.Certificate.CertificateId));
        a.Grant(a.W.CaId, Capabilities.CertRevoke);
        Assert.True(await MayRevoke(adopted.Certificate.CertificateId));
    }
}
