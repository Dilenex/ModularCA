using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services.Continuity;
using ModularCA.Core.Services.Journal;
using ModularCA.Database;
using ModularCA.Journal;
using ModularCA.Keystore.Signing;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Modes;
using ModularCA.Shared.Signing;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Modes;
using ModularCA.Tests.Signer;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using Xunit;

namespace ModularCA.Tests.Journal;

/// <summary>
/// The merge: a node whose database has gone back in time makes again the revocations the
/// signer's journal holds, from the signer's answer alone, with their dates and reasons, audits
/// each, raises one notice, and never takes anything from a journal the signer does not trust.
/// </summary>
public class JournalRevocationMergeTests
{
    /// <summary>A node's database, a signer with its journal, and the merge between them.</summary>
    private sealed class Bench : IAsyncDisposable
    {
        public SignerTestWorld World { get; } = SignerTestWorld.Create();
        public JournalSandbox Sandbox { get; } = new();
        public RecordingAuditService Audit { get; } = new();
        public FixedModeGate Mode { get; } = new(InstanceMode.Full);
        public JournalMergeState State { get; private set; } = new();
        public SignerJournal Journal { get; private set; } = null!;
        public ISigningService Signer { get; private set; } = null!;
        public JournalRevocationMerge Merge { get; private set; } = null!;
        public IServiceScopeFactory Scopes { get; }
        /// <summary>Changes to the writer's options, for a test that needs a short wait.</summary>
        public Action<JournalSandbox.OptionsOverride>? Change { get; set; }
        public SignerTestKey Ca => World["ca-ec"];
        public Guid CaId => Ca.CaId!.Value;
        public string IssuerDn => Ca.Certificate.SubjectDN.ToString();

        public Bench(bool enforce = true)
        {
            var services = new ServiceCollection();
            services.AddScoped(_ => World.OpenDb());
            services.AddSingleton<IAuditService>(Audit);
            Scopes = services.BuildServiceProvider().GetRequiredService<IServiceScopeFactory>();
            Open(enforce);
        }

        private void Open(bool enforce)
        {
            Journal = new SignerJournal(() => Sandbox.Options(change: Change), new SignerJournalSettings(Sandbox.Home, enforce, "0.0.0-test", new byte[32]), NullLogger.Instance);
            Signer = TestSigner.Over(World.Keystore, World.DatabaseName, World.Persistence, Journal);
            State = new JournalMergeState();
            Merge = new JournalRevocationMerge(Scopes, Signer, State, Mode, NullLogger<JournalRevocationMerge>.Instance);
        }

        /// <summary>Stops the signer in order and starts another over the same journal, with a node that has just started too.</summary>
        public async Task RestartAsync(bool enforce = true)
        {
            await Journal.DisposeAsync();
            Open(enforce);
        }

        public ModularCADbContext Db() => World.OpenDb();

        /// <summary>A certificate row under the CA, as issuance leaves it: not revoked.</summary>
        public CertificateEntity Row(BigInteger serial, DateTime? notAfter = null, X509Certificate? real = null)
        {
            using var db = Db();
            var row = new CertificateEntity
            {
                CertificateId = Guid.NewGuid(), SerialNumber = CertificateUtil.FormatSerialNumber(serial), SubjectDN = $"CN=row-{serial.ToString(16)}",
                Issuer = IssuerDn, Pem = real == null ? "x" : CertificateUtil.ConvertDerToPem(real.GetEncoded(), "CERTIFICATE"),
                RawCertificate = real?.GetEncoded() ?? [],
                NotBefore = DateTime.UtcNow.AddDays(-30), NotAfter = notAfter ?? DateTime.UtcNow.AddDays(30),
            };
            db.Certificates.Add(row);
            db.SaveChanges();
            return row;
        }

        public CertificateEntity Reload(CertificateEntity row)
        {
            using var db = Db();
            return db.Certificates.AsNoTracking().Single(c => c.CertificateId == row.CertificateId);
        }

        public List<RevokedSerialTombstoneEntity> Tombstones()
        {
            using var db = Db();
            return db.RevokedSerialTombstones.AsNoTracking().OrderBy(t => t.SerialNumber).ToList();
        }

        /// <summary>Signs a full CRL through the signer, as the CRL service does.</summary>
        public X509Crl SignCrl(long number, params (BigInteger Serial, int Reason, DateTime At)[] entries)
        {
            var at = DateTime.UtcNow;
            var generator = new X509V2CrlGenerator();
            generator.SetIssuerDN(Ca.Certificate.SubjectDN);
            generator.SetThisUpdate(at);
            generator.SetNextUpdate(at.AddHours(6));
            foreach (var (serial, reason, when) in entries)
                generator.AddCrlEntry(serial, when, reason);
            generator.AddExtension(X509Extensions.CrlNumber, false, new DerInteger(BigInteger.ValueOf(number)));
            return generator.Generate(new SigningServiceSignatureFactory(Signer, Ca.Ref, SignatureAlgorithm.ForPublicKey(Ca.PublicKey),
                SigningContext.ForCa("merge-test", SigningPurpose.Crl, CaId, Ca.SpaceId)));
        }

        /// <summary>Signs the CRL the node would generate from its database now: revoked rows that have not expired, and listed tombstones.</summary>
        public X509Crl SignCrlFromDatabase(long number)
        {
            using var db = Db();
            var now = DateTime.UtcNow;
            var entries = db.Certificates.AsNoTracking().Where(c => c.Revoked && c.NotAfter > now && c.Issuer == IssuerDn).ToList()
                .Select(c => (new BigInteger(c.SerialNumber, 16), ModularCA.Core.Services.CrlService.GetCrlReasonCode(c.RevocationReason), c.RevocationDate ?? now))
                .Concat(db.RevokedSerialTombstones.AsNoTracking().Where(t => t.ListedUntil > now).ToList()
                    .Select(t => (new BigInteger(t.SerialNumber, 16), ModularCA.Core.Services.CrlService.GetCrlReasonCode(t.RevocationReason), t.RevocationDate)))
                .ToArray();
            return SignCrl(number, entries);
        }

        private byte[] CaKeyHash => SHA256.HashData(Org.BouncyCastle.X509.SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(Ca.PublicKey).GetDerEncoded());

        /// <summary>A revocation the node records with the signer, as its queue does after the revocation is saved.</summary>
        public Task<ulong> RevokedFact(BigInteger serial, int reason, DateTime at, ulong form = RevocationForm.Revoked)
            => Signer.RecordFactAsync(RecordType.Revocation,
                new RevocationPayload(serial.ToByteArrayUnsigned(), CaKeyHash, CaId.ToString("D"), (ulong)reason, JournalFormat.ToMicros(at), true, form).Encode(),
                new SigningContext("node", SigningPurpose.JournalFact, null, null));

        /// <summary>A released hold the node records with the signer.</summary>
        public Task<ulong> ReleasedFact(BigInteger serial)
            => Signer.RecordFactAsync(RecordType.Unrevocation,
                new UnrevocationPayload(serial.ToByteArrayUnsigned(), CaKeyHash, CaId.ToString("D"), JournalFormat.ToMicros(DateTime.UtcNow)).Encode(),
                new SigningContext("node", SigningPurpose.JournalFact, null, null));

        public List<(string Action, string? TargetId, JsonElement Details)> Audits(string action)
            => Audit.Entries.Where(e => e.Action == action)
                .Select(e => (e.Action, e.TargetId, JsonSerializer.SerializeToElement(e.Details))).ToList();

        public List<InstanceContinuityEventEntity> Notices()
        {
            using var db = Db();
            return db.InstanceContinuityEvents.AsNoTracking().Where(e => e.Kind == ContinuityEventKind.RevocationsMergedFromJournal).ToList();
        }

        public async ValueTask DisposeAsync()
        {
            await Journal.DisposeAsync();
            Sandbox.Dispose();
        }
    }

    private static BigInteger S(long value) => BigInteger.ValueOf(value);

    private static DateTime Seconds(DateTime value) => new(value.Ticks - value.Ticks % TimeSpan.TicksPerSecond, DateTimeKind.Utc);

    private static readonly DateTime T0 = Seconds(DateTime.UtcNow.AddDays(-3));

    [Fact]
    public async Task A_database_taken_back_gets_exactly_the_revocations_the_journal_holds_with_their_dates_and_reasons()
    {
        await using var bench = new Bench();
        // What the database, taken back, still holds: four certificates, none revoked; one of them has expired since.
        var knownA = bench.Row(S(0xA1));
        var knownB = bench.Row(S(0xA2));
        var expiredReal = IssueReal(bench, S(0xA3), DateTime.UtcNow.AddDays(-1));
        var expired = bench.Row(S(0xA3), expiredReal.NotAfter, expiredReal);
        var heldThenReleased = bench.Row(S(0xA4));
        var untouched = bench.Row(S(0xA5));
        // A certificate the database revoked and the journal has never heard of: it stays revoked.
        var revokedHere = bench.Row(S(0xA6));
        using (var db = bench.Db())
        {
            var row = db.Certificates.Single(c => c.CertificateId == revokedHere.CertificateId);
            row.Revoked = true; row.RevocationReason = "Superseded"; row.RevocationDate = T0;
            db.SuppressSignerFacts = true;
            db.SaveChanges();
        }

        // What the signer signed before the database went back: a CRL listing two known
        // certificates, the expired one, a hold, and two serials the database has no row for.
        bench.SignCrl(7,
            (S(0xA1), CrlReason.KeyCompromise, T0),
            (S(0xA2), CrlReason.Superseded, T0.AddHours(1)),
            (S(0xA3), CrlReason.Superseded, T0.AddHours(2)),
            (S(0xA4), CrlReason.CertificateHold, T0.AddHours(3)),
            (S(0xB1), CrlReason.CACompromise, T0.AddHours(4)),
            (S(0xB2), CrlReason.CessationOfOperation, T0.AddHours(5)));
        // After that CRL the hold was released.
        await bench.ReleasedFact(S(0xA4));
        // A new start of the signer and of the node, over the database that went back.
        await bench.RestartAsync();

        var result = await bench.Merge.MergeAsync(bench.CaId);

        Assert.Equal((JournalMergeState.Done, 4, 0), (result.State, result.Merged, result.Pending));
        // The two known certificates are revoked again, with the journaled CRL's dates and reasons.
        var a = bench.Reload(knownA);
        Assert.True(a.Revoked);
        Assert.Equal(("KeyCompromise", (DateTime?)T0), (a.RevocationReason, a.RevocationDate));
        var b = bench.Reload(knownB);
        Assert.Equal((true, "Superseded", (DateTime?)T0.AddHours(1)), (b.Revoked, b.RevocationReason, b.RevocationDate));
        // The two unknown serials are recorded with no certificate, with theirs.
        var tombstones = bench.Tombstones();
        Assert.Equal(new[] { "B1", "B2" }, tombstones.Select(t => t.SerialNumber));
        Assert.Equal(("CACompromise", T0.AddHours(4)), (tombstones[0].RevocationReason, tombstones[0].RevocationDate));
        Assert.Equal(("CessationOfOperation", T0.AddHours(5)), (tombstones[1].RevocationReason, tombstones[1].RevocationDate));
        Assert.All(tombstones, t => { Assert.Equal(bench.CaId, t.CertificateAuthorityId); Assert.Equal(JournalRevocationMerge.Actor, t.CreatedByUsername); Assert.Contains("CRL number 7", t.Note, StringComparison.Ordinal); Assert.True(t.ListedUntil > DateTime.UtcNow); });
        // Not merged: the expired certificate, the hold that was released, and what the journal never listed.
        Assert.False(bench.Reload(expired).Revoked);
        Assert.False(bench.Reload(heldThenReleased).Revoked);
        Assert.False(bench.Reload(untouched).Revoked);
        // Nothing was un-revoked.
        Assert.Equal((true, "Superseded"), (bench.Reload(revokedHere).Revoked, bench.Reload(revokedHere).RevocationReason));

        // Each is audited, naming its source; one summary; one notice.
        var audits = bench.Audits(AuditActionType.RevocationMergedFromJournal);
        Assert.Equal(4, audits.Count);
        Assert.Equal(new[] { "A1", "A2", "B1", "B2" }, audits.Select(x => x.Details.GetProperty("SerialNumber").GetString()).OrderBy(x => x));
        var one = audits.Single(x => x.Details.GetProperty("SerialNumber").GetString() == "A1").Details;
        Assert.Equal(bench.CaId, one.GetProperty("CertificateAuthorityId").GetGuid());
        Assert.Equal("KeyCompromise", one.GetProperty("Reason").GetString());
        Assert.Equal(T0, one.GetProperty("RevocationDate").GetDateTime().ToUniversalTime());
        Assert.Equal("crl", one.GetProperty("Source").GetString());
        Assert.Equal(7, one.GetProperty("SourceCrlNumber").GetInt64());
        Assert.True(one.GetProperty("SourceSeq").GetUInt64() > 0);
        Assert.Equal("certificate", one.GetProperty("Made").GetString());
        Assert.Equal(knownA.CertificateId, one.GetProperty("CertificateId").GetGuid());
        var summary = Assert.Single(bench.Audits(AuditActionType.JournalRevocationMergeCompleted)).Details;
        Assert.Equal(4, summary.GetProperty("Merged").GetInt32());
        Assert.Equal(7, summary.GetProperty("JournaledCrlNumber").GetInt64());
        var notice = Assert.Single(bench.Notices());
        Assert.Null(notice.AcknowledgedAt);
        var sentence = InstanceContinuity.MessageFor(notice);
        Assert.StartsWith("4 revocation(s) were restored from the signer's journal for CA ", sentence, StringComparison.Ordinal);
        Assert.Contains("after the database went back in time", sentence, StringComparison.Ordinal);

        // Each merged revocation is a fact for the journal like any other revocation.
        using (var db = bench.Db())
        {
            var facts = db.SignerFacts.AsNoTracking().Where(f => f.Type == RecordType.Revocation).ToList().Select(f => RevocationPayload.Decode(f.Payload)).ToList();
            Assert.Equal(new[] { "a1", "a2", "b1", "b2" }, facts.Select(f => new BigInteger(1, f.Serial).ToString(16)).OrderBy(x => x));
            Assert.Equal(JournalFormat.ToMicros(T0), facts.Single(f => new BigInteger(1, f.Serial).ToString(16) == "a1").Time);
        }

        // The CRL the node now generates lists them, and the signer signs it.
        var signed = bench.SignCrlFromDatabase(8);
        Assert.Equal(new[] { "a1", "a2", "a6", "b1", "b2" },
            signed.GetRevokedCertificates().Select(e => e.SerialNumber.ToString(16)).OrderBy(x => x));
        Assert.Equal(T0, signed.GetRevokedCertificate(S(0xA1)).RevocationDate.ToUniversalTime());
        Assert.Empty((await bench.Signer.JournalInfoAsync())!.RefusedCrls!);

        // The next run finds nothing to do, audits nothing and raises nothing.
        var again = await bench.Merge.MergeAsync(bench.CaId);
        Assert.Equal((JournalMergeState.Done, 0), (again.State, again.Merged));
        Assert.Equal(4, bench.Audits(AuditActionType.RevocationMergedFromJournal).Count);
        Assert.Single(bench.Notices());
        // And after a restart of both, with the merged facts and the new CRL in the journal: nothing again.
        await bench.RestartAsync();
        Assert.Equal(0, (await bench.Merge.MergeAsync(bench.CaId)).Merged);
        Assert.Single(bench.Notices());
        Assert.Equal(2, bench.Tombstones().Count);
    }

    private static byte[] Spki(Bench bench) => SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bench.Ca.PublicKey).GetDerEncoded();

    /// <summary>The data of an OCSP response that says "good" for <paramref name="serial"/>.</summary>
    private static Org.BouncyCastle.Asn1.Ocsp.ResponseData Good(Bench bench, BigInteger serial)
    {
        var generator = new Org.BouncyCastle.Ocsp.BasicOcspRespGenerator(new Org.BouncyCastle.Ocsp.RespID(bench.Ca.Certificate.SubjectDN));
        generator.AddResponse(new Org.BouncyCastle.Ocsp.CertificateID(Org.BouncyCastle.Ocsp.CertificateID.DigestSha1, bench.Ca.Certificate, serial), Org.BouncyCastle.Ocsp.CertificateStatus.Good);
        var other = KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-256");
        var response = generator.Generate(new Org.BouncyCastle.Crypto.Operators.Asn1SignatureFactory("SHA256WITHECDSA", other.Private), null, DateTime.UtcNow);
        return Org.BouncyCastle.Asn1.Ocsp.ResponseData.GetInstance(Asn1Object.FromByteArray(response.GetTbsResponseData()));
    }

    private static X509Certificate IssueReal(Bench bench, BigInteger serial, DateTime notAfter)
    {
        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(serial);
        generator.SetIssuerDN(bench.Ca.Certificate.SubjectDN);
        generator.SetSubjectDN(new X509Name($"CN=real-{serial.ToString(16)}"));
        generator.SetNotBefore(notAfter.AddDays(-10));
        generator.SetNotAfter(notAfter);
        generator.SetPublicKey(KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-256").Public);
        return generator.Generate(new SigningServiceSignatureFactory(bench.Signer, bench.Ca.Ref, SignatureAlgorithm.ForPublicKey(bench.Ca.PublicKey),
            SigningContext.ForCa("merge-test", SigningPurpose.Certificate, bench.CaId, bench.Ca.SpaceId)));
    }

    [Fact]
    public async Task Revocations_recorded_after_the_last_crl_are_restored_from_the_facts_in_their_order()
    {
        await using var bench = new Bench();
        var onCrl = bench.Row(S(0xC0));
        var afterCrl = bench.Row(S(0xC1));
        var heldAndReleased = bench.Row(S(0xC2));
        var heldStill = bench.Row(S(0xC3));
        var heldReleasedThenRevoked = bench.Row(S(0xC4));
        var retired = bench.Row(S(0xC5));
        bench.SignCrl(3, (S(0xC0), CrlReason.Superseded, T0));

        // After that CRL and before the database went back, the node recorded:
        var revokedSeq = await bench.RevokedFact(S(0xC1), CrlReason.KeyCompromise, T0.AddHours(1));
        await bench.RevokedFact(S(0xC2), CrlReason.CertificateHold, T0.AddHours(2), RevocationForm.Hold);
        await bench.ReleasedFact(S(0xC2));
        await bench.RevokedFact(S(0xC3), CrlReason.CertificateHold, T0.AddHours(3), RevocationForm.Hold);
        await bench.RevokedFact(S(0xC4), CrlReason.CertificateHold, T0.AddHours(4), RevocationForm.Hold);
        await bench.ReleasedFact(S(0xC4));
        await bench.RevokedFact(S(0xC4), CrlReason.AffiliationChanged, T0.AddHours(5));
        await bench.RevokedFact(S(0xC5), 0, T0.AddHours(6), RevocationForm.Retired);
        // A revocation of a serial the database has no row for.
        await bench.RevokedFact(S(0xD1), CrlReason.KeyCompromise, T0.AddHours(7));
        await bench.RestartAsync();

        var result = await bench.Merge.MergeAsync(bench.CaId);

        Assert.Equal(5, result.Merged);
        Assert.Equal((true, "Superseded", (DateTime?)T0), (bench.Reload(onCrl).Revoked, bench.Reload(onCrl).RevocationReason, bench.Reload(onCrl).RevocationDate));
        // The newest revocation, which no CRL ever listed, is back with the fact's own date and reason.
        Assert.Equal((true, "KeyCompromise", (DateTime?)T0.AddHours(1)), (bench.Reload(afterCrl).Revoked, bench.Reload(afterCrl).RevocationReason, bench.Reload(afterCrl).RevocationDate));
        // A hold made and released in the lost time is not.
        Assert.False(bench.Reload(heldAndReleased).Revoked);
        // A hold that still stood is restored as a hold.
        Assert.Equal((true, "CertificateHold", (DateTime?)T0.AddHours(3)), (bench.Reload(heldStill).Revoked, bench.Reload(heldStill).RevocationReason, bench.Reload(heldStill).RevocationDate));
        // Held, released, then revoked: the last word stands.
        Assert.Equal((true, "AffiliationChanged", (DateTime?)T0.AddHours(5)), (bench.Reload(heldReleasedThenRevoked).Revoked, bench.Reload(heldReleasedThenRevoked).RevocationReason, bench.Reload(heldReleasedThenRevoked).RevocationDate));
        // A retirement is not a revocation.
        Assert.False(bench.Reload(retired).Revoked);
        var tombstone = Assert.Single(bench.Tombstones());
        Assert.Equal(("D1", "KeyCompromise", T0.AddHours(7)), (tombstone.SerialNumber, tombstone.RevocationReason, tombstone.RevocationDate));
        Assert.Contains("a revocation the node recorded", tombstone.Note, StringComparison.Ordinal);

        // The audit names the fact, by its sequence, as the source.
        var fromFact = bench.Audits(AuditActionType.RevocationMergedFromJournal).Single(x => x.Details.GetProperty("SerialNumber").GetString() == "C1").Details;
        Assert.Equal("fact", fromFact.GetProperty("Source").GetString());
        Assert.Equal(revokedSeq, fromFact.GetProperty("SourceSeq").GetUInt64());
        Assert.Equal(JsonValueKind.Null, fromFact.GetProperty("SourceCrlNumber").ValueKind);
        var fromCrl = bench.Audits(AuditActionType.RevocationMergedFromJournal).Single(x => x.Details.GetProperty("SerialNumber").GetString() == "C0").Details;
        Assert.Equal(("crl", 3L), (fromCrl.GetProperty("Source").GetString(), fromCrl.GetProperty("SourceCrlNumber").GetInt64()));

        // In the time before the merge, the signer refuses "good" for a serial whose last fact says revoked, and for nothing else.
        Assert.Contains("recorded as revoked", (await bench.Journal.JudgeOcspAsync(Spki(bench), Good(bench, S(0xC1))))!, StringComparison.Ordinal);
        Assert.Contains("recorded as revoked", (await bench.Journal.JudgeOcspAsync(Spki(bench), Good(bench, S(0xC4))))!, StringComparison.Ordinal);
        Assert.Null(await bench.Journal.JudgeOcspAsync(Spki(bench), Good(bench, S(0xC2))));
        Assert.Null(await bench.Journal.JudgeOcspAsync(Spki(bench), Good(bench, S(0xC5))));
        Assert.NotNull(await bench.Journal.JudgeOcspAsync(Spki(bench), Good(bench, S(0xC0))));

        // What the signer answers, as it stands: the hold flagged, nothing released, nothing retired.
        var list = (await bench.Signer.JournaledRevocationsAsync(bench.CaId, 0, 100))!;
        Assert.True(list.Trusted);
        Assert.Equal(new[] { "C0", "C1", "C3", "C4", "D1" }, list.Entries.Select(e => e.Serial));
        Assert.Equal(new[] { false, false, true, false, false }, list.Entries.Select(e => e.Hold));
        Assert.Equal(3, list.CrlNumber);
        Assert.Equal(5, list.Total);
        // A part at a time.
        Assert.Equal(new[] { "C3", "C4" }, (await bench.Signer.JournaledRevocationsAsync(bench.CaId, 2, 2))!.Entries.Select(e => e.Serial));
        Assert.Empty((await bench.Signer.JournaledRevocationsAsync(bench.CaId, 50, 2))!.Entries);

        // The signer keeps the list between parts, and works it out again when what it was made from changes:
        // a fact more,
        await bench.RevokedFact(S(0xD2), CrlReason.KeyCompromise, T0.AddHours(8));
        Assert.Equal(new[] { "C0", "C1", "C3", "C4", "D1", "D2" }, (await bench.Signer.JournaledRevocationsAsync(bench.CaId, 0, 100))!.Entries.Select(e => e.Serial));
        // a hold released,
        await bench.ReleasedFact(S(0xC3));
        Assert.Equal(new[] { "C0", "C1", "C4", "D1", "D2" }, (await bench.Signer.JournaledRevocationsAsync(bench.CaId, 0, 100))!.Entries.Select(e => e.Serial));
        // and a newer CRL.
        bench.SignCrl(4, (S(0xC0), CrlReason.Superseded, T0), (S(0xC1), CrlReason.KeyCompromise, T0.AddHours(1)), (S(0xC4), CrlReason.AffiliationChanged, T0.AddHours(5)),
            (S(0xD1), CrlReason.KeyCompromise, T0.AddHours(7)), (S(0xD2), CrlReason.KeyCompromise, T0.AddHours(8)), (S(0xD3), CrlReason.Superseded, T0.AddHours(9)));
        var newer = (await bench.Signer.JournaledRevocationsAsync(bench.CaId, 0, 100))!;
        Assert.Equal(new[] { "C0", "C1", "C4", "D1", "D2", "D3" }, newer.Entries.Select(e => e.Serial));
        Assert.Equal(4, newer.CrlNumber);
        Assert.All(newer.Entries, e => Assert.Equal("crl", e.Source));
    }

    [Fact]
    public async Task With_no_journaled_crl_the_facts_alone_are_restored()
    {
        await using var bench = new Bench();
        var row = bench.Row(S(0xE1));
        await bench.RevokedFact(S(0xE1), CrlReason.KeyCompromise, T0);
        await bench.RestartAsync();

        Assert.Equal(1, (await bench.Merge.MergeAsync(bench.CaId)).Merged);

        Assert.Equal((true, "KeyCompromise", (DateTime?)T0), (bench.Reload(row).Revoked, bench.Reload(row).RevocationReason, bench.Reload(row).RevocationDate));
        var list = (await bench.Signer.JournaledRevocationsAsync(bench.CaId, 0, 10))!;
        Assert.Null(list.CrlNumber);
        // A CA the journal has nothing for: no answer, and nothing to do.
        Assert.Null(await bench.Signer.JournaledRevocationsAsync(bench.World["ca-rsa"].CaId!.Value, 0, 10));
        Assert.Equal(JournalMergeState.Done, (await bench.Merge.MergeAsync(bench.World["ca-rsa"].CaId!.Value)).State);
    }

    [Fact]
    public async Task A_record_appended_by_someone_who_holds_only_the_files_leads_to_no_merge()
    {
        await using var bench = new Bench();
        var victim = bench.Row(S(0xF1));
        bench.SignCrl(1, (S(0x11), CrlReason.Superseded, T0));
        await bench.Journal.DisposeAsync();

        // Whoever can write the journal's volume, and holds no key, appends a CRL record that lists
        // a certificate of their choosing. The chain's hashes are theirs to compute; a checkpoint is not.
        var last = bench.Sandbox.Records()[^1].Record;
        var forgedTbs = ForgedCrl(bench, 2, S(0x11), S(0xF1));
        var payload = new CrlPayload(bench.CaId.ToString("D"), SHA256.HashData(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bench.Ca.PublicKey).GetDerEncoded()),
            null, null, "0.0.0-test", 2, JournalFormat.ToMicros(DateTime.UtcNow), null, new byte[64], forgedTbs, null, null, false).Encode();
        var (bytes, _) = JournalRecord.Encode(RecordType.Crl, 0, last.Seq + 1, JournalFormat.ToMicros(DateTime.UtcNow), 0, last.Incarnation, last.Hash, payload);
        var file = Path.Combine(bench.Sandbox.Directory, bench.Sandbox.Names()[^1]);
        using (var stream = new FileStream(file, FileMode.Append, FileAccess.Write))
            stream.Write(bytes);
        await bench.RestartAsync();

        var result = await bench.Merge.MergeAsync(bench.CaId);

        // The signer does not answer from it, the node makes nothing, and says why.
        Assert.Equal((JournalMergeState.NotTrusted, 0), (result.State, result.Merged));
        Assert.False(bench.Reload(victim).Revoked);
        Assert.Empty(bench.Tombstones());
        Assert.Empty(bench.Audit.Entries);
        Assert.Empty(bench.Notices());
        var answer = (await bench.Signer.JournaledRevocationsAsync(bench.CaId, 0, 10))!;
        Assert.False(answer.Trusted);
        Assert.Empty(answer.Entries);
        Assert.NotNull(answer.NotTrustedReason);
        var status = bench.State.Of(bench.CaId)!;
        Assert.Equal(JournalMergeState.NotTrusted, status.State);
        Assert.Contains("no revocation was taken from it", status.Message!, StringComparison.Ordinal);
    }

    private static byte[] ForgedCrl(Bench bench, long number, params BigInteger[] serials)
    {
        var generator = new X509V2CrlGenerator();
        generator.SetIssuerDN(bench.Ca.Certificate.SubjectDN);
        generator.SetThisUpdate(DateTime.UtcNow);
        generator.SetNextUpdate(DateTime.UtcNow.AddHours(6));
        foreach (var serial in serials)
            generator.AddCrlEntry(serial, T0, CrlReason.KeyCompromise);
        generator.AddExtension(X509Extensions.CrlNumber, false, new DerInteger(BigInteger.ValueOf(number)));
        // Signed with a key that is not the CA's: the to-be-signed bytes are what matters here.
        var other = KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-256");
        return generator.Generate(new Org.BouncyCastle.Crypto.Operators.Asn1SignatureFactory("SHA256WITHECDSA", other.Private)).GetTbsCertList();
    }

    /// <summary>The serial of a certificate the attacker wants revoked, on a CRL of their own making.</summary>
    private static CrlPayload ForgedCrlPayload(Bench bench, long number, params BigInteger[] serials)
        => new(bench.CaId.ToString("D"), SHA256.HashData(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bench.Ca.PublicKey).GetDerEncoded()),
            null, null, "0.0.0-test", (ulong)number, JournalFormat.ToMicros(DateTime.UtcNow), null, new byte[64], ForgedCrl(bench, number, serials), null, null, false);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task A_change_to_keys_of_their_own_by_someone_who_holds_only_the_files_leads_to_no_merge(bool changesBack)
    {
        await using var bench = new Bench();
        var victim = bench.Row(S(0xF7));
        bench.SignCrl(1, (S(0x17), CrlReason.Superseded, T0));
        await bench.Journal.DisposeAsync();
        var genuine = bench.Sandbox.Verify().Head!;

        // Whoever can write the volume appends a segment in which the journal "changes" to a system
        // key and a checkpoint key of their own, explained by a restore they also write, then a CRL
        // of their own, then a checkpoint signed with their checkpoint key. All of it chains and
        // verifies as a journal. With changesBack they then put the genuine key block back, signed
        // for by "the system key before", which is theirs, to end under the genuine system key.
        var theirSystem = new TestJournalKey();
        var theirCheckpoint = new TestJournalKey();
        var theirBlock = JournalSignatures.MakeKeyBlock(bench.Sandbox.InstanceId, theirCheckpoint.PublicKey, theirSystem);
        var marker = new RestoreMarkerPayload("modularca-backup-20261112-010000.enc", bench.Sandbox.InstanceId, 1_700_000_000_000_000, null);
        JournalGenesisAndProgressTests.AppendSegment(bench.Sandbox, g => g, (_, _) =>
        {
            var records = new List<(ushort, byte, Func<ulong, byte[], byte[]>)>
            {
                (RecordType.RestoreMarker, JournalFormat.FlagNodeAsserted, (_, _) => marker.Encode()),
                (RecordType.CheckpointKeyChanged, 0, (_, _) => new CheckpointKeyChangedPayload(theirBlock,
                    Explains: new ChangeExplanation(ExplanationKind.Restore, marker.Archive, marker.ArchiveInstanceId, marker.ArchiveCreatedAt),
                    SystemPublicKey: theirSystem.PublicKey).Encode()),
                (RecordType.Crl, 0, (_, _) => ForgedCrlPayload(bench, 2, S(0x17), S(0xF7)).Encode()),
                (RecordType.Revocation, JournalFormat.FlagNodeAsserted, (_, _) => new RevocationPayload(S(0xF8).ToByteArrayUnsigned(),
                    SHA256.HashData(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bench.Ca.PublicKey).GetDerEncoded()), bench.CaId.ToString("D"), 1, JournalFormat.ToMicros(T0), true, RevocationForm.Revoked).Encode()),
                (RecordType.Checkpoint, 0, (seq, prev) => new CheckpointPayload(JournalSignatures.KeyHash(theirCheckpoint.PublicKey), theirCheckpoint.Algorithm,
                    theirCheckpoint.Sign(JournalSignatures.CheckpointMessage(bench.Sandbox.InstanceId, seq, prev))).Encode()),
            };
            if (changesBack)
            {
                records.Add((RecordType.CheckpointKeyChanged, 0, (_, _) => new CheckpointKeyChangedPayload(genuine.Key!,
                    OldSystemKeySignature: theirSystem.Sign(JournalSignatures.SystemKeyChangedMessage(bench.Sandbox.InstanceId, genuine.Key!.SystemKey)),
                    OldSystemKeyAlgorithm: theirSystem.Algorithm, SystemPublicKey: genuine.SystemPublicKey).Encode()));
                // And one more revocation of their choosing, now "under" the genuine key block, which they cannot checkpoint.
                records.Add((RecordType.Revocation, JournalFormat.FlagNodeAsserted, (_, _) => new RevocationPayload(S(0xF8).ToByteArrayUnsigned(),
                    SHA256.HashData(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bench.Ca.PublicKey).GetDerEncoded()), bench.CaId.ToString("D"), 1, JournalFormat.ToMicros(T0), true, RevocationForm.Revoked).Encode()));
            }
            return records;
        });
        // As a journal it holds: the change is one a verifier reports for matching from outside.
        var read = bench.Sandbox.Verify();
        Assert.Null(read.Fault);
        Assert.Single(read.Unvouched);
        var other = bench.Row(S(0xF8));
        await bench.RestartAsync();

        var result = await bench.Merge.MergeAsync(bench.CaId);

        // Nothing they wrote is covered by a checkpoint of a key the held system key signed for.
        Assert.Equal((JournalMergeState.NotTrusted, 0), (result.State, result.Merged));
        Assert.False(bench.Reload(victim).Revoked);
        Assert.False(bench.Reload(other).Revoked);
        Assert.Empty(bench.Tombstones());
        Assert.Empty(bench.Notices());
        var answer = (await bench.Signer.JournaledRevocationsAsync(bench.CaId, 0, 10))!;
        Assert.False(answer.Trusted);
        Assert.Empty(answer.Entries);
        Assert.Contains("nothing vouches for it", answer.NotTrustedReason!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_genuine_checkpoint_replayed_after_other_records_does_not_verify()
    {
        await using var bench = new Bench();
        bench.SignCrl(1, (S(0x18), CrlReason.Superseded, T0));
        await bench.Journal.DisposeAsync();
        // The journal's own last checkpoint, signed by the genuine checkpoint key, placed after a forged CRL.
        var genuineCheckpoint = bench.Sandbox.Records().Last(r => r.Record.Type == RecordType.Checkpoint).Record.Payload;
        var name = JournalGenesisAndProgressTests.AppendSegment(bench.Sandbox, g => g, (_, _) =>
        [
            (RecordType.Crl, 0, (_, _) => ForgedCrlPayload(bench, 2, S(0x18), S(0xF9)).Encode()),
            (RecordType.Checkpoint, 0, (_, _) => genuineCheckpoint),
        ]);

        // A checkpoint signs its own sequence and the hash of the record before it: here neither is what it signed.
        var fault = bench.Sandbox.Verify().Fault!;
        Assert.Equal(name, fault.Segment);
        Assert.Contains("Checkpoint's signature does not verify", fault.Reason, StringComparison.Ordinal);

        var victim = bench.Row(S(0xF9));
        await bench.RestartAsync();
        Assert.Equal(0, (await bench.Merge.MergeAsync(bench.CaId)).Merged);
        Assert.False(bench.Reload(victim).Revoked);
    }

    [Fact]
    public async Task After_an_unvouched_change_of_system_key_what_was_recorded_under_the_held_key_is_merged()
    {
        await using var bench = new Bench();
        var before = bench.Row(S(0x61));
        var after = bench.Row(S(0x62));
        var newest = bench.Row(S(0x63));
        bench.SignCrl(1, (S(0x61), CrlReason.KeyCompromise, T0));

        // The keystores are put back to a state with another system key (and so another checkpoint
        // key), on a machine that reports another incarnation: the journal records the change with
        // the changed incarnation as what explains it. No key signed for it.
        bench.Sandbox.SystemKey = new TestJournalKey();
        bench.Sandbox.CheckpointKey = new TestJournalKey();
        bench.Sandbox.Incarnation = Enumerable.Repeat((byte)5, 32).ToArray();
        await bench.RestartAsync();

        // What the journal holds for the CA is still the CRL from before the change, under keys the
        // held system key never signed for: it is not a source.
        var early = await bench.Merge.MergeAsync(bench.CaId);
        Assert.Equal((JournalMergeState.NotTrusted, 0), (early.State, early.Merged));
        Assert.False(bench.Reload(before).Revoked);

        // The signer goes on under the key it holds: a CRL, and a revocation after it.
        bench.SignCrl(2, (S(0x61), CrlReason.KeyCompromise, T0), (S(0x62), CrlReason.Superseded, T0.AddHours(1)));
        await bench.RevokedFact(S(0x63), CrlReason.AffiliationChanged, T0.AddHours(2));
        await bench.RestartAsync();

        // The signer opened its journal again after the change (it reads only the newest segment
        // to do so, where the old incarnation is not to be seen), and the change is still in the
        // journal, reported as unvouched; there is no bar on the journal for it.
        Assert.True((await bench.Signer.JournalInfoAsync())!.Available);
        var verification = bench.Sandbox.Verify();
        Assert.Null(verification.Fault);
        Assert.Single(verification.Unvouched);
        var result = await bench.Merge.MergeAsync(bench.CaId);

        Assert.True(result.State == JournalMergeState.Done, bench.State.Of(bench.CaId)?.Message);
        Assert.Equal((JournalMergeState.Done, 3), (result.State, result.Merged));
        Assert.Equal((true, "KeyCompromise", (DateTime?)T0), (bench.Reload(before).Revoked, bench.Reload(before).RevocationReason, bench.Reload(before).RevocationDate));
        Assert.Equal((true, "Superseded"), (bench.Reload(after).Revoked, bench.Reload(after).RevocationReason));
        Assert.Equal((true, "AffiliationChanged"), (bench.Reload(newest).Revoked, bench.Reload(newest).RevocationReason));
        Assert.True((await bench.Signer.JournalInfoAsync())!.Verified);
    }

    [Fact]
    public async Task After_a_change_of_system_key_that_nothing_explains_the_signer_goes_on_and_later_records_are_merged()
    {
        await using var bench = new Bench();
        var row = bench.Row(S(0x71));
        bench.SignCrl(1, (S(0x70), CrlReason.Superseded, T0));

        // Another system key, the same incarnation, and no restore marker comes: after the wait the change is written unexplained.
        bench.Sandbox.SystemKey = new TestJournalKey();
        bench.Sandbox.CheckpointKey = new TestJournalKey();
        bench.Change = o => o.UnexplainedKeyChangeWait = TimeSpan.FromMilliseconds(150);
        await bench.RestartAsync();
        await bench.RevokedFact(S(0x7F), CrlReason.Superseded, T0);
        var deadline = DateTime.UtcNow.AddSeconds(20);
        while (!bench.Sandbox.Records().Any(r => r.Record.Type == RecordType.CheckpointKeyChanged) && DateTime.UtcNow < deadline)
            await Task.Delay(50);
        bench.SignCrl(2, (S(0x70), CrlReason.Superseded, T0), (S(0x71), CrlReason.KeyCompromise, T0.AddHours(1)), (S(0x7F), CrlReason.Superseded, T0));

        // The verify command calls it a fault, as it is one to explain from outside.
        await bench.Journal.DisposeAsync();
        Assert.Contains("says nothing that explains it", bench.Sandbox.Verify().Fault!.Reason, StringComparison.Ordinal);

        // The signer starts over it all the same, appends, and says that its journal did not verify.
        await bench.RestartAsync();
        var info = (await bench.Signer.JournalInfoAsync())!;
        Assert.True(info.Available);
        bench.SignCrl(3, (S(0x70), CrlReason.Superseded, T0), (S(0x71), CrlReason.KeyCompromise, T0.AddHours(1)), (S(0x7F), CrlReason.Superseded, T0));
        await bench.RestartAsync();

        var result = await bench.Merge.MergeAsync(bench.CaId);

        // What was recorded after the change, under a checkpoint key the held system key signed for, is merged.
        Assert.Equal(JournalMergeState.Done, result.State);
        Assert.Equal((true, "KeyCompromise"), (bench.Reload(row).Revoked, bench.Reload(row).RevocationReason));
        Assert.Equal(new[] { "70", "7F" }, bench.Tombstones().Select(t => t.SerialNumber));
        var after = (await bench.Signer.JournalInfoAsync())!;
        Assert.False(after.Verified);
        Assert.Contains("says nothing that explains it", after.VerificationFault!, StringComparison.Ordinal);
        Assert.Equal(after.VerifyTotalBytes, after.VerifiedBytes is long read && read > 0 ? after.VerifyTotalBytes : -1);
    }

    [Fact]
    public async Task A_journaled_crl_whose_signature_does_not_verify_under_the_ca_key_contributes_nothing()
    {
        await using var bench = new Bench();
        var victim = bench.Row(S(0xF2));
        bench.SignCrl(1, (S(0x12), CrlReason.Superseded, T0));
        await bench.Journal.DisposeAsync();

        // A record written with the journal's own keys, checkpointed and sealed like any other,
        // whose CRL the CA key never signed: what a signer that was made to record it would leave.
        await using (var writer = bench.Sandbox.Open())
        {
            var forgedTbs = ForgedCrl(bench, 2, S(0x12), S(0xF2));
            await writer.AppendAsync(RecordType.Crl, 0, new CrlPayload(bench.CaId.ToString("D"),
                SHA256.HashData(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bench.Ca.PublicKey).GetDerEncoded()),
                null, null, "0.0.0-test", 2, JournalFormat.ToMicros(DateTime.UtcNow), null, new byte[64], forgedTbs, null, null, false).Encode());
        }
        Assert.Null(bench.Sandbox.Verify().Fault);
        await bench.RestartAsync();

        var result = await bench.Merge.MergeAsync(bench.CaId);

        Assert.Equal((JournalMergeState.NotTrusted, 0), (result.State, result.Merged));
        Assert.False(bench.Reload(victim).Revoked);
        Assert.Empty(bench.Tombstones());
        // The journal itself verified; it is this CRL that does not carry the CA's signature.
        Assert.True((await bench.Signer.JournalInfoAsync())!.Verified);
        var answer = (await bench.Signer.JournaledRevocationsAsync(bench.CaId, 0, 10))!;
        Assert.False(answer.Trusted);
        Assert.Contains("does not verify under the CA's key", answer.NotTrustedReason!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task In_dr_mode_the_merge_changes_nothing_counts_what_waits_and_runs_when_the_mode_is_changed()
    {
        await using var bench = new Bench();
        var known = bench.Row(S(0x21));
        bench.SignCrl(1, (S(0x21), CrlReason.KeyCompromise, T0), (S(0x22), CrlReason.Superseded, T0));
        await bench.RestartAsync();
        bench.Mode.Mode = InstanceMode.DisasterRecovery;
        var service = new JournalMergeService(bench.Scopes, bench.Merge, bench.State, bench.Mode, NullLogger<JournalMergeService>.Instance);

        // The pass after start: nothing is written, and the CA is left pending with the count.
        Assert.True(await service.PassAsync(CancellationToken.None));
        Assert.False(bench.Reload(known).Revoked);
        Assert.Empty(bench.Tombstones());
        Assert.Empty(bench.Audit.Entries);
        var pending = bench.State.Of(bench.CaId)!;
        Assert.Equal((JournalMergeState.Pending, 2, 0), (pending.State, pending.Remaining, pending.Merged));
        Assert.Contains("DR mode", pending.Message!, StringComparison.Ordinal);
        // While the mode stands, later passes ask nothing and change nothing.
        Assert.True(await service.PassAsync(CancellationToken.None));
        Assert.Empty(bench.Tombstones());
        // A CRL would not be generated in DR mode; asking the merge before one changes nothing either.
        await bench.Merge.EnsureMergedAsync(await CaCertificateIdAsync(bench));
        Assert.False(bench.Reload(known).Revoked);

        // Maintenance mode revokes: the next pass makes them.
        bench.Mode.Mode = InstanceMode.Maintenance;
        Assert.False(await service.PassAsync(CancellationToken.None));
        Assert.True(bench.Reload(known).Revoked);
        Assert.Single(bench.Tombstones());
        Assert.Equal((JournalMergeState.Done, 2), (bench.State.Of(bench.CaId)!.State, bench.State.Of(bench.CaId)!.Merged));
        Assert.Single(bench.Notices());
    }

    private static async Task<Guid> CaCertificateIdAsync(Bench bench)
    {
        using var db = bench.Db();
        return (await db.CertificateAuthorities.AsNoTracking().Where(c => c.Id == bench.CaId).Select(c => c.CertificateId).SingleAsync())!.Value;
    }

    [Theory]
    [InlineData(InstanceMode.Full)]
    [InlineData(InstanceMode.Restricted)]
    [InlineData(InstanceMode.Maintenance)]
    public async Task The_merge_runs_in_every_mode_that_revokes(InstanceMode mode)
    {
        await using var bench = new Bench();
        var known = bench.Row(S(0x31));
        bench.SignCrl(1, (S(0x31), CrlReason.KeyCompromise, T0));
        await bench.RestartAsync();
        bench.Mode.Mode = mode;

        Assert.Equal(1, (await bench.Merge.MergeAsync(bench.CaId)).Merged);

        Assert.True(bench.Reload(known).Revoked);
    }

    [Fact]
    public async Task The_start_pass_runs_for_every_ca_comes_back_when_the_signer_was_not_reachable_and_a_crl_waits_for_it()
    {
        await using var bench = new Bench();
        var known = bench.Row(S(0x41));
        bench.SignCrl(1, (S(0x41), CrlReason.KeyCompromise, T0));
        await bench.RestartAsync();

        // The signer cannot be reached at first: the pass fails for the CA and is to be tried again.
        var (down, _) = JournalHubReviewTests.JournalAnswers.Create();
        var unreachable = new JournalRevocationMerge(bench.Scopes, down, bench.State, bench.Mode, NullLogger<JournalRevocationMerge>.Instance);
        var failing = new JournalMergeService(bench.Scopes, unreachable, bench.State, bench.Mode, NullLogger<JournalMergeService>.Instance);
        Assert.True(await failing.PassAsync(CancellationToken.None));
        Assert.Equal(JournalMergeState.Failed, bench.State.Of(bench.CaId)!.State);
        Assert.False(bench.Reload(known).Revoked);

        // Before a CRL of the CA is generated, the merge is performed if it has not run to an end.
        await bench.Merge.EnsureMergedAsync(await CaCertificateIdAsync(bench));
        Assert.True(bench.Reload(known).Revoked);
        Assert.Equal(JournalMergeState.Done, bench.State.Of(bench.CaId)!.State);
        var audits = bench.Audit.Entries.Count;
        // Once it has, a CRL does not run it again.
        await bench.Merge.EnsureMergedAsync(await CaCertificateIdAsync(bench));
        Assert.Equal(audits, bench.Audit.Entries.Count);

        // The background pass then has nothing left for any CA.
        var service = new JournalMergeService(bench.Scopes, bench.Merge, bench.State, bench.Mode, NullLogger<JournalMergeService>.Instance);
        Assert.False(await service.PassAsync(CancellationToken.None));
        Assert.All(bench.State.Snapshot(), s => Assert.Equal(JournalMergeState.Done, s.State));
        Assert.True(bench.State.Snapshot().Count >= 2);
    }

    [Fact]
    public async Task Many_entries_are_merged_in_batches_and_a_pass_that_stops_part_way_goes_on_where_the_database_stands()
    {
        await using var bench = new Bench();
        var count = JournalRevocationMerge.BatchSize * 2 + 40;
        bench.SignCrl(1, Enumerable.Range(1, count).Select(i => (S(0x100000 + i), CrlReason.Superseded, T0)).ToArray());
        await bench.RestartAsync();

        // A first pass that is cut off after its first batch is saved.
        using (var stop = new CancellationTokenSource())
        {
            var services = new ServiceCollection();
            services.AddScoped(_ => bench.World.OpenDb());
            services.AddSingleton<IAuditService>(new StopAtFirstAudit(stop));
            var interrupted = new JournalRevocationMerge(services.BuildServiceProvider().GetRequiredService<IServiceScopeFactory>(),
                bench.Signer, bench.State, bench.Mode, NullLogger<JournalRevocationMerge>.Instance);
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => interrupted.MergeAsync(bench.CaId, stop.Token));
        }
        var partial = bench.Tombstones().Count;
        Assert.Equal(JournalRevocationMerge.BatchSize, partial);

        // The next pass makes the rest and no entry twice.
        var result = await bench.Merge.MergeAsync(bench.CaId);
        Assert.Equal(count - partial, result.Merged);
        Assert.Equal(count, bench.Tombstones().Count);
        Assert.Equal(count, bench.Tombstones().Select(t => t.SerialNumber).Distinct().Count());
        Assert.Equal(count - partial, bench.Audits(AuditActionType.RevocationMergedFromJournal).Count);
        var done = bench.State.Of(bench.CaId)!;
        Assert.Equal((JournalMergeState.Done, 0, count), (done.State, done.Remaining, done.Total));
        // The pass that went on counted what was still missing and chose its own form: under the limit, a record for each.
        Assert.Empty(bench.Audits(AuditActionType.RevocationsMergedFromJournalBatch));
        Assert.Equal(JournalRevocationMerge.AuditFormIndividual,
            Assert.Single(bench.Audits(AuditActionType.JournalRevocationMergeCompleted)).Details.GetProperty("AuditForm").GetString());
    }

    /// <summary>A serial of twenty octets, the longest a certificate has.</summary>
    private static BigInteger Long(int i) => BigInteger.One.ShiftLeft(158).Add(BigInteger.ValueOf(i));

    [Fact]
    public async Task Above_the_limit_a_pass_is_audited_with_one_record_for_each_batch_that_carries_its_serials()
    {
        await using var bench = new Bench();
        var count = JournalRevocationMerge.DefaultIndividualAuditLimit + 1;
        var row = bench.Row(Long(1));
        bench.SignCrl(7, Enumerable.Range(1, count).Select(i => (Long(i), i == 2 ? CrlReason.KeyCompromise : CrlReason.Superseded, T0.AddMinutes(i))).ToArray());
        await bench.RestartAsync();

        var result = await bench.Merge.MergeAsync(bench.CaId);

        Assert.Equal((JournalMergeState.Done, count), (result.State, result.Merged));
        Assert.True(bench.Reload(row).Revoked);
        Assert.Equal(count - 1, bench.Tombstones().Count);

        // Never mixed: no record for a single revocation, and one for each save.
        Assert.Empty(bench.Audits(AuditActionType.RevocationMergedFromJournal));
        var batches = bench.Audits(AuditActionType.RevocationsMergedFromJournalBatch);
        Assert.Equal(3, batches.Count);
        Assert.All(batches, b => Assert.Equal(bench.CaId.ToString(), b.TargetId));
        Assert.Equal(new[] { 1, 2, 3 }, batches.Select(b => b.Details.GetProperty("Batch").GetInt32()));
        Assert.Equal(new[] { JournalRevocationMerge.BatchSize, JournalRevocationMerge.BatchSize, 1 }, batches.Select(b => b.Details.GetProperty("Count").GetInt32()));
        var entries = batches.SelectMany(b => b.Details.GetProperty("Revocations").EnumerateArray()).ToList();
        Assert.Equal(count, entries.Select(e => e.GetProperty("Serial").GetString()).Distinct().Count());

        // Each serial with its date, reason, what was made and its source.
        var ofRow = entries.Single(e => e.GetProperty("Serial").GetString() == row.SerialNumber);
        Assert.Equal(("certificate", row.CertificateId), (ofRow.GetProperty("Made").GetString(), ofRow.GetProperty("CertificateId").GetGuid()));
        var second = entries.Single(e => e.GetProperty("Serial").GetString() == CertificateUtil.FormatSerialNumber(Long(2)));
        Assert.Equal(("KeyCompromise", "serial without a certificate", "crl", 7L, T0.AddMinutes(2)),
            (second.GetProperty("Reason").GetString(), second.GetProperty("Made").GetString(), second.GetProperty("Source").GetString(),
             second.GetProperty("SourceCrlNumber").GetInt64(), second.GetProperty("Date").GetDateTime()));
        Assert.Equal(JsonValueKind.Null, second.GetProperty("CertificateId").ValueKind);
        // Eight members: the console shows a list of such objects as a table.
        Assert.Equal(8, second.EnumerateObject().Count());

        // A full batch of the longest serials, as the audit trail stores it: well under 128 KiB, and nothing in it scrubbed.
        var stored = ModularCA.Core.Services.AuditJsonScrubber.SerializeAndScrub(bench.Audit.Entries.First(e => e.Action == AuditActionType.RevocationsMergedFromJournalBatch).Details)!;
        Assert.InRange(stored.Length, 50_000, 128 * 1024);
        Assert.DoesNotContain("***", stored, StringComparison.Ordinal);
        Assert.Contains("\"" + CertificateUtil.FormatSerialNumber(Long(2)) + "\"", stored, StringComparison.Ordinal);

        // The summary says which form the pass used and how many records it wrote; so does the notice.
        var summary = Assert.Single(bench.Audits(AuditActionType.JournalRevocationMergeCompleted)).Details;
        Assert.Equal((JournalRevocationMerge.AuditFormBatch, AuditActionType.RevocationsMergedFromJournalBatch, 3, count),
            (summary.GetProperty("AuditForm").GetString(), summary.GetProperty("AuditAction").GetString(), summary.GetProperty("BatchRecords").GetInt32(), summary.GetProperty("Merged").GetInt32()));
        using var notice = JsonDocument.Parse(Assert.Single(bench.Notices()).DetailsJson!);
        Assert.Equal(("batch", 3), (notice.RootElement.GetProperty("auditForm").GetString(), notice.RootElement.GetProperty("batchRecords").GetInt32()));
    }

    [Theory]
    [InlineData(3, false)]
    [InlineData(4, true)]
    public async Task The_form_is_decided_once_from_what_the_pass_counts_missing_before_it_writes(int missing, bool batch)
    {
        await using var bench = new Bench();
        // Two of the journaled entries are in the database already and do not count.
        bench.SignCrl(1, Enumerable.Range(1, missing + 2).Select(i => (S(0x300000 + i), CrlReason.Superseded, T0)).ToArray());
        using (var db = bench.Db())
        {
            var caCertificateId = db.CertificateAuthorities.AsNoTracking().Single(c => c.Id == bench.CaId).CertificateId!.Value;
            foreach (var i in new[] { 1, 2 })
                db.RevokedSerialTombstones.Add(new RevokedSerialTombstoneEntity
                {
                    CaCertificateId = caCertificateId, CertificateAuthorityId = bench.CaId, IssuerDN = bench.IssuerDn,
                    SerialNumber = CertificateUtil.FormatSerialNumber(S(0x300000 + i)), RevocationDate = T0, RevocationReason = "Superseded",
                    ListedUntil = DateTime.UtcNow.AddYears(1), Note = "kept", CreatedByUsername = "test", CreatedAt = DateTime.UtcNow,
                });
            db.SaveChanges();
        }
        await bench.RestartAsync();
        var merge = new JournalRevocationMerge(bench.Scopes, bench.Signer, bench.State, bench.Mode, NullLogger<JournalRevocationMerge>.Instance) { IndividualAuditLimit = 3 };

        var result = await merge.MergeAsync(bench.CaId);

        Assert.Equal(missing, result.Merged);
        Assert.Equal(batch ? 0 : missing, bench.Audits(AuditActionType.RevocationMergedFromJournal).Count);
        Assert.Equal(batch ? 1 : 0, bench.Audits(AuditActionType.RevocationsMergedFromJournalBatch).Count);
        var summary = Assert.Single(bench.Audits(AuditActionType.JournalRevocationMergeCompleted)).Details;
        Assert.Equal((batch ? "batch" : "individual", batch ? 1 : 0, 3),
            (summary.GetProperty("AuditForm").GetString(), summary.GetProperty("BatchRecords").GetInt32(), summary.GetProperty("IndividualAuditLimit").GetInt32()));
    }

    /// <summary>An audit trail that stops the pass once the first batch has been saved and its first row written.</summary>
    private sealed class StopAtFirstAudit(CancellationTokenSource stop) : IAuditService
    {
        public Task LogAsync(string actionType, Guid? actorUserId, string? actorUsername, string? targetEntityType = null,
            string? targetEntityId = null, object? details = null, string? sourceIp = null, bool success = true,
            string? errorMessage = null, Guid? certificateAuthorityId = null, Guid? spaceId = null)
        {
            stop.Cancel();
            return Task.CompletedTask;
        }
    }
}
