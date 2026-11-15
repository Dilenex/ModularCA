using Xunit;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services.Journal;
using ModularCA.Journal;
using ModularCA.Keystore.Signing;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Signing;
using ModularCA.Shared.Utils;
using ModularCA.Tests.Core.Services;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace ModularCA.Tests.Journal;

/// <summary>
/// Issuance, through the real CA creation and issuance services, with the signer's journal
/// behind the signer: every certificate the instance comes to hold has a record whose
/// to-be-signed bytes and signature rebuild it byte for byte, and the record carries what the
/// node knew of the request.
/// </summary>
public class JournalIssuancePathTests
{
    private sealed class Bench : IAsyncDisposable
    {
        public JournalSandbox Sandbox { get; } = new();
        public SignerJournal Journal { get; }
        public NameConstraintIssuanceTests.IssuanceWorld World { get; }

        public Bench()
        {
            Journal = new SignerJournal(() => Sandbox.Options(), new SignerJournalSettings(Sandbox.Home, true, "0.0.0-test", new byte[32]), NullLogger.Instance);
            World = new NameConstraintIssuanceTests.IssuanceWorld(Journal);
        }

        public List<CertificatePayload> Certificates()
            => Sandbox.Records().Where(r => r.Record.Type == RecordType.Certificate).Select(r => CertificatePayload.Decode(r.Record.Payload)).ToList();

        public CertificatePayload RecordOf(CertificateEntity row)
            => Certificates().Single(p => new Org.BouncyCastle.Math.BigInteger(1, p.Serial).Equals(new Org.BouncyCastle.Math.BigInteger(row.SerialNumber, 16)));

        public async ValueTask DisposeAsync()
        {
            await Journal.DisposeAsync();
            Sandbox.Dispose();
        }
    }

    private static byte[] Rebuild(CertificatePayload payload)
    {
        var tbs = TbsCertificateStructure.GetInstance(Asn1Object.FromByteArray(payload.Tbs));
        return new DerSequence(tbs, tbs.Signature, new DerBitString(payload.Signature)).GetDerEncoded();
    }

    private static byte[] KeyOf(CertificateEntity caRow)
        => SHA256.HashData(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(new X509Certificate(caRow.RawCertificate).GetPublicKey()).GetDerEncoded());

    /// <summary>A stored, approved request under the CA's signing profile, not yet issued.</summary>
    private static CertRequestEntity Request(NameConstraintIssuanceTests.IssuanceWorld w, CertificateAuthorityEntity ca, string subject, Action<CertRequestEntity>? change = null)
    {
        var keys = KeyAlgorithmPolicy.GenerateKeyPair("ECDSA", "P-256");
        var csr = new Pkcs10CertificationRequest(new Asn1SignatureFactory("SHA256WITHECDSA", keys.Private, new SecureRandom()), new X509Name(subject), keys.Public, null);
        using var pem = new StringWriter();
        new PemWriter(pem).WriteObject(csr);
        var request = new CertRequestEntity
        {
            Id = Guid.NewGuid(), CSR = pem.ToString(), Subject = subject, SubjectAlternativeNames = "[]", Status = "Approved",
            KeyAlgorithm = "ECDSA", KeySize = "P-256", SignatureAlgorithm = "SHA256withECDSA",
            CertProfileId = w.LeafProfileId, SigningProfileId = w.Db.SigningProfiles.Single(p => p.IssuerId == ca.CertificateId).Id,
        };
        change?.Invoke(request);
        w.Db.CertificateRequests.Add(request);
        w.Db.SaveChanges();
        return request;
    }

    private static async Task<CertificateEntity> IssueAsync(NameConstraintIssuanceTests.IssuanceWorld w, CertRequestEntity request)
    {
        await w.Issuance.IssueCertificateAsync(request.Id, null, DateTime.UtcNow.AddDays(30));
        var issuedId = w.Db.CertificateRequests.Where(r => r.Id == request.Id).Select(r => r.IssuedCertificateId).Single();
        return w.Db.Certificates.Single(c => c.CertificateId == issuedId);
    }

    [Fact]
    public async Task Every_certificate_made_while_a_ca_is_created_has_a_record_that_rebuilds_it()
    {
        await using var bench = new Bench();
        var w = bench.World;
        var seeded = w.Db.Certificates.Select(c => c.CertificateId).ToHashSet();

        var root = await w.CreateRootAsync("Journal Root", null, null);
        var intermediate = await w.CreateIntermediateAsync(root, "Journal Issuing", null, null);

        // The two CA certificates and every delegated signer certificate made beside them.
        var rows = w.Db.Certificates.AsEnumerable().Where(c => !seeded.Contains(c.CertificateId)).ToList();
        Assert.True(rows.Count >= 4, $"expected CA and delegated certificates, found {rows.Count}");
        var records = bench.Certificates();
        var unstored = records.Where(p => !rows.Any(r => new Org.BouncyCastle.Math.BigInteger(r.SerialNumber, 16).Equals(new Org.BouncyCastle.Math.BigInteger(1, p.Serial))))
            .Select(p => TbsCertificateStructure.GetInstance(Asn1Object.FromByteArray(p.Tbs)).Subject.ToString()).ToList();
        Assert.True(rows.Count == records.Count, $"{rows.Count} rows, {records.Count} records; recorded and not stored: {string.Join(" | ", unstored)}");
        foreach (var row in rows)
            Assert.Equal(row.RawCertificate, Rebuild(bench.RecordOf(row)));

        var rootRow = rows.Single(r => r.CertificateId == root.CertificateId);
        var rootRecord = bench.RecordOf(rootRow);
        Assert.True(rootRecord.IsCa);
        // A root signs itself: the key that signed is its own, and no CA certificate existed yet.
        Assert.Equal(KeyOf(rootRow), rootRecord.CaKey);
        Assert.Equal(rootRecord.SubjectKey, rootRecord.CaKey);
        Assert.Null(rootRecord.CaCert);
        Assert.Equal("CaCreation", rootRecord.Context!.Protocol);
        Assert.Equal(w.SpaceId.ToString("D"), rootRecord.Belongs!.Space);

        var intermediateRow = rows.Single(r => r.CertificateId == intermediate.CertificateId);
        var intermediateRecord = bench.RecordOf(intermediateRow);
        Assert.True(intermediateRecord.IsCa);
        Assert.Equal(KeyOf(rootRow), intermediateRecord.CaKey);
        Assert.Equal(SHA256.HashData(rootRow.RawCertificate!), intermediateRecord.CaCert);
        Assert.Equal(root.Id.ToString("D"), intermediateRecord.Ca);

        // The delegated signers of the root: infrastructure certificates, signed with the root's key.
        var delegated = rows.Where(r => !r.IsCA && r.IssuerCertificateId == root.CertificateId).ToList();
        Assert.NotEmpty(delegated);
        Assert.All(delegated, row =>
        {
            var record = bench.RecordOf(row);
            Assert.False(record.IsCa);
            Assert.Equal(KeyOf(rootRow), record.CaKey);
            Assert.Equal("Infrastructure", record.Context!.Protocol);
            Assert.Equal(AnswersKind.PendingRequest, record.Answers!.Kind);
        });
        Assert.Null(bench.Sandbox.Verify().Fault);
    }

    [Fact]
    public async Task A_certificate_issued_from_a_request_names_the_request_the_profile_the_space_and_the_requester()
    {
        await using var bench = new Bench();
        var w = bench.World;
        var root = await w.CreateRootAsync("Journal Root", null, null);
        var ca = await w.CreateIntermediateAsync(root, "Journal Issuing", null, null);
        var user = new UserEntity { Id = Guid.NewGuid(), Username = "alice", Email = "alice@example.test", PasswordHash = "x" };
        w.Db.Users.Add(user);
        var request = Request(w, ca, "CN=request leaf", r => r.RequestorUserId = user.Id);

        var issued = await IssueAsync(w, request);

        var record = bench.RecordOf(issued);
        Assert.Equal(issued.RawCertificate, Rebuild(record));
        Assert.Equal(new Answers(AnswersKind.PendingRequest, request.Id.ToString("D")), record.Answers);
        Assert.Equal(new Belongs(w.LeafProfileId.ToString("D"), w.SpaceId.ToString("D"), OwnerKind.User, user.Id.ToString("D")), record.Belongs);
        Assert.Equal(new SigningContextInfo("Certificate", null, user.Id.ToString("D")), record.Context);
        Assert.Null(record.Spent);
        Assert.Null(record.Replaces);
        Assert.Equal(ca.Id.ToString("D"), record.Ca);
    }

    [Fact]
    public async Task A_renewal_names_the_certificate_it_replaces()
    {
        await using var bench = new Bench();
        var w = bench.World;
        var root = await w.CreateRootAsync("Journal Root", null, null);
        var ca = await w.CreateIntermediateAsync(root, "Journal Issuing", null, null);
        var first = await IssueAsync(w, Request(w, ca, "CN=renewed leaf"));

        var second = await IssueAsync(w, Request(w, ca, "CN=renewed leaf", r => r.RenewalOfCertificateId = first.CertificateId));

        var replaces = bench.RecordOf(second).Replaces!;
        Assert.Equal(new Org.BouncyCastle.Math.BigInteger(first.SerialNumber, 16).ToByteArrayUnsigned(), replaces.Serial);
        Assert.Equal(KeyOf(w.Db.Certificates.Single(c => c.CertificateId == ca.CertificateId)), replaces.CaKey);
        Assert.Null(bench.RecordOf(first).Replaces);
    }

    [Fact]
    public async Task What_a_protocol_and_a_spent_token_left_on_the_request_reach_the_record_once()
    {
        await using var bench = new Bench();
        var w = bench.World;
        var root = await w.CreateRootAsync("Journal Root", null, null);
        var ca = await w.CreateIntermediateAsync(root, "Journal Issuing", null, null);
        var request = Request(w, ca, "CN=acme leaf");
        var tokenId = Guid.NewGuid().ToString("D");
        // As the enrollment pipeline and the token service leave them, on the request's own context.
        IssuanceNotes.NoteRequest(w.Db, request.Id, "ACME", IssuanceNotes.AnswersFor("ACME", "order-17"), template: "template-3");
        IssuanceNotes.NoteSpent(w.Db, TokenKind.EnrollmentToken, tokenId, use: 2);

        var issued = await IssueAsync(w, request);
        var next = await IssueAsync(w, Request(w, ca, "CN=next leaf"));

        var record = bench.RecordOf(issued);
        Assert.Equal(new Answers(AnswersKind.AcmeOrder, "order-17"), record.Answers);
        Assert.Equal("ACME", record.Context!.Protocol);
        Assert.Equal("template-3", record.Belongs!.Template);
        Assert.Equal(new SpentToken(TokenKind.EnrollmentToken, tokenId, 2), Assert.Single(record.Spent!));
        // Nothing of it clings to the next issuance on the same context.
        var after = bench.RecordOf(next);
        Assert.Null(after.Spent);
        Assert.Equal(AnswersKind.PendingRequest, after.Answers!.Kind);
        Assert.Null(after.Context!.Protocol);
    }

    [Theory]
    [InlineData("ACME", "order-1", AnswersKind.AcmeOrder)]
    [InlineData("acme", "order-1", AnswersKind.AcmeOrder)]
    [InlineData("SCEP", "txn-1", AnswersKind.EnrollmentTransaction)]
    [InlineData("CMP", "aabbcc", AnswersKind.EnrollmentTransaction)]
    public void A_protocols_own_identifier_is_what_its_issuance_answers(string protocol, string correlation, ulong kind)
    {
        Assert.Equal(new IssuanceAnswers(kind, correlation), IssuanceNotes.AnswersFor(protocol, correlation));
    }

    [Theory]
    [InlineData("EST", "anything")]
    [InlineData("MSAE", "anything")]
    [InlineData("ACME", null)]
    [InlineData("SCEP", "")]
    public void A_protocol_with_no_transaction_identifier_answers_the_request_row(string protocol, string? correlation)
    {
        Assert.Null(IssuanceNotes.AnswersFor(protocol, correlation));
    }

    [Fact]
    public async Task With_the_journal_unable_to_take_a_record_no_certificate_is_issued_or_stored()
    {
        var sandbox = new JournalSandbox();
        var files = new RecordingJournalFiles();
        await using var journal = new SignerJournal(() => sandbox.Options(files), new SignerJournalSettings(sandbox.Home, true, "t", new byte[32]), NullLogger.Instance);
        var w = new NameConstraintIssuanceTests.IssuanceWorld(journal);
        var root = await w.CreateRootAsync("Journal Root", null, null);
        var ca = await w.CreateIntermediateAsync(root, "Journal Issuing", null, null);
        var before = w.Db.Certificates.Count();
        var request = Request(w, ca, "CN=unrecorded leaf");

        files.FailFlush = _ => new IOException("There is not enough space on the disk.");
        var refused = await Assert.ThrowsAnyAsync<Exception>(() => w.Issuance.IssueCertificateAsync(request.Id, null, DateTime.UtcNow.AddDays(30)));

        Assert.Contains(Chain(refused), e => e is SigningRefusedException { Reason: SigningRefusalReason.JournalUnavailable });
        Assert.Equal(before, w.Db.Certificates.Count());
        Assert.Null(w.Db.CertificateRequests.AsEnumerable().Single(r => r.Id == request.Id).IssuedCertificateId);
        files.FailFlush = null;
        sandbox.Dispose();

        static IEnumerable<Exception> Chain(Exception e)
        {
            for (Exception? x = e; x != null; x = x.InnerException)
                yield return x;
        }
    }
}
