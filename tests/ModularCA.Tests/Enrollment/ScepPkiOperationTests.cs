using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Core.Services.Enrollment;
using ModularCA.Core.Services.Scep;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enrollment;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Shared.Models.Issuance;
using ModularCA.Shared.Utils;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Xunit;

using CmsAttribute = Org.BouncyCastle.Asn1.Cms.Attribute;

namespace ModularCA.Tests.Enrollment;

/// <summary>
/// Drives <see cref="ScepService.PkiOperationAsync"/> with a real CMS PKIOperation, so what is
/// asserted is the bytes a SCEP client receives and not an account of them.
/// </summary>
/// <remarks>
/// <para>
/// This exists because of a mutation that survived: turning the PENDING answer into a failure
/// changed nothing any test could see, because nothing reached the rendering at all. The envelope
/// is the whole of SCEP's own work, and nothing that only calls the shared middle can cover it.
/// </para>
/// <para>
/// The exchange is built the way a device builds one: a PKCS#10 inside an EnvelopedData encrypted
/// to the CA's key, inside a SignedData carrying the SCEP attributes and signed by a self-signed
/// certificate, which is what RFC 8894 §2.3 has a first-time enrollee use.
/// </para>
/// </remarks>
public class ScepPkiOperationTests
{
    // SCEP attribute OIDs, as the responder and every client spell them.
    private static readonly DerObjectIdentifier IdTransactionId = new("2.16.840.1.113733.1.9.7");
    private static readonly DerObjectIdentifier IdMessageType = new("2.16.840.1.113733.1.9.2");
    private static readonly DerObjectIdentifier IdPkiStatus = new("2.16.840.1.113733.1.9.3");
    private static readonly DerObjectIdentifier IdFailInfo = new("2.16.840.1.113733.1.9.4");
    private static readonly DerObjectIdentifier IdSenderNonce = new("2.16.840.1.113733.1.9.5");

    /// <summary>Records SCEP audit rows; every other protocol's method is unexpected here.</summary>
    private sealed class RecordingAudit : IProtocolAuditService
    {
        public List<(string Operation, string? Subject, string? Serial, bool Success, string? Error)> Entries { get; } = [];

        public Task LogScepAsync(string operation, string? subjectDN, string? certSerial, string? keyAlgorithm, string? keySize,
            string? caLabel, string? transactionId, string? sourceIp, bool success = true, string? errorMessage = null,
            Guid? certificateAuthorityId = null, Guid? spaceId = null, string? callerPrincipal = null)
        {
            Entries.Add((operation, subjectDN, certSerial, success, errorMessage));
            return Task.CompletedTask;
        }

        public Task LogMsaeAsync(string operation, string? subjectDN, string? certSerial,
            string? keyAlgorithm, string? keySize, string? templateName, string? caLabel,
            string? sourceIp, bool success = true, string? errorMessage = null,
            Guid? certificateAuthorityId = null, Guid? spaceId = null, string? callerPrincipal = null,
            string? realm = null, string? authMethod = null)
            => throw new NotSupportedException();
        public Task LogEstAsync(string operation, string? subjectDN, string? certSerial, string? keyAlgorithm, string? keySize,
            string? caLabel, string? sourceIp, bool success = true, string? errorMessage = null,
            Guid? certificateAuthorityId = null, Guid? spaceId = null, string? callerPrincipal = null)
            => throw new NotSupportedException();
        public Task LogCmpAsync(string messageType, string? subjectDN, string? certSerial, string? keyAlgorithm, string? keySize,
            string? caLabel, string? transactionId, string? revocationReason, string? sourceIp, bool success = true,
            string? errorMessage = null, Guid? certificateAuthorityId = null, Guid? spaceId = null, string? callerPrincipal = null)
            => throw new NotSupportedException();
        public Task LogAcmeAsync(string operation, Guid? accountId, Guid? orderId, string? subjectDN, string? certSerial,
            string? identifiers, string? revocationReason, string? sourceIp, bool success = true, string? errorMessage = null,
            string? caLabel = null, Guid? certificateAuthorityId = null, Guid? spaceId = null,
            Guid? signingProfileId = null, Guid? certProfileId = null)
            => throw new NotSupportedException();
        public Task LogNetworkRequestAsync(string sourceIp, string requestPath, string httpMethod, int statusCode,
            long? responseTimeMs, string? protocol, string? caLabel, bool blocked, string? reason, string? userAgent,
            Guid? certificateAuthorityId = null, Guid? spaceId = null)
            => throw new NotSupportedException();
    }

    /// <summary>Answers the CA-membership question yes; SCEP never asks it.</summary>
    private sealed class AlwaysMember : IEnrollmentPrincipalAuthorizer
    {
        public Task<bool> MayEnrollAsync(string username, Guid caId) => Task.FromResult(true);
    }

    /// <summary>Issues a genuine leaf from the test CA and links it to the request row, as issuance does.</summary>
    private sealed class FakeIssuance(ModularCADbContext db, TestCaMaterial ca) : ICertificateIssuanceService
    {
        private int _serial = 100;

        public Task<IssuanceResult> IssueCertificateAsync(Guid csrId, DateTime? notBefore, DateTime? notAfter,
            ValidityCeilingEnforcement ceilingEnforcement = ValidityCeilingEnforcement.AlwaysShorten,
            CancellationToken cancellationToken = default)
        {
            var csr = db.CertificateRequests.Single(c => c.Id == csrId);
            var leaf = ca.Issue(BigInteger.ValueOf(++_serial), csr.Subject);
            var pem = CertificateUtil.ConvertDerToPem(leaf.GetEncoded(), "CERTIFICATE");
            var entity = new CertificateEntity
            {
                CertificateId = Guid.NewGuid(),
                SerialNumber = CertificateUtil.FormatSerialNumber(leaf.SerialNumber),
                Pem = pem,
                SubjectDN = csr.Subject,
                Issuer = ca.SubjectDn,
                NotBefore = leaf.NotBefore,
                NotAfter = leaf.NotAfter,
                SigningProfileId = csr.SigningProfileId,
                CertProfileId = csr.CertProfileId,
            };
            db.Certificates.Add(entity);
            csr.IssuedCertificateId = entity.CertificateId;
            csr.Status = "Issued";
            db.SaveChanges();
            return Task.FromResult(new IssuanceResult(pem));
        }

        public Task<IssuanceResult> IssueCertificateAsync(Guid csrId, DateTime? notBefore, DateTime? notAfter,
            X509Certificate caCertificate, ModularCA.Shared.Signing.KeyRef caKey,
            ModularCA.Shared.Signing.SigningContext caSigningContext, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
        public Task<IssuanceResult> IssueCaCertificateAsync(Guid csrId, DateTime? notBefore, DateTime? notAfter,
            CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
        public Task<IssuanceResult> ReissueCertificateAsync(Guid? certId, string? certSN, Guid? csrId,
            DateTime? notBefore, DateTime? notAfter, string? newSubjectDn = null, List<string>? newSans = null,
            ValidityCeilingEnforcement ceilingEnforcement = ValidityCeilingEnforcement.AlwaysShorten)
            => throw new NotSupportedException();
    }

    /// <summary>One responder, the CA it signs with, and the database behind both.</summary>
    private sealed class Harness
    {
        public required ModularCADbContext Db { get; init; }
        public required TestCaMaterial Ca { get; init; }
        public required ScepService Service { get; init; }
        public required RecordingAudit Audit { get; init; }

        /// <summary>The issuance an approver's click runs; the loop tests drive it directly.</summary>
        public required ICertificateIssuanceService Issuance { get; init; }

        /// <summary>
        /// Does what the console does when an operator approves a waiting request: marks the row
        /// approved and issues it, so the certificate exists exactly where a poll must find it.
        /// </summary>
        public async Task ApproveAndIssueAsync()
        {
            var request = Db.CertificateRequests.Single();
            request.Status = "Approved";
            await Db.SaveChangesAsync();
            await Issuance.IssueCertificateAsync(request.Id, null, null);
        }
    }

    /// <summary>
    /// A CA with SCEP enabled and no challenge password required, so the one thing these tests vary
    /// is the approval gate.
    /// </summary>
    /// <param name="requireApproval">Whether the request profile in force requires an approver.</param>
    private static Harness Build(bool requireApproval)
    {
        var databaseName = $"scep-{Guid.NewGuid():N}";
        var db = InMemoryDbContextFactory.Create(databaseName);
        var ca = TestCaMaterial.CreateCa("CN=Lab SCEP CA, O=ModularCA");

        var certificateId = Guid.NewGuid();
        var caId = Guid.NewGuid();
        var spaceId = Guid.NewGuid();

        db.Certificates.Add(new CertificateEntity
        {
            CertificateId = certificateId,
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
            Id = caId, Name = "lab", Label = "lab", IsDefault = true, IsEnabled = true,
            CertificateId = certificateId, SpaceId = spaceId,
        });

        var signing = new SigningProfileEntity { Id = Guid.NewGuid(), Name = "lab-signing", IssuerId = certificateId };
        var certProfile = new CertProfileEntity { Id = Guid.NewGuid(), Name = "Device", ValidityPeriodMax = "P30D" };
        var requestProfile = new RequestProfileEntity
        {
            Id = Guid.NewGuid(), Name = requireApproval ? "gated" : "open", RequireApproval = requireApproval,
        };
        db.SigningProfiles.Add(signing);
        db.CertProfiles.Add(certProfile);
        db.RequestProfiles.Add(requestProfile);
        db.CaProtocolConfigs.Add(new CaProtocolConfigEntity
        {
            Id = Guid.NewGuid(), CaId = caId, Protocol = "SCEP", IsEnabled = true,
            SigningProfileId = signing.Id, CertProfileId = certProfile.Id,
            RequestProfileId = requestProfile.Id,
            ScepChallengeRequired = false,
        });
        db.SaveChanges();

        var resolver = new CaResolverService(db);
        var profiles = new ProfileResolutionService(db, NullLogger<ProfileResolutionService>.Instance);
        var issuance = new FakeIssuance(db, ca);
        var pipeline = new EnrollmentPipeline(
            db, resolver,
            new EnrollmentAuthorizationService(db, new EnrollmentTokenServiceStub(), resolver,
                new AlwaysMember(), NullLogger<EnrollmentAuthorizationService>.Instance),
            new RequestProfileValidationService(db, profiles), profiles,
            issuance, new NoopNotificationService(),
            NullLogger<EnrollmentPipeline>.Instance);

        var keystore = new TestKeystore(ca.AsSigner());
        var audit = new RecordingAudit();
        return new Harness
        {
            Db = db,
            Ca = ca,
            Audit = audit,
            Issuance = issuance,
            Service = new ScepService(db, keystore, resolver, audit, pipeline,
                NullLogger<ScepService>.Instance, TestSigner.Over(keystore, databaseName)),
        };
    }

    private static AsymmetricCipherKeyPair Rsa()
    {
        var gen = new RsaKeyPairGenerator();
        gen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        return gen.GenerateKeyPair();
    }

    /// <summary>The self-signed certificate a first-time SCEP enrollee signs its PKCSReq with.</summary>
    private static X509Certificate SelfSigned(AsymmetricCipherKeyPair key, string subject)
    {
        var gen = new X509V3CertificateGenerator();
        gen.SetSerialNumber(BigInteger.ValueOf(7));
        gen.SetIssuerDN(new X509Name(subject));
        gen.SetSubjectDN(new X509Name(subject));
        gen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        gen.SetNotAfter(DateTime.UtcNow.AddDays(1));
        gen.SetPublicKey(key.Public);
        return gen.Generate(new Asn1SignatureFactory("SHA256WITHRSA", key.Private, new SecureRandom()));
    }

    /// <summary>
    /// Builds a SCEP message: the given content, enveloped to the CA where one is wanted, inside a
    /// SignedData carrying the SCEP attributes and signed by <paramref name="signerCert"/>.
    /// </summary>
    private static byte[] Message(
        TestCaMaterial ca, AsymmetricCipherKeyPair signerKey, X509Certificate signerCert,
        string messageType, string transactionId, byte[]? payload)
    {
        byte[] content;
        if (payload != null)
        {
            var env = new CmsEnvelopedDataGenerator();
            env.AddKeyTransRecipient(ca.Certificate);
            content = env.Generate(new CmsProcessableByteArray(payload), new DerObjectIdentifier(CmsEnvelopedGenerator.Aes256Cbc)).GetEncoded();
        }
        else
        {
            content = [];
        }

        var nonce = new byte[16];
        new SecureRandom().NextBytes(nonce);
        var attrs = new Asn1EncodableVector
        {
            new CmsAttribute(IdMessageType, new DerSet(new DerPrintableString(messageType))),
            new CmsAttribute(IdTransactionId, new DerSet(new DerPrintableString(transactionId))),
            new CmsAttribute(IdSenderNonce, new DerSet(new DerOctetString(nonce))),
        };

        var gen = new CmsSignedDataGenerator();
        gen.AddSigner(signerKey.Private, signerCert, CmsSignedDataGenerator.DigestSha256,
            new Org.BouncyCastle.Asn1.Cms.AttributeTable(attrs), null);
        gen.AddCertificates(Org.BouncyCastle.Utilities.Collections.CollectionUtilities.CreateStore(
            new List<X509Certificate> { signerCert }));
        return gen.Generate(new CmsProcessableByteArray(content), encapsulate: true).GetEncoded();
    }

    /// <summary>A PKCS#10 over a fresh key, as a device would send.</summary>
    private static byte[] Csr(AsymmetricCipherKeyPair key, string subject)
        => new Pkcs10CertificationRequest("SHA256WITHRSA", new X509Name(subject), key.Public, null, key.Private)
            .GetDerEncoded();

    /// <summary>The pkiStatus and failInfo a CertRep carries, and the certificates it encapsulates.</summary>
    private static (string? PkiStatus, string? FailInfo, List<X509Certificate> Certs) Read(byte[] response)
    {
        var signed = new CmsSignedData(response);
        var signer = signed.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
        var attrs = signer.SignedAttributes;

        string? Value(DerObjectIdentifier oid)
        {
            var attr = attrs?[oid];
            if (attr == null || attr.AttrValues.Count == 0) return null;
            return attr.AttrValues[0] is DerPrintableString ps ? ps.GetString() : attr.AttrValues[0].ToString();
        }

        var certs = new List<X509Certificate>();
        if (signed.SignedContent is CmsProcessableByteArray content)
        {
            using var ms = new MemoryStream();
            content.GetInputStream().CopyTo(ms);
            var bytes = ms.ToArray();
            if (bytes.Length > 0)
            {
                foreach (X509Certificate c in new CmsSignedData(bytes).GetCertificates().EnumerateMatches(null))
                    certs.Add(c);
            }
        }

        return (Value(IdPkiStatus), Value(IdFailInfo), certs);
    }

    /// <summary>
    /// The ordinary exchange: a PKCSReq is answered SUCCESS with the issued certificate inside a
    /// certs-only PKCS#7, and the issuance is on the SCEP tab.
    /// </summary>
    [Fact]
    public async Task A_pkcs_req_is_answered_with_the_issued_certificate()
    {
        var h = Build(requireApproval: false);
        var key = Rsa();
        var signerCert = SelfSigned(key, "CN=printer1.lab.test");

        var response = await h.Service.PkiOperationAsync(
            Message(h.Ca, key, signerCert, "19", "tx-issued", Csr(key, "CN=printer1.lab.test")),
            "lab", "10.0.0.5");

        var (status, failInfo, certs) = Read(response);
        Assert.Equal("0", status);
        Assert.Null(failInfo);
        Assert.Contains(certs, c => c.SubjectDN.ToString().Contains("printer1.lab.test"));
        Assert.Equal("Issued", Assert.Single(h.Db.ScepTransactions).Status);
        Assert.Contains(h.Audit.Entries, e => e.Operation == "PKCSReq" && e.Success && e.Serial != null);
    }

    /// <summary>
    /// A client checks the CertRep's signature before it trusts anything in it. The SignerInfo
    /// named the algorithm the CA certificate was signed with, as a bare OID, while the signer
    /// signed with RSASSA-PSS, so no client could verify a reply from an RSA CA. It names the
    /// algorithm the signer used, with its parameters.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task The_cert_rep_verifies_against_the_ca_certificate(bool fail)
    {
        var h = Build(requireApproval: false);
        var key = Rsa();
        var signerCert = SelfSigned(key, "CN=printer3.lab.test");
        var payload = fail ? [0x30, 0x00] : Csr(key, "CN=printer3.lab.test");

        var response = await h.Service.PkiOperationAsync(
            Message(h.Ca, key, signerCert, "19", $"tx-verify-{fail}", payload), "lab", "10.0.0.5");

        var signer = new CmsSignedData(response).GetSignerInfos().GetSigners().Cast<SignerInformation>().Single();
        var algorithm = signer.SignerInfo.SignatureAlgorithm;
        if (algorithm.Algorithm.Equals(PkcsObjectIdentifiers.IdRsassaPss))
            Assert.IsType<RsassaPssParameters>(RsassaPssParameters.GetInstance(algorithm.Parameters));
        Assert.True(signer.Verify(h.Ca.Certificate));
        Assert.Equal(fail ? "2" : "0", Read(response).PkiStatus);
    }

    /// <summary>
    /// The gate SCEP never read, rendered. A request profile that requires an approver is answered
    /// PENDING — pkiStatus 3, the status this responder declared a constant for and never sent —
    /// and no certificate comes back.
    /// </summary>
    [Fact]
    public async Task An_approval_gated_pkcs_req_is_answered_pending()
    {
        var h = Build(requireApproval: true);
        var key = Rsa();
        var signerCert = SelfSigned(key, "CN=printer2.lab.test");

        var response = await h.Service.PkiOperationAsync(
            Message(h.Ca, key, signerCert, "19", "tx-pending", Csr(key, "CN=printer2.lab.test")),
            "lab", "10.0.0.5");

        var (status, failInfo, certs) = Read(response);
        Assert.Equal("3", status);
        Assert.Null(failInfo);
        Assert.Empty(certs);
        Assert.Equal("PendingApproval", Assert.Single(h.Db.ScepTransactions).Status);
        Assert.Equal("PendingApproval", Assert.Single(h.Db.CertificateRequests).Status);
        Assert.Contains(h.Audit.Entries, e => e.Operation == "PKCSReqPending");
    }

    /// <summary>
    /// The client comes back for it. GetCertInitial answers PENDING again rather than badCertId:
    /// nothing has gone wrong and the request is still with an approver.
    /// </summary>
    [Fact]
    public async Task Get_cert_initial_answers_pending_while_an_approver_owns_the_request()
    {
        var h = Build(requireApproval: true);
        var key = Rsa();
        var signerCert = SelfSigned(key, "CN=printer3.lab.test");

        await h.Service.PkiOperationAsync(
            Message(h.Ca, key, signerCert, "19", "tx-poll", Csr(key, "CN=printer3.lab.test")),
            "lab", "10.0.0.5");

        var polled = await h.Service.PkiOperationAsync(
            Message(h.Ca, key, signerCert, "20", "tx-poll", null), "lab", "10.0.0.5");

        var (status, failInfo, certs) = Read(polled);
        Assert.Equal("3", status);
        Assert.Null(failInfo);
        Assert.Empty(certs);
    }

    /// <summary>
    /// A transaction id nobody has used is still badCertId, so the PENDING answer above is the
    /// approval state and not GetCertInitial having stopped refusing.
    /// </summary>
    [Fact]
    public async Task Get_cert_initial_for_an_unknown_transaction_is_still_bad_cert_id()
    {
        var h = Build(requireApproval: true);
        var key = Rsa();
        var signerCert = SelfSigned(key, "CN=printer4.lab.test");

        var polled = await h.Service.PkiOperationAsync(
            Message(h.Ca, key, signerCert, "20", "tx-never-seen", null), "lab", "10.0.0.5");

        var (status, failInfo, _) = Read(polled);
        Assert.Equal("2", status);
        Assert.Equal("4", failInfo);
    }

    /// <summary>
    /// The whole loop, which is the point of the transaction's link to its request row: a gated
    /// PKCSReq answered PENDING, an operator approving it, and the next poll returning the
    /// certificate — with the transaction completed as an immediate enrollment completes one, so a
    /// second poll is answered from the row and returns the same certificate again.
    /// </summary>
    [Fact]
    public async Task An_approved_request_is_collected_by_the_next_poll()
    {
        var h = Build(requireApproval: true);
        var key = Rsa();
        var signerCert = SelfSigned(key, "CN=printer5.lab.test");

        var enrolled = await h.Service.PkiOperationAsync(
            Message(h.Ca, key, signerCert, "19", "tx-loop", Csr(key, "CN=printer5.lab.test")),
            "lab", "10.0.0.5");
        Assert.Equal("3", Read(enrolled).PkiStatus);

        // The link written when the request was taken under submission: without it the approval
        // below is invisible to every poll that follows.
        var request = Assert.Single(h.Db.CertificateRequests);
        Assert.Equal(request.Id, Assert.Single(h.Db.ScepTransactions).CertRequestId);

        await h.ApproveAndIssueAsync();

        var collected = await h.Service.PkiOperationAsync(
            Message(h.Ca, key, signerCert, "20", "tx-loop", null), "lab", "10.0.0.5");

        var (status, failInfo, certs) = Read(collected);
        Assert.Equal("0", status);
        Assert.Null(failInfo);
        Assert.Contains(certs, c => c.SubjectDN.ToString().Contains("printer5.lab.test"));

        var tx = Assert.Single(h.Db.ScepTransactions);
        Assert.Equal("Issued", tx.Status);
        Assert.Equal(request.IssuedCertificateId, tx.IssuedCertificateId);

        // Again, because a client that missed the first answer re-sends the same message.
        var again = Read(await h.Service.PkiOperationAsync(
            Message(h.Ca, key, signerCert, "20", "tx-loop", null), "lab", "10.0.0.5"));
        Assert.Equal("0", again.PkiStatus);
        Assert.Contains(again.Certs, c => c.SubjectDN.ToString().Contains("printer5.lab.test"));
    }

    /// <summary>
    /// The ownership proof, on the path the approval opened. A stranger who knows the transaction
    /// id is refused while the request waits — so the approval state itself does not leak — and
    /// refused again once the certificate exists, which is the certificate it must not collect.
    /// </summary>
    [Fact]
    public async Task A_poll_signed_by_another_key_collects_nothing()
    {
        var h = Build(requireApproval: true);
        var key = Rsa();
        var signerCert = SelfSigned(key, "CN=printer6.lab.test");
        var strangerKey = Rsa();
        var strangerCert = SelfSigned(strangerKey, "CN=printer6.lab.test");

        await h.Service.PkiOperationAsync(
            Message(h.Ca, key, signerCert, "19", "tx-stranger", Csr(key, "CN=printer6.lab.test")),
            "lab", "10.0.0.5");

        var whilePending = Read(await h.Service.PkiOperationAsync(
            Message(h.Ca, strangerKey, strangerCert, "20", "tx-stranger", null), "lab", "10.9.9.9"));
        Assert.Equal("2", whilePending.PkiStatus);
        Assert.Equal("4", whilePending.FailInfo);
        Assert.Empty(whilePending.Certs);

        await h.ApproveAndIssueAsync();

        var afterIssue = Read(await h.Service.PkiOperationAsync(
            Message(h.Ca, strangerKey, strangerCert, "20", "tx-stranger", null), "lab", "10.9.9.9"));
        Assert.Equal("2", afterIssue.PkiStatus);
        Assert.Equal("4", afterIssue.FailInfo);
        Assert.Empty(afterIssue.Certs);

        // And the legitimate client still collects it, so the refusal above is the key and not the
        // transaction having been spoiled.
        var owner = Read(await h.Service.PkiOperationAsync(
            Message(h.Ca, key, signerCert, "20", "tx-stranger", null), "lab", "10.0.0.5"));
        Assert.Equal("0", owner.PkiStatus);
    }

    /// <summary>
    /// An operator refused it. The poll answers FAILURE with badRequest — the failInfo a refused
    /// PKCSReq already carries — rather than leaving the client polling PENDING forever, and it
    /// says the same thing every time it is asked.
    /// </summary>
    [Fact]
    public async Task A_poll_for_a_rejected_request_is_a_refusal()
    {
        var h = Build(requireApproval: true);
        var key = Rsa();
        var signerCert = SelfSigned(key, "CN=printer7.lab.test");

        await h.Service.PkiOperationAsync(
            Message(h.Ca, key, signerCert, "19", "tx-rejected", Csr(key, "CN=printer7.lab.test")),
            "lab", "10.0.0.5");

        var request = Assert.Single(h.Db.CertificateRequests);
        request.Status = "Rejected";
        request.RejectionReason = "Not a device we enroll.";
        await h.Db.SaveChangesAsync();

        var refused = Read(await h.Service.PkiOperationAsync(
            Message(h.Ca, key, signerCert, "20", "tx-rejected", null), "lab", "10.0.0.5"));
        Assert.Equal("2", refused.PkiStatus);
        Assert.Equal("2", refused.FailInfo);
        Assert.Empty(refused.Certs);

        var again = Read(await h.Service.PkiOperationAsync(
            Message(h.Ca, key, signerCert, "20", "tx-rejected", null), "lab", "10.0.0.5"));
        Assert.Equal("2", again.PkiStatus);
        Assert.Equal("2", again.FailInfo);
    }

    /// <summary>
    /// The seven days ran out with nobody having approved it. The transaction is over: the poll is
    /// badCertId, which tells the client to start a new enrollment, and the row is the sweep's.
    /// </summary>
    [Fact]
    public async Task A_poll_for_an_expired_pending_transaction_is_bad_cert_id()
    {
        var h = Build(requireApproval: true);
        var key = Rsa();
        var signerCert = SelfSigned(key, "CN=printer8.lab.test");

        await h.Service.PkiOperationAsync(
            Message(h.Ca, key, signerCert, "19", "tx-expired", Csr(key, "CN=printer8.lab.test")),
            "lab", "10.0.0.5");

        var tx = Assert.Single(h.Db.ScepTransactions);
        Assert.True(tx.ExpiresAt > DateTime.UtcNow.AddDays(6), "a pending transaction is kept for an approver's timescale");
        tx.ExpiresAt = DateTime.UtcNow.AddMinutes(-1);
        await h.Db.SaveChangesAsync();

        var expired = Read(await h.Service.PkiOperationAsync(
            Message(h.Ca, key, signerCert, "20", "tx-expired", null), "lab", "10.0.0.5"));
        Assert.Equal("2", expired.PkiStatus);
        Assert.Equal("4", expired.FailInfo);
    }

    /// <summary>
    /// Gives the CA an elliptic-curve certificate, as a CA whose SCEP configuration was enabled
    /// before enabling SCEP on a non-RSA CA was refused.
    /// </summary>
    private static void MakeCaElliptic(Harness h)
    {
        using var key = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=Lab EC CA", key, System.Security.Cryptography.HashAlgorithmName.SHA256);
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var row = h.Db.Certificates.Single(c => c.IsCA);
        row.Pem = cert.ExportCertificatePem();
        row.RawCertificate = cert.RawData;
        h.Db.SaveChanges();
    }

    /// <summary>
    /// SCEP on a CA whose key is not RSA cannot work: no client can envelope its request to the CA.
    /// A configuration enabled before that was refused still resolves, so PKIOperation refuses
    /// with the reason before reading the message, and the SCEP tab says why, rather than the
    /// request failing in decryption with nothing recorded.
    /// </summary>
    [Fact]
    public async Task A_pki_operation_at_a_non_rsa_ca_is_refused_with_the_reason_and_audited()
    {
        var h = Build(requireApproval: false);
        var key = Rsa();
        var message = Message(h.Ca, key, SelfSigned(key, "CN=printer9.lab.test"), "19", "tx-ec", Csr(key, "CN=printer9.lab.test"));
        MakeCaElliptic(h);

        var refusal = await Assert.ThrowsAsync<ProtocolIncompatibleException>(
            () => h.Service.PkiOperationAsync(message, "lab", "10.0.0.5"));

        Assert.Equal(ProtocolCompatibility.ScepRequiresRsaKey, refusal.Advisory.Reason);
        Assert.Contains("ECDSA", refusal.Message);
        var entry = Assert.Single(h.Audit.Entries);
        Assert.Equal("PKIOperation", entry.Operation);
        Assert.False(entry.Success);
        Assert.Equal(refusal.Message, entry.Error);
        Assert.Empty(h.Db.CertificateRequests);
        Assert.Empty(h.Db.ScepTransactions);
    }

    /// <summary>
    /// GetCACert, the first thing every SCEP client asks, is refused the same way, so the client is
    /// told why before it tries to build a request it cannot build.
    /// </summary>
    [Fact]
    public async Task Get_ca_cert_at_a_non_rsa_ca_is_refused_with_the_reason_and_audited()
    {
        var h = Build(requireApproval: false);
        MakeCaElliptic(h);

        var refusal = await Assert.ThrowsAsync<ProtocolIncompatibleException>(() => h.Service.GetCaCertAsync("lab", "10.0.0.5"));

        Assert.Equal(ProtocolCompatibility.ScepRequiresRsaKey, refusal.Advisory.Reason);
        var entry = Assert.Single(h.Audit.Entries);
        Assert.Equal("GetCACert", entry.Operation);
        Assert.False(entry.Success);
        Assert.Equal(refusal.Message, entry.Error);
    }

    /// <summary>An RSA CA is answered as before, and nothing is audited for GetCACert.</summary>
    [Fact]
    public async Task Get_ca_cert_at_an_rsa_ca_is_answered()
    {
        var h = Build(requireApproval: false);

        var (data, isPkcs7) = await h.Service.GetCaCertAsync("lab", "10.0.0.5");

        Assert.False(isPkcs7);
        Assert.Equal(h.Ca.Certificate.GetEncoded(), data);
        Assert.Empty(h.Audit.Entries);
    }

    /// <summary>
    /// A PKIOperation the responder cannot read or authenticate is answered with its failInfo and
    /// now leaves an unsuccessful PKIOperation row on the SCEP tab; it was recorded nowhere.
    /// </summary>
    [Fact]
    public async Task A_message_that_is_not_cms_is_answered_bad_message_check_and_audited()
    {
        var h = Build(requireApproval: false);

        var (status, failInfo, _) = Read(await h.Service.PkiOperationAsync([0x30, 0x03, 0x02, 0x01, 0x00], "lab", "10.0.0.5"));

        Assert.Equal("2", status);
        Assert.Equal("1", failInfo);
        var entry = Assert.Single(h.Audit.Entries);
        Assert.Equal("PKIOperation", entry.Operation);
        Assert.False(entry.Success);
        Assert.Contains("not a CMS SignedData", entry.Error);
    }

    [Fact]
    public async Task A_message_whose_signature_does_not_verify_is_answered_bad_message_check_and_audited()
    {
        var h = Build(requireApproval: false);
        var key = Rsa();
        // Signed with one key, carrying the certificate of another.
        var message = Message(h.Ca, key, SelfSigned(Rsa(), "CN=printer8.lab.test"), "19", "tx-badsig", Csr(key, "CN=printer8.lab.test"));

        var (status, failInfo, _) = Read(await h.Service.PkiOperationAsync(message, "lab", "10.0.0.5"));

        Assert.Equal("2", status);
        Assert.Equal("1", failInfo);
        Assert.Contains("CMS signature", Assert.Single(h.Audit.Entries).Error);
        Assert.Empty(h.Db.CertificateRequests);
    }

    [Fact]
    public async Task A_request_enveloped_to_another_key_is_answered_bad_request_and_audited()
    {
        var h = Build(requireApproval: false);
        var key = Rsa();
        var elsewhere = TestCaMaterial.CreateCa("CN=Some Other CA, O=Elsewhere");
        var message = Message(elsewhere, key, SelfSigned(key, "CN=printer7.lab.test"), "19", "tx-envelope", Csr(key, "CN=printer7.lab.test"));

        var (status, failInfo, _) = Read(await h.Service.PkiOperationAsync(message, "lab", "10.0.0.5"));

        Assert.Equal("2", status);
        Assert.Equal("2", failInfo);
        var entry = Assert.Single(h.Audit.Entries);
        Assert.Equal("PKIOperation", entry.Operation);
        Assert.Contains("envelope could not be opened", entry.Error);
    }

    /// <summary>
    /// A configuration fault the shared middle reports (here the certificate profile the SCEP
    /// configuration names is gone) is answered badRequest under the request's transactionID and
    /// leaves exactly one SCEP row. It left none: the row was skipped as already written.
    /// </summary>
    [Fact]
    public async Task A_configuration_fault_is_answered_bad_request_and_audited_once()
    {
        var h = Build(requireApproval: false);
        h.Db.CaProtocolConfigs.Single().CertProfileId = Guid.NewGuid();
        await h.Db.SaveChangesAsync();
        var key = Rsa();

        var response = await h.Service.PkiOperationAsync(
            Message(h.Ca, key, SelfSigned(key, "CN=printer10.lab.test"), "19", "tx-noprofile", Csr(key, "CN=printer10.lab.test")),
            "lab", "10.0.0.5");

        var (status, failInfo, certs) = Read(response);
        Assert.Equal("2", status);
        Assert.Equal("2", failInfo);
        Assert.Empty(certs);
        var signer = new CmsSignedData(response).GetSignerInfos().GetSigners().Cast<SignerInformation>().Single();
        Assert.Equal("tx-noprofile", ((DerPrintableString)signer.SignedAttributes[IdTransactionId].AttrValues[0]).GetString());
        var entry = Assert.Single(h.Audit.Entries);
        Assert.Equal("PKCSReq", entry.Operation);
        Assert.False(entry.Success);
        Assert.Equal("Configured SCEP certificate profile not found.", entry.Error);
        Assert.Empty(h.Db.CertificateRequests);
    }

    // The replay refusal is not tested here. It is the unique index on
    // (CaId, TransactionId) that detects a replayed PKCSReq, and EF Core's in-memory provider
    // does not enforce unique indexes, so a second identical request is simply inserted and
    // nothing is refused. Covering it needs the MySQL integration project.
}
