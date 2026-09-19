using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
using Xunit;

namespace ModularCA.Tests.Enrollment;

/// <summary>
/// Pins what SCEP hands the shared middle and what it does with the answer: which credential is
/// asking, the approval gate it never read, and the key-algorithm rule that is the one refusal it
/// renders as something other than <c>badRequest</c>.
/// </summary>
/// <remarks>
/// <para>
/// SCEP's enrollment path had no test at all before this file. That is how a key-algorithm check
/// that split a JSON array on commas — and so refused every request that reached it — survived,
/// and how a protocol with a PENDING status in its wire format came to issue approval-gated
/// requests with no approver.
/// </para>
/// <para>
/// The submission is built by <see cref="ScepService.BuildSubmission"/> and run through the real
/// <see cref="EnrollmentPipeline"/> over the real <see cref="EnrollmentAuthorizationService"/>, so
/// what these tests assert is the sequence a live PKCSReq runs and not a stub's account of it. The
/// CMS envelopes on either side are SCEP's own and are not what this file is about.
/// </para>
/// </remarks>
public class ScepEnrollmentTests
{
    /// <summary>Answers the CA-membership question with a fixed verdict.</summary>
    private sealed class FixedAuthorizer(bool verdict) : IEnrollmentPrincipalAuthorizer
    {
        public Task<bool> MayEnrollAsync(string username, Guid caId) => Task.FromResult(verdict);
    }

    /// <summary>Issues a real leaf from the test CA and links it to the request row, as issuance does.</summary>
    private sealed class FakeIssuance(ModularCADbContext db, X509Certificate2 caCert) : ICertificateIssuanceService
    {
        public Task<IssuanceResult> IssueCertificateAsync(Guid csrId, DateTime? notBefore, DateTime? notAfter,
            ValidityCeilingEnforcement ceilingEnforcement = ValidityCeilingEnforcement.AlwaysShorten,
            CancellationToken cancellationToken = default)
        {
            var csr = db.CertificateRequests.Single(c => c.Id == csrId);
            using var leaf = TestCertificates.IssueLeaf(caCert, csr.Subject);
            var pem = leaf.ExportCertificatePem();
            var entity = new CertificateEntity
            {
                CertificateId = Guid.NewGuid(),
                SerialNumber = leaf.SerialNumber,
                Pem = pem,
                SubjectDN = csr.Subject,
                Issuer = caCert.Subject,
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
            Org.BouncyCastle.X509.X509Certificate caCertificate, ModularCA.Shared.Signing.KeyRef caKey,
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

    /// <summary>Everything one SCEP exchange needs, assembled over an in-memory database.</summary>
    private sealed class Harness
    {
        public required ModularCADbContext Db { get; init; }
        public required CertificateAuthorityEntity Ca { get; init; }
        public required ResolvedCaContext Context { get; init; }
        public required EnrollmentPipeline Pipeline { get; init; }
        public required CertificateEntity CaCertRow { get; init; }
        public List<EnrollmentAuditRecord> Audit { get; } = [];
    }

    /// <summary>
    /// A CA with SCEP enabled and its challenge password required, which is the configuration where
    /// the only thing that decides authorization is which credential is asking.
    /// </summary>
    /// <param name="scepEnabled">Whether SCEP is switched on for this CA.</param>
    /// <param name="requestProfile">The request profile in force, or null for none.</param>
    private static Harness Build(
        bool scepEnabled = true,
        RequestProfileEntity? requestProfile = null)
    {
        var db = InMemoryDbContextFactory.Create();
        var caCert = TestCertificates.CreateCa("CN=Lab Issuing CA, O=ModularCA");

        var caCertEntity = new CertificateEntity
        {
            CertificateId = Guid.NewGuid(), SerialNumber = caCert.SerialNumber, Pem = caCert.ExportCertificatePem(),
            SubjectDN = caCert.Subject, Issuer = caCert.Issuer, IsCA = true,
            NotBefore = caCert.NotBefore, NotAfter = caCert.NotAfter,
        };
        var ca = new CertificateAuthorityEntity
        {
            Id = Guid.NewGuid(), Name = "lab", Label = "lab", IsDefault = true, IsEnabled = true,
            CertificateId = caCertEntity.CertificateId, TenantId = Guid.NewGuid(),
        };
        var signing = new SigningProfileEntity { Id = Guid.NewGuid(), Name = "lab-signing", IssuerId = caCertEntity.CertificateId };
        var certProfile = new CertProfileEntity
        {
            Id = Guid.NewGuid(), Name = "Device", ValidityPeriodMax = "P30D",
        };
        db.Certificates.Add(caCertEntity);
        db.CertificateAuthorities.Add(ca);
        db.SigningProfiles.Add(signing);
        db.CertProfiles.Add(certProfile);
        if (requestProfile != null) db.RequestProfiles.Add(requestProfile);
        db.CaProtocolConfigs.Add(new CaProtocolConfigEntity
        {
            Id = Guid.NewGuid(), CaId = ca.Id, Protocol = "SCEP", IsEnabled = scepEnabled,
            SigningProfileId = signing.Id, CertProfileId = certProfile.Id,
            RequestProfileId = requestProfile?.Id,
            ScepChallengeRequired = true,
        });
        db.SaveChanges();

        var resolver = new CaResolverService(db);
        var profiles = new ProfileResolutionService(db, NullLogger<ProfileResolutionService>.Instance);
        var requestProfiles = new RequestProfileValidationService(db, profiles);
        var enrollmentAuth = new EnrollmentAuthorizationService(
            db, new EnrollmentTokenServiceStub(), resolver, new FixedAuthorizer(true),
            NullLogger<EnrollmentAuthorizationService>.Instance);

        return new Harness
        {
            Db = db,
            Ca = ca,
            CaCertRow = caCertEntity,
            Context = new ResolvedCaContext
            {
                Ca = ca,
                SigningProfileId = signing.Id,
                CertProfileId = certProfile.Id,
                RequestProfileId = requestProfile?.Id,
            },
            Pipeline = new EnrollmentPipeline(db, resolver, enrollmentAuth, requestProfiles, profiles,
                new FakeIssuance(db, caCert), new NoopNotificationService(),
                NullLogger<EnrollmentPipeline>.Instance),
        };
    }

    /// <summary>A parsed PKCS#10 with no challenge password, which is what a renewal carries.</summary>
    private static (CertificateUtil.ParsedCsrInfo Parsed, string Pem) Csr(string subject = "CN=printer1.lab.test")
    {
        using var key = RSA.Create(2048);
        var pem = CertificateUtil.ConvertDerToPem(
            new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
                .CreateSigningRequest(), "CERTIFICATE REQUEST");
        return (CertificateUtil.ParseCsr(pem), pem);
    }

    /// <summary>Builds the submission SCEP builds, with the harness recording its audit rows.</summary>
    private static EnrollmentSubmission Submission(
        Harness h, bool isRenewal, EnrollmentRenewal? renewal = null, string subject = "CN=printer1.lab.test")
    {
        var (parsed, pem) = Csr(subject);
        var submission = ScepService.BuildSubmission(
            parsed, pem, h.Context, "0123456789abcdef", "10.0.0.5",
            isRenewal ? "scep-renewal:01" : "scep-initial", isRenewal, renewal);
        return submission with { Audit = record => { h.Audit.Add(record); return Task.CompletedTask; } };
    }

    // ── What the submission says about the credential ────────────────────────

    /// <summary>
    /// An initial enrollment is unverified and its credential is the shared secret inside the
    /// request, which is where the shared authorization step goes looking for it.
    /// </summary>
    [Fact]
    public void An_initial_enrollment_is_unverified_and_carries_its_secret_in_the_request()
    {
        var h = Build();
        var submission = Submission(h, isRenewal: false);

        Assert.Equal("SCEP", submission.Protocol);
        Assert.False(submission.Caller.IsVerified);
        Assert.Equal(EnrollmentAuthMethod.SharedSecret, submission.Caller.AuthMethod);
        Assert.NotNull(submission.Request.CsrPem);
        Assert.Null(submission.Renewal);
        Assert.Equal("0123456789abcdef", submission.Correlation);
        Assert.Same(h.Context, submission.ResolvedContext);
    }

    /// <summary>
    /// A renewal is verified, by the signer checks SCEP made before the middle was called, and
    /// names the certificate it replaces.
    /// </summary>
    [Fact]
    public void A_renewal_is_verified_by_its_signature_and_names_the_certificate_it_replaces()
    {
        var h = Build();
        var renewed = new EnrollmentRenewal(Guid.NewGuid(), "0A0B");
        var submission = Submission(h, isRenewal: true, renewed);

        Assert.True(submission.Caller.IsVerified);
        Assert.Equal(EnrollmentAuthMethod.MessageSignature, submission.Caller.AuthMethod);
        Assert.Same(renewed, submission.Renewal);
    }

    /// <summary>SCEP never lets a client choose a profile, a window or an extension.</summary>
    [Fact]
    public void A_scep_client_asks_for_nothing_beyond_its_csr()
    {
        var submission = Submission(Build(), isRenewal: false);

        Assert.Null(submission.RequestedCertProfileId);
        Assert.Null(submission.RequestedNotBefore);
        Assert.Null(submission.RequestedNotAfter);
        Assert.False(submission.ClampRequestedNotAfterToProfileMax);
        Assert.Null(submission.RequestedExtensions);
        Assert.Null(submission.ProfileHint);
    }

    // ── The credential, through the shared middle ────────────────────────────

    /// <summary>
    /// A first enrollment with no challenge password is refused, and the refusal is audited. The
    /// token stub accepts nothing, so this is the shape of every unauthenticated PKCSReq.
    /// </summary>
    [Fact]
    public async Task An_initial_enrollment_without_a_challenge_password_is_refused()
    {
        var h = Build();

        var outcome = Assert.IsType<EnrollmentOutcome.Refused>(
            await h.Pipeline.SubmitAsync(Submission(h, isRenewal: false)));

        Assert.Equal(EnrollmentRefusalReason.CallerNotAuthorized, outcome.Reason);
        Assert.Empty(h.Db.CertificateRequests);
        Assert.Equal(EnrollmentAuditEvent.Refused, Assert.Single(h.Audit).Event);
    }

    /// <summary>
    /// A renewal carries no challenge password and is issued anyway: the signature over the PKCSReq
    /// is what stands in for it (RFC 8894 §3.2.2), and that exemption survived the migration.
    /// </summary>
    [Fact]
    public async Task A_renewal_is_exempt_from_the_challenge_password()
    {
        var h = Build();

        var issued = Assert.IsType<EnrollmentOutcome.Issued>(
            await h.Pipeline.SubmitAsync(Submission(h, isRenewal: true)));

        Assert.NotEmpty(issued.CertificatePem);
        Assert.Equal(EnrollmentAuditEvent.Issued, Assert.Single(h.Audit).Event);
    }

    /// <summary>
    /// A renewal at a CA with SCEP switched off is refused. It was not before: the exemption from
    /// the challenge password was expressed by skipping the authorization service altogether, and
    /// the protocol-enablement check lives inside it.
    /// </summary>
    [Fact]
    public async Task A_renewal_at_a_ca_with_scep_disabled_is_refused()
    {
        var h = Build(scepEnabled: false);

        var outcome = Assert.IsType<EnrollmentOutcome.Refused>(
            await h.Pipeline.SubmitAsync(Submission(h, isRenewal: true)));

        Assert.Equal(EnrollmentRefusalReason.ProtocolDisabledOnCa, outcome.Reason);
        Assert.Empty(h.Db.CertificateRequests);
    }

    /// <summary>The renewal links the new request row to the certificate it replaces.</summary>
    [Fact]
    public async Task A_renewal_links_its_request_row_to_the_certificate_it_replaces()
    {
        var h = Build();
        var replaced = Guid.NewGuid();
        h.Db.Certificates.Add(new CertificateEntity
        {
            CertificateId = replaced, SerialNumber = "0A0B", Pem = h.CaCertRow.Pem,
            SubjectDN = "CN=printer1.lab.test", Issuer = h.CaCertRow.SubjectDN,
        });
        await h.Db.SaveChangesAsync();

        await h.Pipeline.SubmitAsync(
            Submission(h, isRenewal: true, new EnrollmentRenewal(replaced, "0A0B")));

        Assert.Equal(replaced, Assert.Single(h.Db.CertificateRequests).RenewalOfCertificateId);
    }

    // ── The approval gate ────────────────────────────────────────────────────

    /// <summary>
    /// The gate SCEP never read. A request profile that requires an approver takes the request
    /// under submission instead of issuing it, which is what the PENDING status in SCEP's own wire
    /// format has always been for.
    /// </summary>
    [Fact]
    public async Task A_profile_that_requires_approval_takes_the_request_under_submission()
    {
        var h = Build(requestProfile: new RequestProfileEntity
        {
            Id = Guid.NewGuid(), Name = "gated", RequireApproval = true,
        });

        var pending = Assert.IsType<EnrollmentOutcome.Pending>(
            await h.Pipeline.SubmitAsync(Submission(h, isRenewal: true)));

        var row = Assert.Single(h.Db.CertificateRequests);
        Assert.Equal(pending.RequestId, row.Id);
        Assert.Equal("PendingApproval", row.Status);
        Assert.Null(row.IssuedCertificateId);
        Assert.Equal(EnrollmentAuditEvent.Pending, Assert.Single(h.Audit).Event);
    }

    /// <summary>Without the gate the same request is issued, so the gate is what moved and not the path.</summary>
    [Fact]
    public async Task The_same_request_without_the_gate_is_issued()
    {
        var h = Build(requestProfile: new RequestProfileEntity
        {
            Id = Guid.NewGuid(), Name = "ungated", RequireApproval = false,
        });

        Assert.IsType<EnrollmentOutcome.Issued>(
            await h.Pipeline.SubmitAsync(Submission(h, isRenewal: true)));
    }

    // ── The key-algorithm rule ───────────────────────────────────────────────

    /// <summary>
    /// The list is JSON, and the reading that split it on commas turned the default <c>[]</c> into
    /// a single token no key algorithm equals — so every request that reached the check was
    /// refused with <c>badAlg</c>.
    /// </summary>
    [Theory]
    [InlineData("[]", "RSA", true)]
    [InlineData(null, "RSA", true)]
    [InlineData("", "RSA", true)]
    [InlineData("""["RSA","ECDSA"]""", "RSA", true)]
    [InlineData("""["RSA","ECDSA"]""", "ECDSA", true)]
    [InlineData("""["RSA","ECDSA"]""", "Ed25519", false)]
    [InlineData("""["rsa"]""", "RSA", true)]
    [InlineData("RSA,ECDSA", "ECDSA", true)]
    [InlineData("RSA,ECDSA", "Ed25519", false)]
    [InlineData("not json at all", "RSA", false)]
    public void The_allowed_key_algorithm_list_is_read_as_what_it_is(
        string? allowed, string algorithm, bool permitted)
    {
        Assert.Equal(permitted, ScepService.KeyAlgorithmPermitted(allowed, algorithm));
    }

    // ── What SCEP declares about itself ──────────────────────────────────────

    /// <summary>
    /// SCEP names itself as the per-CA protocol configuration and the audit rows spell it, and
    /// declares the four things it can do. <c>GetCertInitial</c> is both the poll and the
    /// collection, which is why both are declared from one message.
    /// </summary>
    [Fact]
    public void Scep_declares_its_name_and_what_it_can_do()
    {
        var protocol = (IEnrollmentProtocol)RuntimeHelpers.GetUninitializedObject(typeof(ScepService));

        Assert.Equal("SCEP", protocol.Name);
        Assert.Equal(
            EnrollmentCapabilities.Enroll | EnrollmentCapabilities.ReEnroll
            | EnrollmentCapabilities.Poll | EnrollmentCapabilities.Collect,
            protocol.Capabilities);
        Assert.Equal(ScepService.Protocol, protocol.Name);
    }
}
