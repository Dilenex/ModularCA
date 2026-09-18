using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Core.Services.Enrollment;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enrollment;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Shared.Utils;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Enrollment;

/// <summary>
/// Pins the shared middle every enrollment protocol runs: the order of its steps, what each of
/// them refuses, and that nothing — accepted or refused — happens without an audit row.
/// </summary>
/// <remarks>
/// These are the tests that make the contract a contract rather than a convention. Each refusal is
/// asserted by its shared reason code and not only by its sentence, because the code is what the
/// console explains a refusal from and what tells a missing CA apart from a disabled protocol apart
/// from an unauthorized caller — three answers the authorization service alone returns as one
/// boolean. Each refusal is also asserted to leave no request row behind: a half-written request
/// surfaces months later as an orphan nobody can account for.
/// </remarks>
public class EnrollmentPipelineTests
{
    /// <summary>Answers the CA-membership question with a fixed verdict and records what was asked.</summary>
    private sealed class FixedAuthorizer(bool verdict) : IEnrollmentPrincipalAuthorizer
    {
        public List<(string Username, Guid CaId)> Asked { get; } = [];
        public Task<bool> MayEnrollAsync(string username, Guid caId)
        {
            Asked.Add((username, caId));
            return Task.FromResult(verdict);
        }
    }

    /// <summary>
    /// Stands in for the signer: issues a real leaf from the test CA and links it to the request
    /// row the way issuance does, so the chain walk and the audited serial are exercised against
    /// real data rather than a stub's say-so.
    /// </summary>
    private sealed class FakeIssuance(ModularCADbContext db, X509Certificate2 caCert) : ICertificateIssuanceService
    {
        public List<Guid> IssuedCsrIds { get; } = [];

        /// <summary>The validity window each issuance was asked for, in call order.</summary>
        public List<(DateTime? NotBefore, DateTime? NotAfter)> Windows { get; } = [];

        /// <summary>
        /// When set, issuance refuses the request on its own rules the way the real one does for a
        /// validity window that resolves to nothing.
        /// </summary>
        public string? RefuseWith { get; set; }

        public Task<IssuanceResult> IssueCertificateAsync(Guid csrId, DateTime? notBefore, DateTime? notAfter,
            ValidityCeilingEnforcement ceilingEnforcement = ValidityCeilingEnforcement.AlwaysShorten,
            CancellationToken cancellationToken = default)
        {
            if (RefuseWith != null)
                throw new ModularCA.Shared.Errors.InvalidRequestException(RefuseWith);
            Windows.Add((notBefore, notAfter));
            var csr = db.CertificateRequests.Single(c => c.Id == csrId);
            IssuedCsrIds.Add(csrId);

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

    /// <summary>Counts the pending-approval notifications the pipeline fires.</summary>
    private sealed class CountingNotifications : NoopNotificationService
    {
        public List<(string Subject, string Protocol)> PendingApprovals { get; } = [];
        public override Task NotifyCsrPendingApprovalAsync(string subject, string protocol)
        {
            PendingApprovals.Add((subject, protocol));
            return Task.CompletedTask;
        }
    }

    private sealed class Harness
    {
        public required ModularCADbContext Db { get; init; }
        public required CertificateAuthorityEntity Ca { get; init; }
        public required CertProfileEntity CertProfile { get; init; }
        public required SigningProfileEntity Signing { get; init; }
        public required FakeIssuance Issuance { get; init; }
        public required CountingNotifications Notifications { get; init; }
        public required EnrollmentPipeline Pipeline { get; init; }
        public List<EnrollmentAuditRecord> Audit { get; } = [];
    }

    /// <summary>
    /// A CA with EST enabled and HTTP authentication required, which is the configuration where
    /// authorization turns on CA membership alone — the one variable these tests want to move.
    /// </summary>
    private static Harness Build(bool estEnabled = true, bool member = true, RequestProfileEntity? requestProfile = null)
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
        var certProfile = new CertProfileEntity { Id = Guid.NewGuid(), Name = "Device", ValidityPeriodMax = "P30D" };
        var row = new CaProtocolConfigEntity
        {
            Id = Guid.NewGuid(), CaId = ca.Id, Protocol = "EST", IsEnabled = estEnabled,
            SigningProfileId = signing.Id, CertProfileId = certProfile.Id,
            RequestProfileId = requestProfile?.Id,
            EstHttpAuthEnabled = true, EstRequireClientCert = false,
        };
        db.Certificates.Add(caCertEntity);
        db.CertificateAuthorities.Add(ca);
        db.SigningProfiles.Add(signing);
        db.CertProfiles.Add(certProfile);
        if (requestProfile != null) db.RequestProfiles.Add(requestProfile);
        db.CaProtocolConfigs.Add(row);
        db.SaveChanges();

        var resolver = new CaResolverService(db);
        var profiles = new ProfileResolutionService(db, NullLogger<ProfileResolutionService>.Instance);
        var requestProfiles = new RequestProfileValidationService(db, profiles);
        var enrollmentAuth = new EnrollmentAuthorizationService(
            db, new EnrollmentTokenServiceStub(), resolver, new FixedAuthorizer(member),
            NullLogger<EnrollmentAuthorizationService>.Instance);
        var issuance = new FakeIssuance(db, caCert);
        var notifications = new CountingNotifications();

        return new Harness
        {
            Db = db, Ca = ca, CertProfile = certProfile, Signing = signing, Issuance = issuance, Notifications = notifications,
            Pipeline = new EnrollmentPipeline(db, resolver, enrollmentAuth, requestProfiles, profiles,
                issuance, notifications, NullLogger<EnrollmentPipeline>.Instance),
        };
    }

    /// <summary>A submission shaped like the one EST builds, with the harness recording its audit.</summary>
    private static EnrollmentSubmission Submission(Harness h, string subject = "CN=device-01.lab.test",
        string? caLabel = "lab", string[]? sans = null)
    {
        using var key = RSA.Create(2048);
        var csrPem = CertificateUtil.ConvertDerToPem(
            new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
                .CreateSigningRequest(), "CERTIFICATE REQUEST");

        return new EnrollmentSubmission
        {
            Protocol = "EST",
            CaLabel = caLabel,
            SourceIp = "10.0.0.5",
            Caller = new EnrollmentCaller("basic:svc-enroll", EnrollmentAuthMethod.HttpCredential,
                IsVerified: true, Username: "svc-enroll"),
            Request = new EnrollmentRequestMaterial
            {
                CsrPem = csrPem,
                Subject = subject,
                SubjectAlternativeNames = sans ?? [],
                KeyAlgorithm = "RSA",
                KeySize = "2048",
                SignatureAlgorithm = "SHA256WITHRSA",
            },
            Audit = record => { h.Audit.Add(record); return Task.CompletedTask; },
        };
    }

    /// <summary>A profile that refuses a subject with no organisation, and never rewrites one.</summary>
    private static RequestProfileEntity ProfileRequiringOrganisation() => new()
    {
        Id = Guid.NewGuid(),
        Name = "org-required",
        SubjectDnRules = """[{"Field":"O","Requirement":"Required"}]""",
    };

    [Fact]
    public async Task A_request_for_a_ca_that_does_not_exist_is_refused_and_audited()
    {
        var h = Build();

        var outcome = Assert.IsType<EnrollmentOutcome.Refused>(
            await h.Pipeline.SubmitAsync(Submission(h, caLabel: "no-such-ca")));

        Assert.Equal(EnrollmentRefusalReason.CaNotFound, outcome.Reason);
        Assert.Contains("no-such-ca", outcome.Message);
        Assert.Empty(await h.Db.CertificateRequests.ToListAsync());
        Assert.Equal(EnrollmentAuditEvent.Refused, Assert.Single(h.Audit).Event);
    }

    [Fact]
    public async Task A_protocol_the_ca_does_not_have_enabled_is_refused_before_the_caller_is_even_asked_about()
    {
        // The reason code is the assertion, not the sentence: the authorization service refuses a
        // disabled protocol too, with its own wording, so a pipeline that skipped this check would
        // still refuse — for what the console would explain as the wrong reason.
        var h = Build(estEnabled: false);

        var outcome = Assert.IsType<EnrollmentOutcome.Refused>(await h.Pipeline.SubmitAsync(Submission(h)));

        Assert.Equal(EnrollmentRefusalReason.ProtocolDisabledOnCa, outcome.Reason);
        Assert.Equal("EST is not enabled for CA 'lab'.", outcome.Message);
        Assert.Empty(await h.Db.CertificateRequests.ToListAsync());
        Assert.Equal(EnrollmentRefusalReason.ProtocolDisabledOnCa, Assert.Single(h.Audit).Reason);
    }

    [Fact]
    public async Task A_caller_without_the_enrollment_capability_on_that_ca_is_refused_and_nothing_is_issued()
    {
        var h = Build(member: false);

        var outcome = Assert.IsType<EnrollmentOutcome.Refused>(await h.Pipeline.SubmitAsync(Submission(h)));

        Assert.Equal(EnrollmentRefusalReason.CallerNotAuthorized, outcome.Reason);
        Assert.Empty(h.Issuance.IssuedCsrIds);
        Assert.Empty(await h.Db.CertificateRequests.ToListAsync());
        Assert.False(Assert.Single(h.Audit).Event == EnrollmentAuditEvent.Issued);
    }

    [Fact]
    public async Task A_subject_the_request_profile_refuses_is_refused_and_nothing_is_issued()
    {
        var h = Build(requestProfile: ProfileRequiringOrganisation());

        var outcome = Assert.IsType<EnrollmentOutcome.Refused>(
            await h.Pipeline.SubmitAsync(Submission(h, subject: "CN=device-01.lab.test")));

        Assert.Equal(EnrollmentRefusalReason.NameRejectedByProfile, outcome.Reason);
        Assert.Contains("'O' is required", outcome.Message);
        Assert.Empty(h.Issuance.IssuedCsrIds);
        Assert.Empty(await h.Db.CertificateRequests.ToListAsync());
        Assert.Equal(EnrollmentAuditEvent.Refused, Assert.Single(h.Audit).Event);
    }

    [Fact]
    public async Task A_name_longer_than_a_certificate_may_carry_is_refused_rather_than_thrown()
    {
        var h = Build();

        // Sixty-five characters: one past what RFC 5280 allows a common name, and one past what
        // the ASN.1 library will construct a name from since 2.7.0. Reaching the library with it
        // would be a server error; the middle answers with a refusal instead, for every protocol.
        var outcome = Assert.IsType<EnrollmentOutcome.Refused>(
            await h.Pipeline.SubmitAsync(Submission(h, subject: "CN=" + new string('a', 65))));

        Assert.Equal(EnrollmentRefusalReason.NameRejectedByProfile, outcome.Reason);
        Assert.Contains("64", outcome.Message);
        Assert.Empty(h.Issuance.IssuedCsrIds);
        Assert.Empty(await h.Db.CertificateRequests.ToListAsync());
        Assert.Equal(EnrollmentAuditEvent.Refused, Assert.Single(h.Audit).Event);

        // Sixty-four is issued, so the boundary is where the standard puts it.
        var ok = Build();
        Assert.IsType<EnrollmentOutcome.Issued>(
            await ok.Pipeline.SubmitAsync(Submission(ok, subject: "CN=" + new string('a', 64))));
    }

    [Fact]
    public async Task A_profile_that_requires_approval_takes_the_request_under_submission_instead_of_issuing()
    {
        var profile = ProfileRequiringOrganisation();
        profile.SubjectDnRules = "[]";
        profile.RequireApproval = true;
        var h = Build(requestProfile: profile);

        var outcome = Assert.IsType<EnrollmentOutcome.Pending>(await h.Pipeline.SubmitAsync(Submission(h)));

        var request = Assert.Single(await h.Db.CertificateRequests.ToListAsync());
        Assert.Equal(request.Id, outcome.RequestId);
        Assert.Equal("PendingApproval", request.Status);
        Assert.Empty(h.Issuance.IssuedCsrIds);
        Assert.Equal(EnrollmentAuditEvent.Pending, Assert.Single(h.Audit).Event);
        Assert.Equal(("CN=device-01.lab.test", "EST"), Assert.Single(h.Notifications.PendingApprovals));
    }

    [Fact]
    public async Task An_accepted_request_is_recorded_issued_audited_and_returned_with_its_chain()
    {
        var h = Build();

        var outcome = Assert.IsType<EnrollmentOutcome.Issued>(await h.Pipeline.SubmitAsync(Submission(h)));

        var request = Assert.Single(await h.Db.CertificateRequests.ToListAsync());
        Assert.Equal(request.Id, outcome.RequestId);
        Assert.Equal("CN=device-01.lab.test", request.Subject);
        Assert.Equal([request.Id], h.Issuance.IssuedCsrIds);
        Assert.Contains("BEGIN CERTIFICATE", outcome.CertificatePem);
        // The chain is the issuer walk from the signing profile: one CA above the leaf here.
        Assert.Single(outcome.ChainPem);
        Assert.NotNull(outcome.SerialNumber);

        var audited = Assert.Single(h.Audit);
        Assert.Equal(EnrollmentAuditEvent.Issued, audited.Event);
        Assert.Equal(outcome.SerialNumber, audited.SerialNumber);
        Assert.Equal(h.Ca.Id, audited.CaId);
        Assert.Equal("10.0.0.5", audited.SourceIp);
    }

    [Fact]
    public async Task The_protocols_own_checks_run_where_the_shared_sequence_says_they_do()
    {
        // The order is the contract: a protocol that binds a CSR to the credential presented must
        // see an unauthorized caller refused first, and a protocol whose check needs the resolved
        // request profile must be given it.
        var h = Build(requestProfile: ProfileRequiringOrganisation());
        var seen = new List<string>();
        var submission = Submission(h, subject: "CN=device-01.lab.test, O=ModularCA") with
        {
            AfterAuthorization = authorized => { seen.Add("authorized"); return Task.FromResult(authorized); },
            AfterProfileValidation = policy =>
            {
                seen.Add(policy.RequestProfileId != null ? "profile" : "profile-missing");
                return Task.CompletedTask;
            },
        };

        Assert.IsType<EnrollmentOutcome.Issued>(await h.Pipeline.SubmitAsync(submission));
        Assert.Equal(["authorized", "profile"], seen);
    }

    [Fact]
    public async Task A_protocol_check_that_refuses_stops_the_request_before_a_row_exists()
    {
        var h = Build();
        var submission = Submission(h) with
        {
            AfterAuthorization = _ => throw new InvalidOperationException("bound to someone else"),
        };

        await Assert.ThrowsAsync<InvalidOperationException>(() => h.Pipeline.SubmitAsync(submission));
        Assert.Empty(await h.Db.CertificateRequests.ToListAsync());
        Assert.Empty(h.Issuance.IssuedCsrIds);
    }

    /// <summary>
    /// The CA and profiles a protocol resolved for itself are the ones the middle works from, and
    /// everything the middle decides is still decided: the protocol is checked on that CA and the
    /// caller is authorized against it.
    /// </summary>
    /// <remarks>
    /// This is the MSAE shape: a Windows client names a certificate template, and the template
    /// carries the CA and the profiles. Without it the middle would resolve the CA protocol
    /// defaults and quietly issue from a profile the client did not ask for.
    /// </remarks>
    [Fact]
    public async Task A_protocol_that_resolved_its_own_ca_and_profiles_issues_from_them()
    {
        var h = Build();
        var templateProfile = new CertProfileEntity { Id = Guid.NewGuid(), Name = "Template Device", ValidityPeriodMax = "P7D" };
        h.Db.CertProfiles.Add(templateProfile);
        await h.Db.SaveChangesAsync();

        var submission = Submission(h, caLabel: null) with
        {
            ResolvedContext = new ResolvedCaContext
            {
                Ca = h.Ca,
                SigningProfileId = h.Signing.Id,
                CertProfileId = templateProfile.Id,
            },
        };

        var issued = Assert.IsType<EnrollmentOutcome.Issued>(await h.Pipeline.SubmitAsync(submission));
        var row = Assert.Single(await h.Db.CertificateRequests.ToListAsync());
        Assert.Equal(templateProfile.Id, row.CertProfileId);
        Assert.NotEqual(h.CertProfile.Id, row.CertProfileId);
        Assert.Equal(row.Id, issued.RequestId);
        // Audited against that CA, not against whatever a label-less request would have resolved to.
        Assert.Equal(h.Ca.Id, Assert.Single(h.Audit).CaId);
    }

    /// <summary>
    /// A protocol whose own check can only run after the caller is authorized settles the names and
    /// the renewal there, and both reach the request row.
    /// </summary>
    /// <remarks>
    /// MSAE proves renewal evidence at that point and takes the new certificate's names from the
    /// certificate being renewed. The row must carry the link, or nothing afterwards knows the
    /// certificate replaced a specific one.
    /// </remarks>
    [Fact]
    public async Task A_protocol_check_settles_the_names_and_the_renewal_it_proved()
    {
        var h = Build();
        var renewed = Guid.NewGuid();
        var submission = Submission(h, subject: "") with
        {
            AfterAuthorization = authorized => Task.FromResult(authorized with
            {
                Request = authorized.Request with
                {
                    Subject = "CN=ws-042.lab.test",
                    SubjectAlternativeNames = ["DNS:ws-042.lab.test"],
                },
                Renewal = new EnrollmentRenewal(renewed, "01AB"),
            }),
        };

        Assert.IsType<EnrollmentOutcome.Issued>(await h.Pipeline.SubmitAsync(submission));
        var row = Assert.Single(await h.Db.CertificateRequests.ToListAsync());
        Assert.Equal("CN=ws-042.lab.test", row.Subject);
        Assert.Contains("ws-042.lab.test", row.SubjectAlternativeNames);
        Assert.Equal(renewed, row.RenewalOfCertificateId);
        // The audit row names what was issued, not what was submitted.
        Assert.Equal("CN=ws-042.lab.test", Assert.Single(h.Audit).Subject);
    }

    /// <summary>
    /// Issuance refusing the request on the profile's rules is a refusal only for a protocol that
    /// asked for that; for every other protocol the exception propagates, as it always has.
    /// </summary>
    [Fact]
    public async Task Issuance_refusing_the_request_is_a_refusal_only_where_the_protocol_asked_for_one()
    {
        var h = Build();
        h.Issuance.RefuseWith = "Validity window resolves to nothing.";

        var refused = Assert.IsType<EnrollmentOutcome.Refused>(
            await h.Pipeline.SubmitAsync(Submission(h) with { IssuanceRefusalIsRefusal = true }));
        Assert.Equal(EnrollmentRefusalReason.IssuanceRefusedByProfile, refused.Reason);
        Assert.Equal("Validity window resolves to nothing.", refused.Message);
        // The row exists by then, so it is closed rather than left where an approver would find it.
        Assert.Equal("Rejected", Assert.Single(await h.Db.CertificateRequests.ToListAsync()).Status);
        var audited = Assert.Single(h.Audit);
        Assert.Equal(EnrollmentAuditEvent.Refused, audited.Event);
        Assert.Equal(EnrollmentRefusalReason.IssuanceRefusedByProfile, audited.Reason);

        var other = Build();
        other.Issuance.RefuseWith = "Validity window resolves to nothing.";
        await Assert.ThrowsAsync<ModularCA.Shared.Errors.InvalidRequestException>(
            () => other.Pipeline.SubmitAsync(Submission(other)));
        Assert.Empty(other.Audit);
    }

    /// <summary>
    /// A protocol that names neither end of the window gets the default one: a backdated start and
    /// the certificate profile's maximum measured from it.
    /// </summary>
    [Fact]
    public async Task A_request_that_asks_for_no_window_is_issued_for_the_cert_profiles_maximum()
    {
        var h = Build();

        Assert.IsType<EnrollmentOutcome.Issued>(await h.Pipeline.SubmitAsync(Submission(h)));

        var (notBefore, notAfter) = Assert.Single(h.Issuance.Windows);
        Assert.NotNull(notBefore);
        Assert.NotNull(notAfter);
        // Backdated by the skew allowance, and P30D from there: the harness profile's maximum.
        Assert.True(notBefore < DateTime.UtcNow);
        Assert.Equal(TimeSpan.FromDays(30), notAfter!.Value - notBefore!.Value);
    }

    /// <summary>
    /// A protocol whose client names a window is issued that window, not the profile's maximum.
    /// </summary>
    /// <remarks>
    /// ACME's newOrder carries <c>notBefore</c> and <c>notAfter</c> and has always honoured both.
    /// The contract first offered a requested <c>TimeSpan</c> instead, which cannot say when a
    /// certificate starts; a protocol migrated onto a duration would have silently dropped the
    /// client's start date.
    /// </remarks>
    [Fact]
    public async Task A_window_the_client_asked_for_is_the_window_issuance_is_asked_for()
    {
        var h = Build();
        var start = DateTime.UtcNow.AddDays(2);
        var end = start.AddDays(5);

        Assert.IsType<EnrollmentOutcome.Issued>(await h.Pipeline.SubmitAsync(
            Submission(h) with { RequestedNotBefore = start, RequestedNotAfter = end }));

        var (notBefore, notAfter) = Assert.Single(h.Issuance.Windows);
        Assert.Equal(start, notBefore);
        Assert.Equal(end, notAfter);
    }

    /// <summary>
    /// A protocol that asks for the clamp has an over-long expiry shortened to the certificate
    /// profile's maximum rather than passed on for issuance to refuse.
    /// </summary>
    /// <remarks>
    /// CMP's OptionalValidity has always been clamped before issuance saw it, so a client asking
    /// for ten years from a thirty-day profile is issued thirty days. Issuance refuses such a
    /// window outright, so moving CMP's middle here without the clamp would have turned every
    /// over-long <c>ir</c> into an error the client never used to receive.
    /// </remarks>
    [Fact]
    public async Task An_over_long_expiry_is_shortened_to_the_profile_maximum_for_a_protocol_that_asks_for_it()
    {
        var h = Build();
        var start = DateTime.UtcNow.AddDays(2);

        Assert.IsType<EnrollmentOutcome.Issued>(await h.Pipeline.SubmitAsync(
            Submission(h) with
            {
                RequestedNotBefore = start,
                RequestedNotAfter = start.AddYears(10),
                ClampRequestedNotAfterToProfileMax = true,
            }));

        var (notBefore, notAfter) = Assert.Single(h.Issuance.Windows);
        Assert.Equal(start, notBefore);
        Assert.Equal(TimeSpan.FromDays(30), notAfter!.Value - notBefore!.Value);
    }

    /// <summary>
    /// The clamp only ever shortens: an expiry inside the profile's maximum is issued as asked,
    /// so asking for the clamp is not a way of always receiving the maximum.
    /// </summary>
    [Fact]
    public async Task The_clamp_leaves_an_expiry_inside_the_profile_maximum_alone()
    {
        var h = Build();
        var start = DateTime.UtcNow.AddDays(2);
        var end = start.AddDays(5);

        Assert.IsType<EnrollmentOutcome.Issued>(await h.Pipeline.SubmitAsync(
            Submission(h) with
            {
                RequestedNotBefore = start,
                RequestedNotAfter = end,
                ClampRequestedNotAfterToProfileMax = true,
            }));

        var (_, notAfter) = Assert.Single(h.Issuance.Windows);
        Assert.Equal(end, notAfter);
    }

    /// <summary>
    /// Without the flag an over-long expiry reaches issuance unaltered, which is what ACME
    /// depends on: its <c>notAfter</c> is refused rather than quietly shortened.
    /// </summary>
    [Fact]
    public async Task An_over_long_expiry_is_left_alone_for_a_protocol_that_does_not_ask_for_the_clamp()
    {
        var h = Build();
        var start = DateTime.UtcNow.AddDays(2);
        var end = start.AddYears(10);

        Assert.IsType<EnrollmentOutcome.Issued>(await h.Pipeline.SubmitAsync(
            Submission(h) with { RequestedNotBefore = start, RequestedNotAfter = end }));

        var (_, notAfter) = Assert.Single(h.Issuance.Windows);
        Assert.Equal(end, notAfter);
    }

    /// <summary>
    /// A start in the past is raised to the floor, so a client cannot ask for a certificate that
    /// was already valid before it was issued.
    /// </summary>
    [Fact]
    public async Task A_start_in_the_past_is_raised_to_the_floor()
    {
        var h = Build();

        Assert.IsType<EnrollmentOutcome.Issued>(await h.Pipeline.SubmitAsync(
            Submission(h) with { RequestedNotBefore = DateTime.UtcNow.AddYears(-3) }));

        var (notBefore, notAfter) = Assert.Single(h.Issuance.Windows);
        Assert.True(notBefore > DateTime.UtcNow.AddMinutes(-10), "The backdated start was honoured instead of clamped.");
        // The expiry is still measured from the clamped start, not from the one that was asked for.
        Assert.Equal(TimeSpan.FromDays(30), notAfter!.Value - notBefore!.Value);
    }

    /// <summary>
    /// A configuration fault says which kind it is, because a protocol may answer the two
    /// differently: a CA with no profile to issue from is something a client is told, a profile row
    /// that is gone is a broken installation.
    /// </summary>
    [Fact]
    public async Task A_configuration_fault_says_which_kind_it_is()
    {
        var h = Build();
        var noProfile = Assert.IsType<EnrollmentOutcome.Failed>(await h.Pipeline.SubmitAsync(
            Submission(h) with
            {
                ResolvedContext = new ResolvedCaContext { Ca = h.Ca, SigningProfileId = h.Signing.Id, CertProfileId = Guid.Empty },
            }));
        Assert.Equal(EnrollmentFailureReason.NoCertificateProfileAvailable, noProfile.Reason);

        var missingRow = Assert.IsType<EnrollmentOutcome.Failed>(await h.Pipeline.SubmitAsync(
            Submission(h) with
            {
                ResolvedContext = new ResolvedCaContext { Ca = h.Ca, SigningProfileId = Guid.NewGuid(), CertProfileId = h.CertProfile.Id },
            }));
        Assert.Equal(EnrollmentFailureReason.ConfiguredProfileMissing, missingRow.Reason);

        // Neither is audited and neither leaves a row: nothing about the request was wrong.
        Assert.Empty(h.Audit);
        Assert.Empty(await h.Db.CertificateRequests.ToListAsync());
    }
}
