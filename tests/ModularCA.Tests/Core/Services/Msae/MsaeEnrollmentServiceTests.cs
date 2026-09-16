using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Core.Services.Msae;
using ModularCA.Core.Services.Msae.Kerberos;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Asn1;
using Xunit;

namespace ModularCA.Tests.Core.Services.Msae;

/// <summary>
/// Pins the MS-WSTEP enrollment pipeline end to end over an in-memory database, with only the
/// certificate signer faked: which CA and profiles a request resolves to, which requests are
/// refused before anything is persisted, and what the client gets back.
/// </summary>
/// <remarks>
/// The refusals matter as much as the happy path. Each one is asserted to leave no certificate
/// request behind and to have written a rejection to the audit trail, because a refusal that
/// persists a half-finished request, or one that leaves no trace, is the kind of defect that only
/// shows up months later as orphaned rows or an unexplained certificate.
/// </remarks>
public class MsaeEnrollmentServiceTests
{
    private sealed class RecordingAuthorizer(bool verdict) : IEnrollmentPrincipalAuthorizer
    {
        public List<(string Username, Guid CaId)> Asked { get; } = [];
        public Task<bool> MayEnrollAsync(string username, Guid caId)
        {
            Asked.Add((username, caId));
            return Task.FromResult(verdict);
        }
    }

    /// <summary>Captures MSAE protocol audit rows; every other protocol's method is unexpected here.</summary>
    private sealed class RecordingAudit : IProtocolAuditService
    {
        public List<(string Action, string? Username, bool Success, string? Error, Guid? CaId, string? Template, string? Serial)> Entries { get; } = [];

        public Task LogMsaeAsync(string operation, string? subjectDN, string? certSerial,
            string? keyAlgorithm, string? keySize, string? templateName, string? caLabel,
            string? sourceIp, bool success = true, string? errorMessage = null,
            Guid? certificateAuthorityId = null, Guid? tenantId = null, string? callerPrincipal = null,
            string? realm = null, string? authMethod = null)
        {
            Entries.Add((operation, callerPrincipal, success, errorMessage, certificateAuthorityId, templateName, certSerial));
            return Task.CompletedTask;
        }

        public Task LogEstAsync(string operation, string? subjectDN, string? certSerial, string? keyAlgorithm, string? keySize,
            string? caLabel, string? sourceIp, bool success = true, string? errorMessage = null,
            Guid? certificateAuthorityId = null, Guid? tenantId = null, string? callerPrincipal = null)
            => throw new NotSupportedException();
        public Task LogScepAsync(string operation, string? subjectDN, string? certSerial, string? keyAlgorithm, string? keySize,
            string? caLabel, string? transactionId, string? sourceIp, bool success = true, string? errorMessage = null,
            Guid? certificateAuthorityId = null, Guid? tenantId = null, string? callerPrincipal = null)
            => throw new NotSupportedException();
        public Task LogCmpAsync(string messageType, string? subjectDN, string? certSerial, string? keyAlgorithm, string? keySize,
            string? caLabel, string? transactionId, string? revocationReason, string? sourceIp, bool success = true,
            string? errorMessage = null, Guid? certificateAuthorityId = null, Guid? tenantId = null, string? callerPrincipal = null)
            => throw new NotSupportedException();
        public Task LogAcmeAsync(string operation, Guid? accountId, Guid? orderId, string? subjectDN, string? certSerial,
            string? identifiers, string? revocationReason, string? sourceIp, bool success = true, string? errorMessage = null,
            string? caLabel = null, Guid? certificateAuthorityId = null, Guid? tenantId = null,
            Guid? signingProfileId = null, Guid? certProfileId = null)
            => throw new NotSupportedException();
        public Task LogNetworkRequestAsync(string sourceIp, string requestPath, string httpMethod, int statusCode,
            long? responseTimeMs, string? protocol, string? caLabel, bool blocked, string? reason, string? userAgent,
            Guid? certificateAuthorityId = null, Guid? tenantId = null)
            => throw new NotSupportedException();
    }

    /// <summary>
    /// Stands in for the real signer: issues a genuine leaf from the test CA and links it to the
    /// request row the way the real service does, so the chain walk and the audit serial are
    /// exercised against real data.
    /// </summary>
    private sealed class FakeIssuance(ModularCADbContext db, X509Certificate2 caCert) : ICertificateIssuanceService
    {
        public List<Guid> IssuedCsrIds { get; } = [];

        public Task<IssuanceResult> IssueCertificateAsync(Guid csrId, DateTime? notBefore, DateTime? notAfter,
            ValidityCeilingEnforcement ceilingEnforcement = ValidityCeilingEnforcement.AlwaysShorten,
            CancellationToken cancellationToken = default)
        {
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
            Org.BouncyCastle.X509.X509Certificate caCertificate, IPrivateKeyHandle caKeyHandle, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public Task<IssuanceResult> IssueCaCertificateAsync(Guid csrId, DateTime? notBefore, DateTime? notAfter,
            Org.BouncyCastle.X509.X509Certificate caCertificate, IPrivateKeyHandle caKeyHandle, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public Task<IssuanceResult> ReissueCertificateAsync(Guid? certId, string? certSN, Guid? csrId, DateTime? notBefore, DateTime? notAfter,
            string? newSubjectDn = null, List<string>? newSans = null,
            ValidityCeilingEnforcement ceilingEnforcement = ValidityCeilingEnforcement.AlwaysShorten)
            => throw new NotSupportedException();
    }

    private sealed class Harness
    {
        public required ModularCADbContext Db { get; init; }
        public required X509Certificate2 CaCert { get; init; }
        public required CertificateAuthorityEntity Ca { get; init; }
        public required SigningProfileEntity Signing { get; init; }
        public required CertProfileEntity CertProfile { get; init; }
        public required CaProtocolConfigEntity MsaeRow { get; init; }
        public required RecordingAudit Audit { get; init; }
        public required FakeIssuance Issuance { get; init; }
        public required RecordingAuthorizer Authorizer { get; init; }
        public required MsaeEnrollmentService Service { get; init; }
    }

    private static Harness Build(bool msaeEnabled = true, bool member = true)
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
            Id = Guid.NewGuid(), CaId = ca.Id, Protocol = "MSAE", IsEnabled = msaeEnabled,
            SigningProfileId = signing.Id, CertProfileId = certProfile.Id,
        };
        db.Certificates.Add(caCertEntity);
        db.CertificateAuthorities.Add(ca);
        db.SigningProfiles.Add(signing);
        db.CertProfiles.Add(certProfile);
        db.CaProtocolConfigs.Add(row);
        db.SaveChanges();

        var audit = new RecordingAudit();
        var issuance = new FakeIssuance(db, caCert);
        var authorizer = new RecordingAuthorizer(member);
        var resolver = new CaResolverService(db);
        var profiles = new ProfileResolutionService(db, NullLogger<ProfileResolutionService>.Instance);
        var requestProfiles = new RequestProfileValidationService(db, profiles);
        var enrollmentAuth = new EnrollmentAuthorizationService(
            db, new EnrollmentTokenServiceStub(), resolver, authorizer, NullLogger<EnrollmentAuthorizationService>.Instance);
        var service = new MsaeEnrollmentService(db, issuance, resolver, enrollmentAuth, requestProfiles, profiles, audit,
            NullLogger<MsaeEnrollmentService>.Instance);

        return new Harness
        {
            Db = db, CaCert = caCert, Ca = ca, Signing = signing, CertProfile = certProfile, MsaeRow = row,
            Audit = audit, Issuance = issuance, Authorizer = authorizer, Service = service,
        };
    }

    private static byte[] Csr(string subject = "CN=device-01.lab.test", string? templateName = null, string? templateOid = null)
    {
        using var key = RSA.Create(2048);
        var req = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        if (templateName != null)
        {
            req.CertificateExtensions.Add(new X509Extension(
                new Oid(MsaeCsrTemplate.TemplateNameOid), new DerBmpString(templateName).GetDerEncoded(), false));
        }
        if (templateOid != null)
        {
            // What a client that fetched policy sends: szOID_CERTIFICATE_TEMPLATE with OID and version.
            req.CertificateExtensions.Add(new X509Extension(
                new Oid(MsaeCsrTemplate.TemplateInfoOid),
                new DerSequence(new DerObjectIdentifier(templateOid), new DerInteger(100), new DerInteger(0)).GetDerEncoded(),
                false));
        }
        return req.CreateSigningRequest();
    }

    private CertificateTemplateEntity AddTemplate(Harness h, string name, CertProfileEntity profile, string? oid = null, bool enabled = true)
    {
        var template = new CertificateTemplateEntity
        {
            Id = Guid.NewGuid(), Name = name, CaId = h.Ca.Id,
            CertProfileId = profile.Id, SigningProfileId = h.Signing.Id, IsEnabled = enabled,
            MsaeTemplateOid = oid,
        };
        h.Db.CertificateTemplates.Add(template);
        h.Db.SaveChanges();
        return template;
    }

    [Fact]
    public async Task A_request_naming_a_template_by_oid_issues_from_that_template()
    {
        // The policy service hands a client the template's OID; the client puts it in its CSR.
        var h = Build();
        var templateProfile = new CertProfileEntity { Id = Guid.NewGuid(), Name = "Lab Device", ValidityPeriodMax = "P7D" };
        h.Db.CertProfiles.Add(templateProfile);
        AddTemplate(h, "LabDevice", templateProfile, oid: "2.25.4242");

        await h.Service.EnrollAsync(Csr(templateOid: "2.25.4242"), "svc-enroll", null, caLabel: "lab");

        var request = Assert.Single(await h.Db.CertificateRequests.ToListAsync());
        Assert.Equal(templateProfile.Id, request.CertProfileId);
        // Audited under the name the OID resolved to, not the bare OID.
        Assert.Equal("LabDevice", Assert.Single(h.Audit.Entries).Template);
    }

    [Fact]
    public async Task A_known_oid_wins_over_a_name_that_disagrees_with_it()
    {
        // The OID is the identifier the policy service promised; the name is informational.
        var h = Build();
        var byOidProfile = new CertProfileEntity { Id = Guid.NewGuid(), Name = "By OID", ValidityPeriodMax = "P7D" };
        var byNameProfile = new CertProfileEntity { Id = Guid.NewGuid(), Name = "By Name", ValidityPeriodMax = "P7D" };
        h.Db.CertProfiles.AddRange(byOidProfile, byNameProfile);
        AddTemplate(h, "OidTemplate", byOidProfile, oid: "2.25.1");
        AddTemplate(h, "NameTemplate", byNameProfile);

        await h.Service.EnrollAsync(Csr(templateName: "NameTemplate", templateOid: "2.25.1"), "svc-enroll", null, null);

        Assert.Equal(byOidProfile.Id, Assert.Single(await h.Db.CertificateRequests.ToListAsync()).CertProfileId);
    }

    [Fact]
    public async Task An_unknown_oid_falls_back_to_the_name_and_is_refused_without_one()
    {
        var h = Build();
        var profile = new CertProfileEntity { Id = Guid.NewGuid(), Name = "Named", ValidityPeriodMax = "P7D" };
        h.Db.CertProfiles.Add(profile);
        AddTemplate(h, "Named", profile);

        // Unknown OID plus a known name: the name carries it.
        await h.Service.EnrollAsync(Csr(templateName: "Named", templateOid: "2.25.999"), "svc-enroll", null, null);
        Assert.Equal(profile.Id, Assert.Single(await h.Db.CertificateRequests.ToListAsync()).CertProfileId);

        // Unknown OID alone: nothing to issue from, and a default would be the wrong answer.
        var h2 = Build();
        await AssertRefusedCleanly(h2,
            () => h2.Service.EnrollAsync(Csr(templateOid: "2.25.999"), "svc-enroll", null, null),
            "2.25.999");
    }

    private static X509Certificate2Collection Certificates(byte[] pkcs7)
    {
        var collection = new X509Certificate2Collection();
        collection.Import(pkcs7);
        return collection;
    }

    private static async Task AssertRefusedCleanly(Harness h, Func<Task> act, string expectedReasonFragment)
    {
        var ex = await Assert.ThrowsAsync<MsaeEnrollmentException>(act);
        Assert.Contains(expectedReasonFragment, ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(await h.Db.CertificateRequests.ToListAsync());
        Assert.Empty(h.Issuance.IssuedCsrIds);
        var rejection = Assert.Single(h.Audit.Entries, e => e.Action == MsaeEnrollmentService.RejectOperation);
        Assert.False(rejection.Success);
        Assert.Equal("user:svc-enroll", rejection.Username);
        Assert.Contains(expectedReasonFragment, rejection.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task A_request_naming_no_template_issues_from_the_ca_msae_defaults()
    {
        var h = Build();

        var pkcs7 = await h.Service.EnrollAsync(Csr(), "svc-enroll", "10.0.0.5", caLabel: null);

        // The client gets its leaf and the issuing CA, in that order, as a certs-only PKCS#7.
        var certs = Certificates(pkcs7);
        Assert.Equal(2, certs.Count);
        Assert.Contains(certs.Cast<X509Certificate2>(), c => c.Subject == "CN=device-01.lab.test");
        Assert.Contains(certs.Cast<X509Certificate2>(), c => c.Thumbprint == h.CaCert.Thumbprint);

        // One request row, issued through the CA's MSAE profiles, and the signer saw exactly it.
        var request = Assert.Single(await h.Db.CertificateRequests.ToListAsync());
        Assert.Equal(h.Signing.Id, request.SigningProfileId);
        Assert.Equal(h.CertProfile.Id, request.CertProfileId);
        Assert.Equal("CN=device-01.lab.test", request.Subject);
        Assert.Equal([request.Id], h.Issuance.IssuedCsrIds);

        // Membership was checked on the CA that issued, and the success is attributed to the caller
        // on the MSAE audit tab, with the serial an incident responder would search for.
        Assert.Equal([("svc-enroll", h.Ca.Id)], h.Authorizer.Asked);
        var entry = Assert.Single(h.Audit.Entries);
        Assert.Equal((MsaeEnrollmentService.EnrollOperation, "user:svc-enroll", true, h.Ca.Id),
            (entry.Action, entry.Username, entry.Success, entry.CaId));
        Assert.Null(entry.Template);
        var issuedSerial = (await h.Db.Certificates.SingleAsync(c => !c.IsCA)).SerialNumber;
        Assert.Equal(issuedSerial, entry.Serial);
    }

    [Fact]
    public async Task A_request_naming_a_known_template_issues_with_that_templates_profiles()
    {
        var h = Build();
        var templateProfile = new CertProfileEntity { Id = Guid.NewGuid(), Name = "Lab Device", ValidityPeriodMax = "P7D" };
        h.Db.CertProfiles.Add(templateProfile);
        h.Db.CertificateTemplates.Add(new CertificateTemplateEntity
        {
            Id = Guid.NewGuid(), Name = "LabDevice", CaId = h.Ca.Id,
            CertProfileId = templateProfile.Id, SigningProfileId = h.Signing.Id, IsEnabled = true,
        });
        await h.Db.SaveChangesAsync();

        await h.Service.EnrollAsync(Csr(templateName: "LabDevice"), "svc-enroll", null, caLabel: "lab");

        var request = Assert.Single(await h.Db.CertificateRequests.ToListAsync());
        Assert.Equal(templateProfile.Id, request.CertProfileId);
        Assert.NotEqual(h.CertProfile.Id, request.CertProfileId);
        // The audit row names the template, so a certificate can be traced back to what was asked for.
        Assert.Equal("LabDevice", Assert.Single(h.Audit.Entries).Template);
    }

    [Fact]
    public async Task A_request_naming_an_unknown_template_is_refused_rather_than_issued_from_a_default()
    {
        var h = Build();
        await AssertRefusedCleanly(h,
            () => h.Service.EnrollAsync(Csr(templateName: "NoSuchTemplate"), "svc-enroll", null, null),
            "NoSuchTemplate");
    }

    [Fact]
    public async Task A_disabled_template_is_refused()
    {
        var h = Build();
        h.Db.CertificateTemplates.Add(new CertificateTemplateEntity
        {
            Id = Guid.NewGuid(), Name = "Retired", CaId = h.Ca.Id,
            CertProfileId = h.CertProfile.Id, SigningProfileId = h.Signing.Id, IsEnabled = false,
        });
        await h.Db.SaveChangesAsync();

        await AssertRefusedCleanly(h,
            () => h.Service.EnrollAsync(Csr(templateName: "Retired"), "svc-enroll", null, null),
            "Retired");
    }

    [Fact]
    public async Task A_template_belonging_to_another_ca_is_refused_when_the_route_names_this_one()
    {
        var h = Build();
        var otherCa = new CertificateAuthorityEntity { Id = Guid.NewGuid(), Name = "other", Label = "other", IsEnabled = true, TenantId = h.Ca.TenantId };
        h.Db.CertificateAuthorities.Add(otherCa);
        h.Db.CertificateTemplates.Add(new CertificateTemplateEntity
        {
            Id = Guid.NewGuid(), Name = "OtherDevice", CaId = otherCa.Id,
            CertProfileId = h.CertProfile.Id, SigningProfileId = h.Signing.Id, IsEnabled = true,
        });
        await h.Db.SaveChangesAsync();

        await AssertRefusedCleanly(h,
            () => h.Service.EnrollAsync(Csr(templateName: "OtherDevice"), "svc-enroll", null, caLabel: "lab"),
            "does not belong to CA 'lab'");
    }

    [Fact]
    public async Task A_ca_with_msae_disabled_refuses_before_anything_is_persisted()
    {
        var h = Build(msaeEnabled: false);
        await AssertRefusedCleanly(h,
            () => h.Service.EnrollAsync(Csr(), "svc-enroll", null, null),
            "MSAE");
    }

    [Fact]
    public async Task A_caller_without_enrollment_rights_on_the_ca_is_refused()
    {
        var h = Build(member: false);
        await AssertRefusedCleanly(h,
            () => h.Service.EnrollAsync(Csr(), "svc-enroll", null, null),
            "not permitted");
        Assert.Equal([("svc-enroll", h.Ca.Id)], h.Authorizer.Asked);
    }

    [Fact]
    public async Task An_approval_gated_request_profile_is_refused_before_a_request_row_exists()
    {
        var h = Build();
        var gated = new RequestProfileEntity { Id = Guid.NewGuid(), Name = "Gated", RequireApproval = true };
        h.Db.RequestProfiles.Add(gated);
        h.MsaeRow.RequestProfileId = gated.Id;
        await h.Db.SaveChangesAsync();

        await AssertRefusedCleanly(h,
            () => h.Service.EnrollAsync(Csr(), "svc-enroll", null, null),
            "requires approval");
    }

    [Fact]
    public async Task A_request_profile_subject_rule_is_enforced()
    {
        var h = Build();
        var strict = new RequestProfileEntity
        {
            Id = Guid.NewGuid(), Name = "Strict",
            SubjectDnRules = """[{"Field":"O","Requirement":"Required"}]""",
        };
        h.Db.RequestProfiles.Add(strict);
        h.MsaeRow.RequestProfileId = strict.Id;
        await h.Db.SaveChangesAsync();

        await AssertRefusedCleanly(h,
            () => h.Service.EnrollAsync(Csr("CN=device-01.lab.test"), "svc-enroll", null, null),
            "'O' is required");
    }

    [Fact]
    public async Task An_unreadable_pkcs10_is_refused()
    {
        var h = Build();
        await AssertRefusedCleanly(h,
            () => h.Service.EnrollAsync(new byte[] { 0x30, 0x03, 0x02, 0x01, 0x00 }, "svc-enroll", null, null),
            "readable PKCS#10");
    }

    [Fact]
    public async Task Empty_input_and_a_blank_caller_are_programming_errors()
    {
        var h = Build();
        await Assert.ThrowsAsync<ArgumentException>(() => h.Service.EnrollAsync([], "svc-enroll", null, null));
        await Assert.ThrowsAsync<ArgumentException>(() => h.Service.EnrollAsync(Csr(), " ", null, null));
        Assert.Empty(h.Audit.Entries);
    }

    /// <summary>A caller from an accepted ticket of a forest bound to the lab tenant, with no keys (none are needed past acceptance).</summary>
    private static KerberosCaller KerberosCallerFor(string principal) => new(
        principal, "CORP.LAB.TEST", principal.EndsWith('$'),
        new KerberosRealmKeys("CORP.LAB.TEST", Guid.NewGuid(), "HTTP/ca.lab.test", "corp.lab.test", Guid.NewGuid(), "svc-enroll", true, true, []),
        ReadOnlyMemory<byte>.Empty);

    [Fact]
    public async Task A_kerberos_callers_identity_names_the_certificate_not_the_csr()
    {
        var machine = Build();
        await machine.Service.EnrollAsync(Csr("CN=whatever-the-client-said"), MsaeCaller.FromKerberos(KerberosCallerFor("WS-042$")), "10.0.0.5", caLabel: null);
        var request = Assert.Single(await machine.Db.CertificateRequests.ToListAsync());
        Assert.Equal("CN=ws-042.corp.lab.test", request.Subject);
        Assert.Contains("DNS:ws-042.corp.lab.test", request.SubjectAlternativeNames);
        Assert.DoesNotContain("whatever", request.SubjectAlternativeNames);

        var user = Build();
        await user.Service.EnrollAsync(Csr("CN=whatever-the-client-said"), MsaeCaller.FromKerberos(KerberosCallerFor("alice")), null, caLabel: null);
        var userRequest = Assert.Single(await user.Db.CertificateRequests.ToListAsync());
        Assert.Equal("CN=alice", userRequest.Subject);
        Assert.Contains("UPN:alice@corp.lab.test", userRequest.SubjectAlternativeNames);
    }
}
