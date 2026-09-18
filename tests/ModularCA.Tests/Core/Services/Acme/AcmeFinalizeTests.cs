using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Core.Services.Acme;
using ModularCA.Core.Services.Enrollment;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Shared.Models.Acme;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services.Acme;

/// <summary>
/// Pins what ACME's finalize decides now that its middle runs on the shared enrollment pipeline:
/// which CA issues, what an approval-gated profile does to an order, and what the ACME audit tab
/// records either way.
/// </summary>
/// <remarks>
/// Finalize had no behavioural test at all before this. That was demonstrated rather than assumed:
/// sending every finalize to the default CA regardless of the label the order carries — the exact
/// cross-CA escalation the guard inside <see cref="AcmeOrderService.FinalizeAsync"/> was written
/// to close — passed the whole suite. The CA a finalize issues from is the first thing asserted
/// here for that reason.
/// </remarks>
public class AcmeFinalizeTests
{
    /// <summary>Captures ACME protocol audit rows; no other protocol's method belongs here.</summary>
    private sealed class RecordingAudit : IProtocolAuditService
    {
        public List<(string Operation, bool Success, string? Error, string? CaLabel, Guid? SigningProfileId, Guid? CertProfileId, string? Serial)> Entries { get; } = [];

        public Task LogAcmeAsync(string operation, Guid? accountId, Guid? orderId, string? subjectDN, string? certSerial,
            string? identifiers, string? revocationReason, string? sourceIp, bool success = true, string? errorMessage = null,
            string? caLabel = null, Guid? certificateAuthorityId = null, Guid? tenantId = null,
            Guid? signingProfileId = null, Guid? certProfileId = null)
        {
            Entries.Add((operation, success, errorMessage, caLabel, signingProfileId, certProfileId, certSerial));
            return Task.CompletedTask;
        }

        public Task LogMsaeAsync(string operation, string? subjectDN, string? certSerial, string? keyAlgorithm,
            string? keySize, string? templateName, string? caLabel, string? sourceIp, bool success = true,
            string? errorMessage = null, Guid? certificateAuthorityId = null, Guid? tenantId = null,
            string? callerPrincipal = null, string? realm = null, string? authMethod = null)
            => throw new NotSupportedException();
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
        public Task LogNetworkRequestAsync(string sourceIp, string requestPath, string httpMethod, int statusCode,
            long? responseTimeMs, string? protocol, string? caLabel, bool blocked, string? reason, string? userAgent,
            Guid? certificateAuthorityId = null, Guid? tenantId = null)
            => throw new NotSupportedException();
    }

    /// <summary>CAA that authorizes everything, so these tests move only the CA and the profile.</summary>
    private sealed class PermissiveCaa : ICaaCheckService
    {
        public Task<bool> IsIssuanceAllowedAsync(string domain, bool isWildcard) => Task.FromResult(true);
    }

    /// <summary>Issues a real leaf from the test CA and links it to the request row, as issuance does.</summary>
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
            var entity = new CertificateEntity
            {
                CertificateId = Guid.NewGuid(),
                SerialNumber = leaf.SerialNumber,
                Pem = leaf.ExportCertificatePem(),
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
            return Task.FromResult(new IssuanceResult(entity.Pem));
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

    private sealed class Harness
    {
        public required ModularCADbContext Db { get; init; }
        public required AcmeOrderService Service { get; init; }
        public required RecordingAudit Audit { get; init; }
        public required FakeIssuance Issuance { get; init; }
        /// <summary>The default CA, which a finalize must not reach when the order names another.</summary>
        public required SigningProfileEntity DefaultSigning { get; init; }
        /// <summary>The labelled CA the order in these tests belongs to.</summary>
        public required SigningProfileEntity ProdSigning { get; init; }
    }

    /// <summary>
    /// Two ACME-enabled CAs: a default one and a labelled "prod" one, so "which CA issued" is a
    /// question with a wrong answer available.
    /// </summary>
    private static Harness Build(RequestProfileEntity? prodRequestProfile = null)
    {
        var db = InMemoryDbContextFactory.Create();
        var caCert = TestCertificates.CreateCa("CN=Lab Issuing CA, O=ModularCA");

        SigningProfileEntity AddCa(string label, bool isDefault, RequestProfileEntity? requestProfile)
        {
            var certEntity = new CertificateEntity
            {
                CertificateId = Guid.NewGuid(), SerialNumber = Guid.NewGuid().ToString("N"),
                Pem = caCert.ExportCertificatePem(), SubjectDN = caCert.Subject, Issuer = caCert.Issuer,
                IsCA = true, NotBefore = caCert.NotBefore, NotAfter = caCert.NotAfter,
            };
            var ca = new CertificateAuthorityEntity
            {
                Id = Guid.NewGuid(), Name = label, Label = label, IsDefault = isDefault, IsEnabled = true,
                CertificateId = certEntity.CertificateId, TenantId = Guid.NewGuid(),
            };
            var signing = new SigningProfileEntity
            {
                Id = Guid.NewGuid(), Name = $"{label}-signing", IssuerId = certEntity.CertificateId,
            };
            var certProfile = new CertProfileEntity
            {
                Id = Guid.NewGuid(), Name = $"{label}-device", ValidityPeriodMax = "P90D",
            };
            db.Certificates.Add(certEntity);
            db.CertificateAuthorities.Add(ca);
            db.SigningProfiles.Add(signing);
            db.CertProfiles.Add(certProfile);
            if (requestProfile != null) db.RequestProfiles.Add(requestProfile);
            db.CaProtocolConfigs.Add(new CaProtocolConfigEntity
            {
                Id = Guid.NewGuid(), CaId = ca.Id, Protocol = "ACME", IsEnabled = true,
                SigningProfileId = signing.Id, CertProfileId = certProfile.Id,
                RequestProfileId = requestProfile?.Id,
            });
            return signing;
        }

        var defaultSigning = AddCa("lab", isDefault: true, requestProfile: null);
        var prodSigning = AddCa("prod", isDefault: false, prodRequestProfile);
        db.SaveChanges();

        var resolver = new CaResolverService(db);
        var profiles = new ProfileResolutionService(db, NullLogger<ProfileResolutionService>.Instance);
        var requestProfiles = new RequestProfileValidationService(db, profiles);
        var enrollmentAuth = new EnrollmentAuthorizationService(
            db, new EnrollmentTokenServiceStub(), resolver, new AlwaysEnrollable(),
            NullLogger<EnrollmentAuthorizationService>.Instance);
        var issuance = new FakeIssuance(db, caCert);
        var audit = new RecordingAudit();
        var pipeline = new EnrollmentPipeline(db, resolver, enrollmentAuth, requestProfiles, profiles,
            issuance, new NoopNotificationService(), NullLogger<EnrollmentPipeline>.Instance);

        return new Harness
        {
            Db = db,
            Audit = audit,
            Issuance = issuance,
            DefaultSigning = defaultSigning,
            ProdSigning = prodSigning,
            Service = new AcmeOrderService(db, audit, pipeline, new PermissiveCaa()),
        };
    }

    /// <summary>ACME authorizes through its challenges, so CA membership never answers no here.</summary>
    private sealed class AlwaysEnrollable : IEnrollmentPrincipalAuthorizer
    {
        public Task<bool> MayEnrollAsync(string username, Guid caId) => Task.FromResult(true);
    }

    /// <summary>A ready order for one DNS identifier, belonging to the labelled CA.</summary>
    private static AcmeOrderEntity ReadyOrder(Harness h, string identifier = "device-01.example.com", string? caLabel = "prod")
    {
        var order = new AcmeOrderEntity
        {
            AccountId = Guid.NewGuid(),
            Status = nameof(AcmeOrderStatus.Ready),
            IdentifiersJson = JsonSerializer.Serialize(new List<AcmeIdentifier>
            {
                new() { Type = "dns", Value = identifier },
            }),
            ExpiresAt = DateTime.UtcNow.AddHours(24),
            CreatedAt = DateTime.UtcNow,
            CaLabel = caLabel,
        };
        h.Db.AcmeOrders.Add(order);
        h.Db.SaveChanges();
        return order;
    }

    /// <summary>A CSR whose CN and only SAN are <paramref name="identifier"/>, base64url DER.</summary>
    private static string CsrFor(string identifier)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest($"CN={identifier}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var sans = new SubjectAlternativeNameBuilder();
        sans.AddDnsName(identifier);
        request.CertificateExtensions.Add(sans.Build());
        return Convert.ToBase64String(request.CreateSigningRequest())
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }

    [Fact]
    public async Task A_finalize_issues_from_the_ca_the_order_belongs_to_and_not_the_default_one()
    {
        var h = Build();
        var order = ReadyOrder(h);

        var dto = await h.Service.FinalizeAsync(order.Id, CsrFor("device-01.example.com"), "https://ca.example.com");

        Assert.Equal("valid", dto.Status);
        var row = Assert.Single(await h.Db.CertificateRequests.ToListAsync());
        Assert.Equal(h.ProdSigning.Id, row.SigningProfileId);
        Assert.NotEqual(h.DefaultSigning.Id, row.SigningProfileId);
        Assert.Equal([row.Id], h.Issuance.IssuedCsrIds);

        // The order now points at what was issued, which is what makes the certificate fetchable.
        var stored = await h.Db.AcmeOrders.FindAsync(order.Id);
        Assert.Equal(nameof(AcmeOrderStatus.Valid), stored!.Status);
        Assert.Equal(row.Id, stored.FinalizedCsrId);
        Assert.Equal(row.IssuedCertificateId, stored.CertificateId);

        // The audit row keeps the profile ids that let a certificate be traced back to the policy
        // that issued it, and they are the profiles the middle actually used.
        var audited = Assert.Single(h.Audit.Entries);
        Assert.Equal("CertificateIssued", audited.Operation);
        Assert.True(audited.Success);
        Assert.Equal("prod", audited.CaLabel);
        Assert.Equal(h.ProdSigning.Id, audited.SigningProfileId);
        Assert.NotNull(audited.Serial);
    }

    [Fact]
    public async Task A_finalize_against_a_different_ca_than_the_order_is_refused_and_the_order_goes_invalid()
    {
        var h = Build();
        var order = ReadyOrder(h);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => h.Service.FinalizeAsync(order.Id, CsrFor("device-01.example.com"), "https://ca.example.com", caLabel: "lab"));

        Assert.Equal(nameof(AcmeOrderStatus.Invalid), (await h.Db.AcmeOrders.FindAsync(order.Id))!.Status);
        Assert.Empty(await h.Db.CertificateRequests.ToListAsync());
        Assert.Empty(h.Issuance.IssuedCsrIds);
    }

    [Fact]
    public async Task A_csr_naming_an_identifier_the_order_does_not_carry_is_refused_before_anything_is_written()
    {
        var h = Build();
        var order = ReadyOrder(h);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => h.Service.FinalizeAsync(order.Id, CsrFor("elsewhere.example.com"), "https://ca.example.com"));

        Assert.Equal(nameof(AcmeOrderStatus.Invalid), (await h.Db.AcmeOrders.FindAsync(order.Id))!.Status);
        Assert.Empty(await h.Db.CertificateRequests.ToListAsync());
    }

    /// <summary>
    /// An approval-gated request profile refuses the finalize rather than issuing, and closes the
    /// row the middle wrote.
    /// </summary>
    /// <remarks>
    /// Before the migration this gate was ignored: ACME wrote its own request row and issued from
    /// it without ever reading <c>RequireApproval</c>, so a CA configured to require an approver
    /// issued to ACME clients anyway. ACME has no state for waiting on a human — nothing links an
    /// approval made later back to the order — so the finalize fails closed, and the row is closed
    /// with it so the approval queue does not fill with certificates nobody can collect.
    /// </remarks>
    [Fact]
    public async Task An_approval_gated_profile_refuses_the_finalize_instead_of_issuing_without_an_approver()
    {
        var h = Build(prodRequestProfile: new RequestProfileEntity
        {
            Id = Guid.NewGuid(), Name = "approval-required", SubjectDnRules = "[]", RequireApproval = true,
        });
        var order = ReadyOrder(h);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => h.Service.FinalizeAsync(order.Id, CsrFor("device-01.example.com"), "https://ca.example.com"));

        Assert.Empty(h.Issuance.IssuedCsrIds);
        Assert.Equal(nameof(AcmeOrderStatus.Invalid), (await h.Db.AcmeOrders.FindAsync(order.Id))!.Status);
        Assert.Equal("Rejected", Assert.Single(await h.Db.CertificateRequests.ToListAsync()).Status);

        var audited = Assert.Single(h.Audit.Entries);
        Assert.Equal("FinalizeRefused", audited.Operation);
        Assert.False(audited.Success);
        Assert.Contains("requires approval", audited.Error);
    }

    /// <summary>
    /// A CA with ACME switched off refuses the finalize, and the refusal reaches the ACME audit
    /// tab, which recorded nothing for a failed finalize before.
    /// </summary>
    [Fact]
    public async Task A_ca_with_acme_disabled_refuses_the_finalize_and_the_refusal_is_audited()
    {
        var h = Build();
        var prodConfig = await h.Db.CaProtocolConfigs
            .FirstAsync(c => c.SigningProfileId == h.ProdSigning.Id);
        prodConfig.IsEnabled = false;
        await h.Db.SaveChangesAsync();
        var order = ReadyOrder(h);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => h.Service.FinalizeAsync(order.Id, CsrFor("device-01.example.com"), "https://ca.example.com"));

        Assert.Empty(await h.Db.CertificateRequests.ToListAsync());
        var audited = Assert.Single(h.Audit.Entries);
        Assert.Equal("FinalizeRefused", audited.Operation);
        Assert.False(audited.Success);
        Assert.Equal("ACME is not enabled for CA 'prod'.", audited.Error);
    }
}
