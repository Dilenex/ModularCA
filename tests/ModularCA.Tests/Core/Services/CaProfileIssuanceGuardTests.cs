using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Xunit;
using ModularCA.Shared.Errors;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Covers the gate that stops a CA-flagged certificate profile being used on a normal issuance
/// path.
/// <para>
/// The certificate profile id is supplied by the caller on the integration, cert-manager, public
/// enrollment, and protocol (ACME/EST/SCEP/CMP) paths, and was validated only for existence. The
/// profile's <c>IsCaProfile</c> flag then flowed straight into the certificate builder as
/// <c>isCa:</c>, and no check anywhere gated who could name a CA-flagged profile at issuance — the
/// only <c>IsCaProfile</c> filters in the solution sat inside <c>CaCreationService</c>, the
/// legitimate CA-creation path.
/// </para>
/// <para>
/// So <c>POST /api/v1/integration/infra/certificates</c> carrying a CA profile's GUID returned a
/// <c>cA=TRUE</c> certificate signed by the production CA, auto-approved with no approval step.
/// The GUID is not a secret: the profile list endpoint returns every profile with no tenant
/// filter.
/// </para>
/// <para>
/// These tests drive the real <see cref="CertificateIssuanceService"/> against a real
/// <see cref="ModularCADbContext"/> and a real <see cref="ProfileResolutionService"/>, with a
/// real signed CSR. The collaborators that the code reaches only after the gate are left null on
/// purpose: if the gate is removed, execution runs on into them and the test fails rather than
/// passing quietly.
/// </para>
/// </summary>
public class CaProfileIssuanceGuardTests
{
    /// <summary>Tenant filter off; this suite is about the CA flag, not tenancy.</summary>
    private sealed class NoTenantContext : ITenantContext
    {
        public bool HasContext => true;
        public bool IsSystemAdmin => true;
        public IReadOnlySet<Guid> AccessibleTenantIds => new HashSet<Guid>();
        public Guid? UserId => null;
        public void Set(Guid? userId, IReadOnlySet<Guid> accessibleTenantIds, bool isSystemAdmin) { }
    }

    private static ModularCADbContext BuildContext(string dbName)
    {
        var options = new DbContextOptionsBuilder<ModularCADbContext>()
            .UseInMemoryDatabase(dbName)
            .ConfigureWarnings(w => w.Ignore(
                Microsoft.EntityFrameworkCore.Diagnostics.InMemoryEventId.TransactionIgnoredWarning))
            .Options;
        return new ModularCADbContext(options, new NoTenantContext());
    }

    /// <summary>
    /// Builds the service with only the collaborators used before the gate: the database, the
    /// profile resolver, and the logger.
    /// </summary>
    private static CertificateIssuanceService BuildService(ModularCADbContext db)
        => new(
            db,
            keystore: null!,
            certStore: null!,
            validation: null!,
            builder: null!,
            profileResolver: new ProfileResolutionService(db, NullLogger<ProfileResolutionService>.Instance),
            ctSubmission: null!,
            certPolicy: null!,
            quotaService: null!,
            passphraseProvider: null!,
            audit: null!,
            certificateAccessService: null!,
            revocation: null!,
            logger: NullLogger<CertificateIssuanceService>.Instance);

    /// <summary>Generates a real, self-signature-verifiable PKCS#10 CSR.</summary>
    private static string GenerateCsrPem(string commonName)
    {
        var gen = new ECKeyPairGenerator();
        gen.Init(new ECKeyGenerationParameters(
            Org.BouncyCastle.Asn1.X9.ECNamedCurveTable.GetOid("P-256"), new SecureRandom()));
        AsymmetricCipherKeyPair keyPair = gen.GenerateKeyPair();

        var request = new Pkcs10CertificationRequest(
            new Asn1SignatureFactory("SHA256WITHECDSA", keyPair.Private, new SecureRandom()),
            new X509Name($"CN={commonName}"),
            keyPair.Public,
            null);

        using var sw = new StringWriter();
        new Org.BouncyCastle.OpenSsl.PemWriter(sw).WriteObject(request);
        return sw.ToString();
    }

    /// <summary>
    /// Seeds a signing profile, a certificate profile with the given CA flag, and an approved CSR
    /// pointing at both. Returns the CSR id.
    /// </summary>
    private static Guid Seed(ModularCADbContext db, bool isCaProfile, bool withIssuedCertificate = false)
    {
        var signingProfile = new SigningProfileEntity
        {
            Id = Guid.NewGuid(),
            Name = "test-signing-profile",
        };
        db.SigningProfiles.Add(signingProfile);

        var certProfile = new CertProfileEntity
        {
            Id = Guid.NewGuid(),
            Name = isCaProfile ? "Main CA Certificate Profile" : "TLS Server",
            IsCaProfile = isCaProfile,
            KeyUsages = "[]",
            ExtendedKeyUsages = "[]",
        };
        db.CertProfiles.Add(certProfile);

        // Reissue resolves a predecessor certificate before it reaches the profile check, so that
        // path needs one seeded and linked.
        Guid? issuedCertId = null;
        if (withIssuedCertificate)
        {
            issuedCertId = Guid.NewGuid();
            db.Certificates.Add(new CertificateEntity
            {
                CertificateId = issuedCertId.Value,
                SerialNumber = issuedCertId.Value.ToString("N"),
                SubjectDN = "CN=guard.test",
                Issuer = "CN=Test CA",
                Pem = "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----",
            });
        }

        var csrId = Guid.NewGuid();
        db.CertificateRequests.Add(new CertRequestEntity
        {
            Id = csrId,
            CSR = GenerateCsrPem("guard.test"),
            Subject = "CN=guard.test",
            Status = withIssuedCertificate ? "Issued" : "Approved",
            CertProfileId = certProfile.Id,
            SigningProfileId = signingProfile.Id,
            IssuedCertificateId = issuedCertId,
        });

        db.SaveChanges();
        return csrId;
    }

    /// <summary>
    /// The escalation itself. A caller-chosen CA profile must be refused on the ordinary issuance
    /// path, which is the one every protocol and integration endpoint uses.
    /// </summary>
    [Fact]
    public async Task Issuance_refuses_a_ca_flagged_profile()
    {
        using var db = BuildContext(nameof(Issuance_refuses_a_ca_flagged_profile));
        var csrId = Seed(db, isCaProfile: true);

        var ex = await Assert.ThrowsAsync<ConfigurationValidationException>(
            () => BuildService(db).IssueCertificateAsync(csrId, null, null));

        Assert.Contains("CA profile", ex.Message, StringComparison.OrdinalIgnoreCase);
        // Pinned as a 4xx, not merely as "some exception": this refusal is caused by the request
        // naming a CA profile, so collapsing it back to a 500 would be the regression.
        Assert.IsAssignableFrom<RequestValidationException>(ex);
        Assert.Equal(400, ex.Status);
    }

    /// <summary>
    /// The pre-resolved-CA overload is a separate public entry point — used for infrastructure
    /// certificates — and must be gated too, or the escalation just moves one method over.
    /// </summary>
    [Fact]
    public async Task Issuance_with_a_preresolved_ca_refuses_a_ca_flagged_profile()
    {
        using var db = BuildContext(nameof(Issuance_with_a_preresolved_ca_refuses_a_ca_flagged_profile));
        var csrId = Seed(db, isCaProfile: true);

        var ex = await Assert.ThrowsAsync<ConfigurationValidationException>(
            () => BuildService(db).IssueCertificateAsync(csrId, null, null, caCert: null!, caKeyHandle: null!));

        Assert.Contains("CA profile", ex.Message, StringComparison.OrdinalIgnoreCase);
        // Pinned as a 4xx, not merely as "some exception": this refusal is caused by the request
        // naming a CA profile, so collapsing it back to a 500 would be the regression.
        Assert.IsAssignableFrom<RequestValidationException>(ex);
        Assert.Equal(400, ex.Status);
    }

    /// <summary>
    /// Reissue resolves the profile from a certificate or CSR id rather than a profile id, so it
    /// is a second route to the same builder argument and is blocked unconditionally — no
    /// CA-creation caller reissues.
    /// </summary>
    [Fact]
    public async Task Reissue_refuses_a_ca_flagged_profile()
    {
        using var db = BuildContext(nameof(Reissue_refuses_a_ca_flagged_profile));
        var csrId = Seed(db, isCaProfile: true, withIssuedCertificate: true);

        var ex = await Assert.ThrowsAsync<ConfigurationValidationException>(
            () => BuildService(db).ReissueCertificateAsync(null, null, csrId, null, null));

        Assert.Contains("CA profile", ex.Message, StringComparison.OrdinalIgnoreCase);
        // Pinned as a 4xx, not merely as "some exception": this refusal is caused by the request
        // naming a CA profile, so collapsing it back to a 500 would be the regression.
        Assert.IsAssignableFrom<RequestValidationException>(ex);
        Assert.Equal(400, ex.Status);
    }

    /// <summary>
    /// The gate must be the CA flag and nothing else. A normal profile has to get past it — this
    /// is what stops the fix from degenerating into "issuance always throws", which would satisfy
    /// the tests above while breaking the product.
    /// </summary>
    [Fact]
    public async Task A_normal_profile_is_not_blocked_by_the_ca_gate()
    {
        using var db = BuildContext(nameof(A_normal_profile_is_not_blocked_by_the_ca_gate));
        var csrId = Seed(db, isCaProfile: false);

        // Issuance still cannot complete here — the collaborators past the gate are null — but it
        // must fail for some later reason, never with the CA-profile refusal.
        var ex = await Record.ExceptionAsync(
            () => BuildService(db).IssueCertificateAsync(csrId, null, null));

        Assert.NotNull(ex);
        Assert.DoesNotContain("CA profile", ex!.Message, StringComparison.OrdinalIgnoreCase);
    }
}
