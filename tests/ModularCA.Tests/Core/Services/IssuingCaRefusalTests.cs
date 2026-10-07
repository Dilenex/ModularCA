using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Helpers;
using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models;
using ModularCA.Shared.Models.Config;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// A CA that is revoked (any reason, certificateHold included), outside its validity, disabled,
/// deleted or unregistered does not sign: not on issuance, not on reissue (and so not on
/// auto-renewal, which issues), and not as the parent of an intermediate. SSH CA keys likewise.
/// </summary>
public class IssuingCaRefusalTests
{
    private static X509Certificate BcCa(DateTime notBefore, DateTime notAfter, string dn = "CN=Refusal CA")
    {
        var gen = new ECKeyPairGenerator();
        gen.Init(new ECKeyGenerationParameters(Org.BouncyCastle.Asn1.X9.ECNamedCurveTable.GetOid("P-256"), new SecureRandom()));
        var kp = gen.GenerateKeyPair();
        var cg = new X509V3CertificateGenerator();
        cg.SetSerialNumber(BigInteger.One);
        cg.SetIssuerDN(new X509Name(dn));
        cg.SetSubjectDN(new X509Name(dn));
        cg.SetNotBefore(notBefore);
        cg.SetNotAfter(notAfter);
        cg.SetPublicKey(kp.Public);
        cg.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
        return cg.Generate(new Asn1SignatureFactory("SHA256WITHECDSA", kp.Private, new SecureRandom()));
    }

    internal sealed record Seeded(CertificateEntity CaRow, X509Certificate CaCert, CertificateAuthorityEntity? Ca, Guid CsrId, CertificateEntity? Predecessor);

    public enum CaState { Healthy, Revoked, OnHold, Expired, NotYetValid, Disabled, Deleted, Unregistered }

    internal static Seeded Seed(ModularCADbContext db, CaState state, bool forReissue = false, bool instanceLeaf = false, bool spaceDeleted = false)
    {
        Guid? spaceId = null;
        if (!instanceLeaf)
        {
            var space = new SpaceEntity { Id = Guid.NewGuid(), Name = "Refusal Space", Slug = $"refusal-{Guid.NewGuid():N}", IsDeleted = spaceDeleted };
            db.Spaces.Add(space);
            spaceId = space.Id;
        }
        var caCert = state switch
        {
            CaState.Expired => BcCa(DateTime.UtcNow.AddYears(-3), DateTime.UtcNow.AddDays(-1)),
            CaState.NotYetValid => BcCa(DateTime.UtcNow.AddDays(1), DateTime.UtcNow.AddYears(3)),
            _ => BcCa(DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(3)),
        };
        var caRow = new CertificateEntity
        {
            CertificateId = Guid.NewGuid(),
            SerialNumber = Guid.NewGuid().ToString("N"),
            SubjectDN = caCert.SubjectDN.ToString(),
            Issuer = caCert.IssuerDN.ToString(),
            Pem = CertificateUtilPem(caCert),
            RawCertificate = caCert.GetEncoded(),
            NotBefore = caCert.NotBefore,
            NotAfter = caCert.NotAfter,
            IsCA = true,
            Revoked = state is CaState.Revoked or CaState.OnHold,
            RevocationReason = state switch { CaState.Revoked => "KeyCompromise", CaState.OnHold => "CertificateHold", _ => null },
        };
        caRow.IssuerCertificateId = caRow.CertificateId;
        db.Certificates.Add(caRow);

        CertificateAuthorityEntity? ca = null;
        if (state != CaState.Unregistered)
        {
            ca = new CertificateAuthorityEntity
            {
                Id = Guid.NewGuid(),
                Name = "Refusal CA",
                Label = "refusal",
                SpaceId = spaceId,
                CertificateId = caRow.CertificateId,
                IsEnabled = state != CaState.Disabled,
                IsDeleted = state == CaState.Deleted,
            };
            db.CertificateAuthorities.Add(ca);
        }

        var signingProfile = new SigningProfileEntity { Id = Guid.NewGuid(), Name = "refusal-sp", IssuerId = caRow.CertificateId };
        var certProfile = new CertProfileEntity { Id = Guid.NewGuid(), Name = "TLS Server", KeyUsages = "[]", ExtendedKeyUsages = "[]", ValidityPeriodMax = "P1Y" };
        db.SigningProfiles.Add(signingProfile);
        db.CertProfiles.Add(certProfile);

        CertificateEntity? predecessor = null;
        if (forReissue)
        {
            predecessor = new CertificateEntity
            {
                CertificateId = Guid.NewGuid(),
                SerialNumber = Guid.NewGuid().ToString("N"),
                SubjectDN = "CN=refusal.test",
                Issuer = caRow.SubjectDN,
                Pem = "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----",
                NotBefore = DateTime.UtcNow.AddDays(-10),
                NotAfter = DateTime.UtcNow.AddDays(100),
                IssuerCertificateId = caRow.CertificateId,
            };
            db.Certificates.Add(predecessor);
        }

        var csrId = Guid.NewGuid();
        db.CertificateRequests.Add(new CertRequestEntity
        {
            Id = csrId,
            CSR = CsrPem("refusal.test"),
            Subject = "CN=refusal.test",
            Status = forReissue ? "Issued" : "Approved",
            KeyAlgorithm = "ECDSA",
            KeySize = "P-256",
            SignatureAlgorithm = "SHA256withECDSA",
            CertProfileId = certProfile.Id,
            SigningProfileId = signingProfile.Id,
            IssuedCertificateId = predecessor?.CertificateId,
            IsInfrastructureCert = !instanceLeaf,
        });
        db.SaveChanges();
        return new Seeded(caRow, caCert, ca, csrId, predecessor);
    }

    private static string CertificateUtilPem(X509Certificate cert) => ModularCA.Shared.Utils.CertificateUtil.ExportCertificateToPem(cert);

    private static string CsrPem(string cn)
    {
        var gen = new ECKeyPairGenerator();
        gen.Init(new ECKeyGenerationParameters(Org.BouncyCastle.Asn1.X9.ECNamedCurveTable.GetOid("P-256"), new SecureRandom()));
        AsymmetricCipherKeyPair kp = gen.GenerateKeyPair();
        var req = new Pkcs10CertificationRequest(new Asn1SignatureFactory("SHA256WITHECDSA", kp.Private, new SecureRandom()),
            new X509Name($"CN={cn}"), kp.Public, null);
        using var sw = new StringWriter();
        new Org.BouncyCastle.OpenSsl.PemWriter(sw).WriteObject(req);
        return sw.ToString();
    }

    private sealed class KeystoreStub(X509Certificate ca) : IKeystoreCertificates
    {
        public List<X509Certificate> GetTrustedAuthorities() => [ca];
        public List<CertificateAuthorityIdentity> GetSigners() => [];
        public void RegisterTrustedCert(X509Certificate cert) { }
    }

    /// <summary>
    /// The real service with the collaborators used up to the CA gate; everything past it is null,
    /// so a missing gate fails with a null reference rather than passing quietly.
    /// </summary>
    internal static CertificateIssuanceService Service(ModularCADbContext db, X509Certificate ca) => new(
        db,
        keystore: new KeystoreStub(ca),
        certStore: null!,
        validation: new IssuanceValidationService(db, NullLogger<IssuanceValidationService>.Instance),
        builder: null!,
        profileResolver: new ProfileResolutionService(db, NullLogger<ProfileResolutionService>.Instance),
        ctSubmission: null!,
        certPolicy: null!,
        quotaService: new QuotaService(db, new RecordingAlertService(), NullLogger<QuotaService>.Instance),
        audit: null!,
        certificateAccessService: null!,
        revocation: null!,
        logger: NullLogger<CertificateIssuanceService>.Instance);

    [Theory]
    [InlineData(CaState.Revoked, ErrorCodes.IssuingCaRevoked)]
    [InlineData(CaState.OnHold, ErrorCodes.IssuingCaRevoked)]
    [InlineData(CaState.Expired, ErrorCodes.IssuingCaOutsideValidity)]
    [InlineData(CaState.NotYetValid, ErrorCodes.IssuingCaOutsideValidity)]
    [InlineData(CaState.Disabled, ErrorCodes.IssuingCaDisabled)]
    [InlineData(CaState.Deleted, ErrorCodes.IssuingCaDisabled)]
    [InlineData(CaState.Unregistered, ErrorCodes.IssuingCaUnregistered)]
    public async Task Issuance_refuses_an_unusable_ca(CaState state, string code)
    {
        using var db = InMemoryDbContextFactory.Create();
        var s = Seed(db, state);

        var ex = await Assert.ThrowsAsync<ConfigurationValidationException>(
            () => Service(db, s.CaCert).IssueCertificateAsync(s.CsrId, null, null));

        Assert.Equal(code, ex.Code);
    }

    [Theory]
    [InlineData(CaState.Revoked, ErrorCodes.IssuingCaRevoked)]
    [InlineData(CaState.OnHold, ErrorCodes.IssuingCaRevoked)]
    [InlineData(CaState.Expired, ErrorCodes.IssuingCaOutsideValidity)]
    [InlineData(CaState.Disabled, ErrorCodes.IssuingCaDisabled)]
    [InlineData(CaState.Deleted, ErrorCodes.IssuingCaDisabled)]
    [InlineData(CaState.Unregistered, ErrorCodes.IssuingCaUnregistered)]
    public async Task Reissue_refuses_an_unusable_ca_before_revoking_the_predecessor(CaState state, string code)
    {
        using var db = InMemoryDbContextFactory.Create();
        var s = Seed(db, state, forReissue: true);

        // The revocation service is null: reaching the predecessor's auto-revocation would throw
        // a NullReferenceException instead of the refusal.
        var ex = await Assert.ThrowsAsync<ConfigurationValidationException>(
            () => Service(db, s.CaCert).ReissueCertificateAsync(null, null, s.CsrId, null, null));

        Assert.Equal(code, ex.Code);
        Assert.False((await db.Certificates.AsNoTracking().FirstAsync(c => c.CertificateId == s.Predecessor!.CertificateId)).Revoked);
    }

    [Fact]
    public async Task A_healthy_ca_gets_past_the_gate()
    {
        using var db = InMemoryDbContextFactory.Create();
        var s = Seed(db, CaState.Healthy);

        var ex = await Record.ExceptionAsync(() => Service(db, s.CaCert).IssueCertificateAsync(s.CsrId, null, null));

        Assert.NotNull(ex);
        Assert.False(ex is ConfigurationValidationException c
            && c.Code is ErrorCodes.IssuingCaRevoked or ErrorCodes.IssuingCaOutsideValidity
                or ErrorCodes.IssuingCaDisabled or ErrorCodes.IssuingCaUnregistered,
            ex.Message);
    }

    /// <summary>
    /// A CA whose space no longer exists (soft-deleted, or never there) has no policy to issue
    /// under, so issuance and reissue refuse it rather than issuing with no ceiling.
    /// </summary>
    [Fact]
    public async Task A_ca_whose_space_is_gone_refuses_to_issue()
    {
        using var db = InMemoryDbContextFactory.Create();
        var deleted = Seed(db, CaState.Healthy, spaceDeleted: true);
        var issue = await Assert.ThrowsAsync<ConfigurationValidationException>(() => Service(db, deleted.CaCert).IssueCertificateAsync(deleted.CsrId, null, null));
        Assert.Equal(ErrorCodes.IssuingCaDisabled, issue.Code);
        Assert.Contains("no longer exists", issue.Message);

        using var db2 = InMemoryDbContextFactory.Create();
        var missing = Seed(db2, CaState.Healthy, forReissue: true);
        missing.Ca!.SpaceId = Guid.NewGuid();
        await db2.SaveChangesAsync();
        var reissue = await Assert.ThrowsAsync<ConfigurationValidationException>(
            () => Service(db2, missing.CaCert).ReissueCertificateAsync(null, null, missing.CsrId, null, null));
        Assert.Equal(ErrorCodes.IssuingCaDisabled, reissue.Code);
        Assert.False((await db2.Certificates.AsNoTracking().FirstAsync(c => c.CertificateId == missing.Predecessor!.CertificateId)).Revoked);
    }

    [Fact]
    public async Task The_ca_creation_seam_may_lack_an_authority_row_but_not_a_usable_certificate()
    {
        using var db = InMemoryDbContextFactory.Create();
        var healthy = Seed(db, CaState.Unregistered);
        Assert.Null(await IssuingCaGuard.EnsureUsableAsync(db, healthy.CaRow, healthy.CaCert, requireAuthority: false, DateTime.UtcNow));

        healthy.CaRow.Revoked = true;
        var ex = await Assert.ThrowsAsync<ConfigurationValidationException>(
            () => IssuingCaGuard.EnsureUsableAsync(db, healthy.CaRow, healthy.CaCert, requireAuthority: false, DateTime.UtcNow));
        Assert.Equal(ErrorCodes.IssuingCaRevoked, ex.Code);
    }

    [Fact]
    public async Task The_guard_returns_the_authority_of_a_usable_ca()
    {
        using var db = InMemoryDbContextFactory.Create();
        var s = Seed(db, CaState.Healthy);

        var ca = await IssuingCaGuard.EnsureUsableAsync(db, s.CaRow, s.CaCert, requireAuthority: true, DateTime.UtcNow);

        Assert.Equal(s.Ca!.Id, ca!.Id);
    }

    /// <summary>
    /// A leaf from an instance CA (no space, as the system signing CA's would be) is held to the
    /// instance's own validity ceiling: Refuse refuses an interactive caller and names the
    /// instance, and a protocol caller is shortened instead. A null space is never "no ceiling".
    /// </summary>
    [Fact]
    public async Task An_instance_ca_leaf_is_held_to_the_instance_validity_ceiling()
    {
        using var db = InMemoryDbContextFactory.Create();
        db.SecurityPolicies.Add(new SecurityPolicyEntity { MaxValidityDays = 30, ValidityCeilingBehavior = ModularCA.Shared.Enums.ValidityCeilingBehavior.Refuse });
        var s = Seed(db, CaState.Healthy, instanceLeaf: true);

        var refused = await Assert.ThrowsAsync<ConfigurationValidationException>(() => Service(db, s.CaCert)
            .IssueCertificateAsync(s.CsrId, null, null, ModularCA.Shared.Enums.ValidityCeilingEnforcement.HonourSpacePolicy));
        Assert.Equal(ErrorCodes.ValidityExceedsSpaceCeiling, refused.Code);
        Assert.Contains("30-day ceiling on the instance", refused.Message);

        var shortened = await Record.ExceptionAsync(() => Service(db, s.CaCert)
            .IssueCertificateAsync(s.CsrId, null, null, ModularCA.Shared.Enums.ValidityCeilingEnforcement.AlwaysShorten));
        Assert.False(shortened is ConfigurationValidationException { Code: ErrorCodes.ValidityExceedsSpaceCeiling }, shortened?.Message);

        var preflight = await new ValidityCeilingService(db, new ProfileResolutionService(db, NullLogger<ProfileResolutionService>.Instance))
            .ResolveAsync(db.SigningProfiles.Single().Id, db.CertProfiles.Single().Id);
        Assert.Equal(30, preflight!.SpaceMaxValidityDays);
        Assert.Equal("instance", preflight.SpaceName);
    }

    [Theory]
    [InlineData(false, true, false)]
    [InlineData(true, false, false)]
    [InlineData(true, true, true)]
    public async Task Ssh_signing_refuses_a_disabled_or_deleted_ca(bool keyEnabled, bool caEnabled, bool caDeleted)
    {
        using var db = InMemoryDbContextFactory.Create();
        var ca = new CertificateAuthorityEntity
        {
            Id = Guid.NewGuid(), Name = "ssh", Label = "ssh", SpaceId = Guid.NewGuid(), IsSshCa = true,
            IsEnabled = caEnabled, IsDeleted = caDeleted,
        };
        var key = new SshCaKeyEntity
        {
            Id = Guid.NewGuid(), Name = "ssh", PublicKey = "ssh-ed25519 AAAA", PrivateKeyPath = "unused",
            CertificateAuthorityId = ca.Id, IsUserCa = true, IsHostCa = true, IsEnabled = keyEnabled,
        };
        db.CertificateAuthorities.Add(ca);
        db.SshCaKeys.Add(key);
        db.SaveChanges();
        var signer = new UnaskedSigner();
        var service = new SshCaService(db, signer, new SshAuditLog(), NullLogger<SshCaService>.Instance);
        var pub = SshNode.SubjectKey();

        var user = await Assert.ThrowsAsync<ConfigurationValidationException>(
            () => service.SignUserKeyAsync(key.Id, pub, SshNode.Ci, ["alice"], 1, null));
        var host = await Assert.ThrowsAsync<ConfigurationValidationException>(
            () => service.SignHostKeyAsync(key.Id, pub, ["host.example"], 1));

        Assert.Equal(ErrorCodes.IssuingCaDisabled, user.Code);
        Assert.Equal(ErrorCodes.IssuingCaDisabled, host.Code);
        Assert.Equal(0, signer.Calls);
    }

    /// <summary>
    /// N2 at the choke point every protocol shares: a leaf certificate profile outside the issuing
    /// CA's scope is refused, whether it is bound to an instance CA, belongs to another space, or is
    /// bound to another CA of the same space.
    /// </summary>
    [Theory]
    [InlineData("instance-ca-bound")]
    [InlineData("other-space")]
    [InlineData("other-ca")]
    public async Task Issuance_refuses_a_profile_outside_the_issuing_cas_scope(string scope)
    {
        using var db = InMemoryDbContextFactory.Create();
        var s = Seed(db, CaState.Healthy);
        var profile = db.CertProfiles.Single(p => p.Name == "TLS Server");
        (profile.SpaceId, profile.CertificateAuthorityId) = scope switch
        {
            "instance-ca-bound" => ((Guid?)null, (Guid?)Guid.NewGuid()),
            "other-space" => (Guid.NewGuid(), null),
            _ => (s.Ca!.SpaceId, Guid.NewGuid()),
        };
        db.SaveChanges();

        var ex = await Assert.ThrowsAsync<ConfigurationValidationException>(() => Service(db, s.CaCert).IssueCertificateAsync(s.CsrId, null, null));
        Assert.Equal(ErrorCodes.CertProfileOutOfScope, ex.Code);
    }

    /// <summary>
    /// Reissue re-checks the CSR's profile against the issuing CA's scope, and refuses before the
    /// predecessor is auto-revoked (the revocation service is null, so reaching it would throw).
    /// </summary>
    [Theory]
    [InlineData("instance-ca-bound")]
    [InlineData("other-space")]
    public async Task Reissue_refuses_a_profile_outside_the_issuing_cas_scope_before_revoking(string scope)
    {
        using var db = InMemoryDbContextFactory.Create();
        var s = Seed(db, CaState.Healthy, forReissue: true);
        var profile = db.CertProfiles.Single(p => p.Name == "TLS Server");
        (profile.SpaceId, profile.CertificateAuthorityId) = scope == "other-space"
            ? ((Guid?)Guid.NewGuid(), (Guid?)null)
            : (null, Guid.NewGuid());
        db.SaveChanges();

        var ex = await Assert.ThrowsAsync<ConfigurationValidationException>(
            () => Service(db, s.CaCert).ReissueCertificateAsync(null, null, s.CsrId, null, null));

        Assert.Equal(ErrorCodes.CertProfileOutOfScope, ex.Code);
        Assert.False((await db.Certificates.AsNoTracking().FirstAsync(c => c.CertificateId == s.Predecessor!.CertificateId)).Revoked);
    }

    /// <summary>An unbound profile, the CA's space's, and one bound to the CA itself all pass the scope rule.</summary>
    [Theory]
    [InlineData("unbound")]
    [InlineData("space")]
    [InlineData("own-ca")]
    public async Task Issuance_admits_a_profile_in_the_issuing_cas_scope(string scope)
    {
        using var db = InMemoryDbContextFactory.Create();
        var s = Seed(db, CaState.Healthy);
        var profile = db.CertProfiles.Single(p => p.Name == "TLS Server");
        (profile.SpaceId, profile.CertificateAuthorityId) = scope switch
        {
            "unbound" => ((Guid?)null, (Guid?)null),
            "space" => (s.Ca!.SpaceId, null),
            _ => (s.Ca!.SpaceId, s.Ca.Id),
        };
        db.SaveChanges();

        var ex = await Record.ExceptionAsync(() => Service(db, s.CaCert).IssueCertificateAsync(s.CsrId, null, null));
        Assert.False(ex is ConfigurationValidationException { Code: ErrorCodes.CertProfileOutOfScope }, ex?.ToString());
    }

    /// <summary>
    /// The user and admin CSR paths refuse another scope's profile early (400), before anything is
    /// stored; EST, SCEP, CMP and ACME reach the issuance check above.
    /// </summary>
    [Fact]
    public async Task A_csr_naming_another_scopes_profile_is_refused_before_it_is_stored()
    {
        using var db = InMemoryDbContextFactory.Create();
        var s = Seed(db, CaState.Healthy);
        var other = new CertProfileEntity { Id = Guid.NewGuid(), Name = "Other Space", SpaceId = Guid.NewGuid(), KeyUsages = "[]", ExtendedKeyUsages = "[]" };
        db.CertProfiles.Add(other);
        db.SaveChanges();
        var signingProfile = db.SigningProfiles.Single().Id;
        var csrs = new CsrService(db, new HeldKeyService(db, new Microsoft.AspNetCore.DataProtection.EphemeralDataProtectionProvider(), new RecordingAuditService()));
        var before = db.CertificateRequests.Count();

        var ex = await Assert.ThrowsAsync<ConfigurationValidationException>(() => csrs.UploadCsrAsync(CsrPem("other.test"), other.Id, signingProfile, Guid.NewGuid()));

        Assert.Equal(ErrorCodes.CertProfileOutOfScope, ex.Code);
        Assert.Equal(before, db.CertificateRequests.Count());
    }
}
