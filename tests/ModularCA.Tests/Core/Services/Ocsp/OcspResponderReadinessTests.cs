using ModularCA.Core.Services.Ocsp;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Utils;
using ModularCA.Tests.TestUtils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Xunit;

namespace ModularCA.Tests.Core.Services.Ocsp;

/// <summary>
/// A CA whose responder certificate cannot be used answers every OCSP request "unauthorized",
/// and nothing said so: two CAs on a staging host had refused OCSP for three weeks behind a
/// green System Health page, because their responder certificates were issued from a profile
/// that listed no OCSP signing usage. These hold the report to what the responder actually does.
/// </summary>
public class OcspResponderReadinessTests
{
    private static readonly DateTime Now = new(2027, 6, 1, 0, 0, 0, DateTimeKind.Utc);
    private static readonly DerObjectIdentifier NoCheck = new("1.3.6.1.5.5.7.48.1.5");

    private static X509Certificate Responder(TestCaMaterial ca, bool ocspSigning = true, bool noCheck = true,
        DateTime? notBefore = null, DateTime? notAfter = null)
    {
        var gen = new X509V3CertificateGenerator();
        gen.SetSerialNumber(BigInteger.ValueOf(Random.Shared.NextInt64(2, long.MaxValue)));
        gen.SetIssuerDN(new X509Name(ca.SubjectDn));
        gen.SetSubjectDN(new X509Name("CN=Test OCSP Responder"));
        gen.SetNotBefore(notBefore ?? new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        gen.SetNotAfter(notAfter ?? new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        gen.SetPublicKey(ca.KeyPair.Public);
        if (ocspSigning)
            gen.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeID.id_kp_OCSPSigning));
        if (noCheck)
            gen.AddExtension(NoCheck, false, DerNull.Instance);
        return gen.Generate(new Asn1SignatureFactory("SHA256WITHRSA", ca.KeyPair.Private, new SecureRandom()));
    }

    [Fact]
    public void A_responder_with_the_usage_inside_its_window_has_no_problem()
    {
        var ca = TestCaMaterial.CreateCa();
        Assert.Null(OcspResponderRules.Problem(Responder(ca), requireNoCheck: true, Now));
    }

    [Fact]
    public void A_responder_without_the_ocsp_signing_usage_is_named_as_the_problem()
    {
        var ca = TestCaMaterial.CreateCa();
        var problem = OcspResponderRules.Problem(Responder(ca, ocspSigning: false), requireNoCheck: false, Now);
        Assert.Contains("OCSP signing extended key usage", problem);
    }

    [Fact]
    public void A_missing_no_check_extension_is_a_problem_only_when_the_policy_requires_it()
    {
        var ca = TestCaMaterial.CreateCa();
        var responder = Responder(ca, noCheck: false);
        Assert.Null(OcspResponderRules.Problem(responder, requireNoCheck: false, Now));
        Assert.Contains("no-check", OcspResponderRules.Problem(responder, requireNoCheck: true, Now));
    }

    [Fact]
    public void An_expired_or_not_yet_valid_responder_says_when()
    {
        var ca = TestCaMaterial.CreateCa();
        var expired = Responder(ca, notAfter: new DateTime(2027, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        var early = Responder(ca, notBefore: new DateTime(2028, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        Assert.Contains("expired on 2027-01-01", OcspResponderRules.Problem(expired, false, Now));
        Assert.Contains("not valid until 2028-01-01", OcspResponderRules.Problem(early, false, Now));
    }

    // ---- per-CA assessment ---------------------------------------------------------------

    private sealed class Flags(bool ocsp) : IFeatureFlagService
    {
        public bool IsEnabled(string flagName) => ocsp && flagName == "OCSP.Enabled";
        public string? GetValue(string flagName) => null;
        public (bool Enabled, string? Value)? Get(string flagName) => (IsEnabled(flagName), null);
        public void InvalidateCache() { }
    }

    private static CertificateEntity Row(X509Certificate cert, bool isCa, bool revoked = false) => new()
    {
        CertificateId = Guid.NewGuid(),
        SerialNumber = CertificateUtil.FormatSerialNumber(cert.SerialNumber),
        SubjectDN = cert.SubjectDN.ToString(),
        Issuer = cert.IssuerDN.ToString(),
        IsCA = isCa,
        Revoked = revoked,
        Pem = CertificateUtil.ConvertDerToPem(cert.GetEncoded(), "CERTIFICATE"),
        RawCertificate = cert.GetEncoded(),
        NotBefore = cert.NotBefore.ToUniversalTime(),
        NotAfter = cert.NotAfter.ToUniversalTime(),
    };

    /// <summary>Seeds one CA; <paramref name="responder"/> builds its responder row, or null for none.</summary>
    private static Guid SeedCa(ModularCADbContext db, TestCaMaterial ca, string name,
        Func<CertificateEntity?>? responder = null, bool enabled = true, bool ocspSwitchedOff = false, Guid? danglingResponderId = null)
    {
        var caRow = Row(ca.Certificate, isCa: true);
        db.Certificates.Add(caRow);
        var responderRow = responder?.Invoke();
        if (responderRow != null)
            db.Certificates.Add(responderRow);

        var id = Guid.NewGuid();
        db.CertificateAuthorities.Add(new CertificateAuthorityEntity
        {
            Id = id,
            Name = name,
            Label = name,
            IsEnabled = enabled,
            CertificateId = caRow.CertificateId,
            OcspResponderCertificateId = responderRow?.CertificateId ?? danglingResponderId,
        });
        if (ocspSwitchedOff)
            db.CaProtocolConfigs.Add(new CaProtocolConfigEntity { Id = Guid.NewGuid(), CaId = id, Protocol = "OCSP", IsEnabled = false });
        db.SaveChanges();
        return id;
    }

    private static OcspResponderReadiness Readiness(ModularCADbContext db, SecurityPolicyEntity? policy = null, bool ocspServed = true)
        => new(db, new StubSecurityPolicyService(policy ?? new SecurityPolicyEntity()), new Flags(ocspServed));

    [Fact]
    public async Task Each_ca_is_reported_as_the_responder_would_treat_it()
    {
        var db = InMemoryDbContextFactory.Create($"ocsp-ready-{Guid.NewGuid():N}");
        var ca = TestCaMaterial.CreateCa();

        var good = SeedCa(db, ca, "good", () => Row(Responder(ca), isCa: false));
        var noUsage = SeedCa(db, ca, "no-usage", () => Row(Responder(ca, ocspSigning: false), isCa: false));
        var revoked = SeedCa(db, ca, "revoked", () => Row(Responder(ca), isCa: false, revoked: true));
        var none = SeedCa(db, ca, "none");
        var gone = SeedCa(db, ca, "gone", danglingResponderId: Guid.NewGuid());

        var states = await Readiness(db).AssessAsync();

        Assert.Equal(("delegated", null), (states[good].Mode, states[good].Problem));
        Assert.Equal("CN=Test OCSP Responder", states[good].ResponderSubject);
        Assert.False(string.IsNullOrEmpty(states[good].ResponderSerial));
        Assert.Equal(new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc), states[good].ResponderNotAfter);
        Assert.Null(states[none].ResponderSerial);
        Assert.Null(states[gone].ResponderSerial);
        Assert.Contains("OCSP signing extended key usage", states[noUsage].Problem);
        Assert.Contains("revoked", states[revoked].Problem);
        Assert.Equal("none", states[none].Mode);
        Assert.Contains("no OCSP responder certificate", states[none].Problem);
        Assert.Contains("no longer exists", states[gone].Problem);
    }

    [Fact]
    public async Task A_ca_without_a_responder_is_fine_when_the_policy_lets_the_ca_key_sign()
    {
        var db = InMemoryDbContextFactory.Create($"ocsp-ready-{Guid.NewGuid():N}");
        var id = SeedCa(db, TestCaMaterial.CreateCa(), "direct");

        var states = await Readiness(db, new SecurityPolicyEntity { AllowCaDirectSigning = true }).AssessAsync();

        Assert.Equal(("direct", null), (states[id].Mode, states[id].Problem));
    }

    [Fact]
    public async Task Nothing_is_expected_of_a_ca_that_does_not_serve_ocsp()
    {
        var db = InMemoryDbContextFactory.Create($"ocsp-ready-{Guid.NewGuid():N}");
        var ca = TestCaMaterial.CreateCa();
        var switchedOff = SeedCa(db, ca, "switched-off", () => Row(Responder(ca, ocspSigning: false), isCa: false), ocspSwitchedOff: true);
        var disabled = SeedCa(db, ca, "disabled", enabled: false);

        var states = await Readiness(db).AssessAsync();
        Assert.Equal(("off", null), (states[switchedOff].Mode, states[switchedOff].Problem));
        Assert.False(states.ContainsKey(disabled));

        var whenOcspIsOff = await Readiness(db, ocspServed: false).AssessAsync();
        Assert.All(whenOcspIsOff.Values, s => Assert.Equal("off", s.Mode));
    }

    [Fact]
    public async Task Only_the_named_cas_are_assessed_when_a_list_is_given()
    {
        var db = InMemoryDbContextFactory.Create($"ocsp-ready-{Guid.NewGuid():N}");
        var ca = TestCaMaterial.CreateCa();
        var wanted = SeedCa(db, ca, "wanted");
        SeedCa(db, ca, "other");

        var states = await Readiness(db).AssessAsync(new[] { wanted });

        Assert.Equal(new[] { wanted }, states.Keys);
    }
}
