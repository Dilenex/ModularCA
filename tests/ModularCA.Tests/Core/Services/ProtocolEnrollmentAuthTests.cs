using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Core.Services;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Utils;
using ModularCA.Tests.TestUtils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Guards the two paths that let an unauthenticated caller obtain a certificate.
/// <para>
/// Both had the same root cause: a protocol treated something the requester controls as proof of
/// identity. SCEP decided a request was a "renewal" — and therefore exempt from the challenge
/// password — by comparing the CMS signer certificate's Issuer DN against a CA subject as
/// strings. CMP gated all three of its protection branches on <c>ProtectionAlg != null</c> with
/// no <c>else</c>, so a message carrying no protection at all fell through to issuance.
/// </para>
/// <para>
/// Neither protocol had any test coverage when these were found, which is why they survived.
/// </para>
/// </summary>
public class ProtocolEnrollmentAuthTests
{
    // ── SCEP: the forged-issuer bypass ───────────────────────────────────────

    /// <summary>
    /// The exact attack. An attacker reads the CA's DN from the anonymous GetCACert endpoint,
    /// self-signs a certificate carrying that DN in its Issuer field and a victim's name in its
    /// Subject, and signs the SCEP PKCSReq with it. The old string comparison accepted this and
    /// skipped the challenge password entirely.
    /// </summary>
    [Fact]
    public void Forged_issuer_certificate_does_not_chain_to_the_CA()
    {
        using var ca = TestCertificates.CreateCa();
        using var forged = TestCertificates.ForgedIssuer(ca);

        // The forgery is convincing to any string-based check...
        Assert.Equal(ca.Subject, forged.Issuer);

        // ...and worthless against a real chain build.
        var chains = X509ChainValidationUtil.ValidateAgainstAnchor(
            forged, ca, requireRevocationCheck: false, out var errors);

        Assert.False(chains);
        Assert.False(string.IsNullOrWhiteSpace(errors));
    }

    /// <summary>
    /// The other half: tightening the check must not break real renewals. A certificate the CA
    /// actually issued still validates, so a legitimate SCEP renewal is unaffected.
    /// </summary>
    [Fact]
    public void Genuinely_issued_certificate_chains_to_the_CA()
    {
        using var ca = TestCertificates.CreateCa();
        using var leaf = TestCertificates.IssueLeaf(ca);

        var chains = X509ChainValidationUtil.ValidateAgainstAnchor(
            leaf, ca, requireRevocationCheck: false, out var errors);

        Assert.True(chains, $"expected a genuinely issued leaf to chain, got: {errors}");
        Assert.Null(errors);
    }

    /// <summary>A certificate from an unrelated CA must not pass either.</summary>
    [Fact]
    public void Certificate_from_a_different_CA_does_not_chain()
    {
        using var ca = TestCertificates.CreateCa("CN=Test Root CA, O=ModularCA");
        using var otherCa = TestCertificates.CreateCa("CN=Some Other CA, O=Elsewhere");
        using var leaf = TestCertificates.IssueLeaf(otherCa);

        Assert.False(X509ChainValidationUtil.ValidateAgainstAnchor(
            leaf, ca, requireRevocationCheck: false, out _));
    }

    // ── CMP: protection is mandatory in both directions ──────────────────────

    private static ModularCA.Database.ModularCADbContext SeededCmp(bool requireSignature)
    {
        var db = InMemoryDbContextFactory.Create();
        var ca = new CertificateAuthorityEntity
        {
            Id = Guid.NewGuid(),
            Name = "cmp-ca",
            Label = "cmp-ca",
        };
        db.CertificateAuthorities.Add(ca);
        db.CaProtocolConfigs.Add(new CaProtocolConfigEntity
        {
            Id = Guid.NewGuid(),
            CaId = ca.Id,
            Protocol = "CMP",
            IsEnabled = true,
            CmpRequireSignature = requireSignature,
        });
        db.SaveChanges();
        return db;
    }

    private static EnrollmentAuthorizationService Service(ModularCA.Database.ModularCADbContext db)
        => new(db, new EnrollmentTokenServiceStub(), NullLogger<EnrollmentAuthorizationService>.Instance);

    /// <summary>
    /// An unprotected CMP message must be refused. This previously returned success whenever
    /// CmpRequireSignature was false — which is the default — leaving proof-of-possession as the
    /// only gate, and an attacker satisfies POP by signing with their own key.
    /// </summary>
    [Theory]
    [InlineData(false)]  // the default configuration
    [InlineData(true)]
    public async Task Unprotected_CMP_request_is_rejected_under_any_configuration(bool requireSignature)
    {
        using var db = SeededCmp(requireSignature);

        var (allowed, error) = await Service(db)
            .ValidateAsync("CMP", "cmp-ca", csrPem: null, clientCert: null, isAuthenticated: false);

        Assert.False(allowed);
        Assert.Contains("protection", error, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The inverse failure, and the reason this was not merely "too permissive": with
    /// CmpRequireSignature set, the old code demanded a client certificate that CmpService always
    /// passes as null, so every request failed even after full signature verification. CMP had no
    /// working secure configuration. A verified message must now be allowed.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Verified_CMP_request_is_allowed_under_any_configuration(bool requireSignature)
    {
        using var db = SeededCmp(requireSignature);

        var (allowed, error) = await Service(db)
            .ValidateAsync("CMP", "cmp-ca", csrPem: null, clientCert: null, isAuthenticated: true);

        Assert.True(allowed, $"expected a protection-verified CMP request to be authorized, got: {error}");
        Assert.Null(error);
    }
}
