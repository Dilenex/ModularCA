using ModularCA.Shared.Enums;
using ModularCA.Shared.Utils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// The tenant validity ceiling's Shorten / Refuse behaviour and its three exemptions, covered
/// through <see cref="CertificateValidityUtil.DecideValidityCeiling"/> — the real decision
/// <c>CertificateIssuanceService.ApplyTenantValidityCeiling</c> calls, not a restatement of it.
/// <para>
/// Two properties here are load-bearing well beyond their size.
/// </para>
/// <para>
/// <b>Refusal must never reach an enrollment protocol.</b> ACME, EST, SCEP, CMP and both renewal
/// jobs derive their requested expiry from the certificate profile with no knowledge of the
/// tenant, so a refusal on those paths would fail every enrollment and every renewal whose profile
/// out-reaches its tenant — silently, at renewal time, over a condition the client can neither see
/// nor fix. Flipping one tenant setting would take a working fleet offline. That is why refusal
/// needs BOTH the tenant's behaviour and the caller's enforcement mode, and why the enforcement
/// default is the shortening one.
/// </para>
/// <para>
/// <b>A CA certificate must never be shortened.</b> Turning a ten-year intermediate into a
/// two-year one takes every certificate beneath it down when it expires, years after anyone
/// remembers the setting was changed. It was previously exempt only incidentally — CA creation
/// happens to build its CSR through the infrastructure helper, which defaults
/// <c>isInfrastructure: true</c> — so a CA-creation path that forgot that flag would have been
/// shortened without a word.
/// </para>
/// </summary>
public class ValidityCeilingBehaviorTests
{
    private static readonly DateTime NotBefore = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    private static readonly DateTime FiveYears = NotBefore.AddDays(1825);
    private const int TwoYearCeiling = 730;

    private static ValidityCeilingDecision Decide(
        ValidityCeilingBehavior behavior,
        ValidityCeilingEnforcement enforcement,
        bool isInfrastructureCert = false,
        bool isCaCertificate = false,
        DateTime? notAfter = null,
        int maxValidityDays = TwoYearCeiling)
        => CertificateValidityUtil.DecideValidityCeiling(
            notAfter ?? FiveYears, NotBefore, maxValidityDays,
            behavior, enforcement, isInfrastructureCert, isCaCertificate);

    [Fact]
    public void An_admin_request_over_the_ceiling_is_refused_when_the_tenant_refuses()
    {
        var decision = Decide(ValidityCeilingBehavior.Refuse, ValidityCeilingEnforcement.HonourTenantPolicy);

        Assert.Equal(ValidityCeilingOutcome.Refused, decision.Outcome);
    }

    [Fact]
    public void A_protocol_enrollment_over_the_ceiling_is_shortened_even_when_the_tenant_refuses()
    {
        // The asymmetry this whole feature turns on. An ACME client asks for what the certificate
        // profile allows, cannot discover the tenant's ceiling, and could do nothing about a
        // refusal if it did — so the tenant setting must not reach it.
        var decision = Decide(ValidityCeilingBehavior.Refuse, ValidityCeilingEnforcement.AlwaysShorten);

        Assert.Equal(ValidityCeilingOutcome.Shortened, decision.Outcome);
        Assert.Equal(NotBefore.AddDays(TwoYearCeiling), decision.NotAfter);
    }

    [Fact]
    public void An_admin_request_over_the_ceiling_is_shortened_when_the_tenant_shortens()
    {
        // Shorten is the default and the behaviour every tenant had before this setting existed, so
        // an interactive caller against an unchanged tenant must still get a certificate.
        var decision = Decide(ValidityCeilingBehavior.Shorten, ValidityCeilingEnforcement.HonourTenantPolicy);

        Assert.Equal(ValidityCeilingOutcome.Shortened, decision.Outcome);
        Assert.Equal(NotBefore.AddDays(TwoYearCeiling), decision.NotAfter);
    }

    [Theory]
    [InlineData(ValidityCeilingBehavior.Shorten, ValidityCeilingEnforcement.AlwaysShorten)]
    [InlineData(ValidityCeilingBehavior.Shorten, ValidityCeilingEnforcement.HonourTenantPolicy)]
    [InlineData(ValidityCeilingBehavior.Refuse, ValidityCeilingEnforcement.AlwaysShorten)]
    public void Refusal_requires_both_the_tenant_behaviour_and_the_callers_enforcement(
        ValidityCeilingBehavior behavior, ValidityCeilingEnforcement enforcement)
    {
        // Every combination except (Refuse, HonourTenantPolicy) issues something. An "or" here
        // instead of an "and" would make either half sufficient, and the half that reaches ACME is
        // the tenant's.
        Assert.NotEqual(ValidityCeilingOutcome.Refused, Decide(behavior, enforcement).Outcome);
    }

    [Fact]
    public void A_request_within_the_ceiling_is_untouched_even_on_a_refusing_tenant()
    {
        // Refuse is not a floor and not a trap: asking for less than the tenant permits is always
        // fine, and must not be reported as an adjustment.
        var withinCeiling = NotBefore.AddDays(365);

        var decision = Decide(
            ValidityCeilingBehavior.Refuse, ValidityCeilingEnforcement.HonourTenantPolicy,
            notAfter: withinCeiling);

        Assert.Equal(ValidityCeilingOutcome.Unchanged, decision.Outcome);
        Assert.Equal(withinCeiling, decision.NotAfter);
    }

    [Fact]
    public void A_tenant_with_no_ceiling_never_refuses_however_it_is_configured()
    {
        // 0 means unlimited, and it is the value the migration gives every existing tenant. A
        // tenant that was switched to Refuse before any ceiling was typed in must not refuse
        // everything.
        var decision = Decide(
            ValidityCeilingBehavior.Refuse, ValidityCeilingEnforcement.HonourTenantPolicy,
            maxValidityDays: 0);

        Assert.Equal(ValidityCeilingOutcome.Unchanged, decision.Outcome);
        Assert.Equal(FiveYears, decision.NotAfter);
    }

    [Fact]
    public void A_ca_certificate_is_exempt_and_is_neither_shortened_nor_refused()
    {
        // The worst outcome this feature can produce. A ten-year intermediate reissued as a
        // two-year one takes down everything under it, years later.
        var decision = Decide(
            ValidityCeilingBehavior.Refuse, ValidityCeilingEnforcement.HonourTenantPolicy,
            isCaCertificate: true);

        Assert.Equal(ValidityCeilingOutcome.Unchanged, decision.Outcome);
        Assert.Equal(FiveYears, decision.NotAfter);
    }

    [Fact]
    public void A_ca_certificate_is_exempt_even_when_the_tenant_merely_shortens()
    {
        // The exemption is about what the certificate IS, not about how the tenant is configured.
        // Shorten is the common case, so this is the path a real CA creation would take.
        var decision = Decide(
            ValidityCeilingBehavior.Shorten, ValidityCeilingEnforcement.AlwaysShorten,
            isCaCertificate: true);

        Assert.Equal(ValidityCeilingOutcome.Unchanged, decision.Outcome);
        Assert.Equal(FiveYears, decision.NotAfter);
    }

    [Fact]
    public void An_infrastructure_certificate_is_exempt_and_is_neither_shortened_nor_refused()
    {
        // TSA, OCSP and Web TLS certificates are artifacts of the CA's own lifecycle rather than
        // subscriber certificates, consistent with the quota and policy checks they already skip.
        var decision = Decide(
            ValidityCeilingBehavior.Refuse, ValidityCeilingEnforcement.HonourTenantPolicy,
            isInfrastructureCert: true);

        Assert.Equal(ValidityCeilingOutcome.Unchanged, decision.Outcome);
        Assert.Equal(FiveYears, decision.NotAfter);
    }

    [Fact]
    public void An_exemption_is_checked_before_the_ceiling_rather_than_after_it()
    {
        // Ordering matters: an exemption evaluated after the clamp would still refuse, because the
        // refusal is what the clamp decides to do. Exempt inputs must produce the requested expiry
        // verbatim, not the ceiling.
        var exempt = Decide(
            ValidityCeilingBehavior.Refuse, ValidityCeilingEnforcement.HonourTenantPolicy,
            isCaCertificate: true, maxValidityDays: 1);

        Assert.Equal(ValidityCeilingOutcome.Unchanged, exempt.Outcome);
        Assert.Equal(FiveYears, exempt.NotAfter);
    }
}
