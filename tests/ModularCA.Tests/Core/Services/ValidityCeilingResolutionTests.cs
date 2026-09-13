using ModularCA.Shared.Models.Issuance;
using ModularCA.Shared.Utils;
using Xunit;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// The pre-flight resolution behind the Issue Certificate form's "Max N days — capped by …"
/// notice: <see cref="CertificateValidityUtil.ResolveCeiling"/>.
/// <para>
/// The point of the pre-flight is that the clamp never fires for an operator at a keyboard. Before
/// it, nothing told them about any ceiling — they picked profiles, typed a Not After, submitted,
/// and learned afterwards, from a diagnostic on a certificate that already exists and already has a
/// serial, that they got something shorter. Fixing that means revoke and reissue.
/// </para>
/// <para>
/// Which is why the layer identity is tested as hard as the number. "Max 730 days" on its own sends
/// an operator to whichever screen they guess first; naming the wrong layer sends them to the wrong
/// one with confidence, which is worse than saying nothing.
/// </para>
/// </summary>
public class ValidityCeilingResolutionTests
{
    private static readonly DateTime Now = new(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);
    private static readonly DateTime NotBefore = Now - CertificateValidityUtil.SkewAllowance;

    private static ValidityCeilingResolution Resolve(
        TimeSpan certProfileMax, int tenantMaxDays, DateTime? caNotAfter)
        => CertificateValidityUtil.ResolveCeiling(NotBefore, Now, certProfileMax, tenantMaxDays, caNotAfter);

    [Fact]
    public void With_no_tenant_ceiling_and_a_long_lived_ca_the_cert_profile_binds()
    {
        var result = Resolve(TimeSpan.FromDays(365), tenantMaxDays: 0, caNotAfter: Now.AddYears(10));

        Assert.Equal(ValidityCeilingSource.CertProfile, result.BoundBy);
        Assert.Equal(Now.AddDays(365), result.EffectiveNotAfter);
    }

    [Fact]
    public void A_tenant_ceiling_narrower_than_the_profile_binds_and_is_named()
    {
        // The case the notice exists for: a profile allowing three years against a tenant capping
        // two. Reporting "certificate profile" here would send the operator to edit a profile that
        // is not the constraint.
        var result = Resolve(TimeSpan.FromDays(1095), tenantMaxDays: 730, caNotAfter: Now.AddYears(10));

        Assert.Equal(ValidityCeilingSource.Tenant, result.BoundBy);
        Assert.Equal(NotBefore.AddDays(730), result.EffectiveNotAfter);
    }

    [Fact]
    public void An_issuing_ca_expiring_first_binds_and_is_named()
    {
        // Not a policy ceiling, and the only one of the three that moves on its own as the CA ages.
        // The remedy is renewing the CA, which has nothing in common with the other two.
        var caNotAfter = Now.AddDays(100);

        var result = Resolve(TimeSpan.FromDays(1095), tenantMaxDays: 730, caNotAfter: caNotAfter);

        Assert.Equal(ValidityCeilingSource.IssuingCa, result.BoundBy);
        Assert.Equal(caNotAfter - CertificateValidityUtil.SkewAllowance, result.EffectiveNotAfter);
    }

    [Fact]
    public void The_ca_ceiling_carries_the_same_skew_margin_issuance_applies()
    {
        // Issuance clamps to notAfter minus five minutes. A pre-flight that promised the CA's bare
        // notAfter would be five minutes optimistic, and the clamp it exists to prevent would fire
        // on precisely the request that took it at its word.
        var caNotAfter = Now.AddDays(10);

        var result = Resolve(TimeSpan.FromDays(3650), tenantMaxDays: 0, caNotAfter: caNotAfter);

        Assert.Equal(caNotAfter - TimeSpan.FromMinutes(5), result.EffectiveNotAfter);
    }

    [Fact]
    public void A_zero_tenant_ceiling_is_unlimited_and_cannot_bind()
    {
        // 0 means unlimited, matching the quota fields beside it, and it is what every existing
        // tenant carries after the migration. Reading it as a ceiling of zero would report every
        // installation as capped at its notBefore.
        var result = Resolve(TimeSpan.FromDays(365), tenantMaxDays: 0, caNotAfter: Now.AddYears(10));

        Assert.Equal(ValidityCeilingSource.CertProfile, result.BoundBy);
        Assert.Null(result.TenantNotAfter);
    }

    [Fact]
    public void A_missing_issuing_ca_cannot_bind()
    {
        // A system-wide signing profile genuinely has no CA behind it. That layer must drop out
        // rather than be treated as an expiry of "now".
        var result = Resolve(TimeSpan.FromDays(365), tenantMaxDays: 0, caNotAfter: null);

        Assert.Equal(ValidityCeilingSource.CertProfile, result.BoundBy);
        Assert.Null(result.IssuingCaNotAfter);
        Assert.Equal(Now.AddDays(365), result.EffectiveNotAfter);
    }

    [Fact]
    public void A_tie_is_attributed_to_the_wider_scoped_layer()
    {
        // A layer only displaces another when STRICTLY narrower. Telling an operator their
        // certificate is capped by the issuing CA, for a date the certificate profile would have
        // produced anyway, sends them to renew a CA that is not the problem.
        var shared = NotBefore.AddDays(730);

        var result = CertificateValidityUtil.ResolveCeiling(
            NotBefore, NotBefore, TimeSpan.FromDays(730),
            tenantMaxValidityDays: 730,
            issuingCaNotAfter: shared + CertificateValidityUtil.SkewAllowance);

        Assert.Equal(ValidityCeilingSource.CertProfile, result.BoundBy);
        Assert.Equal(shared, result.EffectiveNotAfter);
    }

    [Fact]
    public void Every_layers_own_answer_is_reported_alongside_the_winner()
    {
        // The notice says "capped by tenant 'X' (profile allows 3y)", and that aside is what tells
        // an operator whether raising the cap is even possible.
        var caNotAfter = Now.AddYears(10);

        var result = Resolve(TimeSpan.FromDays(1095), tenantMaxDays: 730, caNotAfter: caNotAfter);

        Assert.Equal(Now.AddDays(1095), result.CertProfileNotAfter);
        Assert.Equal(NotBefore.AddDays(730), result.TenantNotAfter);
        Assert.Equal(caNotAfter - CertificateValidityUtil.SkewAllowance, result.IssuingCaNotAfter);
    }

    [Fact]
    public void The_day_count_rounds_down_rather_than_to_nearest()
    {
        // The number is shown as "Max N days" and an operator may type it straight back into a
        // validity field. Rounding up would land them past the ceiling the figure described.
        var result = CertificateValidityUtil.ResolveCeiling(
            NotBefore, Now, TimeSpan.FromDays(365).Add(TimeSpan.FromHours(23)),
            tenantMaxValidityDays: 0, issuingCaNotAfter: null);

        Assert.Equal(365, result.EffectiveMaxDays);
    }

    [Fact]
    public void An_already_expired_issuing_ca_reports_zero_days_rather_than_a_negative_count()
    {
        // The CA cannot issue at all, which is a real state. "-40 days" in a form field reads as a
        // bug in the page rather than as a fact about the CA.
        var result = Resolve(TimeSpan.FromDays(365), tenantMaxDays: 0, caNotAfter: Now.AddDays(-40));

        Assert.Equal(ValidityCeilingSource.IssuingCa, result.BoundBy);
        Assert.Equal(0, result.EffectiveMaxDays);
    }

    [Fact]
    public void The_tenant_ceiling_is_measured_from_notBefore_and_the_profile_from_now()
    {
        // They genuinely differ in the code this mirrors: ClampToValidityCeiling measures from
        // notBefore, while NotBeyondMaximumDate and the timeMax default both measure from now.
        // Collapsing the two into one rule would promise dates issuance then clamps.
        var backdated = Now.AddDays(-30);

        var result = CertificateValidityUtil.ResolveCeiling(
            backdated, Now, TimeSpan.FromDays(365), tenantMaxValidityDays: 365, issuingCaNotAfter: null);

        Assert.Equal(ValidityCeilingSource.Tenant, result.BoundBy);
        Assert.Equal(backdated.AddDays(365), result.EffectiveNotAfter);
    }
}
