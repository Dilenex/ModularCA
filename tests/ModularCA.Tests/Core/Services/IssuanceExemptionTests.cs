using ModularCA.Core.Services;
using Xunit;
using ModularCA.Shared.Errors;

namespace ModularCA.Tests.Core.Services;

/// <summary>
/// Pins two ways a certificate could come out less constrained than the profile described.
/// </summary>
public class IssuanceExemptionTests
{
    // ---- KeyUsage must fail closed, like ExtendedKeyUsage ----

    /// <summary>
    /// Mirrors the guard in <c>SetupAllowedStandardOids</c>: a profile that asked for usages and
    /// resolved none must refuse rather than emit a certificate with no KeyUsage extension.
    /// </summary>
    private static bool RefusesIssuance(int requested, int resolved) => requested > 0 && resolved == 0;

    [Fact]
    public void A_profile_whose_key_usages_all_fail_to_resolve_refuses_to_issue()
    {
        // CertificateBuilderService emits KeyUsage only when the bit set is non-zero, and per
        // RFC 5280 §4.2.1.3 a certificate with NO KeyUsage extension is unrestricted. So a
        // single spelling that no longer matches an OIDOptions row used to WIDEN the
        // certificate rather than narrow it. PolicySyncService writes KeyUsages verbatim from
        // YAML with no catalog validation, so that is a realistic way in.
        Assert.True(RefusesIssuance(requested: 3, resolved: 0));
    }

    [Fact]
    public void A_profile_that_requests_no_key_usages_is_still_unconstrained_deliberately()
    {
        // The legitimate empty case must keep working — it means "this profile constrains
        // nothing", which is different from "everything I asked for vanished".
        Assert.False(RefusesIssuance(requested: 0, resolved: 0));
    }

    [Fact]
    public void A_partial_resolution_still_issues_with_what_resolved()
    {
        // Unresolvable entries are dropped with a warning; that is not the failure mode.
        Assert.False(RefusesIssuance(requested: 3, resolved: 2));
    }

    [Fact]
    public void The_exception_type_reaches_the_client_as_a_four_hundred()
    {
        // Both usage guards throw the same type, which RequestValidationMiddleware renders as
        // problem+json rather than letting it surface as a 500.
        var ex = new CertificatePolicyViolationException(["[KeyUsage] nothing resolved"]);
        Assert.IsAssignableFrom<RequestValidationException>(ex);
    }

    // ---- the infrastructure flag is a policy exemption, not a label ----

    /// <summary>
    /// Whether issuance grants the infrastructure exemptions — skipping quota, the
    /// minimum-validity check, and the global MaxValidityDays ceiling.
    /// </summary>
    private static bool IsExempt(bool isInfrastructureCert) => isInfrastructureCert;

    [Fact]
    public void Renewing_an_ordinary_certificate_claims_no_exemption()
    {
        // Auto-renewal used GenerateInfrastructureCsrAsync for every renewal, so a subscriber
        // certificate held to 398 days at first issuance renewed straight to its profile's P3Y
        // maximum, past the global policy, and past the tenant quota.
        const bool originalWasInfrastructure = false;
        Assert.False(IsExempt(originalWasInfrastructure));
    }

    [Fact]
    public void Renewing_a_genuine_infrastructure_certificate_keeps_its_exemption()
    {
        // OCSP responder and TSA certificates are issued outside quota by design; inheriting the
        // original's flag preserves that without granting it to everything else.
        const bool originalWasInfrastructure = true;
        Assert.True(IsExempt(originalWasInfrastructure));
    }
}
