namespace ModularCA.Shared.Models.Issuance;

/// <summary>
/// Which of the three layers that can limit a certificate's lifetime actually decided it.
/// </summary>
/// <remarks>
/// Naming the binding layer is the whole value of the pre-flight. "Max 730 days" on its own sends
/// an operator to the wrong screen half the time — they lengthen the certificate profile, reload,
/// and get the same 730 days because it was the tenant all along.
/// </remarks>
public enum ValidityCeilingSource
{
    /// <summary>
    /// The certificate profile's <c>ValidityPeriodMax</c> bound it. Also the answer when nothing
    /// is narrower, because every issuance path defaults this to <c>P1Y</c> when it is unset —
    /// there is no "no ceiling at all" state for this layer.
    /// </summary>
    CertProfile = 0,

    /// <summary>The tenant's <c>MaxValidityDays</c> bound it.</summary>
    Tenant = 1,

    /// <summary>The issuing CA's own <c>notAfter</c> bound it; a leaf cannot outlive its issuer.</summary>
    IssuingCa = 2,
}

/// <summary>
/// The effective maximum validity for one (signing profile, cert profile) pairing, and which
/// layer produced it.
/// </summary>
/// <param name="NotBefore">The start the ceiling was measured against.</param>
/// <param name="EffectiveNotAfter">The latest expiry that would survive issuance unchanged.</param>
/// <param name="EffectiveMaxDays">
/// <paramref name="EffectiveNotAfter"/> expressed as whole days from <paramref name="NotBefore"/>,
/// rounded down. Down rather than nearest: a number an operator types back into a validity field
/// must not land past the ceiling it was supposed to describe.
/// </param>
/// <param name="BoundBy">The narrowest layer.</param>
/// <param name="CertProfileNotAfter">Where the cert profile alone would have put the expiry.</param>
/// <param name="TenantNotAfter">Where the tenant alone would have, or null when it is unlimited.</param>
/// <param name="IssuingCaNotAfter">
/// Where the issuing CA alone would have — its own expiry less the clock-skew margin — or null
/// when the CA could not be resolved.
/// </param>
public sealed record ValidityCeilingResolution(
    DateTime NotBefore,
    DateTime EffectiveNotAfter,
    int EffectiveMaxDays,
    ValidityCeilingSource BoundBy,
    DateTime CertProfileNotAfter,
    DateTime? TenantNotAfter,
    DateTime? IssuingCaNotAfter);
