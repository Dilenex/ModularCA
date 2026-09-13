using System.Reflection;

namespace ModularCA.Shared.Errors;

/// <summary>
/// Stable identifiers for the failure classes this CA can refuse a request with.
/// </summary>
/// <remarks>
/// <para>
/// A message explains; a code identifies. The two do different jobs and the codebase needed
/// both. Prose gets reworded — for clarity, for tone, because someone fixed a typo — and every
/// rewording breaks the runbook entry, the support ticket search, and the log filter that
/// matched on it. A code survives all of that, which is what makes it worth pasting into a
/// ticket and searching a wiki for.
/// </para>
/// <para>
/// Format is <c>MCA-AREA-NNN</c>. The area says which subsystem refused:
/// </para>
/// <list type="bullet">
///   <item><description><c>REQ</c> — the request content itself is malformed or unusable.</description></item>
///   <item><description><c>CFG</c> — the request is well-formed and configuration forbids it.</description></item>
///   <item><description><c>RES</c> — a named resource is missing, or collides with existing state.</description></item>
///   <item><description><c>POL</c> — a deliberate certificate-policy limit was exceeded.</description></item>
///   <item><description><c>PRF</c> — the chosen profile does not permit the key parameters.</description></item>
/// </list>
/// <para>
/// <b>Codes are append-only.</b> Never renumber one, and never reuse a retired number for a
/// different failure: somewhere there is a runbook, a saved search or a monitoring rule keyed
/// on it, and silently repointing it is worse than having no code at all. Reword the message
/// freely; the code is the part that is promised to stay put.
/// </para>
/// <para>
/// Every code ending <c>-000</c> is the unclassified member of its area. Those are real codes,
/// not placeholders — they mean "a configuration refusal we have not given its own identity
/// yet" — and narrowing one later is an ordinary, non-breaking refinement.
/// </para>
/// </remarks>
public static class ErrorCodes
{
    // ---- REQ: the request content is wrong -------------------------------------------------

    /// <summary>Request content is unusable and no configuration change would accept it.</summary>
    public const string RequestInvalid = "MCA-REQ-000";

    /// <summary>The CSR's self-signature did not verify against its own public key.</summary>
    public const string CsrSignatureInvalid = "MCA-REQ-001";

    /// <summary>The stored CSR body is empty, so there is nothing to issue against.</summary>
    public const string CsrEmpty = "MCA-REQ-002";

    /// <summary>A subject DN override could not be parsed into RDNs.</summary>
    public const string SubjectDnOverrideInvalid = "MCA-REQ-003";

    /// <summary>A SAN override was malformed, or named a SAN type this CA cannot encode.</summary>
    public const string SanOverrideInvalid = "MCA-REQ-004";

    // ---- CFG: configuration forbids an otherwise well-formed request -----------------------

    /// <summary>Configuration forbids the operation; no narrower classification yet.</summary>
    public const string ConfigurationRefused = "MCA-CFG-000";

    /// <summary>A CA-flagged certificate profile was used on a leaf issuance path.</summary>
    public const string CaProfileOnLeafIssuance = "MCA-CFG-001";

    /// <summary>The signing profile omits an EKU the infrastructure certificate requires.</summary>
    public const string SigningProfileMissingRequiredEku = "MCA-CFG-002";

    /// <summary>The signing profile's AllowedEKUs value could not be read as a list.</summary>
    public const string SigningProfileEkusUnreadable = "MCA-CFG-003";

    /// <summary>The issuing CA is revoked, so anything it signs will be rejected.</summary>
    public const string IssuingCaRevoked = "MCA-CFG-004";

    /// <summary>No usable private key is available for the issuing CA.</summary>
    public const string IssuingCaKeyUnavailable = "MCA-CFG-005";

    /// <summary>The owning tenant is disabled, which blocks issuance beneath it.</summary>
    public const string TenantDisabled = "MCA-CFG-006";

    /// <summary>The reserved system signing CA was asked to issue a non-keystore certificate.</summary>
    public const string SystemSigningCaReserved = "MCA-CFG-007";

    /// <summary>The issuing CA expires too soon to satisfy the profile's minimum validity.</summary>
    public const string IssuingCaExpiresTooSoon = "MCA-CFG-008";

    /// <summary>Reuse of a key belonging to a certificate revoked for key compromise.</summary>
    public const string KeyReuseAfterCompromise = "MCA-CFG-009";

    /// <summary>The previous certificate's revocation reason does not permit reissue.</summary>
    public const string ReissueReasonNotPermitted = "MCA-CFG-010";

    /// <summary>The issuing CA carries name-constraint types this CA cannot enforce.</summary>
    public const string NameConstraintTypeUnsupported = "MCA-CFG-011";

    /// <summary>
    /// A CA certificate was asked to assert keyEncipherment, dataEncipherment or keyAgreement.
    /// </summary>
    public const string CaKeyUsageForbidden = "MCA-CFG-012";

    /// <summary>
    /// A CA certificate was asked to carry an ExtendedKeyUsage, which would constrain every
    /// certificate beneath it.
    /// </summary>
    public const string CaExtendedKeyUsageForbidden = "MCA-CFG-013";

    // ---- RES: missing resource, or collision with existing state ---------------------------

    /// <summary>A resource the request named does not exist or is not of the required kind.</summary>
    public const string ResourceNotFound = "MCA-RES-000";

    /// <summary>The request collides with existing state; no narrower classification yet.</summary>
    public const string ResourceConflict = "MCA-RES-001";

    /// <summary>A CA or tenant certificate quota is already at its ceiling.</summary>
    public const string QuotaExceeded = "MCA-RES-002";

    /// <summary>A CA label, or an auto-generated group name, is already taken.</summary>
    public const string NameAlreadyTaken = "MCA-RES-003";

    /// <summary>The certificate has already been reissued once.</summary>
    public const string AlreadyReissued = "MCA-RES-004";

    /// <summary>The CSR is not in a state from which this operation can proceed.</summary>
    public const string CsrStateNotEligible = "MCA-RES-005";

    // ---- POL: deliberate certificate-policy limits ------------------------------------------

    /// <summary>One or more certificate-policy rules were violated.</summary>
    public const string PolicyViolation = "MCA-POL-000";

    /// <summary>A requested name falls outside the issuing CA's name constraints.</summary>
    public const string NameConstraintViolation = "MCA-POL-001";

    // ---- ISS: issuance succeeded, but not exactly as asked ----------------------------------
    //
    // Advisory rather than refusal. They share the catalog with the refusal codes on purpose —
    // severity is a separate axis from identity, and an operator searching a code should not
    // have to know in advance whether the thing they hit stopped the issuance or merely bent it.

    /// <summary>The certificate was issued, but not exactly as requested.</summary>
    public const string IssuanceAdjusted = "MCA-ISS-000";

    /// <summary>Validity was shortened because the issuing CA expires first.</summary>
    public const string ValidityClampedToIssuer = "MCA-ISS-001";

    /// <summary>notBefore was raised because a certificate cannot precede its issuer.</summary>
    public const string NotBeforeRaisedToIssuer = "MCA-ISS-002";

    /// <summary>
    /// An extended key usage the certificate profile asked for was removed because the signing
    /// profile's AllowedEKUs ceiling does not permit it. The certificate was still issued.
    /// </summary>
    public const string ExtendedKeyUsageDropped = "MCA-ISS-003";

    /// <summary>
    /// Validity was shortened because the owning tenant caps how long its certificates may live.
    /// Distinct from <see cref="ValidityClampedToIssuer"/> because the remedies have nothing in
    /// common: a CA that expires first is fixed by renewing the CA, whereas this is a deliberate
    /// policy ceiling and the only way through it is for someone with tenant authority to raise it.
    /// </summary>
    public const string ValidityClampedToTenant = "MCA-ISS-004";

    /// <summary>
    /// Issuance was refused because the request asked for longer validity than the owning tenant
    /// permits, and that tenant is configured to refuse rather than shorten.
    /// <para>
    /// The one refusal in a block of advisories, and the distinction from
    /// <see cref="ValidityClampedToTenant"/> is the tenant's <c>ValidityCeilingBehavior</c> and
    /// nothing else: the same request, against the same ceiling, raises MCA-ISS-004 and a
    /// certificate on a tenant set to Shorten, and this with no certificate on a tenant set to
    /// Refuse. It lives here rather than in the CFG block so that an operator who has seen
    /// MCA-ISS-004 finds its counterpart next to it — severity is a separate axis from identity,
    /// which is the same reason this block already shares the catalog with the refusal codes.
    /// </para>
    /// <para>
    /// It reaches interactive and admin issuance only. ACME, EST, SCEP, CMP and the renewal jobs
    /// always shorten, so a client that sees this code came from a path where a human can shorten
    /// the request or raise the tenant ceiling — which is exactly the remedy.
    /// </para>
    /// </summary>
    public const string ValidityExceedsTenantCeiling = "MCA-ISS-005";

    // ---- LIC: the installation is not licensed for what was asked --------------------------
    //
    // Distinct from CFG on purpose. A configuration refusal is fixed by changing a profile; a
    // licensing refusal is fixed commercially, and sending an operator to the profile editor for
    // one of these wastes their afternoon.

    /// <summary>Licensing refusal; no narrower classification yet.</summary>
    public const string LicenseRefused = "MCA-LIC-000";

    /// <summary>The licence does not grant this feature at all.</summary>
    public const string FeatureNotEntitled = "MCA-LIC-001";

    /// <summary>A licensed ceiling — tenants, seats — is already reached.</summary>
    public const string LicenseLimitReached = "MCA-LIC-002";

    /// <summary>
    /// The feature is entitled perpetually, but it shipped after the licence's maintenance
    /// window ended. Separate from <see cref="FeatureNotEntitled"/> because "renew maintenance"
    /// and "purchase this feature" are different conversations, and rendering them identically
    /// makes the renewal path worse for a customer who has already paid.
    /// </summary>
    public const string MaintenanceLapsed = "MCA-LIC-003";

    // ---- PRF: profile key-parameter refusals ------------------------------------------------

    /// <summary>The profile does not permit the submitted key or signature parameters.</summary>
    public const string KeyParametersNotPermitted = "MCA-PRF-000";

    /// <summary>
    /// Every code declared above, discovered by reflection so the list cannot drift from the
    /// declarations the way a hand-maintained array does.
    /// </summary>
    public static IReadOnlyList<string> All { get; } =
        typeof(ErrorCodes)
            .GetFields(BindingFlags.Public | BindingFlags.Static | BindingFlags.FlattenHierarchy)
            .Where(f => f is { IsLiteral: true, IsInitOnly: false } && f.FieldType == typeof(string))
            .Select(f => (string)f.GetRawConstantValue()!)
            .ToList();
}
