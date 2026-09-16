using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ModularCA.Shared.Entities;

/// <summary>
/// Per-CA, per-protocol configuration. Controls which protocols are enabled
/// for a given CA and binds the signing / certificate profiles each protocol uses.
/// When no row exists for a CA + protocol pair the system falls back to the
/// global FeatureFlag configuration for backward compatibility.
/// </summary>
public class CaProtocolConfigEntity
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    public Guid CaId { get; set; }

    [ForeignKey("CaId")]
    public virtual CertificateAuthorityEntity Ca { get; set; } = default!;

    /// <summary>
    /// Protocol identifier: "EST", "SCEP", "CMP", "ACME", "OCSP", "MSAE".
    /// </summary>
    [Required]
    [MaxLength(20)]
    public string Protocol { get; set; } = string.Empty;

    public bool IsEnabled { get; set; } = true;

    /// <summary>
    /// Whether this protocol endpoint is shown on the public portal.
    /// When false, the endpoint still works but isn't advertised publicly.
    /// </summary>
    public bool IsPublicVisible { get; set; } = true;

    /// <summary>
    /// Signing profile used by this protocol for this CA.
    /// When null, falls back to the global FeatureFlag configuration.
    /// </summary>
    public Guid? SigningProfileId { get; set; }

    [ForeignKey("SigningProfileId")]
    public virtual SigningProfileEntity? SigningProfile { get; set; }

    /// <summary>
    /// Certificate profile used by this protocol for this CA.
    /// When null, falls back to the global FeatureFlag configuration.
    /// </summary>
    public Guid? CertProfileId { get; set; }

    [ForeignKey("CertProfileId")]
    public virtual CertProfileEntity? CertProfile { get; set; }

    // ─── EST-specific ──────────────────────────────────────────────

    /// <summary>
    /// When true, EST clients must present a valid client certificate for enrollment.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Requires <c>Est.AuthSubdomain</c> to be configured.</b> Kestrel emits a TLS
    /// <c>CertificateRequest</c> only for SNI names the handshake callback gates, and the main CA
    /// hostname is deliberately not one of them — that gate is what lets a single port serve the
    /// admin UI without throwing a certificate picker at every browser visitor. With no EST
    /// hostname configured, a client connecting to the ordinary CA hostname is never asked for a
    /// certificate, so it never sends one however well configured it is,
    /// <c>GetClientCertificateAsync()</c> returns null, and enrollment is refused with "EST
    /// enrollment requires a client certificate (mTLS)" — a message that is accurate and describes
    /// a condition the client cannot fix from that hostname.
    /// </para>
    /// <para>
    /// Verified against a live deployment before the EST hostname existed: a client holding a valid
    /// certificate issued by the CA completed the handshake, reached <c>EstService</c>, and was
    /// refused, because the server never asked.
    /// </para>
    /// <para>
    /// Setting <c>Est.AuthSubdomain</c> gates a second SNI name on the same listener and port,
    /// which <em>requests</em> a client certificate without requiring one — RFC 7030 section 4.1
    /// makes <c>/cacerts</c> the unauthenticated bootstrap step, and a device holds no certificate
    /// until after it enrolls. The certificate is validated against the CAs that currently have EST
    /// enabled, which is the right anchor set because re-enrollment (section 4.2.2) authenticates
    /// with the certificate this CA previously issued to the device. Point EST clients at that
    /// hostname; RFC 7030 has no notion of switching hostname mid-flow, but it has no objection to
    /// the base URL being a different name either.
    /// </para>
    /// <para>
    /// Do not point <c>Est.AuthSubdomain</c> at <c>Mtls.AuthSubdomain</c>. That hostname requires a
    /// certificate and validates against the CAs that sign human login credentials, so sharing one
    /// name would break EST's anonymous bootstrap and let a login certificate enroll as a device.
    /// Startup refuses the pairing rather than letting it be discovered later.
    /// </para>
    /// <para>
    /// <see cref="EstHttpAuthEnabled"/> is the alternative and can be used alongside this: RFC 7030
    /// section 3.2.3 designates HTTP Basic as the baseline client authentication, and it sidesteps
    /// TLS negotiation entirely.
    /// </para>
    /// </remarks>
    public bool EstRequireClientCert { get; set; } = false;

    /// <summary>
    /// When true, EST enrollment requires the caller to be authenticated by the API's own
    /// authentication pipeline.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This means HTTP Basic (RFC 7030 section 3.2.3), which is what most EST clients send by
    /// default, or a bearer token. For a long time it meant only the latter: JWT bearer was the
    /// single registered authentication scheme, so an <c>Authorization: Basic</c> header left
    /// <c>HttpContext.User.Identity.IsAuthenticated</c> false and every enrollment was refused with
    /// "EST enrollment requires HTTP authentication" no matter what credentials were supplied.
    /// Combined with <see cref="EstRequireClientCert"/> being unreachable without an EST hostname,
    /// EST had no working authentication path at all — verified against a live deployment with both
    /// flags exercised in turn.
    /// </para>
    /// <para>
    /// Basic is served by a named scheme invoked only from the EST controller, never as a default
    /// or fallback, so the same header presented to an admin route still authenticates nothing.
    /// Credentials are checked by the same rules as the interactive login — LDAP then local,
    /// shared lockout counters, account state applied after the password so this cannot enumerate
    /// accounts, and an audit record on every outcome.
    /// </para>
    /// <para>
    /// Basic sends a reusable password on every request, so it is the weaker of the two options
    /// even over TLS. Prefer <see cref="EstRequireClientCert"/> with an EST hostname where the
    /// fleet can hold certificates; Basic is the right choice for bootstrapping a device that has
    /// none yet, and the two can be enabled together.
    /// </para>
    /// </remarks>
    public bool EstHttpAuthEnabled { get; set; } = false;

    // ─── SCEP-specific ─────────────────────────────────────────────

    /// <summary>
    /// When true, SCEP enrollment requires a challenge password in the CSR.
    /// </summary>
    public bool ScepChallengeRequired { get; set; } = true;

    // ─── CMP-specific ──────────────────────────────────────────────

    /// <summary>
    /// When true, CMP messages must use signature-based protection (client cert required).
    /// When false, PBMAC (shared secret) protection is also accepted.
    /// </summary>
    public bool CmpRequireSignature { get; set; } = false;

    // ─── ACME-specific ─────────────────────────────────────────────

    /// <summary>
    /// When true, ACME accounts must provide an External Account Binding (EAB)
    /// during registration (RFC 8555 §7.3.4).
    /// </summary>
    public bool AcmeRequireEab { get; set; } = false;

    /// <summary>
    /// Comma-separated list of allowed ACME challenge types (e.g. "http-01,dns-01,tls-alpn-01").
    /// Empty means all challenge types are allowed.
    /// </summary>
    [MaxLength(255)]
    public string? AcmeAllowedChallengeTypes { get; set; }

    /// <summary>
    /// When true, the http-01 validator for this CA is permitted to resolve/connect
    /// to RFC 1918, loopback, and link-local addresses. Defaults to false — the
    /// validator refuses private address space to prevent a public ACME deployment
    /// from being tricked into validating against an internal host. Operators
    /// running ACME for private PKI flip this per-CA rather than globally.
    /// </summary>
    public bool AcmeAllowPrivateAddressValidation { get; set; } = false;

    // ─── OCSP-specific ─────────────────────────────────────────────

    /// <summary>
    /// When true, OCSP responses are signed. Should generally be true for production.
    /// </summary>
    public bool OcspSignResponses { get; set; } = true;

    // ─── Request Profile ──────────────────────────────────────────

    /// <summary>
    /// Optional request profile controlling what requesters can submit for this protocol.
    /// Null means no additional request validation (open enrollment).
    /// </summary>
    public Guid? RequestProfileId { get; set; }

    /// <summary>
    /// MSAE only: accept the WS-Security UsernameToken (and HTTP Basic) a client configured for
    /// username authentication sends. On by default so an existing deployment keeps working.
    /// </summary>
    public bool MsaeAllowUsernameToken { get; set; } = true;

    /// <summary>
    /// MSAE only: accept Kerberos tickets (<c>Authorization: Negotiate</c>) from the forests bound
    /// to the CA's tenant, and challenge a credential-less client with 401 so it fetches one.
    /// Requires at least one enabled realm binding on the tenant.
    /// </summary>
    public bool MsaeAllowKerberos { get; set; } = false;

    [ForeignKey("RequestProfileId")]
    public virtual RequestProfileEntity? RequestProfile { get; set; }
}
