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
    /// Protocol identifier: "EST", "SCEP", "CMP", "ACME", "OCSP".
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
    /// <b>This does not currently work on the hostname EST clients use.</b> Kestrel emits a TLS
    /// <c>CertificateRequest</c> only when the ClientHello's SNI matches
    /// <c>Mtls.AuthSubdomain</c> — see the HTTPS endpoint setup in <c>StartModularCA</c>. A client
    /// connecting to the ordinary CA hostname is never asked for a certificate, so it never sends
    /// one however well configured it is, <c>GetClientCertificateAsync()</c> returns null, and
    /// enrollment fails with "EST enrollment requires a client certificate (mTLS)".
    /// </para>
    /// <para>
    /// Verified against a live deployment: a client holding a valid certificate issued by the CA
    /// completed the handshake, reached <c>EstService</c>, and was refused — because the server
    /// never asked. The message is accurate and describes a condition the client cannot fix from
    /// that hostname.
    /// </para>
    /// <para>
    /// The SNI gate is not a mistake; it is what lets one port serve the admin UI without a browser
    /// certificate picker and the mTLS login flow with one. It was designed around interactive
    /// login, and EST was given this flag afterwards. RFC 7030 has no notion of switching hostname
    /// for the enrollment step: a client is configured with one EST base URL and derives
    /// <c>/cacerts</c>, <c>/simpleenroll</c> and <c>/simplereenroll</c> from it.
    /// </para>
    /// <para>
    /// Three ways out, none of them free. Request (not require) a client certificate on the main
    /// hostname — SNI is decided before any path is known, so this reintroduces the browser
    /// certificate picker the gate exists to avoid. Give EST a dedicated hostname or port that
    /// always requests one, which is what most EST deployments do and keeps the browser surface
    /// untouched. Or register an HTTP Basic handler so
    /// <see cref="EstHttpAuthEnabled"/> becomes true to its name, which RFC 7030 section 3.2.3
    /// designates as the baseline and which sidesteps TLS negotiation entirely.
    /// </para>
    /// </remarks>
    public bool EstRequireClientCert { get; set; } = false;

    /// <summary>
    /// When true, EST enrollment requires the caller to be authenticated by the API's own
    /// authentication pipeline.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This does not currently mean HTTP Basic.</b> It used to say it did. The only
    /// authentication scheme this application registers is JWT bearer, so a caller is
    /// "authenticated" here only by presenting a bearer token — and an
    /// <c>Authorization: Basic</c> header, which RFC 7030 section 3.2.3 designates as the baseline
    /// EST client authentication and which most EST clients send by default, leaves
    /// <c>HttpContext.User.Identity.IsAuthenticated</c> false and is refused.
    /// </para>
    /// <para>
    /// <b>And <see cref="EstRequireClientCert"/> does not currently cover for it.</b> See that
    /// property's remarks: the client certificate never reaches EST on the hostname an EST client
    /// uses. Between the two, EST has no working authentication path today — verified against a
    /// live deployment with both flags exercised in turn.
    /// </para>
    /// <para>
    /// Making this true to its name needs an HTTP Basic authentication handler registered
    /// alongside the bearer scheme and scoped to the EST routes. Until that exists, this comment
    /// is the warning; <c>scripts/test-enrollment-protocols.sh</c> probes the path and reports the
    /// failure so it stays visible.
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

    [ForeignKey("RequestProfileId")]
    public virtual RequestProfileEntity? RequestProfile { get; set; }
}
