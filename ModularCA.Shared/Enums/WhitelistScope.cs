namespace ModularCA.Shared.Enums;

/// <summary>
/// Classifies a whitelist rule by the bucket of gated request paths it applies to.
/// The middleware derives a scope (or ordered list of scopes) from the incoming
/// request path and looks up the first matching enabled rule. Scopes are listed
/// roughly from most general (<see cref="System"/>) to most specific
/// (<see cref="Protocol"/>); when multiple scopes could match, more specific
/// scopes are evaluated first.
/// </summary>
public enum WhitelistScope
{
    /// <summary>
    /// Catch-all default applied to any gated path that has no more-specific
    /// rule. Acts as the system-wide fallback when no scoped rule matches.
    /// </summary>
    System,

    /// <summary>
    /// Covers the setup wizard paths (<c>/setup/*</c> and
    /// <c>/api/v1/setup/*</c>). Locks the first-run bootstrap surface down to
    /// the internal network by default.
    /// </summary>
    Setup,

    /// <summary>
    /// Covers authentication endpoints (<c>/auth/*</c> and
    /// <c>/api/v1/auth/*</c>) including login, refresh, logout, and MFA flows.
    /// Defaults open to preserve out-of-the-box remote admin access.
    /// </summary>
    Auth,

    /// <summary>
    /// Covers the direct <c>/api/v1/*</c> management and protocol routes.
    /// Defaults closed so external clients are forced to use the public
    /// short-URL canonical entry points for PKI protocols.
    /// </summary>
    Api,

    /// <summary>
    /// Covers the public PKI short-URL entry points
    /// (<c>/acme/*</c>, <c>/scep/*</c>, <c>/est/*</c>, <c>/cmp/*</c>,
    /// <c>/ocsp</c>, <c>/tsa</c>, <c>/crl/*</c>, <c>/ca/*</c>). Typically has
    /// no seeded row so short URLs remain publicly reachable.
    /// </summary>
    ShortUrl,

    /// <summary>
    /// Restricts all protocols for a single Certificate Authority identified
    /// by <c>CertificateAuthorityId</c>. Evaluated before <see cref="Api"/> or
    /// <see cref="ShortUrl"/> when a CA label is present on the path.
    /// </summary>
    Ca,

    /// <summary>
    /// Restricts a single protocol (ACME, EST, SCEP, CMP, OCSP, TSA, etc.)
    /// for a single Certificate Authority. Most specific scope — evaluated
    /// first when both a CA label and a protocol are present on the path.
    /// </summary>
    Protocol,

    /// <summary>
    /// Covers the admin surface — the <c>/admin/*</c> SPA routes (HTML + JS
    /// + CSS for the admin console) and the <c>/api/v1/admin/*</c> admin API
    /// endpoints. Seeded closed by default (RFC1918 + loopback) so a public
    /// deployment cannot serve the admin UI or receive admin API calls from
    /// the internet without an explicit operator opt-in. Pairs with JWT + MFA
    /// + step-up as layered defense.
    /// </summary>
    Admin,

    /// <summary>
    /// Covers the relying-party surface — the <c>/public/*</c> portal SPA and
    /// <c>/api/v1/public/info</c>. Seeded OPEN (all addresses), unlike every
    /// other scope.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This exists because the portal is for people outside the network by
    /// definition. A relying party fetching the CA certificate has no trust in
    /// this CA yet — that is the point of the visit — and
    /// <c>HttpSchemeEnforcementMiddleware</c> already allow-lists <c>/public</c>
    /// over plain HTTP on exactly that reasoning. The whitelist contradicted it:
    /// the portal fell through to the System rule and answered 403 to everyone
    /// outside, which was invisible for as long as a reverse proxy made every
    /// caller look internal.
    /// </para>
    /// <para>
    /// The protocol endpoints under <c>/api/v1/public/</c> — CRL, CA, OCSP, TSA
    /// — are NOT in this scope. They are matched earlier and keep their own
    /// per-protocol rules, so an operator can publish OCSP while keeping the
    /// portal internal, or the reverse. Widening this scope to swallow them
    /// would take that apart.
    /// </para>
    /// <para>
    /// Seeded open rather than exempted so it remains a rule: visible in the
    /// admin Whitelists page, editable without a restart, recorded in
    /// <c>AuditNetwork.Blocked</c>, and tightenable to internal-only by an
    /// operator running an air-gapped CA. A path in <c>ExemptPaths</c> can do
    /// none of that — it can only ever open.
    /// </para>
    /// </remarks>
    Public,
}
