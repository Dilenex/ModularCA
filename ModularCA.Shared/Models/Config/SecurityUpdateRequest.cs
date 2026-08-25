namespace ModularCA.Shared.Models.Config;

/// <summary>
/// Request body for <c>PUT /api/v1/admin/config/security</c>. Every member is nullable and
/// <c>null</c> means "not sent — leave it alone".
/// </summary>
/// <remarks>
/// <para>
/// This type exists for the same reason as <see cref="LoggingUpdateRequest"/>. The endpoint used
/// to bind <see cref="SecurityConfig"/> directly, and a JSON body that omits a field does not
/// leave the property null — it leaves it at the type's CONSTRUCTOR DEFAULT, which the handler
/// then wrote over the stored value.
/// </para>
/// <para>
/// On this particular config that is a security downgrade, not just data loss. A caller sending
/// <c>{"behindReverseProxy": true}</c> — an entirely reasonable partial update from a script or
/// a generated client — silently reset <c>BindJwtToIp</c> to <c>Off</c>, disabling JWT-to-IP
/// binding outright, and restored <c>MaxPerUsernameLoginFailures</c> to 20 from whatever
/// tighter value the operator had chosen. The response echoed the mutated config as though it
/// were intended, and the audit row recorded the defaults as the requested change, so the
/// downgrade was indistinguishable from a deliberate one in review.
/// </para>
/// <para>
/// Every sibling handler in <c>AdminConfigController</c> guards each write individually; this
/// endpoint was the outlier. Never bind a config class straight from a request body when partial
/// updates are possible.
/// </para>
/// </remarks>
public class SecurityUpdateRequest
{
    /// <summary>How strictly an access token is bound to the issuing IP: Off, Subnet, or Exact.</summary>
    public JwtIpBindingMode? BindJwtToIp { get; set; }

    /// <summary>Whether refresh tokens record the issuing IP (audit signal).</summary>
    public bool? BindRefreshTokenToIp { get; set; }

    /// <summary>Whether refresh tokens are bound to a client fingerprint.</summary>
    public bool? BindRefreshTokenToFingerprint { get; set; }

    /// <summary>Whether a refresh token surviving a binding mismatch is tolerated.</summary>
    public bool? AllowRefreshTokenMismatch { get; set; }

    /// <summary>Failed logins per username before lockout.</summary>
    public int? MaxPerUsernameLoginFailures { get; set; }

    /// <summary>Rolling window, in minutes, over which those failures are counted.</summary>
    public int? PerUsernameLoginFailureWindowMinutes { get; set; }

    /// <summary>Whether the deployment sits behind a reverse proxy for client-IP resolution.</summary>
    public bool? BehindReverseProxy { get; set; }
}
