using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using ModularCA.Auth.Services;
using ModularCA.Auth.Utils;

namespace ModularCA.API.Auth;

/// <summary>
/// HTTP Basic authentication for EST enrollment, per RFC 7030 section 3.2.3.
/// </summary>
/// <remarks>
/// <para>
/// EST designates HTTP Basic as its baseline client authentication, and most EST clients send it
/// by default. This application registered exactly one authentication scheme — JWT bearer — so an
/// <c>Authorization: Basic</c> header never authenticated anything:
/// <c>HttpContext.User.Identity.IsAuthenticated</c> stayed false and enrollment was refused with
/// "EST enrollment requires HTTP authentication" no matter what credentials were supplied. The
/// per-CA <c>EstHttpAuthEnabled</c> flag promised Basic and could not deliver it.
/// </para>
/// <para>
/// <b>Registered as a named scheme, never as the default.</b> It is invoked only where EST asks
/// for it, so a Basic header on an admin API route still authenticates nothing. Making Basic a
/// default or fallback scheme would hand every authenticated endpoint in the product a
/// password-only, MFA-free entry path, which is a much larger change than the one EST needs.
/// </para>
/// <para>
/// Credential verification is delegated to <see cref="IProtocolCredentialService"/>, which is the
/// extracted form of the interactive login rules — LDAP then local, lockout counters shared with
/// the login page, account state applied after the password so this cannot be used to enumerate
/// accounts, and an audit record on every outcome. That sharing is the point: without it, EST
/// would be a password-grinding surface with no lockout, and the login page's protections would
/// mean nothing.
/// </para>
/// <para>
/// No <c>WWW-Authenticate</c> challenge is emitted on failure. A challenge invites a browser to
/// pop a credential dialog, and these routes are reached by devices; the EST controller answers
/// with the protocol's own refusal instead, which is what a client can act on.
/// </para>
/// </remarks>
public class EstBasicAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    IProtocolCredentialService credentials)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    /// <summary>The scheme name. Referenced by the EST controller and nowhere else.</summary>
    public const string SchemeName = "EstBasic";

    /// <inheritdoc />
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // NoResult rather than Fail throughout: absent or malformed credentials mean "this scheme
        // has nothing to say", leaving the caller unauthenticated so EST's own authorisation can
        // decide whether that matters. Fail would surface as an error to a client that may have
        // been legitimately relying on client-certificate auth instead.
        if (!Request.Headers.TryGetValue("Authorization", out var header))
            return AuthenticateResult.NoResult();

        // Parsing rules live in BasicAuthHeader so the RFC 7617 details are pinned by tests that
        // do not need an HttpContext.
        if (!BasicAuthHeader.TryParse(header.ToString(), out var username, out var password))
            return AuthenticateResult.NoResult();

        var sourceIp = Context.Connection.RemoteIpAddress?.ToString();
        var verified = await credentials.VerifyAsync(username, password, "EST", sourceIp);
        if (verified == null)
            return AuthenticateResult.NoResult();

        // Name is what EstController.ResolveCallerUsername reads, and what EstService binds SANs
        // to when it records callerPrincipal as "basic:{username}".
        var identity = new ClaimsIdentity(
            [new Claim(ClaimTypes.Name, verified), new Claim("username", verified)],
            SchemeName);

        return AuthenticateResult.Success(
            new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName));
    }

    /// <inheritdoc />
    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        // Deliberately no WWW-Authenticate header. See the remarks.
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Task.CompletedTask;
    }
}
