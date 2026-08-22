using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Mvc.Filters;
using ModularCA.Core.Helpers;
using ModularCA.Database;
using ModularCA.Shared.Authorization;
using Serilog;

namespace ModularCA.Auth.Authorization;

/// <summary>
/// Authorization handler that evaluates <see cref="CaGroupRequirement"/> against the
/// current user's group memberships. Extracts the target CA from route values when the
/// requirement is CA-scoped.
/// <para>
/// CA-scoped policies no longer silently degrade to system-level
/// checks when the route has no resolvable CA id. If the requirement is CA-scoped and
/// no CA can be resolved from the route, the handler returns without succeeding — a
/// warning is logged so developers notice the drift. Endpoints that legitimately need
/// system-level access must use <c>Policy = "SystemOperator"</c> / <c>"SystemAdmin"</c>
/// / <c>"SystemAuditor"</c> (<see cref="CaGroupRequirement.IsSystemOnly"/>) instead of
/// relying on the former implicit fallback.
/// </para>
/// <para>
/// Resolved CA ids are cached on <c>HttpContext.Items</c> so downstream
/// controllers can reuse the lookup without a second DB round-trip.
/// </para>
/// </summary>
public class CaGroupAuthorizationHandler : AuthorizationHandler<CaGroupRequirement>
{
    internal const string ResolvedCaIdKey = "ResolvedCaId";

    /// <summary>
    /// Request-scoped marker set when a route identifier matched more than one certificate.
    /// Authorization denies rather than falling back to the broader cross-CA check, because an
    /// unresolvable target cannot be authorized against.
    /// </summary>
    internal const string AmbiguousTargetKey = "CaAuthAmbiguousTarget";
    private readonly ICaGroupAuthorizationService _authService;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ModularCADbContext _db;
    private readonly ILogger<CaGroupAuthorizationHandler> _logger;

    /// <summary>
    /// Initializes a new instance of <see cref="CaGroupAuthorizationHandler"/>.
    /// </summary>
    public CaGroupAuthorizationHandler(
        ICaGroupAuthorizationService authService,
        IHttpContextAccessor httpContextAccessor,
        ModularCADbContext db,
        ILogger<CaGroupAuthorizationHandler> logger)
    {
        _authService = authService;
        _httpContextAccessor = httpContextAccessor;
        _db = db;
        _logger = logger;
    }

    /// <summary>
    /// Evaluates the <see cref="CaGroupRequirement"/> for the authenticated user.
    /// For system-only requirements, checks system group memberships.
    /// For CA-scoped requirements, resolves the CA from route values and checks CA-level access.
    /// Fails closed when a CA-scoped policy is evaluated on a route
    /// with no resolvable CA id.
    /// </summary>
    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        CaGroupRequirement requirement)
    {
        var userId = GetUserId(context.User);
        if (userId == null)
            return;

        var username = context.User?.FindFirst(ClaimTypes.Name)?.Value
                    ?? context.User?.FindFirst(JwtRegisteredClaimNames.UniqueName)?.Value
                    ?? "(unknown)";

        // System-only policies: only check system group grants
        if (requirement.IsSystemOnly)
        {
            if (await _authService.HasSystemCapabilityAsync(userId.Value, requirement.RequiredCapability))
            {
                context.Succeed(requirement);
            }
            else
            {
                LogAuthorizationDenied(userId.Value, username, requirement.RequiredCapability, context);
            }
            return;
        }

        // CA-scoped: try to extract CA ID from route values
        var caId = await ResolveCaIdFromRouteAsync();

        if (caId != null)
        {
            // CA ID found in route — check CA-level access (includes system.manage bypass)
            if (await _authService.HasCaCapabilityAsync(userId.Value, caId.Value, requirement.RequiredCapability))
            {
                context.Succeed(requirement);
            }
            else
            {
                LogAuthorizationDenied(userId.Value, username, requirement.RequiredCapability, context);
            }
            return;
        }

        // A route identifier that matched several certificates is not a listing endpoint — it is a
        // scoped request whose target could not be pinned down. Falling through to the ANY-CA check
        // below would silently downgrade a CA-scoped requirement to a cross-CA one, so deny.
        if (_httpContextAccessor.HttpContext?.Items.ContainsKey(AmbiguousTargetKey) == true)
        {
            LogAuthorizationDenied(userId.Value, username, requirement.RequiredCapability, context);
            return;
        }

        if (await _authService.IsSystemAdminAsync(userId.Value))
        {
            context.Succeed(requirement);
            return;
        }

        // No CA id in the route. For a READ this is a listing/cross-CA endpoint
        // (/admin/certificates, /admin/authorities) whose handler filters results by the caller's
        // own tenant/CA access, so checking "holds this capability on any CA" is adequate.
        //
        // For a MUTATION it is not. A state-changing CA-scoped request whose target cannot be
        // pinned to a CA is precisely the escalation this handler exists to prevent: the operator
        // holds the capability on one small CA, the route carries no CA to check it against, and
        // the target is then taken from the request body. POST /admin/users/{id}/reset-password is
        // the concrete case — it is CaAdmin, its only route value is {id}, and it returns the new
        // plaintext password in the response. A single-CA operator could reset a system
        // administrator's password in a different tenant.
        //
        // Note the method split is a containment measure, not the real fix. An endpoint that is
        // genuinely global should carry Policy = "SystemOperator"/"SystemAdmin"
        // (CaGroupRequirement.IsSystemOnly) rather than relying on a CA-scoped policy that cannot
        // resolve a CA. Denials here are logged at Warning with the route so those endpoints are
        // easy to find and reclassify.
        var method = _httpContextAccessor.HttpContext?.Request.Method;
        var isMutation = !HttpMethods.IsGet(method ?? string.Empty)
                      && !HttpMethods.IsHead(method ?? string.Empty)
                      && !HttpMethods.IsOptions(method ?? string.Empty);

        if (isMutation)
        {
            _logger.LogWarning(
                "Denied {Method} {Path} for user {Username}: CA-scoped capability '{Capability}' " +
                "was evaluated on a route with no resolvable CA id. If this endpoint is genuinely " +
                "global, give it a SystemOperator/SystemAdmin policy instead of a CA-scoped one.",
                method, _httpContextAccessor.HttpContext?.Request.Path.Value,
                username, requirement.RequiredCapability);
            LogAuthorizationDenied(userId.Value, username, requirement.RequiredCapability, context);
            return;
        }

        // Check if the user holds the required capability on any CA via their group memberships
        var accessibleCaIds = await _authService.GetAccessibleCaIdsAsync(userId.Value, requirement.RequiredCapability);
        if (accessibleCaIds.Count > 0)
        {
            context.Succeed(requirement);
            return;
        }

        LogAuthorizationDenied(userId.Value, username, requirement.RequiredCapability, context);
    }

    /// <summary>
    /// Logs an authorization denial via Serilog at Warning level, including user identity,
    /// the required capability, and the HTTP method/path when available from the request context.
    /// ALC-11: ensures authorization failures carry full user context for audit purposes.
    /// </summary>
    private void LogAuthorizationDenied(Guid userId, string username, string capability, AuthorizationHandlerContext context)
    {
        var httpContext = _httpContextAccessor.HttpContext;
        var method = httpContext?.Request.Method ?? "(unknown)";
        var path = httpContext?.Request.Path.Value ?? "(unknown)";
        var remoteIp = httpContext?.Connection.RemoteIpAddress?.ToString() ?? "(unknown)";

        Log.Warning(
            "Authorization denied for user {UserId} ({Username}) on {Method} {Resource} from {RemoteIp} — required capability: {Capability}",
            userId, username, method, path, remoteIp, capability);
    }

    /// <summary>
    /// Extracts the user ID from the JWT <c>sub</c> or <c>nameid</c> claim.
    /// </summary>
    private static Guid? GetUserId(ClaimsPrincipal? principal)
    {
        if (principal == null)
            return null;

        var sub = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value
               ?? principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;

        return Guid.TryParse(sub, out var guid) ? guid : null;
    }

    /// <summary>
    /// Attempts to resolve a CA ID from the current HTTP request route values.
    /// Resolution order is
    /// <list type="number">
    ///   <item><c>caId</c> (explicit CA primary key)</item>
    ///   <item><c>caKeyId</c> (SSH CA key → parent CA)</item>
    ///   <item><c>label</c> (per-tenant URL slug)</item>
    ///   <item><c>caCertificateId</c> (CA certificate → CA record)</item>
    ///   <item><c>certId</c> (issued cert → signing profile → CA)</item>
    ///   <item><c>serial</c> (issued cert serial → signing profile → CA)</item>
    ///   <item><c>csrId</c> (CSR → signing profile → CA)</item>
    ///   <item><c>tokenId</c> (enrollment token → stored tenant/CA)</item>
    ///   <item><c>id</c> + path hint (cert/request/signing-profile endpoints)</item>
    /// </list>
    /// The result is cached on
    /// <c>HttpContext.Items["ResolvedCaId"]</c> so controllers can reuse the lookup
    /// without re-querying the database.
    /// </summary>
    private async Task<Guid?> ResolveCaIdFromRouteAsync()
    {
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext == null)
            return null;

        // Return the cached value when the same request already resolved
        // the CA id earlier (e.g. in a prior policy evaluation).
        if (httpContext.Items.TryGetValue(ResolvedCaIdKey, out var cached) && cached is Guid cachedId)
            return cachedId;

        var resolved = await ResolveCaIdFromRouteCoreAsync(httpContext);
        if (resolved != null)
            httpContext.Items[ResolvedCaIdKey] = resolved.Value;
        return resolved;
    }

    private async Task<Guid?> ResolveCaIdFromRouteCoreAsync(HttpContext httpContext)
    {
        var routeValues = httpContext.Request.RouteValues;
        var path = httpContext.Request.Path.Value ?? "";

        // Try caId route value (explicit CA identifier)
        if (TryGetGuid(routeValues, "caId", out var caId))
            return caId;

        // Try caKeyId route value — resolve SSH CA key to its parent CA
        if (TryGetGuid(routeValues, "caKeyId", out var caKeyId))
        {
            var sshCaKey = await _db.SshCaKeys.AsNoTracking().FirstOrDefaultAsync(k => k.Id == caKeyId);
            if (sshCaKey != null)
                return sshCaKey.CertificateAuthorityId;
        }

        // Try label route value — resolve to CA ID via database
        if (routeValues.TryGetValue("label", out var labelObj) && labelObj != null)
        {
            var label = labelObj.ToString();
            if (!string.IsNullOrWhiteSpace(label))
            {
                var ca = await _db.CertificateAuthorities
                    .AsNoTracking()
                    .IgnoreQueryFilters()
                    .FirstOrDefaultAsync(c => c.Label == label);
                return ca?.Id;
            }
        }

        // caCertificateId → CertificateAuthority
        if (TryGetGuid(routeValues, "caCertificateId", out var caCertId))
        {
            var caFromCert = await _db.CertificateAuthorities
                .AsNoTracking()
                .IgnoreQueryFilters()
                .FirstOrDefaultAsync(c => c.CertificateId == caCertId);
            if (caFromCert != null) return caFromCert.Id;
        }

        // certId / serial / csrId → SigningProfile → CA
        if (TryGetGuid(routeValues, "certId", out var certId))
        {
            var ca = await ResolveCaFromCertIdAsync(certId);
            if (ca != null) return ca;
        }
        if (routeValues.TryGetValue("serial", out var serialObj) && serialObj != null)
        {
            var serial = serialObj.ToString();
            if (!string.IsNullOrWhiteSpace(serial))
            {
                var ca = await ResolveCaFromSerialAsync(serial);
                if (ca != null) return ca;
            }
        }
        if (TryGetGuid(routeValues, "csrId", out var csrId))
        {
            var ca = await ResolveCaFromCsrIdAsync(csrId);
            if (ca != null) return ca;
        }

        // tokenId → EnrollmentToken.CertificateAuthorityId
        if (TryGetGuid(routeValues, "tokenId", out var tokenId))
        {
            var token = await _db.EnrollmentTokens.AsNoTracking().FirstOrDefaultAsync(t => t.Id == tokenId);
            if (token?.CertificateAuthorityId != null) return token.CertificateAuthorityId;
        }

        // Profile endpoints with {id} parameter + path hint
        if (TryGetGuid(routeValues, "id", out var idGuid))
        {
            if (path.Contains("/cert-profiles/", StringComparison.OrdinalIgnoreCase))
            {
                var cp = await _db.CertProfiles
                    .AsNoTracking()
                    .IgnoreQueryFilters()
                    .FirstOrDefaultAsync(p => p.Id == idGuid);
                if (cp?.CertificateAuthorityId != null) return cp.CertificateAuthorityId;
            }
            else if (path.Contains("/request-profiles/", StringComparison.OrdinalIgnoreCase))
            {
                var rp = await _db.RequestProfiles.AsNoTracking().FirstOrDefaultAsync(p => p.Id == idGuid);
                if (rp?.CertificateAuthorityId != null) return rp.CertificateAuthorityId;
            }
            else if (path.Contains("/signing-profiles/", StringComparison.OrdinalIgnoreCase))
            {
                var sp = await _db.SigningProfiles.AsNoTracking().FirstOrDefaultAsync(p => p.Id == idGuid);
                if (sp?.IssuerId != null)
                {
                    var resolvedCa = await _db.CertificateAuthorities
                        .AsNoTracking()
                        .IgnoreQueryFilters()
                        .FirstOrDefaultAsync(ca => ca.CertificateId == sp.IssuerId);
                    if (resolvedCa != null) return resolvedCa.Id;
                }
            }
            else if (path.Contains("/requests/", StringComparison.OrdinalIgnoreCase))
            {
                // /admin/requests/{id}/approve etc.
                var ca = await ResolveCaFromCsrIdAsync(idGuid);
                if (ca != null) return ca;
            }
            else if (path.Contains("/enrollment-tokens/", StringComparison.OrdinalIgnoreCase))
            {
                var tok = await _db.EnrollmentTokens.AsNoTracking().FirstOrDefaultAsync(t => t.Id == idGuid);
                if (tok?.CertificateAuthorityId != null) return tok.CertificateAuthorityId;
            }
        }

        return null;
    }

    private async Task<Guid?> ResolveCaFromCertIdAsync(Guid certId)
    {
        var cert = await _db.Certificates.AsNoTracking().FirstOrDefaultAsync(c => c.CertificateId == certId);
        if (cert?.SigningProfileId == null) return null;
        return await ResolveCaFromSigningProfileAsync(cert.SigningProfileId.Value);
    }

    /// <summary>
    /// Resolves the CA that owns the certificate named by a <c>{serial}</c> route value.
    /// <para>
    /// A serial identifies a certificate only within an issuer, so it can legitimately match more
    /// than one row. This resolver must NOT collapse that case to null: a null return here means
    /// "the route names no particular CA", which sends <c>HandleRequirementAsync</c> down the
    /// listing-endpoint path where holding the capability on ANY CA is sufficient. Returning null
    /// for an ambiguous serial would therefore weaken a CA-scoped check into a cross-CA one — a
    /// fail-open. Ambiguity is recorded on the request instead, and the caller denies outright.
    /// </para>
    /// </summary>
    private async Task<Guid?> ResolveCaFromSerialAsync(string serial)
    {
        var resolution = await _db.Certificates.AsNoTracking().ResolveBySerialAsync(serial);
        if (resolution.Outcome == SerialResolution.Ambiguous)
        {
            _httpContextAccessor.HttpContext?.Items.TryAdd(AmbiguousTargetKey, true);
            return null;
        }
        var cert = resolution.Certificate;
        if (cert?.SigningProfileId == null) return null;
        return await ResolveCaFromSigningProfileAsync(cert.SigningProfileId.Value);
    }

    private async Task<Guid?> ResolveCaFromCsrIdAsync(Guid csrId)
    {
        var csr = await _db.CertificateRequests.AsNoTracking().FirstOrDefaultAsync(c => c.Id == csrId);
        if (csr?.SigningProfileId == null) return null;
        return await ResolveCaFromSigningProfileAsync(csr.SigningProfileId.Value);
    }

    private async Task<Guid?> ResolveCaFromSigningProfileAsync(Guid signingProfileId)
    {
        var sp = await _db.SigningProfiles.AsNoTracking().FirstOrDefaultAsync(s => s.Id == signingProfileId);
        if (sp?.IssuerId == null) return null;
        var ca = await _db.CertificateAuthorities
            .AsNoTracking()
            .IgnoreQueryFilters()
            .FirstOrDefaultAsync(c => c.CertificateId == sp.IssuerId);
        return ca?.Id;
    }

    private static bool TryGetGuid(IDictionary<string, object?> routeValues, string key, out Guid value)
    {
        value = Guid.Empty;
        return routeValues.TryGetValue(key, out var obj)
            && obj != null
            && Guid.TryParse(obj.ToString(), out value);
    }
}
