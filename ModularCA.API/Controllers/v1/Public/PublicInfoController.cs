using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Public;

/// <summary>
/// Public (unauthenticated) endpoint that exposes non-sensitive deployment
/// identity — the operator-configured public domain, the canonical HTTPS base
/// URL, and which system protocols are enabled — so the public SPA can display
/// URLs users should copy into external tooling (certbot, acme.sh, etc.) and
/// advertise only the protocols the deployment actually serves.
/// </summary>
[ApiController]
[Route("api/v1/public/info")]
[AllowAnonymous]
[NodeRole(ProcessRole.Control)]
public class PublicInfoController(SystemConfig config, IFeatureFlagService featureFlags) : ControllerBase
{
    private readonly SystemConfig _config = config;
    private readonly IFeatureFlagService _featureFlags = featureFlags;

    // System protocols surfaced to the public portal, paired with their
    // feature-flag names (the same flags ProtocolFeatureGateMiddleware enforces).
    // Only the enabled ones are returned, so the portal advertises exactly what
    // the deployment serves.
    private static readonly (string Name, string Flag)[] ProtocolFlags =
    {
        ("CRL", "CRL.Enabled"),
        ("OCSP", "OCSP.Enabled"),
        ("ACME", "ACME.Enabled"),
        ("EST", "EST.Enabled"),
        ("SCEP", "SCEP.Enabled"),
        ("CMP", "CMP.Enabled"),
        ("MSAE", "MSAE.Enabled"),
    };

    /// <summary>
    /// Returns <c>{ publicDomain, publicHttpsBaseUrl, enabledProtocols, sourceCodeUrl, license }</c>.
    /// Falls back to the request's scheme/host when <c>Https.PublicDomain</c> is
    /// unset (setup mode) so the SPA has something reasonable to render either way.
    /// <c>enabledProtocols</c> is the subset of system protocols whose feature flag
    /// is on.
    /// </summary>
    [HttpGet]
    public IActionResult GetInfo()
    {
        var publicDomain = _config.Https.PublicDomain?.Trim() ?? string.Empty;
        var baseUrl = !string.IsNullOrWhiteSpace(publicDomain)
            ? _config.Https.GetPublicHttpsBaseUrl()
            : $"{Request.Scheme}://{Request.Host}";

        var enabledProtocols = ProtocolFlags
            .Where(p => _featureFlags.IsEnabled(p.Flag))
            .Select(p => p.Name)
            .ToArray();

        return Ok(new
        {
            publicDomain,
            publicHttpsBaseUrl = baseUrl,
            enabledProtocols,
            // AGPL section 13: every SPA renders this as a source-code offer. Served from the
            // anonymous endpoint on purpose — the obligation is to "all users interacting with
            // it remotely", and a link reachable only behind a login fails for exactly the
            // people most likely to need it.
            //
            // The version and commit are NOT returned here. Each SPA already carries them as
            // build-time constants (__APP_VERSION__ / __APP_COMMIT__ from the repo-root VERSION
            // file), so the notice identifies the running build without this endpoint
            // disclosing a version pre-auth, which /api/v1/version deliberately does not.
            sourceCodeUrl = _config.SourceCode.EffectiveUrl,
            license = _config.SourceCode.License,
        });
    }
}
