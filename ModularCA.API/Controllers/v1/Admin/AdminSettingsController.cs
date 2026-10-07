using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ModularCA.API.Startup;
using ModularCA.Core.Services.Settings;
using ModularCA.Shared.Utils;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// What the console needs to say, beside each setting, where it is kept and when a change to it
/// takes effect. It describes settings and never returns a value: the values are the settings
/// endpoints' (<c>/api/v1/admin/config</c>), which redact what they must.
/// </summary>
[ApiController]
[Route("api/v1/admin/settings")]
[Authorize(Policy = "SystemAdmin")]
[NodeRole(ProcessRole.Control)]
public class AdminSettingsController(SettingsPersistence persistence, EnvVarConfigOverlay environment) : ControllerBase
{
    /// <summary>
    /// Every setting: its key, whether it is kept in the database or in this host's file, whether
    /// a change takes effect at once or at the next start, and where the value in force comes
    /// from (the database, the built-in default, the environment or the file).
    /// </summary>
    [HttpGet]
    [ProducesResponseType(200)]
    public IActionResult Describe()
    {
        var snapshot = persistence.Snapshot;
        return Ok(new
        {
            storeInUse = persistence.StoreInUse,
            revision = snapshot?.Revision ?? 0,
            movedAt = snapshot?.ImportedAt,
            settings = SettingsDescriptions.Describe(snapshot, environment.EnvSourcedPaths),
        });
    }
}
