using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ModularCA.API.Filters;
using ModularCA.API.Startup;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services.Settings;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Settings;
using ModularCA.Shared.Utils;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// What the console needs to say, beside each setting, where it is kept and when a change to it
/// takes effect, and the one secret the console replaces without being told a value: the JWT
/// secret. It describes settings and never returns a value: the values are the settings
/// endpoints' (<c>/api/v1/admin/config</c>), which redact what they must.
/// </summary>
[ApiController]
[Route("api/v1/admin/settings")]
[Authorize(Policy = "SystemAdmin")]
[NodeRole(ProcessRole.Control)]
public class AdminSettingsController(
    SettingsPersistence persistence,
    EnvVarConfigOverlay environment,
    ISettingsStore store,
    ICurrentUserService currentUser) : ControllerBase
{
    /// <summary>
    /// Every setting: its key, whether it is kept in the database or in this host's file, whether
    /// a change takes effect at once or at the next start, and where the value in force comes
    /// from (the database, the built-in default, the environment or the file). Also the keys of
    /// secrets stored since this node started, which it takes up at its next start.
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
            waitingForRestart = persistence.WaitingForRestart,
            settings = SettingsDescriptions.Describe(snapshot, environment.EnvSourcedPaths),
        });
    }

    /// <summary>
    /// Replaces the JWT secret with a new random one, stored wrapped by the signer. No value is
    /// taken and none is returned. This node keeps signing and accepting sessions with the
    /// secret it started with; each node uses the new one from its next start, when access
    /// tokens signed with the old one are refused. Requires step-up MFA
    /// (<see cref="StepUpOps.RotateJwtSecret"/>).
    /// </summary>
    [HttpPost("jwt-secret/rotate")]
    [RequireStepUp(StepUpOps.RotateJwtSecret)]
    [ProducesResponseType(200)]
    [ProducesResponseType(409)]
    [ProducesResponseType(503)]
    public async Task<IActionResult> RotateJwtSecret()
    {
        await currentUser.EnsureLoadedAsync();
        if (currentUser.User == null) return Unauthorized();
        var actor = new SettingsActor(currentUser.User.Id, currentUser.User.Username, HttpContext.Connection.RemoteIpAddress?.ToString());
        try
        {
            var version = await persistence.RotateJwtSecretAsync(store, actor, HttpContext.RequestAborted);
            return Ok(new
            {
                message = "A new JWT secret is stored. It is used from each node's next start.",
                version,
                waitingForRestart = true,
            });
        }
        catch (SettingsRefusedException ex)
        {
            // The signer being locked or out of reach passes; the other refusals are how this node is set up.
            return StatusCode(ex.Reason is SettingsRefusal.SignerRefused or SettingsRefusal.Busy ? 503 : 409, new { error = ex.Message });
        }
    }
}
