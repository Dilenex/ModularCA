using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ModularCA.Core.Services.Msae;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Answers, for one CA, whether Windows autoenrollment would work and what stands in the way.
/// </summary>
/// <remarks>
/// Read-only. The route carries the CA id so the CA-scoped policy resolves it: the caller needs
/// the same right as for the CA's protocol configuration, since the answer names the CA's
/// profiles, the tenant's forests and their enrollment identities.
/// </remarks>
[ApiController]
[Route("api/v1/admin/msae/{caId:guid}")]
[Authorize(Policy = "CaAdmin")]
public class AdminMsaeReadinessController(MsaeReadinessService readiness, MsaeSetupKitService kits) : ControllerBase
{
    /// <summary>Every precondition of Windows autoenrollment for this CA, in dependency order, with a fix pointer per failing step.</summary>
    [HttpGet("readiness")]
    public async Task<IActionResult> Readiness(Guid caId, CancellationToken cancellation)
    {
        var result = await readiness.EvaluateAsync(caId, cancellation);
        return result == null ? NotFound(new { error = "No such certificate authority." }) : Ok(result);
    }

    /// <summary>
    /// The zip a customer's domain administrator runs to point one forest at this CA: the
    /// service-account script, the Group Policy push, the tenant root, a client self-check and a
    /// readme. Contains no secret.
    /// </summary>
    [HttpGet("setup-kit")]
    public async Task<IActionResult> SetupKit(Guid caId, [FromQuery] Guid realmId, CancellationToken cancellation)
    {
        var zip = await kits.BuildAsync(caId, realmId, cancellation);
        if (zip == null) return NotFound(new { error = "No such CA and forest binding in the same tenant." });
        var evaluated = await readiness.EvaluateAsync(caId, cancellation);
        var realm = evaluated?.Realms.FirstOrDefault(r => r.Id == realmId)?.Realm ?? "forest";
        return File(zip, "application/zip", $"modularca-{evaluated?.CaLabel ?? caId.ToString()}-{realm.ToLowerInvariant()}-setup.zip");
    }
}
