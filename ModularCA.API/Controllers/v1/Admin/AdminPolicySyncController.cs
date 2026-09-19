using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;
using ModularCA.API.Controllers.v1.Auth;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using YamlDotNet.Core;
using YamlDotNet.RepresentationModel;
using ModularCA.API.Startup;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for GitOps-style policy synchronization. Allows triggering
/// a sync from the configured policy directory or uploading a YAML file for import.
/// Requires SystemAdmin authorization with step-up MFA verification.
/// </summary>
[ApiController]
[Route("api/v1/admin/policy/sync")]
[Authorize(Policy = "SystemAdmin")]
[NodeRole(ProcessRole.Control)]
public class AdminPolicySyncController(
    IPolicySyncService policySyncService,
    SystemConfig config,
    IAuditService audit,
    ICurrentUserService currentUser,
    IDistributedCache cache,
    ISecurityAlertService alertService) : ControllerBase
{
    /// <summary>
    /// Triggers a policy sync from the configured policy directory.
    /// Reads all YAML profile files and creates or updates profiles in the database.
    /// Profiles are never deleted by sync (additive only).
    /// Requires step-up MFA verification via the X-MFA-Token header.
    /// </summary>
    [HttpPost]
    public async Task<IActionResult> SyncFromDirectory([FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
    {
        await currentUser.EnsureLoadedAsync();
        if (currentUser.User == null)
            return Unauthorized();

        if (!await MfaStepUpController.ValidateStepUpTokenAsync(cache, User, mfaToken, StepUpOps.PolicySync, "directory"))
            return StatusCode(403, new { error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.", requiresStepUp = true });

        if (!config.PolicySync.Enabled)
            return BadRequest(new { error = "Policy sync is not enabled. Set PolicySync.Enabled = true in system configuration." });

        var policyDir = config.PolicySync.PolicyDirectory;
        if (!Path.IsPathRooted(policyDir))
            policyDir = Path.Combine(AppContext.BaseDirectory, policyDir);

        var result = await policySyncService.SyncFromDirectoryAsync(policyDir);

        await audit.LogAsync(AuditActionType.PolicySyncExecuted, currentUser.User.Id, currentUser.User.Username,
            "PolicySync", null, new { result.Created, result.Updated, result.Unchanged, ErrorCount = result.Errors.Count, Directory = policyDir },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        if (result.Errors.Count > 0)
            _ = alertService.RaiseAlertAsync("PolicySyncErrors", AlertSeverity.Warning,
                $"Policy sync completed with {result.Errors.Count} error(s) by {currentUser.User.Username}",
                new { result.Errors });

        return Ok(result);
    }

    /// <summary>Maximum YAML node count accepted by <see cref="ImportYaml"/> — guards
    /// against billion-laughs-style anchor/alias expansion in uploaded policy files.</summary>
    private const int MaxYamlNodeCount = 10_000;

    /// <summary>Maximum accepted upload size for <see cref="ImportYaml"/> in bytes.</summary>
    private const int MaxYamlUploadBytes = 256 * 1024;

    /// <summary>MIME types accepted for the policy-import upload.</summary>
    private static readonly HashSet<string> AllowedYamlContentTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "application/x-yaml",
        "application/yaml",
        "text/yaml",
        "text/x-yaml",
        "text/plain",
        "application/octet-stream",
    };

    /// <summary>
    /// Imports profiles from an uploaded YAML file. The profile type must be specified
    /// as a query parameter: "cert", "signing", or "request".
    /// Requires step-up MFA verification via the X-MFA-Token header.
    /// Caps upload size at <see cref="MaxYamlUploadBytes"/>, rejects
    /// unexpected content types / extensions, and walks the parsed <see cref="YamlStream"/>
    /// to enforce a node-count ceiling before the object graph reaches the policy service.
    /// <c>file.FileName</c> is sanitized before being written to the audit
    /// log so attacker-controlled multipart filenames cannot stage stored XSS against admins.
    /// </summary>
    /// <param name="profileType">The profile type: "cert", "signing", or "request".</param>
    /// <param name="file">The YAML file to import.</param>
    /// <param name="mfaToken">Step-up MFA token from the X-MFA-Token header.</param>
    [HttpPost("/api/v1/admin/policy/import")]
    [RequestSizeLimit(MaxYamlUploadBytes)]
    public async Task<IActionResult> ImportYaml(
        [FromQuery] string profileType,
        IFormFile file,
        [FromHeader(Name = "X-MFA-Token")] string? mfaToken = null)
    {
        await currentUser.EnsureLoadedAsync();
        if (currentUser.User == null)
            return Unauthorized();

        if (!await MfaStepUpController.ValidateStepUpTokenAsync(cache, User, mfaToken, StepUpOps.PolicyImport, profileType))
            return StatusCode(403, new { error = "MFA re-verification required. Call /api/v1/auth/mfa/verify-stepup first.", requiresStepUp = true });

        if (file == null || file.Length == 0)
            return BadRequest(new { error = "No file uploaded." });

        if (file.Length > MaxYamlUploadBytes)
            return BadRequest(new { error = $"Policy file exceeds maximum upload size of {MaxYamlUploadBytes} bytes." });

        if (string.IsNullOrWhiteSpace(profileType))
            return BadRequest(new { error = "profileType query parameter is required. Valid values: cert, signing, request." });

        var validTypes = new[] { "cert", "signing", "request" };
        if (!validTypes.Contains(profileType.ToLowerInvariant()))
            return BadRequest(new { error = $"Invalid profileType '{profileType}'. Valid values: cert, signing, request." });

        // Content-Type allow-list — admin tooling may send "application/octet-stream" via curl,
        // so that is permitted, but arbitrary content types (images, archives) are rejected.
        if (!string.IsNullOrEmpty(file.ContentType) && !AllowedYamlContentTypes.Contains(file.ContentType))
            return BadRequest(new { error = $"Unsupported content type '{file.ContentType}'. Expected a YAML upload." });

        // Filename suffix allow-list — .yaml or .yml only.
        var uploadedName = file.FileName ?? string.Empty;
        if (!uploadedName.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase) &&
            !uploadedName.EndsWith(".yml", StringComparison.OrdinalIgnoreCase))
            return BadRequest(new { error = "Only .yaml or .yml files are accepted." });

        using var reader = new StreamReader(file.OpenReadStream());
        var yamlContent = await reader.ReadToEndAsync();

        // Secondary size guard — RequestSizeLimit above should make this impossible but the
        // belt-and-braces check covers future refactors that remove the attribute.
        if (yamlContent.Length > MaxYamlUploadBytes)
            return BadRequest(new { error = "Policy file exceeds maximum upload size." });

        // Walk the parsed YAML stream and bail if the node count exceeds the cap. This
        // materializes aliases (YamlDotNet resolves them during Load), so a crafted
        // "billion laughs" anchor graph is blocked before it reaches the deserializer.
        try
        {
            using var nodeReader = new StringReader(yamlContent);
            var yamlStream = new YamlStream();
            yamlStream.Load(nodeReader);
            var nodeCount = 0;
            foreach (var doc in yamlStream.Documents)
            {
                if (!CountNodes(doc.RootNode, ref nodeCount, MaxYamlNodeCount))
                    return BadRequest(new { error = $"Policy file has too many YAML nodes (> {MaxYamlNodeCount}). Refusing to import." });
            }
        }
        catch (YamlException)
        {
            return BadRequest(new { error = "Policy file is not valid YAML." });
        }

        var result = await policySyncService.SyncFromYamlAsync(yamlContent, profileType);

        var sanitizedFileName = DownloadFilenameUtil.SanitizeForAuditLog(uploadedName);
        await audit.LogAsync(AuditActionType.PolicySyncImported, currentUser.User.Id, currentUser.User.Username,
            "PolicySync", null, new { ProfileType = profileType, FileName = sanitizedFileName, result.Created, result.Updated, result.Unchanged, ErrorCount = result.Errors.Count },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        if (result.Errors.Count > 0)
            _ = alertService.RaiseAlertAsync("PolicyImportErrors", AlertSeverity.Warning,
                $"Policy import ({profileType}) completed with {result.Errors.Count} error(s) by {currentUser.User.Username}",
                new { result.Errors });

        return Ok(result);
    }

    /// <summary>
    /// Walks a <see cref="YamlNode"/> tree incrementing <paramref name="count"/> per node and
    /// returns <c>false</c> if <paramref name="limit"/> is reached. Iterative to avoid stack
    /// exhaustion on deeply-nested documents.
    /// </summary>
    private static bool CountNodes(YamlNode root, ref int count, int limit)
    {
        var stack = new Stack<YamlNode>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            if (++count > limit) return false;
            var node = stack.Pop();
            switch (node)
            {
                case YamlMappingNode map:
                    foreach (var kv in map.Children)
                    {
                        stack.Push(kv.Key);
                        stack.Push(kv.Value);
                    }
                    break;
                case YamlSequenceNode seq:
                    foreach (var item in seq.Children)
                        stack.Push(item);
                    break;
            }
        }
        return true;
    }
}
