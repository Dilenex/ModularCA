using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Utils;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// Admin endpoints for LDAP group synchronization and user provisioning.
/// </summary>
[ApiController]
[Route("api/v1/admin/ldap")]
[Authorize(Policy = "SystemOperator")]
public class AdminLdapController(
    ILdapGroupSyncService syncService,
    SystemConfig config,
    IAuditService audit,
    ICurrentUserService currentUser,
    EnvVarConfigOverlay envOverlay) : ControllerBase
{
    /// <summary>
    /// Triggers a full LDAP group sync for all active users.
    /// </summary>
    [HttpPost("sync")]
    public async Task<IActionResult> SyncAll()
    {
        await currentUser.EnsureLoadedAsync();
        await syncService.SyncAllUsersAsync();

        await audit.LogAsync(
            AuditActionType.LdapSyncTriggered,
            currentUser.User?.Id,
            currentUser.User?.Username,
            "LdapSync", "all",
            new { Scope = "AllUsers" },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new { message = "LDAP group sync completed for all active users" });
    }

    /// <summary>
    /// Triggers an LDAP group sync for a single user by ID.
    /// </summary>
    [HttpPost("sync/{userId:guid}")]
    public async Task<IActionResult> SyncUser(Guid userId, [FromServices] ILdapGroupProvider groupProvider)
    {
        await currentUser.EnsureLoadedAsync();
        var db = HttpContext.RequestServices.GetRequiredService<ModularCA.Database.ModularCADbContext>();
        var user = await db.Users.FindAsync(userId);
        if (user == null) return NotFound(new { error = "User not found" });

        var groups = await groupProvider.GetUserGroupsAsync(user.Username);
        await syncService.SyncUserGroupsAsync(userId, groups);

        await audit.LogAsync(
            AuditActionType.LdapSyncTriggered,
            currentUser.User?.Id,
            currentUser.User?.Username,
            "User", userId.ToString(),
            new { Scope = "SingleUser", TargetUsername = user.Username, GroupCount = groups.Count },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new { message = $"Synced {groups.Count} groups for user {user.Username}" });
    }

    [HttpGet("group-mappings")]
    public IActionResult GetGroupMappings()
    {
        return Ok(new
        {
            config.LdapAuth.GroupSyncEnabled,
            config.LdapAuth.AutoProvisionUsers,
            config.LdapAuth.GroupSearchBaseDn,
            config.LdapAuth.GroupSearchFilter,
            config.LdapAuth.GroupMemberAttribute,
            config.LdapAuth.GroupToRoleMappings
        });
    }

    /// <summary>
    /// Updates LDAP group-to-role mapping configuration.
    /// </summary>
    [HttpPut("group-mappings")]
    public async Task<IActionResult> UpdateGroupMappings([FromBody] UpdateGroupMappingsRequest request)
    {
        await currentUser.EnsureLoadedAsync();
        if (request.GroupSyncEnabled.HasValue)
            config.LdapAuth.GroupSyncEnabled = request.GroupSyncEnabled.Value;
        if (request.AutoProvisionUsers.HasValue)
            config.LdapAuth.AutoProvisionUsers = request.AutoProvisionUsers.Value;
        if (request.GroupSearchBaseDn != null)
        {
            var dn = request.GroupSearchBaseDn.Trim();
            if (string.IsNullOrWhiteSpace(dn) || !dn.Contains('='))
                return BadRequest(new { error = "GroupSearchBaseDn must be a valid DN (non-empty and contain at least one '=' sign, e.g. 'ou=Groups,dc=example,dc=com')." });
            config.LdapAuth.GroupSearchBaseDn = dn;
        }
        if (request.GroupSearchFilter != null)
        {
            var filter = request.GroupSearchFilter;
            if (!filter.Contains("{0}"))
                return BadRequest(new { error = "GroupSearchFilter must contain a {0} placeholder for the username." });
            if (filter.Count(c => c == '{') != filter.Count(c => c == '}'))
                return BadRequest(new { error = "GroupSearchFilter has unbalanced braces." });
            if (filter.Count(c => c == '(') != filter.Count(c => c == ')'))
                return BadRequest(new { error = "GroupSearchFilter has unbalanced parentheses." });
            config.LdapAuth.GroupSearchFilter = filter;
        }
        if (request.GroupToRoleMappings != null)
        {
            try { JsonSerializer.Deserialize<Dictionary<string, string>>(request.GroupToRoleMappings); }
            catch (JsonException) { return BadRequest(new { error = "GroupToRoleMappings must be valid JSON (Dictionary<string, string>)." }); }
            config.LdapAuth.GroupToRoleMappings = request.GroupToRoleMappings;
        }

        PersistConfig();

        await audit.LogAsync(
            AuditActionType.LdapMappingUpdated,
            currentUser.User?.Id,
            currentUser.User?.Username,
            "LdapGroupMappings", null,
            new
            {
                GroupSyncEnabled = request.GroupSyncEnabled,
                AutoProvisionUsers = request.AutoProvisionUsers,
                GroupSearchBaseDn = request.GroupSearchBaseDn,
                GroupSearchFilterUpdated = request.GroupSearchFilter != null,
                GroupToRoleMappingsUpdated = request.GroupToRoleMappings != null
            },
            HttpContext.Connection.RemoteIpAddress?.ToString());

        return Ok(new { message = "Group mappings updated" });
    }

    /// <summary>
    /// Serializes the current in-memory configuration to config.yaml on disk.
    /// Silently ignores write failures (e.g. read-only filesystem in containers).
    /// </summary>
    private void PersistConfig()
    {
        // Secrets that came from the environment must be nulled before serialization, or a
        // config write persists them in cleartext to config.yaml. WithSecretsProtected covers
        // JWT.Secret, both DB passwords, LdapAuth.BindPassword, the Email secrets,
        // IntegrationApi.ApiKey, CertManager.ApiKey and Hsm.Pin. Writing the whole SystemConfig
        // without it -- as this did -- meant an unrelated settings PUT could drop the JWT
        // SIGNING KEY on disk, where anyone able to read the file can mint admin tokens.
        try
        {
            envOverlay.WithSecretsProtected(config, () =>
            {
                var serializer = new SerializerBuilder()
                    .WithNamingConvention(PascalCaseNamingConvention.Instance)
                    .Build();
                var yaml = serializer.Serialize(config);
                var configPath = Path.Combine(AppContext.BaseDirectory, "config", "config.yaml");
                System.IO.File.WriteAllText(configPath, yaml);
            });
        }
        catch
        {
            // Config file may be read-only (container deployments) — in-memory change still applies
        }
    }
}

public class UpdateGroupMappingsRequest
{
    public bool? GroupSyncEnabled { get; set; }
    public bool? AutoProvisionUsers { get; set; }

    [StringLength(1024)]
    public string? GroupSearchBaseDn { get; set; }

    [StringLength(1024)]
    public string? GroupSearchFilter { get; set; }

    public string? GroupToRoleMappings { get; set; }
}
