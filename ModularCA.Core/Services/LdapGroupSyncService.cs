using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ModularCA.Core.Authorization;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Models.Config;
using System.Security.Cryptography;
using System.Text.Json;

namespace ModularCA.Core.Services;

/// <summary>
/// Provides LDAP group membership lookup for user-to-group mapping.
/// </summary>
public interface ILdapGroupProvider
{
    /// <summary>
    /// Returns the list of LDAP group names (DNs or common names) for the given username, an empty
    /// list when the user genuinely belongs to no groups, or <c>null</c> when the lookup could not
    /// be answered (LDAP or group sync disabled, directory unreachable, query error, user not found).
    /// Callers must treat <c>null</c> as "unknown" and never remove memberships on it.
    /// </summary>
    Task<List<string>?> GetUserGroupsAsync(string username);
}

/// <summary>
/// Synchronizes user CA group memberships from LDAP groups and auto-provisions LDAP users.
/// </summary>
public interface ILdapGroupSyncService
{
    /// <summary>
    /// Synchronizes a user's CA group memberships based on their LDAP group list.
    /// Adds memberships for matching, non-privileged CaGroups in the user's own space and removes
    /// stale ones. A mapping target still naming a space group by its pre-0.4.0 <c>org-</c> name
    /// resolves to the renamed group, with a warning. A <c>null</c> group list (lookup failure)
    /// changes nothing.
    /// </summary>
    Task SyncUserGroupsAsync(Guid userId, List<string>? ldapGroups);

    /// <summary>
    /// Auto-provisions a new user from LDAP and syncs their group memberships.
    /// Returns null if auto-provisioning is disabled or the user already exists.
    /// </summary>
    Task<UserEntity?> AutoProvisionUserAsync(string username, List<string>? ldapGroups);

    /// <summary>
    /// Synchronizes CA group memberships for all active users who have previously logged in.
    /// </summary>
    Task SyncAllUsersAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates a GroupToRoleMappings JSON document: it must parse as a string-to-string map and
    /// no new or changed entry may target a system group or a privilege-controlled group (by
    /// structure or capability). Entries identical to one in <paramref name="previousMappingsJson"/>
    /// (the stored mappings) pass, since sync skips controlled targets at runtime. A target still
    /// naming a space group by its pre-0.4.0 <c>org-</c> name is judged as its renamed group.
    /// Returns an error message, or <c>null</c> when the mappings are acceptable.
    /// </summary>
    Task<string?> ValidateMappingsAsync(string? mappingsJson, string? previousMappingsJson = null);

    /// <summary>
    /// <paramref name="mappingsJson"/> with each target still naming a space group by its pre-0.4.0
    /// <c>org-</c> name replaced by its <c>space-</c> name, when that group exists; unchanged when
    /// there is none. Applied when a super saves the LDAP settings, so the stored mappings stop
    /// depending on the fallback.
    /// </summary>
    Task<string?> RewriteRenamedSpaceGroupsAsync(string? mappingsJson);

    /// <summary>
    /// The startup warning listing every configured mapping target that still names a space group
    /// by its pre-0.4.0 <c>org-</c> name, or <see langword="null"/> when there is none. Those names
    /// are not warned about again at sync.
    /// </summary>
    Task<string?> RenamedMappingTargetsWarningAsync();
}

/// <summary>
/// Maps LDAP groups to CaGroupEntity memberships and provisions users from LDAP directory.
/// LDAP group names are matched against <see cref="CaGroupEntity.Name"/> values in the database.
/// Sync never grants or removes membership of a system group or a privilege-controlled group
/// (by structure or capability, <see cref="ControlledTierResolver.ClassifyGroupAsync"/>): those change
/// only through the ceremony-gated admin paths. A mapping that still targets a space group by its
/// pre-0.4.0 <c>org-</c> name resolves, at sync and in validation, to its renamed <c>space-</c>
/// group, with a warning (<see cref="ResolveRenamedSpaceGroupsAsync"/>).
/// </summary>
public class LdapGroupSyncService : ILdapGroupSyncService
{
    private readonly ModularCADbContext _db;
    private readonly SystemConfig _config;
    private readonly ILdapGroupProvider _groupProvider;
    private readonly ILogger<LdapGroupSyncService> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="LdapGroupSyncService"/> class.
    /// </summary>
    public LdapGroupSyncService(ModularCADbContext db, SystemConfig config, ILdapGroupProvider groupProvider, ILogger<LdapGroupSyncService> logger)
    {
        _db = db;
        _config = config;
        _groupProvider = groupProvider;
        _logger = logger;
    }

    /// <summary>
    /// Synchronizes a user's CA group memberships from LDAP groups.
    /// Matches LDAP group names (via the configured mappings, or directly when none are configured)
    /// against CaGroupEntity.Name, restricted to groups in the user's own enabled space(s), never an
    /// instance group (no space) or a disabled space's. Only an account with no memberships at all
    /// falls back to the single enabled space, when exactly one exists. System and privilege-controlled groups are
    /// skipped with a warning, and their memberships are never removed by sync. A <c>null</c> group
    /// list means the directory lookup failed, so nothing is changed.
    /// </summary>
    public async Task SyncUserGroupsAsync(Guid userId, List<string>? ldapGroups)
    {
        if (ldapGroups == null)
        {
            _logger.LogWarning("LDAP sync: group lookup unavailable for user {UserId}; memberships left unchanged", userId);
            return;
        }

        var mappings = ParseMappings();
        if (mappings.Count == 0 && ldapGroups.Count == 0) return;

        var user = await _db.Users
            .Include(u => u.GroupMemberships)
                .ThenInclude(gm => gm.Group)
            .FirstOrDefaultAsync(u => u.Id == userId);
        if (user == null) return;

        var targetGroupNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (mappings.Count > 0)
        {
            foreach (var ldapGroup in ldapGroups)
            {
                foreach (var (groupDn, caGroupName) in mappings)
                {
                    if (string.Equals(ldapGroup, groupDn, StringComparison.OrdinalIgnoreCase))
                        targetGroupNames.Add(caGroupName);
                }
            }
            foreach (var (legacy, renamed) in await ResolveRenamedSpaceGroupsAsync(targetGroupNames))
            {
                targetGroupNames.Remove(legacy);
                targetGroupNames.Add(renamed);
            }
        }
        else
        {
            foreach (var lg in ldapGroups)
                targetGroupNames.Add(lg);
        }

        var enabledSpaceIds = (await _db.Spaces.Where(t => t.IsEnabled).Select(t => t.Id).ToListAsync()).ToHashSet();
        var userSpaceIds = user.GroupMemberships
            .Where(gm => gm.Group != null && !gm.Group.IsSystemGroup && gm.Group.SpaceId is Guid t && enabledSpaceIds.Contains(t))
            .Select(gm => gm.Group.SpaceId!.Value)
            .ToHashSet();
        // The single-space fallback is for brand-new accounts only; an account that already has
        // memberships (system groups or a disabled space included) is never placed in a space by sync.
        if (userSpaceIds.Count == 0 && user.GroupMemberships.Count == 0 && enabledSpaceIds.Count == 1)
            userSpaceIds.Add(enabledSpaceIds.First());

        var targetNameList = targetGroupNames.ToList();
        var candidates = targetNameList.Count == 0
            ? new List<CaGroupEntity>()
            : await _db.CaGroups.Where(g => targetNameList.Contains(g.Name)).ToListAsync();

        var targetGroups = new List<CaGroupEntity>();
        foreach (var group in candidates)
        {
            if (IsRefusedMappingTarget(group.IsSystemGroup, group.IsSystemTierSuper, await ControlledTierResolver.ClassifyGroupAsync(_db, group) != null))
            {
                _logger.LogWarning("LDAP sync: refusing to grant privileged group {GroupName} to user {Username}; privileged memberships change only through the admin ceremony path",
                    group.Name, user.Username);
                continue;
            }
            // Instance groups (no space) are never synced, as the system tenant's groups were not.
            if (group.SpaceId is not Guid groupSpaceId || !enabledSpaceIds.Contains(groupSpaceId) || !userSpaceIds.Contains(groupSpaceId))
            {
                _logger.LogWarning("LDAP sync: skipping group {GroupName} for user {Username}: group is outside the user's space",
                    group.Name, user.Username);
                continue;
            }
            targetGroups.Add(group);
        }

        var targetGroupIds = new HashSet<Guid>(targetGroups.Select(g => g.Id));

        foreach (var group in targetGroups)
        {
            if (!user.GroupMemberships.Any(gm => gm.GroupId == group.Id))
            {
                _db.CaGroupMembers.Add(new CaGroupMemberEntity
                {
                    UserId = userId,
                    GroupId = group.Id,
                    AddedAt = DateTime.UtcNow,
                });
                _logger.LogInformation("LDAP sync: added user {Username} to group {GroupName}", user.Username, group.Name);
            }
        }

        var membershipsToRemove = new List<CaGroupMemberEntity>();
        foreach (var gm in user.GroupMemberships.Where(gm => gm.Group.IsAutoGenerated
                     && !gm.Group.IsSystemGroup
                     && !targetGroupIds.Contains(gm.GroupId)).ToList())
        {
            if (await ControlledTierResolver.ClassifyGroupAsync(_db, gm.Group) == null)
                membershipsToRemove.Add(gm);
        }

        foreach (var membership in membershipsToRemove)
        {
            _db.CaGroupMembers.Remove(membership);
            _logger.LogInformation("LDAP sync: removed user {Username} from group {GroupName}", user.Username, membership.Group.Name);
        }

        await _db.SaveChangesAsync();
    }

    /// <summary>
    /// Auto-provisions a new user from LDAP if enabled in configuration.
    /// Creates the user with a random password hash and syncs group memberships.
    /// </summary>
    public async Task<UserEntity?> AutoProvisionUserAsync(string username, List<string>? ldapGroups)
    {
        if (!_config.LdapAuth.AutoProvisionUsers) return null;

        var existing = await _db.Users.FirstOrDefaultAsync(u => u.Username == username);
        if (existing != null) return existing;

        var user = new UserEntity
        {
            Username = username,
            PasswordHash = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
            IsActive = true,
            CreatedAt = DateTime.UtcNow,
        };

        _db.Users.Add(user);
        await _db.SaveChangesAsync();

        await SyncUserGroupsAsync(user.Id, ldapGroups);

        _logger.LogInformation("LDAP sync: auto-provisioned user {Username}", username);
        return user;
    }

    /// <summary>
    /// Synchronizes CA group memberships for all active, non-service-identity users with a previous
    /// login timestamp. Users the directory cannot answer for (lookup failure or not found in LDAP)
    /// are left unchanged. Observes the cancellation token between iterations.
    /// </summary>
    public async Task SyncAllUsersAsync(CancellationToken cancellationToken = default)
    {
        if (!_config.LdapAuth.Enabled || !_config.LdapAuth.GroupSyncEnabled) return;

        var users = await _db.Users
            .Where(u => u.IsActive && !u.IsServiceIdentity && u.LastLoginAt != null)
            .ToListAsync(cancellationToken);

        foreach (var user in users)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var groups = await _groupProvider.GetUserGroupsAsync(user.Username);
                await SyncUserGroupsAsync(user.Id, groups);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "LDAP sync failed for user {Username}", user.Username);
            }
        }

        _logger.LogInformation("LDAP group sync completed for {Count} users", users.Count);
    }

    /// <summary>
    /// Whether a group may never be an LDAP mapping target: a system group, the system-tier super
    /// group, or a group membership in which confers a controlled tier
    /// (<see cref="ControlledTierResolver.ClassifyGroupAsync"/>; GET /admin/groups reports it as
    /// <c>isControlled</c>). Validation refuses a new or changed mapping to one, and sync never
    /// grants one. The console applies the same rule to the groups it offers
    /// (<c>modularca.adminui/src/pages/ldapMappings.ts</c>).
    /// </summary>
    public static bool IsRefusedMappingTarget(bool isSystemGroup, bool isSystemTierSuper, bool isControlled) =>
        isSystemGroup || isSystemTierSuper || isControlled;

    /// <inheritdoc />
    public async Task<string?> ValidateMappingsAsync(string? mappingsJson, string? previousMappingsJson = null)
    {
        if (string.IsNullOrWhiteSpace(mappingsJson)) return null;

        Dictionary<string, string>? dict;
        try { dict = JsonSerializer.Deserialize<Dictionary<string, string>>(mappingsJson); }
        catch (JsonException) { return "GroupToRoleMappings must be valid JSON (Dictionary<string, string>)."; }
        if (dict == null || dict.Count == 0) return null;

        // A mapping already stored unchanged passes: sync skips a controlled target at runtime, and
        // re-saving the settings card must not fail on a legacy entry the operator did not touch.
        var previous = new HashSet<(string, string)>();
        if (!string.IsNullOrWhiteSpace(previousMappingsJson))
        {
            try
            {
                foreach (var (k, v) in JsonSerializer.Deserialize<Dictionary<string, string>>(previousMappingsJson) ?? new())
                    if (!string.IsNullOrWhiteSpace(v))
                        previous.Add((k.ToUpperInvariant(), v.Trim().ToUpperInvariant()));
            }
            catch (JsonException) { }
        }

        var targets = dict
            .Where(kv => !string.IsNullOrWhiteSpace(kv.Value)
                         && !previous.Contains((kv.Key.ToUpperInvariant(), kv.Value.Trim().ToUpperInvariant())))
            .Select(kv => kv.Value.Trim())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (targets.Count == 0) return null;
        foreach (var (legacy, renamed) in await ResolveRenamedSpaceGroupsAsync(targets))
        {
            targets.Remove(legacy);
            targets.Add(renamed);
        }

        var groups = (await _db.CaGroups.AsNoTracking().ToListAsync())
            .Where(g => targets.Contains(g.Name))
            .ToList();
        var privileged = new List<string>();
        foreach (var g in groups)
        {
            if (IsRefusedMappingTarget(g.IsSystemGroup, g.IsSystemTierSuper, await ControlledTierResolver.ClassifyGroupAsync(_db, g) != null))
                privileged.Add(g.Name);
        }
        privileged = privileged.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        return privileged.Count == 0
            ? null
            : $"GroupToRoleMappings may not target system or privilege-controlled groups ({string.Join(", ", privileged)}); those memberships change only through the admin ceremony path.";
    }

    /// <inheritdoc />
    public async Task<string?> RewriteRenamedSpaceGroupsAsync(string? mappingsJson)
    {
        if (string.IsNullOrWhiteSpace(mappingsJson)) return mappingsJson;
        Dictionary<string, string>? dict;
        try { dict = JsonSerializer.Deserialize<Dictionary<string, string>>(mappingsJson); }
        catch (JsonException) { return mappingsJson; }
        if (dict == null || dict.Count == 0) return mappingsJson;

        var renamed = await ResolveRenamedSpaceGroupsAsync(
            dict.Values.Where(v => !string.IsNullOrWhiteSpace(v)).Select(v => v.Trim()), warn: false);
        if (renamed.Count == 0) return mappingsJson;
        foreach (var key in dict.Keys.ToList())
            if (dict[key] is { } target && renamed.TryGetValue(target.Trim(), out var name))
                dict[key] = name;
        _logger.LogWarning("LDAP: GroupToRoleMappings rewritten to the 0.4.0 space group names: {Renamed}",
            string.Join(", ", renamed.Select(r => $"{r.Key} -> {r.Value}")));
        return JsonSerializer.Serialize(dict);
    }

    /// <inheritdoc />
    public async Task<string?> RenamedMappingTargetsWarningAsync()
    {
        var renamed = await ResolveRenamedSpaceGroupsAsync(ParseMappings().Select(m => m.CaGroupName), warn: false);
        if (renamed.Count == 0) return null;
        foreach (var legacy in renamed.Keys)
            WarnedRenamedGroups.TryAdd(legacy, 0);
        return "LDAP: LdapAuth.GroupToRoleMappings in config.yaml targets groups that 0.4.0 renamed: "
            + string.Join(", ", renamed.Select(r => $"'{r.Key}' is now '{r.Value}'"))
            + ". Sync uses the new names; a super saving the LDAP settings rewrites them, or rename them in config.yaml.";
    }

    /// <summary>
    /// For each of <paramref name="names"/> of the pre-0.4.0 form
    /// <c>org-&lt;slug&gt;-admin|operator|auditor|user</c> that names no group while
    /// <c>space-&lt;slug&gt;-*</c> does, the new name, with a warning to update config.yaml, once
    /// per legacy name per process: the RenameTenantToSpace migration renamed those groups but
    /// cannot edit the mappings. No other name is ever resolved. With <paramref name="warn"/> false
    /// nothing is logged.
    /// </summary>
    internal async Task<Dictionary<string, string>> ResolveRenamedSpaceGroupsAsync(IEnumerable<string> names, bool warn = true)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var legacy = names.Where(n => LegacySpaceGroupName.IsMatch(n)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (legacy.Count == 0) return result;

        var lookup = legacy.Concat(legacy.Select(RenamedSpaceGroupName)).ToList();
        var existing = await _db.CaGroups.AsNoTracking().Where(g => lookup.Contains(g.Name)).Select(g => g.Name).ToListAsync();
        foreach (var name in legacy)
        {
            var renamed = existing.FirstOrDefault(e => string.Equals(e, RenamedSpaceGroupName(name), StringComparison.OrdinalIgnoreCase));
            if (renamed == null || existing.Contains(name, StringComparer.OrdinalIgnoreCase))
                continue;
            result[name] = renamed;
            if (warn && WarnedRenamedGroups.TryAdd(name, 0))
                _logger.LogWarning(
                    "LDAP: GroupToRoleMappings targets group '{LegacyName}', which 0.4.0 renamed to '{RenamedName}'. Using '{RenamedName}'; update LdapAuth.GroupToRoleMappings in config.yaml.",
                    name, renamed, renamed);
        }
        return result;
    }

    private static readonly System.Text.RegularExpressions.Regex LegacySpaceGroupName = new(
        "^org-.+-(admin|operator|auditor|user)$",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    private static string RenamedSpaceGroupName(string legacyName) => "space-" + legacyName["org-".Length..];

    /// <summary>
    /// The legacy group names already warned about, per process: the service is scoped, so an
    /// instance field would warn on every login.
    /// </summary>
    internal static readonly System.Collections.Concurrent.ConcurrentDictionary<string, byte> WarnedRenamedGroups =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Parses the GroupToRoleMappings config as a dictionary mapping LDAP group DNs to CaGroup names.
    /// </summary>
    private List<(string GroupDn, string CaGroupName)> ParseMappings()
    {
        var result = new List<(string, string)>();
        if (string.IsNullOrWhiteSpace(_config.LdapAuth.GroupToRoleMappings)) return result;

        var dict = JsonSerializer.Deserialize<Dictionary<string, string>>(_config.LdapAuth.GroupToRoleMappings);
        if (dict == null) return result;

        foreach (var (groupDn, caGroupName) in dict)
        {
            if (!string.IsNullOrWhiteSpace(caGroupName))
                result.Add((groupDn, caGroupName));
            else
                _logger.LogWarning("LDAP sync: empty CaGroup name in mapping for '{GroupDn}'", groupDn);
        }

        return result;
    }
}
