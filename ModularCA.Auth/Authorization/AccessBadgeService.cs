using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Models.AccessBadges;

namespace ModularCA.Auth.Authorization;

/// <summary>
/// Creates, edits and lists a user's access badges, and enforces the one invariant that keeps
/// badges safe: a badge may only name grant sources its owner genuinely holds.
/// </summary>
/// <remarks>
/// Used by both the self-service endpoints (a user managing their own badges) and the
/// administrative ones (an administrator managing someone else's); the caller decides who
/// <c>userId</c> is, this class only ever restricts to that user's sources. Deleting a badge
/// clears it from every refresh token that carried it, so the next refresh is badgeless; an
/// access token already minted keeps naming it until it expires and grants nothing meanwhile.
/// </remarks>
public sealed class AccessBadgeService
{
    private readonly ModularCADbContext _db;

    public AccessBadgeService(ModularCADbContext db)
    {
        _db = db;
    }

    /// <summary>Thrown for a request that names a source the user does not hold, or a duplicate name.</summary>
    public sealed class BadgeValidationException(string message) : Exception(message);

    /// <summary>All badges of a user, with their sources labelled.</summary>
    public async Task<List<AccessBadgeDto>> ListAsync(Guid userId)
    {
        var badges = await _db.AccessBadges
            .AsNoTracking()
            .Include(b => b.Sources)
            .Where(b => b.UserId == userId)
            .OrderBy(b => b.Name)
            .ToListAsync();
        var options = await ListSourceOptionsAsync(userId);
        return badges.Select(b => ToDto(b, options)).ToList();
    }

    /// <summary>One badge of a user, or null.</summary>
    public async Task<AccessBadgeDto?> GetAsync(Guid userId, Guid badgeId)
    {
        var badge = await _db.AccessBadges
            .AsNoTracking()
            .Include(b => b.Sources)
            .FirstOrDefaultAsync(b => b.Id == badgeId && b.UserId == userId);
        if (badge == null) return null;
        return ToDto(badge, await ListSourceOptionsAsync(userId));
    }

    /// <summary>The badge a new session of this user starts on, or null.</summary>
    public Task<AccessBadgeEntity?> GetDefaultAsync(Guid userId)
        => _db.AccessBadges.AsNoTracking().FirstOrDefaultAsync(b => b.UserId == userId && b.IsDefault);

    /// <summary>Creates a badge for the user from sources they hold.</summary>
    public async Task<AccessBadgeDto> CreateAsync(Guid userId, AccessBadgeWriteRequest request, Guid? actorUserId)
    {
        var name = request.Name.Trim();
        var options = await ValidateAsync(userId, request, excludeBadgeId: null);

        var badge = new AccessBadgeEntity
        {
            UserId = userId,
            Name = name,
            Description = string.IsNullOrWhiteSpace(request.Description) ? null : request.Description.Trim(),
            IsDefault = request.IsDefault,
            CreatedByUserId = actorUserId,
        };
        foreach (var s in Distinct(request.Sources))
            badge.Sources.Add(new AccessBadgeSourceEntity { BadgeId = badge.Id, Kind = s.Kind, SourceId = s.SourceId });

        if (request.IsDefault) await ClearDefaultAsync(userId);
        _db.AccessBadges.Add(badge);
        await _db.SaveChangesAsync();
        return ToDto(badge, options);
    }

    /// <summary>Replaces a badge's name, description, default flag and sources.</summary>
    public async Task<AccessBadgeDto?> UpdateAsync(Guid userId, Guid badgeId, AccessBadgeWriteRequest request)
    {
        var badge = await _db.AccessBadges
            .Include(b => b.Sources)
            .FirstOrDefaultAsync(b => b.Id == badgeId && b.UserId == userId);
        if (badge == null) return null;

        var options = await ValidateAsync(userId, request, excludeBadgeId: badgeId);

        badge.Name = request.Name.Trim();
        badge.Description = string.IsNullOrWhiteSpace(request.Description) ? null : request.Description.Trim();
        badge.UpdatedAt = DateTime.UtcNow;
        if (request.IsDefault && !badge.IsDefault) await ClearDefaultAsync(userId);
        badge.IsDefault = request.IsDefault;

        _db.AccessBadgeSources.RemoveRange(badge.Sources);
        badge.Sources.Clear();
        foreach (var s in Distinct(request.Sources))
            badge.Sources.Add(new AccessBadgeSourceEntity { BadgeId = badge.Id, Kind = s.Kind, SourceId = s.SourceId });

        await _db.SaveChangesAsync();
        return ToDto(badge, options);
    }

    /// <summary>Deletes a badge and takes it off every session that carried it.</summary>
    public async Task<bool> DeleteAsync(Guid userId, Guid badgeId)
    {
        var badge = await _db.AccessBadges.FirstOrDefaultAsync(b => b.Id == badgeId && b.UserId == userId);
        if (badge == null) return false;

        var carrying = await _db.RefreshTokens.Where(t => t.AccessBadgeId == badgeId).ToListAsync();
        foreach (var t in carrying) t.AccessBadgeId = null;

        _db.AccessBadges.Remove(badge);
        await _db.SaveChangesAsync();
        return true;
    }

    /// <summary>
    /// Every grant source the user holds: group memberships (with the group's grants and
    /// roles), direct role assignments and direct capability grants. These are the only things
    /// a badge may be made of.
    /// </summary>
    public async Task<List<AccessBadgeSourceOptionDto>> ListSourceOptionsAsync(Guid userId)
    {
        var options = new List<AccessBadgeSourceOptionDto>();

        var groups = await _db.CaGroups
            .AsNoTracking()
            .Where(g => g.Members.Any(m => m.UserId == userId))
            .Include(g => g.CertificateAuthority)
            .Include(g => g.Grants)
            .Include(g => g.RoleAssignments).ThenInclude(ra => ra.Role).ThenInclude(r => r.Capabilities)
            .ToListAsync();
        foreach (var g in groups)
        {
            var caps = g.Grants.Where(x => x.ResourceType == null).Select(x => x.Capability)
                .Concat(g.RoleAssignments.SelectMany(ra => ra.Role.Capabilities.Where(rc => rc.ResourceType == null).Select(rc => rc.Capability)))
                .Distinct().OrderBy(c => c, StringComparer.Ordinal).ToList();
            options.Add(new AccessBadgeSourceOptionDto
            {
                Kind = AccessBadgeSourceKind.Group,
                SourceId = g.Id,
                Label = string.IsNullOrEmpty(g.DisplayName) ? g.Name : g.DisplayName,
                Scope = g.IsSystemGroup ? "System" : g.CertificateAuthority?.Label ?? $"tenant {g.TenantId}",
                Capabilities = caps,
            });
        }

        var roles = await _db.RoleAssignments
            .AsNoTracking()
            .Include(ra => ra.Role).ThenInclude(r => r.Capabilities)
            .Include(ra => ra.CertificateAuthority)
            .Where(ra => ra.UserId == userId && ra.GroupId == null)
            .ToListAsync();
        foreach (var ra in roles)
        {
            options.Add(new AccessBadgeSourceOptionDto
            {
                Kind = AccessBadgeSourceKind.RoleAssignment,
                SourceId = ra.Id,
                Label = $"Role: {ra.Role.Name}",
                Scope = ScopeOf(ra.TenantId, ra.CertificateAuthorityId, ra.CertificateAuthority?.Label),
                Capabilities = ra.Role.Capabilities.Where(rc => rc.ResourceType == null).Select(rc => rc.Capability)
                    .Distinct().OrderBy(c => c, StringComparer.Ordinal).ToList(),
            });
        }

        var grants = await _db.UserCapabilityGrants
            .AsNoTracking()
            .Include(ug => ug.CertificateAuthority)
            .Where(ug => ug.UserId == userId)
            .ToListAsync();
        foreach (var ug in grants)
        {
            options.Add(new AccessBadgeSourceOptionDto
            {
                Kind = AccessBadgeSourceKind.CapabilityGrant,
                SourceId = ug.Id,
                Label = ug.ResourceType == null ? ug.Capability : $"{ug.Capability} on {ug.ResourceType}",
                Scope = ScopeOf(ug.TenantId, ug.CertificateAuthorityId, ug.CertificateAuthority?.Label),
                Capabilities = ug.ResourceType == null ? [ug.Capability] : [],
            });
        }

        return options;
    }

    private static string ScopeOf(Guid? tenantId, Guid? caId, string? caLabel)
    {
        if (caId != null) return caLabel ?? caId.Value.ToString();
        if (tenantId != null) return $"tenant {tenantId}";
        return "System";
    }

    private async Task<List<AccessBadgeSourceOptionDto>> ValidateAsync(Guid userId, AccessBadgeWriteRequest request, Guid? excludeBadgeId)
    {
        var name = request.Name?.Trim() ?? string.Empty;
        if (name.Length == 0) throw new BadgeValidationException("A badge needs a name.");
        if (request.Sources == null || request.Sources.Count == 0)
            throw new BadgeValidationException("A badge needs at least one grant source; an empty badge would grant nothing.");

        var clash = await _db.AccessBadges.AnyAsync(b => b.UserId == userId && b.Name == name && (excludeBadgeId == null || b.Id != excludeBadgeId));
        if (clash) throw new BadgeValidationException($"A badge named '{name}' already exists.");

        var options = await ListSourceOptionsAsync(userId);
        var held = options.Select(o => new AccessBadgePolicy.SourceKey(o.Kind, o.SourceId)).ToHashSet();
        var foreign = request.Sources.Where(s => !held.Contains(new AccessBadgePolicy.SourceKey(s.Kind, s.SourceId))).ToList();
        if (foreign.Count > 0)
            throw new BadgeValidationException("A badge can only keep grant sources the user already holds; " +
                $"{foreign.Count} of the requested sources are not theirs.");
        return options;
    }

    private async Task ClearDefaultAsync(Guid userId)
    {
        var current = await _db.AccessBadges.Where(b => b.UserId == userId && b.IsDefault).ToListAsync();
        foreach (var b in current) b.IsDefault = false;
    }

    private static IEnumerable<AccessBadgeSourceRef> Distinct(IEnumerable<AccessBadgeSourceRef> refs)
        => refs.GroupBy(r => new AccessBadgePolicy.SourceKey(r.Kind, r.SourceId)).Select(g => g.First());

    private static AccessBadgeDto ToDto(AccessBadgeEntity badge, List<AccessBadgeSourceOptionDto> options) => new()
    {
        Id = badge.Id,
        UserId = badge.UserId,
        Name = badge.Name,
        Description = badge.Description,
        IsDefault = badge.IsDefault,
        CreatedAt = badge.CreatedAt,
        UpdatedAt = badge.UpdatedAt,
        Sources = badge.Sources.Select(s => new AccessBadgeSourceDto
        {
            Kind = s.Kind,
            SourceId = s.SourceId,
            Label = options.FirstOrDefault(o => o.Kind == s.Kind && o.SourceId == s.SourceId)?.Label,
        }).ToList(),
    };
}
