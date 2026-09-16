using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;

namespace ModularCA.Auth.Authorization;

/// <summary>
/// Resolves the worn badge from the access token's <c>badge</c> claim, once per request.
/// </summary>
/// <remarks>
/// Outside an HTTP request there is no claim and therefore no badge: scheduled jobs and
/// protocol clients are unaffected. A claim naming a badge that no longer exists, or that
/// belongs to another user, yields <see cref="AccessBadgeFilter.Nothing"/>, so the token grants
/// nothing until its holder switches badgeless (which the switch endpoint still allows).
/// </remarks>
public sealed class AccessBadgeContext : IAccessBadgeContext, IWornBadgeProvider
{
    /// <summary>Access-token claim carrying the worn badge's id.</summary>
    public const string BadgeClaim = "badge";
    /// <summary>Access-token claim carrying the worn badge's name, for audit rows and the banner.</summary>
    public const string BadgeNameClaim = "badgen";

    private const string ItemsKey = "ModularCA.AccessBadgeFilter";

    private readonly ModularCADbContext _db;
    private readonly IHttpContextAccessor? _http;

    public AccessBadgeContext(ModularCADbContext db, IHttpContextAccessor? http = null)
    {
        _db = db;
        _http = http;
    }

    /// <inheritdoc />
    public Guid? BadgeId
    {
        get
        {
            var raw = _http?.HttpContext?.User?.FindFirst(BadgeClaim)?.Value;
            return Guid.TryParse(raw, out var id) ? id : null;
        }
    }

    /// <inheritdoc />
    public string? BadgeName => BadgeId == null ? null : _http?.HttpContext?.User?.FindFirst(BadgeNameClaim)?.Value;

    /// <inheritdoc />
    public async Task<AccessBadgeFilter?> GetWornAsync(Guid userId)
    {
        var http = _http?.HttpContext;
        if (http == null) return null;
        if (http.Items.TryGetValue(ItemsKey, out var cached)) return cached as AccessBadgeFilter;

        AccessBadgeFilter? filter = null;
        if (BadgeId is Guid badgeId)
        {
            var badge = await _db.AccessBadges
                .AsNoTracking()
                .Include(b => b.Sources)
                .FirstOrDefaultAsync(b => b.Id == badgeId && b.UserId == userId);
            filter = badge == null
                ? AccessBadgeFilter.Nothing(badgeId)
                : new AccessBadgeFilter(
                    badge.Id,
                    badge.Name,
                    badge.Sources.Where(s => s.Kind == AccessBadgeSourceKind.Group).Select(s => s.SourceId).ToList(),
                    badge.Sources.Where(s => s.Kind == AccessBadgeSourceKind.RoleAssignment).Select(s => s.SourceId).ToList(),
                    badge.Sources.Where(s => s.Kind == AccessBadgeSourceKind.CapabilityGrant).Select(s => s.SourceId).ToList());
        }

        http.Items[ItemsKey] = filter;
        return filter;
    }
}
