using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Signing;
using ModularCA.Shared.Utils;
using ModularCA.Ssh;

namespace ModularCA.Core.Services;

/// <summary>
/// SSH login names over the application database: who holds which name on which SSH CA key
/// (<see cref="SshLoginNameHolding"/>), the grants, what the admin and self-service routes read,
/// and the reconciliation that keeps two invariants: a live certificate issued with grounds
/// never carries a login name its subject no longer holds, and a live certificate issued for a
/// user is on an SSH CA that user may request from (<see cref="ISshRequestRights"/>). It signs
/// nothing and asks no signer.
/// </summary>
/// <remarks>
/// A reconciliation saves on the context it was given, after the change that prompted it has
/// been saved by its caller. The two are one transaction only where the caller holds one.
/// <see cref="SweepAsync"/>, run on a schedule, revokes what a stop between the two left live,
/// and what a change that no hook follows took away.
/// </remarks>
public sealed class SshLoginNameService : ISshLoginNameService
{
    private const string UserType = SshCertificateRequest.UserType;
    private const string HostType = SshCertificateRequest.HostType;

    /// <summary>The longest note left with a grant: the width of <see cref="SshLoginNameGrantEntity.Note"/>.</summary>
    public const int MaxNoteLength = 256;

    /// <summary>The most login names one grant request may carry.</summary>
    public const int MaxNamesPerRequest = 64;

    /// <summary>What the audit entry of a revocation says when its subject may no longer request from the SSH CA.</summary>
    public const string RequestRightLost = "the user may no longer request certificates from the SSH CA";

    private readonly ModularCADbContext _db;
    private readonly IAuditService _audit;
    private readonly ISshRequestRights _rights;
    private readonly ILogger<SshLoginNameService> _logger;

    /// <summary>
    /// Creates the service over the application database, the audit, and <paramref name="rights"/>,
    /// which says which SSH CAs a certificate's subject may request from.
    /// </summary>
    public SshLoginNameService(ModularCADbContext db, IAuditService audit, ISshRequestRights rights, ILogger<SshLoginNameService>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(rights);
        _db = db;
        _audit = audit;
        _rights = rights;
        _logger = logger ?? NullLogger<SshLoginNameService>.Instance;
    }

    // ---- Holding -----------------------------------------------------------------------------

    /// <inheritdoc />
    public async Task<IReadOnlyList<SshHeldLoginName>> HeldAsync(Guid userId, Guid caKeyId, CancellationToken cancellationToken = default)
    {
        var key = await _db.SshCaKeys.AsNoTracking().FirstOrDefaultAsync(k => k.Id == caKeyId, cancellationToken);
        if (key == null)
            return [];
        var now = DateTime.UtcNow;
        return SshLoginNameHolding.Held(await GroundsAsync(userId, key, now, cancellationToken), key.MaxValidityHours, StartOf(now));
    }

    /// <inheritdoc />
    public async Task<SshLoginNameIssuance> ForIssuanceAsync(Guid userId, Guid caKeyId, IReadOnlyList<string> principals, DateTime validAfter,
        CancellationToken cancellationToken = default)
    {
        var key = await _db.SshCaKeys.AsNoTracking().FirstOrDefaultAsync(k => k.Id == caKeyId, cancellationToken)
            ?? throw new InvalidOperationException("SSH CA key not found");
        var grounds = await GroundsAsync(userId, key, DateTime.UtcNow, cancellationToken);
        return SshLoginNameHolding.Issuance(SshLoginNameHolding.Held(grounds, key.MaxValidityHours, validAfter), principals);
    }

    /// <summary>
    /// Every ground on which a user holds a login name on <paramref name="key"/> at
    /// <paramref name="now"/>, read from the user row, the user's memberships and the key's grants.
    /// </summary>
    private async Task<IReadOnlyList<SshLoginNameGround>> GroundsAsync(Guid userId, SshCaKeyEntity key, DateTime now, CancellationToken cancellationToken)
    {
        var user = await _db.Users.AsNoTracking().Where(u => u.Id == userId).Select(u => new { u.Username }).FirstOrDefaultAsync(cancellationToken);
        if (user == null)
            return [];
        var groupIds = await _db.CaGroupMembers.AsNoTracking().Where(m => m.UserId == userId).Select(m => m.GroupId).ToListAsync(cancellationToken);
        var grants = await _db.SshLoginNameGrants.AsNoTracking()
            .Where(g => g.SshCaKeyId == key.Id && (g.UserId == userId || (g.GroupId != null && groupIds.Contains(g.GroupId.Value))))
            .ToListAsync(cancellationToken);
        var groupNames = await GroupNamesAsync(grants.Where(g => g.GroupId != null).Select(g => g.GroupId!.Value), cancellationToken);
        return SshLoginNameHolding.Grounds(userId, user.Username, key.AllowOwnUsername, groupIds.ToHashSet(),
            grants.Select(g => RowOf(g, groupNames)), now);
    }

    private static SshLoginNameGrantRow RowOf(SshLoginNameGrantEntity grant, IReadOnlyDictionary<Guid, (string Name, string DisplayName)> groups)
        => new(grant.Id, grant.LoginName, grant.UserId, grant.GroupId,
            grant.GroupId is Guid g && groups.TryGetValue(g, out var group) ? group.Name : null,
            grant.MaxValidityHours, grant.ExpiresAt, grant.GrantedByUserId, grant.GrantedByUsername);

    private async Task<Dictionary<Guid, (string Name, string DisplayName)>> GroupNamesAsync(IEnumerable<Guid> groupIds, CancellationToken cancellationToken)
    {
        var ids = groupIds.Distinct().ToList();
        if (ids.Count == 0)
            return [];
        return (await _db.CaGroups.AsNoTracking().Where(g => ids.Contains(g.Id)).Select(g => new { g.Id, g.Name, g.DisplayName }).ToListAsync(cancellationToken))
            .ToDictionary(g => g.Id, g => (g.Name, g.DisplayName));
    }

    /// <summary>The start of a certificate issued at <paramref name="now"/>, as <see cref="SshCaService"/> backdates it.</summary>
    private static DateTime StartOf(DateTime now) => now.Subtract(SshCaService.ValidAfterBackdate);

    // ---- Who a key may refer to --------------------------------------------------------------

    /// <inheritdoc />
    public async Task<IReadOnlySet<Guid?>> ScopesOfUserAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        var scopes = new HashSet<Guid?>();
        foreach (var space in await _db.CaGroupMembers.AsNoTracking().Where(m => m.UserId == userId).Select(m => m.Group.SpaceId).ToListAsync(cancellationToken))
            scopes.Add(space);

        var direct = (await _db.UserCapabilityGrants.AsNoTracking().Where(g => g.UserId == userId)
                .Select(g => new { g.SpaceId, g.CertificateAuthorityId }).ToListAsync(cancellationToken))
            .Select(g => (g.SpaceId, g.CertificateAuthorityId))
            .Concat((await _db.RoleAssignments.AsNoTracking().Where(r => r.UserId == userId && r.GroupId == null)
                    .Select(r => new { r.SpaceId, r.CertificateAuthorityId }).ToListAsync(cancellationToken))
                .Select(r => (r.SpaceId, r.CertificateAuthorityId)))
            .ToList();
        var caIds = direct.Where(d => d.CertificateAuthorityId != null).Select(d => d.CertificateAuthorityId!.Value).Distinct().ToList();
        var caSpaces = caIds.Count == 0
            ? []
            : await _db.CertificateAuthorities.AsNoTracking().Where(c => caIds.Contains(c.Id)).ToDictionaryAsync(c => c.Id, c => c.SpaceId, cancellationToken);
        foreach (var (spaceId, caId) in direct)
        {
            if (caId is Guid ca)
            {
                if (caSpaces.TryGetValue(ca, out var caSpace))
                    scopes.Add(caSpace);
            }
            else
            {
                scopes.Add(spaceId);
            }
        }
        return scopes;
    }

    /// <inheritdoc />
    public async Task<bool> MayReferenceUserAsync(Guid caKeyId, Guid userId, CancellationToken cancellationToken = default)
    {
        var scope = await ScopeOfKeyAsync(caKeyId, cancellationToken);
        if (scope == null || !await _db.Users.AsNoTracking().AnyAsync(u => u.Id == userId, cancellationToken))
            return false;
        return (await ScopesOfUserAsync(userId, cancellationToken)).Contains(scope.Value.SpaceId);
    }

    /// <inheritdoc />
    public async Task<bool> MayRequestAsync(Guid userId, Guid caKeyId, CancellationToken cancellationToken = default)
    {
        var caId = await _db.SshCaKeys.AsNoTracking().Where(k => k.Id == caKeyId).Select(k => (Guid?)k.CertificateAuthorityId).FirstOrDefaultAsync(cancellationToken);
        return caId is Guid ca && (await _rights.RequestableCaIdsAsync(userId, cancellationToken)).Contains(ca);
    }

    /// <summary>The space of the certificate authority an SSH CA key belongs to (null for the instance), or null when there is no such key or authority.</summary>
    private async Task<(Guid? SpaceId, Guid CaId)?> ScopeOfKeyAsync(Guid caKeyId, CancellationToken cancellationToken)
    {
        var found = await _db.SshCaKeys.AsNoTracking().Where(k => k.Id == caKeyId)
            .Join(_db.CertificateAuthorities.AsNoTracking(), k => k.CertificateAuthorityId, c => c.Id, (k, c) => new { c.SpaceId, c.Id })
            .FirstOrDefaultAsync(cancellationToken);
        return found == null ? null : (found.SpaceId, found.Id);
    }

    // ---- Grants ------------------------------------------------------------------------------

    /// <inheritdoc />
    public async Task<SshLoginNameGrantList?> ListAsync(Guid caKeyId, CancellationToken cancellationToken = default)
    {
        var key = await _db.SshCaKeys.AsNoTracking().FirstOrDefaultAsync(k => k.Id == caKeyId, cancellationToken);
        if (key == null)
            return null;
        var grants = await _db.SshLoginNameGrants.AsNoTracking().Where(g => g.SshCaKeyId == caKeyId).ToListAsync(cancellationToken);
        return new SshLoginNameGrantList(KeyRefOf(key), key.MaxValidityHours, key.AllowOwnUsername, await ViewsAsync(grants, cancellationToken));
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<SshLoginNameGrantView>> GrantAsync(Guid caKeyId, SshLoginNameGrantRequest request, SshCaActor? actor = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var key = await _db.SshCaKeys.AsNoTracking().FirstOrDefaultAsync(k => k.Id == caKeyId, cancellationToken)
            ?? throw new ResourceNotFoundException("SSH CA key", "SSH CA key not found.", caKeyId.ToString());
        if (!key.IsUserCa)
            throw new InvalidRequestException($"SSH CA key '{key.Name}' signs no user certificates, so it has no login names.");

        var names = (request.LoginNames ?? []).ToList();
        if (names.Count == 0)
            throw new InvalidRequestException("Name at least one login name to grant.");
        if (names.Count > MaxNamesPerRequest)
            throw new InvalidRequestException($"At most {MaxNamesPerRequest} login names can be granted at once.");
        foreach (var name in names)
        {
            if (SshLoginNameRules.Error(name) is { } nameError)
                throw new InvalidRequestException(nameError);
        }
        if (names.Distinct(StringComparer.Ordinal).Count() != names.Count)
            throw new InvalidRequestException("A login name is listed twice.");
        if (request.UserId == null == (request.GroupId == null))
            throw new InvalidRequestException("Grant to exactly one of a user (userId) or a group (groupId).");

        var now = DateTime.UtcNow;
        var expiresAt = Utc(request.ExpiresAt);
        CheckTerms(key, request.MaxValidityHours, expiresAt, request.Note, now);

        string targetName;
        if (request.UserId is Guid userId)
        {
            if (!await MayReferenceUserAsync(caKeyId, userId, cancellationToken))
                throw new InvalidRequestException(
                    "The user does not exist, or has no membership, role or grant in this SSH CA's scope. Give the user a role on the SSH CA first.");
            targetName = await _db.Users.AsNoTracking().Where(u => u.Id == userId).Select(u => u.Username).FirstAsync(cancellationToken);
        }
        else
        {
            var scope = await ScopeOfKeyAsync(caKeyId, cancellationToken);
            var group = await _db.CaGroups.AsNoTracking().Where(g => g.Id == request.GroupId).Select(g => new { g.Name, g.SpaceId }).FirstOrDefaultAsync(cancellationToken);
            if (group == null || scope == null || group.SpaceId != scope.Value.SpaceId)
                throw new InvalidRequestException("The group does not exist, or belongs to another scope than this SSH CA.");
            targetName = group.Name;
        }

        var existing = await _db.SshLoginNameGrants.AsNoTracking()
            .Where(g => g.SshCaKeyId == caKeyId && names.Contains(g.LoginName)
                && ((request.UserId != null && g.UserId == request.UserId) || (request.GroupId != null && g.GroupId == request.GroupId)))
            .Select(g => g.LoginName)
            .ToListAsync(cancellationToken);
        if (existing.Count > 0)
            throw Conflict(existing, targetName, key.Name);

        var note = string.IsNullOrWhiteSpace(request.Note) ? null : request.Note.Trim();
        var grants = names.Select(name => new SshLoginNameGrantEntity
        {
            SshCaKeyId = caKeyId,
            LoginName = name,
            UserId = request.UserId,
            GroupId = request.GroupId,
            MaxValidityHours = request.MaxValidityHours,
            ExpiresAt = expiresAt,
            Note = note,
            GrantedByUserId = actor?.UserId,
            GrantedByUsername = actor?.Username,
            CreatedAt = now,
        }).ToList();
        _db.SshLoginNameGrants.AddRange(grants);
        try
        {
            await _db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException ex) when (PostgresErrorUtil.IsUniqueViolation(ex))
        {
            foreach (var grant in grants)
                _db.Entry(grant).State = EntityState.Detached;
            throw Conflict(names, targetName, key.Name);
        }

        foreach (var grant in grants)
        {
            await _audit.LogAsync(AuditActionType.SshLoginNameGranted, actor?.UserId, actor?.Username ?? "system",
                "SshLoginNameGrant", grant.Id.ToString(),
                new
                {
                    SshCaKeyId = caKeyId, SshCaKeyName = key.Name, grant.LoginName, grant.UserId, grant.GroupId, Target = targetName,
                    grant.MaxValidityHours, grant.ExpiresAt,
                },
                actor?.SourceIp, certificateAuthorityId: key.CertificateAuthorityId);
        }
        return await ViewsAsync(grants, cancellationToken);
    }

    /// <summary>The 409 for names the target already has on the key.</summary>
    private static ResourceConflictException Conflict(IReadOnlyCollection<string> names, string target, string keyName)
        => new($"'{target}' already has a grant of {string.Join(", ", names.Select(n => $"'{n}'"))} on SSH CA key '{keyName}'. "
            + "Nothing was granted. Change that grant, or remove it first.");

    /// <summary>Refuses a limit over the key's maximum or under an hour, an end that is not in the future, and a note that is too long.</summary>
    private static void CheckTerms(SshCaKeyEntity key, int? maxValidityHours, DateTime? expiresAt, string? note, DateTime now)
    {
        if (maxValidityHours is { } hours && (hours < 1 || hours > key.MaxValidityHours))
            throw new InvalidRequestException(
                $"The longest certificate must be between 1 and {key.MaxValidityHours} hours, the maximum of SSH CA key '{key.Name}'. Leave it out for that maximum.");
        if (expiresAt is { } end && end <= now)
            throw new InvalidRequestException("The grant's end is in the past. Remove the grant to end it now.");
        if (note != null && note.Trim().Length > MaxNoteLength)
            throw new InvalidRequestException($"The note is longer than {MaxNoteLength} characters.");
    }

    /// <summary>A time from a request as UTC: a time with no zone is read as UTC.</summary>
    private static DateTime? Utc(DateTime? time) => time switch
    {
        null => null,
        { Kind: DateTimeKind.Local } local => local.ToUniversalTime(),
        { } other => DateTime.SpecifyKind(other, DateTimeKind.Utc),
    };

    /// <inheritdoc />
    public async Task<SshLoginNameGrantChanged?> ChangeGrantAsync(Guid caKeyId, Guid grantId, SshLoginNameGrantChange change, SshCaActor? actor = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(change);
        var grant = await _db.SshLoginNameGrants.FirstOrDefaultAsync(g => g.Id == grantId && g.SshCaKeyId == caKeyId, cancellationToken);
        var key = grant == null ? null : await _db.SshCaKeys.AsNoTracking().FirstOrDefaultAsync(k => k.Id == caKeyId, cancellationToken);
        if (grant == null || key == null)
            return null;

        var now = DateTime.UtcNow;
        var expiresAt = Utc(change.ExpiresAt);
        CheckTerms(key, change.MaxValidityHours, expiresAt == grant.ExpiresAt ? null : expiresAt, change.Note, now);

        var before = new { grant.MaxValidityHours, grant.ExpiresAt };
        var endsEarlier = expiresAt != null && (grant.ExpiresAt == null || expiresAt < grant.ExpiresAt);
        grant.MaxValidityHours = change.MaxValidityHours;
        grant.ExpiresAt = expiresAt;
        grant.Note = string.IsNullOrWhiteSpace(change.Note) ? null : change.Note.Trim();
        await _db.SaveChangesAsync(cancellationToken);

        await _audit.LogAsync(AuditActionType.SshLoginNameGrantChanged, actor?.UserId, actor?.Username ?? "system",
            "SshLoginNameGrant", grant.Id.ToString(),
            new
            {
                SshCaKeyId = caKeyId, SshCaKeyName = key.Name, grant.LoginName, grant.UserId, grant.GroupId,
                grant.MaxValidityHours, grant.ExpiresAt, Before = before,
            },
            actor?.SourceIp, certificateAuthorityId: key.CertificateAuthorityId);

        var revoked = endsEarlier
            ? await ReconcileKeyAsync(caKeyId, $"the grant of login name '{grant.LoginName}' now ends earlier", actor, cancellationToken)
            : 0;
        return new SshLoginNameGrantChanged((await ViewsAsync([grant], cancellationToken))[0], revoked);
    }

    /// <inheritdoc />
    public async Task<int?> RemoveGrantAsync(Guid caKeyId, Guid grantId, SshCaActor? actor = null, CancellationToken cancellationToken = default)
    {
        var grant = await _db.SshLoginNameGrants.FirstOrDefaultAsync(g => g.Id == grantId && g.SshCaKeyId == caKeyId, cancellationToken);
        if (grant == null)
            return null;
        await RemoveGrantsAsync([grant], "removed by an administrator", actor, cancellationToken);
        return await ReconcileKeyAsync(caKeyId, $"the grant of login name '{grant.LoginName}' was removed", actor, cancellationToken);
    }

    /// <summary>Removes grants and writes the audit entry of each, with why it went.</summary>
    private async Task RemoveGrantsAsync(IReadOnlyList<SshLoginNameGrantEntity> grants, string reason, SshCaActor? actor, CancellationToken cancellationToken)
    {
        if (grants.Count == 0)
            return;
        var keyIds = grants.Select(g => g.SshCaKeyId).Distinct().ToList();
        var keys = await _db.SshCaKeys.AsNoTracking().Where(k => keyIds.Contains(k.Id)).ToDictionaryAsync(k => k.Id, cancellationToken);
        _db.SshLoginNameGrants.RemoveRange(grants);
        await _db.SaveChangesAsync(cancellationToken);
        foreach (var grant in grants)
        {
            keys.TryGetValue(grant.SshCaKeyId, out var key);
            await _audit.LogAsync(AuditActionType.SshLoginNameGrantRemoved, actor?.UserId, actor?.Username ?? "system",
                "SshLoginNameGrant", grant.Id.ToString(),
                new { grant.SshCaKeyId, SshCaKeyName = key?.Name, grant.LoginName, grant.UserId, grant.GroupId, Reason = reason },
                actor?.SourceIp, certificateAuthorityId: key?.CertificateAuthorityId);
        }
    }

    /// <inheritdoc />
    public async Task<int?> SetOwnUsernameAsync(Guid caKeyId, bool allowed, SshCaActor? actor = null, CancellationToken cancellationToken = default)
    {
        var key = await _db.SshCaKeys.FirstOrDefaultAsync(k => k.Id == caKeyId, cancellationToken);
        if (key == null)
            return null;
        var was = key.AllowOwnUsername;
        key.AllowOwnUsername = allowed;
        await _db.SaveChangesAsync(cancellationToken);

        var revoked = was && !allowed
            ? await ReconcileKeyAsync(caKeyId, "logging in as one's own username was turned off on the SSH CA key", actor, cancellationToken)
            : 0;
        await _audit.LogAsync(AuditActionType.SshOwnUsernameChanged, actor?.UserId, actor?.Username ?? "system",
            "SshCaKey", caKeyId.ToString(),
            new { SshCaKeyName = key.Name, Allowed = allowed, Was = was, RevokedCertificates = revoked },
            actor?.SourceIp, certificateAuthorityId: key.CertificateAuthorityId);
        return revoked;
    }

    /// <summary>The grants as the admin API answers them, by login name, then by who they were made to.</summary>
    private async Task<IReadOnlyList<SshLoginNameGrantView>> ViewsAsync(IReadOnlyList<SshLoginNameGrantEntity> grants, CancellationToken cancellationToken)
    {
        if (grants.Count == 0)
            return [];
        var now = DateTime.UtcNow;
        var keyIds = grants.Select(g => g.SshCaKeyId).Distinct().ToList();
        var keys = (await _db.SshCaKeys.AsNoTracking().Where(k => keyIds.Contains(k.Id)).ToListAsync(cancellationToken)).ToDictionary(k => k.Id, KeyRefOf);
        var userIds = grants.Where(g => g.UserId != null).Select(g => g.UserId!.Value).Distinct().ToList();
        var users = userIds.Count == 0
            ? []
            : await _db.Users.AsNoTracking().Where(u => userIds.Contains(u.Id)).ToDictionaryAsync(u => u.Id, u => u.Username, cancellationToken);
        var groupIds = grants.Where(g => g.GroupId != null).Select(g => g.GroupId!.Value).Distinct().ToList();
        var groups = await GroupNamesAsync(groupIds, cancellationToken);
        var members = groupIds.Count == 0
            ? []
            : (await _db.CaGroupMembers.AsNoTracking().Where(m => groupIds.Contains(m.GroupId)).Select(m => m.GroupId).ToListAsync(cancellationToken))
                .GroupBy(g => g).ToDictionary(g => g.Key, g => g.Count());

        var live = new Dictionary<Guid, int>();
        var stored = await _db.SshCertificates.AsNoTracking()
            .Where(c => keyIds.Contains(c.SshCaKeyId) && !c.IsRevoked && c.ValidBefore > now && c.LoginNameGrounds != null)
            .Select(c => c.LoginNameGrounds)
            .ToListAsync(cancellationToken);
        foreach (var grounds in stored)
        {
            foreach (var grantId in (SshLoginNameHolding.Parse(grounds) ?? []).Where(g => g.GrantId != null).Select(g => g.GrantId!.Value).Distinct())
                live[grantId] = live.GetValueOrDefault(grantId) + 1;
        }

        return grants
            .Select(g => new SshLoginNameGrantView(
                g.Id,
                keys.GetValueOrDefault(g.SshCaKeyId) ?? new SshCaKeyRef(g.SshCaKeyId, string.Empty, null, Guid.Empty),
                g.LoginName,
                g.UserId is Guid u ? new SshUserRef(u, users.GetValueOrDefault(u)) : null,
                g.GroupId is Guid gr
                    ? new SshGroupRef(gr, groups.TryGetValue(gr, out var group) ? group.Name : string.Empty,
                        groups.TryGetValue(gr, out group) ? group.DisplayName : string.Empty, members.GetValueOrDefault(gr))
                    : null,
                g.MaxValidityHours, g.ExpiresAt, g.ExpiresAt is { } end && end <= now, g.Note,
                new SshUserRef(g.GrantedByUserId, g.GrantedByUsername), g.CreatedAt, live.GetValueOrDefault(g.Id)))
            .OrderBy(v => v.LoginName, StringComparer.Ordinal)
            .ThenBy(v => v.Group?.Name ?? v.User?.Username, StringComparer.OrdinalIgnoreCase)
            .ThenBy(v => v.Id)
            .ToList();
    }

    private static SshCaKeyRef KeyRefOf(SshCaKeyEntity key) => new(key.Id, key.Name, FingerprintOf(key.PublicKey), key.CertificateAuthorityId);

    /// <summary>The SHA-256 fingerprint of an authorized_keys line, as <c>sshd</c> logs it; null when the line cannot be read.</summary>
    private static string? FingerprintOf(string? authorizedKey)
    {
        try
        {
            return SshPublicKey.ParseAuthorizedKey(authorizedKey ?? string.Empty).Fingerprint;
        }
        catch (FormatException)
        {
            return null;
        }
    }

    // ---- What the routes read ----------------------------------------------------------------

    /// <inheritdoc />
    public async Task<IReadOnlyList<SshUserLoginNameView>> NamesOfUserAsync(Guid userId, IReadOnlyCollection<Guid> caKeyIds, CancellationToken cancellationToken = default)
    {
        var ids = caKeyIds.ToList();
        var keys = await _db.SshCaKeys.AsNoTracking().Where(k => ids.Contains(k.Id) && k.IsUserCa).OrderBy(k => k.Name).ToListAsync(cancellationToken);
        var now = DateTime.UtcNow;
        var views = new List<SshUserLoginNameView>();
        foreach (var key in keys)
        {
            var keyRef = KeyRefOf(key);
            foreach (var held in SshLoginNameHolding.Held(await GroundsAsync(userId, key, now, cancellationToken), key.MaxValidityHours, StartOf(now)))
            {
                views.AddRange(held.Grounds.Select(g => new SshUserLoginNameView(keyRef, held.Name, g.Source, g.GrantId, g.GroupId, g.GroupName,
                    SshLoginNameHolding.HoursOf(g, key.MaxValidityHours), g.MaxValidityHours == null || g.MaxValidityHours >= key.MaxValidityHours,
                    g.ExpiresAt, ReferenceEquals(g, held.Ground))));
            }
        }
        return views;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<SshLoginNameGrantView>> GrantsOfGroupAsync(Guid groupId, IReadOnlyCollection<Guid> caKeyIds, CancellationToken cancellationToken = default)
    {
        var ids = caKeyIds.ToList();
        var grants = await _db.SshLoginNameGrants.AsNoTracking().Where(g => g.GroupId == groupId && ids.Contains(g.SshCaKeyId)).ToListAsync(cancellationToken);
        return (await ViewsAsync(grants, cancellationToken))
            .OrderBy(v => v.SshCaKey.Name, StringComparer.OrdinalIgnoreCase).ThenBy(v => v.LoginName, StringComparer.Ordinal).ToList();
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<SshCertificateView>> CertificatesOfUserAsync(Guid userId, IReadOnlyCollection<Guid> caKeyIds, bool liveOnly,
        CancellationToken cancellationToken = default)
    {
        var ids = caKeyIds.ToList();
        var now = DateTime.UtcNow;
        var query = _db.SshCertificates.AsNoTracking().Where(c => c.SubjectUserId == userId && ids.Contains(c.SshCaKeyId));
        if (liveOnly)
            query = query.Where(c => !c.IsRevoked && c.ValidBefore > now);
        return await DescribeAsync(await query.OrderByDescending(c => c.CreatedAt).ToListAsync(cancellationToken), cancellationToken);
    }

    /// <inheritdoc />
    public async Task<SshSubjectRevocation> RevokeCertificatesOfUserAsync(Guid userId, IReadOnlyCollection<Guid> revocableCaKeyIds, SshCaActor? actor = null,
        CancellationToken cancellationToken = default)
    {
        var now = DateTime.UtcNow;
        var live = await _db.SshCertificates.Where(c => c.SubjectUserId == userId && !c.IsRevoked && c.ValidBefore > now).ToListAsync(cancellationToken);
        var mine = live.Where(c => revocableCaKeyIds.Contains(c.SshCaKeyId)).ToList();
        await RevokeAsync(mine.Select(c => (c, (string?)null)).ToList(), "an administrator revoked the user's certificates", actor, cancellationToken);
        return new SshSubjectRevocation(mine.Count, live.Count - mine.Count);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<SshCertificateView>> FindCertificatesAsync(long serial, string? caFingerprint, string? keyId,
        IReadOnlyCollection<Guid> caKeyIds, CancellationToken cancellationToken = default)
    {
        var ids = caKeyIds.ToList();
        if (!string.IsNullOrWhiteSpace(caFingerprint))
        {
            var wanted = caFingerprint.Trim();
            if (!wanted.StartsWith("SHA256:", StringComparison.Ordinal))
                wanted = "SHA256:" + wanted;
            wanted = wanted.TrimEnd('=');
            ids = (await _db.SshCaKeys.AsNoTracking().Where(k => ids.Contains(k.Id)).Select(k => new { k.Id, k.PublicKey }).ToListAsync(cancellationToken))
                .Where(k => string.Equals(FingerprintOf(k.PublicKey), wanted, StringComparison.Ordinal))
                .Select(k => k.Id)
                .ToList();
        }
        if (ids.Count == 0)
            return [];
        var query = _db.SshCertificates.AsNoTracking().Where(c => c.SerialNumber == serial && ids.Contains(c.SshCaKeyId));
        if (!string.IsNullOrEmpty(keyId))
            query = query.Where(c => c.KeyId == keyId);
        return await DescribeAsync(await query.OrderByDescending(c => c.CreatedAt).ToListAsync(cancellationToken), cancellationToken);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<SshCertificateView>> CertificatesAsync(IReadOnlyCollection<Guid> caKeyIds, int page, int pageSize, string? sort,
        CancellationToken cancellationToken = default)
    {
        var ids = caKeyIds.ToList();
        if (ids.Count == 0)
            return [];
        page = Math.Max(1, page);
        pageSize = Math.Clamp(pageSize, 1, ISshLoginNameService.MaxCertificatePageSize);
        var skip = (long)(page - 1) * pageSize;
        if (skip > int.MaxValue)
            return [];
        var rows = await SshCaService.Ordered(_db.SshCertificates.AsNoTracking().Where(c => ids.Contains(c.SshCaKeyId)), sort)
            .ThenBy(c => c.Id)
            .Skip((int)skip).Take(pageSize)
            .ToListAsync(cancellationToken);
        return await DescribeAsync(rows, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<SshCertificateView>> DescribeAsync(IReadOnlyList<SshCertificateEntity> certificates, CancellationToken cancellationToken = default)
    {
        if (certificates.Count == 0)
            return [];
        var now = DateTime.UtcNow;
        var keyIds = certificates.Select(c => c.SshCaKeyId).Distinct().ToList();
        var keys = (await _db.SshCaKeys.AsNoTracking().Where(k => keyIds.Contains(k.Id)).ToListAsync(cancellationToken)).ToDictionary(k => k.Id, KeyRefOf);
        var userIds = certificates.SelectMany(c => new[] { c.SubjectUserId, c.IssuedByUserId }).Where(id => id != null).Select(id => id!.Value).Distinct().ToList();
        var users = userIds.Count == 0
            ? []
            : await _db.Users.AsNoTracking().Where(u => userIds.Contains(u.Id)).ToDictionaryAsync(u => u.Id, u => u.Username, cancellationToken);

        return certificates.Select(c =>
        {
            var grounds = SshLoginNameHolding.Parse(c.LoginNameGrounds);
            return new SshCertificateView
            {
                Id = c.Id,
                SshCaKeyId = c.SshCaKeyId,
                CertificateType = c.CertificateType,
                KeyId = c.KeyId,
                SerialNumber = c.SerialNumber,
                Principals = c.Principals,
                ValidAfter = c.ValidAfter,
                ValidBefore = c.ValidBefore,
                PublicKey = c.PublicKey,
                SignedCertificate = c.SignedCertificate,
                Extensions = c.Extensions,
                IsRevoked = c.IsRevoked,
                RevokedAt = c.RevokedAt,
                IssuedByUserId = c.IssuedByUserId,
                SourceIp = c.SourceIp,
                CreatedAt = c.CreatedAt,
                Status = c.IsRevoked ? "revoked" : c.ValidBefore <= now ? "expired" : "active",
                SshCaKey = keys.GetValueOrDefault(c.SshCaKeyId),
                KeyFingerprint = FingerprintOf(c.PublicKey),
                SubjectUserId = c.SubjectUserId,
                Subject = SubjectOf(c, grounds, users),
                IssuedBy = new SshCertificateIssuerView(c.IssuedByUserId,
                    c.IssuedByUserId is Guid issuer ? users.GetValueOrDefault(issuer) : null,
                    c.SubjectUserId != null && c.SubjectUserId == c.IssuedByUserId, c.SourceIp),
                LoginNameGrounds = grounds,
            };
        }).ToList();
    }

    /// <summary>
    /// Who a certificate row is for. A row with grounds was written by the CA, so its key id says:
    /// <c>svc:</c> and a label for a service identity, otherwise the username, which still names
    /// the subject after the user row is gone.
    /// </summary>
    private static SshCertificateSubjectView SubjectOf(SshCertificateEntity certificate, IReadOnlyList<SshLoginNameGround>? grounds,
        IReadOnlyDictionary<Guid, string> users)
    {
        if (certificate.CertificateType == HostType)
            return new SshCertificateSubjectView("host", null, null, null);
        if (certificate.SubjectUserId is Guid userId)
            return new SshCertificateSubjectView("user", userId, users.GetValueOrDefault(userId) ?? certificate.KeyId, null);
        if (grounds == null)
            return new SshCertificateSubjectView("unknown", null, null, null);
        return grounds.All(g => g.Source == SshLoginNameSources.Typed) && SshKeyIds.ServiceLabelOf(certificate.KeyId) is { } label
            ? new SshCertificateSubjectView("service", null, null, label)
            : new SshCertificateSubjectView("user", null, certificate.KeyId, null);
    }

    /// <inheritdoc />
    public async Task<SshRequestOptions> RequestOptionsAsync(Guid userId, IReadOnlyCollection<Guid> requestableCaIds, CancellationToken cancellationToken = default)
    {
        var username = await _db.Users.AsNoTracking().Where(u => u.Id == userId).Select(u => u.Username).FirstOrDefaultAsync(cancellationToken);
        string? keyId = null;
        try
        {
            keyId = username == null ? null : SshKeyIds.ForUser(username);
        }
        catch (InvalidRequestException)
        {
        }

        var caIds = requestableCaIds.ToList();
        var keys = await _db.SshCaKeys.AsNoTracking()
            .Where(k => k.IsUserCa && k.IsEnabled && caIds.Contains(k.CertificateAuthorityId))
            .OrderBy(k => k.Name)
            .ToListAsync(cancellationToken);
        if (keys.Count == 0)
            return new SshRequestOptions(keyId, []);

        var keyIds = keys.Select(k => k.Id).ToList();
        var signingProfiles = await _db.SshSigningProfiles.AsNoTracking()
            .Where(p => p.AllowUserCerts && p.SshCaKeyId != null && keyIds.Contains(p.SshCaKeyId.Value))
            .OrderBy(p => p.Name).ToListAsync(cancellationToken);
        var certProfiles = await _db.SshCertProfiles.AsNoTracking()
            .Where(p => p.CertificateType == null || p.CertificateType == SshProfileCertificateType.User)
            .OrderBy(p => p.Name).ToListAsync(cancellationToken);
        var requestProfiles = await _db.SshRequestProfiles.AsNoTracking()
            .Where(p => !p.RequireApproval && (p.CertificateType == null || p.CertificateType == SshProfileCertificateType.User))
            .OrderBy(p => p.Name).ToListAsync(cancellationToken);

        var now = DateTime.UtcNow;
        var options = new List<SshRequestKeyOptions>();
        foreach (var key in keys)
        {
            var held = SshLoginNameHolding.Held(await GroundsAsync(userId, key, now, cancellationToken), key.MaxValidityHours, StartOf(now));
            var combinations = new List<SshRequestProfileCombination>();
            foreach (var request in requestProfiles.Where(r => r.CertificateAuthorityId == null || r.CertificateAuthorityId == key.CertificateAuthorityId))
            {
                var allowedSigning = Guids(request.AllowedSshSigningProfileIds);
                var allowedCert = Guids(request.AllowedSshCertProfileIds);
                foreach (var signing in signingProfiles.Where(s => s.SshCaKeyId == key.Id && (allowedSigning.Count == 0 || allowedSigning.Contains(s.Id))))
                {
                    foreach (var cert in certProfiles.Where(c => allowedCert.Count == 0 || allowedCert.Contains(c.Id)))
                    {
                        var patterns = Strings(cert.AllowedPrincipalPatterns);
                        combinations.Add(new SshRequestProfileCombination(request.Id, request.Name, signing.Id, signing.Name, cert.Id, cert.Name,
                            Math.Min(Math.Min(request.MaxValidityHours, signing.MaxValidityHours), Math.Min(cert.MaxValidityHours, key.MaxValidityHours)),
                            cert.MaxPrincipals,
                            patterns.Count == 0
                                ? []
                                : held.Where(h => !patterns.Any(p => ProfileRegex.IsMatch(h.Name, p))).Select(h => h.Name).ToList()));
                    }
                }
            }
            options.Add(new SshRequestKeyOptions(key.Id, key.Name, key.KeyType, FingerprintOf(key.PublicKey), key.MaxValidityHours, key.AllowOwnUsername,
                held.Select(h => new SshRequestLoginName(h.Name, h.Ground.Source, h.Ground.GrantId, h.Ground.GroupId, h.Ground.GroupName,
                    h.MaxValidityHours, h.ExpiresAt)).ToList(),
                combinations));
        }
        return new SshRequestOptions(keyId, options);
    }

    private static List<Guid> Guids(string? json)
    {
        try
        {
            return string.IsNullOrWhiteSpace(json) ? [] : JsonSerializer.Deserialize<List<Guid>>(json) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    private static List<string> Strings(string? json)
    {
        try
        {
            return string.IsNullOrWhiteSpace(json) ? [] : JsonSerializer.Deserialize<List<string>>(json)?.Where(s => s != null).ToList() ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    // ---- Reconciliation ----------------------------------------------------------------------

    /// <inheritdoc />
    public async Task<int> ReconcileUsersAsync(IEnumerable<Guid> userIds, string reason, SshCaActor? actor = null, CancellationToken cancellationToken = default)
    {
        var ids = userIds.Distinct().ToList();
        return ids.Count == 0
            ? 0
            : Sum(await ReconcileAsync(_db.SshCertificates.Where(c => c.SubjectUserId != null && ids.Contains(c.SubjectUserId.Value)), reason, null, actor, cancellationToken));
    }

    /// <inheritdoc />
    public async Task<int> ReconcileKeyAsync(Guid caKeyId, string reason, SshCaActor? actor = null, CancellationToken cancellationToken = default)
        => Sum(await ReconcileAsync(_db.SshCertificates.Where(c => c.SshCaKeyId == caKeyId), reason, null, actor, cancellationToken));

    /// <inheritdoc />
    public async Task<int> ReconcileGroupAsync(Guid groupId, string reason, SshCaActor? actor = null, CancellationToken cancellationToken = default)
        => await ReconcileUsersAsync(
            await _db.CaGroupMembers.AsNoTracking().Where(m => m.GroupId == groupId).Select(m => m.UserId).ToListAsync(cancellationToken),
            reason, actor, cancellationToken);

    /// <inheritdoc />
    public async Task<int> ReconcileAllAsync(string reason, SshCaActor? actor = null, CancellationToken cancellationToken = default)
        => Sum(await ReconcileAsync(_db.SshCertificates, reason, null, actor, cancellationToken));

    private static int Sum((int RequestRightLost, int LoginNameLost) revoked) => revoked.RequestRightLost + revoked.LoginNameLost;

    /// <summary>
    /// Revokes, among <paramref name="scope"/>, the live certificates issued for a user that
    /// their subject may no longer have. First every one on an SSH CA its subject may not
    /// request from now, rows from before login names included, since the right needs no
    /// grounds to judge. Then every one issued with grounds that carries a login name its
    /// subject does not hold now through the certificate's end; rows with no grounds are left
    /// alone there. Returns how many each rule revoked.
    /// </summary>
    /// <param name="reason">Why the pass runs: what changed.</param>
    /// <param name="rightReason">
    /// What the audit entry of a certificate revoked for the right says; null for
    /// <paramref name="reason"/> followed by <see cref="RequestRightLost"/>.
    /// </param>
    private async Task<(int RequestRightLost, int LoginNameLost)> ReconcileAsync(IQueryable<SshCertificateEntity> scope, string reason, string? rightReason,
        SshCaActor? actor, CancellationToken cancellationToken)
    {
        var now = DateTime.UtcNow;
        var live = await scope
            .Where(c => !c.IsRevoked && c.ValidBefore > now && c.CertificateType == UserType && c.SubjectUserId != null)
            .ToListAsync(cancellationToken);
        if (live.Count == 0)
            return (0, 0);

        var keyIds = live.Select(c => c.SshCaKeyId).Distinct().ToList();
        var keys = await _db.SshCaKeys.AsNoTracking().Where(k => keyIds.Contains(k.Id)).ToDictionaryAsync(k => k.Id, cancellationToken);
        var noRight = new List<(SshCertificateEntity Certificate, string? LoginName)>();
        var lost = new List<(SshCertificateEntity Certificate, string? LoginName)>();
        foreach (var byUser in live.GroupBy(c => c.SubjectUserId!.Value))
        {
            var requestable = await _rights.RequestableCaIdsAsync(byUser.Key, cancellationToken);
            foreach (var byKey in byUser.GroupBy(c => c.SshCaKeyId))
            {
                if (!keys.TryGetValue(byKey.Key, out var key))
                    continue;
                if (!requestable.Contains(key.CertificateAuthorityId))
                {
                    noRight.AddRange(byKey.Select(c => (c, (string?)null)));
                    continue;
                }
                var withGrounds = byKey.Where(c => c.LoginNameGrounds != null).ToList();
                if (withGrounds.Count == 0)
                    continue;
                var grounds = (await GroundsAsync(byUser.Key, key, now, cancellationToken)).ToLookup(g => g.Name, StringComparer.Ordinal);
                foreach (var certificate in withGrounds)
                {
                    List<string>? principals;
                    try
                    {
                        principals = JsonSerializer.Deserialize<List<string>>(certificate.Principals);
                    }
                    catch (JsonException)
                    {
                        _logger.LogWarning("The login names of SSH certificate {Id} cannot be read; it was not reconciled.", certificate.Id);
                        continue;
                    }
                    var gone = (principals ?? []).FirstOrDefault(p => !SshLoginNameHolding.HeldThrough(grounds[p], certificate.ValidBefore));
                    if (gone != null)
                        lost.Add((certificate, gone));
                }
            }
        }
        var rightLost = await RevokeAsync(noRight, rightReason ?? $"{reason}, and {RequestRightLost}", actor, cancellationToken);
        return (rightLost, await RevokeAsync(lost, reason, actor, cancellationToken));
    }

    /// <inheritdoc />
    public async Task<int> RevokeAllOfUserAsync(Guid userId, string reason, SshCaActor? actor = null, CancellationToken cancellationToken = default)
    {
        var now = DateTime.UtcNow;
        var live = await _db.SshCertificates.Where(c => c.SubjectUserId == userId && !c.IsRevoked && c.ValidBefore > now).ToListAsync(cancellationToken);
        return await RevokeAsync(live.Select(c => (c, (string?)null)).ToList(), reason, actor, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<int> UserDeletingAsync(Guid userId, SshCaActor? actor = null, CancellationToken cancellationToken = default)
    {
        var revoked = await RevokeAllOfUserAsync(userId, "the user was deleted", actor, cancellationToken);
        var grants = await _db.SshLoginNameGrants.Where(g => g.UserId == userId).ToListAsync(cancellationToken);
        await RemoveGrantsAsync(grants, "the user was deleted", actor, cancellationToken);
        return revoked;
    }

    /// <inheritdoc />
    public async Task<int> GroupDeletingAsync(Guid groupId, SshCaActor? actor = null, CancellationToken cancellationToken = default)
    {
        var grants = await _db.SshLoginNameGrants.Where(g => g.GroupId == groupId).ToListAsync(cancellationToken);
        if (grants.Count == 0)
            return 0;
        var members = await _db.CaGroupMembers.AsNoTracking().Where(m => m.GroupId == groupId).Select(m => m.UserId).ToListAsync(cancellationToken);
        await RemoveGrantsAsync(grants, "the group was deleted", actor, cancellationToken);
        return await ReconcileUsersAsync(members, "a group that gave the login name was deleted", actor, cancellationToken);
    }

    /// <inheritdoc />
    /// <remarks>
    /// The five rules run in the order below (not active, deleted, renamed, right lost, name
    /// lost), each over what the one before left live, so a certificate is revoked once and its
    /// audit entry gives the first reason that applies.
    /// </remarks>
    public async Task<SshLoginNameSweep> SweepAsync(SshCaActor? actor = null, CancellationToken cancellationToken = default)
    {
        var now = DateTime.UtcNow;

        var ofInactive = await _db.SshCertificates
            .Where(c => !c.IsRevoked && c.ValidBefore > now && _db.Users.Any(u => u.Id == c.SubjectUserId && !u.IsActive))
            .ToListAsync(cancellationToken);
        var userNotActive = await RevokeAsync(ofInactive.Select(c => (c, (string?)null)).ToList(),
            "the periodic sweep found that the user is not active", actor, cancellationToken);

        var orphaned = (await _db.SshCertificates.AsNoTracking()
                .Where(c => !c.IsRevoked && c.ValidBefore > now && c.CertificateType == UserType && c.SubjectUserId == null && c.LoginNameGrounds != null)
                .Select(c => new { c.Id, c.LoginNameGrounds })
                .ToListAsync(cancellationToken))
            .Where(c => (SshLoginNameHolding.Parse(c.LoginNameGrounds) ?? []).Any(g => g != null && g.Source != SshLoginNameSources.Typed))
            .Select(c => c.Id)
            .ToList();
        var ofDeleted = orphaned.Count == 0
            ? []
            : await _db.SshCertificates.Where(c => orphaned.Contains(c.Id) && !c.IsRevoked).ToListAsync(cancellationToken);
        var userDeleted = await RevokeAsync(ofDeleted.Select(c => (c, (string?)null)).ToList(),
            "the periodic sweep found that the user was deleted", actor, cancellationToken);

        // The CA wrote the key id of a row with grounds from its subject's username, so one that differs now is a rename.
        var renamed = (await _db.SshCertificates.AsNoTracking()
                .Where(c => !c.IsRevoked && c.ValidBefore > now && c.CertificateType == UserType && c.SubjectUserId != null && c.LoginNameGrounds != null)
                .Join(_db.Users.AsNoTracking(), c => c.SubjectUserId, u => (Guid?)u.Id, (c, u) => new { c.Id, c.KeyId, u.Username })
                .ToListAsync(cancellationToken))
            .Where(c => !string.Equals(c.KeyId, c.Username, StringComparison.Ordinal))
            .Select(c => c.Id)
            .ToList();
        var ofRenamed = renamed.Count == 0
            ? []
            : await _db.SshCertificates.Where(c => renamed.Contains(c.Id) && !c.IsRevoked).ToListAsync(cancellationToken);
        var userRenamed = await RevokeAsync(ofRenamed.Select(c => (c, (string?)null)).ToList(),
            "the periodic sweep found that the user was renamed", actor, cancellationToken);

        var (requestRightLost, loginNameLost) = await ReconcileAsync(_db.SshCertificates,
            "the periodic sweep found a login name that the subject no longer holds",
            "the periodic sweep found that " + RequestRightLost, actor, cancellationToken);

        return new SshLoginNameSweep(userNotActive, userDeleted, loginNameLost, userRenamed, requestRightLost);
    }

    /// <summary>
    /// Marks certificates revoked at one recorded time (<see cref="SshCertificateEntity.Revoke"/>),
    /// saves, and writes the audit entry of each with why: the reason, and the login name its
    /// subject no longer holds when that is why.
    /// </summary>
    private async Task<int> RevokeAsync(IReadOnlyList<(SshCertificateEntity Certificate, string? LoginName)> certificates, string reason, SshCaActor? actor,
        CancellationToken cancellationToken)
    {
        if (certificates.Count == 0)
            return 0;
        var now = DateTime.UtcNow;
        foreach (var (certificate, _) in certificates)
            certificate.Revoke(now);
        await _db.SaveChangesAsync(cancellationToken);

        var keyIds = certificates.Select(c => c.Certificate.SshCaKeyId).Distinct().ToList();
        var cas = await _db.SshCaKeys.AsNoTracking().Where(k => keyIds.Contains(k.Id)).ToDictionaryAsync(k => k.Id, k => k.CertificateAuthorityId, cancellationToken);
        foreach (var (certificate, loginName) in certificates)
        {
            await _audit.LogAsync(AuditActionType.SshCertRevoked, actor?.UserId, actor?.Username ?? "system",
                "SshCertificate", certificate.Id.ToString(),
                new
                {
                    Reason = reason, LoginName = loginName, certificate.KeyId, certificate.SerialNumber, certificate.SubjectUserId, certificate.SshCaKeyId,
                },
                actor?.SourceIp, certificateAuthorityId: cas.TryGetValue(certificate.SshCaKeyId, out var ca) ? ca : null);
        }
        _logger.LogWarning("{Count} SSH certificate(s) revoked: {Reason}.", certificates.Count, reason);
        return certificates.Count;
    }
}
