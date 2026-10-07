using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using ModularCA.Shared.Errors;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Utils;

namespace ModularCA.Core.Services;

/// <summary>A login name grant, as the holding rule reads it.</summary>
/// <param name="Id">The grant.</param>
/// <param name="LoginName">The login name.</param>
/// <param name="UserId">The user it was made to, or null.</param>
/// <param name="GroupId">The group it was made to, or null.</param>
/// <param name="GroupName">That group's name.</param>
/// <param name="MaxValidityHours">Its limit in hours; null for the key's maximum.</param>
/// <param name="ExpiresAt">When it ends, UTC; null when it does not end.</param>
/// <param name="GrantedByUserId">Who granted it.</param>
/// <param name="GrantedByUsername">The username of whoever granted it.</param>
public sealed record SshLoginNameGrantRow(Guid Id, string LoginName, Guid? UserId, Guid? GroupId, string? GroupName, int? MaxValidityHours,
    DateTime? ExpiresAt, Guid? GrantedByUserId, string? GrantedByUsername);

/// <summary>
/// The rule for holding an SSH login name, and what it allows a certificate, as functions of
/// what the database says. A user holds their own username on a key that allows it, when the
/// username is a login name; and each name granted on the key to them or to a group they are a
/// member of, while the grant has not ended. Of several grounds for one name the most generous
/// counts: the one that allows the latest certificate end.
/// </summary>
public static class SshLoginNameHolding
{
    private static readonly JsonSerializerOptions StoredJson = new() { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };

    /// <summary>
    /// Every ground on which a user holds a login name on one key at <paramref name="now"/>.
    /// </summary>
    /// <param name="userId">The user.</param>
    /// <param name="username">The user's username.</param>
    /// <param name="allowOwnUsername">Whether the key lets everyone log in as their own username.</param>
    /// <param name="groupIds">The groups the user is a member of now.</param>
    /// <param name="grantsOnKey">The grants on the key.</param>
    /// <param name="now">The moment judged, UTC.</param>
    public static IReadOnlyList<SshLoginNameGround> Grounds(Guid userId, string? username, bool allowOwnUsername, IReadOnlySet<Guid> groupIds,
        IEnumerable<SshLoginNameGrantRow> grantsOnKey, DateTime now)
    {
        var grounds = new List<SshLoginNameGround>();
        if (allowOwnUsername && SshLoginNameRules.IsValid(username))
            grounds.Add(new SshLoginNameGround { Name = username!, Source = SshLoginNameSources.Own });

        foreach (var grant in grantsOnKey)
        {
            if (grant.ExpiresAt is { } end && end <= now)
                continue;
            var toUser = grant.UserId == userId;
            var toGroup = grant.GroupId is Guid groupId && groupIds.Contains(groupId);
            if (!toUser && !toGroup)
                continue;
            grounds.Add(new SshLoginNameGround
            {
                Name = grant.LoginName,
                Source = toUser ? SshLoginNameSources.User : SshLoginNameSources.Group,
                GrantId = grant.Id,
                GroupId = toUser ? null : grant.GroupId,
                GroupName = toUser ? null : grant.GroupName,
                GrantedByUserId = grant.GrantedByUserId,
                GrantedByUsername = grant.GrantedByUsername,
                MaxValidityHours = grant.MaxValidityHours,
                ExpiresAt = grant.ExpiresAt,
            });
        }
        return grounds;
    }

    /// <summary>The longest certificate a ground allows, in hours: its own limit, never over the key's maximum.</summary>
    public static int HoursOf(SshLoginNameGround ground, int keyMaxValidityHours)
        => Math.Min(ground.MaxValidityHours ?? keyMaxValidityHours, keyMaxValidityHours);

    /// <summary>The latest moment a certificate that starts at <paramref name="validAfter"/> may end under a ground.</summary>
    public static DateTime LatestEnd(SshLoginNameGround ground, int keyMaxValidityHours, DateTime validAfter)
    {
        var byHours = validAfter.AddHours(HoursOf(ground, keyMaxValidityHours));
        return ground.ExpiresAt is { } end && end < byHours ? end : byHours;
    }

    /// <summary>
    /// The names held, by name, each with the most generous of its grounds for a certificate that
    /// starts at <paramref name="validAfter"/>. Between grounds that allow the same end, the
    /// user's own username counts before a grant to the user, and that before a grant to a group.
    /// </summary>
    public static IReadOnlyList<SshHeldLoginName> Held(IEnumerable<SshLoginNameGround> grounds, int keyMaxValidityHours, DateTime validAfter)
        => grounds.GroupBy(g => g.Name, StringComparer.Ordinal)
            .OrderBy(g => g.Key, StringComparer.Ordinal)
            .Select(byName =>
            {
                var all = byName
                    .OrderByDescending(g => LatestEnd(g, keyMaxValidityHours, validAfter))
                    .ThenBy(g => SourceRank(g.Source))
                    .ThenBy(g => g.GrantId)
                    .ToList();
                var best = all[0];
                return new SshHeldLoginName(byName.Key, best, HoursOf(best, keyMaxValidityHours), best.ExpiresAt, all);
            })
            .ToList();

    /// <summary>
    /// What issuance may certify: every one of <paramref name="principals"/> must be among
    /// <paramref name="held"/>. The result carries the ground of each, the smallest limit and the
    /// earliest end.
    /// </summary>
    /// <exception cref="InvalidRequestException">A principal is not held; the message names it.</exception>
    public static SshLoginNameIssuance Issuance(IReadOnlyList<SshHeldLoginName> held, IReadOnlyList<string> principals)
    {
        var byName = held.ToDictionary(h => h.Name, StringComparer.Ordinal);
        var grounds = new List<SshLoginNameGround>();
        int? hours = null;
        string? hoursBy = null;
        DateTime? notAfter = null;
        string? notAfterBy = null;
        foreach (var principal in principals)
        {
            if (principal == null || !byName.TryGetValue(principal, out var name))
                throw new InvalidRequestException(NotHeldMessage(principal));
            grounds.Add(name.Ground);
            if (hours == null || name.MaxValidityHours < hours)
                (hours, hoursBy) = (name.MaxValidityHours, name.Name);
            if (name.ExpiresAt is { } end && (notAfter == null || end < notAfter))
                (notAfter, notAfterBy) = (end, name.Name);
        }
        return new SshLoginNameIssuance(grounds, hours ?? int.MaxValue, hoursBy, notAfter, notAfterBy);
    }

    /// <summary>
    /// When a certificate that starts at <paramref name="validAfter"/> ends. With no validity
    /// asked it is the most allowed: <paramref name="limitHours"/>, the login names' smallest
    /// limit, and no later than the earliest end among their grounds. A validity asked is cut to
    /// <paramref name="limitHours"/> as before login names, and refused when it is over what a
    /// login name allows.
    /// </summary>
    /// <param name="validAfter">The start, UTC.</param>
    /// <param name="requestedHours">The validity asked, in hours; null for the most allowed.</param>
    /// <param name="limitHours">The smallest of the key's and the profiles' limits, in hours.</param>
    /// <param name="names">What the login names allow; null for a certificate that is not for a user.</param>
    /// <exception cref="InvalidRequestException">The validity asked is over a login name's limit or past its end; the message names the name and the limit.</exception>
    public static DateTime ValidBefore(DateTime validAfter, int? requestedHours, int limitHours, SshLoginNameIssuance? names)
    {
        var hours = Math.Min(requestedHours ?? limitHours, limitHours);
        if (names == null)
            return validAfter.AddHours(hours);

        if (requestedHours == null)
        {
            var most = validAfter.AddHours(Math.Min(hours, names.MaxValidityHours));
            return names.NotAfter is { } end && end < most ? WholeSeconds(end) : most;
        }

        if (hours > names.MaxValidityHours)
            throw new InvalidRequestException(
                $"Login name '{names.HoursLimitedBy}' allows a certificate of at most {names.MaxValidityHours} hours; {hours} were asked.");
        var asked = validAfter.AddHours(hours);
        if (names.NotAfter is { } notAfter && notAfter < asked)
        {
            var whole = (int)Math.Floor((notAfter - validAfter).TotalHours);
            throw new InvalidRequestException(
                $"Login name '{names.NotAfterLimitedBy}' is granted until {notAfter.ToString("u", CultureInfo.InvariantCulture)}, so a certificate carrying it "
                + $"can be valid for at most {Math.Max(whole, 0)} hours; {hours} were asked. Leave the validity out for a certificate that ends when the grant does.");
        }
        return asked;
    }

    /// <summary>
    /// Whether a login name is held through <paramref name="validBefore"/>: one of its current
    /// grounds has no end, or an end at or after that moment.
    /// </summary>
    public static bool HeldThrough(IEnumerable<SshLoginNameGround> groundsOfName, DateTime validBefore)
        => groundsOfName.Any(g => g.ExpiresAt == null || g.ExpiresAt >= validBefore);

    /// <summary>The sentence for a principal the subject does not hold.</summary>
    public static string NotHeldMessage(string? principal)
        => SshLoginNameRules.IsValid(principal)
            ? $"Login name '{principal}' is not held: it is not the user's own username on this SSH CA and no grant gives it. An administrator grants login names on the SSH CA."
            : "A login name asked for is not held, and is not a login name at all.";

    /// <summary>The grounds of a certificate as its row stores them.</summary>
    public static string Serialize(IReadOnlyList<SshLoginNameGround> grounds) => JsonSerializer.Serialize(grounds, StoredJson);

    /// <summary>The grounds a certificate row stores; null when it stores none, or something that cannot be read.</summary>
    public static IReadOnlyList<SshLoginNameGround>? Parse(string? stored)
    {
        if (string.IsNullOrWhiteSpace(stored))
            return null;
        try
        {
            return JsonSerializer.Deserialize<List<SshLoginNameGround>>(stored);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>The grounds of typed login names, for a service identity.</summary>
    public static IReadOnlyList<SshLoginNameGround> Typed(IEnumerable<string> principals)
        => principals.Select(p => new SshLoginNameGround { Name = p, Source = SshLoginNameSources.Typed }).ToList();

    private static int SourceRank(string source) => source switch
    {
        SshLoginNameSources.Own => 0,
        SshLoginNameSources.User => 1,
        _ => 2,
    };

    private static DateTime WholeSeconds(DateTime time) => new(time.Ticks - time.Ticks % TimeSpan.TicksPerSecond, DateTimeKind.Utc);
}
