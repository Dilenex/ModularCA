using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Errors;

namespace ModularCA.Core.Services;

/// <summary>
/// The rules every path that names a CA applies: a label matches
/// <c>^[a-z0-9][a-z0-9-]{0,62}$</c>, carries no reserved prefix unless the caller is bootstrap,
/// and a label (compared case-insensitively) or name is unique across the instance, soft-deleted
/// CAs included, because a label is the path of the CRL, OCSP, AIA and enrolment URLs of every
/// certificate its CA issued.
/// </summary>
public static class CaLabelRules
{
    private static readonly System.Text.RegularExpressions.Regex Pattern =
        new(@"^[a-z0-9][a-z0-9-]{0,62}$", System.Text.RegularExpressions.RegexOptions.Compiled);

    /// <summary>
    /// Prefixes kept for the CAs and groups bootstrap creates: <c>space-</c> names a space's
    /// groups from 0.4.0, and <c>org-</c> named them before.
    /// </summary>
    public static readonly string[] ReservedPrefixes = ["system-", "space-", "org-"];

    /// <summary>
    /// Throws <see cref="ArgumentException"/> when <paramref name="label"/> does not match the
    /// label pattern, or, unless <paramref name="allowReserved"/>, starts with a reserved prefix.
    /// </summary>
    public static void Validate(string? label, bool allowReserved = false, string paramName = "label")
    {
        if (string.IsNullOrEmpty(label) || !Pattern.IsMatch(label))
            throw new ArgumentException(
                $"Invalid CA label '{label}'. Labels must match ^[a-z0-9][a-z0-9-]{{0,62}}$.", paramName);
        if (!allowReserved && ReservedPrefixes.Any(p => label.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
            throw new ArgumentException(
                $"CA label '{label}' uses a reserved prefix (system- / space- / org-). Choose a different label.", paramName);
    }

    /// <summary>
    /// Throws <see cref="ResourceConflictException"/> when another CA than
    /// <paramref name="exceptCaId"/>, soft-deleted ones included, already has
    /// <paramref name="label"/> (ignoring case) or <paramref name="name"/>. Either may be null to skip it.
    /// </summary>
    public static async Task EnsureUniqueAsync(ModularCADbContext db, string? label, string? name, Guid? exceptCaId = null)
    {
        if (label != null)
        {
            var lowered = label.ToLowerInvariant();
            if (await db.CertificateAuthorities.IgnoreQueryFilters()
                    .AnyAsync(c => c.Id != exceptCaId && c.Label != null && c.Label.ToLower() == lowered))
                throw new ResourceConflictException(
                    $"A CA with label '{label}' already exists in this instance, or did and was deleted. Labels are never reused.",
                    ErrorCodes.NameAlreadyTaken);
        }
        if (name != null
            && await db.CertificateAuthorities.IgnoreQueryFilters().AnyAsync(c => c.Id != exceptCaId && c.Name == name))
            throw new ResourceConflictException(
                $"A CA named '{name}' already exists in this instance, or did and was deleted.", ErrorCodes.NameAlreadyTaken);
    }

    /// <summary>
    /// Whether <paramref name="ex"/> is a unique violation on <c>CertificateAuthorities</c>: a
    /// label or name another request took between <see cref="EnsureUniqueAsync"/> and the save.
    /// </summary>
    public static bool IsNameRace(DbUpdateException ex)
    {
        for (var inner = ex.InnerException; inner != null; inner = inner.InnerException)
            if (inner is Npgsql.PostgresException pg && pg.SqlState == PostgresErrorUtil.UniqueViolation
                && pg.TableName == "CertificateAuthorities")
                return true;
        return false;
    }

    /// <summary>The conflict a lost <see cref="IsNameRace"/> is reported as (409).</summary>
    public static ResourceConflictException NameRaceConflict(string? label, string? name) => new(
        $"Another CA took the label '{label}' or the name '{name}' while this one was being saved. Labels and names are unique across the instance.",
        ErrorCodes.NameAlreadyTaken);
}
