using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace ModularCA.Database;

/// <summary>
/// Helpers for inspecting PostgreSQL-specific exception details surfaced through EF Core's
/// generic <see cref="DbUpdateException"/>. EF Core wraps the provider exception in
/// <c>InnerException</c>; this util walks the chain and returns provider-specific
/// information in a way callers don't have to repeat.
/// <para>
/// Replaces <c>MySqlErrorUtil</c>, which tested for MySQL error 1062. PostgreSQL reports the
/// same condition as SQLSTATE <c>23505</c> (<c>unique_violation</c>), which Npgsql exposes as
/// a string rather than a number — the SQLSTATE class is standardised, so this is if anything
/// a more durable thing to match on than a vendor error number was.
/// </para>
/// </summary>
public static class PostgresErrorUtil
{
    /// <summary>
    /// SQLSTATE for a unique-index or primary-key violation. Defined by the SQL standard as
    /// <c>unique_violation</c> and stable across every PostgreSQL version.
    /// </summary>
    public const string UniqueViolation = "23505";

    /// <summary>
    /// Returns true when the inner-exception chain of <paramref name="ex"/> contains a
    /// PostgreSQL <c>unique_violation</c> (SQLSTATE 23505) — the canonical "row already
    /// exists" / unique-index violation signal. Use as a <c>when</c> filter on a
    /// <c>catch (DbUpdateException ex)</c> handler so non-uniqueness failures
    /// (transient connection drops, FK violations, schema mismatches) bubble up
    /// instead of being silently treated as "already exists".
    /// </summary>
    /// <param name="ex">The exception EF Core raised from SaveChanges.</param>
    /// <returns>True when a unique-index violation caused the failure.</returns>
    public static bool IsUniqueViolation(DbUpdateException ex)
    {
        for (var inner = ex.InnerException; inner != null; inner = inner.InnerException)
        {
            if (inner is PostgresException pgEx && pgEx.SqlState == UniqueViolation)
                return true;
        }
        return false;
    }
}
