using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace ModularCA.Database;

/// <summary>
/// Normalises every <see cref="DateTime"/> that crosses the provider boundary to UTC.
/// <para>
/// This exists because of the one difference between MySQL and PostgreSQL that fails silently
/// rather than loudly. MySQL's <c>datetime(6)</c> stored whatever wall-clock value it was given
/// and handed it back with <see cref="DateTimeKind.Unspecified"/>; nothing ever checked. Npgsql
/// maps <see cref="DateTime"/> to <c>timestamp with time zone</c> and throws on a value whose
/// kind is not UTC — which is the good case — but the tempting "fix" of switching the column to
/// <c>timestamp without time zone</c> would restore exactly the old ambiguity, and a certificate
/// authority that is an hour wrong about <c>NotBefore</c> issues certificates that are not yet
/// valid.
/// </para>
/// <para>
/// So the columns are <c>timestamptz</c> — true instants — and this converter guarantees the
/// values reaching them are instants:
/// </para>
/// <list type="bullet">
///   <item><description>
///     <see cref="DateTimeKind.Utc"/> passes through untouched. This is almost everything: the
///     codebase uses <c>DateTime.UtcNow</c> and <c>TimeProvider.GetUtcNow()</c> throughout.
///   </description></item>
///   <item><description>
///     <see cref="DateTimeKind.Local"/> is converted with <c>ToUniversalTime()</c>. The value
///     denotes a real instant, so converting it preserves meaning. This is the case that
///     matters in practice: <c>X509Certificate2.NotBefore</c> and <c>NotAfter</c> are returned
///     by .NET in local time, and under MySQL those were being written as local wall-clock
///     values into a column everything else treated as UTC.
///   </description></item>
///   <item><description>
///     <see cref="DateTimeKind.Unspecified"/> is labelled UTC without shifting it. That is
///     precisely the meaning MySQL gave it, so no stored or in-flight value changes; the
///     alternative — refusing it — would turn parsed configuration values and test fixtures
///     into runtime exceptions for no correctness gain.
///   </description></item>
/// </list>
/// <para>
/// On read every value comes back as <see cref="DateTimeKind.Utc"/>, which is an improvement on
/// the old behaviour: comparisons against <c>DateTime.UtcNow</c> elsewhere in the codebase used
/// to be comparing a UTC value against an Unspecified one and getting away with it.
/// </para>
/// </summary>
public class UtcDateTimeConverter : ValueConverter<DateTime, DateTime>
{
    /// <summary>Creates the converter.</summary>
    public UtcDateTimeConverter()
        : base(
            v => Normalize(v),
            v => DateTime.SpecifyKind(v, DateTimeKind.Utc))
    {
    }

    /// <summary>
    /// Converts a value to UTC for storage: local times are shifted, unspecified times are
    /// labelled, UTC times are left alone.
    /// </summary>
    /// <param name="value">The value being written.</param>
    /// <returns>The same instant, with <see cref="DateTimeKind.Utc"/>.</returns>
    public static DateTime Normalize(DateTime value) => value.Kind switch
    {
        DateTimeKind.Utc => value,
        DateTimeKind.Local => value.ToUniversalTime(),
        _ => DateTime.SpecifyKind(value, DateTimeKind.Utc),
    };
}

/// <summary>
/// Nullable counterpart of <see cref="UtcDateTimeConverter"/>. EF Core matches converters by
/// exact CLR type, so <c>DateTime?</c> properties need their own registration — omitting this
/// is how half the timestamps in a schema end up with different semantics from the other half.
/// </summary>
public class NullableUtcDateTimeConverter : ValueConverter<DateTime?, DateTime?>
{
    /// <summary>Creates the converter.</summary>
    public NullableUtcDateTimeConverter()
        : base(
            v => v.HasValue ? UtcDateTimeConverter.Normalize(v.Value) : v,
            v => v.HasValue ? DateTime.SpecifyKind(v.Value, DateTimeKind.Utc) : v)
    {
    }
}
