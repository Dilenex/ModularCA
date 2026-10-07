using System.Globalization;

namespace ModularCA.Migrate;

/// <summary>
/// Turns a value MariaDB handed back into the type the PostgreSQL column expects.
/// <para>
/// These are the conversions the design listed as "types that look equivalent and are not".
/// Identifiers were <c>char(36)</c> and are now native <c>uuid</c>; booleans were
/// <c>tinyint(1)</c> and arrive as a number; binary columns carry protected key material and
/// certificates and must cross byte for byte. Timestamps are the one that bites quietly: MySQL's
/// <c>datetime(6)</c> has no zone and MySqlConnector returns
/// <see cref="DateTimeKind.Unspecified"/>, while Npgsql refuses to write anything but
/// <see cref="DateTimeKind.Utc"/> into <c>timestamptz</c>. Every stored value was already UTC, so
/// the fix is to say so rather than to convert — converting would shift each one by the offset of
/// whatever machine the helper happens to run on.
/// </para>
/// </summary>
public static class ValueCoercion
{
    /// <summary>
    /// Converts a source value to the destination column's CLR type.
    /// </summary>
    /// <param name="value">The value as MySqlConnector returned it.</param>
    /// <param name="target">The destination CLR type, already unwrapped from Nullable.</param>
    /// <returns>A value Npgsql can bind, or null.</returns>
    /// <exception cref="InvalidOperationException">The value cannot be represented in the target type.</exception>
    public static object? Coerce(object? value, Type target)
    {
        if (value is null or DBNull)
            return null;

        if (target.IsInstanceOfType(value) && target != typeof(DateTime))
            return value;

        try
        {
            if (target == typeof(Guid))
                return value switch
                {
                    Guid g => g,
                    string s => Guid.Parse(s),
                    byte[] b when b.Length == 16 => new Guid(b),
                    _ => throw new InvalidOperationException($"cannot read a Guid from {value.GetType().Name}"),
                };

            if (target == typeof(bool))
                return value switch
                {
                    bool b => b,
                    sbyte sb => sb != 0,
                    byte by => by != 0,
                    short sh => sh != 0,
                    int i => i != 0,
                    long l => l != 0,
                    ulong ul => ul != 0,
                    string s => s is "1" or "true" or "True",
                    _ => throw new InvalidOperationException($"cannot read a bool from {value.GetType().Name}"),
                };

            if (target == typeof(DateTime))
            {
                // Already UTC by construction on the source; stamped rather than converted.
                var dt = value as DateTime? ?? DateTime.Parse((string)value, CultureInfo.InvariantCulture);
                return DateTime.SpecifyKind(dt, DateTimeKind.Utc);
            }

            if (target == typeof(DateTimeOffset))
            {
                var dt = value as DateTime? ?? DateTime.Parse((string)value, CultureInfo.InvariantCulture);
                return new DateTimeOffset(DateTime.SpecifyKind(dt, DateTimeKind.Utc));
            }

            if (target == typeof(byte[]))
                return value as byte[]
                    ?? throw new InvalidOperationException($"cannot read bytes from {value.GetType().Name}");

            if (target == typeof(string))
                return value as string ?? Convert.ToString(value, CultureInfo.InvariantCulture);

            if (target == typeof(TimeSpan))
                return value as TimeSpan? ?? TimeSpan.Parse((string)value, CultureInfo.InvariantCulture);

            // Reached only if a caller asks for an enum directly; the copier asks for the
            // provider type, which is already the underlying integer. Returning the number rather
            // than the enum matters because Npgsql binds the former and refuses the latter.
            if (target.IsEnum)
                return Convert.ChangeType(value, Enum.GetUnderlyingType(target), CultureInfo.InvariantCulture);

            return Convert.ChangeType(value, target, CultureInfo.InvariantCulture);
        }
        catch (Exception ex) when (ex is not InvalidOperationException)
        {
            throw new InvalidOperationException(
                $"cannot convert {value.GetType().Name} '{value}' to {target.Name}: {ex.Message}", ex);
        }
    }
}
