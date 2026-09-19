using ModularCA.Migrate;
using Xunit;

namespace ModularCA.Tests.Migrate;

/// <summary>
/// That every column the copier writes is a type the driver can bind.
/// <para>
/// Entity Framework hides a layer that raw ADO does not: a property is not always stored as the
/// type it is declared as. An enum is an <c>integer</c> column, and a property with a value
/// converter is whatever the converter produces. Copying through raw ADO bypasses all of it, so a
/// value bound as the model type reaches Npgsql as something it has no mapping for — which is what
/// <c>AccessBadgeSources.Kind</c> did against a live database, after the schema had been created
/// and the copy was under way.
/// </para>
/// <para>
/// The closed set below is the point. A new property whose provider type is something the driver
/// does not know fails here, at the cost of a test run, rather than partway through a migration
/// somebody is watching.
/// </para>
/// </summary>
public class BindableColumnTypeTests
{
    /// <summary>
    /// The types Npgsql binds from a plain parameter with no explicit NpgsqlDbType. Deliberately
    /// narrow: anything outside it needs either a value converter in the model or a case in
    /// <see cref="ValueCoercion"/>, and both are decisions worth making on purpose.
    /// </summary>
    private static readonly HashSet<Type> Bindable =
    [
        typeof(bool), typeof(byte), typeof(short), typeof(int), typeof(long),
        typeof(float), typeof(double), typeof(decimal),
        typeof(string), typeof(byte[]), typeof(Guid),
        typeof(DateTime), typeof(DateTimeOffset), typeof(TimeSpan),
    ];

    public static TheoryData<string> Models() => new() { "application", "audit" };

    private static IReadOnlyList<ModelIntrospection.TableInfo> Tables(string which) =>
        which == "audit"
            ? ModelIntrospection.Tables(ModelIntrospection.AuditModel())
            : ModelIntrospection.Tables(ModelIntrospection.DestinationModel());

    [Theory]
    [MemberData(nameof(Models))]
    public void Every_copied_column_is_a_type_the_driver_can_bind(string which)
    {
        var offenders = Tables(which)
            .SelectMany(t => t.Columns.Select(c => (Table: t.Name, Column: c)))
            .Where(x => !Bindable.Contains(x.Column.ClrType))
            .Select(x => $"{x.Table}.{x.Column.Name} is {x.Column.ClrType.Name}")
            .ToList();

        Assert.True(offenders.Count == 0,
            "These columns would be bound as a type Npgsql has no mapping for, and would fail "
            + "partway through the copy:\n  " + string.Join("\n  ", offenders));
    }

    [Theory]
    [MemberData(nameof(Models))]
    public void No_copied_column_is_still_an_enum(string which)
    {
        // The specific regression. An enum reaches the driver as an enum unless the provider type
        // is taken instead of the model type, and the driver refuses it.
        Assert.DoesNotContain(Tables(which).SelectMany(t => t.Columns), c => c.ClrType.IsEnum);
    }

    [Fact]
    public void The_badge_source_kind_is_carried_as_its_underlying_number()
    {
        // Named outright because it is the one that failed, and because the column is an integer
        // on both engines — the enum only ever existed in the model.
        var table = Assert.Single(
            ModelIntrospection.Tables(ModelIntrospection.DestinationModel()),
            t => t.Name == "AccessBadgeSources");

        var kind = Assert.Single(table.Columns, c => c.Name == "Kind");

        Assert.Equal(typeof(int), kind.ClrType);
    }

    [Fact]
    public void An_enum_asked_for_directly_still_becomes_a_number()
    {
        // The copier asks for the provider type, so it never requests an enum. A caller that does
        // must still get something bindable back rather than an enum instance.
        var coerced = ValueCoercion.Coerce(2, typeof(DayOfWeek));

        Assert.NotNull(coerced);
        Assert.False(coerced!.GetType().IsEnum);
        Assert.Equal(2, Convert.ToInt32(coerced));
    }

    [Fact]
    public void Nullability_survives_the_provider_type_lookup()
    {
        // Taking the provider type unwraps Nullable<>, and the flag is the only thing left saying
        // a column accepts null. Losing it would not fail the copy, but it would make the column
        // list a worse description of the schema than the model it came from.
        var tables = ModelIntrospection.Tables(ModelIntrospection.DestinationModel());

        Assert.Contains(tables.SelectMany(t => t.Columns), c => c.IsNullable);
        Assert.Contains(tables.SelectMany(t => t.Columns), c => !c.IsNullable);
        Assert.DoesNotContain(tables.SelectMany(t => t.Columns),
            c => Nullable.GetUnderlyingType(c.ClrType) is not null);
    }
}
