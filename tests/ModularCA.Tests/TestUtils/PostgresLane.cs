namespace ModularCA.Tests.TestUtils;

/// <summary>
/// The xUnit collections the PostgreSQL test classes are spread over. The classes of one lane run
/// one after another and the lanes run beside each other, so the number of lanes is the number
/// of tests working the test server at once. The lanes start when every other parallel
/// collection has finished: see <see cref="PhasedTestFramework"/>.
/// </summary>
/// <remarks>
/// Why not a collection per class: every test creates and drops databases, each drop makes the
/// server checkpoint and close its files, and with about twenty classes doing that at once the
/// checkpoints ran to half a minute, long enough for a connection to miss the product's 15 s
/// connect timeout. Why not one collection: the tests of a collection never overlap, and the
/// PostgreSQL tests would again set the length of the run. A new PostgreSQL test class goes in
/// the lane with the least in it; a collection is a lane when its name starts with
/// <see cref="Prefix"/>.
/// </remarks>
internal static class PostgresLane
{
    /// <summary>What every lane's collection name starts with.</summary>
    public const string Prefix = "PostgreSQL lane ";

    /// <summary>Whether <paramref name="collection"/> is one of the lanes.</summary>
    public static bool Is(Xunit.Abstractions.ITestCollection collection)
        => collection.DisplayName.StartsWith(Prefix, StringComparison.Ordinal);

    /// <summary>The first lane.</summary>
    public const string One = "PostgreSQL lane 1";

    /// <summary>The second lane.</summary>
    public const string Two = "PostgreSQL lane 2";

    /// <summary>The third lane.</summary>
    public const string Three = "PostgreSQL lane 3";

    /// <summary>The fourth lane.</summary>
    public const string Four = "PostgreSQL lane 4";

    /// <summary>The fifth lane.</summary>
    public const string Five = "PostgreSQL lane 5";

    /// <summary>The sixth lane.</summary>
    public const string Six = "PostgreSQL lane 6";
}
