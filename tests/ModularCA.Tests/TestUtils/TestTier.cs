namespace ModularCA.Tests.TestUtils;

/// <summary>
/// The <c>Tier</c> trait. A test class or test tagged <c>[Trait(TestTier.Name, TestTier.Slow)]</c>
/// is slow and bound to its environment: it needs the PostgreSQL test server, starts a real node,
/// or runs shell scripts with the system's tools. Everything else is the fast tier,
/// <c>dotnet test tests/ModularCA.Tests --filter "Tier!=Slow"</c>, meant for after each merge.
/// The plain <c>dotnet test</c> runs both tiers, and so does CI.
/// </summary>
internal static class TestTier
{
    /// <summary>The trait's name.</summary>
    public const string Name = "Tier";

    /// <summary>The value that takes a test out of the fast tier.</summary>
    public const string Slow = "Slow";
}
