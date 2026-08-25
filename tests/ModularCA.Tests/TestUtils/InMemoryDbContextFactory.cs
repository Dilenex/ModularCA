using Microsoft.EntityFrameworkCore;
using ModularCA.Database;

namespace ModularCA.Tests.TestUtils;

/// <summary>
/// Builds a fresh <see cref="ModularCADbContext"/> backed by EF Core's in-memory provider for
/// each test invocation. The database name is unique per call so two concurrent tests never
/// see each other's data. Use within a <c>using</c> block — the factory does not own
/// disposal, the test does.
/// <para>
/// Suitable for entity-shape, query-builder, and most service-level tests. Tests that exercise
/// raw SQL, JSON column semantics, transaction isolation, or migration behavior must use a real
/// MySQL container (out of scope for the unit-test project — that's <c>ModularCA.IntegrationTests</c>'s
/// territory).
/// </para>
/// </summary>
internal static class InMemoryDbContextFactory
{
    public static ModularCADbContext Create() => Create($"test-{Guid.NewGuid():N}");

    /// <summary>
    /// Builds a context over a NAMED in-memory database, so a test can open a second, independent
    /// context over the same store.
    /// </summary>
    /// <remarks>
    /// Required for any test that claims to verify persistence. <c>DbSet.FindAsync</c> returns the
    /// tracked instance from the change tracker when one is present, so reading back through the
    /// same context returns the object the test just mutated in memory — the assertion passes
    /// whether or not <c>SaveChangesAsync</c> was ever called. Reading through a fresh context
    /// forces the value to have actually reached the store.
    /// </remarks>
    public static ModularCADbContext Create(string databaseName)
    {
        var options = new DbContextOptionsBuilder<ModularCADbContext>()
            .UseInMemoryDatabase(databaseName)
            // Suppress the "InMemory doesn't support transactions" warning. Production code
            // uses BeginTransactionAsync; in-memory silently no-ops on it. Acceptable for tests
            // that don't depend on rollback semantics — we'd use Testcontainers MySQL otherwise.
            .ConfigureWarnings(w => w.Ignore(Microsoft.EntityFrameworkCore.Diagnostics.InMemoryEventId.TransactionIgnoredWarning))
            .Options;
        return new ModularCADbContext(options);
    }
}
