using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace ModularCA.Database;

/// <summary>
/// Design-time factory for creating ModularCADbContext instances during EF Core migrations.
/// </summary>
public class ModularCADbContextFactory : IDesignTimeDbContextFactory<ModularCADbContext>
{
    /// <summary>
    /// Creates a new ModularCADbContext with a placeholder connection string for migration generation.
    /// </summary>
    public ModularCADbContext CreateDbContext(string[] args)
    {
        var optionsBuilder = new DbContextOptionsBuilder<ModularCADbContext>();
        // Design-time only: `dotnet ef` needs a provider to resolve the relational model, not a
        // reachable server. Npgsql does not probe the server to pick a version the way the MySQL
        // provider did, so migration generation works with no database running at all.
        optionsBuilder.UseNpgsql("Host=localhost;Database=modularca-app;Username=postgres;Password=placeholder");
        return new ModularCADbContext(optionsBuilder.Options);
    }
}
