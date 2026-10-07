using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace ModularCA.Database;

/// <summary>
/// Design-time factory for creating AuditDbContext instances during EF Core migrations.
/// </summary>
public class AuditDbContextFactory : IDesignTimeDbContextFactory<AuditDbContext>
{
    /// <summary>
    /// Creates a new AuditDbContext with a placeholder connection string for migration generation.
    /// </summary>
    public AuditDbContext CreateDbContext(string[] args)
    {
        var optionsBuilder = new DbContextOptionsBuilder<AuditDbContext>();
        // Design-time connection for migration generation only; never opened.
        optionsBuilder.UseNpgsql("Host=localhost;Database=modularca-audit;Username=postgres;Password=placeholder");
        return new AuditDbContext(optionsBuilder.Options);
    }
}
