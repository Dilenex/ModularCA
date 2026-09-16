using Microsoft.EntityFrameworkCore;
using ModularCA.Shared.Entities;

namespace ModularCA.Database;

/// <summary>
/// EF Core database context for audit logging across all protocols (EST, SCEP, CMP, ACME).
/// </summary>
public class AuditDbContext(DbContextOptions<AuditDbContext> options) : DbContext(options)
{
    public DbSet<AuditLogEntity> AuditLogs { get; set; }
    public DbSet<AuditEstEntity> AuditEst { get; set; }
    public DbSet<AuditScepEntity> AuditScep { get; set; }
    public DbSet<AuditCmpEntity> AuditCmp { get; set; }
    public DbSet<AuditMsaeEntity> AuditMsae { get; set; }
    public DbSet<AuditAcmeEntity> AuditAcme { get; set; }
    public DbSet<AuditNetworkEntity> AuditNetwork { get; set; }
    public DbSet<CertComplianceFindingEntity> CertComplianceFindings { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Add composite (TenantId, Timestamp), (CertificateAuthorityId,
        // Timestamp), and (ActorUserId, Timestamp) covering indexes alongside the existing
        // single-column ones. The dominant audit query pattern is "events for tenant X in
        // the last 30 days ordered by timestamp desc" — a composite index serves that
        // directly without index intersection or filesort. Same treatment for protocol
        // audit tables (EST/SCEP/CMP/ACME/Network) using their matching filter column.
        modelBuilder.Entity<AuditLogEntity>(entity =>
        {
            entity.HasIndex(a => a.Timestamp);
            entity.HasIndex(a => a.ActorUserId);
            entity.HasIndex(a => a.ActionType);
            entity.HasIndex(a => a.TargetEntityId);
            entity.HasIndex(a => a.CertificateAuthorityId);
            entity.HasIndex(a => a.TenantId);
            entity.HasIndex(a => new { a.TenantId, a.Timestamp });
            entity.HasIndex(a => new { a.CertificateAuthorityId, a.Timestamp });
            entity.HasIndex(a => new { a.ActorUserId, a.Timestamp });
            entity.HasIndex(a => new { a.TenantId, a.Timestamp, a.Id }).HasDatabaseName("IX_AuditLogs_TenantChain");
        });

        modelBuilder.Entity<AuditEstEntity>(entity =>
        {
            entity.HasIndex(a => a.Timestamp);
            entity.HasIndex(a => a.CertificateSerial);
            entity.HasIndex(a => a.SourceIp);
            entity.HasIndex(a => a.CaLabel);
            entity.HasIndex(a => a.CertificateAuthorityId);
            entity.HasIndex(a => a.TenantId);
            entity.HasIndex(a => new { a.TenantId, a.Timestamp });
            entity.HasIndex(a => new { a.CertificateAuthorityId, a.Timestamp });
        });

        modelBuilder.Entity<AuditMsaeEntity>(entity =>
        {
            entity.HasIndex(a => a.Timestamp);
            entity.HasIndex(a => a.Realm);
            entity.HasIndex(a => a.CertificateSerial);
            entity.HasIndex(a => a.SourceIp);
            entity.HasIndex(a => a.CaLabel);
            entity.HasIndex(a => a.CertificateAuthorityId);
            entity.HasIndex(a => a.TenantId);
            entity.HasIndex(a => new { a.TenantId, a.Timestamp });
            entity.HasIndex(a => new { a.CertificateAuthorityId, a.Timestamp });
        });

        modelBuilder.Entity<AuditScepEntity>(entity =>
        {
            entity.HasIndex(a => a.Timestamp);
            entity.HasIndex(a => a.CertificateSerial);
            entity.HasIndex(a => a.SourceIp);
            entity.HasIndex(a => a.TransactionId);
            entity.HasIndex(a => a.CaLabel);
            entity.HasIndex(a => a.CertificateAuthorityId);
            entity.HasIndex(a => a.TenantId);
            entity.HasIndex(a => new { a.TenantId, a.Timestamp });
            entity.HasIndex(a => new { a.CertificateAuthorityId, a.Timestamp });
        });

        modelBuilder.Entity<AuditCmpEntity>(entity =>
        {
            entity.HasIndex(a => a.Timestamp);
            entity.HasIndex(a => a.CertificateSerial);
            entity.HasIndex(a => a.SourceIp);
            entity.HasIndex(a => a.TransactionId);
            entity.HasIndex(a => a.CaLabel);
            entity.HasIndex(a => a.CertificateAuthorityId);
            entity.HasIndex(a => a.TenantId);
            entity.HasIndex(a => new { a.TenantId, a.Timestamp });
            entity.HasIndex(a => new { a.CertificateAuthorityId, a.Timestamp });
        });

        modelBuilder.Entity<AuditAcmeEntity>(entity =>
        {
            entity.HasIndex(a => a.Timestamp);
            entity.HasIndex(a => a.CertificateSerial);
            entity.HasIndex(a => a.SourceIp);
            entity.HasIndex(a => a.AccountId);
            entity.HasIndex(a => a.CaLabel);
            entity.HasIndex(a => a.CertificateAuthorityId);
            entity.HasIndex(a => a.TenantId);
            entity.HasIndex(a => new { a.TenantId, a.Timestamp });
            entity.HasIndex(a => new { a.CertificateAuthorityId, a.Timestamp });
        });

        modelBuilder.Entity<AuditNetworkEntity>(entity =>
        {
            entity.HasIndex(a => a.Timestamp);
            entity.HasIndex(a => a.SourceIp);
            entity.HasIndex(a => a.CaLabel);
            entity.HasIndex(a => a.CertificateAuthorityId);
            entity.HasIndex(a => a.TenantId);
            entity.HasIndex(a => new { a.TenantId, a.Timestamp });
            entity.HasIndex(a => new { a.CertificateAuthorityId, a.Timestamp });
        });
    }
}
