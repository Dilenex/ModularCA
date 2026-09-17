using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.Logging;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Interfaces;

namespace ModularCA.Database;

/// <summary>
/// Primary EF Core database context for the ModularCA application data (certificates, profiles, ACME, users, etc.).
/// <para>
/// The context accepts an optional <see cref="ITenantContext"/>
/// that feeds the global query filter applied to every tenant-scoped entity. When the
/// context is unresolved (background jobs, anonymous public routes, migrations) the filter
/// allows all rows through so CRL generation, OCSP, and EF migrations continue to work.
/// Cross-tenant admin UIs that legitimately need every row call <c>IgnoreQueryFilters()</c>
/// on the query AND explicitly gate the call on
/// <see cref="ITenantContext.IsSystemAdmin"/>.
/// </para>
/// </summary>
public class ModularCADbContext : DbContext
{
    // Never null — the single-arg constructor populates this with UnresolvedTenantContext.Instance.
    private readonly ITenantContext _tenantContext;

    // True when the filter should allow every row through — i.e. during bootstrap, design-time
    // tooling, background jobs, or for system-admin callers.
    //
    // This MUST stay a computed property. It was previously a readonly field assigned in the
    // constructor, which silently disabled tenant isolation on every authenticated request:
    // TenantResolutionMiddleware takes ModularCADbContext as a method-injected parameter, so DI
    // constructs the scoped context BEFORE the middleware body runs — and therefore before it
    // calls tenantContext.Set(...). At construction HasContext is still false, so the snapshot
    // latched to true, and because AddDbContext is scoped that same bypassed instance was then
    // handed to every downstream controller and service for the rest of the request. A tenant-A
    // user querying CertificateAuthorities saw tenant B's rows.
    //
    // The ITenantContext reference is live, so reading through it here picks up the middleware's
    // Set(...) regardless of construction order. EF Core binds DbContext-instance members as SQL
    // parameters when it compiles each query for execution, not once at model-build time, so a
    // property is evaluated per query — which is exactly what makes this correct.
    private bool TenantFilterBypass => !_tenantContext.HasContext || _tenantContext.IsSystemAdmin;

    // Materialized HashSet<Guid> so EF can translate .Contains() on it directly — HashSet<T>
    // .Contains has a dedicated SQL translator, unlike IReadOnlySet<T>.Contains, and the
    // interface form falls back to client evaluation and NREs during parameter binding.
    //
    // Cached against the source set's identity rather than rebuilt per access: the filter is
    // evaluated on every tenant-scoped query, and Set(...) is called at most once per request,
    // so the cache is refreshed exactly when the underlying set is replaced. Empty in the bypass
    // case, so the Contains() path yields 0 rows if it is ever reached (it should not be —
    // TenantFilterBypass short-circuits first).
    private HashSet<Guid>? _accessibleTenantIdsCache;
    private IReadOnlySet<Guid>? _accessibleTenantIdsSource;

    private HashSet<Guid> AccessibleTenantIds
    {
        get
        {
            if (TenantFilterBypass)
                return _emptyTenantIds;

            var source = _tenantContext.AccessibleTenantIds;
            if (!ReferenceEquals(source, _accessibleTenantIdsSource))
            {
                _accessibleTenantIdsSource = source;
                _accessibleTenantIdsCache = new HashSet<Guid>(source);
            }
            return _accessibleTenantIdsCache!;
        }
    }

    private static readonly HashSet<Guid> _emptyTenantIds = new();

    /// <summary>
    /// Constructs a <see cref="ModularCADbContext"/> with an unresolved tenant context.
    /// Used by EF design-time tooling (`dotnet ef migrations add`), bootstrap, CRL/OCSP
    /// responders, and background services that do not have an HTTP scope. The unresolved
    /// context reports <c>HasContext=false</c> so the query filter allows every row through.
    /// </summary>
    public ModularCADbContext(DbContextOptions<ModularCADbContext> options) : base(options)
    {
        _tenantContext = UnresolvedTenantContext.Instance;
    }

    /// <summary>
    /// Constructs a <see cref="ModularCADbContext"/> with a scoped
    /// <see cref="ITenantContext"/>. Called by ASP.NET Core DI for every HTTP request
    /// so the query filter knows which tenants the caller can see.
    /// </summary>
    public ModularCADbContext(DbContextOptions<ModularCADbContext> options, ITenantContext tenantContext) : base(options)
    {
        // Deliberately no snapshotting here — see TenantFilterBypass. The middleware populates
        // this same ITenantContext instance after DI has already constructed us.
        _tenantContext = tenantContext ?? UnresolvedTenantContext.Instance;
    }

    public DbSet<CrlEntity> Crls { get; set; }
    public DbSet<LdapConfigurationEntity> LdapConfigurations { get; set; }
    public DbSet<CertProfileEntity> CertProfiles { get; set; }
    public DbSet<SigningProfileEntity> SigningProfiles { get; set; }
    public DbSet<CertRequestEntity> CertificateRequests { get; set; }
    public DbSet<CertificateEntity> Certificates { get; set; }
    public DbSet<KeystoreEntryEntity> Keystores { get; set; }
    public DbSet<OIDOptionEntity> OIDOptions { get; set; }

    public DbSet<FeatureFlagEntity> FeatureFlags { get; set; }
    public DbSet<CrlConfigurationEntity> CrlConfigurations { get; set; }
    public DbSet<CertificateAccessListEntity> CertificateAccessLists { get; set; }
    public DbSet<UserEntity> Users { get; set; }

    public DbSet<CaGroupEntity> CaGroups { get; set; }
    public DbSet<CaGroupMemberEntity> CaGroupMembers { get; set; }
    public DbSet<CapabilityGrantEntity> CapabilityGrants { get; set; }
    public DbSet<RoleEntity> Roles { get; set; }
    public DbSet<RoleCapabilityEntity> RoleCapabilities { get; set; }
    public DbSet<RoleAssignmentEntity> RoleAssignments { get; set; }
    public DbSet<UserCapabilityGrantEntity> UserCapabilityGrants { get; set; }

    public DbSet<TenantEntity> Tenants { get; set; }
    public DbSet<CertificateAuthorityEntity> CertificateAuthorities { get; set; }

    public DbSet<RefreshTokenEntity> RefreshTokens { get; set; }

    /// <summary>Access badges: named subsets of a user's own grant sources a session can wear.</summary>
    public DbSet<AccessBadgeEntity> AccessBadges { get; set; }
    public DbSet<AccessBadgeSourceEntity> AccessBadgeSources { get; set; }

    /// <summary>Kerberos realm bindings for Windows autoenrollment: one forest to one tenant, with its service keys.</summary>
    public DbSet<KerberosRealmEntity> KerberosRealms { get; set; }
    public DbSet<KerberosRealmKeyEntity> KerberosRealmKeys { get; set; }
    public DbSet<TenantHostnameEntity> TenantHostnames { get; set; }

    // CA Service URLs (CDP, OCSP, AIA)
    public DbSet<CaServiceUrlEntity> CaServiceUrls { get; set; }

    // Per-CA Protocol Configuration
    public DbSet<CaProtocolConfigEntity> CaProtocolConfigs { get; set; }

    // ACME Protocol
    public DbSet<AcmeAccountEntity> AcmeAccounts { get; set; }
    public DbSet<AcmeOrderEntity> AcmeOrders { get; set; }
    public DbSet<AcmeAuthorizationEntity> AcmeAuthorizations { get; set; }
    public DbSet<AcmeChallengeEntity> AcmeChallenges { get; set; }
    public DbSet<AcmeNonceEntity> AcmeNonces { get; set; }
    public DbSet<AcmeEabKeyEntity> AcmeEabKeys { get; set; }

    public DbSet<PasswordPolicyEntity> PasswordPolicies { get; set; }

    /// <summary>
    /// Per-user rotating password history used
    /// to enforce the "no reuse of the last N passwords" rule. Populated by
    /// <c>IPasswordPolicyService.RecordPasswordHistoryAsync</c> after every
    /// successful password change.
    /// </summary>
    public DbSet<PasswordHistoryEntity> PasswordHistory { get; set; }

    // Runtime-tunable policy tables (moved out of config.yaml so admins can
    // change them via the admin API without a restart).
    public DbSet<SecurityPolicyEntity> SecurityPolicies { get; set; }
    public DbSet<LdapPublisherPolicyEntity> LdapPublisherPolicies { get; set; }
    public DbSet<ProtocolRateLimitEntity> ProtocolRateLimits { get; set; }
    public DbSet<EnrollmentTokenEntity> EnrollmentTokens { get; set; }
    public DbSet<CtLogEntity> CtLogs { get; set; }
    public DbSet<SshCaKeyEntity> SshCaKeys { get; set; }
    public DbSet<SshCertificateEntity> SshCertificates { get; set; }
    public DbSet<SshSigningProfileEntity> SshSigningProfiles { get; set; }
    public DbSet<SshCertProfileEntity> SshCertProfiles { get; set; }
    public DbSet<SshRequestProfileEntity> SshRequestProfiles { get; set; }
    public DbSet<NotificationPreferenceEntity> NotificationPreferences { get; set; }
    public DbSet<AllowedCertProfileSigningProfileEntity> AllowedCertProfileSigningProfiles { get; set; }

    // Certificate Tags (key-value dependency/service metadata)
    public DbSet<CertificateTagEntity> CertificateTags { get; set; }

    // CSR Approvals
    public DbSet<CsrApprovalEntity> CsrApprovals { get; set; }

    // Request Profiles
    public DbSet<RequestProfileEntity> RequestProfiles { get; set; }

    // Certificate Templates
    public DbSet<CertificateTemplateEntity> CertificateTemplates { get; set; }

    // SSH Certificate Templates
    public DbSet<SshCertificateTemplateEntity> SshCertificateTemplates { get; set; }

    // Trust Anchors (cross-certification)
    public DbSet<TrustAnchorEntity> TrustAnchors { get; set; }

    // FIDO2/WebAuthn credentials for 2FA
    public DbSet<Fido2CredentialEntity> Fido2Credentials { get; set; }

    // TOTP (RFC 6238) secrets for authenticator-app 2FA
    public DbSet<TotpSecretEntity> TotpSecrets { get; set; }

    /// <summary>One-time TOTP recovery codes (SHA-256 hashed at rest).</summary>
    public DbSet<TotpRecoveryCodeEntity> TotpRecoveryCodes { get; set; }

    // mTLS client certificate credentials for MFA
    public DbSet<MtlsCredentialEntity> MtlsCredentials { get; set; }

    // Certificate compliance scan findings
    public DbSet<CertComplianceFindingEntity> CertComplianceFindings { get; set; }

    // Key ceremony workflows for catastrophic CA operations
    public DbSet<KeyCeremonyEntity> KeyCeremonies { get; set; }

    // IP allow-list rules for gated paths (System/Setup/Auth/Api/ShortUrl/Ca/Protocol scopes)
    public DbSet<WhitelistEntity> Whitelists { get; set; }

    /// <summary>Database-backed scheduler leader-election lease.</summary>
    public DbSet<SchedulerLeaseEntity> SchedulerLeases { get; set; }

    /// <summary>Persistent per-job scheduler state.</summary>
    public DbSet<SchedulerJobStateEntity> SchedulerJobStates { get; set; }

    /// <summary>Atomic de-dup log for notification jobs.</summary>
    public DbSet<NotificationLogEntity> NotificationLogs { get; set; }

    /// <summary>Persistent SCEP transaction state for GetCertInitial + replay protection.</summary>
    public DbSet<ScepTransactionEntity> ScepTransactions { get; set; }

    /// <summary>Persistent CMP transaction/nonce state for replay protection + certConf correlation.</summary>
    public DbSet<CmpTransactionEntity> CmpTransactions { get; set; }

    /// <summary>Per-user UI preferences (table column layouts, etc.), keyed by user + namespaced key.</summary>
    public DbSet<UserPreferenceEntity> UserPreferences { get; set; }

    /// <summary>
    /// The signer's own record of every decision about a private key, allowed or refused. Kept
    /// apart from the node's audit so a lost node audit still leaves the signer's account.
    /// </summary>
    public DbSet<SignerAuditEntity> SignerAudit { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<CrlEntity>().HasIndex(c => new { c.IssuerName, c.CrlNumber }).IsUnique();
        // One preference row per (user, key); ValueJson holds an opaque client-owned blob.
        modelBuilder.Entity<UserPreferenceEntity>().HasIndex(p => new { p.UserId, p.Key }).IsUnique();

        // The signer's audit is queried by time, by key and by CA; it carries no foreign keys so a
        // row outlives whatever it names.
        modelBuilder.Entity<SignerAuditEntity>(entity =>
        {
            entity.HasIndex(e => e.At);
            entity.HasIndex(e => e.KeyCertificateId);
            entity.HasIndex(e => e.CaId);
        });
        modelBuilder.Entity<LdapConfigurationEntity>(entity =>
        {
            entity.HasIndex(s => s.Name).IsUnique();
            entity.HasOne<CertificateAuthorityEntity>()
                  .WithMany()
                  .HasForeignKey(e => e.CertificateAuthorityId)
                  .OnDelete(DeleteBehavior.Restrict);
        });
        // Deliberately GLOBAL, not per-tenant — and knowingly so.
        //
        // CertProfiles, CaGroups and Roles all carry a TenantId, so a per-tenant unique name
        // would be the natural multi-tenant shape (and CertificateAuthorityEntity was moved to
        // it). They are left global because the CODE still resolves them by bare name:
        //   CaCreationService: CertProfiles.FirstOrDefault(cp => cp.Name == "Main CA Certificate Profile")
        //   BootstrapProfileSeeder / BootstrapService: CaGroups.First(g => g.Name == "system-super")
        //   RoleAssignmentHelper: Roles.FirstOrDefault(r => r.Name == templateName && r.IsBuiltIn)
        //
        // The unique index is what makes those lookups deterministic. Relaxing it without
        // rewriting every one of them would turn "two tenants cannot reuse a profile name" —
        // an inconvenience — into "a CA creation silently picked up another tenant's profile",
        // which is a cross-tenant correctness bug. The index is not the defect here; the
        // tenant-blind lookups are, and they have to move first.
        modelBuilder.Entity<CertProfileEntity>().HasIndex(c => c.Name).IsUnique();
        modelBuilder.Entity<CertProfileEntity>(entity =>
        {
            entity.HasOne(e => e.CertificateAuthority)
                  .WithMany()
                  .HasForeignKey(e => e.CertificateAuthorityId)
                  .OnDelete(DeleteBehavior.SetNull);
            entity.HasOne(e => e.InheritsFrom)
                  .WithMany()
                  .HasForeignKey(e => e.InheritsFromId)
                  .OnDelete(DeleteBehavior.SetNull);
            // Tenant-scoped profile index for fast per-tenant lookups.
            entity.HasIndex(e => e.TenantId);
        });
        modelBuilder.Entity<CertRequestEntity>(entity =>
        {
            entity.HasIndex(c => c.SubmittedAt);
            entity.HasOne(c => c.IssuedCertificate)
                  .WithMany()
                  .HasForeignKey(c => c.IssuedCertificateId)
                  .OnDelete(DeleteBehavior.SetNull);
        });
        modelBuilder.Entity<CertificateEntity>(c =>
        {
            c.HasIndex(c => new { c.SerialNumber, c.Issuer }).IsUnique();

            // Prefix index. SubjectDN widened from 255 to 1024 so it can hold every DN the
            // application will issue (see CertificateEntity.SubjectDnMaxLength), and InnoDB caps an
            // index key at 3072 bytes — 768 characters under utf8mb4 — so the full column is no
            // longer indexable. 255 characters is ample selectivity for the lookups that use this,
            // which search for a subject rather than range over it.
            c.HasIndex(c => c.SubjectDN).HasPrefixLength(255);

            // Index for CRL revoked-cert lookup by issuer FK.
            c.HasIndex(c => c.IssuerCertificateId);

            // Composite index that scopes OCSP status lookup
            // to the resolved issuer. Serials are only unique within an issuer,
            // so the responder MUST filter by IssuerCertificateId to avoid
            // cross-CA serial collisions returning the wrong status.
            c.HasIndex(c => new { c.IssuerCertificateId, c.SerialNumber });

            c.HasOne(c => c.SigningProfile)
                .WithMany()
                .HasForeignKey(c => c.SigningProfileId)
                .OnDelete(DeleteBehavior.SetNull);

            c.HasOne(c => c.CertProfile)
                .WithMany()
                .HasForeignKey(c => c.CertProfileId)
                .OnDelete(DeleteBehavior.SetNull);
        });

        modelBuilder.Entity<CertificateTagEntity>(t =>
        {
            t.HasIndex(t => t.CertificateId);
            t.HasIndex(t => new { t.CertificateId, t.Key }).IsUnique();

            t.HasOne(t => t.Certificate)
                .WithMany(c => c.Tags)
                .HasForeignKey(t => t.CertificateId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<SigningProfileEntity>(s =>
        {
            s.HasIndex(s => s.Name).IsUnique();

            s.HasOne(s => s.Issuer)
                .WithMany()
                .HasForeignKey(s => s.IssuerId)
                .OnDelete(DeleteBehavior.SetNull);

            s.HasOne(s => s.InheritsFrom)
                .WithMany()
                .HasForeignKey(s => s.InheritsFromId)
                .OnDelete(DeleteBehavior.SetNull);
        });

        modelBuilder.Entity<AllowedCertProfileSigningProfileEntity>(entity =>
        {
            entity.HasIndex(e => new { e.CertProfileId, e.SigningProfileId }).IsUnique();

            entity.HasOne(e => e.CertProfile)
                  .WithMany()
                  .HasForeignKey(e => e.CertProfileId)
                  .OnDelete(DeleteBehavior.Cascade);

            entity.HasOne(e => e.SigningProfile)
                  .WithMany()
                  .HasForeignKey(e => e.SigningProfileId)
                  .OnDelete(DeleteBehavior.Cascade);
        });
        modelBuilder.Entity<KeystoreEntryEntity>().HasIndex(k => k.Name).IsUnique();
        modelBuilder.Entity<OIDOptionEntity>().HasIndex(o => o.OID).IsUnique();

        modelBuilder.Entity<FeatureFlagEntity>().HasIndex(f => f.Name).IsUnique();
        modelBuilder.Entity<CrlConfigurationEntity>().HasIndex(c => c.Name).IsUnique();

        // CRL history must not be deletable as a side effect.
        //
        // Neither of these relationships was configured, so EF's convention for a required FK
        // applied: Cascade. Deleting one CA certificate therefore removed its CrlConfigurations,
        // which removed every Crl generated under them. That is worse than losing records — the
        // configuration row carries LastCrlNumber, and RFC 5280 §5.2.3 requires CRL numbers to
        // increase monotonically for an issuer. Recreating the configuration restarts the counter
        // at 0, so the next CRL published reuses numbers already in circulation, and relying
        // parties holding a cached higher-numbered CRL can reasonably ignore it.
        //
        // Restrict makes the delete fail instead, so an operator removing a CA has to deal with
        // its CRL configuration deliberately. LdapConfigurationEntity above already takes this
        // approach for its CA foreign key.
        modelBuilder.Entity<CrlConfigurationEntity>()
            .HasOne(c => c.CaCertificate)
            .WithMany()
            .HasForeignKey(c => c.CaCertificateId)
            .OnDelete(DeleteBehavior.Restrict);

        modelBuilder.Entity<CrlEntity>()
            .HasOne(c => c.Task)
            .WithMany()
            .HasForeignKey(c => c.TaskId)
            .OnDelete(DeleteBehavior.Restrict);

        modelBuilder.Entity<CertificateAccessListEntity>()
            .HasIndex(x => new { x.UserId, x.CertificateId })
            .IsUnique();

        modelBuilder.Entity<CertificateAccessListEntity>()
            .HasOne(x => x.User)
            .WithMany(u => u.CertificateAccess)
            .HasForeignKey(x => x.UserId)
            .OnDelete(DeleteBehavior.Restrict);

        modelBuilder.Entity<CertificateAccessListEntity>()
            .HasOne(x => x.Certificate)
            .WithMany(c => c.AccessList)
            .HasForeignKey(x => x.CertificateId)
            .OnDelete(DeleteBehavior.Cascade);

        // GrantedByUser was Restrict — that blocked deletion of any user
        // who had ever issued an ACL grant, effectively preventing admin offboarding. Switch
        // to SetNull so the grant-history record survives with a null grantor.
        modelBuilder.Entity<CertificateAccessListEntity>()
            .HasOne(c => c.GrantedByUser)
            .WithMany(u => u.GrantedAccess)
            .HasForeignKey(c => c.GrantedByUserId)
            .OnDelete(DeleteBehavior.SetNull);
        modelBuilder.Entity<CaGroupEntity>()
            .HasIndex(g => g.Name).IsUnique();
        modelBuilder.Entity<CaGroupEntity>()
            .HasOne(g => g.CertificateAuthority)
            .WithMany()
            .HasForeignKey(g => g.CertificateAuthorityId)
            .OnDelete(DeleteBehavior.SetNull);
        modelBuilder.Entity<CaGroupEntity>()
            .HasIndex(g => g.TenantId);
        modelBuilder.Entity<CaGroupMemberEntity>()
            .HasIndex(gm => new { gm.GroupId, gm.UserId }).IsUnique();
        modelBuilder.Entity<CaGroupMemberEntity>()
            .HasOne(gm => gm.Group)
            .WithMany(g => g.Members)
            .HasForeignKey(gm => gm.GroupId)
            .OnDelete(DeleteBehavior.Cascade);
        modelBuilder.Entity<CaGroupMemberEntity>()
            .HasOne(gm => gm.User)
            .WithMany(u => u.GroupMemberships)
            .HasForeignKey(gm => gm.UserId)
            .OnDelete(DeleteBehavior.Cascade);
        modelBuilder.Entity<UserEntity>()
            .HasIndex(ur => ur.Username).IsUnique();
        modelBuilder.Entity<UserEntity>()
            .HasIndex(ur => ur.Id).IsUnique();
        modelBuilder.Entity<UserEntity>()
            .HasIndex(ur => ur.Email).IsUnique();
        // Tenant entity
        // Tenant rows gain IsDeleted + DeletedAt soft-delete columns.
        // MySQL/Pomelo does not expose partial/filtered unique indexes, so the unique
        // constraints remain "absolute": an operator re-creating a tenant with the same
        // Name/Slug after soft-deleting the old one must hard-delete the soft record (or
        // rename it) via a SystemAdmin IgnoreQueryFilters path. That trade-off is acceptable
        // in exchange for the global query filter never leaking soft-deleted rows.
        modelBuilder.Entity<TenantEntity>(entity =>
        {
            entity.HasIndex(e => e.Name).IsUnique();
            entity.HasIndex(e => e.Slug).IsUnique();
            entity.HasIndex(e => e.IsDeleted);
            entity.Property(e => e.IsDeleted).HasDefaultValue(false);
        });

        modelBuilder.Entity<CertificateAuthorityEntity>(entity =>
        {
            // Name is per-tenant for the same reason Label is, below. This entity was only half
            // migrated: Label was made composite and Name was left global, so two tenants could
            // each have an "issuing-ca" label but not both call a CA "Issuing CA". Beyond the
            // inconvenience, a global unique name is a cross-tenant oracle — a tenant learns
            // whether another tenant already uses a name by trying to take it.
            //
            // Safe to relax because nothing resolves a CA by bare Name: lookups go through Label
            // or Id. That is NOT true of CertProfiles, CaGroups or Roles, which are still
            // globally unique here deliberately — see the note further down.
            entity.HasIndex(e => new { e.TenantId, e.Name }).IsUnique();
            // Label uniqueness is per-tenant, not global. Two tenants may each
            // have a CA labeled "issuing-ca" without collision. The composite unique index
            // also replaces the old global one so existing queries targeting Label get a
            // fast per-tenant prefix lookup.
            entity.HasIndex(e => new { e.TenantId, e.Label }).IsUnique();
            // Soft-delete flag indexed to make the global query
            // filter predicate (IsDeleted = false) index-friendly.
            entity.HasIndex(e => e.IsDeleted);
            entity.Property(e => e.IsDeleted).HasDefaultValue(false);
            entity.HasOne(e => e.ParentCa)
                  .WithMany(e => e.ChildCAs)
                  .HasForeignKey(e => e.ParentCaId)
                  .OnDelete(DeleteBehavior.Restrict);
            entity.HasOne(e => e.Tenant)
                  .WithMany()
                  .HasForeignKey(e => e.TenantId)
                  .OnDelete(DeleteBehavior.Restrict);
        });

        modelBuilder.Entity<CaServiceUrlEntity>(entity =>
        {
            entity.HasIndex(s => s.CaCertificateId).IsUnique();
            entity.HasOne(s => s.CaCertificate)
                  .WithMany()
                  .HasForeignKey(s => s.CaCertificateId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<CaProtocolConfigEntity>(entity =>
        {
            entity.HasIndex(e => new { e.CaId, e.Protocol }).IsUnique();
            entity.HasOne(e => e.Ca)
                  .WithMany()
                  .HasForeignKey(e => e.CaId)
                  .OnDelete(DeleteBehavior.Cascade);
            entity.HasOne(e => e.SigningProfile)
                  .WithMany()
                  .HasForeignKey(e => e.SigningProfileId)
                  .OnDelete(DeleteBehavior.SetNull);
            entity.HasOne(e => e.CertProfile)
                  .WithMany()
                  .HasForeignKey(e => e.CertProfileId)
                  .OnDelete(DeleteBehavior.SetNull);
            entity.HasOne(e => e.RequestProfile)
                  .WithMany()
                  .HasForeignKey(e => e.RequestProfileId)
                  .OnDelete(DeleteBehavior.SetNull);
        });

        modelBuilder.Entity<CsrApprovalEntity>(entity =>
        {
            entity.HasIndex(e => e.CertRequestId);
            entity.HasOne(e => e.CertRequest)
                  .WithMany(c => c.Approvals)
                  .HasForeignKey(e => e.CertRequestId)
                  .OnDelete(DeleteBehavior.Cascade);
            entity.HasOne(e => e.Approver)
                  .WithMany()
                  .HasForeignKey(e => e.ApproverId)
                  .OnDelete(DeleteBehavior.Restrict);
        });

        modelBuilder.Entity<RequestProfileEntity>(entity =>
        {
            entity.HasIndex(e => e.Name).IsUnique();
            entity.HasOne(e => e.DefaultCertProfile)
                  .WithMany()
                  .HasForeignKey(e => e.DefaultCertProfileId)
                  .OnDelete(DeleteBehavior.SetNull);
            entity.HasOne(e => e.CertificateAuthority)
                  .WithMany()
                  .HasForeignKey(e => e.CertificateAuthorityId)
                  .OnDelete(DeleteBehavior.SetNull);
            entity.HasOne(e => e.InheritsFrom)
                  .WithMany()
                  .HasForeignKey(e => e.InheritsFromId)
                  .OnDelete(DeleteBehavior.SetNull);
        });

        modelBuilder.Entity<CertificateTemplateEntity>(entity =>
        {
            entity.HasIndex(e => e.Name).IsUnique();
            // A Windows client names a template by OID, so two templates must never share one.
            // Nulls (templates not offered to Windows) are exempt from the uniqueness check.
            entity.HasIndex(e => e.MsaeTemplateOid).IsUnique();
            entity.HasOne(e => e.Ca)
                  .WithMany()
                  .HasForeignKey(e => e.CaId)
                  .OnDelete(DeleteBehavior.Cascade);
            entity.HasOne(e => e.SigningProfile)
                  .WithMany()
                  .HasForeignKey(e => e.SigningProfileId)
                  .OnDelete(DeleteBehavior.Cascade);
            entity.HasOne(e => e.CertProfile)
                  .WithMany()
                  .HasForeignKey(e => e.CertProfileId)
                  .OnDelete(DeleteBehavior.Cascade);
            entity.HasOne(e => e.RequestProfile)
                  .WithMany()
                  .HasForeignKey(e => e.RequestProfileId)
                  .OnDelete(DeleteBehavior.SetNull);
        });

        // ACME Protocol
        modelBuilder.Entity<AcmeAccountEntity>()
            .HasIndex(a => a.JwkThumbprint).IsUnique();

        modelBuilder.Entity<AcmeOrderEntity>(entity =>
        {
            entity.HasIndex(o => o.AccountId);
            entity.HasIndex(o => o.ExpiresAt);
            entity.HasOne(o => o.Account)
                  .WithMany()
                  .HasForeignKey(o => o.AccountId)
                  .OnDelete(DeleteBehavior.Cascade);
            entity.HasOne(o => o.Certificate)
                  .WithMany()
                  .HasForeignKey(o => o.CertificateId)
                  .OnDelete(DeleteBehavior.SetNull);
            entity.HasOne(o => o.FinalizedCsr)
                  .WithMany()
                  .HasForeignKey(o => o.FinalizedCsrId)
                  .OnDelete(DeleteBehavior.SetNull);
        });

        modelBuilder.Entity<AcmeAuthorizationEntity>(entity =>
        {
            entity.HasIndex(a => a.OrderId);
            entity.HasOne(a => a.Order)
                  .WithMany()
                  .HasForeignKey(a => a.OrderId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<AcmeChallengeEntity>(entity =>
        {
            entity.HasIndex(c => c.AuthorizationId);
            entity.HasIndex(c => c.Token);
            entity.HasOne(c => c.Authorization)
                  .WithMany()
                  .HasForeignKey(c => c.AuthorizationId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<AcmeNonceEntity>()
            .HasIndex(n => n.Value).IsUnique();

        modelBuilder.Entity<AcmeEabKeyEntity>()
            .HasIndex(e => e.KeyId).IsUnique();

        modelBuilder.Entity<EnrollmentTokenEntity>(entity =>
        {
            entity.HasIndex(t => t.Token).IsUnique();
            entity.HasIndex(t => t.ExpiresAt);
        });

        modelBuilder.Entity<TrustAnchorEntity>(entity =>
        {
            // Unique per ISSUER, not globally. A serial number is only unique within the CA that
            // assigned it — X.509 says nothing about serials being unique across issuers, and
            // small values are commonplace (a self-signed root is very often serial 1). A global
            // unique index therefore made importing two unrelated roots fail with a constraint
            // violation that reads like a duplicate-import error rather than what it is.
            //
            // The Certificates table already gets this right — see its
            // HasIndex(new { SerialNumber, Issuer }) above. This is the sibling that did not.
            entity.HasIndex(t => new { t.SerialNumber, t.Issuer }).IsUnique();
        });

        // FIDO2/WebAuthn credentials
        modelBuilder.Entity<Fido2CredentialEntity>(entity =>
        {
            entity.HasIndex(e => e.UserId);
            entity.HasIndex(e => e.CredentialId).IsUnique();
            entity.HasOne(e => e.User)
                  .WithMany()
                  .HasForeignKey(e => e.UserId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // TOTP secrets
        modelBuilder.Entity<TotpSecretEntity>(entity =>
        {
            entity.HasIndex(e => e.UserId);
            entity.HasOne(e => e.User)
                  .WithMany()
                  .HasForeignKey(e => e.UserId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // TOTP one-time recovery codes.
        modelBuilder.Entity<TotpRecoveryCodeEntity>(entity =>
        {
            entity.HasIndex(e => e.UserId);
            entity.HasIndex(e => new { e.UserId, e.CodeHash }).IsUnique();
            entity.HasOne(e => e.User)
                  .WithMany()
                  .HasForeignKey(e => e.UserId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // Rotating per-user password history.
        // Composite index on (UserId, ChangedAt DESC) supports the "load most
        // recent N hashes for this user" lookup that PasswordPolicyService
        // performs on every password change.
        modelBuilder.Entity<PasswordHistoryEntity>(entity =>
        {
            entity.HasIndex(e => new { e.UserId, e.ChangedAt })
                  .IsDescending(false, true)
                  .HasDatabaseName("IX_PasswordHistory_UserId_ChangedAt");
            entity.HasOne(e => e.User)
                  .WithMany()
                  .HasForeignKey(e => e.UserId)
                  .OnDelete(DeleteBehavior.Cascade);
            entity.Property(e => e.PasswordHash).HasMaxLength(500);
        });

        // mTLS credentials
        modelBuilder.Entity<MtlsCredentialEntity>(entity =>
        {
            entity.HasIndex(e => e.UserId);
            entity.HasIndex(e => e.Thumbprint);
            entity.HasOne(e => e.User)
                  .WithMany()
                  .HasForeignKey(e => e.UserId)
                  .OnDelete(DeleteBehavior.Cascade);
            entity.HasOne(e => e.Certificate)
                  .WithMany()
                  .HasForeignKey(e => e.CertificateId)
                  .OnDelete(DeleteBehavior.SetNull);
            entity.HasOne(e => e.SigningCa)
                  .WithMany()
                  .HasForeignKey(e => e.SigningCaId)
                  .OnDelete(DeleteBehavior.Restrict);
        });

        // CaGroup -> MtlsSigningCa relationship
        modelBuilder.Entity<CaGroupEntity>()
            .HasOne(g => g.MtlsSigningCa)
            .WithMany()
            .HasForeignKey(g => g.MtlsSigningCaId)
            .OnDelete(DeleteBehavior.SetNull);

        // Capability grants — relational authorization model
        modelBuilder.Entity<CapabilityGrantEntity>(entity =>
        {
            entity.HasIndex(e => new { e.GroupId, e.Capability });
            entity.HasIndex(e => new { e.ResourceType, e.ResourceId });
            entity.HasOne(e => e.Group)
                  .WithMany(g => g.Grants)
                  .HasForeignKey(e => e.GroupId)
                  .OnDelete(DeleteBehavior.Cascade);
            entity.HasOne(e => e.GrantedByUser)
                  .WithMany()
                  .HasForeignKey(e => e.GrantedByUserId)
                  .OnDelete(DeleteBehavior.SetNull);
        });

        // Roles — named bundles of capabilities
        modelBuilder.Entity<RoleEntity>(entity =>
        {
            entity.HasIndex(e => e.Name).IsUnique();
            entity.HasIndex(e => e.TenantId);
            entity.HasOne(e => e.Tenant)
                  .WithMany()
                  .HasForeignKey(e => e.TenantId)
                  .OnDelete(DeleteBehavior.SetNull);
            entity.HasOne(e => e.CreatedByUser)
                  .WithMany()
                  .HasForeignKey(e => e.CreatedByUserId)
                  .OnDelete(DeleteBehavior.SetNull);
        });

        // Role capabilities — bindings inside a role
        modelBuilder.Entity<RoleCapabilityEntity>(entity =>
        {
            entity.HasIndex(e => new { e.RoleId, e.Capability });
            entity.HasOne(e => e.Role)
                  .WithMany(r => r.Capabilities)
                  .HasForeignKey(e => e.RoleId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // Role assignments — assigns a role to a user or group with scope
        modelBuilder.Entity<RoleAssignmentEntity>(entity =>
        {
            entity.HasIndex(e => new { e.UserId, e.RoleId });
            entity.HasIndex(e => new { e.GroupId, e.RoleId });
            entity.HasIndex(e => new { e.TenantId, e.CertificateAuthorityId });
            entity.HasOne(e => e.Role)
                  .WithMany(r => r.Assignments)
                  .HasForeignKey(e => e.RoleId)
                  .OnDelete(DeleteBehavior.Cascade);
            entity.HasOne(e => e.User)
                  .WithMany(u => u.RoleAssignments)
                  .HasForeignKey(e => e.UserId)
                  .OnDelete(DeleteBehavior.Cascade);
            entity.HasOne(e => e.Group)
                  .WithMany(g => g.RoleAssignments)
                  .HasForeignKey(e => e.GroupId)
                  .OnDelete(DeleteBehavior.Cascade);
            entity.HasOne(e => e.Tenant)
                  .WithMany()
                  .HasForeignKey(e => e.TenantId)
                  .OnDelete(DeleteBehavior.SetNull);
            entity.HasOne(e => e.CertificateAuthority)
                  .WithMany()
                  .HasForeignKey(e => e.CertificateAuthorityId)
                  .OnDelete(DeleteBehavior.SetNull);
            entity.HasOne(e => e.AssignedByUser)
                  .WithMany()
                  .HasForeignKey(e => e.AssignedByUserId)
                  .OnDelete(DeleteBehavior.SetNull);
        });

        // User capability grants — direct one-off grants on users
        modelBuilder.Entity<AccessBadgeEntity>(entity =>
        {
            entity.HasIndex(e => new { e.UserId, e.Name }).IsUnique();
            entity.HasOne(e => e.User)
                  .WithMany()
                  .HasForeignKey(e => e.UserId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<AccessBadgeSourceEntity>(entity =>
        {
            entity.HasIndex(e => new { e.BadgeId, e.Kind, e.SourceId }).IsUnique();
            entity.HasOne(e => e.Badge)
                  .WithMany(b => b.Sources)
                  .HasForeignKey(e => e.BadgeId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<UserEntity>(entity =>
        {
            entity.HasIndex(e => e.IsServiceIdentity);
            entity.HasIndex(e => e.ServiceScopeTenantId);
            entity.HasIndex(e => e.ServiceScopeCaId);
        });

        modelBuilder.Entity<KerberosRealmEntity>(entity =>
        {
            entity.HasIndex(e => e.Realm).IsUnique();
            entity.HasIndex(e => e.TenantId);
            entity.HasOne(e => e.Tenant)
                  .WithMany()
                  .HasForeignKey(e => e.TenantId)
                  .OnDelete(DeleteBehavior.Cascade);
            entity.HasOne(e => e.EnrollmentUser)
                  .WithMany()
                  .HasForeignKey(e => e.EnrollmentUserId)
                  .OnDelete(DeleteBehavior.Restrict);
        });

        modelBuilder.Entity<KerberosRealmKeyEntity>(entity =>
        {
            entity.HasIndex(e => new { e.RealmId, e.Kvno, e.EncryptionType }).IsUnique();
            entity.Property(e => e.Source).HasConversion<string>().HasMaxLength(16);
            entity.HasOne(e => e.Realm)
                  .WithMany(r => r.Keys)
                  .HasForeignKey(e => e.RealmId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<TenantHostnameEntity>(entity =>
        {
            entity.HasIndex(e => e.Hostname).IsUnique();
            entity.HasIndex(e => e.TenantId);
            entity.HasOne(e => e.Tenant)
                  .WithMany()
                  .HasForeignKey(e => e.TenantId)
                  .OnDelete(DeleteBehavior.Cascade);
            entity.HasOne(e => e.IssuingCa)
                  .WithMany()
                  .HasForeignKey(e => e.IssuingCaId)
                  .OnDelete(DeleteBehavior.Restrict);
            entity.HasOne(e => e.Certificate)
                  .WithMany()
                  .HasForeignKey(e => e.CertificateId)
                  .OnDelete(DeleteBehavior.SetNull);
        });

        modelBuilder.Entity<UserCapabilityGrantEntity>(entity =>
        {
            entity.HasIndex(e => new { e.UserId, e.Capability });
            entity.HasIndex(e => new { e.TenantId, e.CertificateAuthorityId });
            entity.HasOne(e => e.User)
                  .WithMany(u => u.UserGrants)
                  .HasForeignKey(e => e.UserId)
                  .OnDelete(DeleteBehavior.Cascade);
            entity.HasOne(e => e.Tenant)
                  .WithMany()
                  .HasForeignKey(e => e.TenantId)
                  .OnDelete(DeleteBehavior.SetNull);
            entity.HasOne(e => e.CertificateAuthority)
                  .WithMany()
                  .HasForeignKey(e => e.CertificateAuthorityId)
                  .OnDelete(DeleteBehavior.SetNull);
            entity.HasOne(e => e.GrantedByUser)
                  .WithMany()
                  .HasForeignKey(e => e.GrantedByUserId)
                  .OnDelete(DeleteBehavior.SetNull);
        });

        // SSH Signing Profiles
        modelBuilder.Entity<SshSigningProfileEntity>(entity =>
        {
            entity.HasIndex(e => e.Name).IsUnique();
            entity.HasOne(e => e.SshCaKey)
                  .WithMany()
                  .HasForeignKey(e => e.SshCaKeyId)
                  .OnDelete(DeleteBehavior.SetNull);
        });

        // SSH Cert Profiles
        modelBuilder.Entity<SshCertProfileEntity>()
            .HasIndex(e => e.Name).IsUnique();

        // SSH Request Profiles
        modelBuilder.Entity<SshRequestProfileEntity>()
            .HasIndex(e => e.Name).IsUnique();

        // SSH Certificate Templates
        modelBuilder.Entity<SshCertificateTemplateEntity>(entity =>
        {
            entity.HasIndex(e => e.Name).IsUnique();
            entity.HasOne(e => e.SshCaKey)
                  .WithMany()
                  .HasForeignKey(e => e.SshCaKeyId)
                  .OnDelete(DeleteBehavior.Cascade);
            entity.HasOne(e => e.SshSigningProfile)
                  .WithMany()
                  .HasForeignKey(e => e.SshSigningProfileId)
                  .OnDelete(DeleteBehavior.Cascade);
            entity.HasOne(e => e.SshCertProfile)
                  .WithMany()
                  .HasForeignKey(e => e.SshCertProfileId)
                  .OnDelete(DeleteBehavior.Cascade);
            entity.HasOne(e => e.SshRequestProfile)
                  .WithMany()
                  .HasForeignKey(e => e.SshRequestProfileId)
                  .OnDelete(DeleteBehavior.SetNull);
        });

        // Certificate compliance findings
        modelBuilder.Entity<CertComplianceFindingEntity>(entity =>
        {
            entity.HasIndex(e => e.CertificateId);
            entity.HasIndex(e => e.IsResolved);
            entity.HasIndex(e => new { e.CertificateId, e.Type, e.IsResolved });
        });

        // Key Ceremony workflows
        modelBuilder.Entity<KeyCeremonyEntity>(entity =>
        {
            entity.HasIndex(e => e.Status);
            entity.HasIndex(e => e.ExpiresAt);
            entity.HasIndex(e => e.InitiatedByUserId);
        });

        // RefreshToken lookup/expiry indexes and
        // HasMaxLength on the opaque-token columns to bring them off longtext and allow a
        // unique index on Token. JWT refresh tokens are base64url; 512 chars is a generous
        // upper bound that accommodates every signing algorithm we allow. CreatedByIp is
        // an IPv4/IPv6 string; 45 covers IPv6 including scope. UserAgentHash is SHA-256 hex.
        modelBuilder.Entity<RefreshTokenEntity>(entity =>
        {
            entity.Property(t => t.Token).HasMaxLength(512);
            entity.Property(t => t.CreatedByIp).HasMaxLength(45);
            entity.Property(t => t.ReplacedByToken).HasMaxLength(512);
            entity.Property(t => t.UserAgentHash).HasMaxLength(64);
            entity.HasIndex(t => t.Token).IsUnique();
            entity.HasIndex(t => t.ExpiresAt);
        });

        // Bring User.PasswordHash / SecurityStamp / name columns
        // off longtext with sensible maxes. Argon2id/BCrypt output is always under 256 bytes;
        // SecurityStamp is a Guid string; FirstName/LastName are display fields.
        modelBuilder.Entity<UserEntity>(entity =>
        {
            entity.Property(u => u.PasswordHash).HasMaxLength(256);
            entity.Property(u => u.SecurityStamp).HasMaxLength(64);
            entity.Property(u => u.FirstName).HasMaxLength(100);
            entity.Property(u => u.LastName).HasMaxLength(100);
            // Soft-delete flag indexed.
            entity.HasIndex(u => u.IsDeleted);
            entity.Property(u => u.IsDeleted).HasDefaultValue(false);
        });

        // Add ExpiresAt indexes on the high-churn ACME tables. Cleanup
        // jobs filter exclusively by ExpiresAt and were full-scanning the tables. Value is
        // ASCII base64url so we also cap it at 64 to keep the unique index compact.
        modelBuilder.Entity<AcmeNonceEntity>(entity =>
        {
            entity.Property(n => n.Value).HasMaxLength(64);
            entity.HasIndex(n => n.ExpiresAt);
        });
        modelBuilder.Entity<AcmeAuthorizationEntity>(entity =>
        {
            entity.HasIndex(a => a.ExpiresAt);
        });
        modelBuilder.Entity<AcmeChallengeEntity>(entity =>
        {
            entity.HasIndex(c => c.ValidatedAt);
        });

        // Concurrency tokens on the high-risk entities that get mutated
        // by multi-step admin workflows. EF maps a `byte[] RowVersion` with IsRowVersion() to
        // MySQL as a TIMESTAMP(6) stamped on every UPDATE, producing optimistic-concurrency
        // semantics without requiring application-level counter maintenance. Controllers
        // that mutate these entities should catch DbUpdateConcurrencyException and return
        // 409 Conflict.
        modelBuilder.Entity<CertificateAuthorityEntity>()
            .Property(e => e.RowVersion)
            .IsRowVersion();
        modelBuilder.Entity<UserEntity>()
            .Property(e => e.RowVersion)
            .IsRowVersion();
        modelBuilder.Entity<CaGroupEntity>()
            .Property(e => e.RowVersion)
            .IsRowVersion();
        modelBuilder.Entity<CertRequestEntity>()
            .Property(e => e.RowVersion)
            .IsRowVersion();
        modelBuilder.Entity<CsrApprovalEntity>()
            .Property(e => e.RowVersion)
            .IsRowVersion();
        modelBuilder.Entity<SigningProfileEntity>()
            .Property(e => e.RowVersion)
            .IsRowVersion();
        modelBuilder.Entity<KeyCeremonyEntity>()
            .Property(e => e.RowVersion)
            .IsRowVersion();

        // Global query filters for tenant isolation +
        // soft-delete. The filter is evaluated against the scoped ITenantContext and,
        // for tenant-scoped entities, against the caller's AccessibleTenantIds set.
        //
        // Bypass rules:
        //   - When ITenantContext is not resolved (background jobs, migrations, anonymous
        //     public routes), HasContext is false and the filter degrades to "allow all
        //     non-deleted rows". That lets OCSP/CRL/ACME and EF migrations continue to read.
        //   - System admins (IsSystemAdmin == true) similarly see all non-deleted rows.
        //   - Cross-tenant admin UIs that need soft-deleted rows call IgnoreQueryFilters()
        //     with an explicit IsSystemAdmin gate.
        //
        // Tenant-scoped entities (TenantEntity, CertificateAuthorityEntity, CertProfileEntity)
        // fence on TenantId; global entities with only IsDeleted (UserEntity) fence only on
        // the soft-delete flag.
        // Tenant filter. The filter references only scalar bools and a concrete
        // HashSet<Guid> — both have dedicated EF Core SQL translators, avoiding the
        // "IReadOnlySet.Contains is not translatable → client-eval → NRE" trap. The
        // bypass bool short-circuits the Contains() path entirely during bootstrap,
        // design-time tooling, background jobs, and for system admins.
        modelBuilder.Entity<TenantEntity>().HasQueryFilter(t =>
            !t.IsDeleted &&
            (TenantFilterBypass || AccessibleTenantIds.Contains(t.Id)));

        modelBuilder.Entity<CertificateAuthorityEntity>().HasQueryFilter(ca =>
            !ca.IsDeleted &&
            (TenantFilterBypass || AccessibleTenantIds.Contains(ca.TenantId)));

        modelBuilder.Entity<CertProfileEntity>().HasQueryFilter(cp =>
            TenantFilterBypass
            || cp.TenantId == null
            || AccessibleTenantIds.Contains(cp.TenantId.Value));

        modelBuilder.Entity<UserEntity>().HasQueryFilter(u => !u.IsDeleted);

        // IP allow-list rules (Whitelists)
        modelBuilder.Entity<WhitelistEntity>(entity =>
        {
            // Unique composite index: at most one rule per (Scope, CA, Protocol)
            // triple. MySQL permits multiple NULL values in a unique index, so
            // system-level scopes (null CA + null Protocol) coexist per Scope.
            entity.HasIndex(w => new { w.Scope, w.CertificateAuthorityId, w.Protocol }).IsUnique();

            // Switched from Cascade to Restrict. Silent CASCADE deletion
            // of per-CA network allow-list rules on CA removal was a silent widening/narrowing
            // of production protocol access. Admins must now explicitly clear whitelist rows
            // before retiring a CA — surfaces the intent in the audit trail.
            entity.HasOne<CertificateAuthorityEntity>()
                  .WithMany()
                  .HasForeignKey(w => w.CertificateAuthorityId)
                  .OnDelete(DeleteBehavior.Restrict);

            // Store the scope enum as a string column for readability + forward compat.
            entity.Property(w => w.Scope)
                  .HasConversion<string>()
                  .HasMaxLength(20);
        });

        // Scheduler leader-election lease table. Primary-key is the
        // well-known name column so the atomic "take the lease" UPDATE predicate can
        // target a single row without any race window.
        modelBuilder.Entity<SchedulerLeaseEntity>(entity =>
        {
            entity.HasKey(e => e.Name);
            entity.Property(e => e.Name).HasMaxLength(100);
            entity.Property(e => e.OwnerInstanceId).HasMaxLength(64);
            entity.HasIndex(e => e.ExpiresAtUtc);
        });

        // Persistent per-job state (last/next run, outcome, duration).
        modelBuilder.Entity<SchedulerJobStateEntity>(entity =>
        {
            entity.HasKey(e => e.JobName);
            entity.Property(e => e.JobName).HasMaxLength(100);
            entity.Property(e => e.LastResult).HasMaxLength(32);
            entity.Property(e => e.LastError).HasMaxLength(2048);
            entity.HasIndex(e => e.NextRunUtc);
        });

        // Notification de-dup log. Unique composite index on
        // (EventType, TargetEntityId, NotificationDate) makes duplicate sends within
        // the same UTC day an atomic DB-level constraint instead of a string hack.
        modelBuilder.Entity<NotificationLogEntity>(entity =>
        {
            entity.HasIndex(e => new { e.EventType, e.TargetEntityId, e.NotificationDate })
                  .IsUnique()
                  .HasDatabaseName("IX_NotificationLogs_EventType_Target_Date");
            entity.Property(e => e.EventType).HasMaxLength(100);
            entity.Property(e => e.TargetEntityId).HasMaxLength(200);
        });

        // SCEP transaction state with unique (CaId, TransactionId)
        // so a duplicate PKCSReq insert raises a DbUpdate exception the service catches and
        // translates to FailInfoBadRequest.
        modelBuilder.Entity<ScepTransactionEntity>(entity =>
        {
            entity.HasIndex(e => new { e.CaId, e.TransactionId }).IsUnique();
            entity.HasIndex(e => e.ExpiresAt);
            entity.HasIndex(e => e.CreatedAt);
        });

        // CMP transaction state. Unique (CaId, TransactionId) rejects
        // replayed ir/cr/kur. SenderNonce/MessageTime indexed for sweep.
        modelBuilder.Entity<CmpTransactionEntity>(entity =>
        {
            entity.HasIndex(e => new { e.CaId, e.TransactionId }).IsUnique();
            entity.HasIndex(e => e.CreatedAt);
        });

        // Index the CMP reference value so senderKID lookups don't
        // full-scan the enrollment token table.
        modelBuilder.Entity<EnrollmentTokenEntity>(entity =>
        {
            entity.HasIndex(e => e.CmpReferenceValue);
        });

    }

    // ===========================================================================================
    // TEMPORARY DIAGNOSTIC (CERT-FK-DIAG): trace the source of CA / signing-profile FK corruption.
    //
    // Background: CertificateAuthorities.CertificateId and SigningProfiles.IssuerId are both
    // OnDelete(SetNull) FKs onto Certificates. Deleting a CA's certificate row therefore silently
    // nulls the CA's cert link AND its signing profile's issuer link, orphaning the CA (no cert, no
    // signing profile resolvable via IssuerId == CertificateId). We could not find the offending
    // delete by static analysis, so this trap logs — with a full stack trace — every mutation that
    // can produce that state, the moment it is about to hit the database. Remove once the culprit
    // is identified.
    // ===========================================================================================

    public override int SaveChanges(bool acceptAllChangesOnSuccess)
    {
        LogCertFkCorruptionDiagnostics();
        return base.SaveChanges(acceptAllChangesOnSuccess);
    }

    public override Task<int> SaveChangesAsync(bool acceptAllChangesOnSuccess, CancellationToken cancellationToken = default)
    {
        LogCertFkCorruptionDiagnostics();
        return base.SaveChangesAsync(acceptAllChangesOnSuccess, cancellationToken);
    }

    /// <summary>
    /// CERT-FK-DIAG: scans the change tracker for the three mutations that corrupt a CA's identity
    /// — (1) a Certificate row being deleted (cascades SET NULL onto any referencing CA / signing
    /// profile), (2) CertificateAuthorities.CertificateId being set to null, (3) SigningProfiles.IssuerId
    /// being set to null — and logs each with the originating stack trace. Wrapped in try/catch so a
    /// diagnostic failure can never break a real persistence operation.
    /// </summary>
    private void LogCertFkCorruptionDiagnostics()
    {
        try
        {
            var logger = this.GetService<ILoggerFactory>()
                ?.CreateLogger("ModularCA.Database.CertFkDiagnostics");
            if (logger == null)
                return;

            foreach (var entry in ChangeTracker.Entries<CertificateEntity>())
            {
                if (entry.State != EntityState.Deleted)
                    continue;
                var c = entry.Entity;
                logger.LogWarning(
                    "[CERT-FK-DIAG] Certificate being DELETED — CertificateId={CertId} Serial={Serial} Subject={Subject} IsCA={IsCA}. " +
                    "This SET NULLs any CertificateAuthorities.CertificateId / SigningProfiles.IssuerId referencing it.\nOrigin stack:\n{Stack}",
                    c.CertificateId, c.SerialNumber, c.SubjectDN, c.IsCA, Environment.StackTrace);
            }

            foreach (var entry in ChangeTracker.Entries<CertificateAuthorityEntity>())
            {
                if (entry.State != EntityState.Modified)
                    continue;
                var prop = entry.Property(nameof(CertificateAuthorityEntity.CertificateId));
                if (prop.IsModified && prop.CurrentValue == null && prop.OriginalValue != null)
                {
                    logger.LogWarning(
                        "[CERT-FK-DIAG] CertificateAuthority.CertificateId being NULLED — CaId={CaId} Name={Name} previousCertId={Old}.\nOrigin stack:\n{Stack}",
                        entry.Entity.Id, entry.Entity.Name, prop.OriginalValue, Environment.StackTrace);
                }
            }

            foreach (var entry in ChangeTracker.Entries<SigningProfileEntity>())
            {
                if (entry.State == EntityState.Deleted)
                {
                    logger.LogWarning(
                        "[CERT-FK-DIAG] SigningProfile being DELETED — ProfileId={Pid} Name={Name} IssuerId={Issuer}.\nOrigin stack:\n{Stack}",
                        entry.Entity.Id, entry.Entity.Name, entry.Entity.IssuerId, Environment.StackTrace);
                    continue;
                }
                if (entry.State != EntityState.Modified)
                    continue;
                var prop = entry.Property(nameof(SigningProfileEntity.IssuerId));
                if (prop.IsModified && prop.CurrentValue == null && prop.OriginalValue != null)
                {
                    logger.LogWarning(
                        "[CERT-FK-DIAG] SigningProfile.IssuerId being NULLED — ProfileId={Pid} Name={Name} previousIssuerId={Old}.\nOrigin stack:\n{Stack}",
                        entry.Entity.Id, entry.Entity.Name, prop.OriginalValue, Environment.StackTrace);
                }
            }
        }
        catch
        {
            // A diagnostic must never break a real save.
        }
    }
}