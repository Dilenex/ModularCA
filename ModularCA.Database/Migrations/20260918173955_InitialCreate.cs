using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AcmeAccounts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    JwkJson = table.Column<string>(type: "text", nullable: false),
                    JwkThumbprint = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    ContactsJson = table.Column<string>(type: "text", nullable: false),
                    Status = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    TermsOfServiceAgreed = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    CaLabel = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AcmeAccounts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AcmeEabKeys",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    KeyId = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    HmacKey = table.Column<string>(type: "text", nullable: false),
                    Description = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    IsUsed = table.Column<bool>(type: "boolean", nullable: false),
                    UsedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    UsedByAccountId = table.Column<Guid>(type: "uuid", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AcmeEabKeys", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AcmeNonces",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Value = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    IssuedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AcmeNonces", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "CertComplianceFindings",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    CertificateId = table.Column<Guid>(type: "uuid", nullable: false),
                    Severity = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    Type = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    Description = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false),
                    DetectedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    IsResolved = table.Column<bool>(type: "boolean", nullable: false),
                    ResolvedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CertComplianceFindings", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "CmpTransactions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    CaId = table.Column<Guid>(type: "uuid", nullable: true),
                    TransactionId = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    SenderNonce = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    ResponseNonce = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    MessageTime = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    Status = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    PbmReferenceValue = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CmpTransactions", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "CtLogs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Url = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false),
                    PublicKeyBase64 = table.Column<string>(type: "text", nullable: false),
                    IsEnabled = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CtLogs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "FeatureFlags",
                columns: table => new
                {
                    Name = table.Column<string>(type: "text", nullable: false),
                    Enabled = table.Column<bool>(type: "boolean", nullable: false),
                    Value = table.Column<string>(type: "text", nullable: true),
                    Description = table.Column<string>(type: "text", nullable: true),
                    RequiresRestart = table.Column<bool>(type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_FeatureFlags", x => x.Name);
                });

            migrationBuilder.CreateTable(
                name: "KeyCeremonies",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    OperationType = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    CeremonyType = table.Column<int>(type: "integer", nullable: true),
                    Description = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false),
                    TargetEntityId = table.Column<string>(type: "text", nullable: false),
                    InitiatedByUserId = table.Column<Guid>(type: "uuid", nullable: false),
                    InitiatedByUsername = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    RequiredApprovals = table.Column<int>(type: "integer", nullable: false),
                    CurrentApprovals = table.Column<int>(type: "integer", nullable: false),
                    Status = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExecutedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    ParametersJson = table.Column<string>(type: "text", nullable: false),
                    ApprovalsJson = table.Column<string>(type: "text", nullable: false),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: true),
                    xmin = table.Column<uint>(type: "xid", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_KeyCeremonies", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Keystores",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    Name = table.Column<string>(type: "text", nullable: false),
                    Passblob = table.Column<byte[]>(type: "bytea", nullable: false),
                    ScryptN = table.Column<int>(type: "integer", nullable: false),
                    ScryptR = table.Column<int>(type: "integer", nullable: false),
                    ScryptP = table.Column<int>(type: "integer", nullable: false),
                    Salt = table.Column<string>(type: "text", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    Enabled = table.Column<bool>(type: "boolean", nullable: false),
                    SigningCaSpkiSha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    SigningCaSpkiSha256Mac = table.Column<byte[]>(type: "bytea", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Keystores", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "LdapPublisherPolicy",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Enabled = table.Column<bool>(type: "boolean", nullable: false),
                    SinceFallbackHours = table.Column<int>(type: "integer", nullable: false),
                    ConnectionTimeoutSeconds = table.Column<int>(type: "integer", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_LdapPublisherPolicy", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "NotificationLogs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    EventType = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    TargetEntityId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    NotificationDate = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_NotificationLogs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "NotificationPreferences",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    EventType = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    Enabled = table.Column<bool>(type: "boolean", nullable: false),
                    Recipients = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    DaysBeforeExpiry = table.Column<int>(type: "integer", nullable: true),
                    Description = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_NotificationPreferences", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "OIDOptions",
                columns: table => new
                {
                    OID = table.Column<string>(type: "text", nullable: false),
                    FriendlyName = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    IsDefaultEntry = table.Column<bool>(type: "boolean", nullable: false),
                    KeyUsage = table.Column<string>(type: "text", nullable: false),
                    AddedOn = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_OIDOptions", x => x.OID);
                });

            migrationBuilder.CreateTable(
                name: "PasswordPolicy",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    MinLength = table.Column<int>(type: "integer", nullable: false),
                    MaxLength = table.Column<int>(type: "integer", nullable: false),
                    RequireUppercase = table.Column<bool>(type: "boolean", nullable: false),
                    RequireLowercase = table.Column<bool>(type: "boolean", nullable: false),
                    RequireDigit = table.Column<bool>(type: "boolean", nullable: false),
                    RequireSymbol = table.Column<bool>(type: "boolean", nullable: false),
                    MinUppercase = table.Column<int>(type: "integer", nullable: false),
                    MinLowercase = table.Column<int>(type: "integer", nullable: false),
                    MinDigits = table.Column<int>(type: "integer", nullable: false),
                    MinSpecial = table.Column<int>(type: "integer", nullable: false),
                    MaxAgeDays = table.Column<int>(type: "integer", nullable: false),
                    HistoryCount = table.Column<int>(type: "integer", nullable: false),
                    DictionaryPath = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    DictionaryIsHashed = table.Column<bool>(type: "boolean", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PasswordPolicy", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ProtocolRateLimits",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Protocol = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    MaxRequests = table.Column<int>(type: "integer", nullable: false),
                    WindowMinutes = table.Column<int>(type: "integer", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ProtocolRateLimits", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "SchedulerJobStates",
                columns: table => new
                {
                    JobName = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    LastRunUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    NextRunUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    LastResult = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true),
                    LastError = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: true),
                    LastDurationMs = table.Column<long>(type: "bigint", nullable: true),
                    ConsecutiveFailureCount = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SchedulerJobStates", x => x.JobName);
                });

            migrationBuilder.CreateTable(
                name: "SchedulerLeases",
                columns: table => new
                {
                    Name = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    OwnerInstanceId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    AcquiredAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SchedulerLeases", x => x.Name);
                });

            migrationBuilder.CreateTable(
                name: "SecurityPolicy",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    MaxFailedLoginAttempts = table.Column<int>(type: "integer", nullable: false),
                    LockoutMinutes = table.Column<int>(type: "integer", nullable: false),
                    SessionIdleTimeoutMinutes = table.Column<int>(type: "integer", nullable: false),
                    MaxConcurrentSessions = table.Column<int>(type: "integer", nullable: false),
                    MaxSessionLifetimeDays = table.Column<int>(type: "integer", nullable: false),
                    LoginResponseDelayMs = table.Column<int>(type: "integer", nullable: false),
                    LoginBanner = table.Column<string>(type: "text", nullable: true),
                    LoginBannerTitle = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    AllowSystemSuperSelfApproval = table.Column<bool>(type: "boolean", nullable: false),
                    RequireMtlsOcspCheck = table.Column<bool>(type: "boolean", nullable: false),
                    StepUpTokenTtlSeconds = table.Column<int>(type: "integer", nullable: false),
                    MfaSessionTtlSeconds = table.Column<int>(type: "integer", nullable: false),
                    WebAuthnChallengeTtlSeconds = table.Column<int>(type: "integer", nullable: false),
                    RequireWebAuthnUserVerification = table.Column<bool>(type: "boolean", nullable: false),
                    StepUpFailureThreshold = table.Column<int>(type: "integer", nullable: false),
                    StepUpFailureWindowSeconds = table.Column<int>(type: "integer", nullable: false),
                    AllowCaDirectSigning = table.Column<bool>(type: "boolean", nullable: false),
                    RequireNoCheckExtension = table.Column<bool>(type: "boolean", nullable: false),
                    RequireSignedRequests = table.Column<bool>(type: "boolean", nullable: false),
                    DefaultGoodResponseTtlMinutes = table.Column<int>(type: "integer", nullable: false),
                    DefaultRevokedResponseTtlMinutes = table.Column<int>(type: "integer", nullable: false),
                    MaxSingleRequestsPerRequest = table.Column<int>(type: "integer", nullable: false),
                    KeystoreScryptN = table.Column<int>(type: "integer", nullable: false),
                    KeystoreScryptR = table.Column<int>(type: "integer", nullable: false),
                    KeystoreScryptP = table.Column<int>(type: "integer", nullable: false),
                    UserQuorum = table.Column<int>(type: "integer", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SecurityPolicy", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "SignerAudit",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    At = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Operation = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Caller = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    Purpose = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    KeyCertificateId = table.Column<Guid>(type: "uuid", nullable: true),
                    Keystore = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    CaId = table.Column<Guid>(type: "uuid", nullable: true),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: true),
                    CeremonyId = table.Column<Guid>(type: "uuid", nullable: true),
                    PeerIdentity = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    Algorithm = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    Outcome = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    Reason = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: true),
                    DataHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SignerAudit", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "SshCertProfiles",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    Description = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    AllowedPrincipalPatterns = table.Column<string>(type: "text", nullable: false),
                    MaxPrincipals = table.Column<int>(type: "integer", nullable: false),
                    AllowedExtensions = table.Column<string>(type: "text", nullable: false),
                    RequiredExtensions = table.Column<string>(type: "text", nullable: false),
                    MaxValidityHours = table.Column<int>(type: "integer", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SshCertProfiles", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "SshRequestProfiles",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    Description = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    AllowedSshSigningProfileIds = table.Column<string>(type: "text", nullable: false),
                    AllowedSshCertProfileIds = table.Column<string>(type: "text", nullable: false),
                    RequireApproval = table.Column<bool>(type: "boolean", nullable: false),
                    MaxValidityHours = table.Column<int>(type: "integer", nullable: false),
                    CertificateAuthorityId = table.Column<Guid>(type: "uuid", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SshRequestProfiles", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Tenants",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    Slug = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    Description = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    IsEnabled = table.Column<bool>(type: "boolean", nullable: false),
                    IsSystemTenant = table.Column<bool>(type: "boolean", nullable: false),
                    CanBeDeleted = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    MaxCertificateAuthorities = table.Column<int>(type: "integer", nullable: false),
                    MaxCertificatesTotal = table.Column<int>(type: "integer", nullable: false),
                    MaxUsers = table.Column<int>(type: "integer", nullable: false),
                    MaxValidityDays = table.Column<int>(type: "integer", nullable: false),
                    ValidityCeilingBehavior = table.Column<int>(type: "integer", nullable: false),
                    RequireKeyCeremony = table.Column<bool>(type: "boolean", nullable: false),
                    CeremonyRequiredApprovals = table.Column<int>(type: "integer", nullable: false),
                    UserCeremonyRequiredApprovals = table.Column<int>(type: "integer", nullable: true),
                    IsDeleted = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    DeletedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Tenants", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "TrustAnchors",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    SubjectDN = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    Issuer = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    SerialNumber = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    Pem = table.Column<string>(type: "text", nullable: false),
                    RawCertificate = table.Column<byte[]>(type: "bytea", nullable: false),
                    NotBefore = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    NotAfter = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Label = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    Description = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    IsEnabled = table.Column<bool>(type: "boolean", nullable: false),
                    ImportedByUserId = table.Column<Guid>(type: "uuid", nullable: true),
                    ImportedByUsername = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    ImportedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Thumbprints = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TrustAnchors", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "UserPreferences",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: false),
                    Key = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    ValueJson = table.Column<string>(type: "text", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UserPreferences", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Users",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Username = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    Email = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    PasswordHash = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    PasswordNeverExpires = table.Column<bool>(type: "boolean", nullable: false),
                    PasswordExpirationDate = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    PasswordChangeOnNextLogon = table.Column<bool>(type: "boolean", nullable: false),
                    DisplayName = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    FirstName = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    LastName = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    IsActive = table.Column<bool>(type: "boolean", nullable: false),
                    IsServiceIdentity = table.Column<bool>(type: "boolean", nullable: false),
                    ServiceScopeTenantId = table.Column<Guid>(type: "uuid", nullable: true),
                    ServiceScopeCaId = table.Column<Guid>(type: "uuid", nullable: true),
                    Description = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    IsLocked = table.Column<bool>(type: "boolean", nullable: false),
                    FailedLoginAttempts = table.Column<int>(type: "integer", nullable: false),
                    LockoutEndUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastLoginAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    SecurityStamp = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    MfaEnrolledAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    IsDeleted = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    DeletedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    xmin = table.Column<uint>(type: "xid", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Users", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AccessBadges",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    Description = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    IsDefault = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    CreatedByUserId = table.Column<Guid>(type: "uuid", nullable: true),
                    UpdatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AccessBadges", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AccessBadges_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "EnrollmentTokens",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Token = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    CreatedByUserId = table.Column<Guid>(type: "uuid", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    MaxUses = table.Column<int>(type: "integer", nullable: false),
                    UsesRemaining = table.Column<int>(type: "integer", nullable: false),
                    SubjectRestriction = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    SANRestriction = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    Protocol = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: true),
                    IsRevoked = table.Column<bool>(type: "boolean", nullable: false),
                    RequestProfileId = table.Column<Guid>(type: "uuid", nullable: true),
                    CertProfileId = table.Column<Guid>(type: "uuid", nullable: true),
                    SigningProfileId = table.Column<Guid>(type: "uuid", nullable: true),
                    CertificateAuthorityId = table.Column<Guid>(type: "uuid", nullable: true),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: true),
                    UsedForCmp = table.Column<bool>(type: "boolean", nullable: false),
                    CmpReferenceValue = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    CmpSecretHashBase64 = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EnrollmentTokens", x => x.Id);
                    table.ForeignKey(
                        name: "FK_EnrollmentTokens_Users_CreatedByUserId",
                        column: x => x.CreatedByUserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Fido2Credentials",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: false),
                    CredentialId = table.Column<byte[]>(type: "bytea", nullable: false),
                    PublicKey = table.Column<byte[]>(type: "bytea", nullable: false),
                    SignCount = table.Column<long>(type: "bigint", nullable: false),
                    DeviceName = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    RegisteredAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastUsedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Fido2Credentials", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Fido2Credentials_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "KerberosRealms",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: false),
                    Realm = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    DnsDomain = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    ServicePrincipal = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    EnrollmentUserId = table.Column<Guid>(type: "uuid", nullable: false),
                    AllowMachines = table.Column<bool>(type: "boolean", nullable: false),
                    AllowUsers = table.Column<bool>(type: "boolean", nullable: false),
                    IsEnabled = table.Column<bool>(type: "boolean", nullable: false),
                    Notes = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastUsedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_KerberosRealms", x => x.Id);
                    table.ForeignKey(
                        name: "FK_KerberosRealms_Tenants_TenantId",
                        column: x => x.TenantId,
                        principalTable: "Tenants",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_KerberosRealms_Users_EnrollmentUserId",
                        column: x => x.EnrollmentUserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "PasswordHistory",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: false),
                    PasswordHash = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false),
                    ChangedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PasswordHistory", x => x.Id);
                    table.ForeignKey(
                        name: "FK_PasswordHistory_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "RefreshTokens",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: false),
                    Token = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    IsRevoked = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedByIp = table.Column<string>(type: "character varying(45)", maxLength: 45, nullable: true),
                    RevokedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    ReplacedByToken = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    FamilyId = table.Column<Guid>(type: "uuid", nullable: true),
                    FamilyCreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    UserAgentHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    CnfJkt = table.Column<string>(type: "text", nullable: true),
                    LastActivityAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    AccessBadgeId = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RefreshTokens", x => x.Id);
                    table.ForeignKey(
                        name: "FK_RefreshTokens_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Roles",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Description = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    IsBuiltIn = table.Column<bool>(type: "boolean", nullable: false),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    CreatedByUserId = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Roles", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Roles_Tenants_TenantId",
                        column: x => x.TenantId,
                        principalTable: "Tenants",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_Roles_Users_CreatedByUserId",
                        column: x => x.CreatedByUserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateTable(
                name: "TotpRecoveryCodes",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: false),
                    CodeHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UsedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TotpRecoveryCodes", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TotpRecoveryCodes_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "TotpSecrets",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: false),
                    EncryptedSecretKey = table.Column<string>(type: "text", nullable: false),
                    DeviceName = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    IsVerified = table.Column<bool>(type: "boolean", nullable: false),
                    RegisteredAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastUsedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    LastUsedTimeStep = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TotpSecrets", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TotpSecrets_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AccessBadgeSources",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    BadgeId = table.Column<Guid>(type: "uuid", nullable: false),
                    Kind = table.Column<int>(type: "integer", nullable: false),
                    SourceId = table.Column<Guid>(type: "uuid", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AccessBadgeSources", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AccessBadgeSources_AccessBadges_BadgeId",
                        column: x => x.BadgeId,
                        principalTable: "AccessBadges",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "KerberosRealmKeys",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    RealmId = table.Column<Guid>(type: "uuid", nullable: false),
                    Kvno = table.Column<int>(type: "integer", nullable: false),
                    EncryptionType = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ProtectedKey = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: false),
                    Source = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    RetireAfter = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_KerberosRealmKeys", x => x.Id);
                    table.ForeignKey(
                        name: "FK_KerberosRealmKeys_KerberosRealms_RealmId",
                        column: x => x.RealmId,
                        principalTable: "KerberosRealms",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "RoleCapabilities",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    RoleId = table.Column<Guid>(type: "uuid", nullable: false),
                    Capability = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    ResourceType = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    ResourceId = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RoleCapabilities", x => x.Id);
                    table.ForeignKey(
                        name: "FK_RoleCapabilities_Roles_RoleId",
                        column: x => x.RoleId,
                        principalTable: "Roles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AcmeAuthorizations",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    OrderId = table.Column<Guid>(type: "uuid", nullable: false),
                    IdentifierType = table.Column<string>(type: "character varying(10)", maxLength: 10, nullable: false),
                    IdentifierValue = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    Status = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    IsWildcard = table.Column<bool>(type: "boolean", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AcmeAuthorizations", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AcmeChallenges",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    AuthorizationId = table.Column<Guid>(type: "uuid", nullable: false),
                    Type = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    Token = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    Status = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    ValidatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    ErrorJson = table.Column<string>(type: "text", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    AttemptCount = table.Column<int>(type: "integer", nullable: false),
                    NextAttemptAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AcmeChallenges", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AcmeChallenges_AcmeAuthorizations_AuthorizationId",
                        column: x => x.AuthorizationId,
                        principalTable: "AcmeAuthorizations",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AcmeOrders",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    AccountId = table.Column<Guid>(type: "uuid", nullable: false),
                    Status = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    IdentifiersJson = table.Column<string>(type: "text", nullable: false),
                    NotBefore = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    NotAfter = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    ExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    CertificateId = table.Column<Guid>(type: "uuid", nullable: true),
                    FinalizedCsrId = table.Column<Guid>(type: "uuid", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    CaLabel = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AcmeOrders", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AcmeOrders_AcmeAccounts_AccountId",
                        column: x => x.AccountId,
                        principalTable: "AcmeAccounts",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AllowedCertProfileSigningProfiles",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    CertProfileId = table.Column<Guid>(type: "uuid", nullable: false),
                    SigningProfileId = table.Column<Guid>(type: "uuid", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AllowedCertProfileSigningProfiles", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "CaGroupMembers",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    GroupId = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: false),
                    AddedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    AddedByUserId = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CaGroupMembers", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CaGroupMembers_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "CaGroups",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    DisplayName = table.Column<string>(type: "character varying(300)", maxLength: 300, nullable: false),
                    CertificateAuthorityId = table.Column<Guid>(type: "uuid", nullable: true),
                    TemplateName = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    IsSystemGroup = table.Column<bool>(type: "boolean", nullable: false),
                    IsSystemTierSuper = table.Column<bool>(type: "boolean", nullable: false),
                    IsAutoGenerated = table.Column<bool>(type: "boolean", nullable: false),
                    RequiredQuorum = table.Column<int>(type: "integer", nullable: false),
                    MaxCertificates = table.Column<int>(type: "integer", nullable: false),
                    MaxPendingRequests = table.Column<int>(type: "integer", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: false),
                    MtlsSigningCaId = table.Column<Guid>(type: "uuid", nullable: true),
                    xmin = table.Column<uint>(type: "xid", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CaGroups", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "CapabilityGrants",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    GroupId = table.Column<Guid>(type: "uuid", nullable: false),
                    Capability = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    ResourceType = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    ResourceId = table.Column<Guid>(type: "uuid", nullable: true),
                    GrantedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    GrantedByUserId = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CapabilityGrants", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CapabilityGrants_CaGroups_GroupId",
                        column: x => x.GroupId,
                        principalTable: "CaGroups",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_CapabilityGrants_Users_GrantedByUserId",
                        column: x => x.GrantedByUserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateTable(
                name: "CaProtocolConfigs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    CaId = table.Column<Guid>(type: "uuid", nullable: false),
                    Protocol = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    IsEnabled = table.Column<bool>(type: "boolean", nullable: false),
                    IsPublicVisible = table.Column<bool>(type: "boolean", nullable: false),
                    SigningProfileId = table.Column<Guid>(type: "uuid", nullable: true),
                    CertProfileId = table.Column<Guid>(type: "uuid", nullable: true),
                    EstRequireClientCert = table.Column<bool>(type: "boolean", nullable: false),
                    EstHttpAuthEnabled = table.Column<bool>(type: "boolean", nullable: false),
                    ScepChallengeRequired = table.Column<bool>(type: "boolean", nullable: false),
                    CmpRequireSignature = table.Column<bool>(type: "boolean", nullable: false),
                    AcmeRequireEab = table.Column<bool>(type: "boolean", nullable: false),
                    AcmeAllowedChallengeTypes = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    AcmeAllowPrivateAddressValidation = table.Column<bool>(type: "boolean", nullable: false),
                    OcspSignResponses = table.Column<bool>(type: "boolean", nullable: false),
                    RequestProfileId = table.Column<Guid>(type: "uuid", nullable: true),
                    MsaeAllowUsernameToken = table.Column<bool>(type: "boolean", nullable: false),
                    MsaeAllowKerberos = table.Column<bool>(type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CaProtocolConfigs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "CaServiceUrls",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    CaCertificateId = table.Column<Guid>(type: "uuid", nullable: false),
                    PublicBaseUrl = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CaServiceUrls", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "CertificateAccess",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    CertificateId = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: false),
                    AccessLevel = table.Column<int>(type: "integer", nullable: false),
                    GrantedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    GrantedByUserId = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CertificateAccess", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CertificateAccess_Users_GrantedByUserId",
                        column: x => x.GrantedByUserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_CertificateAccess_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "CertificateAuthorities",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    CertificateId = table.Column<Guid>(type: "uuid", nullable: true),
                    Name = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    Label = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    IsDefault = table.Column<bool>(type: "boolean", nullable: false),
                    Type = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    IsEnabled = table.Column<bool>(type: "boolean", nullable: false),
                    ParentCaId = table.Column<Guid>(type: "uuid", nullable: true),
                    OcspResponderCertificateId = table.Column<Guid>(type: "uuid", nullable: true),
                    OcspResponseTtlGoodMinutes = table.Column<int>(type: "integer", nullable: true),
                    OcspResponseTtlRevokedMinutes = table.Column<int>(type: "integer", nullable: true),
                    TsaCertificateId = table.Column<Guid>(type: "uuid", nullable: true),
                    CmpSigningCertificateId = table.Column<Guid>(type: "uuid", nullable: true),
                    KeyStorageType = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    HsmKeyLabel = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    IsSshCa = table.Column<bool>(type: "boolean", nullable: false),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: false),
                    UserCeremonyRequiredApprovals = table.Column<int>(type: "integer", nullable: true),
                    IsDeleted = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    DeletedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    xmin = table.Column<uint>(type: "xid", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CertificateAuthorities", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CertificateAuthorities_CertificateAuthorities_ParentCaId",
                        column: x => x.ParentCaId,
                        principalTable: "CertificateAuthorities",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_CertificateAuthorities_Tenants_TenantId",
                        column: x => x.TenantId,
                        principalTable: "Tenants",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "CertProfiles",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    Description = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    IsCaProfile = table.Column<bool>(type: "boolean", nullable: false),
                    KeyUsages = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    ExtendedKeyUsages = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    ValidityPeriodMin = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    ValidityPeriodMax = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    AllowedKeyAlgorithms = table.Column<string>(type: "text", nullable: false),
                    AllowedKeySizes = table.Column<string>(type: "text", nullable: false),
                    AllowedSignatureAlgorithms = table.Column<string>(type: "text", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Revision = table.Column<int>(type: "integer", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    CanBeDeleted = table.Column<bool>(type: "boolean", nullable: false),
                    ProfileHash = table.Column<string>(type: "text", nullable: false),
                    CtEnabled = table.Column<bool>(type: "boolean", nullable: false),
                    AllowWildcard = table.Column<bool>(type: "boolean", nullable: false),
                    CtLogIds = table.Column<string>(type: "text", nullable: true),
                    CertificateAuthorityId = table.Column<Guid>(type: "uuid", nullable: true),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: true),
                    InheritsFromId = table.Column<Guid>(type: "uuid", nullable: true),
                    InheritanceEnabled = table.Column<bool>(type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CertProfiles", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CertProfiles_CertProfiles_InheritsFromId",
                        column: x => x.InheritsFromId,
                        principalTable: "CertProfiles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_CertProfiles_CertificateAuthorities_CertificateAuthorityId",
                        column: x => x.CertificateAuthorityId,
                        principalTable: "CertificateAuthorities",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateTable(
                name: "LdapConfigurations",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "text", nullable: false),
                    Enabled = table.Column<bool>(type: "boolean", nullable: false),
                    Description = table.Column<string>(type: "text", nullable: true),
                    Host = table.Column<string>(type: "text", nullable: false),
                    Port = table.Column<int>(type: "integer", nullable: false),
                    UseSsl = table.Column<bool>(type: "boolean", nullable: false),
                    Username = table.Column<string>(type: "text", nullable: false),
                    Password = table.Column<string>(type: "text", nullable: false),
                    BaseDn = table.Column<string>(type: "text", nullable: false),
                    CertificateAuthorityId = table.Column<Guid>(type: "uuid", nullable: false),
                    PublishCACert = table.Column<bool>(type: "boolean", nullable: false),
                    PublishCRL = table.Column<bool>(type: "boolean", nullable: false),
                    PublishDelta = table.Column<bool>(type: "boolean", nullable: false),
                    PublishUserCerts = table.Column<bool>(type: "boolean", nullable: false),
                    UserDnTemplate = table.Column<string>(type: "text", nullable: true),
                    UpdateInterval = table.Column<string>(type: "text", nullable: false),
                    LastUpdatedUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    NextUpdateUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_LdapConfigurations", x => x.Id);
                    table.ForeignKey(
                        name: "FK_LdapConfigurations_CertificateAuthorities_CertificateAuthor~",
                        column: x => x.CertificateAuthorityId,
                        principalTable: "CertificateAuthorities",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "RoleAssignments",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    RoleId = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: true),
                    GroupId = table.Column<Guid>(type: "uuid", nullable: true),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: true),
                    CertificateAuthorityId = table.Column<Guid>(type: "uuid", nullable: true),
                    AssignedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    AssignedByUserId = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RoleAssignments", x => x.Id);
                    table.ForeignKey(
                        name: "FK_RoleAssignments_CaGroups_GroupId",
                        column: x => x.GroupId,
                        principalTable: "CaGroups",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_RoleAssignments_CertificateAuthorities_CertificateAuthority~",
                        column: x => x.CertificateAuthorityId,
                        principalTable: "CertificateAuthorities",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_RoleAssignments_Roles_RoleId",
                        column: x => x.RoleId,
                        principalTable: "Roles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_RoleAssignments_Tenants_TenantId",
                        column: x => x.TenantId,
                        principalTable: "Tenants",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_RoleAssignments_Users_AssignedByUserId",
                        column: x => x.AssignedByUserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_RoleAssignments_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "SshCaKeys",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    KeyType = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    KeySize = table.Column<int>(type: "integer", nullable: true),
                    PublicKey = table.Column<string>(type: "text", nullable: false),
                    PrivateKeyPath = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false),
                    CertificateAuthorityId = table.Column<Guid>(type: "uuid", nullable: false),
                    IsUserCa = table.Column<bool>(type: "boolean", nullable: false),
                    IsHostCa = table.Column<bool>(type: "boolean", nullable: false),
                    MaxValidityHours = table.Column<int>(type: "integer", nullable: false),
                    IsEnabled = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SshCaKeys", x => x.Id);
                    table.ForeignKey(
                        name: "FK_SshCaKeys_CertificateAuthorities_CertificateAuthorityId",
                        column: x => x.CertificateAuthorityId,
                        principalTable: "CertificateAuthorities",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "UserCapabilityGrants",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: false),
                    Capability = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: true),
                    CertificateAuthorityId = table.Column<Guid>(type: "uuid", nullable: true),
                    ResourceType = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    ResourceId = table.Column<Guid>(type: "uuid", nullable: true),
                    GrantedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    GrantedByUserId = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UserCapabilityGrants", x => x.Id);
                    table.ForeignKey(
                        name: "FK_UserCapabilityGrants_CertificateAuthorities_CertificateAuth~",
                        column: x => x.CertificateAuthorityId,
                        principalTable: "CertificateAuthorities",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_UserCapabilityGrants_Tenants_TenantId",
                        column: x => x.TenantId,
                        principalTable: "Tenants",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_UserCapabilityGrants_Users_GrantedByUserId",
                        column: x => x.GrantedByUserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_UserCapabilityGrants_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Whitelists",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    Description = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    Scope = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    CertificateAuthorityId = table.Column<Guid>(type: "uuid", nullable: true),
                    Protocol = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: true),
                    Cidrs = table.Column<string>(type: "text", nullable: false),
                    IsEnabled = table.Column<bool>(type: "boolean", nullable: false),
                    IsSystemDefault = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Whitelists", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Whitelists_CertificateAuthorities_CertificateAuthorityId",
                        column: x => x.CertificateAuthorityId,
                        principalTable: "CertificateAuthorities",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "RequestProfiles",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    Description = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    SubjectDnRules = table.Column<string>(type: "text", nullable: false),
                    SanRules = table.Column<string>(type: "text", nullable: false),
                    AllowedCertProfileIds = table.Column<string>(type: "text", nullable: false),
                    DefaultCertProfileId = table.Column<Guid>(type: "uuid", nullable: true),
                    RequireApproval = table.Column<bool>(type: "boolean", nullable: false),
                    RequiredApprovalCount = table.Column<int>(type: "integer", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    CertificateAuthorityId = table.Column<Guid>(type: "uuid", nullable: true),
                    InheritsFromId = table.Column<Guid>(type: "uuid", nullable: true),
                    InheritanceEnabled = table.Column<bool>(type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RequestProfiles", x => x.Id);
                    table.ForeignKey(
                        name: "FK_RequestProfiles_CertProfiles_DefaultCertProfileId",
                        column: x => x.DefaultCertProfileId,
                        principalTable: "CertProfiles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_RequestProfiles_CertificateAuthorities_CertificateAuthority~",
                        column: x => x.CertificateAuthorityId,
                        principalTable: "CertificateAuthorities",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_RequestProfiles_RequestProfiles_InheritsFromId",
                        column: x => x.InheritsFromId,
                        principalTable: "RequestProfiles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateTable(
                name: "SshCertificates",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    SshCaKeyId = table.Column<Guid>(type: "uuid", nullable: false),
                    CertificateType = table.Column<string>(type: "character varying(10)", maxLength: 10, nullable: false),
                    KeyId = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    SerialNumber = table.Column<long>(type: "bigint", nullable: false),
                    Principals = table.Column<string>(type: "text", nullable: false),
                    ValidAfter = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ValidBefore = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    PublicKey = table.Column<string>(type: "text", nullable: false),
                    SignedCertificate = table.Column<string>(type: "text", nullable: false),
                    Extensions = table.Column<string>(type: "text", nullable: true),
                    IsRevoked = table.Column<bool>(type: "boolean", nullable: false),
                    IssuedByUserId = table.Column<Guid>(type: "uuid", nullable: true),
                    SourceIp = table.Column<string>(type: "character varying(45)", maxLength: 45, nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SshCertificates", x => x.Id);
                    table.ForeignKey(
                        name: "FK_SshCertificates_SshCaKeys_SshCaKeyId",
                        column: x => x.SshCaKeyId,
                        principalTable: "SshCaKeys",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "SshSigningProfiles",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    Description = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    SshCaKeyId = table.Column<Guid>(type: "uuid", nullable: true),
                    MaxValidityHours = table.Column<int>(type: "integer", nullable: false),
                    AllowUserCerts = table.Column<bool>(type: "boolean", nullable: false),
                    AllowHostCerts = table.Column<bool>(type: "boolean", nullable: false),
                    ForceCommand = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    SourceAddressRestrictions = table.Column<string>(type: "text", nullable: false),
                    DefaultExtensions = table.Column<string>(type: "text", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SshSigningProfiles", x => x.Id);
                    table.ForeignKey(
                        name: "FK_SshSigningProfiles_SshCaKeys_SshCaKeyId",
                        column: x => x.SshCaKeyId,
                        principalTable: "SshCaKeys",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateTable(
                name: "SshCertificateTemplates",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    Description = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    SshCaKeyId = table.Column<Guid>(type: "uuid", nullable: false),
                    SshSigningProfileId = table.Column<Guid>(type: "uuid", nullable: false),
                    SshCertProfileId = table.Column<Guid>(type: "uuid", nullable: false),
                    SshRequestProfileId = table.Column<Guid>(type: "uuid", nullable: true),
                    IsEnabled = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SshCertificateTemplates", x => x.Id);
                    table.ForeignKey(
                        name: "FK_SshCertificateTemplates_SshCaKeys_SshCaKeyId",
                        column: x => x.SshCaKeyId,
                        principalTable: "SshCaKeys",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_SshCertificateTemplates_SshCertProfiles_SshCertProfileId",
                        column: x => x.SshCertProfileId,
                        principalTable: "SshCertProfiles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_SshCertificateTemplates_SshRequestProfiles_SshRequestProfil~",
                        column: x => x.SshRequestProfileId,
                        principalTable: "SshRequestProfiles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_SshCertificateTemplates_SshSigningProfiles_SshSigningProfil~",
                        column: x => x.SshSigningProfileId,
                        principalTable: "SshSigningProfiles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "CertificateRequests",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    CSR = table.Column<string>(type: "text", nullable: false),
                    Subject = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: false),
                    SubjectAlternativeNames = table.Column<string>(type: "text", nullable: true),
                    SubmittedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Status = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    KeyAlgorithm = table.Column<string>(type: "text", nullable: false),
                    KeySize = table.Column<string>(type: "text", nullable: false),
                    SignatureAlgorithm = table.Column<string>(type: "text", nullable: false),
                    EncryptedPrivateKey = table.Column<byte[]>(type: "bytea", nullable: true),
                    AesKeyEncryptionIv = table.Column<byte[]>(type: "bytea", nullable: true),
                    EncryptedAesForPrivateKey = table.Column<byte[]>(type: "bytea", nullable: true),
                    EncryptionCertSerialNumber = table.Column<string>(type: "text", nullable: true),
                    CertProfileId = table.Column<Guid>(type: "uuid", nullable: true),
                    SigningProfileId = table.Column<Guid>(type: "uuid", nullable: true),
                    RejectionReason = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    IssuedCertificateId = table.Column<Guid>(type: "uuid", nullable: true),
                    RequestorUserId = table.Column<Guid>(type: "uuid", nullable: true),
                    ApprovalCount = table.Column<int>(type: "integer", nullable: false),
                    RenewalOfCertificateId = table.Column<Guid>(type: "uuid", nullable: true),
                    IsInfrastructureCert = table.Column<bool>(type: "boolean", nullable: false),
                    SubjectOverrides = table.Column<string>(type: "text", nullable: true),
                    SanOverrides = table.Column<string>(type: "text", nullable: true),
                    AdditionalExtensions = table.Column<string>(type: "text", nullable: true),
                    RequestedNotBefore = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    RequestedNotAfter = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    HeldPrivateKey = table.Column<byte[]>(type: "bytea", nullable: true),
                    HeldPrivateKeyAlgorithm = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    HeldKeyDeliveredAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    xmin = table.Column<uint>(type: "xid", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CertificateRequests", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CertificateRequests_CertProfiles_CertProfileId",
                        column: x => x.CertProfileId,
                        principalTable: "CertProfiles",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_CertificateRequests_Users_RequestorUserId",
                        column: x => x.RequestorUserId,
                        principalTable: "Users",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "CsrApprovals",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    CertRequestId = table.Column<Guid>(type: "uuid", nullable: false),
                    ApproverId = table.Column<Guid>(type: "uuid", nullable: false),
                    ApproverUsername = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    Decision = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    Comment = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    Timestamp = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    xmin = table.Column<uint>(type: "xid", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CsrApprovals", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CsrApprovals_CertificateRequests_CertRequestId",
                        column: x => x.CertRequestId,
                        principalTable: "CertificateRequests",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_CsrApprovals_Users_ApproverId",
                        column: x => x.ApproverId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "ScepTransactions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    CaId = table.Column<Guid>(type: "uuid", nullable: true),
                    TransactionId = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    Subject = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    RequesterPublicKeyHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    IssuedCertificateId = table.Column<Guid>(type: "uuid", nullable: true),
                    CertRequestId = table.Column<Guid>(type: "uuid", nullable: true),
                    Status = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ScepTransactions", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ScepTransactions_CertificateRequests_CertRequestId",
                        column: x => x.CertRequestId,
                        principalTable: "CertificateRequests",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateTable(
                name: "Certificates",
                columns: table => new
                {
                    CertificateId = table.Column<Guid>(type: "uuid", nullable: false),
                    SerialNumber = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Pem = table.Column<string>(type: "text", nullable: false),
                    SubjectDN = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: false),
                    Issuer = table.Column<string>(type: "text", nullable: false),
                    SubjectAlternativeNamesJson = table.Column<string>(type: "text", nullable: false),
                    KeyUsagesJson = table.Column<string>(type: "text", nullable: false),
                    ExtendedKeyUsagesJson = table.Column<string>(type: "text", nullable: false),
                    EncryptedPrivateKey = table.Column<byte[]>(type: "bytea", nullable: true),
                    EncryptionCertSerialNumber = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    NotBefore = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    NotAfter = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Thumbprints = table.Column<string>(type: "text", nullable: true),
                    IsCA = table.Column<bool>(type: "boolean", nullable: false),
                    IsReissued = table.Column<bool>(type: "boolean", nullable: false),
                    Revoked = table.Column<bool>(type: "boolean", nullable: false),
                    RevocationReason = table.Column<string>(type: "text", nullable: true),
                    RevocationDate = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    InvalidityDate = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    IssuerCertificateId = table.Column<Guid>(type: "uuid", nullable: true),
                    RawCertificate = table.Column<byte[]>(type: "bytea", nullable: true),
                    SctJson = table.Column<string>(type: "text", nullable: true),
                    SigningProfileId = table.Column<Guid>(type: "uuid", nullable: true),
                    CertProfileId = table.Column<Guid>(type: "uuid", nullable: true),
                    AesKeyEncryptionIv = table.Column<byte[]>(type: "bytea", nullable: true),
                    EncryptedAesForPrivateKey = table.Column<byte[]>(type: "bytea", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Certificates", x => x.CertificateId);
                    table.ForeignKey(
                        name: "FK_Certificates_CertProfiles_CertProfileId",
                        column: x => x.CertProfileId,
                        principalTable: "CertProfiles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateTable(
                name: "CertificateTags",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    CertificateId = table.Column<Guid>(type: "uuid", nullable: false),
                    Key = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    Value = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CertificateTags", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CertificateTags_Certificates_CertificateId",
                        column: x => x.CertificateId,
                        principalTable: "Certificates",
                        principalColumn: "CertificateId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "CrlConfigurations",
                columns: table => new
                {
                    TaskId = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    Enabled = table.Column<bool>(type: "boolean", nullable: false),
                    IssuerDN = table.Column<string>(type: "text", nullable: true),
                    CaCertificateId = table.Column<Guid>(type: "uuid", nullable: false),
                    IsDelta = table.Column<bool>(type: "boolean", nullable: false),
                    Description = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    UpdateInterval = table.Column<string>(type: "text", nullable: false),
                    LastUpdatedUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    NextUpdateUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    OverlapPeriod = table.Column<TimeSpan>(type: "interval", nullable: false),
                    DeltaInterval = table.Column<string>(type: "text", nullable: false),
                    LastGenerated = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastCrlNumber = table.Column<long>(type: "bigint", nullable: false),
                    OnlyContainsUserCerts = table.Column<bool>(type: "boolean", nullable: false),
                    OnlyContainsCACerts = table.Column<bool>(type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CrlConfigurations", x => x.TaskId);
                    table.ForeignKey(
                        name: "FK_CrlConfigurations_Certificates_CaCertificateId",
                        column: x => x.CaCertificateId,
                        principalTable: "Certificates",
                        principalColumn: "CertificateId",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "MtlsCredentials",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: false),
                    CertificateId = table.Column<Guid>(type: "uuid", nullable: true),
                    SigningCaId = table.Column<Guid>(type: "uuid", nullable: false),
                    Thumbprint = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    SerialNumber = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    DeviceName = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    IssuedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    IsRevoked = table.Column<bool>(type: "boolean", nullable: false),
                    RevokedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MtlsCredentials", x => x.Id);
                    table.ForeignKey(
                        name: "FK_MtlsCredentials_CertificateAuthorities_SigningCaId",
                        column: x => x.SigningCaId,
                        principalTable: "CertificateAuthorities",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_MtlsCredentials_Certificates_CertificateId",
                        column: x => x.CertificateId,
                        principalTable: "Certificates",
                        principalColumn: "CertificateId",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_MtlsCredentials_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "SigningProfiles",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    Description = table.Column<string>(type: "text", nullable: false),
                    MaxPathLength = table.Column<int>(type: "integer", nullable: true),
                    AllowedAlgorithms = table.Column<string>(type: "text", nullable: false),
                    AllowedEKUs = table.Column<string>(type: "text", nullable: false),
                    IsDefault = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Revision = table.Column<int>(type: "integer", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    IssuerId = table.Column<Guid>(type: "uuid", nullable: true),
                    NameConstraintsPermitted = table.Column<string>(type: "text", nullable: true),
                    NameConstraintsExcluded = table.Column<string>(type: "text", nullable: true),
                    PolicyOids = table.Column<string>(type: "text", nullable: true),
                    PolicyQualifiersJson = table.Column<string>(type: "text", nullable: true),
                    ExtendedKeyUsageCritical = table.Column<bool>(type: "boolean", nullable: false),
                    InhibitAnyPolicy = table.Column<bool>(type: "boolean", nullable: false),
                    InheritsFromId = table.Column<Guid>(type: "uuid", nullable: true),
                    InheritanceEnabled = table.Column<bool>(type: "boolean", nullable: false),
                    xmin = table.Column<uint>(type: "xid", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SigningProfiles", x => x.Id);
                    table.ForeignKey(
                        name: "FK_SigningProfiles_Certificates_IssuerId",
                        column: x => x.IssuerId,
                        principalTable: "Certificates",
                        principalColumn: "CertificateId",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_SigningProfiles_SigningProfiles_InheritsFromId",
                        column: x => x.InheritsFromId,
                        principalTable: "SigningProfiles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateTable(
                name: "TenantHostnames",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: false),
                    Hostname = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    IssuingCaId = table.Column<Guid>(type: "uuid", nullable: false),
                    CertificateId = table.Column<Guid>(type: "uuid", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Notes = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true),
                    NodeUpstream = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TenantHostnames", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TenantHostnames_CertificateAuthorities_IssuingCaId",
                        column: x => x.IssuingCaId,
                        principalTable: "CertificateAuthorities",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_TenantHostnames_Certificates_CertificateId",
                        column: x => x.CertificateId,
                        principalTable: "Certificates",
                        principalColumn: "CertificateId",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_TenantHostnames_Tenants_TenantId",
                        column: x => x.TenantId,
                        principalTable: "Tenants",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Crls",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    IssuerName = table.Column<string>(type: "text", nullable: false),
                    GeneratedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    CrlNumber = table.Column<long>(type: "bigint", nullable: false),
                    IsDelta = table.Column<bool>(type: "boolean", nullable: false),
                    PemData = table.Column<string>(type: "text", nullable: true),
                    RawData = table.Column<byte[]>(type: "bytea", nullable: false),
                    BaseCrlNumber = table.Column<long>(type: "bigint", nullable: true),
                    TaskId = table.Column<Guid>(type: "uuid", nullable: false),
                    ThisUpdate = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    NextUpdate = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Crls", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Crls_CrlConfigurations_TaskId",
                        column: x => x.TaskId,
                        principalTable: "CrlConfigurations",
                        principalColumn: "TaskId",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "CertificateTemplates",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    Description = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    CaId = table.Column<Guid>(type: "uuid", nullable: false),
                    RequestProfileId = table.Column<Guid>(type: "uuid", nullable: true),
                    CertProfileId = table.Column<Guid>(type: "uuid", nullable: false),
                    SigningProfileId = table.Column<Guid>(type: "uuid", nullable: false),
                    IsEnabled = table.Column<bool>(type: "boolean", nullable: false),
                    MsaeTemplateOid = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    MsaeMajorVersion = table.Column<int>(type: "integer", nullable: false),
                    MsaeMinorVersion = table.Column<int>(type: "integer", nullable: false),
                    MsaeMachineType = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CertificateTemplates", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CertificateTemplates_CertProfiles_CertProfileId",
                        column: x => x.CertProfileId,
                        principalTable: "CertProfiles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_CertificateTemplates_CertificateAuthorities_CaId",
                        column: x => x.CaId,
                        principalTable: "CertificateAuthorities",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_CertificateTemplates_RequestProfiles_RequestProfileId",
                        column: x => x.RequestProfileId,
                        principalTable: "RequestProfiles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_CertificateTemplates_SigningProfiles_SigningProfileId",
                        column: x => x.SigningProfileId,
                        principalTable: "SigningProfiles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AccessBadges_UserId_Name",
                table: "AccessBadges",
                columns: new[] { "UserId", "Name" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AccessBadgeSources_BadgeId_Kind_SourceId",
                table: "AccessBadgeSources",
                columns: new[] { "BadgeId", "Kind", "SourceId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AcmeAccounts_JwkThumbprint",
                table: "AcmeAccounts",
                column: "JwkThumbprint",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AcmeAuthorizations_ExpiresAt",
                table: "AcmeAuthorizations",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_AcmeAuthorizations_OrderId",
                table: "AcmeAuthorizations",
                column: "OrderId");

            migrationBuilder.CreateIndex(
                name: "IX_AcmeChallenges_AuthorizationId",
                table: "AcmeChallenges",
                column: "AuthorizationId");

            migrationBuilder.CreateIndex(
                name: "IX_AcmeChallenges_Token",
                table: "AcmeChallenges",
                column: "Token");

            migrationBuilder.CreateIndex(
                name: "IX_AcmeChallenges_ValidatedAt",
                table: "AcmeChallenges",
                column: "ValidatedAt");

            migrationBuilder.CreateIndex(
                name: "IX_AcmeEabKeys_KeyId",
                table: "AcmeEabKeys",
                column: "KeyId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AcmeNonces_ExpiresAt",
                table: "AcmeNonces",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_AcmeNonces_Value",
                table: "AcmeNonces",
                column: "Value",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AcmeOrders_AccountId",
                table: "AcmeOrders",
                column: "AccountId");

            migrationBuilder.CreateIndex(
                name: "IX_AcmeOrders_CertificateId",
                table: "AcmeOrders",
                column: "CertificateId");

            migrationBuilder.CreateIndex(
                name: "IX_AcmeOrders_ExpiresAt",
                table: "AcmeOrders",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_AcmeOrders_FinalizedCsrId",
                table: "AcmeOrders",
                column: "FinalizedCsrId");

            migrationBuilder.CreateIndex(
                name: "IX_AllowedCertProfileSigningProfiles_CertProfileId_SigningProf~",
                table: "AllowedCertProfileSigningProfiles",
                columns: new[] { "CertProfileId", "SigningProfileId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AllowedCertProfileSigningProfiles_SigningProfileId",
                table: "AllowedCertProfileSigningProfiles",
                column: "SigningProfileId");

            migrationBuilder.CreateIndex(
                name: "IX_CaGroupMembers_GroupId_UserId",
                table: "CaGroupMembers",
                columns: new[] { "GroupId", "UserId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CaGroupMembers_UserId",
                table: "CaGroupMembers",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_CaGroups_CertificateAuthorityId",
                table: "CaGroups",
                column: "CertificateAuthorityId");

            migrationBuilder.CreateIndex(
                name: "IX_CaGroups_MtlsSigningCaId",
                table: "CaGroups",
                column: "MtlsSigningCaId");

            migrationBuilder.CreateIndex(
                name: "IX_CaGroups_Name",
                table: "CaGroups",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CaGroups_TenantId",
                table: "CaGroups",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_CapabilityGrants_GrantedByUserId",
                table: "CapabilityGrants",
                column: "GrantedByUserId");

            migrationBuilder.CreateIndex(
                name: "IX_CapabilityGrants_GroupId_Capability",
                table: "CapabilityGrants",
                columns: new[] { "GroupId", "Capability" });

            migrationBuilder.CreateIndex(
                name: "IX_CapabilityGrants_ResourceType_ResourceId",
                table: "CapabilityGrants",
                columns: new[] { "ResourceType", "ResourceId" });

            migrationBuilder.CreateIndex(
                name: "IX_CaProtocolConfigs_CaId_Protocol",
                table: "CaProtocolConfigs",
                columns: new[] { "CaId", "Protocol" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CaProtocolConfigs_CertProfileId",
                table: "CaProtocolConfigs",
                column: "CertProfileId");

            migrationBuilder.CreateIndex(
                name: "IX_CaProtocolConfigs_RequestProfileId",
                table: "CaProtocolConfigs",
                column: "RequestProfileId");

            migrationBuilder.CreateIndex(
                name: "IX_CaProtocolConfigs_SigningProfileId",
                table: "CaProtocolConfigs",
                column: "SigningProfileId");

            migrationBuilder.CreateIndex(
                name: "IX_CaServiceUrls_CaCertificateId",
                table: "CaServiceUrls",
                column: "CaCertificateId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CertComplianceFindings_CertificateId",
                table: "CertComplianceFindings",
                column: "CertificateId");

            migrationBuilder.CreateIndex(
                name: "IX_CertComplianceFindings_CertificateId_Type_IsResolved",
                table: "CertComplianceFindings",
                columns: new[] { "CertificateId", "Type", "IsResolved" });

            migrationBuilder.CreateIndex(
                name: "IX_CertComplianceFindings_IsResolved",
                table: "CertComplianceFindings",
                column: "IsResolved");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateAccess_CertificateId",
                table: "CertificateAccess",
                column: "CertificateId");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateAccess_GrantedByUserId",
                table: "CertificateAccess",
                column: "GrantedByUserId");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateAccess_UserId_CertificateId",
                table: "CertificateAccess",
                columns: new[] { "UserId", "CertificateId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CertificateAuthorities_CertificateId",
                table: "CertificateAuthorities",
                column: "CertificateId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CertificateAuthorities_IsDeleted",
                table: "CertificateAuthorities",
                column: "IsDeleted");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateAuthorities_ParentCaId",
                table: "CertificateAuthorities",
                column: "ParentCaId");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateAuthorities_TenantId_Label",
                table: "CertificateAuthorities",
                columns: new[] { "TenantId", "Label" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CertificateAuthorities_TenantId_Name",
                table: "CertificateAuthorities",
                columns: new[] { "TenantId", "Name" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CertificateRequests_CertProfileId",
                table: "CertificateRequests",
                column: "CertProfileId");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateRequests_IssuedCertificateId",
                table: "CertificateRequests",
                column: "IssuedCertificateId");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateRequests_RequestorUserId",
                table: "CertificateRequests",
                column: "RequestorUserId");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateRequests_SigningProfileId",
                table: "CertificateRequests",
                column: "SigningProfileId");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateRequests_SubmittedAt",
                table: "CertificateRequests",
                column: "SubmittedAt");

            migrationBuilder.CreateIndex(
                name: "IX_Certificates_CertProfileId",
                table: "Certificates",
                column: "CertProfileId");

            migrationBuilder.CreateIndex(
                name: "IX_Certificates_IssuerCertificateId",
                table: "Certificates",
                column: "IssuerCertificateId");

            migrationBuilder.CreateIndex(
                name: "IX_Certificates_IssuerCertificateId_SerialNumber",
                table: "Certificates",
                columns: new[] { "IssuerCertificateId", "SerialNumber" });

            migrationBuilder.CreateIndex(
                name: "IX_Certificates_SerialNumber_Issuer",
                table: "Certificates",
                columns: new[] { "SerialNumber", "Issuer" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Certificates_SigningProfileId",
                table: "Certificates",
                column: "SigningProfileId");

            migrationBuilder.CreateIndex(
                name: "IX_Certificates_SubjectDN",
                table: "Certificates",
                column: "SubjectDN");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateTags_CertificateId",
                table: "CertificateTags",
                column: "CertificateId");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateTags_CertificateId_Key",
                table: "CertificateTags",
                columns: new[] { "CertificateId", "Key" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CertificateTemplates_CaId",
                table: "CertificateTemplates",
                column: "CaId");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateTemplates_CertProfileId",
                table: "CertificateTemplates",
                column: "CertProfileId");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateTemplates_MsaeTemplateOid",
                table: "CertificateTemplates",
                column: "MsaeTemplateOid",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CertificateTemplates_Name",
                table: "CertificateTemplates",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CertificateTemplates_RequestProfileId",
                table: "CertificateTemplates",
                column: "RequestProfileId");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateTemplates_SigningProfileId",
                table: "CertificateTemplates",
                column: "SigningProfileId");

            migrationBuilder.CreateIndex(
                name: "IX_CertProfiles_CertificateAuthorityId",
                table: "CertProfiles",
                column: "CertificateAuthorityId");

            migrationBuilder.CreateIndex(
                name: "IX_CertProfiles_InheritsFromId",
                table: "CertProfiles",
                column: "InheritsFromId");

            migrationBuilder.CreateIndex(
                name: "IX_CertProfiles_Name",
                table: "CertProfiles",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CertProfiles_TenantId",
                table: "CertProfiles",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_CmpTransactions_CaId_TransactionId",
                table: "CmpTransactions",
                columns: new[] { "CaId", "TransactionId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CmpTransactions_CreatedAt",
                table: "CmpTransactions",
                column: "CreatedAt");

            migrationBuilder.CreateIndex(
                name: "IX_CrlConfigurations_CaCertificateId",
                table: "CrlConfigurations",
                column: "CaCertificateId");

            migrationBuilder.CreateIndex(
                name: "IX_CrlConfigurations_Name",
                table: "CrlConfigurations",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Crls_IssuerName_CrlNumber",
                table: "Crls",
                columns: new[] { "IssuerName", "CrlNumber" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Crls_TaskId",
                table: "Crls",
                column: "TaskId");

            migrationBuilder.CreateIndex(
                name: "IX_CsrApprovals_ApproverId",
                table: "CsrApprovals",
                column: "ApproverId");

            migrationBuilder.CreateIndex(
                name: "IX_CsrApprovals_CertRequestId",
                table: "CsrApprovals",
                column: "CertRequestId");

            migrationBuilder.CreateIndex(
                name: "IX_EnrollmentTokens_CmpReferenceValue",
                table: "EnrollmentTokens",
                column: "CmpReferenceValue");

            migrationBuilder.CreateIndex(
                name: "IX_EnrollmentTokens_CreatedByUserId",
                table: "EnrollmentTokens",
                column: "CreatedByUserId");

            migrationBuilder.CreateIndex(
                name: "IX_EnrollmentTokens_ExpiresAt",
                table: "EnrollmentTokens",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_EnrollmentTokens_Token",
                table: "EnrollmentTokens",
                column: "Token",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_FeatureFlags_Name",
                table: "FeatureFlags",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Fido2Credentials_CredentialId",
                table: "Fido2Credentials",
                column: "CredentialId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Fido2Credentials_UserId",
                table: "Fido2Credentials",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_KerberosRealmKeys_RealmId_Kvno_EncryptionType",
                table: "KerberosRealmKeys",
                columns: new[] { "RealmId", "Kvno", "EncryptionType" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_KerberosRealms_EnrollmentUserId",
                table: "KerberosRealms",
                column: "EnrollmentUserId");

            migrationBuilder.CreateIndex(
                name: "IX_KerberosRealms_Realm",
                table: "KerberosRealms",
                column: "Realm",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_KerberosRealms_TenantId",
                table: "KerberosRealms",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_KeyCeremonies_ExpiresAt",
                table: "KeyCeremonies",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_KeyCeremonies_InitiatedByUserId",
                table: "KeyCeremonies",
                column: "InitiatedByUserId");

            migrationBuilder.CreateIndex(
                name: "IX_KeyCeremonies_Status",
                table: "KeyCeremonies",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_Keystores_Name",
                table: "Keystores",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_LdapConfigurations_CertificateAuthorityId",
                table: "LdapConfigurations",
                column: "CertificateAuthorityId");

            migrationBuilder.CreateIndex(
                name: "IX_LdapConfigurations_Name",
                table: "LdapConfigurations",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_MtlsCredentials_CertificateId",
                table: "MtlsCredentials",
                column: "CertificateId");

            migrationBuilder.CreateIndex(
                name: "IX_MtlsCredentials_SigningCaId",
                table: "MtlsCredentials",
                column: "SigningCaId");

            migrationBuilder.CreateIndex(
                name: "IX_MtlsCredentials_Thumbprint",
                table: "MtlsCredentials",
                column: "Thumbprint");

            migrationBuilder.CreateIndex(
                name: "IX_MtlsCredentials_UserId",
                table: "MtlsCredentials",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_NotificationLogs_EventType_Target_Date",
                table: "NotificationLogs",
                columns: new[] { "EventType", "TargetEntityId", "NotificationDate" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_OIDOptions_OID",
                table: "OIDOptions",
                column: "OID",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_PasswordHistory_UserId_ChangedAt",
                table: "PasswordHistory",
                columns: new[] { "UserId", "ChangedAt" },
                descending: new[] { false, true });

            migrationBuilder.CreateIndex(
                name: "IX_RefreshTokens_ExpiresAt",
                table: "RefreshTokens",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_RefreshTokens_Token",
                table: "RefreshTokens",
                column: "Token",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RefreshTokens_UserId",
                table: "RefreshTokens",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_RequestProfiles_CertificateAuthorityId",
                table: "RequestProfiles",
                column: "CertificateAuthorityId");

            migrationBuilder.CreateIndex(
                name: "IX_RequestProfiles_DefaultCertProfileId",
                table: "RequestProfiles",
                column: "DefaultCertProfileId");

            migrationBuilder.CreateIndex(
                name: "IX_RequestProfiles_InheritsFromId",
                table: "RequestProfiles",
                column: "InheritsFromId");

            migrationBuilder.CreateIndex(
                name: "IX_RequestProfiles_Name",
                table: "RequestProfiles",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RoleAssignments_AssignedByUserId",
                table: "RoleAssignments",
                column: "AssignedByUserId");

            migrationBuilder.CreateIndex(
                name: "IX_RoleAssignments_CertificateAuthorityId",
                table: "RoleAssignments",
                column: "CertificateAuthorityId");

            migrationBuilder.CreateIndex(
                name: "IX_RoleAssignments_GroupId_RoleId",
                table: "RoleAssignments",
                columns: new[] { "GroupId", "RoleId" });

            migrationBuilder.CreateIndex(
                name: "IX_RoleAssignments_RoleId",
                table: "RoleAssignments",
                column: "RoleId");

            migrationBuilder.CreateIndex(
                name: "IX_RoleAssignments_TenantId_CertificateAuthorityId",
                table: "RoleAssignments",
                columns: new[] { "TenantId", "CertificateAuthorityId" });

            migrationBuilder.CreateIndex(
                name: "IX_RoleAssignments_UserId_RoleId",
                table: "RoleAssignments",
                columns: new[] { "UserId", "RoleId" });

            migrationBuilder.CreateIndex(
                name: "IX_RoleCapabilities_RoleId_Capability",
                table: "RoleCapabilities",
                columns: new[] { "RoleId", "Capability" });

            migrationBuilder.CreateIndex(
                name: "IX_Roles_CreatedByUserId",
                table: "Roles",
                column: "CreatedByUserId");

            migrationBuilder.CreateIndex(
                name: "IX_Roles_Name",
                table: "Roles",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Roles_TenantId",
                table: "Roles",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_ScepTransactions_CaId_TransactionId",
                table: "ScepTransactions",
                columns: new[] { "CaId", "TransactionId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ScepTransactions_CertRequestId",
                table: "ScepTransactions",
                column: "CertRequestId");

            migrationBuilder.CreateIndex(
                name: "IX_ScepTransactions_CreatedAt",
                table: "ScepTransactions",
                column: "CreatedAt");

            migrationBuilder.CreateIndex(
                name: "IX_ScepTransactions_ExpiresAt",
                table: "ScepTransactions",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_SchedulerJobStates_NextRunUtc",
                table: "SchedulerJobStates",
                column: "NextRunUtc");

            migrationBuilder.CreateIndex(
                name: "IX_SchedulerLeases_ExpiresAtUtc",
                table: "SchedulerLeases",
                column: "ExpiresAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_SignerAudit_At",
                table: "SignerAudit",
                column: "At");

            migrationBuilder.CreateIndex(
                name: "IX_SignerAudit_CaId",
                table: "SignerAudit",
                column: "CaId");

            migrationBuilder.CreateIndex(
                name: "IX_SignerAudit_KeyCertificateId",
                table: "SignerAudit",
                column: "KeyCertificateId");

            migrationBuilder.CreateIndex(
                name: "IX_SigningProfiles_InheritsFromId",
                table: "SigningProfiles",
                column: "InheritsFromId");

            migrationBuilder.CreateIndex(
                name: "IX_SigningProfiles_IssuerId",
                table: "SigningProfiles",
                column: "IssuerId");

            migrationBuilder.CreateIndex(
                name: "IX_SigningProfiles_Name",
                table: "SigningProfiles",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_SshCaKeys_CertificateAuthorityId",
                table: "SshCaKeys",
                column: "CertificateAuthorityId");

            migrationBuilder.CreateIndex(
                name: "IX_SshCertificates_SshCaKeyId",
                table: "SshCertificates",
                column: "SshCaKeyId");

            migrationBuilder.CreateIndex(
                name: "IX_SshCertificateTemplates_Name",
                table: "SshCertificateTemplates",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_SshCertificateTemplates_SshCaKeyId",
                table: "SshCertificateTemplates",
                column: "SshCaKeyId");

            migrationBuilder.CreateIndex(
                name: "IX_SshCertificateTemplates_SshCertProfileId",
                table: "SshCertificateTemplates",
                column: "SshCertProfileId");

            migrationBuilder.CreateIndex(
                name: "IX_SshCertificateTemplates_SshRequestProfileId",
                table: "SshCertificateTemplates",
                column: "SshRequestProfileId");

            migrationBuilder.CreateIndex(
                name: "IX_SshCertificateTemplates_SshSigningProfileId",
                table: "SshCertificateTemplates",
                column: "SshSigningProfileId");

            migrationBuilder.CreateIndex(
                name: "IX_SshCertProfiles_Name",
                table: "SshCertProfiles",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_SshRequestProfiles_Name",
                table: "SshRequestProfiles",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_SshSigningProfiles_Name",
                table: "SshSigningProfiles",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_SshSigningProfiles_SshCaKeyId",
                table: "SshSigningProfiles",
                column: "SshCaKeyId");

            migrationBuilder.CreateIndex(
                name: "IX_TenantHostnames_CertificateId",
                table: "TenantHostnames",
                column: "CertificateId");

            migrationBuilder.CreateIndex(
                name: "IX_TenantHostnames_Hostname",
                table: "TenantHostnames",
                column: "Hostname",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_TenantHostnames_IssuingCaId",
                table: "TenantHostnames",
                column: "IssuingCaId");

            migrationBuilder.CreateIndex(
                name: "IX_TenantHostnames_TenantId",
                table: "TenantHostnames",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_Tenants_IsDeleted",
                table: "Tenants",
                column: "IsDeleted");

            migrationBuilder.CreateIndex(
                name: "IX_Tenants_Name",
                table: "Tenants",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Tenants_Slug",
                table: "Tenants",
                column: "Slug",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_TotpRecoveryCodes_UserId",
                table: "TotpRecoveryCodes",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_TotpRecoveryCodes_UserId_CodeHash",
                table: "TotpRecoveryCodes",
                columns: new[] { "UserId", "CodeHash" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_TotpSecrets_UserId",
                table: "TotpSecrets",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_TrustAnchors_SerialNumber_Issuer",
                table: "TrustAnchors",
                columns: new[] { "SerialNumber", "Issuer" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_UserCapabilityGrants_CertificateAuthorityId",
                table: "UserCapabilityGrants",
                column: "CertificateAuthorityId");

            migrationBuilder.CreateIndex(
                name: "IX_UserCapabilityGrants_GrantedByUserId",
                table: "UserCapabilityGrants",
                column: "GrantedByUserId");

            migrationBuilder.CreateIndex(
                name: "IX_UserCapabilityGrants_TenantId_CertificateAuthorityId",
                table: "UserCapabilityGrants",
                columns: new[] { "TenantId", "CertificateAuthorityId" });

            migrationBuilder.CreateIndex(
                name: "IX_UserCapabilityGrants_UserId_Capability",
                table: "UserCapabilityGrants",
                columns: new[] { "UserId", "Capability" });

            migrationBuilder.CreateIndex(
                name: "IX_UserPreferences_UserId_Key",
                table: "UserPreferences",
                columns: new[] { "UserId", "Key" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Users_Email",
                table: "Users",
                column: "Email",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Users_Id",
                table: "Users",
                column: "Id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Users_IsDeleted",
                table: "Users",
                column: "IsDeleted");

            migrationBuilder.CreateIndex(
                name: "IX_Users_IsServiceIdentity",
                table: "Users",
                column: "IsServiceIdentity");

            migrationBuilder.CreateIndex(
                name: "IX_Users_ServiceScopeCaId",
                table: "Users",
                column: "ServiceScopeCaId");

            migrationBuilder.CreateIndex(
                name: "IX_Users_ServiceScopeTenantId",
                table: "Users",
                column: "ServiceScopeTenantId");

            migrationBuilder.CreateIndex(
                name: "IX_Users_Username",
                table: "Users",
                column: "Username",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Whitelists_CertificateAuthorityId",
                table: "Whitelists",
                column: "CertificateAuthorityId");

            migrationBuilder.CreateIndex(
                name: "IX_Whitelists_Scope_CertificateAuthorityId_Protocol",
                table: "Whitelists",
                columns: new[] { "Scope", "CertificateAuthorityId", "Protocol" },
                unique: true);

            migrationBuilder.AddForeignKey(
                name: "FK_AcmeAuthorizations_AcmeOrders_OrderId",
                table: "AcmeAuthorizations",
                column: "OrderId",
                principalTable: "AcmeOrders",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_AcmeOrders_CertificateRequests_FinalizedCsrId",
                table: "AcmeOrders",
                column: "FinalizedCsrId",
                principalTable: "CertificateRequests",
                principalColumn: "Id",
                onDelete: ReferentialAction.SetNull);

            migrationBuilder.AddForeignKey(
                name: "FK_AcmeOrders_Certificates_CertificateId",
                table: "AcmeOrders",
                column: "CertificateId",
                principalTable: "Certificates",
                principalColumn: "CertificateId",
                onDelete: ReferentialAction.SetNull);

            migrationBuilder.AddForeignKey(
                name: "FK_AllowedCertProfileSigningProfiles_CertProfiles_CertProfileId",
                table: "AllowedCertProfileSigningProfiles",
                column: "CertProfileId",
                principalTable: "CertProfiles",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_AllowedCertProfileSigningProfiles_SigningProfiles_SigningPr~",
                table: "AllowedCertProfileSigningProfiles",
                column: "SigningProfileId",
                principalTable: "SigningProfiles",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_CaGroupMembers_CaGroups_GroupId",
                table: "CaGroupMembers",
                column: "GroupId",
                principalTable: "CaGroups",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_CaGroups_CertificateAuthorities_CertificateAuthorityId",
                table: "CaGroups",
                column: "CertificateAuthorityId",
                principalTable: "CertificateAuthorities",
                principalColumn: "Id",
                onDelete: ReferentialAction.SetNull);

            migrationBuilder.AddForeignKey(
                name: "FK_CaGroups_CertificateAuthorities_MtlsSigningCaId",
                table: "CaGroups",
                column: "MtlsSigningCaId",
                principalTable: "CertificateAuthorities",
                principalColumn: "Id",
                onDelete: ReferentialAction.SetNull);

            migrationBuilder.AddForeignKey(
                name: "FK_CaProtocolConfigs_CertProfiles_CertProfileId",
                table: "CaProtocolConfigs",
                column: "CertProfileId",
                principalTable: "CertProfiles",
                principalColumn: "Id",
                onDelete: ReferentialAction.SetNull);

            migrationBuilder.AddForeignKey(
                name: "FK_CaProtocolConfigs_CertificateAuthorities_CaId",
                table: "CaProtocolConfigs",
                column: "CaId",
                principalTable: "CertificateAuthorities",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_CaProtocolConfigs_RequestProfiles_RequestProfileId",
                table: "CaProtocolConfigs",
                column: "RequestProfileId",
                principalTable: "RequestProfiles",
                principalColumn: "Id",
                onDelete: ReferentialAction.SetNull);

            migrationBuilder.AddForeignKey(
                name: "FK_CaProtocolConfigs_SigningProfiles_SigningProfileId",
                table: "CaProtocolConfigs",
                column: "SigningProfileId",
                principalTable: "SigningProfiles",
                principalColumn: "Id",
                onDelete: ReferentialAction.SetNull);

            migrationBuilder.AddForeignKey(
                name: "FK_CaServiceUrls_Certificates_CaCertificateId",
                table: "CaServiceUrls",
                column: "CaCertificateId",
                principalTable: "Certificates",
                principalColumn: "CertificateId",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_CertificateAccess_Certificates_CertificateId",
                table: "CertificateAccess",
                column: "CertificateId",
                principalTable: "Certificates",
                principalColumn: "CertificateId",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_CertificateAuthorities_Certificates_CertificateId",
                table: "CertificateAuthorities",
                column: "CertificateId",
                principalTable: "Certificates",
                principalColumn: "CertificateId");

            migrationBuilder.AddForeignKey(
                name: "FK_CertificateRequests_Certificates_IssuedCertificateId",
                table: "CertificateRequests",
                column: "IssuedCertificateId",
                principalTable: "Certificates",
                principalColumn: "CertificateId",
                onDelete: ReferentialAction.SetNull);

            migrationBuilder.AddForeignKey(
                name: "FK_CertificateRequests_SigningProfiles_SigningProfileId",
                table: "CertificateRequests",
                column: "SigningProfileId",
                principalTable: "SigningProfiles",
                principalColumn: "Id");

            migrationBuilder.AddForeignKey(
                name: "FK_Certificates_SigningProfiles_SigningProfileId",
                table: "Certificates",
                column: "SigningProfileId",
                principalTable: "SigningProfiles",
                principalColumn: "Id",
                onDelete: ReferentialAction.SetNull);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_CertificateAuthorities_Certificates_CertificateId",
                table: "CertificateAuthorities");

            migrationBuilder.DropForeignKey(
                name: "FK_SigningProfiles_Certificates_IssuerId",
                table: "SigningProfiles");

            migrationBuilder.DropTable(
                name: "AccessBadgeSources");

            migrationBuilder.DropTable(
                name: "AcmeChallenges");

            migrationBuilder.DropTable(
                name: "AcmeEabKeys");

            migrationBuilder.DropTable(
                name: "AcmeNonces");

            migrationBuilder.DropTable(
                name: "AllowedCertProfileSigningProfiles");

            migrationBuilder.DropTable(
                name: "CaGroupMembers");

            migrationBuilder.DropTable(
                name: "CapabilityGrants");

            migrationBuilder.DropTable(
                name: "CaProtocolConfigs");

            migrationBuilder.DropTable(
                name: "CaServiceUrls");

            migrationBuilder.DropTable(
                name: "CertComplianceFindings");

            migrationBuilder.DropTable(
                name: "CertificateAccess");

            migrationBuilder.DropTable(
                name: "CertificateTags");

            migrationBuilder.DropTable(
                name: "CertificateTemplates");

            migrationBuilder.DropTable(
                name: "CmpTransactions");

            migrationBuilder.DropTable(
                name: "Crls");

            migrationBuilder.DropTable(
                name: "CsrApprovals");

            migrationBuilder.DropTable(
                name: "CtLogs");

            migrationBuilder.DropTable(
                name: "EnrollmentTokens");

            migrationBuilder.DropTable(
                name: "FeatureFlags");

            migrationBuilder.DropTable(
                name: "Fido2Credentials");

            migrationBuilder.DropTable(
                name: "KerberosRealmKeys");

            migrationBuilder.DropTable(
                name: "KeyCeremonies");

            migrationBuilder.DropTable(
                name: "Keystores");

            migrationBuilder.DropTable(
                name: "LdapConfigurations");

            migrationBuilder.DropTable(
                name: "LdapPublisherPolicy");

            migrationBuilder.DropTable(
                name: "MtlsCredentials");

            migrationBuilder.DropTable(
                name: "NotificationLogs");

            migrationBuilder.DropTable(
                name: "NotificationPreferences");

            migrationBuilder.DropTable(
                name: "OIDOptions");

            migrationBuilder.DropTable(
                name: "PasswordHistory");

            migrationBuilder.DropTable(
                name: "PasswordPolicy");

            migrationBuilder.DropTable(
                name: "ProtocolRateLimits");

            migrationBuilder.DropTable(
                name: "RefreshTokens");

            migrationBuilder.DropTable(
                name: "RoleAssignments");

            migrationBuilder.DropTable(
                name: "RoleCapabilities");

            migrationBuilder.DropTable(
                name: "ScepTransactions");

            migrationBuilder.DropTable(
                name: "SchedulerJobStates");

            migrationBuilder.DropTable(
                name: "SchedulerLeases");

            migrationBuilder.DropTable(
                name: "SecurityPolicy");

            migrationBuilder.DropTable(
                name: "SignerAudit");

            migrationBuilder.DropTable(
                name: "SshCertificates");

            migrationBuilder.DropTable(
                name: "SshCertificateTemplates");

            migrationBuilder.DropTable(
                name: "TenantHostnames");

            migrationBuilder.DropTable(
                name: "TotpRecoveryCodes");

            migrationBuilder.DropTable(
                name: "TotpSecrets");

            migrationBuilder.DropTable(
                name: "TrustAnchors");

            migrationBuilder.DropTable(
                name: "UserCapabilityGrants");

            migrationBuilder.DropTable(
                name: "UserPreferences");

            migrationBuilder.DropTable(
                name: "Whitelists");

            migrationBuilder.DropTable(
                name: "AccessBadges");

            migrationBuilder.DropTable(
                name: "AcmeAuthorizations");

            migrationBuilder.DropTable(
                name: "RequestProfiles");

            migrationBuilder.DropTable(
                name: "CrlConfigurations");

            migrationBuilder.DropTable(
                name: "KerberosRealms");

            migrationBuilder.DropTable(
                name: "CaGroups");

            migrationBuilder.DropTable(
                name: "Roles");

            migrationBuilder.DropTable(
                name: "SshCertProfiles");

            migrationBuilder.DropTable(
                name: "SshRequestProfiles");

            migrationBuilder.DropTable(
                name: "SshSigningProfiles");

            migrationBuilder.DropTable(
                name: "AcmeOrders");

            migrationBuilder.DropTable(
                name: "SshCaKeys");

            migrationBuilder.DropTable(
                name: "AcmeAccounts");

            migrationBuilder.DropTable(
                name: "CertificateRequests");

            migrationBuilder.DropTable(
                name: "Users");

            migrationBuilder.DropTable(
                name: "Certificates");

            migrationBuilder.DropTable(
                name: "CertProfiles");

            migrationBuilder.DropTable(
                name: "SigningProfiles");

            migrationBuilder.DropTable(
                name: "CertificateAuthorities");

            migrationBuilder.DropTable(
                name: "Tenants");
        }
    }
}
