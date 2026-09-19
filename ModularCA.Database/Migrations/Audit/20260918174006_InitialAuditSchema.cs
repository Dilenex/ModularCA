using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations.Audit
{
    /// <inheritdoc />
    public partial class InitialAuditSchema : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AuditAcme",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Timestamp = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Operation = table.Column<string>(type: "character varying(30)", maxLength: 30, nullable: false),
                    AccountId = table.Column<Guid>(type: "uuid", nullable: true),
                    OrderId = table.Column<Guid>(type: "uuid", nullable: true),
                    SubjectDN = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    CertificateSerial = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    Identifiers = table.Column<string>(type: "text", nullable: true),
                    RevocationReason = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    CaLabel = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    SourceIp = table.Column<string>(type: "character varying(45)", maxLength: 45, nullable: true),
                    Success = table.Column<bool>(type: "boolean", nullable: false),
                    ErrorMessage = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    CertificateAuthorityId = table.Column<Guid>(type: "uuid", nullable: true),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: true),
                    SigningProfileId = table.Column<Guid>(type: "uuid", nullable: true),
                    CertProfileId = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditAcme", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AuditCmp",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Timestamp = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    MessageType = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    SubjectDN = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    CertificateSerial = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    KeyAlgorithm = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: true),
                    KeySize = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: true),
                    CaLabel = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    TransactionId = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    RevocationReason = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    SourceIp = table.Column<string>(type: "character varying(45)", maxLength: 45, nullable: true),
                    Success = table.Column<bool>(type: "boolean", nullable: false),
                    ErrorMessage = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    CertificateAuthorityId = table.Column<Guid>(type: "uuid", nullable: true),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: true),
                    CallerPrincipal = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditCmp", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AuditEst",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Timestamp = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Operation = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    SubjectDN = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    CertificateSerial = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    KeyAlgorithm = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: true),
                    KeySize = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: true),
                    CaLabel = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    SourceIp = table.Column<string>(type: "character varying(45)", maxLength: 45, nullable: true),
                    Success = table.Column<bool>(type: "boolean", nullable: false),
                    ErrorMessage = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    CertificateAuthorityId = table.Column<Guid>(type: "uuid", nullable: true),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: true),
                    CallerPrincipal = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditEst", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AuditLogs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Timestamp = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ActorUserId = table.Column<Guid>(type: "uuid", nullable: true),
                    ActorUsername = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    ActionType = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: false),
                    TargetEntityType = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    TargetEntityId = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    DetailsJson = table.Column<string>(type: "text", nullable: true),
                    SourceIp = table.Column<string>(type: "character varying(45)", maxLength: 45, nullable: true),
                    Success = table.Column<bool>(type: "boolean", nullable: false),
                    ErrorMessage = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    CertificateAuthorityId = table.Column<Guid>(type: "uuid", nullable: true),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: true),
                    AccessBadgeId = table.Column<Guid>(type: "uuid", nullable: true),
                    AccessBadgeName = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    RecordHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    PreviousRecordHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditLogs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AuditMsae",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Timestamp = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Operation = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    SubjectDN = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    CertificateSerial = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    KeyAlgorithm = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: true),
                    KeySize = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: true),
                    TemplateName = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    CaLabel = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    SourceIp = table.Column<string>(type: "character varying(45)", maxLength: 45, nullable: true),
                    Success = table.Column<bool>(type: "boolean", nullable: false),
                    ErrorMessage = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    CertificateAuthorityId = table.Column<Guid>(type: "uuid", nullable: true),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: true),
                    CallerPrincipal = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    Realm = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    AuthMethod = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditMsae", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AuditNetwork",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Timestamp = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    SourceIp = table.Column<string>(type: "character varying(45)", maxLength: 45, nullable: false),
                    RequestPath = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false),
                    Protocol = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: true),
                    CaLabel = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    Reason = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    UserAgent = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    HttpMethod = table.Column<string>(type: "character varying(10)", maxLength: 10, nullable: false),
                    StatusCode = table.Column<int>(type: "integer", nullable: false),
                    ResponseTimeMs = table.Column<long>(type: "bigint", nullable: true),
                    Blocked = table.Column<bool>(type: "boolean", nullable: false),
                    CertificateAuthorityId = table.Column<Guid>(type: "uuid", nullable: true),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditNetwork", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AuditScep",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Timestamp = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Operation = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    SubjectDN = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    CertificateSerial = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    KeyAlgorithm = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: true),
                    KeySize = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: true),
                    CaLabel = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    TransactionId = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    SourceIp = table.Column<string>(type: "character varying(45)", maxLength: 45, nullable: true),
                    Success = table.Column<bool>(type: "boolean", nullable: false),
                    ErrorMessage = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    CertificateAuthorityId = table.Column<Guid>(type: "uuid", nullable: true),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: true),
                    CallerPrincipal = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditScep", x => x.Id);
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

            migrationBuilder.CreateIndex(
                name: "IX_AuditAcme_AccountId",
                table: "AuditAcme",
                column: "AccountId");

            migrationBuilder.CreateIndex(
                name: "IX_AuditAcme_CaLabel",
                table: "AuditAcme",
                column: "CaLabel");

            migrationBuilder.CreateIndex(
                name: "IX_AuditAcme_CertificateAuthorityId",
                table: "AuditAcme",
                column: "CertificateAuthorityId");

            migrationBuilder.CreateIndex(
                name: "IX_AuditAcme_CertificateAuthorityId_Timestamp",
                table: "AuditAcme",
                columns: new[] { "CertificateAuthorityId", "Timestamp" });

            migrationBuilder.CreateIndex(
                name: "IX_AuditAcme_CertificateSerial",
                table: "AuditAcme",
                column: "CertificateSerial");

            migrationBuilder.CreateIndex(
                name: "IX_AuditAcme_SourceIp",
                table: "AuditAcme",
                column: "SourceIp");

            migrationBuilder.CreateIndex(
                name: "IX_AuditAcme_TenantId",
                table: "AuditAcme",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_AuditAcme_TenantId_Timestamp",
                table: "AuditAcme",
                columns: new[] { "TenantId", "Timestamp" });

            migrationBuilder.CreateIndex(
                name: "IX_AuditAcme_Timestamp",
                table: "AuditAcme",
                column: "Timestamp");

            migrationBuilder.CreateIndex(
                name: "IX_AuditCmp_CaLabel",
                table: "AuditCmp",
                column: "CaLabel");

            migrationBuilder.CreateIndex(
                name: "IX_AuditCmp_CertificateAuthorityId",
                table: "AuditCmp",
                column: "CertificateAuthorityId");

            migrationBuilder.CreateIndex(
                name: "IX_AuditCmp_CertificateAuthorityId_Timestamp",
                table: "AuditCmp",
                columns: new[] { "CertificateAuthorityId", "Timestamp" });

            migrationBuilder.CreateIndex(
                name: "IX_AuditCmp_CertificateSerial",
                table: "AuditCmp",
                column: "CertificateSerial");

            migrationBuilder.CreateIndex(
                name: "IX_AuditCmp_SourceIp",
                table: "AuditCmp",
                column: "SourceIp");

            migrationBuilder.CreateIndex(
                name: "IX_AuditCmp_TenantId",
                table: "AuditCmp",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_AuditCmp_TenantId_Timestamp",
                table: "AuditCmp",
                columns: new[] { "TenantId", "Timestamp" });

            migrationBuilder.CreateIndex(
                name: "IX_AuditCmp_Timestamp",
                table: "AuditCmp",
                column: "Timestamp");

            migrationBuilder.CreateIndex(
                name: "IX_AuditCmp_TransactionId",
                table: "AuditCmp",
                column: "TransactionId");

            migrationBuilder.CreateIndex(
                name: "IX_AuditEst_CaLabel",
                table: "AuditEst",
                column: "CaLabel");

            migrationBuilder.CreateIndex(
                name: "IX_AuditEst_CertificateAuthorityId",
                table: "AuditEst",
                column: "CertificateAuthorityId");

            migrationBuilder.CreateIndex(
                name: "IX_AuditEst_CertificateAuthorityId_Timestamp",
                table: "AuditEst",
                columns: new[] { "CertificateAuthorityId", "Timestamp" });

            migrationBuilder.CreateIndex(
                name: "IX_AuditEst_CertificateSerial",
                table: "AuditEst",
                column: "CertificateSerial");

            migrationBuilder.CreateIndex(
                name: "IX_AuditEst_SourceIp",
                table: "AuditEst",
                column: "SourceIp");

            migrationBuilder.CreateIndex(
                name: "IX_AuditEst_TenantId",
                table: "AuditEst",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_AuditEst_TenantId_Timestamp",
                table: "AuditEst",
                columns: new[] { "TenantId", "Timestamp" });

            migrationBuilder.CreateIndex(
                name: "IX_AuditEst_Timestamp",
                table: "AuditEst",
                column: "Timestamp");

            migrationBuilder.CreateIndex(
                name: "IX_AuditLogs_ActionType",
                table: "AuditLogs",
                column: "ActionType");

            migrationBuilder.CreateIndex(
                name: "IX_AuditLogs_ActorUserId",
                table: "AuditLogs",
                column: "ActorUserId");

            migrationBuilder.CreateIndex(
                name: "IX_AuditLogs_ActorUserId_Timestamp",
                table: "AuditLogs",
                columns: new[] { "ActorUserId", "Timestamp" });

            migrationBuilder.CreateIndex(
                name: "IX_AuditLogs_CertificateAuthorityId",
                table: "AuditLogs",
                column: "CertificateAuthorityId");

            migrationBuilder.CreateIndex(
                name: "IX_AuditLogs_CertificateAuthorityId_Timestamp",
                table: "AuditLogs",
                columns: new[] { "CertificateAuthorityId", "Timestamp" });

            migrationBuilder.CreateIndex(
                name: "IX_AuditLogs_TargetEntityId",
                table: "AuditLogs",
                column: "TargetEntityId");

            migrationBuilder.CreateIndex(
                name: "IX_AuditLogs_TenantChain",
                table: "AuditLogs",
                columns: new[] { "TenantId", "Timestamp", "Id" });

            migrationBuilder.CreateIndex(
                name: "IX_AuditLogs_TenantId",
                table: "AuditLogs",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_AuditLogs_TenantId_Timestamp",
                table: "AuditLogs",
                columns: new[] { "TenantId", "Timestamp" });

            migrationBuilder.CreateIndex(
                name: "IX_AuditLogs_Timestamp",
                table: "AuditLogs",
                column: "Timestamp");

            migrationBuilder.CreateIndex(
                name: "IX_AuditMsae_CaLabel",
                table: "AuditMsae",
                column: "CaLabel");

            migrationBuilder.CreateIndex(
                name: "IX_AuditMsae_CertificateAuthorityId",
                table: "AuditMsae",
                column: "CertificateAuthorityId");

            migrationBuilder.CreateIndex(
                name: "IX_AuditMsae_CertificateAuthorityId_Timestamp",
                table: "AuditMsae",
                columns: new[] { "CertificateAuthorityId", "Timestamp" });

            migrationBuilder.CreateIndex(
                name: "IX_AuditMsae_CertificateSerial",
                table: "AuditMsae",
                column: "CertificateSerial");

            migrationBuilder.CreateIndex(
                name: "IX_AuditMsae_Realm",
                table: "AuditMsae",
                column: "Realm");

            migrationBuilder.CreateIndex(
                name: "IX_AuditMsae_SourceIp",
                table: "AuditMsae",
                column: "SourceIp");

            migrationBuilder.CreateIndex(
                name: "IX_AuditMsae_TenantId",
                table: "AuditMsae",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_AuditMsae_TenantId_Timestamp",
                table: "AuditMsae",
                columns: new[] { "TenantId", "Timestamp" });

            migrationBuilder.CreateIndex(
                name: "IX_AuditMsae_Timestamp",
                table: "AuditMsae",
                column: "Timestamp");

            migrationBuilder.CreateIndex(
                name: "IX_AuditNetwork_CaLabel",
                table: "AuditNetwork",
                column: "CaLabel");

            migrationBuilder.CreateIndex(
                name: "IX_AuditNetwork_CertificateAuthorityId",
                table: "AuditNetwork",
                column: "CertificateAuthorityId");

            migrationBuilder.CreateIndex(
                name: "IX_AuditNetwork_CertificateAuthorityId_Timestamp",
                table: "AuditNetwork",
                columns: new[] { "CertificateAuthorityId", "Timestamp" });

            migrationBuilder.CreateIndex(
                name: "IX_AuditNetwork_SourceIp",
                table: "AuditNetwork",
                column: "SourceIp");

            migrationBuilder.CreateIndex(
                name: "IX_AuditNetwork_TenantId",
                table: "AuditNetwork",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_AuditNetwork_TenantId_Timestamp",
                table: "AuditNetwork",
                columns: new[] { "TenantId", "Timestamp" });

            migrationBuilder.CreateIndex(
                name: "IX_AuditNetwork_Timestamp",
                table: "AuditNetwork",
                column: "Timestamp");

            migrationBuilder.CreateIndex(
                name: "IX_AuditScep_CaLabel",
                table: "AuditScep",
                column: "CaLabel");

            migrationBuilder.CreateIndex(
                name: "IX_AuditScep_CertificateAuthorityId",
                table: "AuditScep",
                column: "CertificateAuthorityId");

            migrationBuilder.CreateIndex(
                name: "IX_AuditScep_CertificateAuthorityId_Timestamp",
                table: "AuditScep",
                columns: new[] { "CertificateAuthorityId", "Timestamp" });

            migrationBuilder.CreateIndex(
                name: "IX_AuditScep_CertificateSerial",
                table: "AuditScep",
                column: "CertificateSerial");

            migrationBuilder.CreateIndex(
                name: "IX_AuditScep_SourceIp",
                table: "AuditScep",
                column: "SourceIp");

            migrationBuilder.CreateIndex(
                name: "IX_AuditScep_TenantId",
                table: "AuditScep",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_AuditScep_TenantId_Timestamp",
                table: "AuditScep",
                columns: new[] { "TenantId", "Timestamp" });

            migrationBuilder.CreateIndex(
                name: "IX_AuditScep_Timestamp",
                table: "AuditScep",
                column: "Timestamp");

            migrationBuilder.CreateIndex(
                name: "IX_AuditScep_TransactionId",
                table: "AuditScep",
                column: "TransactionId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AuditAcme");

            migrationBuilder.DropTable(
                name: "AuditCmp");

            migrationBuilder.DropTable(
                name: "AuditEst");

            migrationBuilder.DropTable(
                name: "AuditLogs");

            migrationBuilder.DropTable(
                name: "AuditMsae");

            migrationBuilder.DropTable(
                name: "AuditNetwork");

            migrationBuilder.DropTable(
                name: "AuditScep");

            migrationBuilder.DropTable(
                name: "CertComplianceFindings");
        }
    }
}
