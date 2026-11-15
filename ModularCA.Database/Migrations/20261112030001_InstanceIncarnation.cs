using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <summary>
    /// 0.4.5: rollback detection (<c>docs/architecture/rollback-continuity.md</c>, sections 1
    /// and 2). Adds the one-row table holding the incarnation this database last saw, and the
    /// table of continuity events, whose unacknowledged rows are the standing notice in the
    /// console and in <c>/health/ready</c>. Both start empty: the first start after the upgrade
    /// stores the incarnation it sees and reports nothing.
    /// </summary>
    public partial class InstanceIncarnation : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "InstanceContinuityEvents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Kind = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    DetectedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    OldTag = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    NewTag = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    EdgeOfMemoryUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    AuditNewestUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    CrlNumberFloor = table.Column<long>(type: "bigint", nullable: true),
                    CrlCountersRaised = table.Column<int>(type: "integer", nullable: false),
                    DetailsJson = table.Column<string>(type: "text", nullable: true),
                    AcknowledgedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    AcknowledgedByUserId = table.Column<Guid>(type: "uuid", nullable: true),
                    AcknowledgedByUsername = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_InstanceContinuityEvents", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "InstanceIncarnation",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false),
                    Source = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    ValueHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    RecordedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    RecordedBy = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_InstanceIncarnation", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_InstanceContinuityEvents_AcknowledgedAt",
                table: "InstanceContinuityEvents",
                column: "AcknowledgedAt");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "InstanceContinuityEvents");

            migrationBuilder.DropTable(
                name: "InstanceIncarnation");
        }
    }
}
