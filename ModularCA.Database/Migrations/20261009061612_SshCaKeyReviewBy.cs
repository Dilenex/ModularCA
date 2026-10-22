using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <summary>
    /// 0.4.2: an advisory review date on each SSH CA key. <c>SshCaKeys.ReviewBy</c> is added and
    /// set on every existing key from the time it was created, counted in UTC: two years later
    /// for a key that signs user certificates, five years later for a key that signs host
    /// certificates only. The date reminds and never acts, so a key whose date is already past
    /// signs as before. No other column of any row changes. A column and a backfill; nothing to
    /// refuse.
    /// </summary>
    public partial class SshCaKeyReviewBy : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "ReviewBy",
                table: "SshCaKeys",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.Sql(
                """
                UPDATE "SshCaKeys" SET "ReviewBy" = (("CreatedAt" AT TIME ZONE 'UTC')
                    + CASE WHEN "IsHostCa" AND NOT "IsUserCa" THEN interval '5 years' ELSE interval '2 years' END) AT TIME ZONE 'UTC';
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ReviewBy",
                table: "SshCaKeys");
        }
    }
}
