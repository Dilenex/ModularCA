using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <summary>
    /// 0.4.2: the record of each SSH CA key that was a plaintext file on the node and has been
    /// imported into the signer: its name, fingerprint and file, when it was imported, and when
    /// the file was removed and the import audited. The import writes a row in the transaction
    /// that switches the key row to the signer. Table creation only; nothing to refuse.
    /// </summary>
    public partial class SshKeyImports : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "SshKeyImports",
                columns: table => new
                {
                    SshCaKeyId = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    Fingerprint = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    FilePath = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: false),
                    ImportedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    FileRemovedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    AuditedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SshKeyImports", x => x.SshCaKeyId);
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "SshKeyImports");
        }
    }
}
