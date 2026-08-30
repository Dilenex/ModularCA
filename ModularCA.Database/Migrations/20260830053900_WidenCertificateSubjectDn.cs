using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <summary>
    /// Widens <c>Certificates.SubjectDN</c> from varchar(255) to varchar(1024).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The column was narrower than the subject the application permits: CN 64 + O 128 + OU 128
    /// already reaches roughly 331 characters and passes every validation rule. MySQL 8 defaults to
    /// STRICT_TRANS_TABLES, so the INSERT failed with error 1406 <em>after</em> the certificate had
    /// been signed by the production CA — leaving a valid, trusted certificate with no row in this
    /// table: never published in a CRL, never revocable, invisible to OCSP. 1024 matches
    /// <c>CertRequestEntity.Subject</c>, so storage can no longer be narrower than what may be
    /// requested.
    /// </para>
    /// <para>
    /// The index is dropped and recreated with a 255-character prefix. InnoDB caps an index key at
    /// 3072 bytes, which is 768 characters under utf8mb4, so the widened column cannot be indexed
    /// in full.
    /// </para>
    /// <para>
    /// <b>Down is lossy and is not safe to run on a populated database.</b> Narrowing back to
    /// varchar(255) truncates or rejects any subject longer than that — which is precisely the data
    /// this migration exists to allow. It is written out for completeness; rolling back after any
    /// certificate with a long subject has been issued will fail under STRICT_TRANS_TABLES.
    /// </para>
    /// </remarks>
    public partial class WidenCertificateSubjectDn : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Certificates_SubjectDN",
                table: "Certificates");

            migrationBuilder.AlterColumn<string>(
                name: "SubjectDN",
                table: "Certificates",
                type: "varchar(1024)",
                maxLength: 1024,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "varchar(255)",
                oldMaxLength: 255)
                .Annotation("MySql:CharSet", "utf8mb4")
                .OldAnnotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateIndex(
                name: "IX_Certificates_SubjectDN",
                table: "Certificates",
                column: "SubjectDN")
                .Annotation("MySql:IndexPrefixLength", new[] { 255 });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Certificates_SubjectDN",
                table: "Certificates");

            migrationBuilder.AlterColumn<string>(
                name: "SubjectDN",
                table: "Certificates",
                type: "varchar(255)",
                maxLength: 255,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "varchar(1024)",
                oldMaxLength: 1024)
                .Annotation("MySql:CharSet", "utf8mb4")
                .OldAnnotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateIndex(
                name: "IX_Certificates_SubjectDN",
                table: "Certificates",
                column: "SubjectDN");
        }
    }
}
