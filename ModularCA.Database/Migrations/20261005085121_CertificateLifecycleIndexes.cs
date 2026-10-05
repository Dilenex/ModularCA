using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <summary>
    /// 0.4.0: indexes for the expired-certificate feedback. <c>Certificates.NotAfter</c> serves the
    /// lifecycle summary's band, the list's status, date-range and <c>replaced</c> filters and its
    /// expiry sort; <c>CertificateRequests.RenewalOfCertificateId</c> serves the join from a
    /// certificate to the requests that renew it. Index creation only; nothing to refuse.
    /// </summary>
    public partial class CertificateLifecycleIndexes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateIndex(
                name: "IX_Certificates_NotAfter",
                table: "Certificates",
                column: "NotAfter");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateRequests_RenewalOfCertificateId",
                table: "CertificateRequests",
                column: "RenewalOfCertificateId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Certificates_NotAfter",
                table: "Certificates");

            migrationBuilder.DropIndex(
                name: "IX_CertificateRequests_RenewalOfCertificateId",
                table: "CertificateRequests");
        }
    }
}
