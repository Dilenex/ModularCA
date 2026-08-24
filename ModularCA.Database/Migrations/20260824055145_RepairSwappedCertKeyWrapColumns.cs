using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ModularCA.Database.Migrations
{
    /// <summary>
    /// Repairs certificate rows whose key-wrapping columns were written the wrong way round.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>KeyEncryptionUtil.EncryptPrivateKey</c> returns
    /// <c>(aesKeyEncrypted, iv, encryptedPrivateKey)</c>. Issuance deconstructed it positionally
    /// into <c>(certIv, certEncryptedAes, certEncryptedPrivKey)</c>, so every certificate issued
    /// with a CA-generated key stored the wrapped AES key in <c>AesKeyEncryptionIv</c> and the
    /// 12-byte GCM nonce in <c>EncryptedAesForPrivateKey</c>. Issuance itself never touched those
    /// values again, so nothing failed until the first PFX export, which died with an
    /// ArgumentOutOfRangeException while trying to slice a 32-byte HKDF salt out of a 12-byte
    /// buffer. The write path is fixed; this repairs the rows it already wrote.
    /// </para>
    /// <para>
    /// The discriminator is exact rather than heuristic. A correct IV is always exactly 12 bytes
    /// (the AES-GCM nonce), and a correct wrapped AES key never is: it is either RSA-OAEP output
    /// (at least 128 bytes) or the non-RSA form of 32-byte salt + 12-byte IV + ciphertext and tag
    /// (at least 60 bytes). So "the AES column holds exactly 12 bytes and the IV column does not"
    /// identifies a swapped row and cannot match a correct one.
    /// </para>
    /// <para>
    /// Only the Certificates table is affected. Every other writer of these columns —
    /// CsrService, AdminIssuanceController, the renewal paths — assigns by name and is correct,
    /// which is why the CSR rows decrypt fine and only the certificate rows do not.
    /// </para>
    /// </remarks>
    public partial class RepairSwappedCertKeyWrapColumns : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // A temp column is required because MySQL evaluates SET clauses left to right,
            // using already-updated values — so a direct "a = b, b = a" would copy b into both.
            migrationBuilder.Sql(
                "ALTER TABLE `Certificates` ADD COLUMN `KeyWrapSwapTmp` LONGBLOB NULL;");

            migrationBuilder.Sql(@"
                UPDATE `Certificates`
                SET `KeyWrapSwapTmp` = `AesKeyEncryptionIv`
                WHERE `AesKeyEncryptionIv` IS NOT NULL
                  AND `EncryptedAesForPrivateKey` IS NOT NULL
                  AND LENGTH(`EncryptedAesForPrivateKey`) = 12
                  AND LENGTH(`AesKeyEncryptionIv`) <> 12;");

            // Gated on the temp column, not on the length predicate: the first assignment below
            // changes the lengths, which would otherwise stop the row matching mid-statement.
            migrationBuilder.Sql(@"
                UPDATE `Certificates`
                SET `AesKeyEncryptionIv` = `EncryptedAesForPrivateKey`,
                    `EncryptedAesForPrivateKey` = `KeyWrapSwapTmp`
                WHERE `KeyWrapSwapTmp` IS NOT NULL;");

            migrationBuilder.Sql(
                "ALTER TABLE `Certificates` DROP COLUMN `KeyWrapSwapTmp`;");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Deliberately empty. Down would have to re-corrupt the repaired rows, and the
            // repaired state is valid under both the old and the new code — the old write path
            // simply produced rows that could never be decrypted. Rolling this back gains
            // nothing and would break PFX export again.
        }
    }
}
