using ModularCA.Core.Services;
using ModularCA.Database;
using Npgsql;

namespace ModularCA.API.Startup;

// The --upgrade-check finding for SSH CA keys that are still files, and its notes about SSH
// signing profiles and SSH login names. Kept apart because it reads the application database by
// column names that exist on both sides of the SSH migrations, in SQL, not through the model.
public static partial class SchemaStartup
{
    /// <summary>
    /// What <see cref="SshUpgradeAsync"/> read: the finding for the SSH CA key files, and the
    /// informational notes about signing profiles and about login names, each null when there
    /// is nothing to say.
    /// </summary>
    private sealed record SshUpgradeResult(UpgradeFinding Keys, string? ProfilesNote, string? LoginNamesNote = null);

    /// <summary>
    /// Reads the SSH CA key rows that name a key file, the SSH signing and certificate
    /// profiles, and the live user certificates, from the application database, and judges them
    /// (<see cref="SshUpgradeCheck"/>): the key files are looked for on this host, a relative
    /// path under <paramref name="installDirectory"/>. Read-only: one read-only transaction as
    /// the runtime role, rolled back. A database without the SSH tables has nothing to check;
    /// one that cannot be read here is reported unreachable, and its schema finding says why.
    /// </summary>
    /// <param name="target">The application database.</param>
    /// <param name="installDirectory">The installed application directory, the parent of the config directory.</param>
    /// <param name="ct">Cancellation token.</param>
    private static async Task<SshUpgradeResult> SshUpgradeAsync(SchemaTarget target, string installDirectory, CancellationToken ct)
    {
        const string name = SshUpgradeCheck.KeysFindingName;
        var keys = new List<SshUpgradeKeyRow>();
        var signingProfiles = new List<SshUpgradeSigningProfile>();
        var certProfiles = new List<SshUpgradeCertProfile>();
        var liveUserCertificates = new List<SshUpgradeUserCertificate>();
        var keyCount = 0;
        bool beforeUpgrade, beforeLoginNames;
        try
        {
            await using var connection = new NpgsqlConnection(GateReadConnectionString(target.Instance));
            await connection.OpenAsync(ct);
            await using var transaction = await connection.BeginTransactionAsync(ct);
            await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY", connection, transaction))
                await readOnly.ExecuteNonQueryAsync(ct);

            bool hasKeys, hasSigningProfiles, hasCertProfiles, hasCertificates;
            await using (var probe = new NpgsqlCommand(SshUpgradeProbeSql, connection, transaction))
            await using (var reader = await probe.ExecuteReaderAsync(ct))
            {
                await reader.ReadAsync(ct);
                hasKeys = reader.GetBoolean(0);
                hasSigningProfiles = reader.GetBoolean(1);
                hasCertProfiles = reader.GetBoolean(2);
                beforeUpgrade = !reader.GetBoolean(3);
                hasCertificates = reader.GetBoolean(4);
                beforeLoginNames = !reader.GetBoolean(5);
            }

            if (hasKeys)
            {
                await using (var query = new NpgsqlCommand(SshUpgradeKeysSql, connection, transaction))
                await using (var reader = await query.ExecuteReaderAsync(ct))
                {
                    while (await reader.ReadAsync(ct))
                        keys.Add(new SshUpgradeKeyRow(reader.GetGuid(0), reader.GetString(1), reader.IsDBNull(2) ? null : reader.GetString(2),
                            reader.GetString(3), reader.GetBoolean(4)));
                }
                await using var count = new NpgsqlCommand("""SELECT count(*) FROM "SshCaKeys" """, connection, transaction);
                keyCount = Convert.ToInt32(await count.ExecuteScalarAsync(ct));
            }
            if (hasCertificates && keyCount > 0)
            {
                await using var query = new NpgsqlCommand(SshUpgradeLiveUserCertificatesSql, connection, transaction);
                await using var reader = await query.ExecuteReaderAsync(ct);
                while (await reader.ReadAsync(ct))
                    liveUserCertificates.Add(new SshUpgradeUserCertificate(
                        reader.IsDBNull(0) ? null : reader.GetString(0), reader.IsDBNull(1) ? null : reader.GetString(1)));
            }
            if (hasSigningProfiles)
            {
                await using var query = new NpgsqlCommand(
                    """SELECT "Id", "Name"::text, "AllowUserCerts", "DefaultExtensions" FROM "SshSigningProfiles" """, connection, transaction);
                await using var reader = await query.ExecuteReaderAsync(ct);
                while (await reader.ReadAsync(ct))
                    signingProfiles.Add(new SshUpgradeSigningProfile(reader.GetGuid(0), reader.GetString(1), reader.GetBoolean(2),
                        reader.IsDBNull(3) ? null : reader.GetString(3)));
            }
            if (hasCertProfiles)
            {
                await using var query = new NpgsqlCommand(
                    """SELECT "Id", "Name"::text, "RequiredExtensions" FROM "SshCertProfiles" """, connection, transaction);
                await using var reader = await query.ExecuteReaderAsync(ct);
                while (await reader.ReadAsync(ct))
                    certProfiles.Add(new SshUpgradeCertProfile(reader.GetGuid(0), reader.GetString(1), reader.IsDBNull(2) ? null : reader.GetString(2)));
            }
            await transaction.RollbackAsync(ct);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            return new SshUpgradeResult(
                new UpgradeFinding(name, UpgradeReadiness.Unreachable, "SSH CA keys could not be checked",
                    $"The SSH CA keys could not be read from the {target.Name} database: {SchemaFailure.Describe(ex)}.", 0),
                null);
        }

        var finding = SshUpgradeCheck.Keys(keys, installDirectory);
        return new SshUpgradeResult(
            new UpgradeFinding(name, finding.Refused ? UpgradeReadiness.Refused : UpgradeReadiness.Clean, finding.Summary, finding.Detail, 0),
            SshUpgradeCheck.ProfilesNote(signingProfiles, certProfiles, beforeUpgrade),
            SshUpgradeCheck.LoginNamesNote(keyCount, liveUserCertificates, beforeLoginNames));
    }

    /// <summary>
    /// Whether the SSH tables exist, as <c>to_regclass</c> resolves them on the
    /// <c>search_path</c>; whether the key table already has the storage column the SSH
    /// keystore added, which says the database has been upgraded past it; and whether it has the
    /// own-username column, which says the database has been upgraded past login names.
    /// </summary>
    private const string SshUpgradeProbeSql = """
        SELECT to_regclass('"SshCaKeys"') IS NOT NULL,
               to_regclass('"SshSigningProfiles"') IS NOT NULL,
               to_regclass('"SshCertProfiles"') IS NOT NULL,
               EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = to_regclass('"SshCaKeys"')
                       AND attname = 'KeyStorage' AND attnum > 0 AND NOT attisdropped),
               to_regclass('"SshCertificates"') IS NOT NULL,
               EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = to_regclass('"SshCaKeys"')
                       AND attname = 'AllowOwnUsername' AND attnum > 0 AND NOT attisdropped)
        """;

    /// <summary>
    /// The key id and the principals of every unexpired, unrevoked SSH user certificate, by
    /// columns the table has had since before login names.
    /// </summary>
    private const string SshUpgradeLiveUserCertificatesSql = """
        SELECT "KeyId", "Principals"
        FROM "SshCertificates"
        WHERE "CertificateType" = 'user' AND NOT "IsRevoked" AND "ValidBefore" > now()
        """;

    /// <summary>
    /// The SSH CA key rows that name a key file, with whether the key and its CA are in service.
    /// Before the SSH keystore that is every row; after it, the rows not yet imported.
    /// </summary>
    private const string SshUpgradeKeysSql = """
        SELECT k."Id", k."Name", k."PublicKey", k."PrivateKeyPath",
               (k."IsEnabled" AND c."IsEnabled" AND NOT c."IsDeleted")
        FROM "SshCaKeys" k
        JOIN "CertificateAuthorities" c ON c."Id" = k."CertificateAuthorityId"
        WHERE k."PrivateKeyPath" IS NOT NULL AND k."PrivateKeyPath" <> ''
        ORDER BY k."Name", k."Id"
        """;
}
