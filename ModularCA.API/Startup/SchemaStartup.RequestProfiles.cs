using ModularCA.Core.Services;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using Npgsql;

namespace ModularCA.API.Startup;

// The --upgrade-check note about the request profiles the enrollment protocols use. Which protocol
// issued a certificate is recorded only in the audit database, so the certificates are found there
// and their requests in the application database, both read by column names that exist on both
// sides of the 0.4.2 migrations.
public static partial class SchemaStartup
{
    /// <summary>
    /// The note about the request profiles the enrollment protocols use
    /// (<see cref="RequestProfileUpgradeCheck"/>): the certificates each protocol issued in the
    /// last <see cref="RequestProfileUpgradeCheck.Days"/> days, from the protocol tables of the
    /// audit database, replayed against the request profile that protocol uses on its CA now.
    /// Null when there is nothing to say. Read-only: one read-only transaction on each database
    /// as its runtime role, rolled back. A database that cannot be read here is mentioned, not
    /// refused.
    /// </summary>
    /// <param name="application">The application database.</param>
    /// <param name="audit">The audit database.</param>
    /// <param name="ct">Cancellation token.</param>
    private static async Task<string?> RequestProfileUpgradeNoteAsync(SchemaTarget application, SchemaTarget audit, CancellationToken ct)
    {
        var since = DateTime.UtcNow.AddDays(-RequestProfileUpgradeCheck.Days);
        var issuedBySerial = new Dictionary<string, (string Protocol, string CaLabel, DateTime At)>(StringComparer.OrdinalIgnoreCase);
        try
        {
            await using var connection = new NpgsqlConnection(GateReadConnectionString(audit.Instance));
            await connection.OpenAsync(ct);
            await using var transaction = await connection.BeginTransactionAsync(ct);
            await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY", connection, transaction))
                await readOnly.ExecuteNonQueryAsync(ct);

            foreach (var (protocol, table) in ProtocolAuditTables)
            {
                await using (var probe = new NpgsqlCommand($"SELECT to_regclass('\"{table}\"') IS NOT NULL", connection, transaction))
                {
                    if (await probe.ExecuteScalarAsync(ct) is not true)
                        continue;
                }
                await using var query = new NpgsqlCommand($"""
                    SELECT "CertificateSerial", "CaLabel", max("Timestamp")
                    FROM "{table}"
                    WHERE "Success" AND "Timestamp" >= @since
                      AND coalesce("CertificateSerial", '') <> '' AND coalesce("CaLabel", '') <> ''
                    GROUP BY "CertificateSerial", "CaLabel"
                    """, connection, transaction);
                query.Parameters.AddWithValue("since", since);
                await using var reader = await query.ExecuteReaderAsync(ct);
                while (await reader.ReadAsync(ct))
                {
                    var at = reader.GetDateTime(2);
                    var serial = reader.GetString(0).Trim();
                    if (!issuedBySerial.TryGetValue(serial, out var seen) || seen.At < at)
                        issuedBySerial[serial] = (protocol, reader.GetString(1), at);
                }
            }
            await transaction.RollbackAsync(ct);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            return $"The certificates the enrollment protocols issued could not be read from the {audit.Name} database: "
                + $"{SchemaFailure.Describe(ex)}. The request profiles were not checked against them.";
        }
        if (issuedBySerial.Count == 0)
            return null;

        var profiles = new List<RequestProfileEntity>();
        var issued = new List<ProtocolIssuance>();
        try
        {
            await using var connection = new NpgsqlConnection(GateReadConnectionString(application.Instance));
            await connection.OpenAsync(ct);
            await using var transaction = await connection.BeginTransactionAsync(ct);
            await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY", connection, transaction))
                await readOnly.ExecuteNonQueryAsync(ct);

            await using (var query = new NpgsqlCommand(RequestProfileUpgradeProfilesSql, connection, transaction))
            await using (var reader = await query.ExecuteReaderAsync(ct))
            {
                while (await reader.ReadAsync(ct))
                {
                    profiles.Add(new RequestProfileEntity
                    {
                        Id = reader.GetGuid(0),
                        Name = reader.GetString(1),
                        SubjectDnRules = reader.IsDBNull(2) ? "[]" : reader.GetString(2),
                        SanRules = reader.IsDBNull(3) ? "{}" : reader.GetString(3),
                        AllowedCertProfileIds = reader.IsDBNull(4) ? "[]" : reader.GetString(4),
                        DefaultCertProfileId = reader.IsDBNull(5) ? null : reader.GetGuid(5),
                        RequireApproval = reader.GetBoolean(6),
                        RequiredApprovalCount = reader.GetInt32(7),
                        InheritsFromId = reader.IsDBNull(8) ? null : reader.GetGuid(8),
                        InheritanceEnabled = reader.GetBoolean(9),
                    });
                }
            }

            var profileOf = new Dictionary<(string Label, string Protocol), Guid?>();
            await using (var query = new NpgsqlCommand(RequestProfileUpgradeProtocolsSql, connection, transaction))
            await using (var reader = await query.ExecuteReaderAsync(ct))
            {
                while (await reader.ReadAsync(ct))
                    profileOf[(reader.GetString(0).ToLowerInvariant(), reader.GetString(1).ToUpperInvariant())] = reader.IsDBNull(2) ? null : reader.GetGuid(2);
            }

            await using (var query = new NpgsqlCommand(RequestProfileUpgradeRequestsSql, connection, transaction))
            {
                query.Parameters.AddWithValue("serials", issuedBySerial.Keys.Select(s => s.ToLowerInvariant()).ToArray());
                await using var reader = await query.ExecuteReaderAsync(ct);
                while (await reader.ReadAsync(ct))
                {
                    if (!issuedBySerial.TryGetValue(reader.GetString(0), out var source))
                        continue;
                    // A protocol that is off on the CA, or no longer configured there, asks nothing again.
                    if (!profileOf.TryGetValue((source.CaLabel.ToLowerInvariant(), source.Protocol), out var requestProfileId))
                        continue;
                    issued.Add(new ProtocolIssuance(source.Protocol, source.CaLabel, requestProfileId,
                        reader.IsDBNull(1) ? null : reader.GetString(1), reader.IsDBNull(2) ? null : reader.GetString(2), source.At));
                }
            }
            await transaction.RollbackAsync(ct);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            return $"The requests of the certificates the enrollment protocols issued could not be read from the {application.Name} database: "
                + $"{SchemaFailure.Describe(ex)}. The request profiles were not checked against them.";
        }

        return RequestProfileUpgradeCheck.Note(profiles, issued);
    }

    /// <summary>Each enrollment protocol, as a CA's protocol configuration names it, and its table in the audit database.</summary>
    private static readonly (string Protocol, string Table)[] ProtocolAuditTables =
    [
        ("ACME", "AuditAcme"), ("EST", "AuditEst"), ("SCEP", "AuditScep"), ("CMP", "AuditCmp"), ("MSAE", "AuditMsae"),
    ];

    /// <summary>Every request profile, with what its effective rules are resolved from.</summary>
    private const string RequestProfileUpgradeProfilesSql = """
        SELECT "Id", "Name"::text, "SubjectDnRules", "SanRules", "AllowedCertProfileIds", "DefaultCertProfileId",
               "RequireApproval", "RequiredApprovalCount", "InheritsFromId", "InheritanceEnabled"
        FROM "RequestProfiles"
        """;

    /// <summary>The request profile each enabled protocol uses on each CA that is in service.</summary>
    private const string RequestProfileUpgradeProtocolsSql = """
        SELECT c."Label"::text, p."Protocol", p."RequestProfileId"
        FROM "CaProtocolConfigs" p
        JOIN "CertificateAuthorities" c ON c."Id" = p."CaId"
        WHERE p."IsEnabled" AND c."IsEnabled" AND NOT c."IsDeleted" AND c."Label" IS NOT NULL
        """;

    /// <summary>The recorded names of the request that issued each certificate with one of the given serial numbers, lower case.</summary>
    private const string RequestProfileUpgradeRequestsSql = """
        SELECT lower(c."SerialNumber"), r."Subject", r."SubjectAlternativeNames"
        FROM "Certificates" c
        JOIN "CertificateRequests" r ON r."IssuedCertificateId" = c."CertificateId"
        WHERE lower(c."SerialNumber") = ANY(@serials)
        """;
}
