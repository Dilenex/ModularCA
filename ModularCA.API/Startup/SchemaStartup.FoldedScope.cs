using ModularCA.Database;
using ModularCA.Shared.Utils;
using Npgsql;

namespace ModularCA.API.Startup;

// The --upgrade-check refusal of an integration key scoped to the system tenant, which
// FoldSystemTenant deletes, or to no existing space. Kept apart because it reads the schema by
// whichever names it has: Tenants before RenameTenantToSpace, Spaces after.
public static partial class SchemaStartup
{
    /// <summary>
    /// Refuses when a configured integration key's <c>SpaceId</c> (read from the legacy
    /// <c>TenantId</c> too) is a GUID that names the system tenant or no existing space, before
    /// the fold or after it. <c>FoldSystemTenant</c> deletes the system tenant and moves its CAs to
    /// the instance, so a key scoped to it would reach no CA after the upgrade, silently; an
    /// enrollment host checked after the control host folded sees no system tenant at all, and its
    /// key names no space. The spaces are read from <c>Spaces</c> when it exists, otherwise from
    /// <c>Tenants</c> (soft-deleted ones do not count), each found through <c>to_regclass</c> so
    /// the lookup follows the <c>search_path</c>. Read-only: one read-only transaction as the
    /// runtime role, rolled back. A database that cannot be read here is reported unreachable; its
    /// schema finding says why.
    /// </summary>
    /// <param name="target">The application database.</param>
    /// <param name="scopes">The integration keys whose <c>SpaceId</c> is set, by config key name.</param>
    /// <param name="ct">Cancellation token.</param>
    private static async Task<UpgradeFinding> FoldedScopeFindingAsync(
        SchemaTarget target, IReadOnlyList<(string Key, string Value)> scopes, CancellationToken ct)
    {
        const string name = "configuration";
        var systemTenants = new List<Guid>();
        var spaces = new List<Guid>();
        try
        {
            await using var connection = new NpgsqlConnection(GateReadConnectionString(target.Instance));
            await connection.OpenAsync(ct);
            await using var transaction = await connection.BeginTransactionAsync(ct);
            await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY", connection, transaction))
                await readOnly.ExecuteNonQueryAsync(ct);

            string? table;
            bool hasSystemColumn, hasDeletedColumn;
            await using (var probe = new NpgsqlCommand(FoldedScopeProbeSql, connection, transaction))
            await using (var reader = await probe.ExecuteReaderAsync(ct))
            {
                await reader.ReadAsync(ct);
                table = reader.IsDBNull(0) ? null : reader.GetString(0);
                hasSystemColumn = reader.GetBoolean(1);
                hasDeletedColumn = reader.GetBoolean(2);
            }
            if (table == null)
                return new(name, UpgradeReadiness.Clean, name, "no spaces yet: the integration key scopes need no change.", 0);

            var sql = $"SELECT \"Id\", {(hasSystemColumn ? "\"IsSystemTenant\"" : "false")} FROM \"{table}\""
                + (hasDeletedColumn ? " WHERE NOT \"IsDeleted\"" : "");
            await using (var query = new NpgsqlCommand(sql, connection, transaction))
            await using (var reader = await query.ExecuteReaderAsync(ct))
            {
                while (await reader.ReadAsync(ct))
                    (reader.GetBoolean(1) ? systemTenants : spaces).Add(reader.GetGuid(0));
            }
            await transaction.RollbackAsync(ct);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            return new(name, UpgradeReadiness.Unreachable, "integration key scopes could not be checked",
                $"The integration key scopes could not be checked against the {target.Name} database: {SchemaFailure.Describe(ex)}.", 0);
        }

        var refused = FoldedScopeRefusals(scopes, systemTenants, spaces);
        if (refused.Count == 0)
            return new(name, UpgradeReadiness.Clean, name, "no integration key is scoped to the system tenant or to a space that does not exist.", 0);
        var reasons = new List<string>();
        var toSystem = refused.Where(r => r.ToSystemTenant).Select(r => r.Key).ToList();
        var toNothing = refused.Where(r => !r.ToSystemTenant).Select(r => r.Key).ToList();
        if (toSystem.Count > 0)
            reasons.Add($"{string.Join(", ", toSystem)} scoped to the system tenant");
        if (toNothing.Count > 0)
            reasons.Add($"{string.Join(", ", toNothing)} scoped to no existing space");
        return new(name, UpgradeReadiness.Refused, $"{name}: {string.Join("; ", reasons)}",
            string.Join(Environment.NewLine, refused.Select(r => r.Message)), 0);
    }

    /// <summary>
    /// The table the spaces are in (<c>Spaces</c>, else <c>Tenants</c>, else null) as
    /// <c>to_regclass</c> resolves them on the <c>search_path</c>, and whether that table has the
    /// pre-fold <c>IsSystemTenant</c> and the <c>IsDeleted</c> columns.
    /// </summary>
    private const string FoldedScopeProbeSql = """
        WITH t AS (
            SELECT CASE WHEN to_regclass('"Spaces"') IS NOT NULL THEN 'Spaces'
                        WHEN to_regclass('"Tenants"') IS NOT NULL THEN 'Tenants' END AS name)
        SELECT t.name,
               EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = to_regclass(quote_ident(t.name))
                       AND attname = 'IsSystemTenant' AND attnum > 0 AND NOT attisdropped),
               EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = to_regclass(quote_ident(t.name))
                       AND attname = 'IsDeleted' AND attnum > 0 AND NOT attisdropped)
        FROM t
        """;

    /// <summary>
    /// The configured keys among <paramref name="scopes"/> whose value is a GUID naming one of
    /// <paramref name="systemTenants"/> or none of <paramref name="spaces"/>, each with the refusal
    /// that names it and its remedy, and whether it named the system tenant.
    /// </summary>
    internal static IReadOnlyList<(string Key, string Message, bool ToSystemTenant)> FoldedScopeRefusals(
        IReadOnlyList<(string Key, string Value)> scopes, IReadOnlyCollection<Guid> systemTenants, IReadOnlyCollection<Guid> spaces)
    {
        var refusals = new List<(string, string, bool)>();
        foreach (var (key, value) in scopes)
        {
            if (!Guid.TryParse(value, out var id) || (spaces.Contains(id) && !systemTenants.Contains(id)))
                continue;
            var legacy = key.Replace(".SpaceId", ".TenantId", StringComparison.Ordinal);
            refusals.Add(systemTenants.Contains(id)
                ? (key, $"{key} (named {legacy} before 0.4.0) is {value}, "
                    + "the system tenant. 0.4.0 folds the system tenant into the instance and deletes it, so this key would reach no CA "
                    + $"and fail every request. Set {key} to '{IntegrationSpaceScope.InstanceValue}' (the instance's CAs, "
                    + "which the system tenant's CAs become) and remove the TenantId key, then run the check again.", true)
                : (key, $"{key} (named {legacy} before 0.4.0) is {value}, which names no existing space, so this key would reach "
                    + "no CA and fail every request. If it named the system tenant before 0.4.0, which the upgrade folds into the "
                    + $"instance, set {key} to '{IntegrationSpaceScope.InstanceValue}' (the instance's CAs); otherwise set it to an "
                    + "existing space's id. Remove the TenantId key, then run the check again.", false));
        }
        return refusals;
    }
}
