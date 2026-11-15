using System.Text.Json;
using System.Text.RegularExpressions;
using ModularCA.Shared.Settings;
using Npgsql;

namespace ModularCA.Core.Services.Settings;

/// <summary>The instance's identifier as one read found it.</summary>
/// <param name="Id">
/// The identifier; null when it is not known: nothing is stored and no fingerprint can be
/// derived, the stored row holds no usable value, or the database could not be read.
/// </param>
/// <param name="Stored">
/// Whether a row is stored. True with a null <paramref name="Id"/> means the row is there and
/// holds no usable value; the derived fingerprint is not given in its place.
/// </param>
public sealed record InstanceIdReading(string? Id, bool Stored);

/// <summary>What <see cref="InstanceIdentity.EnsureStoredAsync"/> found.</summary>
public enum InstanceIdStoreCase
{
    /// <summary>An identifier was stored before this call, by an earlier start or by another node a moment ago. Nothing was written.</summary>
    AlreadyStored,

    /// <summary>Nothing was stored, and this call stored the fingerprint derived now.</summary>
    StoredNow,

    /// <summary>Nothing is stored and no fingerprint could be derived, so nothing was written. A later start tries again.</summary>
    NothingToStore,

    /// <summary>A row is stored and holds no usable value. Nothing was written: the row is never replaced.</summary>
    Unusable,
}

/// <summary>What <see cref="InstanceIdentity.EnsureStoredAsync"/> found and did.</summary>
/// <param name="Case">The outcome.</param>
/// <param name="Id">The stored identifier after the call; null when none is stored or the stored row is unusable.</param>
/// <param name="Derived">
/// The fingerprint derived at the time of the call, for the log; null when none could be
/// derived. It differs from <paramref name="Id"/> once the system signing CA has been re-keyed.
/// </param>
public sealed record InstanceIdStoreResult(InstanceIdStoreCase Case, string? Id, string? Derived);

/// <summary>
/// The instance's identifier: what a backup's manifest records as <c>InstanceId</c> and what the
/// hub's local connection answers in <c>hello</c>, so a hub can match an archive to a running
/// instance for as long as it keeps either.
/// </summary>
/// <remarks>
/// <para>
/// <b>Where it is kept.</b> One row of the <c>Settings</c> table of the application database,
/// under the reserved key <see cref="Key"/>, its value a JSON string. The row is with the
/// instance's data: every host of the instance reads the same one, and a backup carries it, so a
/// restore onto a new host brings it along. It is in no file on any host, and that does not
/// depend on whether the settings have been moved out of <c>config.yaml</c>: the row is not a
/// setting (<see cref="ReservedSettingKeys"/>), and is written and read here with SQL of its own.
/// </para>
/// <para>
/// <b>What it is.</b> The SHA-256 of the public key of the system signing CA, as the
/// <c>Keystores</c> rows pinned it at the first start of a build that stores the identifier
/// (<see cref="EnsureStoredAsync"/>), 64 lower-case hex digits. That is the value builds before
/// this one derived each time, so archives already made agree with it. Once stored it is only
/// read: re-keying the system signing CA changes the fingerprint and not the identifier.
/// </para>
/// <para>
/// <b>Written once.</b> The only statement that writes the row is an <c>INSERT ... ON CONFLICT
/// DO NOTHING</c> on the table's primary key. Of two nodes starting together one inserts and the
/// other finds the row; neither replaces it. Nothing here updates or deletes the row, and
/// the settings store refuses a change that names the key
/// (<see cref="SettingsRefusal.WrittenOnce"/>). The row takes no settings revision and has no
/// history entry: it is not a change to a setting, and it has one value for ever.
/// </para>
/// <para>
/// Everything here runs over a connection of its own, without the service container, because
/// the backup and the other host commands need it where there is none.
/// </para>
/// </remarks>
public static partial class InstanceIdentity
{
    /// <summary>The key of the row in the <c>Settings</c> table.</summary>
    public const string Key = ReservedSettingKeys.InstanceId;

    /// <summary>The name recorded on the row as its writer.</summary>
    public static string StartActor => $"host:{Environment.MachineName}:startup";

    [GeneratedRegex("^[0-9a-f]{64}$")]
    private static partial Regex Sha256Hex();

    /// <summary>Whether <paramref name="value"/> has the form of an identifier that is stored: 64 lower-case hex digits.</summary>
    /// <param name="value">The value.</param>
    public static bool IsWellFormed(string? value) => value != null && Sha256Hex().IsMatch(value);

    /// <summary>
    /// The identifier for everything that needs it: the stored one, or, only while nothing is
    /// stored, the fingerprint derived now (an install that has not yet started a build that
    /// stores it, or a host command run before that start). Never throws: a database that cannot
    /// be read gives a reading with no identifier, which is "not known" and never a different one.
    /// </summary>
    /// <param name="appConnectionString">The application database.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    public static async Task<InstanceIdReading> ReadAsync(string appConnectionString, CancellationToken cancellationToken = default)
    {
        try
        {
            await using var connection = new NpgsqlConnection(appConnectionString);
            await connection.OpenAsync(cancellationToken);
            var (exists, stored) = await ReadStoredAsync(connection, cancellationToken);
            if (exists)
                return new InstanceIdReading(stored, true);
            return new InstanceIdReading(await DeriveAsync(connection, cancellationToken), false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            return new InstanceIdReading(null, false);
        }
    }

    /// <summary>
    /// Stores the identifier if none is stored, and returns what is stored afterwards. The value
    /// written is the fingerprint derived now (<see cref="DeriveAsync"/>); when none can be
    /// derived, or it is not a SHA-256 in hex, nothing is written. A row that is already there
    /// is never replaced, whatever it holds and whatever is derived now. Safe to run from
    /// several nodes at once: one insert wins and the others read its value.
    /// </summary>
    /// <param name="appConnectionString">The application database, with its schema current.</param>
    /// <param name="actor">The name recorded on the row as its writer; <see cref="StartActor"/> when null.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <exception cref="NpgsqlException">The database could not be read or written. Nothing was stored by this call.</exception>
    public static async Task<InstanceIdStoreResult> EnsureStoredAsync(string appConnectionString, string? actor = null,
        CancellationToken cancellationToken = default)
    {
        await using var connection = new NpgsqlConnection(appConnectionString);
        await connection.OpenAsync(cancellationToken);

        var derived = await DeriveAsync(connection, cancellationToken);
        var (exists, stored) = await ReadStoredAsync(connection, cancellationToken);
        if (exists)
            return new InstanceIdStoreResult(stored == null ? InstanceIdStoreCase.Unusable : InstanceIdStoreCase.AlreadyStored, stored, derived);
        if (!IsWellFormed(derived))
            return new InstanceIdStoreResult(InstanceIdStoreCase.NothingToStore, null, derived);

        // The one statement that writes the row. The primary key decides between two nodes: the
        // second waits for the first and then does nothing.
        int inserted;
        await using (var insert = new NpgsqlCommand(
            """
            INSERT INTO "Settings" ("Key", "ValueJson", "Version", "Revision", "UpdatedAt", "ActorId", "ActorName", "Source")
            VALUES (@key, @value, 1, COALESCE((SELECT "Revision" FROM "SettingsState" WHERE "Id" = 1), 0), @now, NULL, @actor, @source)
            ON CONFLICT ("Key") DO NOTHING
            """, connection))
        {
            insert.Parameters.AddWithValue("key", Key);
            insert.Parameters.AddWithValue("value", JsonSerializer.Serialize(derived));
            insert.Parameters.AddWithValue("now", DateTime.UtcNow);
            insert.Parameters.AddWithValue("actor", actor ?? StartActor);
            insert.Parameters.AddWithValue("source", SettingsSource.Startup);
            inserted = await insert.ExecuteNonQueryAsync(cancellationToken);
        }

        (_, stored) = await ReadStoredAsync(connection, cancellationToken);
        return new InstanceIdStoreResult(
            inserted == 1 ? InstanceIdStoreCase.StoredNow : stored == null ? InstanceIdStoreCase.Unusable : InstanceIdStoreCase.AlreadyStored,
            stored, derived);
    }

    /// <summary>
    /// The fingerprint the identifier is taken from when it is first stored: the SHA-256 of the
    /// public key of the system signing CA, as the <c>Keystores</c> rows pin it
    /// (<c>SigningCaSpkiSha256</c>), trimmed and in lower case. Null when no row carries a pin:
    /// an install from before the pin that was never backfilled.
    /// </summary>
    /// <param name="connection">An open connection to the application database.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    public static async Task<string?> DeriveAsync(NpgsqlConnection connection, CancellationToken cancellationToken = default)
    {
        await using var command = new NpgsqlCommand(
            """SELECT "SigningCaSpkiSha256" FROM "Keystores" WHERE "SigningCaSpkiSha256" IS NOT NULL AND "SigningCaSpkiSha256" <> '' ORDER BY "Id" LIMIT 1""",
            connection);
        var pin = (await command.ExecuteScalarAsync(cancellationToken) as string)?.Trim().ToLowerInvariant();
        return string.IsNullOrEmpty(pin) ? null : pin;
    }

    /// <summary>
    /// The stored row. <c>Exists</c> is false when there is none, and also when the database has
    /// no <c>Settings</c> table at all (a database from before the settings store, read by a host
    /// command). <c>Id</c> is null for a row that holds anything other than a non-empty JSON
    /// string: such a row is there, so nothing is derived in its place and nothing replaces it.
    /// </summary>
    /// <param name="connection">An open connection to the application database.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    public static async Task<(bool Exists, string? Id)> ReadStoredAsync(NpgsqlConnection connection, CancellationToken cancellationToken = default)
    {
        object? value;
        try
        {
            await using var command = new NpgsqlCommand("""SELECT "ValueJson" FROM "Settings" WHERE "Key" = @key""", connection);
            command.Parameters.AddWithValue("key", Key);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
                return (false, null);
            value = reader.IsDBNull(0) ? null : reader.GetString(0);
        }
        catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.UndefinedTable)
        {
            return (false, null);
        }

        if (value is not string json)
            return (true, null);
        try
        {
            using var document = JsonDocument.Parse(json);
            var id = document.RootElement.ValueKind == JsonValueKind.String ? document.RootElement.GetString()?.Trim() : null;
            return (true, string.IsNullOrEmpty(id) ? null : id);
        }
        catch (JsonException)
        {
            return (true, null);
        }
    }
}
