using Microsoft.EntityFrameworkCore;
using ModularCA.Core.Services.Settings;
using ModularCA.Database;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Settings;
using ModularCA.Shared.Utils;
using Serilog;

namespace ModularCA.API.Startup;

/// <summary>
/// The identifier step of a start: the control role, once the schema is current and the settings
/// are read, and long before the hub's socket opens, stores the instance's identifier if none is
/// stored (<see cref="InstanceIdentity.EnsureStoredAsync"/>). The first start of a build that has
/// this step writes the fingerprint the instance has then; every later start finds the row and
/// writes nothing, whatever the fingerprint has become. Like the settings step it runs over a
/// connection of its own.
/// <para>
/// It never stops a start. With no fingerprint to store (no keystore row carries a pin) it says
/// why and the next start tries again; a database fault is logged as an error and the next start
/// tries again. Until an identifier is stored, a backup's manifest and <c>hello</c> give the
/// derived fingerprint, as builds before this one did.
/// </para>
/// </summary>
public static class InstanceIdStartup
{
    /// <summary>
    /// Stores the identifier if none is stored, says what it found, and records a first store in
    /// the audit trail. Returns what it found, or null when the database could not be read or written.
    /// </summary>
    /// <param name="config">This host's configuration, for the two databases.</param>
    public static async Task<InstanceIdStoreResult?> RunAsync(SystemConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        try
        {
            var result = await InstanceIdentity.EnsureStoredAsync(PostgresConnection.Build(config.DB.App));
            switch (result.Case)
            {
                case InstanceIdStoreCase.StoredNow:
                    Log.Information("Instance identifier stored: {InstanceId}. It is kept with the instance's data and never changes from here on.", result.Id);
                    Console.WriteLine($"[INSTANCE] Identifier stored: {result.Id}");
                    await AuditAsync(config, result.Id!);
                    break;
                case InstanceIdStoreCase.AlreadyStored when result.Derived != null && result.Derived != result.Id:
                    Log.Information("Instance identifier: {InstanceId}. The system signing CA's fingerprint is now {Derived}; the identifier is the stored one and stays as it is.",
                        result.Id, result.Derived);
                    break;
                case InstanceIdStoreCase.AlreadyStored:
                    Log.Information("Instance identifier: {InstanceId}.", result.Id);
                    break;
                case InstanceIdStoreCase.NothingToStore when result.Derived == null:
                    Log.Warning("No instance identifier is stored and none could be stored: no keystore row carries the pin of the system signing CA "
                        + "(an install from before the pin). Run --backfill-keystore-pins --write; the next start stores the identifier. "
                        + "Until then backups and the hub's hello carry no identifier.");
                    break;
                case InstanceIdStoreCase.NothingToStore:
                    Log.Warning("No instance identifier is stored and none could be stored: the pin of the system signing CA in the Keystores table "
                        + "is not a SHA-256 in hex. The next start tries again.");
                    break;
                case InstanceIdStoreCase.Unusable:
                    Log.Error("The stored instance identifier (the Settings row {Key}) holds no usable value. It is never replaced automatically, "
                        + "so backups and the hub's hello carry no identifier until the row is put right by hand.", InstanceIdentity.Key);
                    break;
            }
            return result;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "The instance identifier could not be read or stored. The start goes on; the next start tries again.");
            Console.Error.WriteLine($"[INSTANCE] The identifier could not be read or stored ({ex.GetType().Name}: {ex.Message}). The start goes on.");
            return null;
        }
    }

    /// <summary>
    /// Records the first store as a <see cref="AuditActionType.ConfigUpdated"/> record under the
    /// host. Written after the row, which is a fact about the instance and not somebody's change:
    /// a record that cannot be written is reported and the identifier stands.
    /// </summary>
    private static async Task AuditAsync(SystemConfig config, string id)
    {
        try
        {
            await using var auditDb = string.IsNullOrWhiteSpace(config.DB.Audit.Database) ? null
                : new AuditDbContext(new DbContextOptionsBuilder<AuditDbContext>()
                    .UseNpgsql(PostgresConnection.Build(config.DB.Audit)).Options);
            if (auditDb == null) return;
            IAuditService audit = new HostAuditService(auditDb);
            await audit.LogAsync(AuditActionType.ConfigUpdated, null, InstanceIdentity.StartActor,
                targetEntityType: "Settings", targetEntityId: InstanceIdentity.Key,
                details: new
                {
                    key = InstanceIdentity.Key,
                    after = id,
                    source = SettingsSource.Startup,
                    reason = "The instance's identifier, stored once at the first start of a build that keeps it. It is never changed afterwards.",
                });
        }
        catch (Exception ex)
        {
            Log.Warning("The instance identifier is stored, and its audit record could not be written ({Kind}: {Message}).", ex.GetType().Name, ex.Message);
        }
    }
}
