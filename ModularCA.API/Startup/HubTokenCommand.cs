using System.Text.Json.Nodes;
using ModularCA.Auth.Services;
using ModularCA.Core.Services.Hub;
using ModularCA.Shared.Enums;
using ModularCA.Shared.Interfaces;
using ModularCA.Shared.Settings;

namespace ModularCA.API.Startup;

/// <summary>
/// The host commands for the hub's affiliation token:
/// <list type="bullet">
/// <item><c>--new-hub-token</c> generates a token and prints it with its hash and the
/// bootstrap.yaml line that carries the hash, for whoever stands in for a hub. It touches nothing
/// and needs no database.</item>
/// <item><c>--set-hub-token-hash &lt;64 hex digits&gt;</c> sets or replaces the hash an existing
/// instance holds, which is how an instance made before there was a token is given one.
/// <c>--set-hub-token-hash none</c> removes it, which turns the token check off. Like
/// <see cref="ClaimTokenCommand"/> it runs on the host as the service user with the credentials
/// in db.yaml, never over HTTP, and is recorded in the audit trail as
/// <see cref="AuditActionType.HubAffiliationTokenReplaced"/>. A running node reads the hash at
/// start, so restart it for the change to take effect.</item>
/// </list>
/// Only the hash ever reaches the instance; the token is the hub's.
/// </summary>
public static class HubTokenCommand
{
    /// <summary>The flag that generates a token and prints its hash.</summary>
    public const string NewFlag = "--new-hub-token";

    /// <summary>The flag, followed by a hash or <c>none</c>, that sets the hash an instance holds.</summary>
    public const string SetFlag = "--set-hub-token-hash";

    /// <summary>The value that removes the hash.</summary>
    public const string None = "none";

    /// <summary>The usage line printed for missing or wrong arguments.</summary>
    public const string Usage = "Usage: --set-hub-token-hash <64 hex digits | none>   (run as the service user after bootstrap; restart the node afterwards)";

    /// <summary>Prints a new token, its hash and the bootstrap.yaml line holding the hash. Returns 0.</summary>
    /// <param name="output">Where they are written.</param>
    public static int RunNew(TextWriter output)
    {
        var token = AccountClaims.NewToken();
        var hash = AccountClaims.HashHex(token);
        output.WriteLine("Affiliation token. It is shown only this once; the hub keeps it and sends it with every request:");
        output.WriteLine();
        output.WriteLine($"    {token}");
        output.WriteLine();
        output.WriteLine("Its SHA-256, which is all the instance holds:");
        output.WriteLine();
        output.WriteLine($"    {hash}");
        output.WriteLine();
        output.WriteLine("Lines for bootstrap.yaml (the hash only; the token never goes in the file):");
        output.WriteLine();
        output.WriteLine("Hub:");
        output.WriteLine($"  AffiliationTokenSha256: \"{hash}\"");
        output.WriteLine();
        output.WriteLine($"For an instance that already exists:  {SetFlag} {hash}");
        return 0;
    }

    /// <summary>
    /// Sets, replaces or removes the hash in the settings store and records it. Returns the
    /// process exit code: 0 on success, 1 when <paramref name="value"/> is neither a SHA-256 nor
    /// <c>none</c>, 2 when the store refused the write.
    /// </summary>
    /// <param name="store">The settings store, with the db.yaml credentials.</param>
    /// <param name="audit">The audit trail.</param>
    /// <param name="value">The hash as 64 hex digits, or <c>none</c>.</param>
    /// <param name="output">Where the outcome is written.</param>
    /// <param name="error">Where a refusal is written.</param>
    public static async Task<int> RunSetAsync(ISettingsStore store, IAuditService audit, string? value, TextWriter output, TextWriter error)
    {
        var remove = string.Equals(value?.Trim(), None, StringComparison.OrdinalIgnoreCase);
        if (!remove && !AccountClaims.TryParseHashHex(value, out _))
        {
            error.WriteLine("That is not a SHA-256: give the hash of the hub's affiliation token as 64 hex digits, never the token itself.");
            error.WriteLine(Usage);
            return 1;
        }
        var hash = remove ? "" : value!.Trim().ToLowerInvariant();
        var actor = $"host:{Environment.MachineName}:{Environment.UserName}";
        try
        {
            await store.WriteAsync(new SettingsChange
            {
                Set = new Dictionary<string, JsonNode?> { [NodeHubOperations.TokenHashKey] = JsonValue.Create(hash) },
                Actor = new SettingsActor(null, actor),
                Source = SettingsSource.Cli,
                Reason = remove ? "The hub's affiliation token hash was removed on the host" : "The hub's affiliation token hash was set on the host",
            });
        }
        catch (SettingsRefusedException ex)
        {
            error.WriteLine($"The settings store refused the change: {ex.Message}");
            return 2;
        }

        try
        {
            await audit.LogAsync(AuditActionType.HubAffiliationTokenReplaced, null, actor, "HubAffiliationToken", null,
                new { Removed = remove, Source = "host command", Host = Environment.MachineName, OsUser = Environment.UserName });
        }
        catch (Exception ex)
        {
            output.WriteLine($"WARNING: the change stands, and its own audit record could not be written ({ex.GetType().Name}: {ex.Message}).");
        }

        output.WriteLine(remove
            ? "The instance now holds no affiliation token hash: the token check on the hub's local connection is off."
            : "The instance now holds that hash: a request on the hub's local connection must carry the token it is the hash of.");
        output.WriteLine("A running node read the old value when it started. Restart it for this to take effect.");
        return 0;
    }
}
