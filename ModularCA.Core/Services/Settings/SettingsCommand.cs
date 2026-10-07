using System.Text.Json;
using System.Text.Json.Nodes;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Settings;

namespace ModularCA.Core.Services.Settings;

/// <summary>
/// <c>--settings</c>: reading and changing the stored settings from the host, with the service
/// stopped or running. It is the way back in when a setting has locked the administrators out
/// of the console, which is what editing <c>config.yaml</c> used to be before the instance-wide
/// settings left that file.
/// </summary>
/// <remarks>
/// It writes through the same store as the console, so a change made here has the same checks,
/// history entry and audit record, under a host actor. It asks for no step-up: whoever can run
/// it can already read <c>db.yaml</c>. A running service takes the change at its next start.
/// </remarks>
public static class SettingsCommand
{
    /// <summary>The command-line flag.</summary>
    public const string Flag = "--settings";

    /// <summary>How the command is used, for the help text and a mistyped invocation.</summary>
    public const string Usage =
        "Usage (run as the service user, never as root):\n"
        + "  --settings list                              the settings that have been set\n"
        + "  --settings get <Key>                         one setting: its value, where it comes from, its default\n"
        + "  --settings set <Key> <value> [--reason <text>]\n"
        + "  --settings clear <Key> [--reason <text>]     back to the built-in default\n"
        + "  --settings history <Key>\n"
        + "A key is written with underscores (Acme_Http01_MaxAddresses) or dots (Acme.Http01.MaxAddresses).\n"
        + "A value is JSON; plain text is accepted for a text setting. A running service takes a change at its next start.";

    /// <summary>The actor recorded for a change made from the host.</summary>
    public static string Actor => $"host:{Environment.MachineName}:{Environment.UserName}";

    /// <summary>
    /// Runs the command in <paramref name="args"/>, the arguments after <see cref="Flag"/>.
    /// Returns 0 on success, 1 on a mistyped command or an unknown setting, 2 when the store
    /// refused the change.
    /// </summary>
    public static async Task<int> RunAsync(ISettingsStore store, IReadOnlyList<string> args, TextWriter output, TextWriter error,
        CancellationToken cancellationToken = default)
    {
        var positional = new List<string>();
        string? reason = null;
        for (var i = 0; i < args.Count; i++)
        {
            if (string.Equals(args[i], "--reason", StringComparison.OrdinalIgnoreCase))
            {
                if (++i >= args.Count) return Mistyped(error, "--reason takes the reason as its next argument.");
                reason = args[i];
            }
            else
            {
                positional.Add(args[i]);
            }
        }
        if (positional.Count == 0) return Mistyped(error, null);

        var verb = positional[0].ToLowerInvariant();
        switch (verb)
        {
            case "list" when positional.Count == 1:
                return await ListAsync(store, output, cancellationToken);
            case "get" when positional.Count == 2:
            case "history" when positional.Count == 2:
            case "clear" when positional.Count == 2:
            case "set" when positional.Count == 3:
                break;
            default:
                return Mistyped(error, null);
        }

        var definition = Resolve(positional[1], error);
        if (definition == null) return 1;

        if (verb == "get") return await GetAsync(store, definition, output, cancellationToken);
        if (verb == "history") return await HistoryAsync(store, definition, output, cancellationToken);

        if (definition.Class == SettingClass.Secret)
        {
            error.WriteLine($"{definition.Key} is a secret. Secrets are still set in config.yaml on this build, or through the environment.");
            return 2;
        }

        try
        {
            var change = new SettingsChange
            {
                Set = verb == "set"
                    ? new Dictionary<string, JsonNode?> { [definition.Key] = ParseValue(definition, positional[2]) }
                    : new Dictionary<string, JsonNode?>(),
                Clear = verb == "clear" ? [definition.Key] : [],
                Actor = new SettingsActor(null, Actor),
                Source = SettingsSource.Cli,
                Reason = reason,
            };
            var result = await store.WriteAsync(change, cancellationToken);
            if (result.ChangedKeys.Count == 0)
                output.WriteLine($"{definition.Key} already has that value. Nothing was changed.");
            else
                output.WriteLine($"{definition.Key} {(verb == "set" ? "set" : "cleared")} at revision {result.Revision}. Recorded in the audit trail. A running service takes it at its next start.");
            return 0;
        }
        catch (SettingsRefusedException ex)
        {
            error.WriteLine(ex.Message);
            return 2;
        }
    }

    private static int Mistyped(TextWriter error, string? why)
    {
        if (why != null) error.WriteLine(why);
        error.WriteLine(Usage);
        return 1;
    }

    /// <summary>
    /// The setting <paramref name="name"/> names: a key or a dotted path, in any case. Null, with
    /// the reason written, when it names none, or one that is not kept in the database.
    /// </summary>
    private static SettingDefinition? Resolve(string name, TextWriter error)
    {
        var key = name.Replace('.', SettingsCatalog.KeySeparator);
        var matches = SettingsCatalog.Definitions.Where(d => string.Equals(d.Key, key, StringComparison.OrdinalIgnoreCase)).ToList();
        if (matches.Count != 1)
        {
            error.WriteLine($"{name} is not a setting.");
            var near = SettingsCatalog.Definitions
                .Where(d => d.StoredInDatabase && d.Key.Contains(key, StringComparison.OrdinalIgnoreCase))
                .Select(d => d.Key).Take(8).ToList();
            if (near.Count > 0) error.WriteLine("Did you mean: " + string.Join(", ", near));
            return null;
        }
        if (!matches[0].StoredInDatabase)
        {
            error.WriteLine(matches[0].Class == SettingClass.SignerLocal
                ? $"{matches[0].Key} belongs to the signer and is set in the signer's own directory."
                : $"{matches[0].Key} is set per host, in that host's configuration file.");
            return null;
        }
        return matches[0];
    }

    /// <summary>JSON when the text is JSON; otherwise the text itself, for a setting that takes text.</summary>
    private static JsonNode? ParseValue(SettingDefinition definition, string text)
    {
        try
        {
            var parsed = JsonNode.Parse(text);
            if (SettingsCatalog.Problem(definition, parsed) == null)
                return parsed;
        }
        catch (JsonException)
        {
        }
        return JsonValue.Create(text);
    }

    private static async Task<int> ListAsync(ISettingsStore store, TextWriter output, CancellationToken cancellationToken)
    {
        var snapshot = await store.LoadAsync(cancellationToken);
        output.WriteLine(snapshot.ImportedAt == null
            ? "The settings have not been moved to the database yet: config.yaml decides them. The control role moves them at its first start."
            : $"Settings at revision {snapshot.Revision}, moved to the database {snapshot.ImportedAt:yyyy-MM-dd HH:mm} UTC.");
        var set = snapshot.Settings.Values.Where(s => s.ValueJson != null).OrderBy(s => s.Key, StringComparer.Ordinal).ToList();
        if (set.Count == 0)
        {
            output.WriteLine("Every setting is at its default.");
            return 0;
        }
        foreach (var setting in set)
            output.WriteLine($"{setting.Key} = {setting.ValueJson}   (version {setting.Version}, {setting.Source}, {setting.ActorName}, {setting.UpdatedAt:yyyy-MM-dd HH:mm} UTC)");
        return 0;
    }

    private static async Task<int> GetAsync(ISettingsStore store, SettingDefinition definition, TextWriter output, CancellationToken cancellationToken)
    {
        var snapshot = await store.LoadAsync(cancellationToken);
        var defaultJson = SettingsCatalog.CanonicalJson(definition, SettingsCatalog.Read(new SystemConfig(), definition));
        output.WriteLine($"{definition.Key}   ({definition.Path}; a change takes effect: {definition.Reload switch
        {
            SettingReload.Restart => "at the next start",
            _ => "at the next start, until settings reload while the service runs",
        }})");
        if (definition.Class == SettingClass.Secret)
        {
            output.WriteLine("  a secret: set in config.yaml on this build, and never shown.");
            return 0;
        }
        var stored = snapshot.Settings.GetValueOrDefault(definition.Key);
        if (stored?.ValueJson != null)
            output.WriteLine($"  value:   {stored.ValueJson}   (set by {stored.ActorName}, {stored.Source}, {stored.UpdatedAt:yyyy-MM-dd HH:mm} UTC, version {stored.Version})");
        else
            output.WriteLine($"  value:   {defaultJson}   (the default; nothing is stored)");
        output.WriteLine($"  default: {defaultJson}");
        if (snapshot.ImportedAt == null)
            output.WriteLine("  The settings have not been moved to the database yet, so config.yaml still decides this one.");
        return 0;
    }

    private static async Task<int> HistoryAsync(ISettingsStore store, SettingDefinition definition, TextWriter output, CancellationToken cancellationToken)
    {
        var history = await store.HistoryAsync(definition.Key, 100, cancellationToken);
        if (history.Count == 0)
        {
            output.WriteLine($"{definition.Key} has never been changed.");
            return 0;
        }
        foreach (var entry in history)
        {
            var value = definition.Class == SettingClass.Secret ? "(a secret)" : entry.ValueJson ?? "(cleared: the default)";
            output.WriteLine($"revision {entry.Revision}  {entry.ChangedAt:yyyy-MM-dd HH:mm} UTC  {entry.ActorName} ({entry.Source})  {value}{(entry.Reason == null ? "" : $"  reason: {entry.Reason}")}");
        }
        return 0;
    }
}
