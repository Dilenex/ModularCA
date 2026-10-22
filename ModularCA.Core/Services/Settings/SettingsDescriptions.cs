using ModularCA.Shared.Settings;

namespace ModularCA.Core.Services.Settings;

/// <summary>One setting as the console describes it: where it is kept, and when a change to it takes effect. Never its value.</summary>
/// <param name="Key">The store key, with underscores.</param>
/// <param name="Path">The dotted path, as the settings endpoints name fields.</param>
/// <param name="Kept">
/// <c>database</c>: an instance-wide setting or a secret the store decides. <c>host</c>: kept in
/// this host's <c>config.yaml</c>. <c>signer</c>: the signer's own. <c>bootstrap</c>: needed
/// before the database can be reached.
/// </param>
/// <param name="Applies"><c>live</c>: a saved change takes effect at once on the node that saved it. <c>restart</c>: at that node's next start.</param>
/// <param name="Source">
/// Where the value in force comes from: <c>database</c>, <c>default</c> (nothing is stored),
/// <c>environment</c> (an environment variable, which wins and cannot be changed here) or
/// <c>file</c>.
/// </param>
/// <param name="Secret">Whether the value is a secret, which is never shown.</param>
/// <param name="Version">How many times the stored value has been changed; null when nothing is stored.</param>
public sealed record SettingDescription(
    string Key, string Path, string Section, string Kept, string Applies, string Source, bool Secret,
    int? Version, string? UpdatedBy, DateTime? UpdatedAt);

/// <summary>Describes every setting for the console, from the catalog and the stored settings.</summary>
public static class SettingsDescriptions
{
    /// <summary>
    /// Every setting, in catalog order. <paramref name="snapshot"/> is the stored settings this
    /// process runs on, null while the store is not in use; <paramref name="environmentPaths"/>
    /// the dotted paths an environment variable supplies.
    /// </summary>
    public static IReadOnlyList<SettingDescription> Describe(SettingsSnapshot? snapshot, IReadOnlySet<string> environmentPaths)
    {
        var storeInUse = snapshot?.ImportedAt != null;
        var covered = SettingsRuntime.Covered(environmentPaths).Select(d => d.Key)
            .Concat(SettingsRuntime.CoveredSecrets(environmentPaths).Select(d => d.Key))
            .ToHashSet(StringComparer.Ordinal);

        return SettingsCatalog.Definitions.Select(definition =>
        {
            var fromEnvironment = environmentPaths.Contains(definition.Path);
            var decidedByStore = storeInUse && covered.Contains(definition.Key);
            var kept = definition.Class switch
            {
                SettingClass.Bootstrap => "bootstrap",
                SettingClass.SignerLocal => "signer",
                SettingClass.HostLocal => "host",
                // The two single API keys are secrets the store does not take: named keys replace them.
                _ => decidedByStore || fromEnvironment ? "database" : storeInUse && !covered.Contains(definition.Key) ? "host" : "database",
            };

            int? version = null;
            string? updatedBy = null;
            DateTime? updatedAt = null;
            var stored = false;
            if (decidedByStore && definition.Class == SettingClass.Secret && snapshot!.Secrets.TryGetValue(definition.Key, out var secret))
            {
                (version, updatedBy, updatedAt, stored) = (secret.Version, secret.ActorName, secret.UpdatedAt, secret.Value != null);
            }
            else if (decidedByStore && snapshot!.Settings.TryGetValue(definition.Key, out var setting))
            {
                (version, updatedBy, updatedAt, stored) = (setting.Version, setting.ActorName, setting.UpdatedAt, setting.ValueJson != null);
            }

            var source = fromEnvironment ? "environment"
                : !decidedByStore ? "file"
                : stored ? "database"
                // A secret that has not been stored yet is still the file's; an ordinary setting is at its default.
                : definition.Class == SettingClass.Secret && version == null ? "file" : "default";

            return new SettingDescription(
                definition.Key, definition.Path, definition.Section, kept,
                definition.Reload == SettingReload.Live ? "live" : "restart",
                source, definition.Class == SettingClass.Secret, version, updatedBy, updatedAt);
        }).ToList();
    }
}
