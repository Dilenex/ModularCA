using ModularCA.Auth.Interfaces;
using ModularCA.Core.Services.Settings;
using ModularCA.Shared.Models.Config;
using ModularCA.Shared.Settings;
using ModularCA.Shared.Utils;

namespace ModularCA.API.Controllers.v1.Admin;

/// <summary>
/// How a settings endpoint saves the configuration it has just changed in memory. Every one of
/// them goes through here, so there is one answer to where a setting is kept: the settings store
/// for an instance-wide setting once the settings have been moved there, and <c>config.yaml</c>
/// for the rest.
/// </summary>
internal static class ConfigSave
{
    /// <summary>
    /// Saves the configuration: the instance-wide settings that changed to the settings store
    /// when it is in use, and the file. The caller named in the store's history is
    /// <paramref name="currentUser"/>.
    /// </summary>
    /// <exception cref="SettingsRefusedException">The store refused the change; the file was not written.</exception>
    public static async Task SaveAsync(HttpContext? http, SystemConfig config, EnvVarConfigOverlay environment, ICurrentUserService currentUser)
    {
        var persistence = http?.RequestServices?.GetService<SettingsPersistence>();
        var store = http?.RequestServices?.GetService<ISettingsStore>();
        if (persistence == null || store == null)
        {
            WriteWholeFile(config, environment);
            return;
        }

        await currentUser.EnsureLoadedAsync();
        var actor = new SettingsActor(currentUser.User?.Id, currentUser.User?.Username ?? "unknown",
            http!.Connection.RemoteIpAddress?.ToString());
        await persistence.SaveAsync(store, actor, cancellationToken: http.RequestAborted);
    }

    /// <summary>Writes the file only, for a change to settings that belong to the host.</summary>
    public static void WriteFile(HttpContext? http, SystemConfig config, EnvVarConfigOverlay environment)
    {
        var persistence = http?.RequestServices?.GetService<SettingsPersistence>();
        if (persistence != null)
            persistence.WriteFile();
        else
            WriteWholeFile(config, environment);
    }

    /// <summary>The whole configuration to <c>config.yaml</c>, as it was written before there was a settings store.</summary>
    private static void WriteWholeFile(SystemConfig config, EnvVarConfigOverlay environment)
    {
        Exception? failure = null;
        environment.WithSecretsProtected(config, () =>
        {
            try
            {
                ConfigYamlWriter.Write(Path.Combine(AppContext.BaseDirectory, "config", "config.yaml"), config);
            }
            catch (Exception ex)
            {
                failure = ex;
            }
        });
        if (failure != null)
            throw failure;
    }
}
