namespace ModularCA.Shared.Settings;

/// <summary>
/// Keys of the <c>Settings</c> table that are not settings: rows the instance writes about
/// itself, kept in the settings store because that is what lives in the application database
/// and travels with it and its backups. Nobody sets one. No property of
/// <see cref="ModularCA.Shared.Models.Config.SystemConfig"/> stands behind one, so it is in no
/// <c>config.yaml</c>, no environment variable supplies it, and the move out of the file never
/// sees it; and <see cref="ISettingsStore.WriteAsync"/> refuses a change that names one
/// (<see cref="SettingsRefusal.WrittenOnce"/>), which closes the settings API, the console, the
/// host command and the hub at once.
/// </summary>
public static class ReservedSettingKeys
{
    /// <summary>
    /// The instance's identifier: written once, at the first start of a build that stores it,
    /// and never changed afterwards. See <c>ModularCA.Core.Services.Settings.InstanceIdentity</c>.
    /// </summary>
    public const string InstanceId = "Instance_Id";

    /// <summary>
    /// Whether <paramref name="key"/> is a reserved key. Compared without regard to case, so no
    /// setting can be added whose key differs from a reserved one only by case.
    /// </summary>
    /// <param name="key">A key of the <c>Settings</c> table.</param>
    public static bool IsReserved(string? key) => string.Equals(key, InstanceId, StringComparison.OrdinalIgnoreCase);
}
