namespace ModularCA.Shared.Settings;

/// <summary>
/// Where a setting lives, which decides whether it can move to the database. See section 1 of
/// <c>docs/architecture/settings-store.md</c>.
/// </summary>
public enum SettingClass
{
    /// <summary>Needed before the database can be reached. Stays in <c>db.yaml</c> and <c>config.yaml</c>.</summary>
    Bootstrap,

    /// <summary>Read by the signer role only. Stays in the signer's own directory.</summary>
    SignerLocal,

    /// <summary>Differs per host by nature: listeners, files, paths, network position. Stays in that host's <c>config.yaml</c>.</summary>
    HostLocal,

    /// <summary>One value for the whole instance, every role on every host. Stored in the database.</summary>
    InstanceWide,

    /// <summary>Instance-wide and secret. Stored in the database wrapped or hashed, never as itself.</summary>
    Secret,
}

/// <summary>How a change to a setting reaches a running process once its reader takes it from the store.</summary>
public enum SettingReload
{
    /// <summary>The next call sees the new value.</summary>
    Live,

    /// <summary>One component rebuilds itself on the change.</summary>
    Component,

    /// <summary>The process must restart.</summary>
    Restart,
}

/// <summary>How a <see cref="SettingClass.Secret"/> setting is kept.</summary>
public enum SettingSecretKind
{
    /// <summary>Not a secret.</summary>
    None,

    /// <summary>A secret the node has to use, so it is stored wrapped by the signer.</summary>
    Wrapped,

    /// <summary>A secret the node only has to verify, so it is stored as a hash.</summary>
    Hashed,
}

/// <summary>
/// Declares, on one leaf property of <see cref="Models.Config.SystemConfig"/>, where the setting
/// lives and how a change to it reloads. Every leaf carries one: <see cref="SettingsCatalog"/>
/// refuses to build without it, so a new setting cannot inherit an answer by accident.
/// </summary>
/// <param name="settingClass">Where the setting lives.</param>
/// <param name="reload">How a change reloads.</param>
[AttributeUsage(AttributeTargets.Property, AllowMultiple = false, Inherited = false)]
public sealed class SettingAttribute(SettingClass settingClass, SettingReload reload) : Attribute
{
    /// <summary>Where the setting lives.</summary>
    public SettingClass Class { get; } = settingClass;

    /// <summary>How a change reloads.</summary>
    public SettingReload Reload { get; } = reload;

    /// <summary>How the value is kept when <see cref="Class"/> is <see cref="SettingClass.Secret"/>.</summary>
    public SettingSecretKind Secret { get; init; } = SettingSecretKind.None;
}
