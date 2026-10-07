using ModularCA.Shared.Settings;

namespace ModularCA.Shared.Models.Config;

/// <summary>
/// Configuration for PKCS#11 HSM integration. When enabled, CA private keys
/// can be stored on hardware security modules instead of software keystores.
/// </summary>
public class HsmConfig
{
    /// <summary>Whether HSM support is enabled.</summary>
    [Setting(SettingClass.SignerLocal, SettingReload.Restart)]
    public bool Enabled { get; set; } = false;

    /// <summary>Path to the PKCS#11 module (.so on Linux, .dll on Windows).</summary>
    [Setting(SettingClass.SignerLocal, SettingReload.Restart)]
    public string ModulePath { get; set; } = string.Empty;

    /// <summary>PKCS#11 slot ID to use.</summary>
    [Setting(SettingClass.SignerLocal, SettingReload.Restart)]
    public ulong SlotId { get; set; } = 0;

    /// <summary>PIN for authenticating to the HSM token.</summary>
    [Setting(SettingClass.SignerLocal, SettingReload.Restart)]
    public string Pin { get; set; } = string.Empty;

    /// <summary>Mappings from CA labels to HSM key labels.</summary>
    [Setting(SettingClass.SignerLocal, SettingReload.Restart)]
    public List<HsmKeyMapping> KeyMappings { get; set; } = new();
}

/// <summary>
/// Maps a CA label to an HSM key label/ID for key lookup during startup.
/// </summary>
public class HsmKeyMapping
{
    /// <summary>The CA label (matches CertificateAuthorityEntity.Label).</summary>
    public string CaLabel { get; set; } = string.Empty;

    /// <summary>The PKCS#11 key label (CKA_LABEL) on the HSM.</summary>
    public string KeyLabel { get; set; } = string.Empty;

    /// <summary>Optional hex-encoded CKA_ID for key lookup.</summary>
    public string? KeyId { get; set; }
}
