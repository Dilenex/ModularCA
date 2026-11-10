namespace ModularCA.Shared.Models.Config;

/// <summary>
/// What the console's Settings page may show of the HSM settings: read-only, and never the PIN.
/// <para>
/// The <c>Hsm</c> settings are signer-local (<see cref="ModularCA.Shared.Settings.SettingClass.SignerLocal"/>).
/// With the signer in the node's process they are read from this host's <c>config.yaml</c>, so the
/// node can say what is in force. With a remote signer they live in the signer's own
/// <c>signer.yaml</c>, and whatever this node's file still carries is not what the signer uses
/// (the pod removes it once the signer holds its own copy), so nothing but where they are kept is
/// reported.
/// </para>
/// </summary>
/// <param name="HeldBy">
/// <see cref="HeldByNode"/> when this node's process holds the HSM settings;
/// <see cref="HeldBySigner"/> when a remote signer does, and every other field but
/// <paramref name="SignerEndpoint"/> is null.
/// </param>
/// <param name="SignerEndpoint">The remote signer's address, for the page to name it; null in process.</param>
/// <param name="Enabled">Whether the HSM is switched on; null when the signer holds the settings.</param>
/// <param name="ModulePath">The PKCS#11 module path, empty when none is set; null when the signer holds the settings.</param>
/// <param name="SlotId">
/// The PKCS#11 slot, as decimal text so a slot id above 2^53 survives JavaScript; null when the
/// signer holds the settings.
/// </param>
/// <param name="KeyMappings">Which HSM key label each CA uses; null when the signer holds the settings.</param>
public sealed record HsmSettingsSummary(
    string HeldBy,
    string? SignerEndpoint,
    bool? Enabled,
    string? ModulePath,
    string? SlotId,
    IReadOnlyList<HsmKeyMappingSummary>? KeyMappings)
{
    /// <summary>This node's process holds the HSM settings: the signer runs in process.</summary>
    public const string HeldByNode = "node";

    /// <summary>A remote signer holds the HSM settings in its own directory.</summary>
    public const string HeldBySigner = "signer";

    /// <summary>
    /// The summary for this node's configuration. Copies only the fields named on the record, so
    /// <see cref="HsmConfig.Pin"/> and each mapping's key id never leave the process.
    /// </summary>
    public static HsmSettingsSummary From(SystemConfig config)
    {
        if (config.Signer.IsRemote)
            return new HsmSettingsSummary(HeldBySigner, config.Signer.Endpoint, null, null, null, null);

        var hsm = config.Hsm ?? new HsmConfig();
        return new HsmSettingsSummary(
            HeldByNode,
            null,
            hsm.Enabled,
            hsm.ModulePath ?? string.Empty,
            hsm.SlotId.ToString(System.Globalization.CultureInfo.InvariantCulture),
            (hsm.KeyMappings ?? []).Select(m => new HsmKeyMappingSummary(m.CaLabel, m.KeyLabel)).ToList());
    }
}

/// <summary>One CA's HSM key, as the Settings page shows it: the CA label and the key's PKCS#11 label.</summary>
/// <param name="CaLabel">The CA label the mapping is for.</param>
/// <param name="KeyLabel">The key's PKCS#11 label (CKA_LABEL) on the token.</param>
public sealed record HsmKeyMappingSummary(string CaLabel, string KeyLabel);
