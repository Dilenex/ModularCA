namespace ModularCA.Shared.Models.Config;

/// <summary>
/// What the console's Settings page may show of the HSM settings: read-only, and never the PIN.
/// <para>
/// The <c>Hsm</c> settings are signer-local (<see cref="ModularCA.Shared.Settings.SettingClass.SignerLocal"/>).
/// With the signer in the node's process they are read from this host's <c>config.yaml</c>, so the
/// node can say what is in force. With a remote signer they live in the signer's own
/// <c>signer.yaml</c>, and whatever this node's file still carries is not what the signer uses
/// (the pod removes it once the signer holds its own copy), so nothing is taken from this node's
/// file: what is reported is what the signer itself says in its health answer
/// (<see cref="ModularCA.Shared.Signing.SignerHealth.Hsm"/>), and only where the settings are
/// kept when the signer did not say (it did not answer, or predates the field).
/// </para>
/// </summary>
/// <param name="HeldBy">
/// <see cref="HeldByNode"/> when this node's process holds the HSM settings;
/// <see cref="HeldBySigner"/> when a remote signer does. Then every other field but
/// <paramref name="SignerEndpoint"/> is what the signer reported, or null when it reported nothing.
/// </param>
/// <param name="SignerEndpoint">The remote signer's address, for the page to name it; null in process.</param>
/// <param name="Enabled">Whether the HSM is switched on; null when a remote signer did not report.</param>
/// <param name="ModulePath">The PKCS#11 module path, empty when none is set; null when a remote signer did not report.</param>
/// <param name="SlotId">
/// The PKCS#11 slot, as decimal text so a slot id above 2^53 survives JavaScript; null when a
/// remote signer did not report.
/// </param>
/// <param name="KeyMappings">Which HSM key label each CA uses; null when a remote signer did not report.</param>
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
    public static HsmSettingsSummary From(SystemConfig config) => From(config, null);

    /// <summary>
    /// The summary for this node. With the signer in process it is this node's configuration and
    /// <paramref name="signerHsm"/> is not looked at. With a remote signer it is what the signer
    /// reported in <paramref name="signerHsm"/>, or only where the settings are kept when that is
    /// null; this node's own <c>Hsm</c> section is never reported for a remote signer.
    /// </summary>
    /// <param name="config">This node's configuration.</param>
    /// <param name="signerHsm">What the remote signer's health answer said of its HSM; null when it said nothing.</param>
    public static HsmSettingsSummary From(SystemConfig config, ModularCA.Shared.Signing.SignerHsmStatus? signerHsm)
    {
        if (config.Signer.IsRemote)
        {
            return signerHsm == null
                ? new HsmSettingsSummary(HeldBySigner, config.Signer.Endpoint, null, null, null, null)
                : new HsmSettingsSummary(
                    HeldBySigner,
                    config.Signer.Endpoint,
                    signerHsm.Enabled,
                    signerHsm.ModulePath,
                    signerHsm.SlotId.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    signerHsm.KeyLabels.Select(l => new HsmKeyMappingSummary(l.CaLabel, l.KeyLabel)).ToList());
        }

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
