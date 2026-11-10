using ModularCA.Shared.Models.Config;

namespace ModularCA.Shared.Signing;

/// <summary>
/// What a signer says of its HSM settings, as it loaded them at start: whether the HSM is on,
/// the PKCS#11 module, the slot, and which key label each CA uses. It is made to be shown, so it
/// has no field for the PIN or for a mapping's key id, and neither ever crosses the signer
/// channel.
/// </summary>
/// <param name="Enabled">Whether the signer runs with its HSM on.</param>
/// <param name="ModulePath">The PKCS#11 module path; empty when none is set.</param>
/// <param name="SlotId">The PKCS#11 slot.</param>
/// <param name="KeyLabels">Which HSM key label each CA uses.</param>
public sealed record SignerHsmStatus(bool Enabled, string ModulePath, ulong SlotId, IReadOnlyList<SignerHsmKeyLabel> KeyLabels)
{
    /// <summary>
    /// The status for a signer's <c>Hsm</c> settings. Copies only the fields named on the
    /// record, so <see cref="HsmConfig.Pin"/> and each mapping's key id stay where they are.
    /// </summary>
    public static SignerHsmStatus From(HsmConfig? hsm)
    {
        hsm ??= new HsmConfig();
        return new SignerHsmStatus(
            hsm.Enabled,
            hsm.ModulePath ?? string.Empty,
            hsm.SlotId,
            (hsm.KeyMappings ?? []).Select(m => new SignerHsmKeyLabel(m.CaLabel ?? string.Empty, m.KeyLabel ?? string.Empty)).ToList());
    }
}

/// <summary>One CA's HSM key as the signer reports it: the CA label and the key's PKCS#11 label.</summary>
/// <param name="CaLabel">The CA label the mapping is for.</param>
/// <param name="KeyLabel">The key's PKCS#11 label (CKA_LABEL) on the token.</param>
public sealed record SignerHsmKeyLabel(string CaLabel, string KeyLabel);
