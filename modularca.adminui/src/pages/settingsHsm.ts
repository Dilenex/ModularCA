/*
 * What the Settings page's HSM card shows, from the `hsm` section of GET /api/v1/admin/config.
 * No React here, so it is covered by tests/modularca.web.tests.
 *
 * Bug hunt 2026-11: the card read `config.hsm`, which the response never carried, so it always
 * said Disabled, No and Not configured, even on a CA whose keys are on an HSM. The API now sends a
 * read-only summary (HsmSettingsSummary). The HSM settings are signer-local: with the signer in
 * the node's process they are this host's config.yaml and the summary says what is in force; with
 * a remote signer they are in the signer's own signer.yaml, and the node reports only that.
 */

/** The `hsm` section as the API sends it. It never carries the PIN. */
export interface HsmSummary {
    /** `node`: the signer runs in this process and the settings below are in force. `signer`: a remote signer holds them. */
    heldBy: 'node' | 'signer';
    /** The remote signer's address; null in process. */
    signerEndpoint: string | null;
    enabled: boolean | null;
    modulePath: string | null;
    /** Decimal text, so a large slot id keeps its digits. */
    slotId: string | null;
    keyMappings: { caLabel: string; keyLabel: string }[] | null;
}

/** One read-only row of the card. */
export interface HsmRow {
    label: string;
    value: string;
    mono?: boolean;
}

/** The card: the header's summary, its rows, and the sentence under them saying where the settings are kept. */
export interface HsmCardView {
    description: string;
    rows: HsmRow[];
    note: string;
}

/**
 * The HSM card for a `hsm` section, or for none: a server that predates the section sends
 * nothing, and the card says it cannot tell rather than report the HSM off.
 */
export function hsmCardView(hsm: HsmSummary | null | undefined): HsmCardView {
    if (!hsm || (hsm.heldBy !== 'node' && hsm.heldBy !== 'signer')) {
        return {
            description: 'Not reported',
            rows: [],
            note: 'This server did not report its HSM settings. Check Hsm in the configuration file of the host that runs the signer.',
        };
    }

    if (hsm.heldBy === 'signer') {
        return {
            description: 'Held by the signer',
            rows: hsm.signerEndpoint ? [{ label: 'Signer', value: hsm.signerEndpoint, mono: true }] : [],
            note: "This node reaches a remote signer, which keeps the HSM settings in its own signer.yaml. "
                + 'This node does not hold them, so they cannot be shown here: check Hsm in signer.yaml on the signer host.',
        };
    }

    const mappings = hsm.keyMappings ?? [];
    const rows: HsmRow[] = [
        { label: 'Enabled', value: hsm.enabled ? 'Yes' : 'No' },
        { label: 'Module Path', value: hsm.modulePath || 'Not set', mono: !!hsm.modulePath },
        { label: 'Slot ID', value: hsm.slotId ?? 'Not set', mono: hsm.slotId != null },
        {
            label: 'Key Mappings',
            value: mappings.length === 0 ? 'None' : mappings.map((m) => `${m.caLabel} → ${m.keyLabel}`).join(', '),
        },
    ];
    return {
        description: hsm.enabled ? 'Enabled' : 'Disabled',
        rows,
        note: "The signer runs in this node's process and reads these from Hsm in this host's config.yaml at start; "
            + 'change them there and restart. The PIN is never shown.',
    };
}
