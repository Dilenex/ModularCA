import { describe, expect, it } from 'vitest';
import { hsmCardView, type HsmSummary } from '@adminui/pages/settingsHsm';

// Bug hunt 2026-11: the Settings page's HSM card read config.hsm, which GET /admin/config never
// returned, so it said Disabled on every install, HSM or not. The API now sends a read-only
// summary, and the card shows it, or says a remote signer holds the settings.
const inProcess = (over: Partial<HsmSummary> = {}): HsmSummary => ({
    heldBy: 'node',
    signerEndpoint: null,
    enabled: true,
    modulePath: '/usr/lib/softhsm/libsofthsm2.so',
    slotId: '1234567890123',
    keyMappings: [{ caLabel: 'root-ca', keyLabel: 'root-key' }],
    ...over,
});

const row = (view: ReturnType<typeof hsmCardView>, label: string) => view.rows.find((r) => r.label === label)?.value;

describe('Settings HSM card', () => {
    it('shows what is in force when the signer runs in process', () => {
        const view = hsmCardView(inProcess());
        expect(view.description).toBe('Enabled');
        expect(row(view, 'Enabled')).toBe('Yes');
        expect(row(view, 'Module Path')).toBe('/usr/lib/softhsm/libsofthsm2.so');
        // Kept as text: as a number this slot id would lose its last digits.
        expect(row(view, 'Slot ID')).toBe('1234567890123');
        expect(row(view, 'Key Mappings')).toBe('root-ca → root-key');
        expect(view.note).toContain("this host's config.yaml");
    });

    it('reports an HSM that is off as off, with what is unset said so', () => {
        const view = hsmCardView(inProcess({ enabled: false, modulePath: '', slotId: '0', keyMappings: [] }));
        expect(view.description).toBe('Disabled');
        expect(row(view, 'Enabled')).toBe('No');
        expect(row(view, 'Module Path')).toBe('Not set');
        expect(row(view, 'Key Mappings')).toBe('None');
    });

    // 0.4.4: a remote signer reports its HSM settings in its health answer, and the card shows them.
    it('shows what a remote signer reported, and says it is the signer that holds them', () => {
        const view = hsmCardView({
            heldBy: 'signer', signerEndpoint: 'https://signer.internal:8446',
            enabled: true, modulePath: '/opt/hsm/lib/libcs_pkcs11_R3.so', slotId: '18446744073709551000',
            keyMappings: [{ caLabel: 'root-ca', keyLabel: 'root-key-2026' }, { caLabel: 'issuing-ca', keyLabel: 'issuing-key-2026' }],
        });
        expect(view.description).toBe('Enabled on the signer');
        expect(view.rows[0]).toEqual({ label: 'Signer', value: 'https://signer.internal:8446', mono: true });
        expect(row(view, 'Enabled')).toBe('Yes');
        expect(row(view, 'Module Path')).toBe('/opt/hsm/lib/libcs_pkcs11_R3.so');
        // Above 2^53: kept as the text the API sent.
        expect(row(view, 'Slot ID')).toBe('18446744073709551000');
        expect(row(view, 'Key Mappings')).toBe('root-ca → root-key-2026, issuing-ca → issuing-key-2026');
        // Where to change them is the signer's file, not this host's.
        expect(view.note).toContain('signer.yaml');
        expect(view.note).not.toContain("this host's config.yaml");
        expect(view.note).toContain('The PIN is never shown');
    });

    it('reports a remote signer whose HSM is off as off on the signer', () => {
        const view = hsmCardView({
            heldBy: 'signer', signerEndpoint: 'https://signer.internal:8446',
            enabled: false, modulePath: '', slotId: '0', keyMappings: [],
        });
        expect(view.description).toBe('Disabled on the signer');
        expect(row(view, 'Enabled')).toBe('No');
        expect(row(view, 'Module Path')).toBe('Not set');
        expect(row(view, 'Key Mappings')).toBe('None');
    });

    it('says a remote signer holds the settings instead of showing blanks', () => {
        const view = hsmCardView({
            heldBy: 'signer', signerEndpoint: 'https://signer.internal:8446',
            enabled: null, modulePath: null, slotId: null, keyMappings: null,
        });
        expect(view.description).toBe('Held by the signer');
        expect(view.rows).toEqual([{ label: 'Signer', value: 'https://signer.internal:8446', mono: true }]);
        expect(view.note).toContain('signer.yaml');
        // Never reads as an HSM that is off, nor as values the node does not have.
        expect(view.description).not.toBe('Disabled');
        expect(row(view, 'Enabled')).toBeUndefined();
    });

    it('does not call the HSM off when the server sent no hsm section', () => {
        for (const missing of [undefined, null]) {
            const view = hsmCardView(missing);
            expect(view.description).toBe('Not reported');
            expect(view.rows).toEqual([]);
        }
    });
});
