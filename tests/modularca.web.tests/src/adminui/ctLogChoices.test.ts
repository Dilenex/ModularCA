import { describe, expect, it } from 'vitest';
import {
    canonicalCtLogIds, ctLogChoicesFromResponse, ctLogDisplay, ctLogIdsFromStored, ctLogIdsToBody, ctLogOptions, noEnabledLogChosen,
    unknownCtLogIds,
} from '@adminui/pages/profiles/ctLogChoices';

/**
 * A cert profile's CtLogIds against the CT log catalog (GET /admin/ct-logs/options): ids in and
 * out, names for display, and the ids the server would refuse because no log has them.
 */
const A = '0b6f3f0e-aaaa-4c4c-9a9a-00000000000a';
const B = '0b6f3f0e-bbbb-4c4c-9a9a-00000000000b';
const logs = ctLogChoicesFromResponse([
    { id: A, name: 'Argon', url: 'https://ct.example/argon', enabled: true },
    { id: B, name: 'Xenon', url: 'https://ct.example/xenon', enabled: false },
    { name: 'no id' },
]);

describe('CT log ids', () => {
    it('reads the catalog, skipping entries without an id', () => {
        expect(logs.map((l) => l.name)).toEqual(['Argon', 'Xenon']);
        expect(ctLogChoicesFromResponse(null)).toEqual([]);
    });

    it('reads stored ids once each, in order, from JSON or anything list-like', () => {
        expect(ctLogIdsFromStored(`["${A}","${B}","${A.toUpperCase()}"]`)).toEqual([A, B]);
        expect(ctLogIdsFromStored(null)).toEqual([]);
        expect(ctLogIdsFromStored('  ')).toEqual([]);
        expect(ctLogIdsFromStored('garbage')).toEqual(['garbage']);
    });

    it('writes null for none and a JSON array otherwise', () => {
        expect(ctLogIdsToBody([])).toBeNull();
        expect(ctLogIdsToBody([A])).toBe(`["${A}"]`);
    });

    it('finds ids that name no log, ignoring case, and judges nothing without the catalog', () => {
        expect(unknownCtLogIds([A.toUpperCase(), 'garbage'], logs)).toEqual(['garbage']);
        expect(unknownCtLogIds(['garbage'], null)).toEqual([]);
        expect(canonicalCtLogIds([A.toUpperCase(), 'garbage'], logs)).toEqual([A, 'garbage']);
    });

    it('offers each log by name with its URL and an enabled badge', () => {
        expect(ctLogOptions(logs)).toEqual([
            { value: A, label: 'Argon', badge: { label: 'Enabled', tone: 'ok' }, description: 'https://ct.example/argon' },
            { value: B, label: 'Xenon', badge: { label: 'Disabled', tone: 'muted' }, description: 'https://ct.example/xenon (skipped at issuance while disabled)' },
        ]);
    });

    it('names stored ids for the read-only view', () => {
        expect(ctLogDisplay(A, logs)).toEqual({ text: 'Argon', tone: 'ok' });
        expect(ctLogDisplay(B, logs).text).toMatch(/disabled/);
        expect(ctLogDisplay('garbage', logs)).toEqual({ text: 'Unknown log (garbage)', tone: 'crit' });
        expect(ctLogDisplay('garbage', null)).toEqual({ text: 'garbage', tone: 'ok' });
    });

    it('notices when only disabled logs are chosen, since nothing is then submitted', () => {
        expect(noEnabledLogChosen([B], logs)).toBe(true);
        expect(noEnabledLogChosen([A, B], logs)).toBe(false);
        expect(noEnabledLogChosen([], logs)).toBe(false);
        expect(noEnabledLogChosen([B], null)).toBe(false);
    });
});
