import { describe, expect, it } from 'vitest';
import { KEY_USAGE_DESCRIPTIONS, groupEkuOptions, groupSshExtensions, keyUsageOptions } from '@adminui/pages/profiles/pickerCatalogs';
import { DEFAULT_EKU_OPTIONS, KEY_USAGE_OPTIONS } from '@adminui/pages/profiles/profileFormCore';

describe('picker catalogs', () => {
    it('describes every key usage the server can emit', () => {
        for (const ku of KEY_USAGE_OPTIONS) expect(KEY_USAGE_DESCRIPTIONS[ku]).toBeTruthy();
        expect(keyUsageOptions(KEY_USAGE_OPTIONS, (v) => v).map((o) => o.value)).toEqual([...KEY_USAGE_OPTIONS]);
    });

    it('groups the default EKUs and puts anything else under Other', () => {
        const custom = '1.3.6.1.4.1.66874.1';
        const groups = groupEkuOptions([...DEFAULT_EKU_OPTIONS, custom], (oid) => oid);
        expect(groups.map((g) => g.id)).toEqual(['tls', 'signing', 'logon', 'other']);
        expect(groups[0].options.map((o) => o.value)).toEqual(['1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2']);
        expect(groups[3].options.map((o) => o.value)).toEqual(['1.3.6.1.5.5.7.3.9', custom]);
        expect(groups.flatMap((g) => g.options).length).toBe(DEFAULT_EKU_OPTIONS.length + 1);
    });

    it('leaves out empty EKU groups', () => {
        expect(groupEkuOptions(['1.3.6.1.5.5.7.3.1'], (o) => o).map((g) => g.id)).toEqual(['tls']);
    });

    it('splits SSH extensions into permit and deny, marking conflicts', () => {
        const groups = groupSshExtensions(['permit-pty', 'no-pty', 'permit-user-rc'], () => undefined, (e) => (e === 'permit-user-rc' ? 'warn' : undefined));
        expect(groups.map((g) => g.options.map((o) => o.value))).toEqual([['permit-pty', 'permit-user-rc'], ['no-pty']]);
        expect(groups[0].options[1].tone).toBe('warn');
    });
});
