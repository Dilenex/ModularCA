import { describe, expect, it } from 'vitest';
import { renameColumnKeys } from '@shared/tablePrefsKeys';

/**
 * A renamed column keeps its stored layout. The CA list's space column was keyed 'tenant' before
 * 0.4.0; a width or a hidden flag stored under that key now applies to 'space'.
 */
describe('renameColumnKeys', () => {
    const renamed = { tenant: 'space' };

    it('moves a stored width and hidden flag to the new key', () => {
        expect(renameColumnKeys({ widths: { tenant: 180, name: 240 }, hidden: ['tenant', 'expires'] }, renamed))
            .toEqual({ widths: { space: 180, name: 240 }, hidden: ['expires', 'space'] });
    });

    it('lets a value already stored under the new key win', () => {
        expect(renameColumnKeys({ widths: { tenant: 180, space: 120 }, hidden: ['tenant', 'space'] }, renamed))
            .toEqual({ widths: { space: 120 }, hidden: ['space'] });
    });

    it('returns the layout unchanged when nothing was stored under an old key', () => {
        const prefs = { widths: { name: 240 }, hidden: ['expires'] };
        expect(renameColumnKeys(prefs, renamed)).toBe(prefs);
        expect(renameColumnKeys(prefs, undefined)).toBe(prefs);
    });
});
