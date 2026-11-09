import { describe, expect, it } from 'vitest';
import { PasswordSource } from '@shared/generated';
import { PASSWORD_SOURCES, PASSWORD_SOURCE_TEXT, accountPasswordSource, storedPasswordSourceName } from '@adminui/pages/passwordSource';

describe('password source controls', () => {
    it('lists the three sources in the server enum order, each with a label and help text', () => {
        expect(PASSWORD_SOURCES).toEqual(['Inherit', 'Local', 'Directory']);
        expect(Object.values(PasswordSource)).toEqual([...PASSWORD_SOURCES]);
        for (const s of PASSWORD_SOURCES) {
            expect(PASSWORD_SOURCE_TEXT[s].label).toBe(s);
            expect(PASSWORD_SOURCE_TEXT[s].hint.length).toBeGreaterThan(0);
        }
    });

    it('reads an account record, defaulting to Inherit when the field is missing or unknown', () => {
        expect(accountPasswordSource({ passwordSource: 'Directory' })).toBe('Directory');
        expect(accountPasswordSource({ passwordSource: 'Local' })).toBe('Local');
        expect(accountPasswordSource({})).toBe('Inherit');
        expect(accountPasswordSource(null)).toBe('Inherit');
        expect(accountPasswordSource({ passwordSource: 'Bogus' as PasswordSource })).toBe('Inherit');
    });

    it('names a source stored as its number in ceremony parameters, and passes a name through', () => {
        expect(storedPasswordSourceName(0)).toBe('Inherit');
        expect(storedPasswordSourceName(1)).toBe('Local');
        expect(storedPasswordSourceName(2)).toBe('Directory');
        expect(storedPasswordSourceName(7)).toBe('7');
        expect(storedPasswordSourceName('Local')).toBe('Local');
    });
});
