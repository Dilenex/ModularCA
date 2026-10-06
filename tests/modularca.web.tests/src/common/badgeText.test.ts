import { describe, expect, it } from 'vitest';
import { badgeText } from '@shared/badgeText';

/** Every badge and tag reads with a capital first letter, whatever case the caller passed. */
describe('badge text', () => {
    it('capitalises a lower-case status', () => {
        expect(badgeText('active')).toBe('Active');
        expect(badgeText('never run')).toBe('Never run');
    });

    it('leaves acronyms, protocol names and mixed case as written', () => {
        for (const text of ['OK', 'CA', 'ACME', 'SCEP', 'MSAE', 'Built-in', 'CA (Auto)', '404']) {
            expect(badgeText(text)).toBe(text);
        }
    });
});
