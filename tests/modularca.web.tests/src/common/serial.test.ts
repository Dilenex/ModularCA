import { describe, expect, it } from 'vitest';
import { displaySerial } from '@shared/serial';

/**
 * The server stores a serial as minimal hex; OpenSSL prints whole octets. The consoles show
 * the second, so a serial read in the console matches one read anywhere else.
 */
describe('a serial as the consoles show it', () => {
    it('has a leading zero when the stored form has an odd number of digits', () => {
        expect(displaySerial('2C06C00CB8D82FBE8931387809E6DA6')).toBe('02C06C00CB8D82FBE8931387809E6DA6');
        expect(displaySerial('A')).toBe('0A');
    });

    it('is left as it is when it already has whole octets', () => {
        expect(displaySerial('E8790FF9CBADC6BD5C0D3B1F7A82613E')).toBe('E8790FF9CBADC6BD5C0D3B1F7A82613E');
    });

    it('is empty for nothing, and untouched for anything that is not hex', () => {
        expect(displaySerial(null)).toBe('');
        expect(displaySerial(undefined)).toBe('');
        expect(displaySerial('')).toBe('');
        expect(displaySerial('—')).toBe('—');
    });
});
