import { describe, expect, it } from 'vitest';
import { adoptionBody, normalizeSerial, serialProblem, tombstoneBody } from '@adminui/components/revokedSerials';

describe('the serial an administrator types for a certificate the CA does not hold', () => {
    it('is stored as the server stores serials: no separators, no leading zeros, upper case', () => {
        expect(normalizeSerial('0a:1b:2c:3d')).toBe('A1B2C3D');
        expect(normalizeSerial(' 00-ff 10 ')).toBe('FF10');
        expect(normalizeSerial('A1B2')).toBe('A1B2');
    });

    it('keeps an all-zero serial as zero, so it is refused rather than sent empty', () => {
        expect(normalizeSerial('00:00')).toBe('0');
        expect(normalizeSerial('   ')).toBe('');
    });

    it('is accepted when it is a positive hexadecimal number of at most twenty octets', () => {
        expect(serialProblem('0A:1B:2C')).toBeNull();
        expect(serialProblem('F'.repeat(40))).toBeNull();
        expect(serialProblem('00' + 'F'.repeat(40))).toBeNull();
    });

    it('is refused with the reason otherwise, as the server refuses it', () => {
        expect(serialProblem('')).toMatch(/required/);
        expect(serialProblem('12G4')).toMatch(/hexadecimal/);
        expect(serialProblem('0x1234')).toMatch(/hexadecimal/);
        expect(serialProblem('00:00')).toMatch(/positive/);
        expect(serialProblem('F'.repeat(41))).toMatch(/twenty octets/);
    });
});

describe('the requests the two actions send', () => {
    it('records a serial with its reason and the trimmed note', () => {
        expect(tombstoneBody('0a:1b', 'KeyCompromise', '  issued before the rollback \n')).toEqual({
            serialNumber: 'A1B', reason: 'KeyCompromise', note: 'issued before the rollback',
        });
    });

    it('adopts a certificate as good unless a reason is given', () => {
        const pem = '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----';
        expect(adoptionBody(`\n${pem}\n`, ' from the subscriber ', null)).toEqual({ certificate: pem, note: 'from the subscriber' });
        expect(adoptionBody(pem, 'leaked', 'KeyCompromise')).toEqual({ certificate: pem, note: 'leaked', revokeReason: 'KeyCompromise' });
    });
});
