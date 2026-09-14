import { describe, expect, it } from 'vitest';
import {
    buildOpensslCmpCommand, commonNameOf, drawerTitle, isCmpCredentialRow,
    signingProfileLabel, tokenColumnLabel, validateReferenceValue,
} from '@adminui/components/cmpCredential';

/**
 * The helpers behind the CMP credential form and the token table's handling of CMP rows.
 *
 * The list endpoint never returns a CMP credential's secret, and returns null for its token
 * column, so a table that assumed every row had a token rendered "…" for CMP rows and titled
 * the drawer "Token …". These pin the row-type distinction and the reference-value rules the
 * form enforces before the request is sent.
 */
describe('CMP credential rows', () => {
    it('are recognised by the usedForCmp flag, not by the absence of a token', () => {
        expect(isCmpCredentialRow({ usedForCmp: true, token: null })).toBe(true);
        expect(isCmpCredentialRow({ usedForCmp: false, token: null })).toBe(false);
        expect(isCmpCredentialRow({ token: 'abc' })).toBe(false);
    });

    it('show the reference value in the token column, since the secret is never returned', () => {
        expect(tokenColumnLabel({ usedForCmp: true, cmpReferenceValue: 'printer-fleet' })).toBe('CMP · printer-fleet');
        expect(tokenColumnLabel({ usedForCmp: true })).toBe('CMP · (no reference)');
    });

    it('bearer tokens keep the prefix display', () => {
        expect(tokenColumnLabel({ token: 'E_6BRiQddLy8J-msLzn23WgmhwcL0JU0rWCRhkJqBOI' })).toBe('E_6BRiQddLy8J-msLzn2…');
        expect(tokenColumnLabel({ token: 'short' })).toBe('short');
    });

    it('title the drawer by reference value rather than a missing token', () => {
        expect(drawerTitle({ usedForCmp: true, cmpReferenceValue: 'printer-fleet' })).toBe('CMP credential printer-fleet');
        expect(drawerTitle({ token: 'E_6BRiQddLy8J-msLzn23W' })).toBe('Token E_6BRiQddLy8…');
    });
});

describe('reference value validation', () => {
    it('accepts the characters a senderKID and a shell argument both tolerate', () => {
        expect(validateReferenceValue('cmp-probe')).toBeNull();
        expect(validateReferenceValue('fleet.printers:site-2@acme')).toBeNull();
    });

    it('refuses empty, overlong, and shell-hostile values', () => {
        expect(validateReferenceValue('')).not.toBeNull();
        expect(validateReferenceValue('   ')).not.toBeNull();
        expect(validateReferenceValue('a'.repeat(65))).not.toBeNull();
        expect(validateReferenceValue('has space')).not.toBeNull();
        expect(validateReferenceValue('quote"d')).not.toBeNull();
    });
});

describe('signing profile labels', () => {
    it('append the issuing CA common name when the API supplied the issuer', () => {
        expect(signingProfileLabel({ id: '1', name: 'CMP Devices', issuer: { subjectDN: 'CN=Staging CA R1,O=Staging,C=US' } }))
            .toBe('CMP Devices — Staging CA R1');
        expect(signingProfileLabel({ id: '1', name: 'CMP Devices' })).toBe('CMP Devices');
    });

    it('fall back to the whole DN when it has no CN', () => {
        expect(commonNameOf('O=Staging,C=US')).toBe('O=Staging,C=US');
        expect(commonNameOf('C=US, CN=With Space')).toBe('With Space');
    });
});

describe('the example command', () => {
    it('names the endpoint and reference, and never carries the secret', () => {
        const cmd = buildOpensslCmpCommand('https://ca4.example.test', 'staging-ca-r1', 'cmp-probe');
        expect(cmd).toContain('-server https://ca4.example.test/cmp/staging-ca-r1');
        expect(cmd).toContain('-ref "cmp-probe"');
        expect(cmd).toContain('<shared secret>');
        expect(cmd).toContain('-cmd ir');
    });

    it('leaves a visible placeholder when the CA label is unknown', () => {
        expect(buildOpensslCmpCommand('https://x', null, 'r')).toContain('/cmp/<ca-label>');
    });
});
