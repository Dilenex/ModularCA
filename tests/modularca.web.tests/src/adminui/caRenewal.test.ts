import { describe, expect, it } from 'vitest';
import {
    RSA_PAST_2030, renewalCannotExtend, renewalMinimumYears, historyBadge, historyFileName, isRootCa, originLabel, renewalEffects, renewalUnavailable, renewalYearsProblem, validityNotes,
} from '@adminui/pages/caRenewal';

const root = { id: 'r', name: 'Acme Root', label: 'acme-root', certificate: { revoked: false } };
const issuing = { ...root, id: 'i', name: 'Acme Issuing', label: 'acme-issuing', parentCaId: 'r' };

describe('when renewal of a CA certificate is offered', () => {
    it('is offered for a root and an intermediate with a certificate', () => {
        expect(renewalUnavailable(root)).toBeNull();
        expect(renewalUnavailable(issuing)).toBeNull();
    });

    it('is not offered without a certificate or for a revoked one, and is offered for the system signing CA', () => {
        expect(renewalUnavailable({ id: 'x' })).toContain('no certificate');
        expect(renewalUnavailable({ ...root, certificate: { revoked: true } })).toContain('revoked');
        expect(renewalUnavailable({ ...root, label: 'System-Signing-CA' })).toBeNull();
    });

    it('tells the holder of the system signing CA that nothing depends on its certificate', () => {
        const effects = renewalEffects({ ...root, label: 'system-signing-ca' });
        expect(effects.stays.join(' ')).toContain('instance identifier');
        expect(effects.after.join(' ')).toContain('No restart is needed');
    });

    it('says when a validity is longer than common practice, and when an RSA key under 3072 bits would run past 2030', () => {
        const now = new Date(Date.UTC(2027, 0, 1));
        expect(validityNotes(true, 25, false, now)).toEqual([]);
        expect(validityNotes(true, 26, false, now).map((n) => [n.reason, n.severity])).toEqual([['CaValidityBeyondCommonPractice', 'notice']]);
        expect(validityNotes(false, 10, false, now)).toEqual([]);
        expect(validityNotes(false, 11, false, now)[0].message).toContain('No standard that binds a private CA');
        expect(validityNotes(true, 3, true, now)).toEqual([]);
        expect(validityNotes(true, 4, true, now).map((n) => [n.reason, n.severity])).toEqual([[RSA_PAST_2030, 'warning']]);
        expect(validityNotes(true, '', true, now)).toEqual([]);
    });

    it('takes a whole number of years from 1 to 50', () => {
        expect(renewalYearsProblem(1)).toBeNull();
        expect(renewalYearsProblem(50)).toBeNull();
        expect(renewalYearsProblem('20')).toBeNull();
        expect(renewalYearsProblem(0)).not.toBeNull();
        expect(renewalYearsProblem(51)).not.toBeNull();
        expect(renewalYearsProblem(2.5)).not.toBeNull();
        expect(renewalYearsProblem('')).not.toBeNull();
    });
});

describe('a certificate that a renewal could not extend', () => {
    const now = new Date(Date.UTC(2027, 0, 1));
    const withEnd = (notAfter: string) => ({ ...root, label: 'system-signing-ca', certificate: { revoked: false, notAfter } });

    it('is explained with its end date instead of being offered an action that would fail', () => {
        const message = renewalCannotExtend(withEnd('2126-11-01T00:00:00Z'), now);
        expect(message).toContain('already runs to 2126-11-01');
        expect(message).toContain('can only extend');
        expect(message).toContain('before 2077');
    });

    it('is offered once fewer than fifty years remain, and asks for enough years to end after the current one', () => {
        expect(renewalCannotExtend(withEnd('2076-12-31T00:00:00Z'), now)).toBeNull();
        expect(renewalCannotExtend(withEnd('2077-01-01T00:00:00Z'), now)).not.toBeNull();
        expect(renewalCannotExtend({ ...root }, now)).toBeNull();
        expect(renewalMinimumYears(withEnd('2031-06-01T00:00:00Z'), now)).toBe(5);
        expect(renewalMinimumYears(withEnd('2027-06-01T00:00:00Z'), now)).toBe(1);
        expect(renewalMinimumYears({ ...root }, now)).toBe(1);
    });
});

describe('what the console says a renewal does', () => {
    it('knows a root from an intermediate', () => {
        expect(isRootCa(root)).toBe(true);
        expect(isRootCa(issuing)).toBe(false);
    });

    it('says the key, the subject and the earlier certificate stay, and the serial and validity change', () => {
        const effects = renewalEffects(root);
        expect(effects.stays.join(' ')).toContain('The key.');
        expect(effects.stays.join(' ')).toContain('is not revoked');
        expect(effects.changes.join(' ')).toContain('serial number and the validity');
    });

    it('tells the holder of a root that the new certificate is theirs to distribute, and not the holder of an intermediate', () => {
        expect(renewalEffects(root).after[0]).toContain('This product cannot do that for you');
        expect(renewalEffects(root).changes.join(' ')).toContain('signed by this CA itself');
        expect(renewalEffects(issuing).after[0]).toContain('Nothing has to be redistributed');
        expect(renewalEffects(issuing).changes.join(' ')).toContain('signed by the parent CA');
    });
});

describe('a certificate in the history of a CA', () => {
    it('is labeled by its status, with color for status only', () => {
        expect(historyBadge({ isCurrent: true })).toEqual({ status: 'active', label: 'Current' });
        expect(historyBadge({ isCurrent: false })).toEqual({ status: 'disabled', label: 'Earlier, still valid' });
        expect(historyBadge({ isCurrent: false, expired: true })).toEqual({ status: 'expired', label: 'Expired' });
        expect(historyBadge({ isCurrent: true, expired: true })).toEqual({ status: 'expired', label: 'Current, expired' });
        expect(historyBadge({ isCurrent: true, revoked: true, expired: true })).toEqual({ status: 'revoked', label: 'Revoked' });
    });

    it('says how it became the CA\'s', () => {
        expect(originLabel('Renewal')).toBe('Renewal (same key)');
        expect(originLabel('Initial')).toBe('First certificate');
        expect(originLabel(undefined)).toBe('First certificate');
    });

    it('downloads under the CA\'s label and its serial', () => {
        expect(historyFileName(root, { serialNumber: '0A1B' })).toBe('acme-root-0a1b.pem');
        expect(historyFileName({ name: 'My CA!' }, { serialNumber: 'FF' })).toBe('my-ca-ff.pem');
        expect(historyFileName({}, { serialNumber: 'FF' })).toBe('ca-ff.pem');
    });
});
