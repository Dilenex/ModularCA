import { describe, expect, it } from 'vitest';
import { consoleRoute, journalAttention } from '@adminui/components/journalAttention';
import { bulkBody, missingRows, missingSummary, recordable, type MissingFromCrl, type MissingSerialRow } from '@adminui/components/missingFromCrl';

const health = (journal: unknown) => ({ status: 'healthy', checks: { journal } });

describe('the signer journal under Needs attention', () => {
    it('says nothing while the journal is fine, absent or unreadable', () => {
        expect(journalAttention(null)).toBeNull();
        expect(journalAttention(undefined)).toBeNull();
        expect(journalAttention({})).toBeNull();
        expect(journalAttention({ checks: {} })).toBeNull();
        expect(journalAttention(health({ status: 'ok', message: null }))).toBeNull();
        expect(journalAttention(health({ status: 'none' }))).toBeNull();
        expect(journalAttention(health({ status: 7 }))).toBeNull();
        // A status this console does not know is not turned into an alarm.
        expect(journalAttention(health({ status: 'something_new', message: 'x' }))).toBeNull();
    });

    it('warns before a full volume stops issuance, with the server’s sentence', () => {
        const low = journalAttention(health({ status: 'low_space', message: 'The volume of the signer\'s issuance journal has 700 MiB free.' }));
        expect(low).toEqual({
            status: 'low_space', tone: 'warn', title: 'The signer’s journal volume is low on space',
            message: 'The volume of the signer\'s issuance journal has 700 MiB free.',
        });
        expect(journalAttention(health({ status: 'stale_checkpoint', message: 'm' }))?.tone).toBe('warn');
    });

    it('is loud when issuance has stopped or is about to', () => {
        expect(journalAttention(health({ status: 'unavailable', message: 'm' }))?.tone).toBe('crit');
        expect(journalAttention(health({ status: 'critical_space', message: 'm' }))?.tone).toBe('crit');
    });

    it('shows a refused CRL loudly, with each CA, its missing serials and when its CRL runs out', () => {
        const refused = journalAttention(health({
            status: 'crl_refused',
            message: 'The signer refuses to sign a new CRL for 2 CA(s).',
            refusedCrls: [
                { caId: '0b7e3a52-0000-4000-8000-000000000001', caName: 'Issuing CA 1', missingSerials: 3, publishedCrlExpiresAtUtc: '2026-11-20T08:30:00Z' },
                { caId: '0b7e3a52-0000-4000-8000-000000000002', caName: null, missingSerials: 1, publishedCrlExpiresAtUtc: null },
                { caName: 'no count' },
            ],
        }));
        expect(refused?.tone).toBe('crit');
        expect(refused?.message).toBe('The signer refuses to sign a new CRL for 2 CA(s).');
        expect(refused?.details).toEqual([
            'Issuing CA 1: 3 serials missing; its published CRL runs out 2026-11-20 08:30 UTC',
            '0b7e3a52-0000-4000-8000-000000000002: 1 serial missing',
        ]);
        // No list from the server: the sentence alone.
        expect(journalAttention(health({ status: 'crl_refused', message: 'm' }))?.details).toBeUndefined();
    });

    it('says the journal waits for a restore marker, as a warning', () => {
        const waiting = journalAttention(health({ status: 'awaiting_restore_marker', message: 'The journal waits 9 minute(s) more.' }));
        expect(waiting?.tone).toBe('warn');
        expect(waiting?.message).toBe('The journal waits 9 minute(s) more.');
        expect(waiting?.details).toBeUndefined();
    });

    it('shows the merge while it waits or runs, and a journal that did not verify loudly', () => {
        expect(journalAttention(health({ status: 'merge_pending', message: 'm' }))?.tone).toBe('warn');
        expect(journalAttention(health({ status: 'merge_running', message: 'm' }))?.tone).toBe('warn');
        const unverified = journalAttention(health({ status: 'not_verified', message: 'The journal did not verify.' }));
        expect(unverified?.tone).toBe('crit');
        expect(unverified?.title).toBe('The signer’s journal did not verify');
    });

    it('links a refused CRL to the page that lists its serials', () => {
        const refused = journalAttention(health({
            status: 'crl_refused', message: 'm',
            refusedCrls: [
                { caId: 'a', caName: 'Issuing CA 1', missingSerials: 3, consolePath: '/admin/authorities/manage/0b7e3a52-0000-4000-8000-000000000001#missing-from-crl' },
                { caId: 'b', caName: null, missingSerials: 1, consolePath: null },
                { caId: 'c', caName: 'Elsewhere', missingSerials: 1, consolePath: 'https://other.example/admin/x' },
            ],
        }));
        expect(refused?.links).toEqual([
            { label: 'Missing serials of Issuing CA 1', to: '/authorities/manage/0b7e3a52-0000-4000-8000-000000000001#missing-from-crl' },
        ]);
        // Only a path of this console is a link.
        expect(consoleRoute('/admin/authorities/manage/x#missing-from-crl')).toBe('/authorities/manage/x#missing-from-crl');
        expect(consoleRoute('/user/x')).toBeNull();
        expect(consoleRoute(undefined)).toBeNull();
    });

    it('falls back to a pointer when the server sent no sentence', () => {
        expect(journalAttention(health({ status: 'unavailable' }))?.message).toContain('System health');
        expect(journalAttention(health({ status: 'unavailable', message: '  ' }))?.message).toContain('System health');
    });
});

describe('the serials missing from a refused CRL, on the CA\'s page', () => {
    const row = (serialNumber: string, certificateHeld = false, reason = 'KeyCompromise'): MissingSerialRow =>
        ({ serialNumber, reason, reasonCode: 1, revocationDate: '2026-11-12T17:45:00Z', certificateHeld });
    const answer = (serials: MissingSerialRow[], refused = true): MissingFromCrl =>
        ({ caId: 'ca', refused, refusedAtUtc: null, journaledCrlNumber: 12, count: serials.length, consolePath: '/admin/authorities/manage/ca#missing-from-crl', serials });

    it('shows nothing when no refusal stands or the answer is missing', () => {
        expect(missingRows(null)).toEqual([]);
        expect(missingRows(undefined)).toEqual([]);
        expect(missingRows(answer([row('A1')], false))).toEqual([]);
        expect(missingRows(answer([row('A1'), row('B2')]))).toHaveLength(2);
    });

    it('records only the serials the CA holds no certificate for, each with the journaled reason', () => {
        const rows = [row('A1'), row('B2', true), row('C3', false, 'Superseded'), row('D4', false, 'CertificateHold')];
        expect(recordable(rows).map((r) => r.serialNumber)).toEqual(['A1', 'C3', 'D4']);
        expect(bulkBody(rows, '  lost in the roll-back  ')).toEqual({
            serials: [
                { serialNumber: 'A1', reason: 'KeyCompromise' },
                { serialNumber: 'C3', reason: 'Superseded' },
                // A hold cannot be recorded for a serial with no certificate.
                { serialNumber: 'D4', reason: 'Unspecified' },
            ],
            note: 'lost in the roll-back',
        });
    });

    it('says how many are missing and where each kind is revoked', () => {
        expect(missingSummary([row('A1')])).toContain('leave out 1 serial that');
        expect(missingSummary([row('A1'), row('B2')])).toContain('holds no certificate for any of them');
        expect(missingSummary([row('A1', true)])).toContain('revoke each on its own page');
        expect(missingSummary([row('A1', true), row('B2'), row('C3')])).toContain('holds the certificate of 1 of them');
    });
});
