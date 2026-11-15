import { describe, expect, it } from 'vitest';
import { journalAge, journalBadge, journalRefusedLinks, journalRestored, journalSize, journalSummary } from '@adminui/pages/journalHealth';

const healthy = { status: 'ok', seq: 4, sizeBytes: 1638, freeBytes: 13099900000, lastCheckpointAgeSeconds: 51, verified: true, setAsideJournals: 0, merge: [], refusedCrls: [] };
const words = (text: string): number => text.trim().split(/\s+/).length;

/** The "Signer Journal" row of System Health: where a healthy journal can be seen. */
describe('the badge of the signer\'s journal', () => {
    it('is green when healthy', () => {
        expect(journalBadge(healthy)).toEqual({ tone: 'ok', status: 'active', label: 'Healthy' });
    });

    it('is neutral with a hint for a signer that keeps none', () => {
        expect(journalBadge({ status: 'none' })).toEqual({ tone: 'neutral', status: 'disabled', label: 'Not kept', hint: 'This signer keeps no journal.' });
    });

    it.each(['merge_running', 'merge_pending', 'awaiting_restore_marker'])('is informational for %s', (status) => {
        expect(journalBadge({ status })).toMatchObject({ tone: 'info', status: 'pending' });
    });

    it.each(['low_space', 'stale_checkpoint'])('is a warning for %s', (status) => {
        expect(journalBadge({ status })).toMatchObject({ tone: 'warn', status: 'held' });
    });

    it.each(['critical_space', 'crl_refused', 'unavailable'])('is critical for %s', (status) => {
        expect(journalBadge({ status })).toMatchObject({ tone: 'crit', status: 'revoked' });
    });

    it('is informational while the journal is still being read, and critical once reading stopped without verifying', () => {
        expect(journalBadge({ status: 'not_verified', verified: false, verifiedBytes: 400, verifyTotalBytes: 1000 })).toEqual({ tone: 'info', status: 'pending', label: 'Verifying' });
        expect(journalBadge({ status: 'not_verified', verified: false, verifiedBytes: 1000, verifyTotalBytes: 1000 })).toMatchObject({ tone: 'crit', label: 'Not verified' });
        expect(journalBadge({ status: 'not_verified', verified: false, verifiedBytes: 400, verifyTotalBytes: 1000, verificationFault: 'record 3 does not chain' })).toMatchObject({ tone: 'crit' });
        expect(journalBadge({ status: 'not_verified' })).toMatchObject({ tone: 'crit' });
    });

    it('shows a status it does not know as it came, in neutral, and nothing without a journal', () => {
        expect(journalBadge({ status: 'something_new' })).toEqual({ tone: 'neutral', status: 'disabled', label: 'something new' });
        expect(journalBadge(undefined)).toBeNull();
        expect(journalBadge({})).toBeNull();
    });

    it('keeps every label to a few words', () => {
        for (const status of ['ok', 'none', 'merge_running', 'merge_pending', 'awaiting_restore_marker', 'not_verified', 'low_space', 'stale_checkpoint', 'critical_space', 'crl_refused', 'unavailable'])
            expect(words(journalBadge({ status })!.label)).toBeLessThanOrEqual(3);
    });
});

describe('the summary line of the signer\'s journal', () => {
    it('gives the records, the size, the last checkpoint, the free space and whether it verified', () => {
        expect(journalSummary(healthy)).toBe('4 records, 1.6 KiB, last checkpoint 51 s ago, 12.2 GiB free, verified');
    });

    it('stays within about 20 words at its longest', () => {
        const longest = journalSummary({ ...healthy, seq: 1234567, lastCheckpointAgeSeconds: 90000, verified: false, verifiedBytes: 1, verifyTotalBytes: 3, setAsideJournals: 2 })!;
        expect(longest).toBe('1234567 records, 1.6 KiB, last checkpoint 1 d ago, 12.2 GiB free, verifying, 33% read, 2 earlier journals set aside');
        expect(words(`Signer journal: ${longest}`)).toBeLessThanOrEqual(22);
    });

    it('says only what the answer carries, and nothing for a signer that keeps no journal', () => {
        expect(journalSummary({ status: 'unavailable' })).toBeNull();
        expect(journalSummary({ status: 'none' })).toBeNull();
        expect(journalSummary({ status: 'ok', seq: 1, verified: false })).toBe('1 record, not verified');
        expect(journalSummary(null)).toBeNull();
    });

    it('writes sizes in binary units and ages in their largest whole unit', () => {
        expect([journalSize(0), journalSize(1023), journalSize(1024), journalSize(5 * 1024 ** 2), journalSize(3 * 1024 ** 4)]).toEqual(['0 B', '1023 B', '1.0 KiB', '5.0 MiB', '3.0 TiB']);
        expect([journalAge(0), journalAge(59), journalAge(60), journalAge(3599), journalAge(7200), journalAge(172800)]).toEqual(['0 s', '59 s', '1 min', '59 min', '2 h', '2 d']);
    });
});

describe('the links of the signer\'s journal', () => {
    it('names each CA that had revocations restored since this start, linking to its page', () => {
        const journal = { ...healthy, merge: [
            { caId: 'a b', caName: 'Issuing CA', state: 'done', merged: 3 },
            { caId: 'c', caName: 'Other', state: 'done', merged: 0 },
            { caId: 'd', caName: 'Running', state: 'running', merged: 9 },
            { caId: 'e', caName: '', state: 'done', merged: 1 },
        ] };
        expect(journalRestored(journal)).toEqual([
            { text: '3 revocations restored for Issuing CA', to: '/authorities/manage/a%20b' },
            { text: '1 revocation restored for a CA', to: '/authorities/manage/e' },
        ]);
        expect(journalRestored(healthy)).toEqual([]);
    });

    it('links a refused CRL to the missing-serials section of each affected CA, by the path the server gives', () => {
        const journal = { status: 'crl_refused', refusedCrls: [
            { caId: 'a', caName: 'Issuing CA', consolePath: '/admin/authorities/manage/a#missing-from-crl' },
            { caId: null, caName: null, consolePath: null },
            { caId: 'x', caName: 'Elsewhere', consolePath: 'https://example.org/' },
        ] };
        expect(journalRefusedLinks(journal)).toEqual([{ text: 'Missing serials of Issuing CA', to: '/authorities/manage/a#missing-from-crl' }]);
        expect(journalRefusedLinks({ ...journal, status: 'ok' })).toEqual([]);
    });
});
