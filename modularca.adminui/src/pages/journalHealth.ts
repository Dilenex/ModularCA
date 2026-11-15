/*
 * The signer's journal on System Health: its row in the "Health Checks" list and the summary line
 * under it, from `checks.journal` of `/health/ready`. No React here, so tests/modularca.web.tests
 * can cover it. The dashboard's "Needs attention" entry (components/journalAttention.ts) speaks
 * only when something is wrong; this row is where a healthy journal can be seen.
 */

import { consoleRoute } from '../components/journalAttention';

/** How loud the row is: green, neutral grey, informational blue, amber, red. */
export type JournalTone = 'ok' | 'neutral' | 'info' | 'warn' | 'crit';

/** The journal's badge: a `StatusBadge` status with the tone's color, and its words. */
export interface JournalBadge {
    tone: JournalTone;
    /** The `StatusBadge` status that carries the tone's color. */
    status: 'active' | 'disabled' | 'pending' | 'held' | 'revoked';
    label: string;
    /** A few words beside the badge, where the label alone would leave a question. */
    hint?: string;
}

const badgeStatus: Record<JournalTone, JournalBadge['status']> = { ok: 'active', neutral: 'disabled', info: 'pending', warn: 'held', crit: 'revoked' };

const known: Record<string, { tone: JournalTone; label: string; hint?: string }> = {
    ok: { tone: 'ok', label: 'Healthy' },
    none: { tone: 'neutral', label: 'Not kept', hint: 'This signer keeps no journal.' },
    not_known: { tone: 'info', label: 'Not known yet', hint: 'The signer has not answered.' },
    merge_running: { tone: 'info', label: 'Restoring revocations' },
    merge_pending: { tone: 'info', label: 'Revocations to restore' },
    awaiting_restore_marker: { tone: 'info', label: 'Awaiting restore' },
    low_space: { tone: 'warn', label: 'Low space' },
    stale_checkpoint: { tone: 'warn', label: 'Checkpoint overdue' },
    critical_space: { tone: 'crit', label: 'Nearly full' },
    crl_refused: { tone: 'crit', label: 'CRL refused' },
    unavailable: { tone: 'crit', label: 'Unavailable' },
};

const count = (value: unknown): number | null => (typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null);

/** Whether the signer is still reading its journal through: not verified yet, no fault found, bytes still to read. */
export function journalVerifying(journal: any): boolean {
    if (!journal || journal.verified === true) return false;
    if (typeof journal.verificationFault === 'string' && journal.verificationFault.trim() !== '') return false;
    const done = count(journal.verifiedBytes);
    const total = count(journal.verifyTotalBytes);
    return done !== null && total !== null && total > 0 && done < total;
}

/**
 * The badge for `checks.journal`, or null when the answer carries no journal. A journal that is
 * not verified is informational while the signer is still reading it and critical once it has
 * stopped; a status this console does not know is shown as it came, in neutral grey.
 */
export function journalBadge(journal: any): JournalBadge | null {
    if (!journal || typeof journal.status !== 'string' || journal.status === '') return null;
    if (journal.status === 'not_verified') {
        return journalVerifying(journal)
            ? { tone: 'info', status: badgeStatus.info, label: 'Verifying' }
            : { tone: 'crit', status: badgeStatus.crit, label: 'Not verified' };
    }
    const entry = known[journal.status];
    if (!entry) return { tone: 'neutral', status: badgeStatus.neutral, label: journal.status.replace(/_/g, ' ') };
    return { tone: entry.tone, status: badgeStatus[entry.tone], label: entry.label, ...(entry.hint ? { hint: entry.hint } : {}) };
}

/** A size in binary units, one decimal from KiB up: `1.6 KiB`, `12.2 GiB`. */
export function journalSize(bytes: number): string {
    const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
    let value = bytes;
    let unit = 0;
    while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++; }
    return unit === 0 ? `${Math.round(value)} B` : `${value.toFixed(1)} ${units[unit]}`;
}

/** An age in its largest whole unit: `51 s`, `4 min`, `3 h`, `2 d`. */
export function journalAge(seconds: number): string {
    if (seconds < 60) return `${Math.floor(seconds)} s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)} min`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)} h`;
    return `${Math.floor(seconds / 86400)} d`;
}

/**
 * The line under the list, after "Signer journal: ". Only what the answer carries is said, so a
 * signer that could not be asked gives a short line, and one that keeps no journal gives none.
 * At most about 20 words.
 */
export function journalSummary(journal: any): string | null {
    if (!journal || typeof journal.status !== 'string' || journal.status === 'none') return null;
    const parts: string[] = [];
    const seq = count(journal.seq);
    if (seq !== null) parts.push(`${seq} record${seq === 1 ? '' : 's'}`);
    const size = count(journal.sizeBytes);
    if (size !== null) parts.push(journalSize(size));
    const age = count(journal.lastCheckpointAgeSeconds);
    if (age !== null) parts.push(`last checkpoint ${journalAge(age)} ago`);
    const free = count(journal.freeBytes);
    if (free !== null) parts.push(`${journalSize(free)} free`);
    if (journal.verified === true) parts.push('verified');
    else if (journalVerifying(journal)) parts.push(`verifying, ${Math.floor((journal.verifiedBytes / journal.verifyTotalBytes) * 100)}% read`);
    else if (journal.verified === false) parts.push('not verified');
    const aside = count(journal.setAsideJournals);
    if (aside !== null && aside > 0) parts.push(`${aside} earlier journal${aside === 1 ? '' : 's'} set aside`);
    return parts.length > 0 ? parts.join(', ') : null;
}

/** A link from the journal's lines to a page of this console. */
export interface JournalLink { text: string; to: string }

/** One line for each CA that had revocations restored from the journal since this process started, linking to the CA's page. */
export function journalRestored(journal: any): JournalLink[] {
    if (!journal || !Array.isArray(journal.merge)) return [];
    const links: JournalLink[] = [];
    for (const m of journal.merge) {
        const merged = count(m?.merged);
        if (!m || m.state !== 'done' || merged === null || merged === 0 || typeof m.caId !== 'string') continue;
        const name = typeof m.caName === 'string' && m.caName !== '' ? m.caName : 'a CA';
        links.push({ text: `${merged} revocation${merged === 1 ? '' : 's'} restored for ${name}`, to: `/authorities/manage/${encodeURIComponent(m.caId)}` });
    }
    return links;
}

/** For a refused CRL: each affected CA's missing-serials section, from `refusedCrls[].consolePath`. */
export function journalRefusedLinks(journal: any): JournalLink[] {
    if (!journal || journal.status !== 'crl_refused' || !Array.isArray(journal.refusedCrls)) return [];
    const links: JournalLink[] = [];
    for (const r of journal.refusedCrls) {
        const to = r && typeof r === 'object' ? consoleRoute(r.consolePath) : null;
        if (!to) continue;
        const name = typeof r.caName === 'string' && r.caName !== '' ? r.caName : 'the CA';
        links.push({ text: `Missing serials of ${name}`, to });
    }
    return links;
}
