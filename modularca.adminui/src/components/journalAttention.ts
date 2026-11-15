/** What the dashboard shows under "Needs attention" for the signer's issuance journal. */
export interface JournalAttentionItem {
    /** `checks.journal.status` of `/health/ready`. */
    status: string;
    /** How loud: a volume that is low is a warning; a journal that cannot be written stops issuance. */
    tone: 'warn' | 'crit';
    title: string;
    /** The sentence to show, written by the server. */
    message: string;
    /** One line for each CA whose CRL the signer refuses: its name, how many serials are missing, and when its published CRL runs out. */
    details?: string[];
    /** For a refused CRL: where on each CA's page its missing serials are listed and can be revoked, as a path inside this console. */
    links?: { label: string; to: string }[];
}

interface RefusedCrl {
    caId?: unknown;
    caName?: unknown;
    missingSerials?: unknown;
    publishedCrlExpiresAtUtc?: unknown;
    consolePath?: unknown;
}

/**
 * The console path of a refused CRL's page as a route inside the admin console: the server gives
 * the whole path, `/admin/…`, for a link from elsewhere; a link in the console is relative to it.
 */
export function consoleRoute(path: unknown): string | null {
    if (typeof path !== 'string' || !path.startsWith('/admin/')) return null;
    return path.slice('/admin'.length);
}

const titles: Record<string, { tone: 'warn' | 'crit'; title: string }> = {
    unavailable: { tone: 'crit', title: 'The signer’s journal cannot be written' },
    critical_space: { tone: 'crit', title: 'The signer’s journal volume is nearly full' },
    low_space: { tone: 'warn', title: 'The signer’s journal volume is low on space' },
    stale_checkpoint: { tone: 'warn', title: 'The signer’s journal is not being checkpointed' },
    crl_refused: { tone: 'crit', title: 'The signer refuses to sign a CRL that leaves out revoked serials' },
    awaiting_restore_marker: { tone: 'warn', title: 'The signer’s journal waits for a restore to explain a changed system key' },
    not_verified: { tone: 'crit', title: 'The signer’s journal did not verify' },
    merge_pending: { tone: 'warn', title: 'Revocations from the signer’s journal wait to be restored' },
    merge_running: { tone: 'warn', title: 'Revocations are being restored from the signer’s journal' },
};

function refusedLine(entry: RefusedCrl): string | null {
    if (typeof entry.missingSerials !== 'number') return null;
    const name = typeof entry.caName === 'string' && entry.caName !== ''
        ? entry.caName
        : typeof entry.caId === 'string' ? entry.caId : 'A CA key with no registered CA';
    const serials = `${entry.missingSerials} serial${entry.missingSerials === 1 ? '' : 's'} missing`;
    const expires = typeof entry.publishedCrlExpiresAtUtc === 'string' && !Number.isNaN(Date.parse(entry.publishedCrlExpiresAtUtc))
        ? `; its published CRL runs out ${new Date(entry.publishedCrlExpiresAtUtc).toISOString().replace('T', ' ').slice(0, 16)} UTC`
        : '';
    return `${name}: ${serials}${expires}`;
}

/**
 * The journal's entry for "Needs attention", from the answer of `/health/ready`. Nothing when
 * the journal is fine, when the signer keeps none, and when the answer could not be read: an
 * entry here is something to act on, before a full volume stops issuance or a published CRL
 * runs out with no new one signed.
 */
export function journalAttention(health: unknown): JournalAttentionItem | null {
    const journal = (health as { checks?: { journal?: { status?: unknown; message?: unknown; refusedCrls?: unknown } } } | null | undefined)?.checks?.journal;
    if (!journal || typeof journal.status !== 'string') return null;
    const known = titles[journal.status];
    if (!known) return null;
    const message = typeof journal.message === 'string' && journal.message.trim() !== ''
        ? journal.message
        : 'See System health for the journal’s size, the free space on its volume and its last checkpoint.';
    const item: JournalAttentionItem = { status: journal.status, tone: known.tone, title: known.title, message };
    if (journal.status === 'crl_refused' && Array.isArray(journal.refusedCrls)) {
        const details = (journal.refusedCrls as RefusedCrl[])
            .map((entry) => (entry && typeof entry === 'object' ? refusedLine(entry) : null))
            .filter((line): line is string => line !== null);
        if (details.length > 0) item.details = details;
        const links = (journal.refusedCrls as RefusedCrl[])
            .map((entry) => {
                const to = entry && typeof entry === 'object' ? consoleRoute(entry.consolePath) : null;
                if (!to) return null;
                const name = typeof entry.caName === 'string' && entry.caName !== '' ? entry.caName : 'the CA';
                return { label: `Missing serials of ${name}`, to };
            })
            .filter((link): link is { label: string; to: string } => link !== null);
        if (links.length > 0) item.links = links;
    }
    return item;
}
