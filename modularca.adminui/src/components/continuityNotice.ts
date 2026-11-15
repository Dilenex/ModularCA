/** One continuity event of the standing notice, as `/api/v1/admin/continuity/notice` returns it. */
export interface ContinuityEvent {
    id: string;
    /** `IncarnationChanged`, `IncarnationSourceLost`, `PublishedCrlAhead` or `RevocationsMergedFromJournal`. */
    kind: string;
    detectedAt: string;
    oldTag: string | null;
    newTag: string | null;
    /** The newest record the database held: what an earlier timeline did after it is unknown here. */
    edgeOfMemoryUtc: string | null;
    /** The audit trail's newest row at that moment; later than the edge when the audit trail was not taken back. */
    auditNewestUtc: string | null;
    crlNumberFloor: number | null;
    crlCountersRaised: number;
    /** The sentence to show, written by the server. */
    message: string;
}

/** The standing notice. */
export interface ContinuityNotice {
    applies: boolean;
    events: ContinuityEvent[];
    incarnation: { source: string; tag: string | null; recordedAt: string; recordedBy: string } | null;
}

/** The short heading of an event, by kind; an unknown kind gets the general one. */
export function continuityTitle(kind: string): string {
    switch (kind) {
        case 'IncarnationSourceLost': return 'Rollback detection lost its source.';
        case 'PublishedCrlAhead': return 'The database was taken back in time.';
        case 'RevocationsMergedFromJournal': return 'Revocations were restored from the signer’s journal.';
        default: return 'Running from an earlier or copied state.';
    }
}

/** The events a banner shows, oldest first; nothing when the notice does not apply or could not be read. */
export function standingEvents(notice: ContinuityNotice | null | undefined): ContinuityEvent[] {
    if (!notice?.applies || !Array.isArray(notice.events)) return [];
    return [...notice.events].sort((a, b) => a.detectedAt.localeCompare(b.detectedAt));
}

/**
 * How far past the edge of memory the audit trail must reach before the banner says so. The two
 * are written by different things a few moments apart even when they were taken back together.
 */
const AUDIT_MARGIN_MS = 5 * 60 * 1000;

/**
 * Whether the audit trail reaches well past the edge of memory: it is a separate database, and
 * when a rollback left it alone it holds rows from the lost time, which may list what was issued
 * and revoked in it.
 */
export function auditTrailOutlivesEdge(event: ContinuityEvent): boolean {
    if (!event.edgeOfMemoryUtc || !event.auditNewestUtc) return false;
    return new Date(event.auditNewestUtc).getTime() - new Date(event.edgeOfMemoryUtc).getTime() > AUDIT_MARGIN_MS;
}
