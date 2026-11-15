import { describe, expect, it } from 'vitest';
import { auditTrailOutlivesEdge, continuityTitle, standingEvents, type ContinuityEvent, type ContinuityNotice } from '@adminui/components/continuityNotice';

const event = (over: Partial<ContinuityEvent> = {}): ContinuityEvent => ({
    id: 'e1', kind: 'IncarnationChanged', detectedAt: '2026-11-11T12:00:00Z', oldTag: 'AAAA', newTag: 'BBBB',
    edgeOfMemoryUtc: '2026-11-10T09:30:00Z', auditNewestUtc: null, crlNumberFloor: 1794398400, crlCountersRaised: 2,
    message: 'This instance is running from an earlier or copied state.', ...over,
});

describe('the standing rollback notice', () => {
    it('shows nothing when the notice does not apply or could not be read', () => {
        expect(standingEvents(null)).toEqual([]);
        expect(standingEvents(undefined)).toEqual([]);
        expect(standingEvents({ applies: false, events: [event()], incarnation: null })).toEqual([]);
        expect(standingEvents({ applies: true, events: undefined as unknown as ContinuityEvent[], incarnation: null })).toEqual([]);
    });

    it('shows every unacknowledged event, oldest first', () => {
        const notice: ContinuityNotice = {
            applies: true, incarnation: null,
            events: [event({ id: 'later', detectedAt: '2026-11-12T08:00:00Z' }), event({ id: 'earlier', detectedAt: '2026-11-11T12:00:00Z' })],
        };
        expect(standingEvents(notice).map((e) => e.id)).toEqual(['earlier', 'later']);
        // The notice itself is not reordered.
        expect(notice.events[0].id).toBe('later');
    });

    it('heads each kind with what happened', () => {
        expect(continuityTitle('IncarnationChanged')).toBe('Running from an earlier or copied state.');
        expect(continuityTitle('PublishedCrlAhead')).toBe('The database was taken back in time.');
        expect(continuityTitle('IncarnationSourceLost')).toBe('Rollback detection lost its source.');
        expect(continuityTitle('SomethingNewer')).toBe('Running from an earlier or copied state.');
    });

    it('points at the audit trail only when it reaches well past the edge of memory', () => {
        expect(auditTrailOutlivesEdge(event({ auditNewestUtc: '2026-11-11T11:59:00Z' }))).toBe(true);
        expect(auditTrailOutlivesEdge(event({ auditNewestUtc: '2026-11-10T09:36:00Z' }))).toBe(true);
        // Written a moment apart by different things: taken back together, not a surviving trail.
        expect(auditTrailOutlivesEdge(event({ auditNewestUtc: '2026-11-10T09:34:00Z' }))).toBe(false);
        expect(auditTrailOutlivesEdge(event({ auditNewestUtc: '2026-11-10T09:30:00Z' }))).toBe(false);
        expect(auditTrailOutlivesEdge(event({ auditNewestUtc: '2026-11-09T00:00:00Z' }))).toBe(false);
        expect(auditTrailOutlivesEdge(event({ auditNewestUtc: null }))).toBe(false);
        expect(auditTrailOutlivesEdge(event({ edgeOfMemoryUtc: null, auditNewestUtc: '2026-11-11T11:59:00Z' }))).toBe(false);
    });
});
