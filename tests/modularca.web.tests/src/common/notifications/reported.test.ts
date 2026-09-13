import { afterEach, describe, expect, it, vi } from 'vitest';
import {
    consumeReported, noteReported, resetReported,
} from '@shared/notifications/reported';
import { ApiError, parseProblem } from '@shared-auth/api/problem';

/**
 * The duplicate-toast suppressor.
 *
 * Approving your own certificate request produced two toasts for one click: the API client toasts
 * every failure it parses, and then the catch block in the page toasts `err.message`, which is the
 * same failure flattened into one line. About a hundred call sites across the two authenticated
 * SPAs are written that way, so this is the single place the duplicate can be removed without
 * touching all of them — and without leaving them silent if the client's safety net ever narrows.
 *
 * What has to hold is narrow: suppress the echo, suppress it once, and never suppress a message
 * that merely resembles one already reported.
 */
describe('reported', () => {
    afterEach(() => { resetReported(); vi.useRealTimers(); });

    it('suppresses the exact message the client just reported', () => {
        noteReported('You cannot approve your own request');
        expect(consumeReported('You cannot approve your own request')).toBe(true);
    });

    it('does not suppress a message that was never reported', () => {
        noteReported('You cannot approve your own request');
        expect(consumeReported('Failed to load request')).toBe(false);
    });

    it('suppresses exactly one echo per report', () => {
        // Consuming is what bounds this. Two clicks that each produce the same refusal are two
        // events and deserve two toasts; only the second toast of a single event is the duplicate.
        noteReported('Request rejected');
        expect(consumeReported('Request rejected')).toBe(true);
        expect(consumeReported('Request rejected')).toBe(false);
    });

    it('does not suppress a sentence that merely contains the reported one', () => {
        // The bulk handler builds "1 failed — <reason>" out of the same reason. That sentence says
        // something the client's toast did not — how many failed — so it must survive. Bulk callers
        // suppress the client's per-request toast with `toast: false` instead.
        noteReported('You cannot approve your own request');
        expect(consumeReported('1 failed — You cannot approve your own request')).toBe(false);
    });

    it('ignores an empty or missing message', () => {
        // parseProblem degrades to the status line rather than throwing, but a composed message can
        // still come back empty. Recording '' would then suppress the next call site that toasted
        // an empty string, which is not a duplicate of anything.
        noteReported('');
        noteReported(undefined);
        expect(consumeReported('')).toBe(false);
    });

    it('stops suppressing once the window has passed', () => {
        vi.useFakeTimers();
        noteReported('Transient failure');
        vi.advanceTimersByTime(5000);
        expect(consumeReported('Transient failure')).toBe(false);
    });

    it('still suppresses within the window', () => {
        vi.useFakeTimers();
        noteReported('Immediate failure');
        vi.advanceTimersByTime(50);
        expect(consumeReported('Immediate failure')).toBe(true);
    });

    it('matches the string a catch block actually reads off the error', () => {
        // The load-bearing assumption, pinned rather than assumed. The client records
        // `problem.message`; the call site toasts `err.message`. Those are only ever the same
        // string because ApiError's constructor passes the one to the other, and if that link is
        // ever broken — a call site switching to `err.problem.detail`, or ApiError composing its
        // own summary — this suppressor silently stops suppressing and the duplicate returns with
        // nothing failing to announce it.
        const body = JSON.stringify({ error: 'You cannot approve your own request' });
        const problem = parseProblem(400, body);
        const err = new ApiError(problem);

        expect(err.message).toBe(problem.message);

        noteReported(problem.message);
        expect(consumeReported(err.message)).toBe(true);
    });

    it('does not accumulate records across a long session', () => {
        // Pruning is on both entry points, so a page that fails repeatedly over hours cannot grow
        // the map without bound. Asserted through the observable behaviour: an old record is gone,
        // and recording new ones is what collects it.
        vi.useFakeTimers();
        noteReported('Old failure');
        vi.advanceTimersByTime(60000);
        noteReported('New failure');
        expect(consumeReported('Old failure')).toBe(false);
        expect(consumeReported('New failure')).toBe(true);
    });
});
