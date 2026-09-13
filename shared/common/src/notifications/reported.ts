/**
 * A short-lived record of failures the API client has already put on screen, so the call site that
 * catches the same error does not put it there a second time.
 *
 * The duplicate is structural, not a mistake at any one call site. `createAuthClient` toasts every
 * non-ok response — that is its safety net, and it is why a failure surfaces even from a caller
 * that forgot to handle one — and then throws an `ApiError`. Roughly a hundred call sites across
 * the two authenticated SPAs then do the obvious thing:
 *
 *     catch (err: any) { showToast('error', err.message || 'Failed to record approval'); }
 *
 * Both are reasonable in isolation and together they produce two toasts for one click, the second
 * strictly worse than the first: the client's carries the title, remediation, code and correlation
 * id as separate elements, while `err.message` is the same content flattened into one line.
 *
 * The fix has to be here rather than at the call sites for two reasons. Deleting a hundred catch
 * blocks' toasts would leave every one of them silent if the client's safety net is ever narrowed,
 * and the fallback in `err.message || 'Failed to …'` is still load-bearing — a step-up cancellation
 * or a client-side throw never passed through the client's error path at all, so nothing toasted it
 * and the call site is the only thing that will.
 *
 * Matching is by exact string, which is what makes this precise rather than a heuristic. The client
 * records `problem.message`, and `problem.message` is the identical string the call site reads back
 * off `err.message` — same object, same field. Nothing that merely resembles a reported failure is
 * suppressed, and in particular a caller that builds its own sentence out of one ("1 failed — you
 * cannot approve your own request") is unaffected, which is correct: that sentence says something
 * the client's toast did not. Callers that aggregate should pass `toast: false` to opt out of the
 * client's toast in the first place.
 */

/**
 * How long a reported failure stays eligible for suppression.
 *
 * Long enough to cover a synchronous catch and the render it triggers, short enough that a second
 * identical failure from a later click is its own event and shows. A click that genuinely produces
 * the same refusal twice inside this window is a double-submit, where one toast is also the right
 * answer.
 */
const WINDOW_MS = 3000;

const reported = new Map<string, number>();

/** Drops entries past the window, so a long session cannot accumulate them. */
function prune(now: number): void {
    for (const [text, at] of reported) {
        if (now - at > WINDOW_MS) reported.delete(text);
    }
}

/**
 * Records that this exact message has just been shown to the operator.
 *
 * Called by the API client immediately after it toasts a parsed problem, with the composed
 * single-line form of that problem — the same string the thrown `ApiError` carries.
 */
export function noteReported(text: string | undefined): void {
    if (!text) return;
    const now = Date.now();
    prune(now);
    reported.set(text, now);
}

/**
 * True when this message was reported within the window, and consumes the record.
 *
 * Consuming is what keeps the suppression to exactly one duplicate per report. A call site that
 * deliberately shows the same sentence twice gets its second toast; a call site echoing the error
 * the client already reported does not get its first.
 */
export function consumeReported(text: string): boolean {
    const now = Date.now();
    prune(now);
    const at = reported.get(text);
    if (at === undefined) return false;
    reported.delete(text);
    return now - at <= WINDOW_MS;
}

/** Clears the record. Exists for tests, which must not leak state between cases. */
export function resetReported(): void {
    reported.clear();
}
