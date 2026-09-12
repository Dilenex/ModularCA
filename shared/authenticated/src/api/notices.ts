/**
 * Adapters from what the API sends to what a notification surface renders.
 *
 * `problem.ts` parses; `notifications/notice.ts` renders and decides; this file is the join. It is
 * a separate module from both on purpose. `problem.ts` has a suite that pins its output
 * byte-for-byte against the previous client's for legacy bodies, and that guarantee is easier to
 * keep when the file gains nothing. `notice.ts` lives in `shared/common`, which the anonymous SPAs
 * also bundle and which therefore must not depend on the authenticated tree — so the dependency
 * runs one way, from here to there.
 *
 * Nothing in `problem.ts` changes shape as a result of this file. `ApiProblem.message` is still
 * composed the same way and still reaches `err.message`, which is what the hundreds of
 * `showToast('error', err.message)` call sites read. This is an additional, richer view of the same
 * parsed object, taken by the call sites that have somewhere better to put it.
 */
import type { Notice, NoticeSeverity } from '@shared/notifications/notice';
import type { ApiProblem, Diagnostic } from './problem';

/**
 * The supporting lines a problem carries beyond its detail sentence.
 *
 * `violations` is the important one: a certificate-policy refusal lists every rule that tripped,
 * already formatted "[Rule] message" by the middleware, and collapsing several of those into one
 * line loses the fact that there were several. A profile refusal instead names the value that was
 * sent and the values that were allowed, which is the same information an operator would otherwise
 * have to open the profile to find.
 */
function problemItems(problem: ApiProblem): string[] | undefined {
    if (problem.violations?.length) return problem.violations;

    const lines: string[] = [];
    if (problem.supplied) lines.push(`Supplied: ${problem.supplied}`);
    if (problem.allowed?.length) lines.push(`Allowed: ${problem.allowed.join(', ')}`);
    return lines.length > 0 ? lines : undefined;
}

/**
 * The one notice that summarizes a problem — what a toast shows.
 *
 * It takes `field` from `parameter`, so a `ProfileValidationException` about "Signature algorithm"
 * can be placed next to the signature algorithm control on a form that renders one, and falls back
 * to the toast on a form that does not.
 */
export function problemNotice(problem: ApiProblem): Notice {
    return {
        severity: 'error',
        title: problem.title,
        detail: problem.detail,
        remediation: problem.remediation,
        code: problem.code,
        correlationId: problem.correlationId,
        field: problem.parameter,
        items: problemItems(problem),
    };
}

/**
 * Every message in a problem: the summary first, then one notice per model-state field.
 *
 * The split is what makes inline rendering possible — a form passes this whole array to each of its
 * controls and to its summary banner, and the field matching decides where each message lands. The
 * summary stays first so a caller that only has room for one still shows the explanation rather
 * than an arbitrary field error.
 */
export function problemNotices(problem: ApiProblem): Notice[] {
    const notices: Notice[] = [problemNotice(problem)];
    for (const [field, messages] of Object.entries(problem.fieldErrors ?? {})) {
        notices.push({ severity: 'error', detail: messages.join(' '), field });
    }
    return notices;
}

/**
 * Maps a server severity string onto the client union.
 *
 * Unrecognized values become warnings rather than info. A severity this client has not been taught
 * about is one the server added after this build shipped, and the safe assumption about an unknown
 * message attached to a certificate that has already been signed is that it matters.
 */
export function diagnosticSeverity(severity: string): NoticeSeverity {
    switch (severity?.toLowerCase()) {
        case 'info': return 'info';
        case 'error': return 'error';
        default: return 'warning';
    }
}

/** One diagnostic from a successful response, as a notice. */
export function diagnosticNotice(diagnostic: Diagnostic): Notice {
    return {
        severity: diagnosticSeverity(diagnostic.severity),
        title: diagnostic.title,
        detail: diagnostic.detail,
        remediation: diagnostic.remediation,
        code: diagnostic.code || undefined,
        field: diagnostic.field,
    };
}

/** The diagnostics on a successful response, as notices. */
export function diagnosticNotices(diagnostics: Diagnostic[]): Notice[] {
    return diagnostics.map(diagnosticNotice);
}

/**
 * Whatever a `catch` block caught, as notices.
 *
 * Call sites catch `err: any` and cannot assume an `ApiError`: a step-up cancellation, a thrown
 * string from an older path and a genuine problem response all arrive through the same parameter.
 * This gives every one of them the same shape, so a form can render its inline messages without
 * first proving what it caught.
 */
export function errorNotices(err: unknown): Notice[] {
    const problem = (err as { problem?: ApiProblem } | null | undefined)?.problem;
    // Duck-typed rather than `instanceof ApiError`, so this module stays type-only against
    // problem.ts and a client bundled twice cannot fail the check for the wrong reason.
    if (problem && typeof problem.status === 'number' && typeof problem.title === 'string') {
        return problemNotices(problem);
    }
    const message = err instanceof Error ? err.message : typeof err === 'string' ? err : '';
    return [{ severity: 'error', detail: message || 'The request failed.' }];
}
