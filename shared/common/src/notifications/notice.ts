/**
 * The structure a notification carries, and the pure logic that decides how it behaves.
 *
 * `problem.ts` already parses a refusal into title / detail / remediation / code / correlation id,
 * and a success response into a list of diagnostics with the same shape. All of it then collapsed
 * into one string on the way to `showToast`, because a toast could only hold a string. A
 * certificate-policy refusal that names the dropped EKU, explains the profile rule and quotes a
 * code arrived as one run-on sentence in a 24rem box that erased itself after five seconds.
 *
 * This module is the missing middle: a {@link Notice} is what the API layer produces and what the
 * rendering layer consumes, and neither has to know about the other. It deliberately holds no
 * React and no DOM, for two reasons. It lives in `shared/common`, which the anonymous SPAs also
 * bundle and which therefore cannot reach into `shared/authenticated` where `ApiProblem` is
 * defined — the adapters live on that side and depend on this one, never the reverse. And every
 * decision worth arguing about (how long a message stays, whether a message belongs to a control)
 * is a pure function here rather than a conditional buried in JSX, so it can be tested.
 */

/**
 * Severity of a notification.
 *
 * Identical to the old `ToastType` union, which is re-exported from `components/Toast` under its
 * original name so the existing imports keep resolving. The rename is not cosmetic: the same four
 * values now also classify a message rendered next to a form control, where "toast" would be the
 * wrong word.
 */
export type NoticeSeverity = 'success' | 'error' | 'warning' | 'info';

/**
 * One structured message.
 *
 * Every field is optional because the sources disagree about which they populate: a
 * `ProfileValidationException` has a `parameter` and no `code`, a diagnostic has a `code` and a
 * `field` but never a correlation id, and a plain `catch (err)` has nothing but a sentence. A
 * renderer therefore has to handle any subset, and the alternative — four near-identical
 * interfaces — would only push that same branching into the call sites.
 */
export interface Notice {
    /** Severity, when the notice carries its own. A toast takes its severity from its type. */
    severity?: NoticeSeverity;
    /** Short classification, e.g. "Certificate policy violation". */
    title?: string;
    /** The explanatory sentence — the part actually worth reading. */
    detail?: string;
    /** What the operator should do about it. */
    remediation?: string;
    /** Stable identifier, e.g. MCA-ISS-003. Exists to be pasted into a ticket. */
    code?: string;
    /** Correlation id for the server log. Also exists to be pasted into a ticket. */
    correlationId?: string;
    /**
     * The request or profile field this concerns, in whatever spelling its source used —
     * `extendedKeyUsages` from a diagnostic, `NotAfter` from model state, "Signature algorithm"
     * from a profile refusal. {@link fieldMatches} is what reconciles those spellings.
     */
    field?: string;
    /** Supporting lines: policy violations, permitted values, one entry per model-state message. */
    items?: string[];
}

/**
 * What a notification surface accepts.
 *
 * The string arm is the whole compatibility story. There are 238 `showToast(type, message)` calls
 * across the five SPAs and none of them change; a structured notice is simply the other thing the
 * same parameter now accepts.
 */
export type NoticeInput = string | Notice;

/** True when a notification payload is structured rather than a bare string. */
export function isNotice(value: NoticeInput): value is Notice {
    return typeof value === 'object' && value !== null;
}

/** Wraps a bare string as a notice, so a renderer can treat both arms identically. */
export function toNotice(value: NoticeInput, severity?: NoticeSeverity): Notice {
    if (isNotice(value)) return severity && !value.severity ? { ...value, severity } : value;
    return { detail: value, severity };
}

/**
 * Renders a notice as the single line it used to be.
 *
 * Kept because some places genuinely only have room for one line — a `title` attribute, a list
 * entry inside another notice, an `Error.message` — and because it is the text a "copy" action
 * should produce. The ordering mirrors `composeMessage` in `problem.ts`: detail first because it
 * is the explanation, the title only when it says something the detail does not, then the
 * remediation, then the bracketed code.
 */
export function noticeText(value: NoticeInput): string {
    const n = toNotice(value);
    const parts: string[] = [];
    if (n.title && n.title !== n.detail) parts.push(n.title);
    if (n.detail) parts.push(n.detail);
    if (n.items?.length) parts.push(n.items.join('; '));
    if (n.remediation) parts.push(n.remediation);
    let text = parts.join(' ');
    if (n.code) text = text ? `${text} [${n.code}]` : `[${n.code}]`;
    if (n.correlationId) {
        const suffix = `(correlation id ${n.correlationId})`;
        text = text ? `${text} ${suffix}` : suffix;
    }
    return text;
}

/**
 * How long a toast of this severity stays on screen, in milliseconds. Zero means "until
 * dismissed".
 *
 * Success and info keep the historical five seconds: they confirm that what was asked for is what
 * happened, so the message is a receipt and re-reading it changes nothing.
 *
 * Errors and warnings get much longer, and warnings for the same reason as errors rather than as a
 * softer version of them. The difference between the two is only whether a certificate came out the
 * other end — not whether the operator got what they asked for. `MCA-ISS-003` reports a certificate
 * that was issued *without* the extended key usages that were requested: the artifact exists, it is
 * already signed, and it will fail in production for a reason nothing else will explain. That is
 * the single most valuable sentence this system produces and it was disappearing on a five-second
 * timer alongside "Saved".
 *
 * These were briefly pinned open instead — lifetime 0, dismissed only by a click. That was the
 * wrong correction. It fixed the message that mattered by making every incidental refusal into
 * litter the operator had to clear by hand, and during a bulk action a screenful of them. The
 * timers below are long enough to read a policy refusal and copy a code out of it, and
 * {@link Toast} suspends its timer while the pointer is over the toast or focus is inside it, so
 * anything actually being read or copied from stays until it is let go. A call site that wants a
 * toast pinned regardless can still pass 0, which always wins.
 */
export function autoDismissMs(severity: NoticeSeverity): number {
    if (severity === 'error') return 15000;
    if (severity === 'warning') return 12000;
    return 5000;
}

/**
 * Reduces a field name to a comparison key.
 *
 * The three sources spell the same field three ways. A diagnostic says `extendedKeyUsages`; ASP.NET
 * model state says `NotAfter`, or `$.notAfter` when the failure happened in the JSON reader, or
 * `request.NotAfter` when it is nested; a profile refusal says "Signature algorithm", which is
 * prose. Case, separators and the owning path are therefore all noise — only the trailing
 * identifier's letters and digits carry meaning.
 */
export function normalizeFieldName(name: string): string {
    const last = name
        .replace(/\[\d+\]/g, '')
        .split(/[.[\]/]/)
        .filter(segment => segment.trim().length > 0)
        .pop() ?? '';
    return last.toLowerCase().replace(/[^a-z0-9]/g, '');
}

/**
 * True when a notice's field refers to one of the names a control answers to.
 *
 * Controls declare their own aliases rather than consulting a synonym table here, because the
 * mismatches are local and asymmetric: the reissue form's `notAfter` input is what the server
 * calls `validTo` in a diagnostic and `NotAfter` in model state, and only that form knows it. A
 * central table of such pairs would have to be updated from the far side of the wire and would
 * silently rot.
 *
 * A notice with no field, or a field that normalizes to nothing, matches no control — otherwise
 * an empty string would attach every unscoped message to the first control that asked.
 */
export function fieldMatches(field: string | undefined, names: string | string[]): boolean {
    if (!field) return false;
    const key = normalizeFieldName(field);
    if (!key) return false;
    const candidates = typeof names === 'string' ? [names] : names;
    return candidates.some(candidate => normalizeFieldName(candidate) === key);
}

/** The notices that belong next to a control answering to any of `names`. */
export function selectFieldNotices(notices: Notice[], names: string | string[]): Notice[] {
    return notices.filter(notice => fieldMatches(notice.field, names));
}

/**
 * The notices no rendered control has claimed, for the summary banner.
 *
 * The complement of {@link selectFieldNotices}, and it takes the list of field names the form
 * actually renders rather than simply returning the unscoped notices. A form that inlines
 * `notAfter` but has no control for `keyAlgorithm` must still show a `keyAlgorithm` message
 * somewhere; filtering on "has a field" alone would drop it on the floor, which is the failure
 * mode this whole effort exists to remove.
 */
export function unclaimedNotices(notices: Notice[], claimed: string | string[]): Notice[] {
    const names = typeof claimed === 'string' ? [claimed] : claimed;
    return notices.filter(notice => !fieldMatches(notice.field, names));
}

/** Rank used to compare severities; only the ordering matters. */
const SEVERITY_RANK: Record<NoticeSeverity, number> = { success: 0, info: 1, warning: 2, error: 3 };

/**
 * The most serious severity in a list, or `fallback` when the list is empty or unlabelled.
 *
 * Lets a caller pick one toast type for a set of diagnostics without writing
 * `diagnostics.length ? 'warning' : 'success'`, which is what the issuance page did — and which
 * promotes a purely informational diagnostic to a warning, so the operator learns that a warning
 * badge does not necessarily mean anything is wrong.
 */
export function worstSeverity(notices: Notice[], fallback: NoticeSeverity = 'info'): NoticeSeverity {
    let worst = fallback;
    for (const notice of notices) {
        if (notice.severity && SEVERITY_RANK[notice.severity] > SEVERITY_RANK[worst]) {
            worst = notice.severity;
        }
    }
    return worst;
}

/**
 * Folds a headline and a list of notices into the one notice a toast can show.
 *
 * A single notice keeps its structure — remediation and code stay in their own slots, so the code
 * remains copyable — and only gains the headline. Its own title is folded into the detail rather
 * than being overwritten by the headline: "Certificate issued for CN=host" and "Extended key usage
 * dropped" are both worth reading, and the second one is the one that matters.
 *
 * Several notices become list items, because there is no honest way to merge two remediations into
 * one sentence and flattening them into prose is what produced the run-on toast in the first place.
 */
export function mergeNotices(title: string, notices: Notice[]): Notice {
    if (notices.length === 0) return { title };
    if (notices.length === 1) {
        const only = notices[0];
        const ownTitle = only.title && only.title !== only.detail ? only.title : undefined;
        const detail = ownTitle ? (only.detail ? `${ownTitle}: ${only.detail}` : ownTitle) : only.detail;
        return { ...only, title, detail };
    }
    return {
        title,
        severity: worstSeverity(notices),
        items: notices.map(noticeText),
    };
}
