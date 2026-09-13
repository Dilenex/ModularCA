import type { ValidityCeilingPreflight } from '@shared/generated';

/**
 * The pure half of the Issue Certificate form's validity pre-flight: turning the server's answer
 * into the sentence shown beside the validity inputs, and into the `max` the date picker is bound
 * to.
 *
 * Split out of `IssueCertificate.tsx` for the reason `requestProfileRules.ts` is split out of its
 * editor — every decision here is arguable and none of it needs React. Two in particular are worth
 * covering rather than trusting:
 *
 * The first is the local-time conversion. `<input type="datetime-local">` reads and writes LOCAL
 * wall-clock components, and the ceiling arrives from the API as a UTC instant. Seeding one from
 * the other through `toISOString()` is precisely the defect that once shipped in this form's
 * `notBefore`: the field opened pre-filled one UTC offset in the future, and the certificates it
 * produced were invalid to every relying party until that time arrived. A `max` built the same
 * wrong way would be off by the host's offset in whichever direction the host happens to sit —
 * silently permitting an over-long request west of UTC, and silently forbidding a legal one east
 * of it.
 *
 * The second is naming the binding layer. "Max 730 days" on its own sends an operator to whichever
 * screen they guess first, and the wrong guess costs a profile edit, a reload, and the same 730
 * days.
 */

/** What the form renders beside the validity inputs. */
export interface CeilingNotice {
    /** One sentence: the ceiling, the layer that set it, and what the other layers allowed. */
    text: string;
    /**
     * Local wall-clock value for the Not After picker's `max` attribute, or '' when there is no
     * usable ceiling (an already-expired issuing CA), in which case the picker stays unbounded and
     * the server remains the authority.
     */
    maxInputValue: string;
    /**
     * 'warn' when exceeding this ceiling costs the operator the request outright — a tenant set to
     * refuse. 'info' when it would merely be shortened. Rendering both the same way is wrong in one
     * of the two cases.
     */
    tone: 'info' | 'warn';
}

/**
 * Formats a `Date` as the local wall-clock string `<input type="datetime-local">` expects.
 *
 * Not `toISOString()`. That returns UTC, and this field is read as local time, so the difference
 * is the host's UTC offset applied in the wrong direction.
 */
export function toDatetimeLocalValue(d: Date): string {
    const pad = (v: number) => String(v).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
        + `T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/**
 * Renders an ISO-8601 duration compactly for the "profile allows …" aside — `P3Y` as `3y`,
 * `P18M` as `18mo`, `PT12H` as `12h`.
 *
 * Anything it does not recognise is echoed verbatim rather than guessed at. This string is shown
 * next to a number the operator is about to act on, and a duration rendered wrongly is worse than
 * one rendered as the raw `P…` the profile actually stores.
 */
export function formatIso8601Duration(iso: string | null | undefined): string | null {
    if (!iso) return null;
    const m = /^P(?!$)(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?(?:T(?!$)(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$/.exec(iso);
    if (!m) return iso;
    const units: [string | undefined, string][] = [
        [m[1], 'y'], [m[2], 'mo'], [m[3], 'w'], [m[4], 'd'],
        [m[5], 'h'], [m[6], 'min'], [m[7], 's'],
    ];
    const parts = units.filter(([v]) => v).map(([v, suffix]) => `${v}${suffix}`);
    return parts.length > 0 ? parts.join(' ') : iso;
}

/** Formats a date for the "expires …" aside, in the viewer's locale, date only. */
function formatDate(iso: string): string {
    return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

/**
 * Builds the notice shown beside the validity inputs from a pre-flight response.
 *
 * The parenthetical aside always names what the *other* layers would have allowed, because that is
 * the part that tells an operator whether raising the ceiling is even possible: a tenant cap of 730
 * days against a profile that allows three years is a tenant conversation, whereas the same 730
 * days against a profile that allows exactly 730 is not.
 */
export function describeCeiling(p: ValidityCeilingPreflight): CeilingNotice {
    const days = p.resolution.effectiveMaxDays;
    const profileAllows = formatIso8601Duration(p.certProfileValidityPeriodMax) ?? '1y';
    const refuses = p.tenantCeilingApplies && p.tenantBehavior === 'Refuse';

    let text: string;
    switch (p.resolution.boundBy) {
        case 'Tenant':
            text = `Max ${days} days — capped by tenant '${p.tenantName ?? 'unknown'}'`
                + ` (profile allows ${profileAllows})`;
            break;
        case 'IssuingCa':
            // Not a policy ceiling at all, and the only one of the three with a deadline attached:
            // it moves on its own as the CA ages, and the fix is to renew the CA.
            text = `Max ${days} days — capped by issuing CA '${p.issuingCaName ?? 'unknown'}',`
                + ` which expires ${p.issuingCaNotAfter ? formatDate(p.issuingCaNotAfter) : 'sooner'}`;
            break;
        default:
            text = `Max ${days} days — from certificate profile '${p.certProfileName}' (${profileAllows})`;
            break;
    }

    // Stated whenever the tenant refuses, not only when the tenant is the binding layer: the CA may
    // be the narrower limit today and stop being it after the CA is renewed, and an operator who
    // was never told about the refusal will meet it then.
    if (refuses && p.tenantMaxValidityDays > 0) {
        text += ` · Tenant '${p.tenantName ?? 'unknown'}' refuses requests beyond`
            + ` ${p.tenantMaxValidityDays} days rather than shortening them`;
    }

    return {
        text,
        maxInputValue: days > 0 ? toDatetimeLocalValue(new Date(p.resolution.effectiveNotAfter)) : '',
        tone: refuses ? 'warn' : 'info',
    };
}

/**
 * True when the Not After currently typed into the form is past the effective ceiling.
 *
 * The date picker's `max` is not enough on its own. Browsers vary in whether they block an
 * out-of-range value or merely mark it invalid, and a value can arrive by paste or by keyboard in
 * either case — so the form checks the value rather than trusting the attribute to have prevented
 * it.
 *
 * @param notAfterLocalValue The raw `<input type="datetime-local">` value, i.e. local wall-clock.
 * @param p The pre-flight answer, or null when it has not loaded; null means "cannot tell", not "fine".
 */
export function exceedsCeiling(
    notAfterLocalValue: string,
    p: ValidityCeilingPreflight | null,
): boolean {
    if (!p || !notAfterLocalValue) return false;
    const requested = new Date(notAfterLocalValue);
    if (Number.isNaN(requested.getTime())) return false;
    return requested.getTime() > new Date(p.resolution.effectiveNotAfter).getTime();
}
