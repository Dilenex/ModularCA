import type { ValidityCeilingPreflight } from '@shared/generated';
import { describeCeiling } from './validityCeiling';

/**
 * The "Valid until" date picker offered when an approved request is issued, on the request page
 * and in the bulk issue dialog.
 *
 * Bug hunt 2026-11: the picker's max was the raw certificate profile's period added to now and cut
 * to a UTC calendar date, and the chosen day was sent as 23:59:59 UTC. The last day offered could
 * therefore run up to a day past the server's ceiling, which refuses a notAfter beyond it, and near
 * midnight the day shown was not the operator's day. It also ignored the space and issuing-CA
 * ceilings and the profile inheritance issuance applies.
 *
 * The limit now comes from the server's validity pre-flight, the same answer the Issue Certificate
 * form uses, and every date is the operator's local day. The server stays the authority: it still
 * refuses anything past its ceiling, and an unknown ceiling leaves the picker unbounded.
 */

/** Formats a `Date` as the local calendar day `<input type="date">` reads and writes. Not `toISOString()`, which is the UTC day. */
export function toDateInputValue(d: Date): string {
    const pad = (v: number) => String(v).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

/** The fields of a certificate request the pre-flight needs. */
export interface CeilingRequestFields {
    signingProfileId?: string | null;
    certificateProfileId?: string | null;
    certProfileId?: string | null;
    requestedNotBefore?: string | null;
}

/**
 * The validity pre-flight to ask for a request, or null when it lacks a profile. It passes the start
 * the request asked for, because issuing without an explicit start falls back to that one, and the
 * ceiling is measured from the start.
 */
export function validityCeilingUrl(csr: CeilingRequestFields | null | undefined): string | null {
    const signingProfileId = csr?.signingProfileId;
    const certProfileId = csr?.certificateProfileId || csr?.certProfileId;
    if (!signingProfileId || !certProfileId) return null;
    let url = `/api/v1/admin/certificates/validity-ceiling?signingProfileId=${encodeURIComponent(signingProfileId)}`
        + `&certProfileId=${encodeURIComponent(certProfileId)}`;
    if (csr?.requestedNotBefore) url += `&notBefore=${encodeURIComponent(csr.requestedNotBefore)}`;
    return url;
}

/** What the picker is bound to. */
export interface ValidUntilLimit {
    /** The picker's `max`: the local day the ceiling falls on. */
    maxDate: string;
    /** The ceiling itself; a day chosen on `maxDate` is sent as this instant. */
    latest: Date;
    /** The pre-flight's sentence: the ceiling and the layer that set it. */
    text: string;
}

/** The picker's limit from a pre-flight answer, or null when it is unknown or has already passed. */
export function validUntilLimit(p: ValidityCeilingPreflight | null): ValidUntilLimit | null {
    if (!p) return null;
    const notice = describeCeiling(p);
    if (!notice.maxInputValue) return null;
    const latest = new Date(p.resolution.effectiveNotAfter);
    return { maxDate: toDateInputValue(latest), latest, text: notice.text };
}

/** The limit as the hint beside the picker states it: the pre-flight's sentence and the latest instant, in local time. */
export function describeValidUntilLimit(limit: ValidUntilLimit): string {
    const latest = limit.latest.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
    return `${limit.text}. The latest is ${latest} local time.`;
}

/**
 * The notAfter to send for a chosen day: the end of that local day, or the ceiling when the ceiling
 * falls earlier on it. Undefined for a blank or unreadable day, which lets the server use the
 * profile default.
 */
export function validUntilNotAfter(dateValue: string, p: ValidityCeilingPreflight | null): string | undefined {
    const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(dateValue);
    if (!m) return undefined;
    const endOfDay = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]), 23, 59, 59);
    if (Number.isNaN(endOfDay.getTime())) return undefined;
    const limit = validUntilLimit(p);
    return limit && endOfDay.getTime() > limit.latest.getTime()
        ? limit.latest.toISOString()
        : endOfDay.toISOString();
}
