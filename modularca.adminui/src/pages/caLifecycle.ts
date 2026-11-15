/*
 * What the console says about a CA's key and certificate over time: the notices the server
 * raises (certificate nearing its end, profiles asking for more time than it has left, a key
 * past the configured usage period, a certificate that outlives its parent's), the facts behind
 * them, and the three settings that decide when a notice appears. Nothing here changes a CA.
 */
import type { CaKeyAdvisory } from './tighterDefaults';

/** `PUT /api/v1/admin/config/ca-lifecycle`, and `caLifecycle` in `GET /api/v1/admin/config`. Days; 0 is off. */
export interface CaLifecycleSettings {
    rootExpiryNoticeDays: number;
    intermediateExpiryNoticeDays: number;
    keyUsagePeriodDays: number;
}

/** What a new install and an upgraded one both start with. */
export const CA_LIFECYCLE_DEFAULTS: CaLifecycleSettings = { rootExpiryNoticeDays: 730, intermediateExpiryNoticeDays: 365, keyUsagePeriodDays: 0 };

/** The largest value the server accepts for any of the three, in days. */
export const CA_LIFECYCLE_MAX_DAYS = 36500;

const days = (value: unknown, fallback: number): number =>
    typeof value === 'number' && Number.isFinite(value) ? value : fallback;

/** The body the save sends: the three numbers, with what the server holds for a field the page has not loaded. */
export function caLifecycleBody(section: Partial<CaLifecycleSettings> | null | undefined): CaLifecycleSettings {
    return {
        rootExpiryNoticeDays: days(section?.rootExpiryNoticeDays, CA_LIFECYCLE_DEFAULTS.rootExpiryNoticeDays),
        intermediateExpiryNoticeDays: days(section?.intermediateExpiryNoticeDays, CA_LIFECYCLE_DEFAULTS.intermediateExpiryNoticeDays),
        keyUsagePeriodDays: days(section?.keyUsagePeriodDays, CA_LIFECYCLE_DEFAULTS.keyUsagePeriodDays),
    };
}

/** Why the card cannot be saved as it stands, or null. The server applies the same bounds. */
export function caLifecycleProblem(section: Partial<CaLifecycleSettings> | null | undefined): string | null {
    const body = caLifecycleBody(section);
    const fields: [string, number][] = [
        ['The root CA expiry notice', body.rootExpiryNoticeDays],
        ['The intermediate CA expiry notice', body.intermediateExpiryNoticeDays],
        ['The CA key usage period', body.keyUsagePeriodDays],
    ];
    for (const [name, value] of fields) {
        if (!Number.isInteger(value) || value < 0 || value > CA_LIFECYCLE_MAX_DAYS)
            return `${name} must be from 0 to ${CA_LIFECYCLE_MAX_DAYS} days.`;
    }
    return null;
}

/** The card's one-line summary. */
export function caLifecycleSummary(section: Partial<CaLifecycleSettings> | null | undefined): string {
    const body = caLifecycleBody(section);
    const window = (n: number) => (n > 0 ? `${n}d` : 'off');
    return `Root ${window(body.rootExpiryNoticeDays)} / intermediate ${window(body.intermediateExpiryNoticeDays)} before expiry; key usage period ${body.keyUsagePeriodDays > 0 ? `${body.keyUsagePeriodDays}d` : 'off'}`;
}

/** How loud a notice is shown: `notice` is something to plan for, `warn` a close deadline, `crit` something stopped. */
export type AdvisoryTone = 'notice' | 'warn' | 'crit';

/** The tone of a notice from its `severity`; a notice from a server that sends none is something to plan for. */
export function advisoryTone(advisory: Pick<CaKeyAdvisory, 'severity'> | null | undefined): AdvisoryTone {
    return advisory?.severity === 'critical' ? 'crit' : advisory?.severity === 'warning' ? 'warn' : 'notice';
}

/**
 * How a notice is shown as an `InlineNotice`: a notice is informational (blue), a warning is
 * amber, and only something critical is red. A notice is never amber: amber means a deadline.
 */
export function advisoryNoticeSeverity(advisory: Pick<CaKeyAdvisory, 'severity'> | null | undefined): 'info' | 'warning' | 'error' {
    const tone = advisoryTone(advisory);
    return tone === 'crit' ? 'error' : tone === 'warn' ? 'warning' : 'info';
}

/** The `StatusBadge` status with a notice's color: blue (`pending`), amber (`held`) or red (`revoked`). */
export function advisoryBadgeStatus(advisory: Pick<CaKeyAdvisory, 'severity'> | null | undefined): 'pending' | 'held' | 'revoked' {
    const tone = advisoryTone(advisory);
    return tone === 'crit' ? 'revoked' : tone === 'warn' ? 'held' : 'pending';
}

/** The border-and-background and the text classes of a hand-built notice box, from the console's status tokens. */
export function advisoryBox(tone: AdvisoryTone): { box: string; text: string } {
    return tone === 'crit' ? { box: 'border-crit/40 bg-crit-soft', text: 'text-crit' }
        : tone === 'warn' ? { box: 'border-warn/40 bg-warn-soft', text: 'text-warn' }
        : { box: 'border-info/40 bg-info-soft', text: 'text-info' };
}

/** The words for a badge or a heading: the server's `title`, or what the console said before notices carried one. */
export function advisoryTitle(advisory: Pick<CaKeyAdvisory, 'title' | 'reason'>): string {
    if (typeof advisory.title === 'string' && advisory.title.trim() !== '') return advisory.title;
    return advisory.reason === 'CaRsaKeyBelow3072' ? 'Replace before 2031' : 'Notice';
}

/** The facts behind a CA's notices, as `cryptoperiod` in the hierarchy feed carries them. */
export interface CaCryptoperiod {
    isRoot?: boolean;
    keyInUseSince?: string | null;
    keyInUseSinceSource?: string | null;
    keyInUseDays?: number | null;
    certificateCount?: number | null;
    certificateNotBefore?: string | null;
    certificateNotAfter?: string | null;
    daysRemaining?: number | null;
    latestIssuedNotAfter?: string | null;
    longestProfileValidityDays?: number | null;
    longestProfileName?: string | null;
    /** True when the CA has no end-entity profile with a maximum and the one shown is one of its own infrastructure profiles. */
    longestProfileIsInfrastructure?: boolean;
    /** The parent CA's name; null for a root and for a parent outside the viewer's space fence. */
    parentName?: string | null;
    /** The end of the parent's certificate; null for a root and for a parent outside the viewer's space fence. */
    parentCertificateNotAfter?: string | null;
}

/** "412 days", "1 day", "3.2 years": a number of days in the unit a person plans in. */
export function daysPhrase(value: number | null | undefined): string {
    if (typeof value !== 'number' || !Number.isFinite(value)) return '-';
    const n = Math.abs(Math.trunc(value));
    if (n < 730) return n === 1 ? '1 day' : `${n} days`;
    const years = Math.round((n / 365.25) * 10) / 10;
    return `${years} years`;
}

const day = (value: string | null | undefined): string | null => {
    if (!value) return null;
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString().slice(0, 10);
};

/** One row of the CA page's "Key and certificate lifetime" section. */
export interface CryptoperiodRow {
    label: string;
    value: string;
    /** What the value is and where it comes from, for the field's hint. */
    hint?: string;
}

/** The rows the CA page shows for a CA's cryptoperiod; empty when the server sent none. */
export function cryptoperiodRows(period: CaCryptoperiod | null | undefined): CryptoperiodRow[] {
    if (!period) return [];
    const rows: CryptoperiodRow[] = [];
    const since = day(period.keyInUseSince);
    if (since)
        rows.push({
            label: 'Key in use since',
            value: `${since} (${daysPhrase(period.keyInUseDays)})`,
            hint: period.keyInUseSinceSource || undefined,
        });
    if (typeof period.certificateCount === 'number')
        rows.push({
            label: 'Certificates over this key',
            value: period.certificateCount === 1 ? '1 (never renewed)' : `${period.certificateCount} (renewed ${period.certificateCount - 1} time${period.certificateCount === 2 ? '' : 's'})`,
        });
    const end = day(period.certificateNotAfter);
    if (end) {
        const left = period.daysRemaining;
        rows.push({
            label: 'Current certificate expires',
            value: typeof left === 'number' ? (left < 0 ? `${end} (expired ${daysPhrase(left)} ago)` : `${end} (in ${daysPhrase(left)})`) : end,
        });
    }
    const latest = day(period.latestIssuedNotAfter);
    rows.push({
        label: 'Latest expiry it has issued',
        value: latest || 'No unexpired certificate',
        hint: 'The latest end of validity among the unexpired, unrevoked certificates issued under this key.',
    });
    if (typeof period.longestProfileValidityDays === 'number')
        rows.push({
            label: period.longestProfileIsInfrastructure ? 'Longest validity its profiles allow (infrastructure only)' : 'Longest validity its profiles allow',
            value: `${daysPhrase(period.longestProfileValidityDays)}${period.longestProfileName ? ` (${period.longestProfileName})` : ''}`,
            hint: period.longestProfileIsInfrastructure
                ? 'No end-entity profile linked to this CA sets a maximum. This is one of the CA\'s own infrastructure profiles (OCSP responder, timestamp, CMP signer), whose certificates are issued to end with the CA\'s.'
                : 'End-entity profiles only. A certificate that would end after the CA certificate is shortened to end five minutes before it.',
        });
    const parentEnd = day(period.parentCertificateNotAfter);
    if (parentEnd)
        rows.push({ label: "Parent's certificate expires", value: `${parentEnd}${period.parentName ? ` (${period.parentName})` : ''}` });
    return rows;
}

/** What the dashboard shows under "Needs attention" for one CA. */
export interface CaAttentionItem {
    caId: string;
    caName: string;
    tone: 'warn' | 'crit';
    title: string;
    message: string;
    /** The CA's page, as a route inside this console. */
    to: string;
}

/**
 * The CAs to list under "Needs attention", from the answer of `/health/ready`
 * (`checks.caLifecycle`): one entry for each CA with a notice that is a warning or critical,
 * with its most pressing notice. A notice that is only something to plan for is not listed
 * here; it is on the CA's page and on System Health. Nothing when the answer could not be read.
 */
export function caLifecycleAttention(health: unknown): CaAttentionItem[] {
    const cas = (health as { checks?: { caLifecycle?: { cas?: unknown } } } | null | undefined)?.checks?.caLifecycle?.cas;
    if (!Array.isArray(cas)) return [];
    const items: CaAttentionItem[] = [];
    for (const ca of cas as any[]) {
        if (!ca || typeof ca.caId !== 'string' || !Array.isArray(ca.keyAdvisories)) continue;
        const pressing = (ca.keyAdvisories as CaKeyAdvisory[]).filter((a) => a && advisoryTone(a) !== 'notice');
        if (pressing.length === 0) continue;
        const first = pressing.find((a) => advisoryTone(a) === 'crit') || pressing[0];
        const name = typeof ca.caName === 'string' && ca.caName !== '' ? ca.caName : ca.caId;
        items.push({
            caId: ca.caId,
            caName: name,
            tone: advisoryTone(first) === 'crit' ? 'crit' : 'warn',
            title: `${name}: ${advisoryTitle(first)}`,
            message: typeof first.message === 'string' ? first.message : '',
            to: `/authorities/manage/${encodeURIComponent(ca.caId)}`,
        });
    }
    return items;
}
