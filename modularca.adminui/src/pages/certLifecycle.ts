/**
 * Expiry wording, tones and ordering for certificates, shared by the dashboard, the certificate
 * list and detail pages and the self-service portal. No JSX, so the web tests can cover it.
 */
import type { CertificateAttentionItemModel, CertificateLifecycleSummaryModel } from '@shared/generated';

export type LifecycleTone = 'ok' | 'warn' | 'crit' | 'neutral';

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

const toDate = (d: string | Date): Date => (d instanceof Date ? d : new Date(d));

function plural(n: number, unit: string): string {
    return `${n} ${unit}${n === 1 ? '' : 's'}`;
}

/** A span of time in the largest unit that fits, rounded down: "3 days", "1 hour", "less than a minute". */
export function durationPhrase(ms: number): string {
    const abs = Math.abs(ms);
    if (abs < MINUTE) return 'less than a minute';
    if (abs < HOUR) return plural(Math.floor(abs / MINUTE), 'minute');
    if (abs < DAY) return plural(Math.floor(abs / HOUR), 'hour');
    if (abs < 60 * DAY) return plural(Math.floor(abs / DAY), 'day');
    if (abs < 730 * DAY) return plural(Math.floor(abs / (30 * DAY)), 'month');
    return plural(Math.floor(abs / (365 * DAY)), 'year');
}

/** "3 days ago" for the past, "in 5 days" for the future. */
export function relativeTime(target: string | Date, now: Date = new Date()): string {
    const ms = toDate(target).getTime() - now.getTime();
    return ms < 0 ? `${durationPhrase(ms)} ago` : `in ${durationPhrase(ms)}`;
}

/** "expired 3 days ago" or "expires in 5 days". */
export function expiryPhrase(notAfter: string | Date, now: Date = new Date()): string {
    return toDate(notAfter).getTime() < now.getTime()
        ? `expired ${relativeTime(notAfter, now)}`
        : `expires ${relativeTime(notAfter, now)}`;
}

/** The phrase with a capital first letter, for the start of a line. */
export function capitalize(s: string): string {
    return s ? s[0].toUpperCase() + s.slice(1) : s;
}

/** Days from now until notAfter; negative once expired. */
export function daysUntil(notAfter: string | Date, now: Date = new Date()): number {
    return (toDate(notAfter).getTime() - now.getTime()) / DAY;
}

/**
 * When a certificate's expiry warning (amber) and alert (red) start, as the server stored them from
 * its certificate profile at issuance. Both equal notAfter when the profile never warns.
 */
export interface ExpiryInstants {
    notAfter: string | Date;
    expiryWarningAt?: string | null;
    expiryAlertAt?: string | null;
}

/** Fixed windows of releases before 0.4.3, used when a row carries no instants. */
const FALLBACK_WARNING_DAYS = 30;
const FALLBACK_ALERT_DAYS = 7;

/**
 * Which expiry level a valid certificate is in at now: its alert, its warning, or neither. Uses
 * the stored instants, or the old 30- and 7-day windows when the row has none.
 */
export function expiryLevel(cert: ExpiryInstants, now: Date = new Date()): 'alert' | 'warning' | 'none' {
    const t = now.getTime();
    if (cert.expiryWarningAt) {
        if (cert.expiryAlertAt && toDate(cert.expiryAlertAt).getTime() <= t) return 'alert';
        return toDate(cert.expiryWarningAt).getTime() <= t ? 'warning' : 'none';
    }
    const days = daysUntil(cert.notAfter, now);
    if (days <= FALLBACK_ALERT_DAYS) return 'alert';
    return days <= FALLBACK_WARNING_DAYS ? 'warning' : 'none';
}

/** Whether the certificate's profile never warns of its expiry (both instants at notAfter). */
export function neverWarns(cert: ExpiryInstants): boolean {
    return !!cert.expiryWarningAt && toDate(cert.expiryWarningAt).getTime() >= toDate(cert.notAfter).getTime();
}

/**
 * Whether a certificate is expired or in its expiry warning, ignoring revoked ones. The warning
 * starts at the stored instant; a row without one falls back to soonDays before expiry.
 */
export function expiryState(cert: { revoked?: boolean; notAfter: string; expiryWarningAt?: string | null; expiryAlertAt?: string | null },
    now: Date = new Date(), soonDays = FALLBACK_WARNING_DAYS): 'revoked' | 'expired' | 'expiring' | 'active' {
    if (cert.revoked) return 'revoked';
    const days = daysUntil(cert.notAfter, now);
    if (days < 0) return 'expired';
    if (cert.expiryWarningAt) return expiryLevel(cert, now) === 'none' ? 'active' : 'expiring';
    return days <= soonDays ? 'expiring' : 'active';
}

/**
 * How loud a certificate's expiry should be. A replaced certificate is routine (neutral). One
 * that expired in the last 30 days with no replacement, or is in its expiry alert, is critical;
 * one that expired earlier or is in its expiry warning is a warning; anything else is fine. Pass
 * the certificate (or attention item) itself to use its stored instants; a bare notAfter, or a
 * row without them, uses the old 7- and 30-day windows.
 */
export function lifecycleTone(cert: string | Date | ExpiryInstants, replaced: boolean, now: Date = new Date()): LifecycleTone {
    if (replaced) return 'neutral';
    const c: ExpiryInstants = typeof cert === 'string' || cert instanceof Date ? { notAfter: cert } : cert;
    const days = daysUntil(c.notAfter, now);
    if (days < 0) return days >= -30 ? 'crit' : 'warn';
    switch (expiryLevel(c, now)) {
        case 'alert': return 'crit';
        case 'warning': return 'warn';
        default: return 'ok';
    }
}

/**
 * When the certificate's expiry warning and alert start, for its page: "No expiry warning
 * (profile)" when the profile never warns; null when the row carries no instants.
 */
export function expiryScheduleText(cert: ExpiryInstants, formatDate: (d: string) => string = (d) => new Date(d).toLocaleString()): string | null {
    if (!cert.expiryWarningAt) return null;
    if (neverWarns(cert)) return 'No expiry warning (profile)';
    const warns = `Warns from ${formatDate(String(cert.expiryWarningAt))}`;
    return cert.expiryAlertAt ? `${warns}; alert from ${formatDate(String(cert.expiryAlertAt))}` : warns;
}

/** Text colour for a tone. */
export function toneTextClass(tone: LifecycleTone): string {
    switch (tone) {
        case 'crit': return 'text-crit';
        case 'warn': return 'text-warn';
        case 'ok': return 'text-ok';
        default: return 'text-ink-muted';
    }
}

/** Dot or swatch fill for a tone. */
export function toneDotClass(tone: LifecycleTone): string {
    switch (tone) {
        case 'crit': return 'bg-crit';
        case 'warn': return 'bg-warn';
        case 'ok': return 'bg-ok';
        default: return 'bg-line-strong';
    }
}

/** Banner surface for a tone. */
export function toneBannerClass(tone: LifecycleTone): string {
    switch (tone) {
        case 'crit': return 'bg-crit-soft border-crit/40';
        case 'warn': return 'bg-warn-soft border-warn/40';
        case 'ok': return 'bg-ok-soft border-ok/40';
        default: return 'bg-sunken border-line';
    }
}

/** A date as YYYY-MM-DD in local time, the format the list's date filters take. */
export function isoDay(d: Date): string {
    const pad = (n: number) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

/**
 * List link for certificates in their expiry warning (or, with alert, their expiry alert); with
 * notReplaced, only those with no replacement that are not retired or dismissed.
 */
export function expiringLink(alert = false, notReplaced = true): string {
    return `/certificates?status=${alert ? 'alert' : 'expiring'}${notReplaced ? '&replaced=no' : ''}`;
}

export interface LifecycleHealthItem {
    key: string;
    label: string;
    tone: LifecycleTone;
    detail: string;
    to: string;
}

const certs = (n: number) => `${n} certificate${n === 1 ? '' : 's'}`;

/**
 * The dashboard's expiry health items, each with a tone and a link to the matching list. The
 * expiring item counts the certificates in their expiry warning or alert, which start at the
 * instants each certificate's profile gave it.
 */
export function lifecycleHealth(s: CertificateLifecycleSummaryModel, _now: Date = new Date()): LifecycleHealthItem[] {
    const items: LifecycleHealthItem[] = [];
    const warned = s.inExpiryWarning ?? 0, warnedOpen = s.inExpiryWarningNotReplaced ?? 0, alertedOpen = s.inExpiryAlertNotReplaced ?? 0;

    if (alertedOpen > 0) {
        items.push({ key: 'expiring', label: 'Expiring', tone: 'crit', to: expiringLink(true),
            detail: `${certs(alertedOpen)} in their expiry alert with no replacement` });
    } else if (warnedOpen > 0) {
        items.push({ key: 'expiring', label: 'Expiring', tone: 'warn', to: expiringLink(),
            detail: `${certs(warnedOpen)} in their expiry warning with no replacement` });
    } else if (warned > 0) {
        items.push({ key: 'expiring', label: 'Expiring', tone: 'ok', to: expiringLink(false, false),
            detail: s.retiredOrDismissed > 0
                ? `${certs(warned)} in their expiry warning, each replaced, retired or dismissed`
                : `${certs(warned)} in their expiry warning, all already replaced` });
    } else {
        items.push({ key: 'expiring', label: 'Expiring', tone: 'ok', to: '/certificates?status=active',
            detail: 'No certificate is in its expiry warning' });
    }

    if (s.recentlyExpiredNotReplaced > 0) {
        items.push({ key: 'expired', label: 'Expired', tone: 'crit', to: '/certificates?status=expired&replaced=no',
            detail: `${certs(s.recentlyExpiredNotReplaced)} expired in the last 30 days with no replacement` });
    } else if (s.expiredNotReplaced > 0) {
        items.push({ key: 'expired', label: 'Expired', tone: 'warn', to: '/certificates?status=expired&replaced=no',
            detail: `${certs(s.expiredNotReplaced)} expired in the last ${s.replacementWindowDays} days with no replacement` });
    } else if (s.expired > 0) {
        items.push({ key: 'expired', label: 'Expired', tone: 'neutral', to: '/certificates?status=expired',
            detail: s.expiredReplaced > 0 || s.retiredOrDismissed > 0
                ? `${certs(s.expired)} expired; every one from the last ${s.replacementWindowDays} days was replaced, retired or dismissed`
                : `${certs(s.expired)} expired more than ${s.replacementWindowDays} days ago` });
    } else {
        items.push({ key: 'expired', label: 'Expired', tone: 'ok', to: '/certificates?status=expired', detail: 'No expired certificates' });
    }

    return items;
}

/**
 * Tone of one attention item: expired recently or in its expiry alert is critical, in its expiry
 * warning a warning. An item without instants falls back to the 7- and 30-day windows.
 */
export function attentionTone(item: Pick<CertificateAttentionItemModel, 'notAfter'> & Partial<Pick<CertificateAttentionItemModel, 'expiryWarningAt' | 'expiryAlertAt'>>,
    now: Date = new Date()): LifecycleTone {
    return lifecycleTone(item, false, now);
}

/**
 * Attention items in the order they are worked: expired before expiring; expired ones most
 * recent first, expiring ones soonest first.
 */
export function sortAttention<T extends Pick<CertificateAttentionItemModel, 'notAfter' | 'serialNumber'>>(items: T[], now: Date = new Date()): T[] {
    const t = (i: T) => new Date(i.notAfter).getTime();
    const nowMs = now.getTime();
    return [...items].sort((a, b) => {
        const ae = t(a) < nowMs, be = t(b) < nowMs;
        if (ae !== be) return ae ? -1 : 1;
        const diff = ae ? t(b) - t(a) : t(a) - t(b);
        return diff !== 0 ? diff : a.serialNumber.localeCompare(b.serialNumber);
    });
}

/** What the issuance channel means for an expired or expiring certificate. */
export function channelNote(channel: string | null | undefined): string {
    switch ((channel || '').toUpperCase()) {
        case 'ACME':
            return 'Issued through ACME. Its client renews it on its own schedule, so a missing replacement usually means the client stopped: check the ACME client on the host (its timer or service, logs, and challenge setup).';
        case 'EST':
            return 'Issued through EST. The device re-enrolls itself; check the EST client and that its credential still authenticates.';
        case 'SCEP':
            return 'Issued through SCEP. Renewal is driven by the device or its MDM profile; check that the profile is still deployed and can reach the CA.';
        case 'CMP':
            return 'Issued through CMP. The client renews with a key update request; check the CMP client and its signing credential.';
        case 'MSAE':
            return 'Issued through Windows autoenrollment. Check that the computer or user still receives the Group Policy and can reach the enrollment service.';
        case 'MANUAL':
            return 'Requested from the console or the portal. Nothing renews it unless auto-renewal is on: reissue it here, or ask its owner to request a new one.';
        default:
            return 'How this certificate was issued is not on record. Reissue it here, or renew it the way it was obtained.';
    }
}

/** Short channel label for a chip; empty when unknown. */
export function channelLabel(channel: string | null | undefined): string {
    if (!channel) return '';
    return channel.toUpperCase() === 'MANUAL' ? 'Manual' : channel.toUpperCase();
}

/**
 * Whether the console offers Reissue, as on the certificate page: an active or expired
 * certificate, or one revoked only by Certificate Hold.
 */
export function canReissue(cert: { revoked?: boolean; revocationReason?: string | null; retiredAt?: string | null }): boolean {
    if (cert.retiredAt) return false;
    if (!cert.revoked) return true;
    return /hold/i.test(String(cert.revocationReason ?? ''));
}

/**
 * How an operator has handled a certificate's expiry: retired (nothing renews it, its subject
 * enrolls anew), its warning dismissed (it renews as before, quietly), or neither.
 */
export function expiryHandling(cert: { retiredAt?: string | null; expiryWarningDismissedAt?: string | null }): 'retired' | 'dismissed' | null {
    if (cert.retiredAt) return 'retired';
    if (cert.expiryWarningDismissedAt) return 'dismissed';
    return null;
}

/** The sentence the certificate page shows for a retired certificate or a dismissed warning. */
export function expiryHandlingNote(cert: { retiredAt?: string | null; retiredBy?: string | null; retiredReason?: string | null;
    expiryWarningDismissedAt?: string | null; expiryWarningDismissedBy?: string | null }): string | null {
    const by = (who: string | null | undefined) => (who ? ` by ${who}` : '');
    switch (expiryHandling(cert)) {
        case 'retired':
            return `Retired${by(cert.retiredBy)}${cert.retiredReason ? `: ${cert.retiredReason}` : ''}. It stays valid until it expires, but is not renewed or reissued; its subject needs a new enrollment.`;
        case 'dismissed':
            return `Expiry warning dismissed${by(cert.expiryWarningDismissedBy)}. It can still be renewed, by hand, by auto-renewal or by its client.`;
        default:
            return null;
    }
}
