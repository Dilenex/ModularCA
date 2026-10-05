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

/** Whether a certificate is expired or expiring within soonDays, ignoring revoked ones. */
export function expiryState(cert: { revoked?: boolean; notAfter: string }, now: Date = new Date(), soonDays = 30): 'revoked' | 'expired' | 'expiring' | 'active' {
    if (cert.revoked) return 'revoked';
    const days = daysUntil(cert.notAfter, now);
    if (days < 0) return 'expired';
    return days <= soonDays ? 'expiring' : 'active';
}

/**
 * How loud a certificate's expiry should be. A replaced certificate is routine (neutral). One
 * that expired in the last 30 days with no replacement, or expires within 7, is critical; one
 * that expired earlier or expires within 30 days is a warning; anything further out is fine.
 */
export function lifecycleTone(notAfter: string | Date, replaced: boolean, now: Date = new Date()): LifecycleTone {
    if (replaced) return 'neutral';
    const days = daysUntil(notAfter, now);
    if (days < 0) return days >= -30 ? 'crit' : 'warn';
    if (days <= 7) return 'crit';
    if (days <= 30) return 'warn';
    return 'ok';
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

/** List link for active certificates expiring within days with no replacement. */
export function expiringLink(days: number, now: Date = new Date()): string {
    return `/certificates?status=active&replaced=no&notAfterTo=${isoDay(new Date(now.getTime() + (days + 1) * DAY))}`;
}

export interface LifecycleHealthItem {
    key: string;
    label: string;
    tone: LifecycleTone;
    detail: string;
    to: string;
}

const certs = (n: number) => `${n} certificate${n === 1 ? '' : 's'}`;

/** The dashboard's expiry health items, each with a tone and a link to the matching list. */
export function lifecycleHealth(s: CertificateLifecycleSummaryModel, now: Date = new Date()): LifecycleHealthItem[] {
    const items: LifecycleHealthItem[] = [];

    if (s.expiringWithin7DaysNotReplaced > 0) {
        items.push({ key: 'expiring', label: 'Expiring', tone: 'crit', to: expiringLink(7, now),
            detail: `${certs(s.expiringWithin7DaysNotReplaced)} expire within 7 days with no replacement` });
    } else if (s.expiringWithin30DaysNotReplaced > 0) {
        items.push({ key: 'expiring', label: 'Expiring', tone: 'warn', to: expiringLink(30, now),
            detail: `${certs(s.expiringWithin30DaysNotReplaced)} expire within 30 days with no replacement` });
    } else if (s.expiringWithin30Days > 0) {
        items.push({ key: 'expiring', label: 'Expiring', tone: 'ok', to: `/certificates?status=active&notAfterTo=${isoDay(new Date(now.getTime() + 31 * DAY))}`,
            detail: `${certs(s.expiringWithin30Days)} expire within 30 days, all already replaced` });
    } else {
        items.push({ key: 'expiring', label: 'Expiring', tone: 'ok', to: '/certificates?status=active',
            detail: 'Nothing expires within 30 days' });
    }

    if (s.recentlyExpiredNotReplaced > 0) {
        items.push({ key: 'expired', label: 'Expired', tone: 'crit', to: '/certificates?status=expired&replaced=no',
            detail: `${certs(s.recentlyExpiredNotReplaced)} expired in the last 30 days with no replacement` });
    } else if (s.expiredNotReplaced > 0) {
        items.push({ key: 'expired', label: 'Expired', tone: 'warn', to: '/certificates?status=expired&replaced=no',
            detail: `${certs(s.expiredNotReplaced)} expired in the last ${s.replacementWindowDays} days with no replacement` });
    } else if (s.expired > 0) {
        items.push({ key: 'expired', label: 'Expired', tone: 'neutral', to: '/certificates?status=expired',
            detail: s.expiredReplaced > 0
                ? `${certs(s.expired)} expired; every one from the last ${s.replacementWindowDays} days was replaced`
                : `${certs(s.expired)} expired more than ${s.replacementWindowDays} days ago` });
    } else {
        items.push({ key: 'expired', label: 'Expired', tone: 'ok', to: '/certificates?status=expired', detail: 'No expired certificates' });
    }

    return items;
}

/** Tone of one attention item: expired or within 7 days is critical, the rest a warning. */
export function attentionTone(item: Pick<CertificateAttentionItemModel, 'notAfter'>, now: Date = new Date()): LifecycleTone {
    return lifecycleTone(item.notAfter, false, now);
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
export function canReissue(cert: { revoked?: boolean; revocationReason?: string | null }): boolean {
    if (!cert.revoked) return true;
    return /hold/i.test(String(cert.revocationReason ?? ''));
}
