/*
 * What the console says about the three sets of defaults 0.4.5 tightened (NIST SP 800-63B for
 * sessions and passwords, SP 800-57 for CA keys). A new install starts with them; an install made
 * earlier keeps what it has stored and is offered them here. Nothing in this module changes a
 * setting: it words the offer.
 */

/** The maximum session lifetime a new install gets, in hours (SP 800-63B, AAL2 and AAL3). */
export const RECOMMENDED_SESSION_HOURS = 12;

/** The smallest RSA key a new CA may have, in bits (SP 800-57: RSA 2048 only through 2030). */
export const MIN_CA_RSA_BITS = 3072;

/** The id of the NIST SP 800-63B password policy preset in the admin API. */
export const NIST_PASSWORD_PRESET = 'nist-sp-800-63b';

/** What the preset sets, as one phrase. */
export const NIST_PRESET_SUMMARY =
    'minimum length 15, no required character classes, no expiry, and the bundled blocklist on (a maximum length under 64 becomes 128)';

/** `GET /api/v1/admin/password-policy/guidance`. */
export interface PasswordPolicyGuidance {
    nist80063B: { preset: string; name: string; meets: boolean; differences: string[] };
    bundledBlocklist: { available: boolean; entries: number; fileName: string; inUse: boolean };
}

/** One thing to know about a CA's own key, as the API reports it. */
export interface CaKeyAdvisory {
    /** A stable code, e.g. `CaRsaKeyBelow3072`. */
    reason: string;
    /** The sentence to show the operator. */
    message: string;
}

/** A CA, X.509 or SSH, whose key carries a notice. */
export interface CaKeyFinding {
    /** Where the CA's page is. */
    link: string;
    caName: string;
    advisory: CaKeyAdvisory;
}

const number = (value: unknown): number => (typeof value === 'number' && Number.isFinite(value) ? value : Number(value) || 0);

/** "12 hours", "336 hours (14 days)", "36 hours (1.5 days)", "no maximum". */
export function hoursPhrase(hours: unknown): string {
    const h = number(hours);
    if (h <= 0) return 'no maximum';
    const unit = h === 1 ? 'hour' : 'hours';
    if (h < 24) return `${h} ${unit}`;
    const days = Math.round((h / 24) * 10) / 10;
    return `${h} ${unit} (${days} ${days === 1 ? 'day' : 'days'})`;
}

/**
 * Why the stored maximum session lifetime is worth a look, or null when it is 12 hours or less.
 * Shown beside the field with a button that fills in 12; the administrator still saves.
 */
export function sessionMaximumAdvice(hours: unknown): string | null {
    const h = number(hours);
    if (h > 0 && h <= RECOMMENDED_SESSION_HOURS) return null;
    return h <= 0
        ? `NIST SP 800-63B asks for a new sign-in at least every ${RECOMMENDED_SESSION_HOURS} hours. This instance sets no maximum, so an active session never has to sign in again.`
        : `NIST SP 800-63B asks for a new sign-in at least every ${RECOMMENDED_SESSION_HOURS} hours, which is what a new install starts with. This instance allows ${hoursPhrase(h)}.`;
}

/**
 * Which of the refresh-token lifetime and the maximum session lifetime decides, in words. The
 * rule the server applies: a refresh token expires `refreshTokenDays` after it is issued, or when
 * the session reaches its maximum, whichever comes first.
 */
export function refreshTokenRule(refreshTokenDays: unknown, maxSessionLifetimeHours: unknown): string {
    const days = number(refreshTokenDays) || 7;
    const max = number(maxSessionLifetimeHours);
    const rule = 'The maximum session lifetime in Security Policy wins over this setting: a refresh token never outlives the session it belongs to.';
    if (max <= 0)
        return `${rule} No maximum is set now, so only this lifetime and the idle timeout end a session.`;
    if (max <= days * 24)
        return `${rule} The maximum is ${hoursPhrase(max)} now, shorter than ${days} ${days === 1 ? 'day' : 'days'}, so every refresh token expires when its session does and this setting has no effect until it is shorter than the maximum.`;
    return `${rule} The maximum is ${hoursPhrase(max)} now, so a session left unrefreshed ends after ${days} ${days === 1 ? 'day' : 'days'} and an active one after ${hoursPhrase(max)}.`;
}

/** The key notices the API attached to one CA or SSH CA key; empty when there are none. */
export function keyAdvisoriesOf(ca: any): CaKeyAdvisory[] {
    return Array.isArray(ca?.keyAdvisories) ? (ca.keyAdvisories as CaKeyAdvisory[]) : [];
}

/**
 * Every CA whose own key carries a notice, from the hierarchy feed (children included) and the SSH
 * CA key list, ordered by name. A disabled CA is listed too: its certificates are still relied on.
 */
export function caKeyFindings(hierarchy: any[], sshKeys: any[] = []): CaKeyFinding[] {
    const found: CaKeyFinding[] = [];
    const walk = (cas: any[]) => {
        for (const ca of cas || []) {
            for (const advisory of keyAdvisoriesOf(ca))
                found.push({ link: `/authorities/manage/${encodeURIComponent(ca.id)}`, caName: ca.name || ca.label || ca.id, advisory });
            walk(ca?.children);
        }
    };
    walk(hierarchy);
    for (const key of sshKeys || []) {
        for (const advisory of keyAdvisoriesOf(key))
            found.push({ link: `/authorities/ssh/${encodeURIComponent(key.id)}`, caName: `${key.name || key.id} (SSH)`, advisory });
    }
    return found.sort((a, b) => a.caName.localeCompare(b.caName));
}

/** The RSA sizes offered for a new CA key: none under 3072 bits. */
export const CA_RSA_KEY_SIZES: { value: string; label: string }[] = [
    { value: '3072', label: '3072 bits' },
    { value: '4096', label: '4096 bits' },
    { value: '7680', label: '7680 bits (high compute)' },
    { value: '8192', label: '8192 bits (high compute)' },
];

/** Why RSA 2048 is not offered for a new CA, for the hint under the size picker. */
export const CA_RSA_FLOOR_HINT =
    'A new CA\'s RSA key is at least 3072 bits: NIST SP 800-57 accepts RSA 2048 only through 2030, and a CA key made today is relied on well beyond that.';
