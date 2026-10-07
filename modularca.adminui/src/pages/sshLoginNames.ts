import type { Capability } from '@shared/generated';
import type { EffectiveCapabilities } from '../authz';

/**
 * SSH login names as the console reads and words them: the answers of the login name routes
 * (AdminSshLoginNameController, UserSshController), the login name rule as typed, what a
 * certificate may last, and what a host log line says. No React here, so it is covered by
 * tests/modularca.web.tests.
 */

export interface SshCaKeyRef { id: string; name: string; fingerprint?: string | null; certificateAuthorityId?: string | null }
export interface SshUserRef { id?: string | null; username?: string | null }
export interface SshGroupRef { id: string; name: string; displayName: string; memberCount: number }

/** One grant, as `GET .../ca-keys/{caKeyId}/login-names` and the group route answer it. */
export interface SshLoginNameGrant {
    id: string;
    sshCaKey: SshCaKeyRef;
    loginName: string;
    user?: SshUserRef | null;
    group?: SshGroupRef | null;
    maxValidityHours?: number | null;
    expiresAt?: string | null;
    ended: boolean;
    note?: string | null;
    grantedBy?: SshUserRef | null;
    grantedAt: string;
    liveCertificates: number;
}

export interface SshLoginNameGrantList {
    sshCaKey: SshCaKeyRef;
    maxValidityHours: number;
    allowOwnUsername: boolean;
    grants: SshLoginNameGrant[];
}

/** A login name someone holds on one key, with the ground that counts. */
export interface SshHeldLoginName {
    name: string;
    source: string;
    grantId?: string | null;
    groupId?: string | null;
    groupName?: string | null;
    maxValidityHours: number;
    expiresAt?: string | null;
}

/** One ground of one name, as `GET .../users/{userId}/login-names` answers it. */
export interface SshUserLoginName {
    sshCaKey: SshCaKeyRef;
    loginName: string;
    source: string;
    grantId?: string | null;
    groupId?: string | null;
    groupName?: string | null;
    maxValidityHours: number;
    limitIsKeyMaximum: boolean;
    expiresAt?: string | null;
    effective: boolean;
}

/** Why a certificate's subject held one login name when it was issued. */
export interface SshLoginNameGround {
    name: string;
    source: string;
    grantId?: string | null;
    groupId?: string | null;
    groupName?: string | null;
    grantedByUserId?: string | null;
    grantedByUsername?: string | null;
    maxValidityHours?: number | null;
    expiresAt?: string | null;
}

export interface SshCertificateView {
    id: string;
    sshCaKeyId: string;
    certificateType?: string;
    keyId: string;
    serialNumber: number | string;
    principals: string | string[];
    validAfter: string;
    validBefore: string;
    publicKey?: string;
    signedCertificate?: string;
    extensions?: string | string[] | null;
    isRevoked: boolean;
    createdAt?: string;
    status?: string;
    sshCaKey?: SshCaKeyRef | null;
    keyFingerprint?: string | null;
    subjectUserId?: string | null;
    subject?: { kind: string; userId?: string | null; username?: string | null; serviceLabel?: string | null } | null;
    issuedBy?: { userId?: string | null; username?: string | null; selfService?: boolean; sourceIp?: string | null } | null;
    loginNameGrounds?: SshLoginNameGround[] | null;
}

export interface SshRequestProfileCombination {
    requestProfileId: string;
    requestProfileName: string;
    signingProfileId: string;
    signingProfileName: string;
    certProfileId: string;
    certProfileName: string;
    maxValidityHours: number;
    maxPrincipals: number;
    unavailableLoginNames: string[];
}

export interface SshRequestKey {
    id: string;
    name: string;
    keyType: string;
    fingerprint?: string | null;
    maxValidityHours: number;
    allowOwnUsername: boolean;
    loginNames: SshHeldLoginName[];
    profiles: SshRequestProfileCombination[];
}

/** `GET /api/v1/user/ssh/request-options`. */
export interface SshRequestOptions {
    keyId?: string | null;
    caKeys: SshRequestKey[];
}

/* ── the login name rule ─────────────────────────────────────────────────── */

export const LOGIN_NAME_MAX_LENGTH = 128;
export const LOGIN_NAMES_PER_GRANT = 64;
export const GRANT_NOTE_MAX_LENGTH = 256;

const LOGIN_NAME = /^[A-Za-z0-9_][A-Za-z0-9._@+-]*$/;

/** Null when `name` can be a login name, otherwise the sentence shown under the field. */
export function loginNameError(name: string): string | null {
    if (name.length <= LOGIN_NAME_MAX_LENGTH && LOGIN_NAME.test(name)) return null;
    const shown = name.length > 0 && name.length <= 40 ? `"${name}"` : 'This entry';
    return `${shown} is not a login name. Use 1 to ${LOGIN_NAME_MAX_LENGTH} characters: first a letter, a digit or an underscore, then letters, digits and . _ @ + -`;
}

const SERVICE_LABEL = /^[A-Za-z0-9._-]{1,64}$/;

/** Null when `label` can name a service identity, otherwise the sentence shown under the field. */
export function serviceLabelError(label: string): string | null {
    return SERVICE_LABEL.test(label) ? null : 'A label is 1 to 64 letters, digits and . _ -';
}

/** What hosts log for a service identity. */
export const serviceKeyId = (label: string): string => `svc:${label}`;

/* ── reading lists the API keeps as text ─────────────────────────────────── */

/** `principals` and `extensions` arrive as a JSON array inside a string. */
export function jsonList(value: unknown): string[] {
    if (Array.isArray(value)) return value.map(String);
    if (typeof value !== 'string' || value.trim() === '') return [];
    try {
        const parsed = JSON.parse(value);
        if (Array.isArray(parsed)) return parsed.map(String);
    } catch {
        return value.split(',').map((s) => s.trim()).filter(Boolean);
    }
    return [];
}

/* ── dates ───────────────────────────────────────────────────────────────── */

const DAY_MS = 86_400_000;
const HOUR_MS = 3_600_000;

/** A certificate starts five minutes before it is issued (SshCaService.ValidAfterBackdate). */
export const VALID_AFTER_BACKDATE_MS = 5 * 60_000;

/** A grant that ends within this many days is marked. */
export const GRANT_ENDS_SOON_DAYS = 14;

export type DayFormat = (iso: string) => string;

/** "14 Oct 2026", in the reader's time zone. */
export const dayText: DayFormat = (iso) =>
    new Date(iso).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });

/** "14 Oct 2026, 17:55", in the reader's time zone. */
export const dayTimeText: DayFormat = (iso) =>
    new Date(iso).toLocaleString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });

export interface GrantEnd {
    state: 'never' | 'later' | 'soon' | 'ended';
    /** Whole days left, rounded up, for `soon` and `later`. */
    daysLeft: number | null;
    /** The badge beside the date, when there is one. */
    badge: { status: 'expired' | 'disabled'; label: string } | null;
}

/** Where a grant stands against its end: no end, ended, ending within two weeks, or later. */
export function grantEnd(expiresAt: string | null | undefined, now: Date, ended?: boolean): GrantEnd {
    if (!expiresAt) return { state: 'never', daysLeft: null, badge: null };
    const left = new Date(expiresAt).getTime() - now.getTime();
    if (ended || left <= 0) return { state: 'ended', daysLeft: null, badge: { status: 'disabled', label: 'Ended' } };
    const daysLeft = Math.ceil(left / DAY_MS);
    if (daysLeft <= GRANT_ENDS_SOON_DAYS) {
        return { state: 'soon', daysLeft, badge: { status: 'expired', label: left < DAY_MS ? 'Under 1 d' : `${daysLeft} d` } };
    }
    return { state: 'later', daysLeft, badge: null };
}

/** The value of a date field for a stored end, in the reader's time zone; empty for no end. */
export function dateFieldValue(expiresAt: string | null | undefined): string {
    if (!expiresAt) return '';
    const d = new Date(expiresAt);
    const two = (n: number) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${two(d.getMonth() + 1)}-${two(d.getDate())}`;
}

/** The end of the day a date field names, in the reader's time zone, as the API takes it. */
export function endOfDayIso(dateField: string): string | null {
    const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(dateField);
    if (!m) return null;
    const d = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]), 23, 59, 59);
    return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

/**
 * The end to send for a date field. A day that is still the stored end's day keeps the stored
 * moment, so opening and saving a grant does not move its end.
 */
export function grantEndToSend(dateField: string, stored?: string | null): string | null {
    if (!dateField) return null;
    if (stored && dateFieldValue(stored) === dateField) return stored;
    return endOfDayIso(dateField);
}

/* ── the grant form ──────────────────────────────────────────────────────── */

export interface GrantTerms {
    /** Hours as typed; empty for the CA maximum. */
    hours: string;
    /** A date field value; empty for no end. */
    endDate: string;
    note: string;
}

/** What is wrong with the limit, the end and the note, in the order of the fields. */
export function grantTermProblems(terms: GrantTerms, keyMaxValidityHours: number, now: Date, storedEnd?: string | null): string[] {
    const problems: string[] = [];
    if (terms.hours !== '') {
        const hours = Number(terms.hours);
        if (!/^\d+$/.test(terms.hours) || hours < 1 || hours > keyMaxValidityHours) {
            problems.push(`The longest certificate is between 1 and ${keyMaxValidityHours} hours, the maximum of this SSH CA. Leave it empty for that maximum.`);
        }
    }
    if (terms.endDate !== '') {
        const end = grantEndToSend(terms.endDate, storedEnd);
        const unchanged = !!storedEnd && end === storedEnd;
        if (!end) problems.push('The end is not a date.');
        else if (!unchanged && new Date(end).getTime() <= now.getTime()) problems.push('The end is in the past. Remove the grant to end it now.');
    }
    if (terms.note.trim().length > GRANT_NOTE_MAX_LENGTH) problems.push(`The note is longer than ${GRANT_NOTE_MAX_LENGTH} characters.`);
    return problems;
}

/** The limit, end and note of a grant request or change; null clears one. */
export function grantTermsBody(terms: GrantTerms, storedEnd?: string | null): { maxValidityHours: number | null; expiresAt: string | null; note: string | null } {
    return {
        maxValidityHours: terms.hours === '' ? null : Number(terms.hours),
        expiresAt: grantEndToSend(terms.endDate, storedEnd),
        note: terms.note.trim() === '' ? null : terms.note.trim(),
    };
}

/**
 * The grants of `names` the target already has on a key. A grant that has ended still holds its
 * place, so granting the name again is refused until that grant is changed or removed.
 */
export function existingGrants(grants: SshLoginNameGrant[], names: string[], target: { userId?: string | null; groupId?: string | null }): SshLoginNameGrant[] {
    const wanted = new Set(names);
    return grants.filter((g) => wanted.has(g.loginName)
        && ((!!target.userId && g.user?.id === target.userId) || (!!target.groupId && g.group?.id === target.groupId)));
}

/** Who a grant was made to, as a name. */
export const grantTargetName = (grant: SshLoginNameGrant): string =>
    grant.group ? (grant.group.displayName || grant.group.name) : (grant.user?.username || 'a deleted user');

/* ── wording ─────────────────────────────────────────────────────────────── */

const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);

/** "24 h", or "CA maximum" for a grant with no limit of its own. */
export function longestCertificateText(hours: number | null | undefined, keyMaxValidityHours?: number | null): string {
    if (hours != null) return `${hours} h`;
    return keyMaxValidityHours != null ? `CA maximum, ${keyMaxValidityHours} h` : 'CA maximum';
}

/** Where a held login name comes from. `whose` is "you" on the reader's own form, otherwise the username. */
export function heldSourceText(name: { source: string; groupName?: string | null; expiresAt?: string | null }, whose: string, format: DayFormat = dayText): string {
    const until = name.expiresAt ? ` until ${format(name.expiresAt)}` : '';
    if (name.source === 'own') return whose === 'you' ? 'Your username' : 'Own username';
    if (name.source === 'group') return `${name.groupName ? `Through the group ${name.groupName}` : 'Through a group'}${until}`;
    if (name.source === 'user') return `Granted to ${whose}${until}`;
    return 'Typed when the certificate was signed';
}

/** Why a login name was held, in three parts so a page can make the group a link. */
export interface GroundWords { lead: string; groupName: string | null; tail: string }

/** Why a certificate's subject held a login name when it was issued. */
export function groundWords(ground: SshLoginNameGround, subject: string, format: DayFormat = dayText): GroundWords {
    const by = ground.grantedByUsername ? ` by ${ground.grantedByUsername}` : '';
    const until = ground.expiresAt ? `, until ${format(ground.expiresAt)}` : '';
    if (ground.source === 'own') return { lead: 'Own username', groupName: null, tail: '' };
    if (ground.source === 'group') {
        const tail = `${by ? `, granted${by}` : ''}${until}`;
        return ground.groupName ? { lead: 'Through the group ', groupName: ground.groupName, tail } : { lead: 'Through a group', groupName: null, tail };
    }
    if (ground.source === 'user') return { lead: `Granted to ${subject}${by}${until}`, groupName: null, tail: '' };
    return { lead: 'Typed by whoever signed it, for a service identity', groupName: null, tail: '' };
}

/** `groundWords` as one sentence. */
export function groundText(ground: SshLoginNameGround, subject: string, format: DayFormat = dayText): string {
    const words = groundWords(ground, subject, format);
    return `${words.lead}${words.groupName ?? ''}${words.tail}`;
}

export const isUserCertificate = (cert: { certificateType?: string | null }): boolean =>
    (cert.certificateType || '').toLowerCase().includes('user');

/** `active`, `expired` or `revoked`, from the API's own word or from the row. */
export function certificateStatus(cert: Pick<SshCertificateView, 'status' | 'isRevoked' | 'validBefore'>, now: Date): 'active' | 'expired' | 'revoked' {
    if (cert.status === 'active' || cert.status === 'expired' || cert.status === 'revoked') return cert.status;
    if (cert.isRevoked) return 'revoked';
    return new Date(cert.validBefore).getTime() <= now.getTime() ? 'expired' : 'active';
}

/** The badge of a certificate: green while it works, red once revoked, grey once it has simply run out. */
export function certificateBadge(status: 'active' | 'expired' | 'revoked'): { status: 'active' | 'disabled' | 'revoked'; label: string } {
    if (status === 'active') return { status: 'active', label: 'Active' };
    return status === 'revoked' ? { status: 'revoked', label: 'Revoked' } : { status: 'disabled', label: 'Expired' };
}

export const NOT_RECORDED = 'Not recorded';
export const BEFORE_LOGIN_NAMES = 'Issued before login names were recorded';

/** Who a certificate was issued to, in a table cell. */
export function issuedToText(cert: SshCertificateView): string {
    const subject = cert.subject;
    if (subject?.kind === 'user') return subject.username || cert.keyId;
    if (subject?.kind === 'service') return serviceKeyId(subject.serviceLabel || '');
    if (subject?.kind === 'host' || (!subject && !isUserCertificate(cert))) return jsonList(cert.principals)[0] || cert.keyId;
    return NOT_RECORDED;
}

/** Who a certificate was issued to, with what kind of subject that is. */
export function issuedToDetail(cert: SshCertificateView): string {
    const subject = cert.subject;
    if (subject?.kind === 'user') {
        return subject.userId ? `${subject.username || cert.keyId}, a user of this console` : `${subject.username || cert.keyId}, a user who has since been deleted`;
    }
    if (subject?.kind === 'service') return `${serviceKeyId(subject.serviceLabel || '')}, a service identity with no account`;
    if (subject?.kind === 'host' || (!subject && !isUserCertificate(cert))) return `${jsonList(cert.principals)[0] || cert.keyId}, a host`;
    return `${NOT_RECORDED}. ${BEFORE_LOGIN_NAMES}.`;
}

/** Who asked for a certificate, in a table cell. */
export function issuedByText(cert: SshCertificateView): string {
    const by = cert.issuedBy;
    if (!by || (!by.username && !by.userId)) return NOT_RECORDED;
    const name = by.username || 'a deleted user';
    return by.selfService ? `${name} (self-service)` : name;
}

/** Who asked for a certificate, with the address the request came from. */
export function issuedByDetail(cert: SshCertificateView): string {
    const by = cert.issuedBy;
    if (!by || (!by.username && !by.userId)) return NOT_RECORDED;
    const parts = [by.username || 'a deleted user'];
    if (by.selfService) parts.push('self-service');
    if (by.sourceIp) parts.push(`from ${by.sourceIp}`);
    return parts.join(', ');
}

/** What a grant change or removal came to, for the toast after it. */
export function revokedSentence(count: number): string {
    if (count === 0) return 'No certificate was revoked.';
    return `${count} ${plural(count, 'certificate was', 'certificates were')} revoked.`;
}

/** What removing a grant will do, for the confirmation before it. */
export function removeGrantQuestion(grant: SshLoginNameGrant): string {
    const live = grant.liveCertificates;
    const consequence = live === 0
        ? 'No live certificate carries the name under this grant.'
        : `${live} live ${plural(live, 'certificate carries', 'certificates carry')} the name under this grant. ${plural(live, 'It is', 'Each is')} revoked, unless its holder still has the name another way.`;
    return `Remove the grant of "${grant.loginName}" to ${grantTargetName(grant)} on ${grant.sshCaKey.name}? ${consequence}`;
}

/** What revoking all of a user's certificates came to. */
export function revokeAllSentence(revoked: number, leftForRights: number): string {
    const done = revoked === 0 ? 'No certificate was revoked.' : `Revoked ${revoked} ${plural(revoked, 'certificate', 'certificates')}.`;
    if (leftForRights === 0) return done;
    return `${done} ${leftForRights} ${plural(leftForRights, 'was', 'were')} left, because you may not revoke on ${plural(leftForRights, 'its', 'their')} SSH CA.`;
}

/* ── how long a certificate may last ─────────────────────────────────────── */

export interface ValidityLimit {
    /** The most whole hours that can be asked for. */
    maxHours: number;
    /** What sets it: the profiles and the SSH CA, a login name's limit, or the end of a login name's grant. */
    by: 'ceiling' | 'hours' | 'end';
    /** The login name that sets it, for `hours` and `end`. */
    loginName: string | null;
    /** The most whole hours without that login name; null when none sets the limit. */
    withoutHours: number | null;
    /** When that login name's grant ends, for `end`. */
    endsAt: string | null;
}

type Limited = { name: string; maxValidityHours: number; expiresAt?: string | null };

const hoursUntil = (expiresAt: string, now: Date): number =>
    Math.max(0, Math.floor((new Date(expiresAt).getTime() - (now.getTime() - VALID_AFTER_BACKDATE_MS)) / HOUR_MS));

/**
 * The longest certificate that can be asked for with these login names: the smallest of the
 * ceiling (the profiles and the SSH CA) and the names' limits, and no later than the earliest
 * end among their grants, counted from the certificate's start.
 */
export function validityLimit(names: Limited[], ceilingHours: number, now: Date): ValidityLimit {
    let maxHours = ceilingHours;
    let by: ValidityLimit['by'] = 'ceiling';
    let limiter: Limited | null = null;
    for (const n of names) {
        if (n.maxValidityHours < maxHours) { maxHours = n.maxValidityHours; by = 'hours'; limiter = n; }
    }
    for (const n of names) {
        if (!n.expiresAt) continue;
        const fits = hoursUntil(n.expiresAt, now);
        if (fits < maxHours) { maxHours = fits; by = 'end'; limiter = n; }
    }
    if (!limiter) return { maxHours, by, loginName: null, withoutHours: null, endsAt: null };
    const without = validityLimit(names.filter((n) => n !== limiter), ceilingHours, now).maxHours;
    return { maxHours, by, loginName: limiter.name, withoutHours: without, endsAt: by === 'end' ? (limiter.expiresAt ?? null) : null };
}

/** The sentence under "Valid for"; null when only the profiles and the SSH CA set the limit. */
export function validityLimitText(limit: ValidityLimit, format: DayFormat = dayTimeText): string | null {
    if (limit.by === 'ceiling' || !limit.loginName) return null;
    const hours = (n: number) => `${n} ${plural(n, 'hour', 'hours')}`;
    const without = limit.withoutHours != null && limit.withoutHours > limit.maxHours
        ? ` Without it this certificate could last ${hours(limit.withoutHours)}.`
        : '';
    if (limit.by === 'hours') return `At most ${hours(limit.maxHours)}, because ${limit.loginName} is ticked.${without}`;
    const end = limit.endsAt ? format(limit.endsAt) : 'its end';
    const most = limit.maxHours === 0 ? 'Less than an hour can be asked for' : `At most ${hours(limit.maxHours)} can be asked for`;
    return `${most}, because ${limit.loginName} is ticked and its grant ends on ${end}.${without} Left empty, the certificate ends when the grant does.`;
}

/** What "Valid for" starts at: the most allowed, or empty where a grant's end sets the limit, since empty then lasts longest. */
export const defaultValidity = (limit: ValidityLimit): string => (limit.by === 'end' ? '' : String(limit.maxHours));

/** Null when the typed validity can be asked for, otherwise why not. Empty means the most allowed. */
export function validityProblem(typed: string, limit: ValidityLimit): string | null {
    if (typed === '') return null;
    const hours = Number(typed);
    if (!/^\d+$/.test(typed) || hours < 1) return 'Enter whole hours, 1 or more, or leave the field empty for the most allowed.';
    if (limit.maxHours === 0) return 'Less than an hour is left before a grant ends. Leave the field empty.';
    if (hours > limit.maxHours) return `${hours} hours is over the most allowed here, ${limit.maxHours}.`;
    return null;
}

/* ── the profile choices of the request form ─────────────────────────────── */

export interface NamedId { id: string; name: string }

const distinct = (items: NamedId[]): NamedId[] => {
    const seen = new Set<string>();
    return items.filter((i) => (seen.has(i.id) ? false : (seen.add(i.id), true)));
};

export const requestProfileChoices = (combinations: SshRequestProfileCombination[]): NamedId[] =>
    distinct(combinations.map((c) => ({ id: c.requestProfileId, name: c.requestProfileName })));

export const signingProfileChoices = (combinations: SshRequestProfileCombination[], requestProfileId: string): NamedId[] =>
    distinct(combinations.filter((c) => c.requestProfileId === requestProfileId).map((c) => ({ id: c.signingProfileId, name: c.signingProfileName })));

export const certProfileChoices = (combinations: SshRequestProfileCombination[], requestProfileId: string, signingProfileId: string): NamedId[] =>
    distinct(combinations.filter((c) => c.requestProfileId === requestProfileId && c.signingProfileId === signingProfileId)
        .map((c) => ({ id: c.certProfileId, name: c.certProfileName })));

/**
 * The combination a selection names. A choice that is empty or no longer offered falls back to
 * the first one offered, so a form with a single combination needs no picker at all.
 */
export function chosenCombination(combinations: SshRequestProfileCombination[],
    selection: { requestProfileId?: string; signingProfileId?: string; certProfileId?: string }): SshRequestProfileCombination | null {
    if (combinations.length === 0) return null;
    const requests = requestProfileChoices(combinations);
    const request = requests.find((r) => r.id === selection.requestProfileId) ?? requests[0];
    const signings = signingProfileChoices(combinations, request.id);
    const signing = signings.find((s) => s.id === selection.signingProfileId) ?? signings[0];
    const certs = certProfileChoices(combinations, request.id, signing.id);
    const cert = certs.find((c) => c.id === selection.certProfileId) ?? certs[0];
    return combinations.find((c) => c.requestProfileId === request.id && c.signingProfileId === signing.id && c.certProfileId === cert.id) ?? null;
}

/* ── host log lines ──────────────────────────────────────────────────────── */

export type SshLogLine =
    | { kind: 'empty' }
    /** A login by certificate: what `sshd` printed after the key. */
    | { kind: 'certificate'; account: string | null; keyId: string; serial: string; caKeyType: string; caFingerprint: string | null }
    /** A login line with no certificate in it: a plain public key, a password. */
    | { kind: 'noCertificate'; account: string | null; method: string | null }
    | { kind: 'unreadable' };

const CERT_TAIL = /-CERT\s+\S+\s+ID\s(.+)\s\(serial\s(\d+)\)\sCA\s(\S+)\s(\S+)\s*$/;
const ACCOUNT = /\sfor\s(?:invalid user\s)?(\S+)\sfrom\s/;
const METHOD = /\b(?:Accepted|Failed|Postponed)\s(\S+)\sfor\s/;

/**
 * Reads the `sshd` line of a login: the account after `for`, and for a login by certificate the
 * key id after ` ID `, the serial in `(serial N)` and the CA's fingerprint after ` CA <type> `.
 * The certificate part is read from the end of the line, where `sshd` writes it, so a key id that
 * itself holds such text cannot stand in for it.
 */
export function parseSshdLogLine(line: string): SshLogLine {
    const text = line.replace(/[\r\n]+/g, ' ').trim();
    if (text === '') return { kind: 'empty' };
    const account = ACCOUNT.exec(text)?.[1] ?? null;
    const cert = CERT_TAIL.exec(text);
    if (cert) {
        const fingerprint = cert[4];
        return {
            kind: 'certificate', account, keyId: cert[1], serial: cert[2], caKeyType: cert[3],
            caFingerprint: fingerprint.startsWith('SHA256:') ? fingerprint : null,
        };
    }
    const method = METHOD.exec(text)?.[1] ?? null;
    if (account || method) return { kind: 'noCertificate', account, method };
    return { kind: 'unreadable' };
}

/** What to say about a pasted line that names no certificate. */
export function logLineProblem(line: SshLogLine): string | null {
    if (line.kind === 'noCertificate') {
        const how = line.method && line.method !== 'publickey' ? ` (${line.method})` : '';
        return `This line records a login without a certificate${how}: it has no ID, serial and CA after the key. A login with a plain public key or a password names no certificate, so there is none to find.`;
    }
    if (line.kind === 'unreadable') return 'No login could be read from this text. Paste the whole sshd line, the one that begins with "Accepted publickey for".';
    return null;
}

/** The query of the find route for a line read from a log. */
export function findQuery(line: Extract<SshLogLine, { kind: 'certificate' }>): string {
    const query = new URLSearchParams({ serial: line.serial, keyId: line.keyId });
    if (line.caFingerprint) query.set('caFingerprint', line.caFingerprint);
    return query.toString();
}

/* ── what a host records, and where a certificate is saved ───────────────── */

/** The key type as `sshd` prints it, from a public key line or an SSH CA's key type. */
export function sshdKeyType(keyTypeOrLine: string | null | undefined): string {
    const first = (keyTypeOrLine || '').trim().split(/\s+/)[0].toLowerCase();
    if (first.startsWith('sk-ssh-ed25519')) return 'ED25519-SK';
    if (first.startsWith('sk-ecdsa')) return 'ECDSA-SK';
    if (first.includes('ed25519')) return 'ED25519';
    if (first.includes('ecdsa')) return 'ECDSA';
    if (first.includes('rsa')) return 'RSA';
    return 'KEY';
}

/** The usual file name of a private key of the type a public key line names. */
export function defaultKeyFile(publicKeyLine: string | null | undefined): string {
    switch (sshdKeyType(publicKeyLine)) {
        case 'ED25519-SK': return 'id_ed25519_sk';
        case 'ECDSA-SK': return 'id_ecdsa_sk';
        case 'ECDSA': return 'id_ecdsa';
        case 'RSA': return 'id_rsa';
        default: return 'id_ed25519';
    }
}

/* ── rights ──────────────────────────────────────────────────────────────── */

/**
 * Whether `capability` is held on the certificate authority an SSH CA key belongs to. A
 * capability held at system scope holds on every CA.
 */
export function canOnSshCa(caps: EffectiveCapabilities | null | undefined, key: { certificateAuthorityId?: string | null } | null | undefined,
    capability: Capability): boolean {
    if (!caps) return false;
    if (caps.system.includes(capability)) return true;
    const caId = key?.certificateAuthorityId;
    return !!caId && caps.cas.some((ca) => ca.id === caId && ca.capabilities.includes(capability));
}
