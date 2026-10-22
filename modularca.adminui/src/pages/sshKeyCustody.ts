/** What `GET /api/v1/admin/ssh/ca-keys` says about where one SSH CA key is. */
export interface SshCaKeyCustodyFields {
    keyStorage?: string | null;
    signerState?: string | null;
    signerStateCode?: string | null;
    signerStateReason?: string | null;
    keyFile?: string | null;
    importedAt?: string | null;
}

export type SshSignerState = 'held' | 'awaitingImport' | 'notHeld' | 'unknown';

export interface SshKeyCustodyView {
    state: SshSignerState;
    badge: { status: 'active' | 'expired' | 'revoked' | 'disabled'; label: string };
    /** Where the key is kept. */
    heldIn: string;
    /** What the state means. */
    summary: string;
    /** The API's own sentence for a key that is not held; null for a held key. */
    reason: string | null;
    /** Where the key file of a key awaiting import is expected. */
    keyFile: string | null;
    /** What the operator does about it; null when the API's reason already says, or nothing is needed. */
    remedy: string | null;
}

const BADGES: Record<SshSignerState, SshKeyCustodyView['badge']> = {
    held: { status: 'active', label: 'Held by the signer' },
    awaitingImport: { status: 'expired', label: 'Awaiting import' },
    notHeld: { status: 'revoked', label: 'Not held' },
    unknown: { status: 'disabled', label: 'Unknown' },
};

const SUMMARIES: Record<SshSignerState, string> = {
    held: 'The signer holds this key and signs with it. The key is not on the node.',
    awaitingImport: 'This key is still a file on the node, from before the signer held SSH CA keys. It signs nothing until it has been imported into the signer.',
    notHeld: 'This SSH CA is recorded as held by the signer, but the signer holds no key for it. It signs nothing.',
    unknown: 'The signer could not be asked whether it holds this key.',
};

const KEY_FILE_REMEDY = 'Put the unencrypted private key file of this SSH CA at the expected path, on the host that runs the control role, and make it readable by the account the service runs as. The import looks again every few minutes; no restart is needed. If the key file is lost, this SSH CA cannot sign again: disable it and create a new one.';
const LOG_REMEDY = 'The log of the node, and of the signer, has the detail. The import tries again every few minutes.';

/** What to do about a key awaiting import, by the reason code the API gives. */
const IMPORT_REMEDIES: Record<string, string> = {
    fileMissing: KEY_FILE_REMEDY,
    fileUnreadable: KEY_FILE_REMEDY,
    fileNotAKey: KEY_FILE_REMEDY,
    keyMismatch: KEY_FILE_REMEDY,
    fileEncrypted: 'Replace the key file with a copy of the key that has no passphrase. Only an unencrypted key file is imported. The import looks again every few minutes; no restart is needed.',
    rowUnreadable: 'The record of this SSH CA is damaged, so no key file can be matched to it. Disable this SSH CA and create a new one.',
    unsupportedKey: 'The signer holds no SSH CA key of this type or size, so this key cannot be imported. Create a new SSH CA, move your servers to it, and disable this one.',
    signerLocked: 'Unlock the signer. The import runs by itself once the signer is unlocked; the node needs no restart.',
    signerUnreachable: 'Check that the signer is running and that this node can reach it. The import runs by itself once the signer answers.',
    signerUpgradeRequired: 'Upgrade the signer to the same release as this node and start it. The import runs by itself once the upgraded signer is unlocked.',
    notAttempted: 'The import runs on the node with the control role once the signer is unlocked. If this has not changed in a few minutes, look at that node\'s log.',
};

const UNKNOWN_REMEDY = 'Unlock the signer, or check that it is running and that this node can reach it, then reload this page.';

const STORAGE: Record<string, string> = {
    signer: 'The signer\'s SSH keystore',
    legacyFile: 'A key file on the node',
    pkcs11: 'A hardware security module, through the signer',
};

/** The state the API reports; a value this build does not know reads as unknown. */
export function sshSignerState(key: SshCaKeyCustodyFields | null | undefined): SshSignerState {
    const state = key?.signerState;
    return state === 'held' || state === 'awaitingImport' || state === 'notHeld' ? state : 'unknown';
}

/** Where an SSH CA key is held and in what state, in the words the console shows. */
export function sshKeyCustody(key: SshCaKeyCustodyFields | null | undefined): SshKeyCustodyView {
    const state = sshSignerState(key);
    const reason = state === 'held' ? null : (key?.signerStateReason || null);
    let remedy: string | null = null;
    if (state === 'awaitingImport') remedy = IMPORT_REMEDIES[key?.signerStateCode ?? ''] ?? LOG_REMEDY;
    else if (state === 'unknown') remedy = UNKNOWN_REMEDY;
    return {
        state,
        badge: BADGES[state],
        heldIn: STORAGE[key?.keyStorage ?? ''] ?? 'Not reported',
        summary: SUMMARIES[state],
        reason,
        keyFile: state === 'awaitingImport' ? (key?.keyFile || null) : null,
        remedy,
    };
}

/** Why nothing can be signed with this key now, or null when signing can be tried. */
export function signBlockedReason(key: SshCaKeyCustodyFields | null | undefined): string | null {
    const state = sshSignerState(key);
    if (state === 'awaitingImport') {
        const reason = key?.signerStateReason ? ` ${key.signerStateReason}` : '';
        return `This SSH CA key is awaiting import into the signer and signs nothing until it has been imported.${reason}`;
    }
    if (state === 'notHeld') return key?.signerStateReason || 'The signer holds no key for this SSH CA, so it signs nothing.';
    return null;
}

/** One SSH CA key the signer does not hold, as `/health/ready` names it. */
export interface SshKeyReadinessEntry {
    id: string;
    name: string;
    reasonCode: string;
    reason: string;
}

export interface SshKeyReadinessView {
    total: number;
    held: number;
    unknown: number;
    summary: string;
    awaitingImport: SshKeyReadinessEntry[];
    notHeld: SshKeyReadinessEntry[];
}

const readinessEntries = (value: unknown): SshKeyReadinessEntry[] =>
    (Array.isArray(value) ? value : []).map((k: any) => ({
        id: String(k?.id ?? ''),
        name: k?.name || String(k?.id ?? ''),
        reasonCode: k?.reasonCode || '',
        reason: k?.reason || '',
    }));

/**
 * The SSH part of the signer's entry in the readiness payload (`checks.signer.sshKeys`), or null
 * when the payload carries none or the install has no SSH CA key.
 */
export function sshKeyReadiness(sshKeys: any): SshKeyReadinessView | null {
    if (!sshKeys || typeof sshKeys !== 'object') return null;
    const total = Number(sshKeys.total) || 0;
    if (total === 0) return null;
    const held = Number(sshKeys.held) || 0;
    return {
        total,
        held,
        unknown: Number(sshKeys.unknown) || 0,
        summary: `${held} of ${total} held by the signer`,
        awaitingImport: readinessEntries(sshKeys.awaitingImport),
        notHeld: readinessEntries(sshKeys.notHeld),
    };
}

/** `GET /api/v1/admin/ssh/plaintext-notice`. */
export interface SshPlaintextNotice {
    applies: boolean;
    awaitingImport: number;
    firstImportedAt: string | null;
    lastImportedAt: string | null;
    message: string;
    keys: Array<{ id: string; name: string; fingerprint: string; importedAt: string; keyFile: string; keyFileRemoved: boolean }>;
    earlierArchives: Array<{ name: string; writtenAt: string }>;
}

/** What a user's dismissal of the notice records: what the notice said then, and whose dismissal it is. */
export interface SshPlaintextNoticePrefs {
    dismissed: string;
    by: string;
}

export const SSH_PLAINTEXT_NOTICE_PREF = 'notice:ssh-plaintext';

/** The most archives the API lists. */
export const SSH_PLAINTEXT_ARCHIVE_LIMIT = 200;

/** Changes whenever the facts of the notice change, so that a dismissal covers only what was read. */
export function plaintextNoticeVersion(notice: SshPlaintextNotice): string {
    return `${notice.lastImportedAt ?? ''}|${notice.keys?.length ?? 0}|${notice.awaitingImport ?? 0}`;
}

/** Whether this user dismissed the notice as it stands now. */
export function plaintextNoticeDismissed(notice: SshPlaintextNotice, prefs: SshPlaintextNoticePrefs | null | undefined, userId: string | null | undefined): boolean {
    if (!prefs?.dismissed || !userId) return false;
    return prefs.by === userId && prefs.dismissed === plaintextNoticeVersion(notice);
}
