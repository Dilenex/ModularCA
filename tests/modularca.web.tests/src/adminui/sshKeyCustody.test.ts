import { describe, expect, it } from 'vitest';
import {
    plaintextNoticeDismissed, plaintextNoticeVersion, signBlockedReason, sshKeyCustody, sshKeyReadiness, sshSignerState,
    type SshPlaintextNotice,
} from '@adminui/pages/sshKeyCustody';

/**
 * How the console reads where an SSH CA key is held. The states and reason codes are those of
 * ModularCA.Core/Services/SshKeyCustody.cs and SshKeyImportState.cs (SshKeyImportReasons).
 */

// SshKeyImportReasons, every code a key awaiting import can carry.
const IMPORT_CODES = [
    'fileMissing', 'fileUnreadable', 'fileEncrypted', 'fileNotAKey', 'keyMismatch', 'rowUnreadable', 'unsupportedKey',
    'signerLocked', 'signerUnreachable', 'signerUpgradeRequired', 'signerRefused', 'notConfirmed', 'failed', 'notAttempted',
];

const NOT_HELD_REASON = 'The signer holds no key for this SSH CA, so it signs nothing. Its creation stopped before the key was committed, '
    + 'or the signer no longer has the SSH keystore that held it. Disable this SSH CA and create a new one, or restore the signer\'s SSH keystore from a backup.';

describe('the state of an SSH CA key', () => {
    it('reads the four states the API reports', () => {
        expect(sshSignerState({ signerState: 'held' })).toBe('held');
        expect(sshSignerState({ signerState: 'awaitingImport' })).toBe('awaitingImport');
        expect(sshSignerState({ signerState: 'notHeld' })).toBe('notHeld');
        expect(sshSignerState({ signerState: 'unknown' })).toBe('unknown');
    });

    it('reads a missing or unrecognised state as unknown, never as held', () => {
        expect(sshSignerState({})).toBe('unknown');
        expect(sshSignerState(null)).toBe('unknown');
        expect(sshSignerState({ signerState: 'somethingNew' })).toBe('unknown');
    });

    it('gives each state its own badge', () => {
        expect(sshKeyCustody({ signerState: 'held' }).badge).toEqual({ status: 'active', label: 'Held by the signer' });
        expect(sshKeyCustody({ signerState: 'awaitingImport' }).badge).toEqual({ status: 'expired', label: 'Awaiting import' });
        expect(sshKeyCustody({ signerState: 'notHeld' }).badge).toEqual({ status: 'revoked', label: 'Not held' });
        expect(sshKeyCustody({ signerState: 'unknown' }).badge).toEqual({ status: 'disabled', label: 'Unknown' });
    });

    it('names where the key is kept', () => {
        expect(sshKeyCustody({ keyStorage: 'signer', signerState: 'held' }).heldIn).toBe('The signer\'s SSH keystore');
        expect(sshKeyCustody({ keyStorage: 'legacyFile', signerState: 'awaitingImport' }).heldIn).toBe('A key file on the node');
        expect(sshKeyCustody({ keyStorage: 'pkcs11', signerState: 'held' }).heldIn).toContain('hardware security module');
        expect(sshKeyCustody({ signerState: 'unknown' }).heldIn).toBe('Not reported');
    });

    it('shows no reason, file or remedy for a held key', () => {
        const view = sshKeyCustody({ keyStorage: 'signer', signerState: 'held', signerStateReason: 'stale', keyFile: '/stale' });
        expect(view.reason).toBeNull();
        expect(view.keyFile).toBeNull();
        expect(view.remedy).toBeNull();
    });
});

describe('a key awaiting import', () => {
    const awaiting = {
        keyStorage: 'legacyFile', signerState: 'awaitingImport', signerStateCode: 'fileMissing',
        signerStateReason: 'No key file was found at /opt/modularca/config/ssh-ca-keys/abc.',
        keyFile: '/opt/modularca/config/ssh-ca-keys/abc',
    };

    it('carries the API reason as it is, and the expected path', () => {
        const view = sshKeyCustody(awaiting);
        expect(view.reason).toBe(awaiting.signerStateReason);
        expect(view.keyFile).toBe(awaiting.keyFile);
    });

    it('has something to do for every reason code, and for one it does not know', () => {
        for (const code of [...IMPORT_CODES, 'aCodeFromLater']) {
            expect(sshKeyCustody({ ...awaiting, signerStateCode: code }).remedy, code).toBeTruthy();
        }
        expect(sshKeyCustody({ ...awaiting, signerStateCode: null }).remedy).toBeTruthy();
    });

    it('sends the operator to the signer, not to the file, when the signer is the cause', () => {
        expect(sshKeyCustody({ ...awaiting, signerStateCode: 'signerLocked' }).remedy).toMatch(/^Unlock the signer/);
        expect(sshKeyCustody({ ...awaiting, signerStateCode: 'signerUpgradeRequired' }).remedy).toMatch(/^Upgrade the signer/);
        expect(sshKeyCustody({ ...awaiting, signerStateCode: 'fileMissing' }).remedy).toMatch(/key file/);
    });

    it('cannot sign, and says why with the API reason', () => {
        const reason = signBlockedReason(awaiting);
        expect(reason).toContain('awaiting import into the signer');
        expect(reason).toContain(awaiting.signerStateReason);
    });
});

describe('a key that cannot sign for another reason', () => {
    it('blocks a key the signer does not hold, with the remedy the API gives', () => {
        const key = { keyStorage: 'signer', signerState: 'notHeld', signerStateCode: 'signerHoldsNoKey', signerStateReason: NOT_HELD_REASON };
        expect(signBlockedReason(key)).toBe(NOT_HELD_REASON);
        expect(sshKeyCustody(key).reason).toBe(NOT_HELD_REASON);
        expect(sshKeyCustody(key).remedy).toBeNull();
        expect(signBlockedReason({ signerState: 'notHeld' })).toBeTruthy();
    });

    it('does not block a held key, or one whose state is unknown', () => {
        expect(signBlockedReason({ signerState: 'held' })).toBeNull();
        expect(signBlockedReason({ signerState: 'unknown', signerStateReason: 'The signer is locked or did not answer, so whether it holds this key is not known.' })).toBeNull();
        expect(sshKeyCustody({ signerState: 'unknown' }).remedy).toMatch(/^Unlock the signer/);
    });
});

describe('the SSH row of the readiness payload', () => {
    it('is absent when the payload has none or there is no SSH CA key', () => {
        expect(sshKeyReadiness(null)).toBeNull();
        expect(sshKeyReadiness(undefined)).toBeNull();
        expect(sshKeyReadiness({ total: 0, held: 0, unknown: 0, awaitingImport: [], notHeld: [] })).toBeNull();
    });

    it('says how many are held and lists the others with their reasons', () => {
        const view = sshKeyReadiness({
            total: 4, held: 2, unknown: 0,
            awaitingImport: [{ id: 'a', name: 'Users', reasonCode: 'fileMissing', reason: 'The key file is not where the key\'s row says it is.' }],
            notHeld: [{ id: 'b', name: 'Hosts', reasonCode: 'signerHoldsNoKey', reason: 'The signer holds no key for this SSH CA, so it signs nothing.' }],
        });
        expect(view?.summary).toBe('2 of 4 held by the signer');
        expect(view?.awaitingImport).toEqual([{ id: 'a', name: 'Users', reasonCode: 'fileMissing', reason: 'The key file is not where the key\'s row says it is.' }]);
        expect(view?.notHeld[0].name).toBe('Hosts');
    });

    it('counts the keys a locked signer could not be asked about', () => {
        const view = sshKeyReadiness({ total: 2, held: 0, unknown: 2, awaitingImport: [], notHeld: [] });
        expect(view?.unknown).toBe(2);
        expect(view?.summary).toBe('0 of 2 held by the signer');
    });

    it('tolerates missing lists', () => {
        const view = sshKeyReadiness({ total: 1, held: 1 });
        expect(view?.awaitingImport).toEqual([]);
        expect(view?.notHeld).toEqual([]);
        expect(view?.unknown).toBe(0);
    });
});

describe('dismissing the plaintext notice', () => {
    const notice: SshPlaintextNotice = {
        applies: true, awaitingImport: 0, firstImportedAt: '2026-10-07T08:00:00Z', lastImportedAt: '2026-10-07T08:00:05Z',
        message: 'These SSH CA keys were stored on the node in plaintext before the signer held them.',
        keys: [{ id: 'a', name: 'Users', fingerprint: 'SHA256:abc', importedAt: '2026-10-07T08:00:05Z', keyFile: '/opt/modularca/config/ssh-ca-keys/a', keyFileRemoved: true }],
        earlierArchives: [],
    };
    const dismissal = { dismissed: plaintextNoticeVersion(notice), by: 'user-1' };

    it('is not dismissed until someone dismisses it', () => {
        expect(plaintextNoticeDismissed(notice, { dismissed: '', by: '' }, 'user-1')).toBe(false);
        expect(plaintextNoticeDismissed(notice, null, 'user-1')).toBe(false);
    });

    it('stays dismissed for the user who dismissed it', () => {
        expect(plaintextNoticeDismissed(notice, dismissal, 'user-1')).toBe(true);
    });

    it('is not dismissed for another user of the same browser, or before the user is known', () => {
        expect(plaintextNoticeDismissed(notice, dismissal, 'user-2')).toBe(false);
        expect(plaintextNoticeDismissed(notice, dismissal, undefined)).toBe(false);
    });

    it('comes back when another key is imported or another key awaits import', () => {
        const later = { ...notice, lastImportedAt: '2026-10-08T09:00:00Z', keys: [...notice.keys, { ...notice.keys[0], id: 'b' }] };
        expect(plaintextNoticeDismissed(later, dismissal, 'user-1')).toBe(false);
        expect(plaintextNoticeDismissed({ ...notice, awaitingImport: 1 }, dismissal, 'user-1')).toBe(false);
    });

    it('does not come back because archives were pruned', () => {
        expect(plaintextNoticeDismissed({ ...notice, earlierArchives: [{ name: 'backup-1.enc', writtenAt: '2026-10-01T00:00:00Z' }] }, dismissal, 'user-1')).toBe(true);
    });
});
