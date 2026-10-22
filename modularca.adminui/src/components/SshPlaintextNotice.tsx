import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { apiGet } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { useTablePrefs } from '@shared/context/TablePrefsContext';
import { actionButton } from '@shared/components/actionButtons';
import {
    SSH_PLAINTEXT_ARCHIVE_LIMIT, SSH_PLAINTEXT_NOTICE_PREF, plaintextNoticeDismissed, plaintextNoticeVersion,
    type SshPlaintextNotice, type SshPlaintextNoticePrefs,
} from '../pages/sshKeyCustody';
import { sshCaKeyPath } from '../pages/sshPlaces';

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

/** Loads the plaintext notice; null while loading, and for a caller the API answers 404 or 403. */
export function useSshPlaintextNotice(refreshTrigger: number = 0): SshPlaintextNotice | null {
    const [notice, setNotice] = useState<SshPlaintextNotice | null>(null);
    useEffect(() => {
        let cancelled = false;
        apiGet<SshPlaintextNotice>('/api/v1/admin/ssh/plaintext-notice', { toast: false })
            .then((data) => { if (!cancelled) setNotice(data && typeof data === 'object' ? data : null); })
            .catch(() => { if (!cancelled) setNotice(null); });
        return () => { cancelled = true; };
    }, [refreshTrigger]);
    return notice;
}

const cell = 'py-1 pr-4 align-top';

/// <summary>
/// The whole notice that SSH CA keys were plaintext files on the node: the API's message, the
/// imported keys and the earlier archives.
/// </summary>
export const SshPlaintextNoticePanel: React.FC<{
    notice: SshPlaintextNotice;
    /** The key whose page shows the notice; its row is marked. */
    currentKeyId?: string;
    onDismiss?: () => void;
}> = ({ notice, currentKeyId, onDismiss }) => {
    const keys = notice.keys ?? [];
    const archives = notice.earlierArchives ?? [];
    const awaiting = notice.awaitingImport ?? 0;
    const filesLeft = keys.some((k) => !k.keyFileRemoved);

    return (
        <div role="note" aria-label="SSH CA keys were stored in plaintext" className="bg-warn-soft border border-warn/40 rounded-lg p-4 space-y-3">
            <div className="flex items-start justify-between gap-3">
                <p className="text-sm font-semibold text-warn">SSH CA keys were stored in plaintext on this node</p>
                {onDismiss && <button type="button" onClick={onDismiss} className={actionButton}>Dismiss</button>}
            </div>
            <p className="text-sm text-ink max-w-4xl">{notice.message}</p>

            {awaiting > 0 && (
                <p className="text-sm text-ink max-w-4xl">
                    {awaiting === 1 ? 'One SSH CA key is' : `${awaiting} SSH CA keys are`} still a key file on the node, awaiting import into the signer. The SSH CA key list shows each with its reason.
                </p>
            )}

            {keys.length > 0 && (
                <div className="space-y-1">
                    <p className="text-xs font-semibold text-ink">Imported keys</p>
                    <div className="overflow-x-auto">
                        <table className="text-xs text-ink text-left">
                            <thead>
                                <tr className="text-ink-muted">
                                    <th className={`${cell} font-medium`}>SSH CA key</th>
                                    <th className={`${cell} font-medium`}>Fingerprint</th>
                                    <th className={`${cell} font-medium`}>Imported</th>
                                    <th className={`${cell} font-medium`}>Key file</th>
                                    <th className={`${cell} font-medium`}>File on the node</th>
                                </tr>
                            </thead>
                            <tbody>
                                {keys.map((k) => (
                                    <tr key={k.id}>
                                        <td className={cell}>
                                            {k.id === currentKeyId
                                                ? <span className="font-semibold">{k.name} (this key)</span>
                                                : <Link to={sshCaKeyPath(k.id)} className="text-accent-ink hover:underline">{k.name}</Link>}
                                        </td>
                                        <td className={`${cell} data-mono break-all`}>{k.fingerprint}</td>
                                        <td className={`${cell} whitespace-nowrap`}>{formatDate(k.importedAt)}</td>
                                        <td className={`${cell} data-mono break-all`}>{k.keyFile}</td>
                                        <td className={`${cell} whitespace-nowrap`}>
                                            {k.keyFileRemoved ? 'Overwritten and removed' : <span className="text-warn font-semibold">Not removed yet</span>}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                    {filesLeft && (
                        <p className="text-xs text-ink max-w-4xl">
                            A file marked as not removed yet is still on the node. The node tries to remove it again at its next import pass; if it stays, the node's log says why.
                        </p>
                    )}
                </div>
            )}

            <div className="space-y-1">
                <p className="text-xs font-semibold text-ink">Archives written before the last import</p>
                {!notice.lastImportedAt ? (
                    <p className="text-xs text-ink max-w-4xl">Archives are listed here once a key has been imported.</p>
                ) : archives.length === 0 ? (
                    <p className="text-xs text-ink max-w-4xl">
                        No backup archive or pre-restore snapshot in the backup directory was written before the last key was imported ({formatDate(notice.lastImportedAt)}).
                    </p>
                ) : (
                    <>
                        <p className="text-xs text-ink max-w-4xl">
                            These files in the backup directory were written before the last key was imported ({formatDate(notice.lastImportedAt)}) and may still hold the keys:
                        </p>
                        <div className="max-h-48 overflow-y-auto">
                            <table className="text-xs text-ink text-left">
                                <thead>
                                    <tr className="text-ink-muted">
                                        <th className={`${cell} font-medium`}>File</th>
                                        <th className={`${cell} font-medium`}>Written</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {archives.map((a) => (
                                        <tr key={a.name}>
                                            <td className={`${cell} data-mono break-all`}>{a.name}</td>
                                            <td className={`${cell} whitespace-nowrap`}>{formatDate(a.writtenAt)}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                        {archives.length >= SSH_PLAINTEXT_ARCHIVE_LIMIT && (
                            <p className="text-xs text-ink max-w-4xl">The list stops at the {SSH_PLAINTEXT_ARCHIVE_LIMIT} newest files; older ones are in the backup directory too.</p>
                        )}
                    </>
                )}
                <p className="text-xs text-ink max-w-4xl">
                    Only the backup directory is searched. Copies of archives kept elsewhere, and snapshots of the disk or of the virtual machine, are not listed here.
                </p>
            </div>

            {onDismiss && (
                <p className="text-xs text-ink-muted max-w-4xl">
                    Dismissing hides this notice on this page for your account only. It stays on the page of each SSH CA key that was imported or is awaiting import.
                </p>
            )}
        </div>
    );
};

/// <summary>
/// The plaintext notice on the SSH tab of Authorities: shown while it applies, until this user dismisses it.
/// A dismissed notice leaves one line from which it can be opened again, and comes back by
/// itself when what it says changes.
/// </summary>
export const SshPlaintextNoticeBanner: React.FC<{ refreshTrigger?: number }> = ({ refreshTrigger = 0 }) => {
    const notice = useSshPlaintextNotice(refreshTrigger);
    const { user } = useAuth();
    const [prefs, setPrefs] = useTablePrefs<SshPlaintextNoticePrefs>(SSH_PLAINTEXT_NOTICE_PREF, { dismissed: '', by: '' });
    const [reopened, setReopened] = useState(false);

    if (!notice?.applies) return null;

    if (!reopened && plaintextNoticeDismissed(notice, prefs, user?.id)) {
        return (
            <p className="text-xs text-ink-muted">
                SSH CA keys were stored in plaintext on this node before the signer held them.{' '}
                <button type="button" onClick={() => setReopened(true)} className="text-accent-ink hover:underline">Show the notice</button>
            </p>
        );
    }

    return (
        <SshPlaintextNoticePanel
            notice={notice}
            onDismiss={() => { setPrefs({ dismissed: plaintextNoticeVersion(notice), by: user?.id ?? '' }); setReopened(false); }}
        />
    );
};

export default SshPlaintextNoticeBanner;
