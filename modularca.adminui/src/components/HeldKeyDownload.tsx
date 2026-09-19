import React, { useState } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { StepUpOps } from '@shared/generated';
import { inputClass, labelClass, FieldHint } from '@shared/components/forms';
import { apiBlobWithMfa } from '../api/client';
import { useStepUp } from './StepUpMfaContext';

/**
 * The one download of a server-generated private key: certificate, chain and key as a single
 * PKCS#12 under a password the holder types here. The CA holds the key only until this
 * succeeds and deletes it in the same save that records the delivery, so the panel shows the
 * password form while the key is held and the certificate exists, and "Key delivered on ..."
 * afterwards. Rendered by the request form's success panel, the user's My Requests rows and the
 * admin request detail page, against the request endpoints of the API each page talks to.
 *
 * Step-up MFA is required, as for certificate export; the first attempt answers 403 with the
 * step-up sentinel and `apiBlobWithMfa` retries with the token the modal obtains.
 */
export interface HeldKeyDownloadProps {
    /** POST endpoint answering `application/x-pkcs12`: the request's `pkcs12` route. */
    endpoint: string;
    /** The request id, which is also the step-up target. */
    requestId: string;
    /** File name for the download, without the extension. */
    fileName: string;
    /** Whether the CA still holds the key. */
    keyHeld: boolean;
    /** When the key was delivered, if it was; shown instead of the form. */
    deliveredAt?: string | null;
    /** Whether the certificate exists; without it there is nothing to download yet. */
    issued: boolean;
    /** Called after a successful download, so the page can refresh what it shows. */
    onDelivered?: (deliveredAt: string) => void;
    className?: string;
}

const MIN_PASSWORD = 8;

function formatDeliveredAt(value: string): string {
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? value : d.toLocaleString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function saveBlob(blob: Blob, filename: string) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}

export const HeldKeyDownload: React.FC<HeldKeyDownloadProps> = ({ endpoint, requestId, fileName, keyHeld, deliveredAt, issued, onDelivered, className = '' }) => {
    const { requireStepUp } = useStepUp();
    const [password, setPassword] = useState('');
    const [confirm, setConfirm] = useState('');
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<NoticeInput | null>(null);
    // Set locally on success so the panel flips without waiting for the page to reload.
    const [delivered, setDelivered] = useState<string | null>(null);

    const shownDeliveredAt = delivered || deliveredAt || null;
    if (shownDeliveredAt) {
        return (
            <p className={`text-xs text-gray-600 dark:text-gray-400 ${className}`}>
                Key delivered on {formatDeliveredAt(shownDeliveredAt)}. The CA no longer holds it.
            </p>
        );
    }
    if (!keyHeld || !issued) return null;

    const tooShort = password.length > 0 && password.length < MIN_PASSWORD;
    const mismatch = confirm.length > 0 && confirm !== password;
    const canDownload = !busy && password.length >= MIN_PASSWORD && confirm === password;

    const download = async () => {
        if (!canDownload) return;
        setBusy(true);
        setError(null);
        try {
            const resp = await apiBlobWithMfa(
                endpoint,
                { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password }) },
                requireStepUp,
                StepUpOps.ExportCert,
                requestId,
            );
            saveBlob(await resp.blob(), `${fileName}.pfx`);
            const now = new Date().toISOString();
            setPassword('');
            setConfirm('');
            setDelivered(now);
            onDelivered?.(now);
        } catch (err: any) {
            setError(errorNotice(err, 'The download failed'));
        } finally {
            setBusy(false);
        }
    };

    return (
        <div className={`space-y-2 ${className}`}>
            <p className="text-xs text-gray-700 dark:text-gray-300">
                The certificate is issued and the CA still holds its private key. Choose a password for the .pfx;
                the key is deleted from the CA the moment the file is delivered, so keep the file.
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 max-w-xl">
                <div>
                    <label htmlFor={`pfx-password-${requestId}`} className={labelClass}>PKCS#12 password</label>
                    <input id={`pfx-password-${requestId}`} type="password" autoComplete="new-password" value={password}
                        onChange={(e) => setPassword(e.target.value)} disabled={busy} className={inputClass} />
                    {tooShort && <FieldHint tone="warn">At least {MIN_PASSWORD} characters.</FieldHint>}
                </div>
                <div>
                    <label htmlFor={`pfx-confirm-${requestId}`} className={labelClass}>Confirm password</label>
                    <input id={`pfx-confirm-${requestId}`} type="password" autoComplete="new-password" value={confirm}
                        onChange={(e) => setConfirm(e.target.value)} disabled={busy} className={inputClass} />
                    {mismatch && <FieldHint tone="warn">The passwords do not match.</FieldHint>}
                </div>
            </div>
            <button type="button" onClick={download} disabled={!canDownload}
                className="px-4 py-2 text-sm font-semibold bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors">
                {busy ? 'Preparing…' : 'Download certificate and key (.pfx)'}
            </button>
            {error && (
                <div className="bg-red-50 dark:bg-red-900/30 border border-red-300 dark:border-red-700 rounded p-3">
                    <InlineNotice notice={error} variant="line" />
                </div>
            )}
        </div>
    );
};

export default HeldKeyDownload;
