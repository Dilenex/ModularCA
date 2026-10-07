import React, { useEffect, useRef, useState } from 'react';

/**
 * Shows a reset's temporary password once. The server keeps no copy: it is in this response only,
 * so closing the dialog discards it and a lost password means a new reset. Escape and the backdrop
 * do not close it, so it is not dismissed by accident; only the acknowledge button does.
 */
interface TemporaryPasswordModalProps {
    password: string | null;
    username?: string | null;
    onClose: () => void;
}

const TemporaryPasswordModal: React.FC<TemporaryPasswordModalProps> = ({ password, username, onClose }) => {
    const [copied, setCopied] = useState(false);
    const closeRef = useRef<HTMLButtonElement | null>(null);
    const titleId = React.useId();

    useEffect(() => {
        setCopied(false);
        if (password) closeRef.current?.focus();
    }, [password]);

    if (!password) return null;

    const copy = async () => {
        try { await navigator.clipboard.writeText(password); setCopied(true); } catch { setCopied(false); }
    };

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-scrim">
            <div role="dialog" aria-modal="true" aria-labelledby={titleId}
                className="bg-raised border border-line rounded-xl shadow-2xl p-6 w-full max-w-md mx-4 space-y-4">
                <h3 id={titleId} className="text-lg font-bold text-ink">Temporary password</h3>
                <p className="text-sm text-ink-muted">
                    {username ? <>The password of <span className="font-semibold">{username}</span> was reset. </> : 'The password was reset. '}
                    They must change it at next sign-in.
                </p>
                <div className="flex items-center gap-2">
                    <code className="flex-1 px-3 py-2 data-mono break-all bg-sunken text-ink border border-line rounded select-all">{password}</code>
                    <button onClick={copy} className="px-3 py-2 text-xs bg-sunken text-ink rounded hover:bg-hover transition-colors">
                        {copied ? 'Copied' : 'Copy'}
                    </button>
                </div>
                <div className="p-3 text-xs bg-warn-soft border border-warn/40 rounded text-warn">
                    Shown once. The server does not keep it, so it cannot be shown again: hand it to the user over a
                    channel you trust now. If it is lost, start a new reset.
                </div>
                <div className="flex justify-end">
                    <button ref={closeRef} onClick={onClose} className="px-4 py-2 text-sm bg-accent text-on-accent rounded hover:bg-accent-hover transition-colors">
                        I have handed it over
                    </button>
                </div>
            </div>
        </div>
    );
};

export default TemporaryPasswordModal;
