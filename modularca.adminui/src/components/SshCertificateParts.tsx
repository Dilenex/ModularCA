import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { actionButton } from '@shared/components/actionButtons';
import { copyText } from '@shared/clipboard';
import {
    BEFORE_LOGIN_NAMES, defaultHostKeyFile, defaultKeyFile, groundWords, heldSourceText, jsonList,
    type SshCertificateView, type SshHeldLoginName,
} from '../pages/sshLoginNames';

function downloadText(content: string, filename: string) {
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
}

/// <summary>
/// A certificate just signed, on its own page: the certificate with copy and download, named for
/// the key file it certifies, and where to save it beside that private key. A host certificate
/// goes in /etc/ssh and is named in sshd_config. <c>children</c> says where else it can be found.
/// </summary>
export const SignedCertificateHandOver: React.FC<{
    title: string;
    signedCertificate: string;
    publicKey: string;
    forHost?: boolean;
    onDismiss: () => void;
    children?: React.ReactNode;
}> = ({ title, signedCertificate, publicKey, forHost, onDismiss, children }) => {
    const [copied, setCopied] = useState(false);
    const keyFile = forHost ? defaultHostKeyFile(publicKey) : defaultKeyFile(publicKey);
    const copy = async () => {
        if (await copyText(signedCertificate)) {
            setCopied(true);
            window.setTimeout(() => setCopied(false), 1500);
        }
    };
    return (
        <div className="bg-raised border border-line border-l-4 border-l-ok rounded-lg p-4 space-y-3">
            <div className="flex items-center justify-between gap-2 flex-wrap">
                <span className="text-ok font-semibold text-sm">{title}</span>
                <button type="button" onClick={onDismiss} className="text-xs text-ink-muted hover:text-ink transition-colors">Dismiss</button>
            </div>
            <textarea readOnly rows={3} aria-label="Signed certificate" value={signedCertificate}
                className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-ink data-mono focus:outline-none" />
            <div className="flex flex-wrap gap-2">
                <button type="button" onClick={copy} className={actionButton}>{copied ? 'Copied' : 'Copy'}</button>
                <button type="button" onClick={() => downloadText(signedCertificate, `${keyFile}-cert.pub`)} className={actionButton}>Download as {keyFile}-cert.pub</button>
            </div>
            <p className="text-xs text-ink-muted max-w-3xl">
                {forHost
                    ? <>On the host, save it as <code className="text-accent-ink">/etc/ssh/{keyFile}-cert.pub</code>, beside the host key <code className="text-accent-ink">/etc/ssh/{keyFile}</code>, add <code className="text-accent-ink">HostCertificate /etc/ssh/{keyFile}-cert.pub</code> to <code className="text-accent-ink">sshd_config</code> and reload sshd.</>
                    : <>Save it as <code className="text-accent-ink">~/.ssh/{keyFile}-cert.pub</code>, beside the private key <code className="text-accent-ink">~/.ssh/{keyFile}</code>. If the key file has another name, use that name with <code className="text-accent-ink">-cert.pub</code> added. ssh then presents the certificate by itself.</>}
                {children && <> {children}</>}
            </p>
        </div>
    );
};

/// <summary>
/// The login names someone holds on an SSH CA key, as a tick list: each name with where it comes
/// from and how long a certificate carrying it may last, never more than <c>ceilingHours</c>, the
/// limit of the profiles and the key. A name with a reason in <c>unavailable</c> is shown disabled
/// with that reason.
/// </summary>
export const LoginNameTicks: React.FC<{
    idPrefix: string;
    names: SshHeldLoginName[];
    ticked: string[];
    onChange: (next: string[]) => void;
    /** "you" on the reader's own form, otherwise the username the names belong to. */
    whose: string;
    unavailable?: Record<string, string>;
    /** The name that sets the validity limit, shown in the stronger ink. */
    limitedBy?: string | null;
    disabled?: boolean;
    ceilingHours?: number;
}> = ({ idPrefix, names, ticked, onChange, whose, unavailable = {}, limitedBy, disabled, ceilingHours }) => {
    const toggle = (name: string) => onChange(ticked.includes(name) ? ticked.filter((n) => n !== name) : [...ticked, name]);
    return (
        <div className="max-w-3xl border border-line rounded bg-raised divide-y divide-line">
            {names.map((n) => {
                const reason = unavailable[n.name];
                const id = `${idPrefix}-${n.name}`;
                return (
                    <label key={n.name} htmlFor={id}
                        className={`grid grid-cols-[1.75rem_minmax(0,9rem)_minmax(0,1fr)_auto] items-center gap-x-2 min-h-[2.75rem] px-3 py-1.5 text-sm ${reason || disabled ? 'cursor-not-allowed' : 'cursor-pointer'}`}>
                        <input id={id} type="checkbox" checked={ticked.includes(n.name) && !reason} disabled={!!reason || disabled}
                            onChange={() => toggle(n.name)} className="h-4 w-4 rounded border-line-strong accent-accent" />
                        <span className={`data-mono truncate ${reason ? 'text-ink-faint' : 'text-ink'}`} title={n.name}>{n.name}</span>
                        <span className={reason ? 'text-warn' : 'text-ink-muted'}>{reason || heldSourceText(n, whose)}</span>
                        <span className={`text-right tabular-nums whitespace-nowrap ${limitedBy === n.name ? 'text-ink font-medium' : 'text-ink-muted'}`}>up to {ceilingHours != null && ceilingHours > 0 ? Math.min(n.maxValidityHours, ceilingHours) : n.maxValidityHours} h</span>
                    </label>
                );
            })}
        </div>
    );
};

/// <summary>
/// The login names of a user certificate, each with why its holder had it when the certificate
/// was issued. A certificate from before login names were recorded lists its names and says so.
/// </summary>
export const LoginNameGrounds: React.FC<{
    cert: SshCertificateView;
    /** The login name a host log line shows was used. */
    usedName?: string | null;
    /** Link each group to its page; off where the reader has no group pages. */
    linkGroups?: boolean;
}> = ({ cert, usedName, linkGroups }) => {
    const subject = cert.subject?.username || (cert.subject?.serviceLabel ? `svc:${cert.subject.serviceLabel}` : cert.keyId);
    const names = jsonList(cert.principals);
    const grounds = cert.loginNameGrounds;
    const usedMissing = !!usedName && !names.includes(usedName);
    return (
        <div className="space-y-2">
            {!grounds && <p className="text-sm text-ink-muted">{BEFORE_LOGIN_NAMES}, so why its holder had each name is not known.</p>}
            <div className="max-w-3xl border-t border-line">
                {names.map((name) => {
                    const ground = grounds?.find((g) => g.name === name);
                    const words = ground ? groundWords(ground, subject) : null;
                    const used = usedName === name;
                    return (
                        <div key={name} className={`grid grid-cols-[minmax(0,9rem)_minmax(0,1fr)_auto] items-center gap-x-3 min-h-[2.25rem] px-2 py-1 border-b border-line text-sm ${used ? 'bg-accent-soft' : ''}`}>
                            <span className={`data-mono truncate ${used ? 'font-medium' : ''}`} title={name}>{name}</span>
                            <span className="text-ink-muted">
                                {!grounds ? BEFORE_LOGIN_NAMES
                                    : !words ? 'No reason was recorded for this name'
                                    : <>
                                        {words.lead}
                                        {words.groupName && (linkGroups && ground?.groupId
                                            ? <Link to={`/groups/${ground.groupId}`} className="text-accent-ink hover:underline">{words.groupName}</Link>
                                            : words.groupName)}
                                        {words.tail}
                                    </>}
                            </span>
                            <span className="text-accent-ink font-medium whitespace-nowrap">{used ? 'Used in this line' : ''}</span>
                        </div>
                    );
                })}
            </div>
            {usedMissing && (
                <p className="text-sm text-warn">
                    The line says the login was as <span className="data-mono">{usedName}</span>, which is not a login name of this certificate. The host mapped the certificate to that account itself, for example with AuthorizedPrincipalsFile.
                </p>
            )}
        </div>
    );
};
