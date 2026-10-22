import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { apiGet } from '../api/client';
import { StatusBadge, Tag } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import { FieldHint } from '@shared/components/forms';
import { actionButton } from '@shared/components/actionButtons';
import { LoginNameGrounds } from './SshCertificateParts';
import {
    certificateBadge, certificateStatus, dayTimeText, findQuery, isUserCertificate, issuedByDetail, issuedToDetail, issuedToText, logLineProblem, parseSshdLogLine, sshdKeyType,
    type SshCertificateView,
} from '../pages/sshLoginNames';
import { sshCaKeyPath, sshCertificatePath } from '../pages/sshPlaces';

const certPath = (cert: SshCertificateView, usedName: string | null) => sshCertificatePath(cert, usedName);

/// <summary>
/// Finds a certificate from the line a host's sshd wrote for a login. The line is read here, in
/// the browser; the server is asked only for the serial, the name after ID and the SSH CA's
/// fingerprint. One match is shown with the login name the line used marked; none and several
/// are both said.
/// </summary>
export const SshLogLineLookup: React.FC<{
    /** Called with the single certificate a line matches. */
    onFound?: (cert: SshCertificateView) => void;
}> = ({ onFound }) => {
    const [text, setText] = useState('');
    const [matches, setMatches] = useState<SshCertificateView[] | null>(null);
    const [searching, setSearching] = useState(false);
    const [error, setError] = useState<NoticeInput | null>(null);
    const line = parseSshdLogLine(text);
    const query = line.kind === 'certificate' ? findQuery(line) : '';

    useEffect(() => {
        setMatches(null);
        setError(null);
        if (!query) { setSearching(false); return; }
        let cancelled = false;
        setSearching(true);
        const timer = setTimeout(() => {
            apiGet<SshCertificateView[]>(`/api/v1/admin/ssh/certificates/find?${query}`, { toast: false })
                .then((found) => {
                    if (cancelled) return;
                    const list = Array.isArray(found) ? found : [];
                    setMatches(list);
                    setSearching(false);
                    if (list.length === 1) onFound?.(list[0]);
                })
                .catch((err) => { if (!cancelled) { setError(errorNotice(err, 'The search failed.')); setSearching(false); } });
        }, 400);
        return () => { cancelled = true; clearTimeout(timer); };
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [query]);

    const problem = logLineProblem(line);
    const only = matches?.length === 1 ? matches[0] : null;
    const usedName = line.kind === 'certificate' ? line.account : null;

    return (
        <div className="bg-raised border border-line rounded-lg p-4 space-y-3">
            <div>
                <label htmlFor="ssh-log-line" className="block text-sm font-semibold text-ink mb-1">Find by host log line</label>
                <textarea id="ssh-log-line" rows={2} value={text} onChange={(e) => setText(e.target.value)} spellCheck={false}
                    placeholder="Accepted publickey for root from 192.0.2.10 port 51122 ssh2: ED25519-CERT SHA256:... ID alice (serial 8841) CA ED25519 SHA256:..."
                    aria-describedby="ssh-log-line-hint"
                    className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-ink data-mono placeholder-ink-faint focus:outline-none focus:border-accent" />
                <FieldHint id="ssh-log-line-hint">
                    Paste the line sshd wrote for a login, the one that begins with "Accepted publickey for". The certificate is found by its serial, the name after ID and the fingerprint of the SSH CA. The line stays in your browser.
                </FieldHint>
            </div>

            {line.kind === 'certificate' && (
                <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs text-ink-muted">Read from the line:</span>
                    {only?.sshCaKey?.name
                        ? <Tag label={`SSH CA ${only.sshCaKey.name}`} />
                        : <Tag label={line.caFingerprint ? `SSH CA ${line.caKeyType} ${line.caFingerprint}` : `SSH CA ${line.caKeyType}, fingerprint not SHA256`} />}
                    <Tag label={`Serial ${line.serial}`} />
                    <Tag label={`Name ${line.keyId}`} />
                    {line.account && <Tag label={`Logged in as ${line.account}`} />}
                    <button type="button" onClick={() => setText('')} className={actionButton}>Clear</button>
                </div>
            )}
            {line.kind === 'certificate' && !line.caFingerprint && (
                <FieldHint tone="warn">The line gives the fingerprint of the SSH CA in a form other than SHA256, so it could not narrow the search: every SSH CA you may view was searched.</FieldHint>
            )}
            {problem && (
                <div className="flex flex-wrap items-center gap-2">
                    <p role="status" className="text-sm text-warn max-w-3xl">{problem}</p>
                    <button type="button" onClick={() => setText('')} className={actionButton}>Clear</button>
                </div>
            )}
            {searching && <p className="text-sm text-ink-muted">Searching…</p>}
            <InlineNotice notice={error} onDismiss={() => setError(null)} />

            {matches && matches.length === 0 && line.kind === 'certificate' && (
                <p role="status" className="text-sm text-warn max-w-3xl">
                    No certificate with serial {line.serial} and the name <span className="data-mono">{line.keyId}</span> was found{line.caFingerprint ? ' on the SSH CA with that fingerprint' : ''}. The SSH CA may be one you have no right to view, or the certificate was issued by another CA.
                </p>
            )}

            {matches && matches.length > 1 && (
                <div className="space-y-1.5">
                    <p role="status" className="text-sm text-ink max-w-3xl">
                        {matches.length} certificates match this line, one on each of several SSH CAs. Open the one from the SSH CA the host trusts.
                    </p>
                    <ul className="text-sm space-y-1">
                        {matches.map((c) => (
                            <li key={c.id} className="flex flex-wrap items-center gap-2">
                                <Link to={certPath(c, usedName)} className="text-accent-ink hover:underline">Certificate {String(c.serialNumber)} on {c.sshCaKey?.name || 'an SSH CA'}</Link>
                                <span className="text-ink-muted">issued to {issuedToText(c)}, valid until {dayTimeText(c.validBefore)}</span>
                            </li>
                        ))}
                    </ul>
                </div>
            )}

            {only && (() => {
                const status = certificateStatus(only, new Date());
                const subject = only.subject;
                return (
                    <div className="border border-line rounded p-4 space-y-3">
                        <div className="flex flex-wrap items-center gap-2">
                            <h3 className="text-base font-semibold text-ink">Certificate {String(only.serialNumber)}</h3>
                            <StatusBadge {...certificateBadge(status)} />
                            <Tag label={isUserCertificate(only) ? 'User certificate' : 'Host certificate'} />
                        </div>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8">
                            <DetailField label="Issued to" value={subject?.kind === 'user' && subject.userId
                                ? <><Link to={`/users/${subject.userId}`} className="text-accent-ink hover:underline">{subject.username || only.keyId}</Link>, a user of this console</>
                                : issuedToDetail(only)} />
                            <DetailField label="Issued by" value={issuedByDetail(only)} />
                            <DetailField label="Name in host logs" value={only.keyId} mono />
                            <DetailField label="SSH CA" value={<Link to={sshCaKeyPath(only.sshCaKeyId)} className="text-accent-ink hover:underline">{only.sshCaKey?.name || only.sshCaKeyId}</Link>} />
                            <DetailField label="Valid" value={`${dayTimeText(only.validAfter)} to ${dayTimeText(only.validBefore)}`} />
                            <DetailField label="Key" value={only.keyFingerprint ? `${sshdKeyType(only.publicKey)} ${only.keyFingerprint}` : null} mono />
                        </div>
                        {isUserCertificate(only) && (
                            <div className="space-y-1.5">
                                <div className="label-caps">Login names, and why {subject?.kind === 'user' || subject?.kind === 'service' ? issuedToText(only) : 'the holder'} had each</div>
                                <LoginNameGrounds cert={only} usedName={usedName} linkGroups />
                            </div>
                        )}
                        <div className="flex flex-wrap gap-2 pt-3 border-t border-line">
                            <Link to={certPath(only, usedName)} className={actionButton}>Open the certificate's page</Link>
                        </div>
                    </div>
                );
            })()}
        </div>
    );
};
