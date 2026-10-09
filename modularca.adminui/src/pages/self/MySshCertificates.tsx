import React, { useState, useEffect } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { apiGet, apiPost, apiBlob } from '../../api/client';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import { DataTable, type DataTableColumn } from '@shared/components/DataTable';
import { Link } from 'react-router-dom';
import { SELF_SSH_CERTIFICATES_PATH } from '../sshPlaces';
import { FieldHint, inputClass, inputClassNarrow, labelClass } from '@shared/components/forms';
import { actionButton, actionButtonPrimary } from '@shared/components/actionButtons';
import { copyText } from '@shared/clipboard';
import { LoginNameGrounds, LoginNameTicks } from '../../components/SshCertificateParts';
import {
    certProfileChoices, certificateBadge, certificateStatus, chosenCombination, dayTimeText, defaultKeyFile, defaultValidity, issuedByText, jsonList,
    requestProfileChoices, signingProfileChoices, sshdKeyType, validityLimit, validityLimitText, validityProblem,
    type SshCertificateView, type SshRequestKey, type SshRequestOptions,
} from '../sshLoginNames';

function downloadText(content: string, filename: string) {
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}

/** What `POST /api/v1/user/ssh/sign-user` answers, with the key it certified. */
interface SignedCertificate {
    id: string;
    serialNumber: number | string;
    principals: string | string[];
    validAfter: string;
    validBefore: string;
    signedCertificate: string;
    keyId: string;
    publicKey: string;
}

/** The column renamed with login names, so a stored layout keeps its width. */
const RENAMED_COLUMNS = { principals: 'loginNames' };

const statusOf = (c: SshCertificateView) => certificateStatus(c, new Date());
const namesOf = (c: SshCertificateView) => jsonList(c.principals).join(', ') || '-';

/// <summary>
/// The "Request a certificate" form: the reader's public key, the login names they hold on the
/// chosen SSH CA as a tick list, and how long the certificate lasts. Nothing is typed that the CA
/// decides: the name hosts log is shown read-only, and only held login names are offered.
/// </summary>
const RequestForm: React.FC<{
    options: SshRequestOptions;
    onSigned: (result: SignedCertificate) => void;
    onCancel: () => void;
}> = ({ options, onSigned, onCancel }) => {
    const [caKeyId, setCaKeyId] = useState(options.caKeys[0]?.id ?? '');
    const [selection, setSelection] = useState<{ requestProfileId?: string; signingProfileId?: string; certProfileId?: string }>({});
    const [publicKey, setPublicKey] = useState('');
    const [ticked, setTicked] = useState<string[]>([]);
    /** Null while the field follows the most allowed. */
    const [validity, setValidity] = useState<string | null>(null);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<NoticeInput | null>(null);

    const caKey: SshRequestKey | undefined = options.caKeys.find((k) => k.id === caKeyId);
    const combinations = caKey?.profiles ?? [];
    const combination = chosenCombination(combinations, selection);
    const requestChoices = requestProfileChoices(combinations);
    const signingChoices = combination ? signingProfileChoices(combinations, combination.requestProfileId) : [];
    const certChoices = combination ? certProfileChoices(combinations, combination.requestProfileId, combination.signingProfileId) : [];

    const held = caKey?.loginNames ?? [];
    const unavailable: Record<string, string> = {};
    for (const name of combination?.unavailableLoginNames ?? []) unavailable[name] = `Not allowed by the profile ${combination!.certProfileName}`;
    const tickedHeld = held.filter((n) => ticked.includes(n.name) && !unavailable[n.name]);
    const names = tickedHeld.map((n) => n.name);
    const limit = validityLimit(tickedHeld, combination?.maxValidityHours ?? caKey?.maxValidityHours ?? 0, new Date());
    const validityShown = validity ?? defaultValidity(limit);
    const limitText = validityLimitText(limit);

    const problems: string[] = [];
    if (combination && names.length > combination.maxPrincipals) {
        problems.push(`${names.length} login names are ticked, and one certificate carries at most ${combination.maxPrincipals} with this profile.`);
    }
    const validityError = validityProblem(validityShown, limit);
    if (validityError) problems.push(validityError);

    const noName = options.keyId == null;
    const ready = !noName && !!combination && names.length > 0 && publicKey.trim() !== '' && problems.length === 0;
    const shownAccount = names[names.length - 1] ?? null;

    const pickKey = (id: string) => { setCaKeyId(id); setSelection({}); setTicked([]); setValidity(null); };

    const submit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!ready || !combination) return;
        setBusy(true);
        setError(null);
        try {
            const body: Record<string, unknown> = {
                publicKey: publicKey.trim(),
                principals: names,
                sshRequestProfileId: combination.requestProfileId,
                sshSigningProfileId: combination.signingProfileId,
                sshCertProfileId: combination.certProfileId,
            };
            if (validityShown !== '') body.validityHours = Number(validityShown);
            const result: any = await apiPost('/api/v1/user/ssh/sign-user', body);
            onSigned({ ...result, publicKey: publicKey.trim() });
        } catch (err: any) {
            setError(errorNotice(err, 'The certificate could not be issued.'));
        } finally {
            setBusy(false);
        }
    };

    if (options.caKeys.length === 0) {
        return (
            <div className="bg-raised border border-line rounded-lg p-4 space-y-3">
                <h3 className="text-sm font-semibold text-ink">Request a certificate</h3>
                <p className="text-sm text-ink max-w-3xl">There is no SSH CA you may request a certificate from. An administrator gives you the right to request on an SSH CA.</p>
            </div>
        );
    }

    return (
        <form onSubmit={submit} className="bg-raised border border-line rounded-lg p-4 space-y-4">
            <h3 className="text-sm font-semibold text-ink">Request a certificate</h3>

            {noName && (
                <InlineNotice severity="warning" notice="No certificate can be requested for your account: the CA cannot write your username as the name hosts log. A username that begins with svc:, is longer than 255 characters or holds a control character cannot be one. Ask an administrator to change your username." />
            )}

            {options.caKeys.length > 1 && (
                <div className="max-w-sm">
                    <label htmlFor="ssh-req-ca" className={labelClass}>SSH CA</label>
                    <select id="ssh-req-ca" value={caKeyId} onChange={(e) => pickKey(e.target.value)} className={inputClass}>
                        {options.caKeys.map((k) => <option key={k.id} value={k.id}>{k.name} ({k.keyType})</option>)}
                    </select>
                </div>
            )}

            {caKey && combinations.length === 0 && (
                <InlineNotice severity="warning" notice={`Nothing can be requested from ${caKey.name} yet: it has no request profile you can use without approval. An administrator sets one up under Profiles.`} />
            )}

            {(requestChoices.length > 1 || signingChoices.length > 1 || certChoices.length > 1) && combination && (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 max-w-4xl">
                    {requestChoices.length > 1 && (
                        <div>
                            <label htmlFor="ssh-req-request" className={labelClass}>Request profile</label>
                            <select id="ssh-req-request" value={combination.requestProfileId} className={inputClass}
                                onChange={(e) => { setSelection({ requestProfileId: e.target.value }); setValidity(null); }}>
                                {requestChoices.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
                            </select>
                        </div>
                    )}
                    {signingChoices.length > 1 && (
                        <div>
                            <label htmlFor="ssh-req-signing" className={labelClass}>Signing profile</label>
                            <select id="ssh-req-signing" value={combination.signingProfileId} className={inputClass}
                                onChange={(e) => { setSelection({ requestProfileId: combination.requestProfileId, signingProfileId: e.target.value }); setValidity(null); }}>
                                {signingChoices.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
                            </select>
                        </div>
                    )}
                    {certChoices.length > 1 && (
                        <div>
                            <label htmlFor="ssh-req-cert" className={labelClass}>Certificate profile</label>
                            <select id="ssh-req-cert" value={combination.certProfileId} className={inputClass}
                                onChange={(e) => { setSelection({ ...selection, requestProfileId: combination.requestProfileId, signingProfileId: combination.signingProfileId, certProfileId: e.target.value }); setValidity(null); }}>
                                {certChoices.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
                            </select>
                        </div>
                    )}
                </div>
            )}

            <div className="max-w-3xl">
                <label htmlFor="ssh-req-key" className={labelClass}>Your public key</label>
                <textarea id="ssh-req-key" rows={2} value={publicKey} onChange={(e) => setPublicKey(e.target.value)} spellCheck={false}
                    placeholder="ssh-ed25519 AAAA... you@laptop" aria-describedby="ssh-req-key-hint"
                    className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-ink data-mono placeholder-ink-faint focus:outline-none focus:border-accent" />
                <FieldHint id="ssh-req-key-hint">
                    The contents of <span className="font-mono">~/.ssh/id_ed25519.pub</span>, or of the .pub file of the key you use. The private key never leaves your machine.
                </FieldHint>
            </div>

            <fieldset className="space-y-1.5 min-w-0">
                <legend className={labelClass}>Log in as</legend>
                {held.length === 0 ? (
                    <InlineNotice severity="warning" notice={caKey?.allowOwnUsername
                        ? `You hold no login name on ${caKey?.name ?? 'this SSH CA'}: your username cannot be used as one, and nothing has been granted to you. An administrator of the SSH CA grants login names.`
                        : `You hold no login name on ${caKey?.name ?? 'this SSH CA'}: logging in as your own username is turned off for it, and nothing has been granted to you. An administrator of the SSH CA grants login names.`} />
                ) : (
                    <LoginNameTicks idPrefix="ssh-req-name" names={held} ticked={ticked} onChange={(next) => { setTicked(next); setValidity(null); }}
                        whose="you" unavailable={unavailable} limitedBy={limit.loginName} />
                )}
                <FieldHint>
                    These are the only accounts you may ask for. An administrator of the SSH CA grants more. A login name is the SSH principal: the account on the host that you log in to.
                </FieldHint>
            </fieldset>

            <div className="space-y-1.5">
                <label htmlFor="ssh-req-hours" className={labelClass}>Valid for (hours)</label>
                <input id="ssh-req-hours" type="text" inputMode="numeric" value={validityShown}
                    onChange={(e) => setValidity(e.target.value.replace(/\D/g, ''))} className={`${inputClassNarrow} w-36`} />
                {limitText
                    ? <div role="status" className="max-w-3xl px-3 py-2 border border-warn/40 rounded bg-warn-soft text-sm text-ink">{limitText}</div>
                    : combination && <FieldHint>At most {limit.maxHours} hours, the limit of the profile and the SSH CA. Leave empty for the most allowed.</FieldHint>}
            </div>

            <div>
                <span className={labelClass}>Your name in host logs</span>
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                    <span className="inline-flex items-center min-w-[9rem] px-3 py-1.5 border border-line rounded bg-sunken data-mono text-ink">{options.keyId ?? '-'}</span>
                    <span className="text-xs text-ink-muted">Set by the CA and cannot be changed. Every host records it with each login, whichever account you use.</span>
                </div>
            </div>

            {shownAccount && options.keyId && (
                <div>
                    <span className={labelClass}>What a host records when you log in as {shownAccount}</span>
                    <div className="max-w-full overflow-x-auto px-3 py-2 border border-line rounded bg-raised data-mono whitespace-nowrap text-ink">
                        Accepted publickey for <strong className="font-medium text-accent-ink">{shownAccount}</strong> from [your address] port [port] ssh2: {sshdKeyType(publicKey || caKey?.keyType)}-CERT SHA256:[your key] ID <strong className="font-medium text-accent-ink">{options.keyId}</strong> (serial [new serial]) CA {sshdKeyType(caKey?.keyType)} {caKey?.fingerprint || 'SHA256:[CA key]'}
                    </div>
                </div>
            )}

            {problems.map((p) => <FieldHint key={p} tone="warn">{p}</FieldHint>)}
            <InlineNotice notice={error} onDismiss={() => setError(null)} />

            <div className="flex gap-2">
                <button type="submit" disabled={busy || !ready} className={actionButtonPrimary}>{busy ? 'Requesting…' : 'Request certificate'}</button>
                <button type="button" onClick={onCancel} className={actionButton}>Clear</button>
            </div>
        </form>
    );
};

/// <summary>
/// The SSH tab of the self-service Request Certificate page: the form to request an SSH
/// certificate. A new certificate is shown once with copy and download and where to save it,
/// and stays downloadable from the SSH tab of My Certificates.
/// </summary>
export const MySshRequestTab: React.FC = () => {
    const [options, setOptions] = useState<SshRequestOptions | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [refresh, setRefresh] = useState(0);
    const [signed, setSigned] = useState<SignedCertificate | null>(null);
    const [copied, setCopied] = useState(false);
    /** Bumped after each certificate, so the form starts empty for the next one. */
    const [formRound, setFormRound] = useState(0);

    useEffect(() => {
        let cancelled = false;
        apiGet<SshRequestOptions>('/api/v1/user/ssh/request-options', { toast: false })
            .then((data) => { if (!cancelled) { setOptions(data && Array.isArray(data.caKeys) ? data : null); setError(null); } })
            .catch((err) => { if (!cancelled) { setOptions(null); setError(errorNotice(err, 'The request form could not be loaded.')); } })
            .finally(() => { if (!cancelled) setLoading(false); });
        return () => { cancelled = true; };
    }, [refresh]);

    const copySigned = async () => {
        if (signed && await copyText(signed.signedCertificate)) {
            setCopied(true);
            window.setTimeout(() => setCopied(false), 1500);
        }
    };

    const keyFile = defaultKeyFile(signed?.publicKey);

    return (
        <div className="space-y-4 sm:space-y-6">
            {signed && (
                <div className="bg-raised border border-line border-l-4 border-l-ok rounded-lg p-4 space-y-3">
                    <div className="flex items-center justify-between gap-2 flex-wrap">
                        <span className="text-ok font-semibold text-sm">Your certificate is ready</span>
                        <button type="button" onClick={() => setSigned(null)} className="text-xs text-ink-muted hover:text-ink transition-colors">Dismiss</button>
                    </div>
                    <div className="max-w-3xl">
                        <DetailField label="Serial" value={String(signed.serialNumber)} mono />
                        <DetailField label="Login names" value={jsonList(signed.principals).join(', ')} mono />
                        <DetailField label="Valid until" value={dayTimeText(signed.validBefore)} />
                    </div>
                    <textarea readOnly rows={3} aria-label="Your certificate" value={signed.signedCertificate}
                        className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-ink data-mono focus:outline-none" />
                    <div className="flex flex-wrap gap-2">
                        <button type="button" onClick={copySigned} className={actionButton}>{copied ? 'Copied' : 'Copy'}</button>
                        <button type="button" onClick={() => downloadText(signed.signedCertificate, `${keyFile}-cert.pub`)} className={actionButton}>Download certificate</button>
                    </div>
                    <p className="text-xs text-ink-muted max-w-3xl">
                        Save it as <code className="text-accent-ink">~/.ssh/{keyFile}-cert.pub</code>, beside the private key <code className="text-accent-ink">~/.ssh/{keyFile}</code>. If your key file has another name, use that name with <code className="text-accent-ink">-cert.pub</code> added. ssh then presents the certificate by itself. It stays under <Link to={SELF_SSH_CERTIFICATES_PATH} className="text-accent-ink hover:underline">My Certificates, on the SSH tab</Link>, where it can be downloaded again; a download from that list is named after you, so rename it the same way.
                    </p>
                </div>
            )}

            {loading && <p className="text-sm text-ink-muted">Loading…</p>}
            <InlineNotice notice={error} />
            {options && (
                <RequestForm key={formRound} options={options}
                    onSigned={(result) => { setSigned(result); setCopied(false); setFormRound((r) => r + 1); setRefresh((r) => r + 1); }}
                    onCancel={() => setFormRound((r) => r + 1)} />
            )}
        </div>
    );
};

/// <summary>
/// The SSH tab of the self-service My Certificates page: the SSH certificates issued for the
/// reader, whoever asked for them, each downloadable.
/// </summary>
export const MySshCertificatesTab: React.FC = () => {
    const { showToast } = useToast();
    const [certificates, setCertificates] = useState<SshCertificateView[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [endpointUnavailable, setEndpointUnavailable] = useState(false);

    useEffect(() => {
        let cancelled = false;
        apiGet<SshCertificateView[]>('/api/v1/user/ssh/certificates')
            .then((data) => { if (!cancelled) setCertificates(Array.isArray(data) ? data : []); })
            .catch((err) => {
                if (cancelled) return;
                if (err.message?.includes('404') || err.message?.includes('Not Found')) {
                    setEndpointUnavailable(true);
                } else {
                    setError(errorNotice(err, 'The request failed.'));
                }
            })
            .finally(() => { if (!cancelled) setLoading(false); });
        return () => { cancelled = true; };
    }, []);

    const handleDownload = async (cert: SshCertificateView) => {
        try {
            const resp = await apiBlob(`/api/v1/user/ssh/certificates/${cert.id}/download`);
            downloadText(await resp.text(), `${cert.keyId || cert.id}-cert.pub`);
        } catch (err: any) {
            showToast('error', err.message || 'Download failed');
        }
    };

    const columns: DataTableColumn<SshCertificateView>[] = [
        {
            key: 'status', header: 'Status', defaultWidth: 110, truncate: false,
            exportValue: (c) => certificateBadge(statusOf(c)).label,
            render: (c) => <StatusBadge {...certificateBadge(statusOf(c))} />,
        },
        { key: 'serial', header: 'Serial', defaultWidth: 110, exportValue: (c) => String(c.serialNumber), render: (c) => <span className="data-mono text-ink">{String(c.serialNumber)}</span> },
        { key: 'sshCa', header: 'SSH CA', defaultWidth: 180, exportValue: (c) => c.sshCaKey?.name || '', render: (c) => <span className="text-ink">{c.sshCaKey?.name || '-'}</span> },
        {
            key: 'loginNames', header: 'Login names', defaultWidth: 240,
            headerTitle: 'The accounts the certificate lets you log in as.',
            exportValue: namesOf, render: (c) => <span className="data-mono text-ink-muted">{namesOf(c)}</span>,
        },
        {
            key: 'validBefore', header: 'Valid until', defaultWidth: 200, truncate: false,
            exportValue: (c) => dayTimeText(c.validBefore),
            render: (c) => <span className="text-xs text-ink-muted whitespace-nowrap tabular-nums">{dayTimeText(c.validBefore)}</span>,
        },
    ];

    const renderExpanded = (cert: SshCertificateView) => (
        <div className="space-y-3">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                <DetailField label="Your name in host logs" value={cert.keyId} mono />
                <DetailField label="Serial" value={String(cert.serialNumber)} mono />
                <DetailField label="SSH CA" value={cert.sshCaKey?.name} />
                <DetailField label="Valid" value={`${dayTimeText(cert.validAfter)} to ${dayTimeText(cert.validBefore)}`} />
                <DetailField label="Issued by" value={cert.issuedBy?.selfService ? 'You (self-service)' : issuedByText(cert)} />
                <DetailField label="Key" value={cert.keyFingerprint} mono />
            </div>

            <div className="space-y-1.5">
                <div className="label-caps">Login names, and why you had each</div>
                <LoginNameGrounds cert={cert} />
            </div>

            {statusOf(cert) === 'revoked' && (
                <div className="bg-crit-soft border border-crit/40 rounded p-2">
                    <span className="text-xs text-crit">This certificate has been revoked. A host refuses it once the host has fetched the SSH CA's revocation list.</span>
                </div>
            )}

            <div className="flex flex-wrap gap-2 pt-2 border-t border-line">
                <button onClick={() => handleDownload(cert)} className={actionButton}>Download certificate</button>
            </div>
        </div>
    );

    return endpointUnavailable ? (
        <div className="bg-raised border border-line rounded-lg p-8 text-center">
            <p className="text-ink-muted">SSH certificates will appear here once issued.</p>
        </div>
    ) : (
        <DataTable<SshCertificateView>
            tableId="my-ssh-certificates"
            renamedColumns={RENAMED_COLUMNS}
            title="SSH Certificates"
            rows={certificates}
            rowKey={(c) => c.id}
            loading={loading}
            error={error}
            empty="No SSH certificate has been issued for you yet."
            columns={columns}
            exportFileName="my-ssh-certificates"
            renderExpanded={renderExpanded}
        />
    );
};
