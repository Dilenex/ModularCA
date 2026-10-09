import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { apiGet, apiPost, apiPostWithMfa, apiDeleteWithMfa, apiBlob } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge, Tag } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DataTable, DataTableColumn, DataTableBulkAction } from '@shared/components/DataTable';
import { NewButton } from '@shared/components/NewButton';
import { Capabilities, StepUpOps } from '@shared/generated';
import { useAuth } from '../context/AuthContext';
import { FieldHint } from '@shared/components/forms';
import { actionButton } from '@shared/components/actionButtons';
import { copyText } from '@shared/clipboard';
import { type CeremonyRefusal, readCeremonyRefusal } from './ceremonyRefusal';
import { CeremonyRefusalNotice } from '../components/CeremonyRefusalNotice';
import { runWithOneStepUp } from '@shared-auth/api/stepUpBatch';
import { signBlockedReason, sshKeyCustody, sshSignerState } from './sshKeyCustody';
import { SshPlaintextNoticeBanner } from '../components/SshPlaintextNotice';
import { SshSignKeyForm, type SshSignResult } from '../components/SshSignKeyForm';
import { SshLogLineLookup } from '../components/SshLogLineLookup';
import { LoginNameGrounds } from '../components/SshCertificateParts';
import {
    canOnSshCa, certificateBadge, certificateStatus, dayText, dayTimeText, defaultKeyFile, isUserCertificate, issuedByDetail, issuedByText, issuedToDetail, issuedToText, jsonList,
    sshKeyChoices,
    type SshCaKeyRef, type SshCertificateView,
} from './sshLoginNames';
import { FilterBar, FilterField, filterControlClass } from '@shared/components/FilterBar';
import { SshScopeSentence } from '../components/KindTabs';
import type { Scope } from '../scope';
import { SSH_CA_KEYS_PATH, sshCaKeyPath, sshCertificatePath, sshScopeSentence } from './sshPlaces';
import {
    REVIEW_DATE_ACTS_ON_NOTHING, SSH_CA_MAX_VALIDITY_HOURS, WHY_ONE_TYPE, emptySshCaKeyForm, hoursProblem, hoursText, sshCaKeyBody, sshCaKeyReview, withHours, withKind,
    type SshCaKeyForm,
} from './sshCaDefaults';

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function downloadText(content: string, filename: string) {
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}

/* ─── SSH CA Keys Section ─── */
const SshCaKeys: React.FC<{ refreshTrigger: number; onRefresh: () => void }> = ({ refreshTrigger, onRefresh }) => {
    const { showToast } = useToast();
    // Generating an SSH CA key is SystemOperator on the server: ca.manage at system scope.
    const { can } = useAuth();
    const canGenerate = can(Capabilities.CaManage);
    const { requireStepUp } = useStepUp();
    const [keys, setKeys] = useState<any[]>([]);
    const [pendingCeremonies, setPendingCeremonies] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [generating, setGenerating] = useState(false);
    const [genForm, setGenForm] = useState<SshCaKeyForm>(emptySshCaKeyForm);
    const [showGenForm, setShowGenForm] = useState(false);
    // Creating the CA was refused because nobody else could approve its ceremony.
    const [genRefusal, setGenRefusal] = useState<CeremonyRefusal | null>(null);
    const [genError, setGenError] = useState<NoticeInput | null>(null);
    const [confirmAction, setConfirmAction] = useState<{ action: () => Promise<void>; title: string; message: string; confirmLabel: string } | null>(null);
    const [confirmLoading, setConfirmLoading] = useState(false);

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError(null);

        Promise.all([
            apiGet<any>('/api/v1/admin/ssh/ca-keys'),
            apiGet<any>('/api/v1/admin/ceremonies?status=Pending').catch(() => []),
        ]).then(([keyData, ceremonyData]) => {
                if (cancelled) return;
                setKeys(Array.isArray(keyData) ? keyData : (keyData.items || keyData.keys || []));
                const allCeremonies = Array.isArray(ceremonyData) ? ceremonyData : (ceremonyData.items || []);
                setPendingCeremonies(allCeremonies.filter((c: any) =>
                    c.operationType === 'CreateSshCa' || c.operationType === 'DeleteSshCa'));
                setLoading(false);
            })
            .catch((err) => {
                if (!cancelled) {
                    setError(errorNotice(err, 'Failed to load SSH CA keys'));
                    setLoading(false);
                }
            });

        return () => { cancelled = true; };
    }, [refreshTrigger]);

    const genHoursProblem = hoursProblem(genForm);

    const handleGenerate = async (e: React.FormEvent) => {
        e.preventDefault();
        if (genHoursProblem) return;
        setGenerating(true);
        setGenRefusal(null);
        setGenError(null);
        try {
            const result: any = await apiPostWithMfa('/api/v1/admin/ssh/ca-keys', sshCaKeyBody(genForm), requireStepUp, StepUpOps.CreateSshCa);
            if (result?.requiresCeremony) {
                showToast('info', result.message || 'Key ceremony created for approval.');
                setShowGenForm(false);
                setGenForm(emptySshCaKeyForm());
                return;
            }
            setShowGenForm(false);
            setGenForm(emptySshCaKeyForm());
            onRefresh();
        } catch (err: any) {
            const refusal = readCeremonyRefusal(err);
            if (refusal) setGenRefusal(refusal);
            else setGenError(errorNotice(err, 'Failed to generate CA key'));
        } finally {
            setGenerating(false);
        }
    };

    const handleDisableKey = (keyId: string, keyName: string) => {
        setConfirmAction({
            title: 'Disable SSH CA Key',
            message: `Are you sure you want to disable "${keyName}"? All active certificates will be revoked. This action cannot be undone.`,
            confirmLabel: 'Disable',
            action: async () => {
                const result: any = await apiDeleteWithMfa(
                    `/api/v1/admin/ssh/ca-keys/${keyId}`,
                    requireStepUp, StepUpOps.DisableSshCa, keyId);
                if (result?.requiresCeremony) {
                    showToast('info', result.message || 'Key ceremony created for approval.');
                } else {
                    showToast('success', 'CA key disabled successfully.');
                    onRefresh();
                }
            },
        });
    };

    // Build a combined list: real keys + pending ceremony placeholders
    const pendingCreateEntries = pendingCeremonies
        .filter((c: any) => c.operationType === 'CreateSshCa')
        .map((c: any) => ({
            id: `ceremony-${c.id}`,
            ceremonyId: c.id,
            name: c.description?.replace(/^Create SSH CA '/, '').replace(/'$/, '') || 'Pending SSH CA',
            keyType: '—',
            isUserCa: false,
            isHostCa: false,
            isEnabled: true,
            isPendingCeremony: true,
            ceremonyStatus: c.status,
            currentApprovals: c.currentApprovals,
            requiredApprovals: c.requiredApprovals,
        }));

    const keyStatusLabel = (key: any) => key.isEnabled === false
        ? 'Disabled'
        : (pendingCeremonies.some((c: any) => c.targetEntityId === key.id && c.operationType === 'DeleteSshCa') ? 'Disable Pending' : 'CA Key');
    const keyStatusBadge = (key: any) => {
        if (key.isEnabled === false) return <StatusBadge status="revoked" label="Disabled" />;
        if (pendingCeremonies.some((c: any) => c.targetEntityId === key.id && c.operationType === 'DeleteSshCa')) return <StatusBadge status="pending" label="Disable Pending" />;
        return <Tag label="CA Key" />;
    };

    const columns: DataTableColumn<any>[] = [
        { key: 'name', header: 'Name', defaultWidth: 200, minWidth: 140, truncate: false, exportValue: (k) => k.name || 'Unnamed', render: (k) => <span className="text-ink font-medium truncate">{k.name || 'Unnamed'}</span> },
        { key: 'status', header: 'Status', defaultWidth: 130, truncate: false, exportValue: keyStatusLabel, render: keyStatusBadge },
        {
            key: 'storage', header: 'Storage', defaultWidth: 160, truncate: false,
            headerTitle: 'Where the private key is held. Open a row for the reason when the signer does not hold it.',
            exportValue: (k) => { const c = sshKeyCustody(k); return c.reason ? `${c.badge.label}: ${c.reason}` : c.badge.label; },
            render: (k) => { const c = sshKeyCustody(k); return <span title={c.reason || c.summary}><StatusBadge status={c.badge.status} label={c.badge.label} /></span>; },
        },
        { key: 'algorithm', header: 'Algorithm', defaultWidth: 150, exportValue: (k) => `${k.keyType || k.algorithm}${k.keySize ? ` (${k.keySize})` : ''}`, render: (k) => <span className="text-xs text-ink">{k.keyType || k.algorithm}{k.keySize ? ` (${k.keySize})` : ''}</span> },
        {
            key: 'role', header: 'Role', defaultWidth: 120, truncate: false,
            exportValue: (k) => [k.isUserCa ? 'User' : null, k.isHostCa ? 'Host' : null].filter(Boolean).join(', '),
            render: (k) => (
                <span className="flex gap-1">
                    {k.isUserCa && <span className="px-1.5 py-0.5 text-xs bg-ok-soft text-ok rounded">User</span>}
                    {k.isHostCa && <span className="px-1.5 py-0.5 text-xs bg-accent-soft text-accent-ink rounded">Host</span>}
                    {!k.isUserCa && !k.isHostCa && <span className="text-xs text-ink-muted">-</span>}
                </span>
            ),
        },
        { key: 'created', header: 'Created', defaultWidth: 160, exportValue: (k) => formatDate(k.createdAt), render: (k) => <span className="text-xs text-ink-muted">{formatDate(k.createdAt)}</span> },
        {
            key: 'reviewBy', header: 'Review by', defaultWidth: 220, truncate: false,
            headerTitle: 'A reminder to review the key. Nothing stops working on this date.',
            exportValue: (k) => { const r = sshCaKeyReview(k, new Date()); return k.reviewBy ? `${dayText(k.reviewBy)}${r.badge ? ` (${r.badge.label})` : ''}` : ''; },
            render: (k) => {
                if (!k.reviewBy) return <span className="text-xs text-ink-muted">-</span>;
                const review = sshCaKeyReview(k, new Date());
                return (
                    <span className="inline-flex items-center gap-1.5" title={review.warning ? `${review.warning} ${REVIEW_DATE_ACTS_ON_NOTHING}` : REVIEW_DATE_ACTS_ON_NOTHING}>
                        <span className="text-xs text-ink-muted tabular-nums">{dayText(k.reviewBy)}</span>
                        {review.badge && <StatusBadge status={review.badge.status} label={review.badge.label} />}
                    </span>
                );
            },
        },
    ];

    // Disable is step-up MFA gated with no bulk endpoint, so it's single-select.
    const bulkActions: DataTableBulkAction<any>[] = [
        { label: 'Disable', single: true, variant: 'danger', enabledFor: (k) => k.isEnabled !== false, onClick: (rows) => handleDisableKey(rows[0].id, rows[0].name) },
    ];

    const caKeyDrawer = (k: any) => {
        const custody = sshKeyCustody(k);
        return (
            <div className="text-sm">
                <DetailField label="ID" value={k.id} mono />
                <DetailField label="Status" value={keyStatusLabel(k)} />
                <DetailField label="Key storage" value={custody.heldIn} />
                <DetailField label="Storage state" value={<StatusBadge status={custody.badge.status} label={custody.badge.label} />} />
                <DetailField label="What it means" value={custody.summary} />
                <DetailField label="Reason" value={custody.reason} />
                <DetailField label="Expected key file" value={custody.keyFile} mono />
                <DetailField label="What to do" value={custody.remedy} />
                {k.importedAt && <DetailField label="Imported" value={`${formatDate(k.importedAt)}, from a key file on the node`} />}
                <DetailField label="Algorithm" value={`${k.keyType || k.algorithm}${k.keySize ? ` (${k.keySize} bits)` : ''}`} />
                <DetailField label="Max Validity" value={`${k.maxValidityHours}h`} />
                <DetailField label="Created" value={formatDate(k.createdAt)} />
                {k.reviewBy && <DetailField label="Review by" value={dayText(k.reviewBy)} />}
                {sshCaKeyReview(k, new Date()).warning && <DetailField label="Review" value={`${sshCaKeyReview(k, new Date()).warning} ${REVIEW_DATE_ACTS_ON_NOTHING}`} />}
                <DetailField label="User CA" value={k.isUserCa ? 'Yes' : 'No'} />
                <DetailField label="Host CA" value={k.isHostCa ? 'Yes' : 'No'} />
                <DetailField label="Public Key" value={k.publicKey} mono />
            </div>
        );
    };

    return (
        <div className="space-y-4">
            {canGenerate && showGenForm && (
                <form onSubmit={handleGenerate} className="bg-raised border border-line rounded-lg p-4 space-y-3">
                    <h3 className="text-sm font-semibold text-ink">Generate New SSH CA Key</h3>
                    <FieldHint>SSH CAs belong to the instance, not to a space. The private key is generated by the signer and held in the signer's SSH keystore; it is never written to the node.</FieldHint>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                        <div>
                            <label className="block text-xs text-ink-muted mb-1">Name</label>
                            <input
                                type="text"
                                required
                                placeholder="My SSH CA"
                                value={genForm.name}
                                onChange={(e) => setGenForm({ ...genForm, name: e.target.value })}
                                className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-sm text-ink placeholder-ink-faint focus:outline-none focus:border-accent"
                            />
                        </div>
                        <div>
                            <label className="block text-xs text-ink-muted mb-1">Key Type</label>
                            <select
                                value={genForm.keyType}
                                onChange={(e) => setGenForm({ ...genForm, keyType: e.target.value, keySize: '' })}
                                className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-sm text-ink focus:outline-none focus:border-accent"
                            >
                                <option value="ed25519">ed25519</option>
                                <option value="ecdsa">ecdsa</option>
                                <option value="rsa">rsa</option>
                            </select>
                        </div>
                        {genForm.keyType !== 'ed25519' && (
                        <div>
                            <label className="block text-xs text-ink-muted mb-1">Key Size</label>
                            <select
                                value={genForm.keySize}
                                onChange={(e) => setGenForm({ ...genForm, keySize: e.target.value })}
                                className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-sm text-ink focus:outline-none focus:border-accent"
                            >
                                {genForm.keyType === 'rsa' ? (
                                    <>
                                        <option value="">Default (3072)</option>
                                        <option value="2048">2048 bits</option>
                                        <option value="3072">3072 bits</option>
                                        <option value="4096">4096 bits</option>
                                        <option value="7680">7680 bits (high compute)</option>
                                        <option value="8192">8192 bits (high compute)</option>
                                    </>
                                ) : (
                                    <>
                                        <option value="">Default (256)</option>
                                        <option value="256">P-256 (256 bits)</option>
                                        <option value="384">P-384 (384 bits)</option>
                                        <option value="521">P-521 (521 bits)</option>
                                    </>
                                )}
                            </select>
                            {genForm.keyType === 'rsa' && (genForm.keySize === '7680' || genForm.keySize === '8192') && (
                                <p className="text-xs text-warn mt-1">
                                    ⚠ High-compute RSA — key generation may take 30+ seconds.
                                </p>
                            )}
                        </div>
                        )}
                    </div>
                    <fieldset>
                        <legend className="block text-xs text-ink-muted mb-1">Type</legend>
                        <div className="flex gap-4">
                            <label className="flex items-center gap-2 text-sm text-ink">
                                <input type="radio" name="ssh-ca-kind" checked={genForm.kind === 'user'} onChange={() => setGenForm(withKind(genForm, 'user'))} />
                                User: signs the certificates people present to servers
                            </label>
                            <label className="flex items-center gap-2 text-sm text-ink">
                                <input type="radio" name="ssh-ca-kind" checked={genForm.kind === 'host'} onChange={() => setGenForm(withKind(genForm, 'host'))} />
                                Host: signs the certificates servers present to clients
                            </label>
                        </div>
                        <FieldHint>{WHY_ONE_TYPE}</FieldHint>
                    </fieldset>
                    <div className="max-w-xs">
                        <label htmlFor="ssh-ca-max-validity" className="block text-xs text-ink-muted mb-1">Longest certificate (hours)</label>
                        <input
                            id="ssh-ca-max-validity"
                            type="text"
                            inputMode="numeric"
                            value={genForm.maxValidityHours}
                            onChange={(e) => setGenForm(withHours(genForm, e.target.value))}
                            aria-describedby="ssh-ca-max-validity-hint"
                            className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-sm text-ink placeholder-ink-faint focus:outline-none focus:border-accent"
                        />
                        {genHoursProblem
                            ? <FieldHint id="ssh-ca-max-validity-hint" tone="warn">{genHoursProblem}</FieldHint>
                            : <FieldHint id="ssh-ca-max-validity-hint">The hard ceiling for every certificate this key signs: {hoursText(SSH_CA_MAX_VALIDITY_HOURS[genForm.kind])} for a {genForm.kind} key unless you change it. Profiles and login name grants can only shorten it.</FieldHint>}
                    </div>
                    <button
                        type="submit"
                        disabled={generating || !!genHoursProblem}
                        className="px-4 py-2 text-sm bg-accent text-on-accent rounded hover:bg-accent-hover disabled:opacity-50 transition-colors"
                    >
                        {generating ? 'Generating...' : 'Generate'}
                    </button>
                    {genRefusal && <CeremonyRefusalNotice refusal={genRefusal} />}
                    <InlineNotice notice={genError} onDismiss={() => setGenError(null)} />
                </form>
            )}

            {pendingCreateEntries.length > 0 && (
                <div className="bg-warn-soft border border-warn/40 rounded-lg p-3 text-xs space-y-1">
                    <p className="font-semibold text-warn">Pending CA key ceremonies</p>
                    {pendingCreateEntries.map((c) => (
                        <div key={c.id} className="flex items-center gap-2">
                            <StatusBadge status="pending" label={`Ceremony (${c.currentApprovals}/${c.requiredApprovals})`} />
                            <span className="text-ink">{c.name}</span>
                        </div>
                    ))}
                </div>
            )}

            <DataTable<any>
                tableId="ssh-ca-keys"
                toolbarAction={canGenerate ? <NewButton what="SSH CA key" open={showGenForm} onClick={() => { setShowGenForm(!showGenForm); setGenError(null); }} /> : undefined}
                title="SSH CA Keys"
                rows={keys}
                rowKey={(k) => k.id || k.fingerprint}
                loading={loading}
                error={error}
                empty="No SSH CA keys configured"
                columns={columns}
                selectable
                bulkActions={bulkActions}
                exportFileName="ssh-ca-keys"
                renderDrawer={caKeyDrawer}
                drawerTitle={(k) => k.name || 'Unnamed'}
                detailPath={(k) => sshCaKeyPath(k.id)}
            />

            <ConfirmModal
                isOpen={!!confirmAction}
                title={confirmAction?.title || ''}
                message={confirmAction?.message || ''}
                confirmLabel={confirmAction?.confirmLabel || 'Confirm'}
                tone="crit"
                loading={confirmLoading}
                onConfirm={async () => {
                    if (!confirmAction) return;
                    setConfirmLoading(true);
                    try {
                        await confirmAction.action();
                    } catch (err: any) {
                        if (err.message !== 'Step-up MFA cancelled')
                            showToast('error', err.message || 'Action failed');
                    } finally {
                        setConfirmLoading(false);
                        setConfirmAction(null);
                    }
                }}
                onCancel={() => setConfirmAction(null)}
            />
        </div>
    );
};

/* ─── SSH Certificates Section ─── */
/** Columns renamed with login names, so a stored layout keeps its widths. */
const RENAMED_CERT_COLUMNS = { keyId: 'issuedTo', principals: 'loginNames' };

/** Rows asked for at a time; the list route answers a page and no total. */
const CERTIFICATE_PAGE_SIZE = 50;

/// <summary>
/// The SSH tab of All Certificates: the SSH certificates of every SSH CA key the reader may view,
/// a page at a time, with the key as a column and as a filter, finding a certificate from a host
/// log line, and download and revoke for the certificates of the keys the reader may revoke on.
/// </summary>
const SshCertificateList: React.FC = () => {
    const { showToast } = useToast();
    const { requireStepUp } = useStepUp();
    const { capabilities } = useAuth();
    const [certs, setCerts] = useState<SshCertificateView[]>([]);
    /** The keys the key list answered; null while it has not, and for a reader it refuses. */
    const [listedKeys, setListedKeys] = useState<SshCaKeyRef[] | null>(null);
    const [seenKeys, setSeenKeys] = useState<SshCaKeyRef[]>([]);
    const [keyFilter, setKeyFilter] = useState('');
    const [page, setPage] = useState(1);
    const [refreshTrigger, setRefreshTrigger] = useState(0);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [confirmRevoke, setConfirmRevoke] = useState<SshCertificateView[] | null>(null);
    const [revoking, setRevoking] = useState<string | null>(null);

    const mayRevokeOn = (c: SshCertificateView) => canOnSshCa(capabilities, c.sshCaKey, Capabilities.CertRevoke);
    const keyChoices = sshKeyChoices(listedKeys, seenKeys);

    // The key list needs cert.revoke; a reader with cert.view alone filters by the keys of the rows seen.
    useEffect(() => {
        let cancelled = false;
        apiGet<any>('/api/v1/admin/ssh/ca-keys', { toast: false })
            .then((data) => {
                if (cancelled) return;
                const list: any[] = Array.isArray(data) ? data : (data?.items || data?.keys || []);
                setListedKeys(list.map((k) => ({ id: k.id, name: k.isEnabled === false ? `${k.name || k.id} (disabled)` : (k.name || k.id), certificateAuthorityId: k.certificateAuthorityId })));
            })
            .catch(() => { if (!cancelled) setListedKeys(null); });
        return () => { cancelled = true; };
    }, []);

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError(null);
        const query = new URLSearchParams({ page: String(page), pageSize: String(CERTIFICATE_PAGE_SIZE) });
        if (keyFilter) query.set('caKeyId', keyFilter);
        apiGet<SshCertificateView[]>(`/api/v1/admin/ssh/certificates?${query}`)
            .then((data) => {
                if (cancelled) return;
                const rows = Array.isArray(data) ? data : [];
                setCerts(rows);
                setSeenKeys((seen) => sshKeyChoices(null, [...seen, ...rows.flatMap((c) => (c.sshCaKey ? [c.sshCaKey] : []))]));
                setLoading(false);
            })
            .catch((err) => {
                if (!cancelled) {
                    setError(errorNotice(err, 'Failed to load SSH certificates'));
                    setLoading(false);
                }
            });
        return () => { cancelled = true; };
    }, [refreshTrigger, keyFilter, page]);

    // One step-up prompt names every selected certificate; each is then revoked with that token, on its own SSH CA key.
    const performBulkRevoke = async () => {
        if (!confirmRevoke) return;
        setRevoking('bulk');
        let ok = 0, failed = 0;
        try {
            const result = await runWithOneStepUp(confirmRevoke.filter((c) => !c.isRevoked), (c) => String(c.id), requireStepUp, StepUpOps.RevokeSshCert,
                (c, headers) => apiPost(`/api/v1/admin/ssh/ca-keys/${c.sshCaKeyId}/certificates/${c.id}/revoke`, {}, { toast: false, headers }));
            ok = result.ok;
            failed = result.failures.length;
            if (ok) showToast('success', `Revoked ${ok} certificate${ok !== 1 ? 's' : ''}.`);
            if (failed) showToast('error', `${failed} failed to revoke.`);
            setRefreshTrigger((t) => t + 1);
        } finally {
            setRevoking(null);
            setConfirmRevoke(null);
        }
    };

    const handleDownloadCert = async (cert: SshCertificateView) => {
        try {
            // Route through apiBlob.
            const resp = await apiBlob(`/api/v1/admin/ssh/certificates/${cert.id}/download`);
            const text = await resp.text();
            downloadText(text, `${cert.keyId || cert.id}-cert.pub`);
        } catch (err: any) {
            showToast('error', err.message || 'Failed to download certificate');
        }
    };

    const statusOf = (c: SshCertificateView) => certificateStatus(c, new Date());
    const namesOf = (c: SshCertificateView) => jsonList(c.principals).join(', ');

    const columns: DataTableColumn<SshCertificateView>[] = [
        {
            key: 'status', header: 'Status', defaultWidth: 110, truncate: false,
            exportValue: (c) => certificateBadge(statusOf(c)).label,
            render: (c) => <StatusBadge {...certificateBadge(statusOf(c))} />,
        },
        { key: 'type', header: 'Type', defaultWidth: 90, truncate: false, exportValue: (c) => (isUserCertificate(c) ? 'User' : 'Host'), render: (c) => <Tag label={isUserCertificate(c) ? 'User' : 'Host'} /> },
        { key: 'serial', header: 'Serial', defaultWidth: 110, exportValue: (c) => String(c.serialNumber), render: (c) => <span className="data-mono text-ink-muted">{String(c.serialNumber)}</span> },
        {
            key: 'sshCa', header: 'SSH CA', defaultWidth: 170, minWidth: 120,
            headerTitle: 'The SSH CA key that signed the certificate.',
            exportValue: (c) => c.sshCaKey?.name || c.sshCaKeyId, render: (c) => <span className="text-ink">{c.sshCaKey?.name || c.sshCaKeyId}</span>,
        },
        {
            key: 'issuedTo', header: 'Issued to', defaultWidth: 180, minWidth: 130,
            headerTitle: 'Who the certificate is for: a user of this console, a service identity (svc: and its label) or a host.',
            exportValue: (c) => issuedToText(c),
            render: (c) => c.subject?.kind === 'user' && c.subject.userId
                ? <Link to={`/users/${c.subject.userId}`} className="text-accent-ink hover:underline">{issuedToText(c)}</Link>
                : <span className={c.subject?.kind === 'unknown' ? 'text-ink-muted' : 'text-ink'}>{issuedToText(c)}</span>,
        },
        {
            key: 'loginNames', header: 'Login names', defaultWidth: 220,
            headerTitle: 'The accounts a user certificate may log in as. For a host certificate, its hostnames.',
            exportValue: namesOf, render: (c) => <span className="data-mono text-ink-muted">{namesOf(c)}</span>,
        },
        { key: 'validBefore', header: 'Valid until', defaultWidth: 180, exportValue: (c) => dayTimeText(c.validBefore), render: (c) => <span className="text-xs text-ink-muted tabular-nums">{dayTimeText(c.validBefore)}</span> },
        { key: 'issuedBy', header: 'Issued by', defaultWidth: 190, headerTitle: 'Who asked for the certificate.', exportValue: (c) => issuedByText(c), render: (c) => <span className="text-ink-muted">{issuedByText(c)}</span> },
    ];

    // Download and revoke need cert.revoke on the certificate's own SSH CA, as their routes do.
    const bulkActions: DataTableBulkAction<SshCertificateView>[] = [
        { label: 'Download', single: true, enabledFor: mayRevokeOn, onClick: (rows) => handleDownloadCert(rows[0]) },
        { label: 'Revoke', variant: 'danger', enabledFor: (c) => !c.isRevoked && mayRevokeOn(c), onClick: (rows) => setConfirmRevoke(rows) },
    ];

    const certDrawer = (c: SshCertificateView) => {
        const extensions = jsonList(c.extensions);
        return (
            <div className="text-sm space-y-3">
                <div>
                    <DetailField label="Status" value={<StatusBadge {...certificateBadge(statusOf(c))} />} />
                    <DetailField label="Issued to" value={issuedToDetail(c)} />
                    <DetailField label="Issued by" value={issuedByDetail(c)} />
                    <DetailField label="Name in host logs" value={c.keyId} mono />
                    <DetailField label="Serial" value={String(c.serialNumber)} mono />
                    <DetailField label="Valid" value={`${dayTimeText(c.validAfter)} to ${dayTimeText(c.validBefore)}`} />
                    <DetailField label="SSH CA" value={c.sshCaKey?.name || c.sshCaKeyId} />
                    {!isUserCertificate(c) && <DetailField label="Hostnames" value={namesOf(c)} />}
                    {extensions.length > 0 && <DetailField label="Extensions" value={extensions.join(', ')} />}
                </div>
                {isUserCertificate(c) && (
                    <div className="space-y-1.5">
                        <div className="label-caps">Login names, and why the holder had each</div>
                        <LoginNameGrounds cert={c} linkGroups />
                    </div>
                )}
            </div>
        );
    };

    return (
        <div className="space-y-4">
            <SshLogLineLookup />

            <FilterBar>
                <FilterField label="SSH CA">
                    <select id="ssh-cert-key" aria-label="SSH CA" value={keyFilter} onChange={(e) => { setKeyFilter(e.target.value); setPage(1); }} className={filterControlClass}>
                        <option value="">Every SSH CA you may view</option>
                        {keyChoices.map((k) => <option key={k.id} value={k.id}>{k.name}</option>)}
                    </select>
                </FilterField>
            </FilterBar>

            {/* Certificate List */}
            <DataTable<SshCertificateView>
                tableId="ssh-certs"
                renamedColumns={RENAMED_CERT_COLUMNS}
                title="SSH Certificates"
                rows={certs}
                rowKey={(c) => c.id}
                loading={loading}
                error={error}
                empty={page > 1 ? 'No more SSH certificates' : 'No SSH certificates issued'}
                columns={columns}
                selectable
                bulkActions={bulkActions}
                exportFileName="ssh-certificates"
                renderDrawer={certDrawer}
                drawerTitle={(c) => `Certificate ${c.serialNumber}`}
                detailPath={(c) => sshCertificatePath(c)}
                page={page}
                pageSize={CERTIFICATE_PAGE_SIZE}
                onPageChange={setPage}
            />

            <ConfirmModal
                isOpen={!!confirmRevoke}
                title="Revoke SSH Certificates"
                message={confirmRevoke ? (() => {
                    const n = confirmRevoke.filter((c) => !c.isRevoked).length;
                    return `Revoke ${n} certificate${n !== 1 ? 's' : ''}? This cannot be undone.`;
                })() : ''}
                confirmLabel="Revoke"
                tone="crit"
                loading={revoking === 'bulk'}
                onConfirm={performBulkRevoke}
                onCancel={() => setConfirmRevoke(null)}
            />
        </div>
    );
};

/* ─── Sign key ─── */
/// <summary>
/// The SSH tab of Request Certificate: the SSH CA key to sign with, the Sign key form, and the
/// signed certificate once, with copy and download and where to save it.
/// </summary>
const SshSign: React.FC = () => {
    const [caKeys, setCaKeys] = useState<any[]>([]);
    const [signingProfiles, setSigningProfiles] = useState<any[]>([]);
    const [certProfiles, setCertProfiles] = useState<any[]>([]);
    const [requestProfiles, setRequestProfiles] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [selectedCaKeyId, setSelectedCaKeyId] = useState<string>('');
    const [signResult, setSignResult] = useState<SshSignResult | null>(null);
    const [copied, setCopied] = useState(false);
    /** Bumped after each signature, so the form starts empty for the next one. */
    const [formRound, setFormRound] = useState(0);

    useEffect(() => {
        let cancelled = false;
        Promise.all([
            apiGet<any>('/api/v1/admin/ssh/ca-keys'),
            apiGet<any>('/api/v1/admin/ssh/profiles/signing'),
            apiGet<any>('/api/v1/admin/ssh/profiles/cert'),
            apiGet<any>('/api/v1/admin/ssh/profiles/request'),
        ]).then(([keyData, signingData, certProfData, reqProfData]) => {
                if (cancelled) return;
                setCaKeys(Array.isArray(keyData) ? keyData : (keyData.items || keyData.keys || []));
                setSigningProfiles(Array.isArray(signingData) ? signingData : []);
                setCertProfiles(Array.isArray(certProfData) ? certProfData : []);
                setRequestProfiles(Array.isArray(reqProfData) ? reqProfData : []);
                setLoading(false);
            })
            .catch((err) => {
                if (!cancelled) {
                    setError(errorNotice(err, 'Failed to load SSH data'));
                    setLoading(false);
                }
            });
        return () => { cancelled = true; };
    }, []);

    const enabledKeys = caKeys.filter((k) => k.isEnabled !== false);

    // Auto-select the first enabled CA key the signer can sign with, when there is one.
    useEffect(() => {
        if (enabledKeys.length > 0 && !selectedCaKeyId) {
            setSelectedCaKeyId((enabledKeys.find((k) => !signBlockedReason(k)) ?? enabledKeys[0]).id);
        }
    }, [caKeys]); // eslint-disable-line react-hooks/exhaustive-deps

    const selectedCaKey = enabledKeys.find((k) => k.id === selectedCaKeyId);
    const signBlocked = selectedCaKey ? signBlockedReason(selectedCaKey) : null;
    const signerStateUnknown = !!selectedCaKey && sshSignerState(selectedCaKey) === 'unknown';

    const copyResult = async () => {
        if (signResult && await copyText(signResult.signedCertificate)) {
            setCopied(true);
            window.setTimeout(() => setCopied(false), 1500);
        }
    };

    const keyFile = defaultKeyFile(signResult?.publicKey);

    if (loading) return <p className="text-sm text-ink-muted">Loading…</p>;
    if (error) return <InlineNotice notice={error} />;

    return (
        <div className="space-y-4">
            {/* CA Key Selector */}
            <div className="flex items-center gap-3">
                <label htmlFor="ssh-ca-key" className="text-sm text-ink-muted font-medium">CA Key:</label>
                <select
                    id="ssh-ca-key"
                    value={selectedCaKeyId}
                    onChange={(e) => { setSelectedCaKeyId(e.target.value); setSignResult(null); }}
                    className="px-3 py-2 bg-raised border border-line-strong rounded text-sm text-ink focus:outline-none focus:border-accent"
                >
                    {enabledKeys.length === 0 && <option value="">No CA keys available</option>}
                    {enabledKeys.map((k: any) => (
                        <option key={k.id} value={k.id}>{k.name || k.id} ({k.keyType || k.algorithm}){signBlockedReason(k) ? `, ${sshKeyCustody(k).badge.label.toLowerCase()}` : ''}</option>
                    ))}
                </select>
            </div>

            {enabledKeys.length === 0 && (
                <p className="text-sm text-ink max-w-3xl">
                    There is no enabled SSH CA key to sign with. SSH CA keys are generated on <Link to={SSH_CA_KEYS_PATH} className="text-accent-ink hover:underline">Authorities, on the SSH tab</Link>.
                </p>
            )}

            {signBlocked && selectedCaKey && (
                <div role="status" className="bg-warn-soft border border-warn/40 rounded-md px-3 py-2 space-y-1 max-w-4xl">
                    <p className="text-sm font-semibold text-warn">Signing is unavailable with "{selectedCaKey.name || selectedCaKey.id}"</p>
                    <p className="text-sm text-ink break-words">{signBlocked}</p>
                    <p className="text-xs text-ink">
                        <Link to={sshCaKeyPath(selectedCaKey.id)} className="text-accent-ink hover:underline">Open the key's page</Link> for what to do. Certificates it has already issued are listed under All Certificates, on the SSH tab, and can still be revoked.
                    </p>
                </div>
            )}
            {signerStateUnknown && (
                <FieldHint tone="warn">The signer could not be asked whether it holds this key. Signing is refused while the signer is locked or out of reach.</FieldHint>
            )}

            {signResult && (
                <div className="bg-raised border border-line border-l-4 border-l-ok rounded-lg p-4 space-y-3">
                    <div className="flex items-center justify-between gap-2 flex-wrap">
                        <span className="text-ok font-semibold text-sm">Certificate signed</span>
                        <button type="button" onClick={() => setSignResult(null)} className="text-xs text-ink-muted hover:text-ink transition-colors">Dismiss</button>
                    </div>
                    <div className="max-w-3xl">
                        <DetailField label="Name in host logs" value={signResult.keyId} mono />
                        <DetailField label="Serial" value={String(signResult.serialNumber)} mono />
                        <DetailField label="Valid" value={`${dayTimeText(signResult.validAfter)} to ${dayTimeText(signResult.validBefore)}`} />
                    </div>
                    {signResult.signedCertificate && (
                        <>
                            <textarea
                                readOnly
                                rows={3}
                                aria-label="Signed certificate"
                                value={signResult.signedCertificate}
                                className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-ink data-mono focus:outline-none"
                            />
                            <div className="flex flex-wrap gap-2">
                                <button type="button" onClick={copyResult} className={actionButton}>{copied ? 'Copied' : 'Copy'}</button>
                                <button type="button" onClick={() => downloadText(signResult.signedCertificate, `${keyFile}-cert.pub`)} className={actionButton}>
                                    Download certificate
                                </button>
                                <Link to={sshCertificatePath({ id: signResult.id, sshCaKeyId: selectedCaKeyId })} className={actionButton}>Open the certificate's page</Link>
                            </div>
                        </>
                    )}
                    <p className="text-xs text-ink-muted max-w-3xl">
                        It belongs beside the private key it certifies, under that key file's name with <code className="text-accent-ink">-cert.pub</code> added: for a key in <code className="text-accent-ink">~/.ssh/{keyFile}</code>, save it as <code className="text-accent-ink">~/.ssh/{keyFile}-cert.pub</code>.
                        {signResult.forUser && ` ${signResult.forUser} also finds it under My Certificates, on the SSH tab, in their own portal, and can download it there.`}
                    </p>
                </div>
            )}

            {selectedCaKey && (
                <SshSignKeyForm
                    key={`${selectedCaKey.id}:${formRound}`}
                    caKey={selectedCaKey}
                    signBlocked={signBlocked}
                    signingProfiles={signingProfiles}
                    certProfiles={certProfiles}
                    requestProfiles={requestProfiles}
                    onSigned={(result) => { setSignResult(result); setCopied(false); setFormRound((r) => r + 1); }}
                    onCancel={() => setFormRound((r) => r + 1)}
                />
            )}
        </div>
    );
};

/* ─── The SSH tabs ─── */
/// <summary>
/// The SSH tab of Authorities: the SSH CA keys, the form for a new one, and the notice that keys
/// were plaintext files on the node. SSH CAs belong to the instance, so under a scope confined
/// to a space the tab says so and shows nothing else.
/// </summary>
/// <remarks>The scope is an input so that the tab can list a space's SSH CAs once an SSH CA can be assigned to spaces.</remarks>
export const SshCaKeysTab: React.FC<{ scope: Scope }> = ({ scope }) => {
    const [refreshTrigger, setRefreshTrigger] = useState(0);
    const sentence = sshScopeSentence(scope);
    if (sentence) return <SshScopeSentence text={sentence} />;
    return (
        <div className="space-y-4 sm:space-y-6">
            <SshPlaintextNoticeBanner refreshTrigger={refreshTrigger} />
            <SshCaKeys refreshTrigger={refreshTrigger} onRefresh={() => setRefreshTrigger((t) => t + 1)} />
        </div>
    );
};

/// <summary>
/// The SSH tab of All Certificates. Under a scope confined to a space it says that SSH CAs belong
/// to the instance and shows nothing else.
/// </summary>
/// <remarks>The scope is an input so that the tab can list a space's SSH certificates once an SSH CA can be assigned to spaces.</remarks>
export const SshCertificatesTab: React.FC<{ scope: Scope }> = ({ scope }) => {
    const sentence = sshScopeSentence(scope);
    return sentence ? <SshScopeSentence text={sentence} /> : <SshCertificateList />;
};

/// <summary>
/// The SSH tab of Request Certificate. Under a scope confined to a space it says that SSH CAs
/// belong to the instance and shows nothing else.
/// </summary>
/// <remarks>The scope is an input so that the tab can offer a space's SSH CAs once an SSH CA can be assigned to spaces.</remarks>
export const SshSignTab: React.FC<{ scope: Scope }> = ({ scope }) => {
    const sentence = sshScopeSentence(scope);
    return sentence ? <SshScopeSentence text={sentence} /> : <SshSign />;
};
