import React, { useState, useEffect } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { errorNotice } from '@shared-auth/api/notices';
import { useNavigate, Link } from 'react-router-dom';
import { apiPost, apiBlob, apiPostWithMfa, apiGetAllPages } from '../../api/client';
import { useStepUp } from '../../components/StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import { DataTable, type DataTableColumn } from '@shared/components/DataTable';
import { StepUpOps } from '@shared/generated';
import { inputClassNarrow as inputClass } from '@shared/components/forms';
import { RevocationReasonHint } from '../CertificateDetail';

// Revocation reasons a user may select when self-revoking an owned certificate. Must stay in
// sync with UserCertificateController.SelfRevokeAllowedReasons on the backend — CA-level reasons
// and the administrative hold state are intentionally excluded.
const SELF_REVOKE_REASONS: { value: string; label: string }[] = [
    { value: 'Unspecified', label: 'Unspecified' },
    { value: 'KeyCompromise', label: 'Key compromise' },
    { value: 'Superseded', label: 'Superseded (replaced)' },
    { value: 'AffiliationChanged', label: 'Affiliation changed' },
    { value: 'CessationOfOperation', label: 'Cessation of operation' },
    { value: 'PrivilegeWithdrawn', label: 'Privilege withdrawn' },
];

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function certStatus(cert: any): 'active' | 'revoked' | 'expired' {
    if (cert.revoked) return 'revoked';
    if (new Date(cert.notAfter) < new Date()) return 'expired';
    return 'active';
}

function statusBadgeType(s: string): 'active' | 'disabled' | 'pending' {
    if (s === 'active') return 'active';
    if (s === 'revoked') return 'disabled';
    return 'pending';
}

function daysUntilExpiry(notAfter: string): number {
    return Math.ceil((new Date(notAfter).getTime() - Date.now()) / (1000 * 60 * 60 * 24));
}

const MyCertificates: React.FC = () => {
    const navigate = useNavigate();
    const { showToast } = useToast();
    const { requireStepUp } = useStepUp();
    const [certificates, setCertificates] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [statusFilter, setStatusFilter] = useState<'all' | 'active' | 'revoked' | 'expired'>('all');

    // PFX export modal state
    const [pfxTarget, setPfxTarget] = useState<any | null>(null);
    const [pfxPassword, setPfxPassword] = useState('');
    const [pfxLoading, setPfxLoading] = useState(false);

    // Revocation modal state
    const [revokeTarget, setRevokeTarget] = useState<any | null>(null);
    const [revokeReason, setRevokeReason] = useState('Unspecified');
    const [revokeLoading, setRevokeLoading] = useState(false);

    // Renewal modal state
    const [renewTarget, setRenewTarget] = useState<any | null>(null);
    const [renewLoading, setRenewLoading] = useState(false);

    useEffect(() => {
        // Every page, not just the first: the endpoint pages at 25 by default and the table
        // below does its own client-side paging, so a plain apiGet capped the whole view at 25.
        apiGetAllPages<any>('/api/v1/user/certificates')
            .then(({ items }) => setCertificates(items))
            .catch((err) => setError(errorNotice(err, 'The request failed.')))
            .finally(() => setLoading(false));
    }, []);

    const downloadBlob = (data: BlobPart, filename: string, mimeType: string) => {
        const blob = new Blob([data], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
    };

    const getCertName = (cert: any) => {
        const cn = (cert.subjectDN || '').match(/CN=([^,]+)/)?.[1] || cert.serialNumber || 'cert';
        return cn.replace(/[^a-zA-Z0-9._-]/g, '_');
    };

    const handleDownloadPem = async (cert: any) => {
        try {
            const resp = await apiBlob(`/api/v1/user/certificates/${cert.serialNumber}/file`, {
                headers: { Accept: 'application/x-pem-file' },
            });
            const pem = await resp.text();
            downloadBlob(pem, `${getCertName(cert)}.pem`, 'application/x-pem-file');
        } catch (err: any) { showToast('error', err.message || 'Download failed'); }
    };

    const handleDownloadDer = async (cert: any) => {
        try {
            const resp = await apiBlob(`/api/v1/user/certificates/${cert.serialNumber}/file`, {
                headers: { Accept: 'application/pkix-cert' },
            });
            const blob = await resp.blob();
            downloadBlob(blob, `${getCertName(cert)}.cer`, 'application/pkix-cert');
        } catch (err: any) { showToast('error', err.message || 'Download failed'); }
    };

    const handleDownloadChain = async (cert: any) => {
        try {
            const resp = await apiBlob(`/api/v1/user/certificates/${cert.serialNumber}/chain`);
            const chainPem = await resp.text();
            downloadBlob(chainPem, `${getCertName(cert)}-fullchain.pem`, 'application/x-pem-file');
        } catch (err: any) { showToast('error', err.message || 'Download failed'); }
    };

    const handleExportPfx = (cert: any) => {
        setPfxTarget(cert);
        setPfxPassword('');
    };

    const handlePfxConfirm = async () => {
        if (!pfxTarget) return;
        setPfxLoading(true);
        try {
            const doExport = async (extraHeaders: Record<string, string> = {}) => {
                return apiBlob(`/api/v1/user/certificates/${pfxTarget.serialNumber}/export`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', ...extraHeaders },
                    body: JSON.stringify({ password: pfxPassword }),
                });
            };

            let resp: Response;
            try {
                resp = await doExport();
            } catch (err: any) {
                // Handle step-up MFA requirement
                if (err.requiresStepUp) {
                    const mfaToken = await requireStepUp(StepUpOps.ExportCert, pfxTarget.serialNumber);
                    resp = await doExport({ 'X-MFA-Token': mfaToken });
                } else {
                    throw err;
                }
            }

            const blob = await resp!.blob();
            downloadBlob(blob, `${getCertName(pfxTarget)}.pfx`, 'application/x-pkcs12');
            setPfxTarget(null);
        } catch (err: any) { showToast('error', err.message || 'PFX export failed'); }
        finally { setPfxLoading(false); }
    };

    const handleRevoke = (cert: any) => {
        setRevokeTarget(cert);
        setRevokeReason('Unspecified');
    };

    const handleRevokeConfirm = async () => {
        if (!revokeTarget) return;
        const serial = revokeTarget.serialNumber;
        setRevokeLoading(true);
        try {
            await apiPostWithMfa(
                `/api/v1/user/certificates/${serial}/revoke`,
                { reason: revokeReason },
                requireStepUp,
                StepUpOps.RevokeSelfCert,
                serial,
            );

            // Reflect the new state locally without a full refetch.
            setCertificates((prev) => prev.map((c) =>
                c.serialNumber === serial
                    ? { ...c, revoked: true, revocationReason: revokeReason }
                    : c));
            showToast('success', 'Certificate revoked.');
            setRevokeTarget(null);
        } catch (err: any) {
            if (err?.message === 'Step-up MFA cancelled') {
                // User backed out of the MFA prompt — leave the modal open, no error toast.
                return;
            }
            showToast('error', err.message || 'Revocation failed');
        } finally {
            setRevokeLoading(false);
        }
    };

    const handleRenew = (cert: any) => {
        setRenewTarget(cert);
    };

    const handleRenewConfirm = async () => {
        if (!renewTarget) return;
        const serial = renewTarget.serialNumber;
        setRenewLoading(true);
        try {
            await apiPost(`/api/v1/user/certificates/${serial}/renew`, {});
            showToast('success', 'Renewal request submitted.');
            setRenewTarget(null);
            // Take the user to Request Status so they can track the new pending request.
            navigate('/requests');
        } catch (err: any) {
            showToast('error', err.message || 'Renewal failed');
        } finally {
            setRenewLoading(false);
        }
    };

    const filtered = certificates.filter(cert => {
        if (statusFilter === 'all') return true;
        return certStatus(cert) === statusFilter;
    });


    const columns: DataTableColumn<any>[] = [
        {
            key: 'status', header: 'Status', defaultWidth: 110, truncate: false,
            exportValue: (c) => certStatus(c),
            render: (c) => {
                const s = certStatus(c);
                return <StatusBadge status={statusBadgeType(s)} label={s.charAt(0).toUpperCase() + s.slice(1)} />;
            },
        },
        {
            key: 'subject', header: 'Subject', defaultWidth: 280,
            exportValue: (c) => c.subjectDN || c.serialNumber,
            render: (c) => <span className="text-sm text-ink truncate">{c.subjectDN || c.serialNumber}</span>,
        },
        {
            key: 'algorithm', header: 'Algorithm', defaultWidth: 150,
            exportValue: (c) => `${c.keyAlgorithm || ''} ${c.keySize || ''}`.trim(),
            render: (c) => <span className="text-xs text-ink-muted">{c.keyAlgorithm || '-'} {c.keySize || ''}</span>,
        },
        {
            key: 'expires', header: 'Expires', defaultWidth: 210, minWidth: 120, truncate: false,
            exportValue: (c) => formatDate(c.notAfter),
            render: (c) => {
                const s = certStatus(c);
                const days = daysUntilExpiry(c.notAfter);
                return (
                    <span className="text-xs text-ink-muted flex items-center gap-2 whitespace-nowrap">
                        {formatDate(c.notAfter)}
                        {s === 'active' && days <= 30 && <span className="text-warn">{days}d left</span>}
                    </span>
                );
            },
        },
    ];

    const renderExpanded = (cert: any) => {
        const serial = cert.serialNumber;
        const status = certStatus(cert);
        // The API reports this as a boolean and never sends key material to the browser. The
        // old check looked for `encryptedPrivateKey` in the response, which no read path
        // populates, so Export PFX was hidden for every certificate -- including ones the CA
        // holds an exportable key for.
        const hasPrivateKey = cert.hasPrivateKey === true;
        return (
            <div className="space-y-3">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                    <DetailField label="Serial Number" value={serial} mono />
                    <DetailField label="Subject" value={cert.subjectDN} />
                    <DetailField label="Issuer" value={cert.issuer} />
                    <DetailField label="Not Before" value={formatDate(cert.notBefore)} />
                    <DetailField label="Not After" value={formatDate(cert.notAfter)} />
                    <DetailField label="Algorithm" value={`${cert.keyAlgorithm || '-'} ${cert.keySize || ''}`} />
                    <DetailField label="Signature" value={cert.signatureAlgorithm || '-'} />
                </div>

                {cert.subjectAlternativeNames?.length > 0 && (
                    <div>
                        <span className="text-xs font-semibold text-ink-muted">SANs</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                            {cert.subjectAlternativeNames.map((san: string, i: number) => (
                                <span key={i} className="px-2 py-0.5 text-xs bg-sunken text-ink rounded">{san}</span>
                            ))}
                        </div>
                    </div>
                )}

                {status === 'revoked' && (
                    <div className="bg-crit-soft border border-crit/40 rounded p-2">
                        <span className="text-xs text-crit">Revoked{cert.revocationReason ? `: ${cert.revocationReason}` : ''}</span>
                    </div>
                )}

                {/* Action buttons */}
                <div className="flex flex-wrap gap-2 pt-2 border-t border-line">
                    <button onClick={() => handleDownloadPem(cert)}
                        className="px-3 py-1.5 text-xs bg-accent text-on-accent rounded hover:bg-accent-hover transition-colors">
                        PEM
                    </button>
                    <button onClick={() => handleDownloadDer(cert)}
                        className="px-3 py-1.5 text-xs bg-sunken text-ink rounded hover:bg-hover transition-colors">
                        DER
                    </button>
                    <button onClick={() => handleDownloadChain(cert)}
                        className="px-3 py-1.5 text-xs bg-sunken text-ink rounded hover:bg-hover transition-colors">
                        Full Chain
                    </button>
                    {hasPrivateKey && (
                        <button onClick={() => handleExportPfx(cert)}
                            className="px-3 py-1.5 text-xs bg-accent text-on-accent rounded hover:bg-accent-hover transition-colors">
                            Export PFX
                        </button>
                    )}
                    {status !== 'revoked' && (
                        <button onClick={() => handleRenew(cert)}
                            className="px-3 py-1.5 text-xs bg-ok text-on-accent rounded hover:bg-ok-hover transition-colors">
                            Renew
                        </button>
                    )}
                    {status === 'active' && (
                        <button onClick={() => handleRevoke(cert)}
                            className="px-3 py-1.5 text-xs bg-crit text-on-accent rounded hover:bg-crit-hover transition-colors ml-auto">
                            Revoke
                        </button>
                    )}
                </div>
            </div>
        );
    };

    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <div className="flex items-center justify-between">
                <h1 className="text-xl font-semibold text-ink">My Certificates</h1>
                <Link to="/request" className="px-4 py-2 text-sm font-medium bg-accent text-on-accent rounded hover:bg-accent-hover transition-colors">
                    Request New
                </Link>
            </div>

            {/* Filter */}
            <div>
                <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value as any)} className={inputClass}>
                    <option value="all">All Certificates</option>
                    <option value="active">Active</option>
                    <option value="expired">Expired</option>
                    <option value="revoked">Revoked</option>
                </select>
            </div>

            <DataTable<any>
                tableId="my-certificates"
                title="Certificates"
                rows={filtered}
                rowKey={(c) => c.serialNumber}
                loading={loading}
                error={error}
                empty="No certificates match this filter."
                columns={columns}
                exportFileName="my-certificates"
                renderExpanded={renderExpanded}
            />

            {/* PFX Export Modal */}
            {pfxTarget && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-scrim" onClick={() => !pfxLoading && setPfxTarget(null)}>
                    <div className="bg-raised border border-line rounded-xl shadow-2xl p-6 w-full max-w-sm mx-4 space-y-4" onClick={(e) => e.stopPropagation()}>
                        <h3 className="text-lg font-bold text-ink">Export PFX</h3>
                        <p className="text-sm text-ink-muted">Enter a password to protect the PFX file:</p>
                        <input type="password" value={pfxPassword} onChange={e => setPfxPassword(e.target.value)}
                            autoComplete="new-password" placeholder="PFX password" autoFocus
                            className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-sm text-ink focus:outline-none focus:border-accent" />
                        <div className="flex justify-end gap-3">
                            <button onClick={() => setPfxTarget(null)} disabled={pfxLoading}
                                className="px-4 py-2 text-sm bg-sunken text-ink rounded hover:bg-hover transition-colors disabled:opacity-50">
                                Cancel
                            </button>
                            <button onClick={handlePfxConfirm} disabled={!pfxPassword || pfxLoading}
                                className="px-4 py-2 text-sm bg-accent text-on-accent rounded hover:bg-accent-hover disabled:opacity-40 transition-colors">
                                {pfxLoading ? 'Exporting...' : 'Export'}
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Revocation Modal */}
            {revokeTarget && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-scrim" onClick={() => !revokeLoading && setRevokeTarget(null)}>
                    <div className="bg-raised border border-line rounded-xl shadow-2xl p-6 w-full max-w-sm mx-4 space-y-4" onClick={(e) => e.stopPropagation()}>
                        <h3 className="text-lg font-bold text-ink">Revoke Certificate</h3>
                        <div className="bg-crit-soft border border-crit/40 rounded p-3">
                            <p className="text-xs text-crit">
                                Revocation is <span className="font-semibold">permanent</span> and cannot be undone. The
                                certificate will stop being trusted once the next CRL is published.
                            </p>
                        </div>
                        <div className="text-sm text-ink-muted break-words">
                            <span className="font-semibold text-ink">Subject:</span> {revokeTarget.subjectDN || revokeTarget.serialNumber}
                        </div>
                        <div>
                            <label className="block text-xs font-semibold text-ink-muted mb-1">Reason</label>
                            <select value={revokeReason} onChange={(e) => setRevokeReason(e.target.value)} disabled={revokeLoading}
                                className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-sm text-ink focus:outline-none focus:border-accent">
                                {SELF_REVOKE_REASONS.map((r) => (
                                    <option key={r.value} value={r.value}>{r.label}</option>
                                ))}
                            </select>
                            <RevocationReasonHint reason={revokeReason} />
                        </div>
                        <div className="flex justify-end gap-3">
                            <button onClick={() => setRevokeTarget(null)} disabled={revokeLoading}
                                className="px-4 py-2 text-sm bg-sunken text-ink rounded hover:bg-hover transition-colors disabled:opacity-50">
                                Cancel
                            </button>
                            <button onClick={handleRevokeConfirm} disabled={revokeLoading}
                                className="px-4 py-2 text-sm bg-crit text-on-accent rounded hover:bg-crit-hover disabled:opacity-40 transition-colors">
                                {revokeLoading ? 'Revoking...' : 'Revoke'}
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Renewal Modal */}
            {renewTarget && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-scrim" onClick={() => !renewLoading && setRenewTarget(null)}>
                    <div className="bg-raised border border-line rounded-xl shadow-2xl p-6 w-full max-w-sm mx-4 space-y-4" onClick={(e) => e.stopPropagation()}>
                        <h3 className="text-lg font-bold text-ink">Renew Certificate</h3>
                        <p className="text-sm text-ink-muted">
                            This submits a new certificate request reusing the same subject, SANs, and profile as the
                            existing certificate. Depending on the profile, it may require administrator approval before
                            a new certificate is issued. The existing certificate is left unchanged.
                        </p>
                        <div className="text-sm text-ink-muted break-words">
                            <span className="font-semibold text-ink">Subject:</span> {renewTarget.subjectDN || renewTarget.serialNumber}
                        </div>
                        <div className="flex justify-end gap-3">
                            <button onClick={() => setRenewTarget(null)} disabled={renewLoading}
                                className="px-4 py-2 text-sm bg-sunken text-ink rounded hover:bg-hover transition-colors disabled:opacity-50">
                                Cancel
                            </button>
                            <button onClick={handleRenewConfirm} disabled={renewLoading}
                                className="px-4 py-2 text-sm bg-ok text-on-accent rounded hover:bg-ok-hover disabled:opacity-40 transition-colors">
                                {renewLoading ? 'Submitting...' : 'Submit Renewal'}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default MyCertificates;
