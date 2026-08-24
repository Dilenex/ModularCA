import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { apiPost, apiBlob, apiPostWithMfa, apiGetAllPages } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '../context/ToastContext';
import StatusBadge from '../components/cards/StatusBadge';
import DetailField from '../components/cards/DetailField';
import { DataTable, type DataTableColumn } from '../components/DataTable';
import { StepUpOps } from '@shared/generated';

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
    const [error, setError] = useState<string | null>(null);
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
            .catch((err) => setError(err.message))
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

    const inputClass = 'px-3 py-2 bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500';

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
            render: (c) => <span className="text-sm text-gray-900 dark:text-white truncate">{c.subjectDN || c.serialNumber}</span>,
        },
        {
            key: 'algorithm', header: 'Algorithm', defaultWidth: 150,
            exportValue: (c) => `${c.keyAlgorithm || ''} ${c.keySize || ''}`.trim(),
            render: (c) => <span className="text-xs text-gray-600 dark:text-gray-400">{c.keyAlgorithm || '-'} {c.keySize || ''}</span>,
        },
        {
            key: 'expires', header: 'Expires', defaultWidth: 210, minWidth: 120, truncate: false,
            exportValue: (c) => formatDate(c.notAfter),
            render: (c) => {
                const s = certStatus(c);
                const days = daysUntilExpiry(c.notAfter);
                return (
                    <span className="text-xs text-gray-600 dark:text-gray-400 flex items-center gap-2 whitespace-nowrap">
                        {formatDate(c.notAfter)}
                        {s === 'active' && days <= 30 && <span className="text-yellow-700 dark:text-yellow-400">{days}d left</span>}
                    </span>
                );
            },
        },
    ];

    const renderExpanded = (cert: any) => {
        const serial = cert.serialNumber;
        const status = certStatus(cert);
        const hasPrivateKey = cert.encryptedPrivateKey && cert.encryptedPrivateKey.length > 0;
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
                        <span className="text-xs font-semibold text-gray-600 dark:text-gray-400">SANs</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                            {cert.subjectAlternativeNames.map((san: string, i: number) => (
                                <span key={i} className="px-2 py-0.5 text-xs bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded">{san}</span>
                            ))}
                        </div>
                    </div>
                )}

                {status === 'revoked' && (
                    <div className="bg-red-50 dark:bg-red-900/20 border border-red-300 dark:border-red-800 rounded p-2">
                        <span className="text-xs text-red-800 dark:text-red-400">Revoked{cert.revocationReason ? `: ${cert.revocationReason}` : ''}</span>
                    </div>
                )}

                {/* Action buttons */}
                <div className="flex flex-wrap gap-2 pt-2 border-t border-gray-300 dark:border-gray-700">
                    <button onClick={() => handleDownloadPem(cert)}
                        className="px-3 py-1.5 text-xs bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors">
                        PEM
                    </button>
                    <button onClick={() => handleDownloadDer(cert)}
                        className="px-3 py-1.5 text-xs bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors">
                        DER
                    </button>
                    <button onClick={() => handleDownloadChain(cert)}
                        className="px-3 py-1.5 text-xs bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors">
                        Full Chain
                    </button>
                    {hasPrivateKey && (
                        <button onClick={() => handleExportPfx(cert)}
                            className="px-3 py-1.5 text-xs bg-purple-600 text-white rounded hover:bg-purple-700 transition-colors">
                            Export PFX
                        </button>
                    )}
                    {status !== 'revoked' && (
                        <button onClick={() => handleRenew(cert)}
                            className="px-3 py-1.5 text-xs bg-emerald-600 text-white rounded hover:bg-emerald-700 transition-colors">
                            Renew
                        </button>
                    )}
                    {status === 'active' && (
                        <button onClick={() => handleRevoke(cert)}
                            className="px-3 py-1.5 text-xs bg-red-600 text-white rounded hover:bg-red-700 transition-colors ml-auto">
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
                <h1 className="text-2xl font-bold text-gray-900 dark:text-white">My Certificates</h1>
                <Link to="/request" className="px-4 py-2 text-sm font-medium bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors">
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
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={() => !pfxLoading && setPfxTarget(null)}>
                    <div className="bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-xl shadow-2xl p-6 w-full max-w-sm mx-4 space-y-4" onClick={(e) => e.stopPropagation()}>
                        <h3 className="text-lg font-bold text-gray-900 dark:text-white">Export PFX</h3>
                        <p className="text-sm text-gray-600 dark:text-gray-400">Enter a password to protect the PFX file:</p>
                        <input type="password" value={pfxPassword} onChange={e => setPfxPassword(e.target.value)}
                            autoComplete="new-password" placeholder="PFX password" autoFocus
                            className="w-full px-3 py-2 bg-gray-100 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500" />
                        <div className="flex justify-end gap-3">
                            <button onClick={() => setPfxTarget(null)} disabled={pfxLoading}
                                className="px-4 py-2 text-sm bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors disabled:opacity-50">
                                Cancel
                            </button>
                            <button onClick={handlePfxConfirm} disabled={!pfxPassword || pfxLoading}
                                className="px-4 py-2 text-sm bg-purple-600 text-white rounded hover:bg-purple-700 disabled:opacity-40 transition-colors">
                                {pfxLoading ? 'Exporting...' : 'Export'}
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Revocation Modal */}
            {revokeTarget && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={() => !revokeLoading && setRevokeTarget(null)}>
                    <div className="bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-xl shadow-2xl p-6 w-full max-w-sm mx-4 space-y-4" onClick={(e) => e.stopPropagation()}>
                        <h3 className="text-lg font-bold text-gray-900 dark:text-white">Revoke Certificate</h3>
                        <div className="bg-red-50 dark:bg-red-900/20 border border-red-300 dark:border-red-800 rounded p-3">
                            <p className="text-xs text-red-800 dark:text-red-400">
                                Revocation is <span className="font-semibold">permanent</span> and cannot be undone. The
                                certificate will stop being trusted once the next CRL is published.
                            </p>
                        </div>
                        <div className="text-sm text-gray-600 dark:text-gray-400 break-words">
                            <span className="font-semibold text-gray-700 dark:text-gray-300">Subject:</span> {revokeTarget.subjectDN || revokeTarget.serialNumber}
                        </div>
                        <div>
                            <label className="block text-xs font-semibold text-gray-600 dark:text-gray-400 mb-1">Reason</label>
                            <select value={revokeReason} onChange={(e) => setRevokeReason(e.target.value)} disabled={revokeLoading}
                                className="w-full px-3 py-2 bg-gray-100 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500">
                                {SELF_REVOKE_REASONS.map((r) => (
                                    <option key={r.value} value={r.value}>{r.label}</option>
                                ))}
                            </select>
                        </div>
                        <div className="flex justify-end gap-3">
                            <button onClick={() => setRevokeTarget(null)} disabled={revokeLoading}
                                className="px-4 py-2 text-sm bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors disabled:opacity-50">
                                Cancel
                            </button>
                            <button onClick={handleRevokeConfirm} disabled={revokeLoading}
                                className="px-4 py-2 text-sm bg-red-600 text-white rounded hover:bg-red-700 disabled:opacity-40 transition-colors">
                                {revokeLoading ? 'Revoking...' : 'Revoke'}
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Renewal Modal */}
            {renewTarget && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={() => !renewLoading && setRenewTarget(null)}>
                    <div className="bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-xl shadow-2xl p-6 w-full max-w-sm mx-4 space-y-4" onClick={(e) => e.stopPropagation()}>
                        <h3 className="text-lg font-bold text-gray-900 dark:text-white">Renew Certificate</h3>
                        <p className="text-sm text-gray-600 dark:text-gray-400">
                            This submits a new certificate request reusing the same subject, SANs, and profile as the
                            existing certificate. Depending on the profile, it may require administrator approval before
                            a new certificate is issued. The existing certificate is left unchanged.
                        </p>
                        <div className="text-sm text-gray-600 dark:text-gray-400 break-words">
                            <span className="font-semibold text-gray-700 dark:text-gray-300">Subject:</span> {renewTarget.subjectDN || renewTarget.serialNumber}
                        </div>
                        <div className="flex justify-end gap-3">
                            <button onClick={() => setRenewTarget(null)} disabled={renewLoading}
                                className="px-4 py-2 text-sm bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors disabled:opacity-50">
                                Cancel
                            </button>
                            <button onClick={handleRenewConfirm} disabled={renewLoading}
                                className="px-4 py-2 text-sm bg-emerald-600 text-white rounded hover:bg-emerald-700 disabled:opacity-40 transition-colors">
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
