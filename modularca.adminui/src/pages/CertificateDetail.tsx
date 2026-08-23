import React, { useEffect, useState, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { apiGet, apiPostWithMfa, apiBlob } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '../context/ToastContext';
import StatusBadge from '../components/cards/StatusBadge';
import DetailField from '../components/cards/DetailField';
import CertificateReissueModal from '../components/CertificateReissueModal';
import { DetailPage, DetailSection } from '../components/DetailPage';
import { StepUpOps } from '@shared/generated';

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}
function certStatus(cert: any): 'active' | 'revoked' | 'expired' {
    if (cert.revoked) return 'revoked';
    if (new Date(cert.notAfter) < new Date()) return 'expired';
    return 'active';
}
function parseThumbprints(raw: any): { label: string; value: string }[] | null {
    if (!raw) return null;
    try { const obj = typeof raw === 'string' ? JSON.parse(raw) : raw; if (typeof obj === 'object' && obj !== null) return Object.entries(obj).map(([k, v]) => ({ label: k, value: String(v) })); } catch { /* not JSON */ }
    return null;
}
function parseSans(raw: any): string[] | null {
    if (!raw) return null;
    if (Array.isArray(raw)) return raw;
    try { const parsed = JSON.parse(raw); if (Array.isArray(parsed)) return parsed; } catch { /* not JSON */ }
    return null;
}
function getCertName(cert: any) {
    const cn = (cert.subjectDN || '').match(/CN=([^,]+)/)?.[1] || cert.serialNumber || 'cert';
    return cn.replace(/[^a-zA-Z0-9._-]/g, '_');
}
function downloadBlob(data: BlobPart, filename: string, mimeType: string) {
    const blob = new Blob([data], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
}

export const REVOCATION_REASONS: { value: string; label: string }[] = [
    { value: 'Unspecified', label: 'Unspecified' },
    { value: 'KeyCompromise', label: 'Key Compromise' },
    { value: 'CACompromise', label: 'CA Compromise' },
    { value: 'AffiliationChanged', label: 'Affiliation Changed' },
    { value: 'Superseded', label: 'Superseded' },
    { value: 'CessationOfOperation', label: 'Cessation of Operation' },
    { value: 'CertificateHold', label: 'Certificate Hold' },
    { value: 'PrivilegeWithdrawn', label: 'Privilege Withdrawn' },
];

const actBtn = 'px-3 py-1.5 text-xs bg-blue-50 dark:bg-blue-900/50 text-blue-800 dark:text-blue-300 border border-blue-300 dark:border-blue-700 rounded hover:bg-blue-900 transition-colors';

/// <summary>
/// Read-only detail page for a single certificate (fetched by serial). Shows identity, validity,
/// thumbprints, SANs and on-demand extensions; revoke / reissue / downloads live in the action bar.
/// </summary>
const CertificateDetail: React.FC = () => {
    const { serial } = useParams<{ serial: string }>();
    const navigate = useNavigate();
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();

    const [cert, setCert] = useState<any | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [refresh, setRefresh] = useState(0);

    const [ext, setExt] = useState<any | null>(null);
    const [extLoading, setExtLoading] = useState(false);
    const [extError, setExtError] = useState<string | null>(null);
    const [extVisible, setExtVisible] = useState(false);

    const [revokeOpen, setRevokeOpen] = useState(false);
    const [revokeReason, setRevokeReason] = useState('Unspecified');
    const [revokeLoading, setRevokeLoading] = useState(false);
    const [revokeError, setRevokeError] = useState<string | null>(null);

    const [reissueOpen, setReissueOpen] = useState(false);

    // Per-certificate ACL (supplementary grants on top of RBAC).
    const [acl, setAcl] = useState<{ entries: any[]; requestorUserId: string | null; rbac?: any } | null>(null);
    const [aclLoading, setAclLoading] = useState(false);
    const [allUsers, setAllUsers] = useState<any[]>([]);
    const [addUserId, setAddUserId] = useState('');
    const [addLevel, setAddLevel] = useState<'View' | 'Manage'>('View');
    const [aclBusy, setAclBusy] = useState(false);

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError(null);
        apiGet<any>(`/api/v1/admin/certificates/${serial}`)
            .then((data) => { if (!cancelled) { setCert(data); setLoading(false); } })
            .catch((err) => { if (!cancelled) { setError(err.message || 'Failed to load certificate'); setLoading(false); } });
        return () => { cancelled = true; };
    }, [serial, refresh]);

    const loadAcl = useCallback(() => {
        setAclLoading(true);
        apiGet<any>(`/api/v1/admin/manage/cert-permissions/serial/${serial}`)
            .then((d) => setAcl({ entries: d.entries || [], requestorUserId: d.requestorUserId || null, rbac: d.rbac || null }))
            .catch(() => setAcl({ entries: [], requestorUserId: null, rbac: null }))
            .finally(() => setAclLoading(false));
    }, [serial]);

    useEffect(() => {
        loadAcl();
        apiGet<any>('/api/v1/admin/users').then((d) => setAllUsers(Array.isArray(d) ? d : (d.items || d.users || []))).catch(() => {});
    }, [loadAcl]);

    // ACL changes are step-up gated (granting Manage confers revoke/reissue rights).
    const setAccess = async (userId: string, level: 'View' | 'Manage') => {
        setAclBusy(true);
        try {
            await apiPostWithMfa(`/api/v1/admin/manage/cert-permissions/serial/${serial}/set`, { userId, accessLevel: level }, requireStepUp, StepUpOps.UpdateCertAcl, serial!);
            loadAcl();
        } catch (err: any) { if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to set access'); }
        finally { setAclBusy(false); }
    };
    const revokeAccess = async (userId: string) => {
        setAclBusy(true);
        try {
            await apiPostWithMfa(`/api/v1/admin/manage/cert-permissions/serial/${serial}/revoke-user`, { userId }, requireStepUp, StepUpOps.UpdateCertAcl, serial!);
            loadAcl();
        } catch (err: any) { if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to remove access'); }
        finally { setAclBusy(false); }
    };
    const addAccess = async () => {
        if (!addUserId) return;
        await setAccess(addUserId, addLevel);
        setAddUserId(''); setAddLevel('View');
    };

    const toggleExtensions = async () => {
        if (extVisible) { setExtVisible(false); return; }
        setExtVisible(true);
        if (ext) return;
        setExtLoading(true); setExtError(null);
        try { setExt(await apiGet<any>(`/api/v1/admin/certificates/${serial}/extensions`)); }
        catch (err: any) { setExtError(err.message || 'Failed to load extensions'); }
        finally { setExtLoading(false); }
    };

    const handleDownloadPem = async () => {
        try {
            const resp = await apiBlob(`/api/v1/admin/certificates/${serial}/file`, { headers: { Accept: 'application/x-pem-file' } });
            downloadBlob(await resp.text(), `${getCertName(cert)}.pem`, 'application/x-pem-file');
        } catch (err: any) { showToast('error', err.message || 'Download failed'); }
    };
    const handleDownloadDer = async () => {
        try {
            const resp = await apiBlob(`/api/v1/admin/certificates/${serial}/file`, { headers: { Accept: 'application/pkix-cert' } });
            downloadBlob(await resp.blob(), `${getCertName(cert)}.crt`, 'application/pkix-cert');
        } catch (err: any) { showToast('error', err.message || 'Download failed'); }
    };
    const handleDownloadChain = async () => {
        try {
            const resp = await apiBlob(`/api/v1/user/certificates/${serial}/chain`);
            downloadBlob(await resp.text(), `${getCertName(cert)}-fullchain.pem`, 'application/x-pem-file');
        } catch (err: any) { showToast('error', err.message || 'Download failed'); }
    };
    const handleCopySerial = () => navigator.clipboard.writeText(cert?.serialNumber || '').then(() => showToast('success', 'Serial copied')).catch(() => {});

    const handleRevokeConfirm = async () => {
        if (!cert) return;
        setRevokeLoading(true); setRevokeError(null);
        try {
            // The revoke endpoints key off the BODY (serialNumber), not the route param — the page is
            // loaded by serial, so revoke by serial. CA certs use the revoke-ca step-up op.
            const op = cert.isCA ? 'revoke-ca' : 'revoke-cert';
            await apiPostWithMfa(`/api/v1/admin/certificates/serial/${serial}/revoke`, { serialNumber: serial, reason: revokeReason }, requireStepUp, op, serial!);
            setRevokeOpen(false);
            setRefresh((r) => r + 1);
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') setRevokeError(err.message || 'Revocation failed');
        } finally {
            setRevokeLoading(false);
        }
    };

    if (loading) return <div className="p-6 text-sm text-gray-600 dark:text-gray-400">Loading…</div>;
    if (error) return (
        <div className="p-6 space-y-3">
            <p className="text-sm text-red-800 dark:text-red-400">{error}</p>
            <button onClick={() => navigate('/certificates')} className="px-3 py-1.5 text-sm bg-gray-200 dark:bg-gray-700 rounded">Back to Certificates</button>
        </div>
    );
    if (!cert) return (
        <div className="p-6 space-y-3">
            <p className="text-sm text-gray-600 dark:text-gray-400">Certificate not found.</p>
            <button onClick={() => navigate('/certificates')} className="px-3 py-1.5 text-sm bg-gray-200 dark:bg-gray-700 rounded">Back to Certificates</button>
        </div>
    );

    const status = certStatus(cert);
    const thumbprints = parseThumbprints(cert.thumbprints);
    const sans = parseSans(cert.subjectAlternativeNames);
    const cn = (cert.subjectDN || '').match(/CN=([^,]+)/)?.[1] || cert.serialNumber;
    const reissueTarget = {
        id: cert.certificateId, serialNumber: cert.serialNumber, subjectDN: cert.subjectDN,
        sans: (parseSans(cert.subjectAlternativeNames) ?? parseSans(cert.subjectAlternativeNamesJson)) ?? undefined,
        notBefore: cert.notBefore, notAfter: cert.notAfter,
    };

    return (
        <DetailPage
            breadcrumbs={[{ label: 'Certificates', to: '/certificates' }, { label: cn }]}
            title={cn}
            status={<StatusBadge status={status} />}
            subtitle={<span className="font-mono">{cert.serialNumber}</span>}
            backTo="/certificates"
            actions={
                <div className="flex items-center gap-2 flex-wrap">
                    {status === 'active' && <button onClick={() => { setRevokeReason('Unspecified'); setRevokeError(null); setRevokeOpen(true); }} className="px-3 py-1.5 text-xs bg-red-50 dark:bg-red-900/50 text-red-800 dark:text-red-300 border border-red-300 dark:border-red-700 rounded hover:bg-red-900 transition-colors">Revoke</button>}
                    {status === 'active' && <button onClick={() => setReissueOpen(true)} className="px-3 py-1.5 text-xs bg-green-50 dark:bg-green-900/50 text-green-800 dark:text-green-300 border border-green-300 dark:border-green-700 rounded hover:bg-green-900 transition-colors">Reissue</button>}
                    <button onClick={handleDownloadPem} className={actBtn}>PEM</button>
                    <button onClick={handleDownloadDer} className={actBtn}>DER</button>
                    <button onClick={handleDownloadChain} className="px-3 py-1.5 text-xs bg-cyan-50 dark:bg-cyan-900/50 text-cyan-800 dark:text-cyan-300 border border-cyan-300 dark:border-cyan-700 rounded hover:bg-cyan-900 transition-colors">Full Chain</button>
                    <button onClick={handleCopySerial} className="px-3 py-1.5 text-xs bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 border border-gray-400 dark:border-gray-600 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors">Copy Serial</button>
                </div>
            }
        >
            {() => (<>
                {status === 'revoked' && (
                    <div className="px-3 py-2 bg-red-50 dark:bg-red-900/30 border border-red-300 dark:border-red-700/50 rounded-md flex items-center gap-2">
                        <span className="inline-block px-2 py-0.5 text-xs font-semibold bg-red-600 text-white rounded">REVOKED</span>
                        {cert.revocationReason && <span className="text-sm text-red-800 dark:text-red-300">Reason: {cert.revocationReason}</span>}
                        {cert.revokedAt && <span className="text-xs text-red-800 dark:text-red-400 ml-auto">{formatDate(cert.revokedAt)}</span>}
                    </div>
                )}

                <DetailSection title="Certificate">
                    <DetailField label="Serial" value={cert.serialNumber} mono />
                    <DetailField label="Subject" value={cert.subjectDN} />
                    <DetailField label="Issuer" value={cert.issuer} />
                    <DetailField label="Not Before" value={formatDate(cert.notBefore)} />
                    <DetailField label="Not After" value={formatDate(cert.notAfter)} />
                    <DetailField label="Key Algorithm" value={cert.keyAlgorithm} />
                    <DetailField label="Signature Algorithm" value={cert.signatureAlgorithm} />
                    {thumbprints ? thumbprints.map((tp) => <DetailField key={tp.label} label={`Thumbprint (${tp.label})`} value={tp.value} mono />)
                        : <DetailField label="Thumbprints" value={cert.thumbprints} mono />}
                    {sans && sans.length > 0
                        ? <DetailField label="SANs" value={sans.join(', ')} />
                        : <DetailField label="SANs" value={cert.subjectAlternativeNames?.join?.(', ') || '-'} />}
                </DetailSection>

                <DetailSection title="Extensions">
                    <button onClick={toggleExtensions} className="px-3 py-1 text-xs bg-gray-200/50 dark:bg-gray-700/50 text-gray-700 dark:text-gray-300 border border-gray-400 dark:border-gray-600 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors">
                        {extVisible ? 'Hide Extensions' : 'View Extensions'}
                    </button>
                    {extVisible && (
                        <div className="mt-2 pl-2 border-l-2 border-gray-300 dark:border-gray-600 space-y-1">
                            {extLoading && <div className="text-xs text-gray-600">Loading extensions...</div>}
                            {extError && <div className="text-xs text-red-800 dark:text-red-400">{extError}</div>}
                            {ext && (<>
                                {ext.basicConstraints && <DetailField label="Basic Constraints" value={`CA: ${ext.basicConstraints.isCA ? 'Yes' : 'No'}${ext.basicConstraints.pathLength != null ? `, Path Length: ${ext.basicConstraints.pathLength}` : ''}`} />}
                                {ext.keyUsage?.length > 0 && <DetailField label="Key Usage" value={ext.keyUsage.join(', ')} />}
                                {ext.extendedKeyUsage?.length > 0 && <DetailField label="Extended Key Usage" value={ext.extendedKeyUsage.join(', ')} />}
                                {ext.subjectAlternativeNames?.length > 0 && <DetailField label="SANs (ext)" value={ext.subjectAlternativeNames.join(', ')} />}
                                {ext.subjectKeyIdentifier && <DetailField label="Subject Key ID" value={ext.subjectKeyIdentifier} mono />}
                                {ext.authorityKeyIdentifier && <DetailField label="Authority Key ID" value={ext.authorityKeyIdentifier} mono />}
                                {ext.authorityInformationAccess?.ocspUrls?.map((url: string, i: number) => <DetailField key={`ocsp-${i}`} label="OCSP" value={<a href={url} target="_blank" rel="noopener noreferrer" className="text-blue-500 hover:text-blue-400 underline break-all">{url}</a>} />)}
                                {ext.authorityInformationAccess?.caIssuerUrls?.map((url: string, i: number) => <DetailField key={`caissuer-${i}`} label="CA Issuer" value={<a href={url} target="_blank" rel="noopener noreferrer" className="text-blue-500 hover:text-blue-400 underline break-all">{url}</a>} />)}
                                {ext.crlDistributionPoints?.map((url: string, i: number) => <DetailField key={`cdp-${i}`} label="CRL Distribution Point" value={<a href={url} target="_blank" rel="noopener noreferrer" className="text-blue-500 hover:text-blue-400 underline break-all">{url}</a>} />)}
                                {ext.certificatePolicies?.length > 0 && <DetailField label="Certificate Policies" value={ext.certificatePolicies.join(', ')} mono />}
                            </>)}
                        </div>
                    )}
                </DetailSection>

                <DetailSection title="Access Control (ACL)">
                    <p className="text-[11px] text-gray-500 mb-3">
                        Per-certificate grants for individual users. Anyone with CA-wide access (or the original requestor) can already view/manage this certificate and isn't listed here. <strong>Manage</strong> allows revoke/reissue; <strong>View</strong> is read-only.
                    </p>
                    {aclLoading && <div className="text-xs text-gray-600">Loading access…</div>}
                    {!aclLoading && acl && (<>
                        {acl.entries.length === 0 ? (
                            <div className="text-xs text-gray-500 mb-3">No explicit ACL entries.</div>
                        ) : (
                            <div className="divide-y divide-gray-200 dark:divide-gray-700/60 mb-3 border border-gray-200 dark:border-gray-700/60 rounded">
                                {acl.entries.map((e: any) => (
                                    <div key={e.userId} className="flex items-center gap-2 px-3 py-2 text-sm">
                                        <div className="flex-1 min-w-0">
                                            <span className="text-gray-900 dark:text-white">{e.username || e.userId}</span>
                                            {e.email && <span className="text-xs text-gray-500 ml-2">{e.email}</span>}
                                            {e.userId === acl.requestorUserId && <span className="text-[10px] text-gray-500 ml-2">(requestor)</span>}
                                        </div>
                                        <select value={e.accessLevel} disabled={aclBusy} onChange={(ev) => setAccess(e.userId, ev.target.value as 'View' | 'Manage')}
                                            className="px-2 py-1 text-xs bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-gray-900 dark:text-white focus:outline-none focus:border-blue-500 disabled:opacity-50">
                                            <option value="View">View</option>
                                            <option value="Manage">Manage</option>
                                        </select>
                                        <button onClick={() => revokeAccess(e.userId)} disabled={aclBusy}
                                            className="px-2 py-1 text-[10px] bg-red-50 dark:bg-red-900/50 text-red-800 dark:text-red-300 border border-red-300 dark:border-red-700 rounded hover:bg-red-900 disabled:opacity-50 transition-colors">Remove</button>
                                    </div>
                                ))}
                            </div>
                        )}
                        <div className="flex items-center gap-2">
                            <select value={addUserId} onChange={(e) => setAddUserId(e.target.value)} disabled={aclBusy}
                                className="flex-1 px-2 py-1.5 text-xs bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-gray-900 dark:text-white focus:outline-none focus:border-blue-500 disabled:opacity-50">
                                <option value="">Grant access to a user…</option>
                                {allUsers.filter((u) => !acl.entries.some((e: any) => e.userId === u.id)).map((u) => (
                                    <option key={u.id} value={u.id}>{u.username}{u.email ? ` (${u.email})` : ''}</option>
                                ))}
                            </select>
                            <select value={addLevel} onChange={(e) => setAddLevel(e.target.value as 'View' | 'Manage')} disabled={aclBusy}
                                className="px-2 py-1.5 text-xs bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-gray-900 dark:text-white focus:outline-none focus:border-blue-500 disabled:opacity-50">
                                <option value="View">View</option>
                                <option value="Manage">Manage</option>
                            </select>
                            <button onClick={addAccess} disabled={aclBusy || !addUserId} className="px-3 py-1.5 text-xs bg-green-600 text-white rounded hover:bg-green-700 disabled:opacity-50">Add</button>
                        </div>

                        {/* Read-only RBAC hint — who can already access via CA-scoped group capabilities. */}
                        <div className="mt-4 pt-3 border-t border-gray-200 dark:border-gray-700/60">
                            <div className="text-[11px] font-semibold text-gray-600 dark:text-gray-400 mb-1">Also accessible via RBAC{acl.rbac?.caLabel ? ` — CA: ${acl.rbac.caLabel}` : ''}</div>
                            {acl.rbac?.groups?.length ? (<>
                                <p className="text-[10px] text-gray-500 mb-2">Members of these groups can already view/manage this certificate through CA-scoped capabilities — adjust on the Groups / Roles pages, not here. Direct per-user role grants aren't shown.</p>
                                <div className="flex flex-wrap gap-1.5">
                                    {acl.rbac.groups.map((g: any) => (
                                        <span key={g.groupId} title={`${g.memberCount} member${g.memberCount === 1 ? '' : 's'}`}
                                            className={`inline-flex items-center gap-1 px-2 py-0.5 text-[11px] rounded border ${g.level === 'Manage' ? 'bg-orange-50 dark:bg-orange-900/40 text-orange-800 dark:text-orange-300 border-orange-300 dark:border-orange-700' : 'bg-blue-50 dark:bg-blue-900/40 text-blue-800 dark:text-blue-300 border-blue-300 dark:border-blue-700'}`}>
                                            {g.displayName || g.name}
                                            <span className="opacity-70">· {g.level}</span>
                                            <span className="opacity-50">· {g.memberCount}</span>
                                        </span>
                                    ))}
                                </div>
                            </>) : (
                                <p className="text-[10px] text-gray-500">No groups grant RBAC access on this certificate's CA scope — only the ACL above and the original requestor apply.</p>
                            )}
                        </div>
                    </>)}
                </DetailSection>

                {/* Revoke modal */}
                {revokeOpen && (
                    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/20 dark:bg-black/50" onClick={() => !revokeLoading && setRevokeOpen(false)}>
                        <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg shadow-xl w-full max-w-md mx-4" onClick={(e) => e.stopPropagation()}>
                            <div className="px-6 py-4 border-b border-gray-300 dark:border-gray-700"><h2 className="text-lg font-semibold text-gray-900 dark:text-white">Revoke Certificate</h2></div>
                            <div className="px-6 py-4 space-y-4">
                                <div className="space-y-1"><div className="text-xs text-gray-600 dark:text-gray-400">Serial Number</div><div className="font-mono text-sm text-gray-800 dark:text-gray-200 break-all">{cert.serialNumber}</div></div>
                                <div className="space-y-1"><div className="text-xs text-gray-600 dark:text-gray-400">Subject</div><div className="text-sm text-gray-800 dark:text-gray-200 break-all">{cert.subjectDN}</div></div>
                                <div className="space-y-1">
                                    <label htmlFor="revoke-reason" className="block text-xs text-gray-600 dark:text-gray-400">Revocation Reason</label>
                                    <select id="revoke-reason" value={revokeReason} onChange={(e) => setRevokeReason(e.target.value)} disabled={revokeLoading} className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-400 dark:border-gray-600 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500 disabled:opacity-50">
                                        {REVOCATION_REASONS.map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}
                                    </select>
                                </div>
                                {revokeError && <div className="px-3 py-2 bg-red-50 dark:bg-red-900/30 border border-red-300 dark:border-red-700/50 rounded text-sm text-red-800 dark:text-red-300">{revokeError}</div>}
                            </div>
                            <div className="px-6 py-4 border-t border-gray-300 dark:border-gray-700 flex justify-end gap-3">
                                <button onClick={() => setRevokeOpen(false)} disabled={revokeLoading} className="px-4 py-2 text-sm bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors disabled:opacity-50">Cancel</button>
                                <button onClick={handleRevokeConfirm} disabled={revokeLoading} className="px-4 py-2 text-sm bg-red-600 text-white rounded hover:bg-red-700 transition-colors disabled:opacity-50">{revokeLoading ? 'Revoking...' : 'Revoke'}</button>
                            </div>
                        </div>
                    </div>
                )}

                <CertificateReissueModal open={reissueOpen} onClose={() => setReissueOpen(false)} onSuccess={(msg) => { showToast('success', msg); setRefresh((r) => r + 1); }} cert={reissueTarget} />
            </>)}
        </DetailPage>
    );
};

export default CertificateDetail;
