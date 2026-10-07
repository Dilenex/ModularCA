import React, { useEffect, useState, useCallback } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { Link, useParams, useNavigate } from 'react-router-dom';
import { apiGet, apiPostWithMfa, apiBlob } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import { actionButton, actionButtonDanger, actionButtonPrimary } from '@shared/components/actionButtons';
import CertificateReissueModal from '../components/CertificateReissueModal';
import { DetailPage, DetailSection } from '../components/DetailPage';
import { StepUpOps } from '@shared/generated';
import { FieldHint } from '@shared/components/forms';
import { type CeremonyRefusal, readCeremonyRefusal } from './ceremonyRefusal';
import { CeremonyRefusalNotice } from '../components/CeremonyRefusalNotice';
import { canReissue, capitalize, channelNote, expiryPhrase, expiryState, lifecycleTone, toneBannerClass, toneTextClass } from './certLifecycle';

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

/**
 * What each RFC 5280 revocation reason means to the operator choosing it. Every reason picker in
 * the console (this page, the bulk modal, the dashboard quick revoke, the user portal) shows the
 * sentence for the selected value, because only Certificate Hold can ever be undone.
 */
export const REVOCATION_REASON_HELP: Record<string, string> = {
    Unspecified: 'No reason recorded. Permanent, and it cannot be changed later.',
    KeyCompromise: 'The private key may have leaked. Permanent, and some clients hard-fail on it.',
    CACompromise: 'The issuing CA\'s own key is suspected compromised; use it only for CA certificates, and expect every certificate under that CA to be distrusted. Permanent.',
    AffiliationChanged: 'The subject\'s name or organisation is no longer accurate, but the key itself is not suspected. Permanent.',
    Superseded: 'Replaced by a new certificate; the normal choice after a reissue. Permanent.',
    CessationOfOperation: 'The service or device this certificate identified has been decommissioned and will not return. Permanent.',
    CertificateHold: 'The only reversible reason. The hold can be lifted from the certificate\'s page.',
    PrivilegeWithdrawn: 'The subject no longer holds the role or privilege the certificate asserted; the key is not suspected. Permanent.',
};

/** Helper text for a revocation-reason select; amber unless the reversible Certificate Hold is chosen. */
export const RevocationReasonHint: React.FC<{ reason: string; id?: string }> = ({ reason, id }) => (
    <FieldHint id={id} tone={reason === 'CertificateHold' ? 'muted' : 'warn'}>
        {REVOCATION_REASON_HELP[reason] || 'Permanent once published to the CRL and OCSP.'}
    </FieldHint>
);

/// <summary>
/// Read-only detail page for a single certificate (fetched by serial). Shows identity, validity,
/// thumbprints, SANs and on-demand extensions; revoke / reissue / downloads live in the action bar.
/// </summary>
const CertificateDetail: React.FC = () => {
    const { serial } = useParams<{ serial: string }>();
    const navigate = useNavigate();
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();
    const [holdBusy, setHoldBusy] = useState(false);   // declared with the other hooks, above the early returns

    const [cert, setCert] = useState<any | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [refresh, setRefresh] = useState(0);

    const [ext, setExt] = useState<any | null>(null);
    const [extLoading, setExtLoading] = useState(false);
    const [extError, setExtError] = useState<NoticeInput | null>(null);

    const [revokeOpen, setRevokeOpen] = useState(false);
    const [revokeReason, setRevokeReason] = useState('Unspecified');
    const [revokeLoading, setRevokeLoading] = useState(false);
    const [revokeError, setRevokeError] = useState<NoticeInput | null>(null);
    // Revoking a CA was refused because nobody else could approve its ceremony.
    const [revokeRefusal, setRevokeRefusal] = useState<CeremonyRefusal | null>(null);

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
            .catch((err) => { if (!cancelled) { setError(errorNotice(err, 'Failed to load certificate')); setLoading(false); } });
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

    useEffect(() => {
        let cancelled = false;
        setExt(null); setExtError(null); setExtLoading(true);
        apiGet<any>(`/api/v1/admin/certificates/${serial}/extensions`)
            .then((data) => { if (!cancelled) setExt(data); })
            .catch((err) => { if (!cancelled) setExtError(errorNotice(err, 'Failed to load extensions')); })
            .finally(() => { if (!cancelled) setExtLoading(false); });
        return () => { cancelled = true; };
    }, [serial]);

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
            const resp = await apiBlob(`/api/v1/admin/certificates/${serial}/chain`);
            downloadBlob(await resp.text(), `${getCertName(cert)}-fullchain.pem`, 'application/x-pem-file');
        } catch (err: any) { showToast('error', err.message || 'Download failed'); }
    };
    const handleCopySerial = () => navigator.clipboard.writeText(cert?.serialNumber || '').then(() => showToast('success', 'Serial copied')).catch(() => {});

    const handleRevokeConfirm = async () => {
        if (!cert) return;
        setRevokeLoading(true); setRevokeError(null); setRevokeRefusal(null);
        try {
            // The revoke endpoints key off the BODY (serialNumber), not the route param — the page is
            // loaded by serial, so revoke by serial. CA certs use the revoke-ca step-up op.
            const op = cert.isCA ? 'revoke-ca' : 'revoke-cert';
            await apiPostWithMfa(`/api/v1/admin/certificates/serial/${serial}/revoke`, { serialNumber: serial, reason: revokeReason }, requireStepUp, op, serial!);
            setRevokeOpen(false);
            setRefresh((r) => r + 1);
        } catch (err: any) {
            const refusal = readCeremonyRefusal(err);
            if (refusal) setRevokeRefusal(refusal);
            else if (err.message !== 'Step-up MFA cancelled') setRevokeError(errorNotice(err, 'Revocation failed'));
        } finally {
            setRevokeLoading(false);
        }
    };

    if (loading) return <div className="p-6 text-sm text-ink-muted">Loading…</div>;
    if (error) return (
        <div className="p-6 space-y-3">
            <InlineNotice notice={error} variant="line" />
            <button onClick={() => navigate('/certificates')} className="px-3 py-1.5 text-sm bg-sunken rounded">Back to Certificates</button>
        </div>
    );
    if (!cert) return (
        <div className="p-6 space-y-3">
            <p className="text-sm text-ink-muted">Certificate not found.</p>
            <button onClick={() => navigate('/certificates')} className="px-3 py-1.5 text-sm bg-sunken rounded">Back to Certificates</button>
        </div>
    );

    const status = certStatus(cert);
    // Certificate Hold (RFC 5280 reason 6) is the only reversible revocation; the server exposes
    // the reversal and this is the only place in the console that can offer it.
    const isOnHold = status === 'revoked' && /hold/i.test(String(cert?.revocationReason ?? ''));
    const liftHold = async () => {
        if (!cert?.certificateId) return;
        setHoldBusy(true);
        try {
            await apiPostWithMfa(`/api/v1/admin/certificates/${cert.certificateId}/unhold`, {}, requireStepUp, StepUpOps.UnholdCert, cert.certificateId);
            showToast('success', 'Hold lifted. The certificate is valid again from the next CRL and OCSP update.');
            setRefresh((r) => r + 1);
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Could not lift the hold');
        } finally {
            setHoldBusy(false);
        }
    };
    const lifecycle = expiryState(cert);
    const lifecycleToneValue = lifecycleTone(cert.notAfter, !!cert.replaced);
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
            status={status === 'expired' && cert.replaced ? <StatusBadge status="disabled" label="expired" /> : <StatusBadge status={status} />}
            subtitle={<span className="font-mono">{cert.serialNumber}</span>}
            backTo="/certificates"
            actions={
                <div className="flex items-center gap-2 flex-wrap">
                    <button onClick={handleDownloadPem} className={actionButton}>PEM</button>
                    <button onClick={handleDownloadDer} className={actionButton}>DER</button>
                    <button onClick={handleDownloadChain} className={actionButton}>Full Chain</button>
                    <button onClick={handleCopySerial} className={actionButton}>Copy Serial</button>
                    {/* Reissue builds a fresh request from the old subject, so an expired certificate can be replaced too; a revoked one only while it is merely on hold. */}
                    {(status === 'active' || status === 'expired' || isOnHold) && <button onClick={() => setReissueOpen(true)} title={status === 'expired' ? 'Request a replacement with the same subject and names' : undefined} className={actionButton}>Reissue</button>}
                    {status === 'active' && <button onClick={() => { setRevokeReason('Unspecified'); setRevokeError(null); setRevokeOpen(true); }} className={actionButtonDanger}>Revoke</button>}
                </div>
            }
        >
            {() => (<>
                {status === 'revoked' && (
                    <div className="px-3 py-2 bg-crit-soft border border-crit/40 rounded-md flex items-center gap-2 flex-wrap">
                        <span className="inline-block px-2 py-0.5 text-xs font-semibold bg-crit text-on-accent rounded">REVOKED</span>
                        {cert.revocationReason && <span className="text-sm text-crit">Reason: {cert.revocationReason}</span>}
                        {cert.revokedAt && <span className="text-xs text-crit ml-auto">{formatDate(cert.revokedAt)}</span>}
                        {isOnHold && (
                            <button onClick={liftHold} disabled={holdBusy} className="px-2.5 py-1 text-xs rounded border border-crit text-crit hover:bg-crit-soft disabled:opacity-50">
                                {holdBusy ? 'Lifting…' : 'Lift hold'}
                            </button>
                        )}
                    </div>
                )}
                {(lifecycle === 'expired' || lifecycle === 'expiring') && (
                    <div className={`px-3 py-2.5 border rounded-md space-y-1.5 ${toneBannerClass(lifecycleToneValue)}`}>
                        <div className="flex items-center gap-x-3 gap-y-1 flex-wrap">
                            <span className={`text-sm font-semibold ${toneTextClass(lifecycleToneValue)}`}>{capitalize(expiryPhrase(cert.notAfter))}</span>
                            <span className="text-xs text-ink-muted">{formatDate(cert.notAfter)}</span>
                            <span className="text-sm text-ink">
                                {cert.replaced
                                    ? (cert.replacedBySerial
                                        ? <>Replaced by <Link to={`/certificates/${cert.replacedBySerial}`} className="font-mono text-accent-ink hover:underline">{cert.replacedBySerial}</Link></>
                                        : 'Replaced')
                                    : 'Not replaced'}
                            </span>
                            {!cert.replaced && canReissue(cert) && (
                                <button onClick={() => setReissueOpen(true)} className={`ml-auto ${actionButtonPrimary}`}>Reissue</button>
                            )}
                        </div>
                        {!cert.replaced && (
                            <p className="text-xs text-ink-muted">
                                {channelNote(cert.issuanceChannel)}
                            </p>
                        )}
                    </div>
                )}
                {isOnHold && (
                    <p className="text-xs text-ink-muted -mt-1">Certificate Hold is the one revocation reason that can be reversed. Lifting it returns the certificate to good standing on the next CRL and OCSP answer.</p>
                )}

                <DetailSection title="Certificate">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8">
                        <div>
                            <DetailField label="Subject" value={cert.subjectDN} />
                            <DetailField label="Issuer" value={cert.issuer} />
                            {sans && sans.length > 0
                                ? <DetailField label="SANs" value={sans.join(', ')} />
                                : <DetailField label="SANs" value={cert.subjectAlternativeNames?.join?.(', ') || '-'} />}
                            <DetailField label="Serial" value={cert.serialNumber} mono />
                        </div>
                        <div>
                            <DetailField label="Not Before" value={formatDate(cert.notBefore)} />
                            <DetailField label="Not After" value={formatDate(cert.notAfter)} />
                            <DetailField label="Key Algorithm" value={[cert.keyAlgorithm, cert.keySize].filter(Boolean).join(' ')} />
                            <DetailField label="Signature Algorithm" value={cert.signatureAlgorithm} />
                        </div>
                    </div>
                    {thumbprints ? thumbprints.map((tp) => <DetailField key={tp.label} label={`Thumbprint (${tp.label})`} value={tp.value} mono />)
                        : <DetailField label="Thumbprints" value={cert.thumbprints} mono />}
                </DetailSection>

                <DetailSection title="Extensions">
                    {extLoading && <div className="text-xs text-ink-muted">Loading extensions...</div>}
                    {extError && <InlineNotice notice={extError} />}
                    {ext && (<>
                        {ext.basicConstraints && <DetailField label="Basic Constraints" value={`CA: ${ext.basicConstraints.isCA ? 'Yes' : 'No'}${ext.basicConstraints.pathLength != null ? `, Path Length: ${ext.basicConstraints.pathLength}` : ''}`} />}
                        {ext.keyUsage?.length > 0 && <DetailField label="Key Usage" value={ext.keyUsage.join(', ')} />}
                        {ext.extendedKeyUsage?.length > 0 && <DetailField label="Extended Key Usage" value={ext.extendedKeyUsage.join(', ')} />}
                        {ext.subjectKeyIdentifier && <DetailField label="Subject Key ID" value={ext.subjectKeyIdentifier} mono />}
                        {ext.authorityKeyIdentifier && <DetailField label="Authority Key ID" value={ext.authorityKeyIdentifier} mono />}
                        {ext.authorityInformationAccess?.ocspUrls?.map((url: string, i: number) => <DetailField key={`ocsp-${i}`} label="OCSP" value={<a href={url} target="_blank" rel="noopener noreferrer" className="text-accent-ink hover:underline underline break-all">{url}</a>} />)}
                        {ext.authorityInformationAccess?.caIssuerUrls?.map((url: string, i: number) => <DetailField key={`caissuer-${i}`} label="CA Issuer" value={<a href={url} target="_blank" rel="noopener noreferrer" className="text-accent-ink hover:underline underline break-all">{url}</a>} />)}
                        {ext.crlDistributionPoints?.map((url: string, i: number) => <DetailField key={`cdp-${i}`} label="CRL Distribution Point" value={<a href={url} target="_blank" rel="noopener noreferrer" className="text-accent-ink hover:underline underline break-all">{url}</a>} />)}
                        {ext.certificatePolicies?.length > 0 && <DetailField label="Certificate Policies" value={ext.certificatePolicies.join(', ')} mono />}
                    </>)}
                </DetailSection>

                <DetailSection title="Access Control (ACL)">
                    <p className="text-[11px] text-ink-muted mb-3">
                        Per-certificate grants for individual users. Anyone with CA-wide access (or the original requestor) can already view/manage this certificate and isn't listed here. <strong>Manage</strong> allows revoke/reissue; <strong>View</strong> is read-only.
                    </p>
                    {aclLoading && <div className="text-xs text-ink-muted">Loading access…</div>}
                    {!aclLoading && acl && (<>
                        {acl.entries.length === 0 ? (
                            <div className="text-xs text-ink-muted mb-3">No explicit ACL entries.</div>
                        ) : (
                            <div className="divide-y divide-line mb-3 border border-line rounded">
                                {acl.entries.map((e: any) => (
                                    <div key={e.userId} className="flex items-center gap-2 px-3 py-2 text-sm">
                                        <div className="flex-1 min-w-0">
                                            <span className="text-ink">{e.username || e.userId}</span>
                                            {e.email && <span className="text-xs text-ink-muted ml-2">{e.email}</span>}
                                            {e.userId === acl.requestorUserId && <span className="text-[10px] text-ink-muted ml-2">(requestor)</span>}
                                        </div>
                                        <select value={e.accessLevel} disabled={aclBusy} onChange={(ev) => setAccess(e.userId, ev.target.value as 'View' | 'Manage')}
                                            className="px-2 py-1 text-xs bg-raised border border-line-strong rounded text-ink focus:outline-none focus:border-accent disabled:opacity-50">
                                            <option value="View">View</option>
                                            <option value="Manage">Manage</option>
                                        </select>
                                        <button onClick={() => revokeAccess(e.userId)} disabled={aclBusy}
                                            className="px-2 py-1 text-[10px] bg-crit-soft text-crit border border-crit/40 rounded hover:bg-crit/15 disabled:opacity-50 transition-colors">Remove</button>
                                    </div>
                                ))}
                            </div>
                        )}
                        <div className="flex items-center gap-2">
                            <select value={addUserId} onChange={(e) => setAddUserId(e.target.value)} disabled={aclBusy}
                                className="flex-1 px-2 py-1.5 text-xs bg-raised border border-line-strong rounded text-ink focus:outline-none focus:border-accent disabled:opacity-50">
                                <option value="">Grant access to a user…</option>
                                {allUsers.filter((u) => !acl.entries.some((e: any) => e.userId === u.id)).map((u) => (
                                    <option key={u.id} value={u.id}>{u.username}{u.email ? ` (${u.email})` : ''}</option>
                                ))}
                            </select>
                            <select value={addLevel} onChange={(e) => setAddLevel(e.target.value as 'View' | 'Manage')} disabled={aclBusy}
                                className="px-2 py-1.5 text-xs bg-raised border border-line-strong rounded text-ink focus:outline-none focus:border-accent disabled:opacity-50">
                                <option value="View">View</option>
                                <option value="Manage">Manage</option>
                            </select>
                            <button onClick={addAccess} disabled={aclBusy || !addUserId} className={actionButtonPrimary}>Add</button>
                        </div>

                        {/* Read-only RBAC hint — who can already access via CA-scoped group capabilities. */}
                        <div className="mt-4 pt-3 border-t border-line">
                            <div className="text-[11px] font-semibold text-ink-muted mb-1">Also accessible via RBAC{acl.rbac?.caLabel ? ` — CA: ${acl.rbac.caLabel}` : ''}</div>
                            {acl.rbac?.groups?.length ? (<>
                                <p className="text-[10px] text-ink-muted mb-2">Members of these groups can already view/manage this certificate through CA-scoped capabilities — adjust on the Groups / Roles pages, not here. Direct per-user role grants aren't shown.</p>
                                <div className="flex flex-wrap gap-1.5">
                                    {acl.rbac.groups.map((g: any) => (
                                        <span key={g.groupId} title={`${g.memberCount} member${g.memberCount === 1 ? '' : 's'}`}
                                            className={`inline-flex items-center gap-1 px-2 py-0.5 text-[11px] rounded border ${g.level === 'Manage' ? 'bg-warn-soft text-warn border-warn/40' : 'bg-info-soft text-info border-info/40'}`}>
                                            {g.displayName || g.name}
                                            <span className="opacity-70">· {g.level}</span>
                                            <span className="opacity-50">· {g.memberCount}</span>
                                        </span>
                                    ))}
                                </div>
                            </>) : (
                                <p className="text-[10px] text-ink-muted">No groups grant RBAC access on this certificate's CA scope — only the ACL above and the original requestor apply.</p>
                            )}
                        </div>
                    </>)}
                </DetailSection>

                {/* Revoke modal */}
                {revokeOpen && (
                    <div className="fixed inset-0 z-50 flex items-center justify-center bg-scrim" onClick={() => !revokeLoading && setRevokeOpen(false)}>
                        <div className="bg-raised border border-line rounded-lg shadow-xl w-full max-w-md mx-4" onClick={(e) => e.stopPropagation()}>
                            <div className="px-6 py-4 border-b border-line"><h2 className="text-lg font-semibold text-ink">Revoke Certificate</h2></div>
                            <div className="px-6 py-4 space-y-4">
                                <div className="space-y-1"><div className="text-xs text-ink-muted">Serial Number</div><div className="data-mono text-ink break-all">{cert.serialNumber}</div></div>
                                <div className="space-y-1"><div className="text-xs text-ink-muted">Subject</div><div className="text-sm text-ink break-all">{cert.subjectDN}</div></div>
                                <div className="space-y-1">
                                    <label htmlFor="revoke-reason" className="block text-xs text-ink-muted">Revocation Reason</label>
                                    <select id="revoke-reason" value={revokeReason} onChange={(e) => setRevokeReason(e.target.value)} disabled={revokeLoading} className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-sm text-ink focus:outline-none focus:border-accent disabled:opacity-50">
                                        {REVOCATION_REASONS.map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}
                                    </select>
                                    <RevocationReasonHint reason={revokeReason} />
                                </div>
                                {revokeRefusal && <CeremonyRefusalNotice refusal={revokeRefusal} />}
                                {revokeError && <InlineNotice notice={revokeError} />}
                            </div>
                            <div className="px-6 py-4 border-t border-line flex justify-end gap-3">
                                <button onClick={() => setRevokeOpen(false)} disabled={revokeLoading} className="px-4 py-2 text-sm bg-sunken text-ink rounded hover:bg-hover transition-colors disabled:opacity-50">Cancel</button>
                                <button onClick={handleRevokeConfirm} disabled={revokeLoading} className="px-4 py-2 text-sm bg-crit text-on-accent rounded hover:bg-crit-hover transition-colors disabled:opacity-50">{revokeLoading ? 'Revoking...' : 'Revoke'}</button>
                            </div>
                        </div>
                    </div>
                )}

                <CertificateReissueModal open={reissueOpen} onClose={() => setReissueOpen(false)} onSuccess={(msg, severity) => { showToast(severity ?? 'success', msg); setRefresh((r) => r + 1); }} cert={reissueTarget} />
            </>)}
        </DetailPage>
    );
};

export default CertificateDetail;
