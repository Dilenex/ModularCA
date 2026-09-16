import React, { useEffect, useState } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { apiGet, apiPostWithMfa } from '../api/client';
import { DataTable, type DataTableColumn } from '@shared/components/DataTable';
import { useStepUp } from '../components/StepUpMfaContext';
import { StepUpOps } from '@shared/generated';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import { DetailPage, DetailSection } from '../components/DetailPage';

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function caTypeBadge(ca: any): { status: 'active' | 'pending' | 'disabled'; label: string } {
    const t = (ca.type || ca.caType || '').toLowerCase();
    if (t.includes('root')) return { status: 'active', label: 'Root' };
    if (t.includes('intermediate')) return { status: 'pending', label: 'Intermediate' };
    return { status: 'disabled', label: 'Issuing' };
}

export const caKey = (ca: any): string => ca.id || ca.certificateId || ca.serialNumber || ca.name;

function flattenCas(cas: any[]): any[] {
    const result: any[] = [];
    for (const ca of cas) {
        result.push(ca);
        if (ca.children && ca.children.length > 0) result.push(...flattenCas(ca.children));
    }
    return result;
}

/// <summary>
/// Read-only detail page for a single certificate authority: CA info, certificate details, protocol
/// configurations, service URLs and OCSP responder. CAs aren't edited in place (creation lives on the
/// CA Management page), so this page is View-only.
/// </summary>
const CaDetail: React.FC = () => {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();

    const { requireStepUp } = useStepUp();

    const [ca, setCa] = useState<any | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);

    // Infrastructure certificate reissue. OCSP defaults on because a broken responder is the
    // reason to be here; TSA defaults off because reissuing it is rarer and not free.
    const [reissueOcsp, setReissueOcsp] = useState(true);
    const [reissueTsa, setReissueTsa] = useState(false);
    // Off by default like the TSA: most CAs never serve signature-protected CMP, and a signer that
    // exists is a signer that has to be rotated.
    const [reissueCmp, setReissueCmp] = useState(false);
    const [revokeSuperseded, setRevokeSuperseded] = useState(true);
    const [reissuing, setReissuing] = useState(false);
    const [reissueResult, setReissueResult] = useState<any | null>(null);
    const [reissueError, setReissueError] = useState<NoticeInput | null>(null);

    const handleReissueInfrastructure = async () => {
        if (!ca) return;
        setReissuing(true);
        setReissueResult(null);
        setReissueError(null);
        try {
            const res = await apiPostWithMfa<any>(
                `/api/v1/admin/authorities/${caKey(ca)}/reissue-infrastructure`,
                { reissueOcspResponder: reissueOcsp, reissueTsa, reissueCmpSigner: reissueCmp, revokeSuperseded },
                requireStepUp,
                StepUpOps.ReissueInfrastructureCerts,
                caKey(ca),
            );
            setReissueResult(res);
        } catch (err: any) {
            // Cancelling the step-up prompt is a deliberate choice, not a failure to report.
            if (err?.message !== 'Step-up MFA cancelled') {
                setReissueError(errorNotice(err, 'Reissue failed'));
            }
        } finally {
            setReissuing(false);
        }
    };

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError(null);
        apiGet<any>('/api/v1/admin/authorities/hierarchy')
            .then((data) => {
                if (cancelled) return;
                const items = Array.isArray(data) ? data : (data.items || data.authorities || []);
                setCa(flattenCas(items).find((c: any) => caKey(c) === id) || null);
                setLoading(false);
            })
            .catch((err) => { if (!cancelled) { setError(errorNotice(err, 'Failed to load CA')); setLoading(false); } });
        return () => { cancelled = true; };
    }, [id]);

    if (loading) return <div className="p-6 text-sm text-gray-600 dark:text-gray-400">Loading…</div>;
    if (error) return <InlineNotice notice={error} />;
    if (!ca) return (
        <div className="p-6 space-y-3">
            <p className="text-sm text-gray-600 dark:text-gray-400">Certificate authority not found.</p>
            <button onClick={() => navigate('/authorities/manage')} className="px-3 py-1.5 text-sm bg-gray-200 dark:bg-gray-700 rounded">Back to CA Management</button>
        </div>
    );

    const typeBadge = caTypeBadge(ca);
    // Wire name is `isEnabled`; `ca.enabled` was always undefined, so a disabled CA
    // presented as enabled here and in CaManagement.
    const enabled = !!ca.isEnabled;
    const cert = ca.certificate;

    let thumbprintDisplay = cert?.thumbprints;
    try { const tp = JSON.parse(cert?.thumbprints); thumbprintDisplay = Object.entries(tp).map(([k, v]) => `${k}: ${v}`).join('\n'); } catch { }
    let keyUsages = '';
    try { keyUsages = JSON.parse(cert?.keyUsagesJson || '[]').join(', '); } catch { }
    let ekuUsages = '';
    try { ekuUsages = JSON.parse(cert?.extendedKeyUsagesJson || '[]').join(', '); } catch { }

    return (
        <DetailPage
            breadcrumbs={[{ label: 'CA Management', to: '/authorities/manage' }, { label: ca.name || ca.subjectDN }]}
            title={ca.name || ca.subjectDN}
            status={<span className="flex items-center gap-2"><StatusBadge status={typeBadge.status} label={typeBadge.label} /><StatusBadge status={enabled ? 'enabled' : 'disabled'} label={enabled ? 'Enabled' : 'Disabled'} /></span>}
            subtitle={ca.label ? <span className="font-mono">{ca.label}</span> : undefined}
            backTo="/authorities/manage"
        >
            {() => (<>
                <DetailSection title="CA Information">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8">
                        <DetailField label="Label" value={ca.label} mono />
                        {ca.tenantName && <DetailField label="Tenant" value={ca.tenantName} />}
                        <DetailField label="Default" value={ca.isDefault ? 'Yes' : 'No'} />
                        {ca.parentCaId && <DetailField label="Parent CA" value={ca.parentCaId} mono />}
                    </div>
                </DetailSection>

                <DetailSection title="Certificate Details">
                    {!cert ? (
                        <div className="text-xs text-gray-600 dark:text-gray-400">No certificate data available</div>
                    ) : (
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8">
                            <DetailField label="Subject" value={cert.subjectDN} />
                            <DetailField label="Serial Number" value={cert.serialNumber} mono />
                            <DetailField label="Issuer" value={cert.issuer} />
                            <DetailField label="Not Before" value={formatDate(cert.notBefore)} />
                            <DetailField label="Not After" value={formatDate(cert.notAfter)} />
                            <DetailField label="Is CA" value={cert.isCA ? 'Yes' : 'No'} />
                            <DetailField label="Revoked" value={cert.revoked ? `Yes (${cert.revocationReason})` : 'No'} />
                            {keyUsages && <DetailField label="Key Usages" value={keyUsages} />}
                            {ekuUsages && <DetailField label="Extended Key Usages" value={ekuUsages} />}
                            <DetailField label="Thumbprints" value={thumbprintDisplay} mono />
                        </div>
                    )}
                </DetailSection>

                {ca.protocolConfigs && ca.protocolConfigs.length > 0 && (
                    <DetailSection title="Protocol Configurations">
                        <p className="mb-2 text-xs text-gray-600 dark:text-gray-400">
                            Setting this CA up for Windows clients? <Link to={`/authorities/windows/${ca.id}`} className="text-blue-600 dark:text-blue-400 hover:underline">Windows Autoenrollment</Link> checks every prerequisite in order and links to each.
                        </p>
                        <div className="overflow-x-auto">
                            <DataTable<any>
                                tableId="ca-protocols"
                                rows={ca.protocolConfigs}
                                rowKey={(pc: any) => pc.protocol || pc.name || pc.id}
                                empty="No protocol configuration"
                                disableExport
                                columns={[
                                    { key: 'protocol', header: 'Protocol', defaultWidth: 120, sortable: true, exportValue: (pc: any) => pc.protocol || pc.name, render: (pc: any) => <span className="text-gray-700 dark:text-gray-300">{pc.protocol || pc.name}</span> },
                                    { key: 'enabled', header: 'Enabled', defaultWidth: 100, truncate: false, sortable: true, sortValue: (pc: any) => !!pc.enabled, exportValue: (pc: any) => (pc.enabled ? 'Yes' : 'No'), render: (pc: any) => <StatusBadge status={pc.enabled ? 'enabled' : 'disabled'} label={pc.enabled ? 'Yes' : 'No'} /> },
                                    { key: 'profile', header: 'Profile', flex: true, exportValue: (pc: any) => pc.signingProfileName || pc.signingProfile || pc.certProfile || '', render: (pc: any) => <span className="text-gray-600 dark:text-gray-400 truncate">{pc.signingProfileName || pc.signingProfile || pc.certProfile || '-'}</span> },
                                ] as DataTableColumn<any>[]}
                            />
                        </div>
                    </DetailSection>
                )}

                {ca.serviceUrls && (
                    <DetailSection title="Service URLs">
                        <div className="flex items-center justify-end -mt-1 mb-2">
                            <Link to="/distribution?tab=serviceurls" className="text-xs text-blue-500 hover:text-blue-400 underline">Edit on Distribution</Link>
                        </div>
                        <DetailField label="Public Base URL" value={ca.serviceUrls.publicBaseUrl || '(not set)'} mono />
                        {ca.serviceUrls.publicBaseUrl && (
                            <>
                                <DetailField label="CDP" value={`${ca.serviceUrls.publicBaseUrl}/crl/${ca.label || ca.certificate?.serialNumber || ''}`} mono />
                                <DetailField label="OCSP" value={`${ca.serviceUrls.publicBaseUrl}/ocsp`} mono />
                                <DetailField label="CA Issuer" value={`${ca.serviceUrls.publicBaseUrl}/ca/${ca.label || ca.certificate?.serialNumber || ''}`} mono />
                            </>
                        )}
                    </DetailSection>
                )}

                {ca.ocspResponder && (
                    <DetailSection title="OCSP Responder">
                        <DetailField label="URL" value={ca.ocspResponder.url} mono />
                        <DetailField label="Status" value={ca.ocspResponder.enabled ? 'Enabled' : 'Disabled'} />
                        <DetailField label="Signing Cert" value={ca.ocspResponder.signingCertSubject} />
                    </DetailSection>
                )}

                {/* Infrastructure certificates.
                    Placed next to the OCSP Responder section because that is where an operator
                    looks when OCSP is answering "unauthorized" — which is the state this repairs. */}
                <DetailSection title="Infrastructure Certificates">
                    <div className="space-y-3">
                        <p className="text-xs text-gray-600 dark:text-gray-400 max-w-3xl">
                            Issues or reissues this CA's delegated OCSP responder, TSA certificate and CMP
                            signing certificate, repoints the CA at the new certificate, and registers it
                            with the running service. The new certificate is live immediately — no restart.
                        </p>

                        {/* The CMP signer is the one of the three that is not issued at CA creation, so
                            its absence is a state the operator has to be told about here. */}
                        {!ca.cmpSigningCertificateId && (
                            <div className="rounded border border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-900/30 p-3 max-w-3xl">
                                <p className="text-xs text-amber-900 dark:text-amber-300">
                                    <strong>No CMP signing certificate.</strong> If CMP is enabled on this CA, its
                                    signature-protected responses are signed with the CA certificate, which carries no
                                    <code> digitalSignature</code> key usage and is rejected by OpenSSL-based clients.
                                    Shared-secret (PBMAC) clients are unaffected. Tick <em>CMP signer</em> below and
                                    reissue to create one.
                                </p>
                            </div>
                        )}
                        <div className="rounded border border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-900/30 p-3 max-w-3xl">
                            <p className="text-xs text-amber-900 dark:text-amber-300">
                                <strong>Use this rather than the generic certificate Reissue action.</strong> That
                                action revokes the old certificate and issues a replacement, but it does not
                                update which certificate this CA points at — leaving the CA referencing a revoked
                                responder, which makes every OCSP request for it answer <code>unauthorized</code>.
                                Restarting does not fix that. This action does.
                            </p>
                        </div>

                        <div className="flex flex-wrap items-center gap-4">
                            <label className="flex items-center gap-2 text-sm text-gray-900 dark:text-white cursor-pointer">
                                <input type="checkbox" checked={reissueOcsp} onChange={(e) => setReissueOcsp(e.target.checked)} />
                                OCSP responder
                            </label>
                            <label className="flex items-center gap-2 text-sm text-gray-900 dark:text-white cursor-pointer">
                                <input type="checkbox" checked={reissueTsa} onChange={(e) => setReissueTsa(e.target.checked)} />
                                TSA signer
                            </label>
                            <label className="flex items-center gap-2 text-sm text-gray-900 dark:text-white cursor-pointer">
                                <input type="checkbox" checked={reissueCmp} onChange={(e) => setReissueCmp(e.target.checked)} />
                                <span title="Dedicated certificate that signs CMP responses (RFC 4210). Needed for signature-protected CMP; PBMAC clients do not use it.">
                                    CMP signer{ca.cmpSigningCertificateId ? '' : ' (not yet issued)'}
                                </span>
                            </label>
                            <label className="flex items-center gap-2 text-sm text-gray-900 dark:text-white cursor-pointer">
                                <input type="checkbox" checked={revokeSuperseded} onChange={(e) => setRevokeSuperseded(e.target.checked)} />
                                <span title="Leave on unless you have a reason to keep two valid responders for this CA. A predecessor that is already revoked is untouched either way.">
                                    Revoke the replaced certificate
                                </span>
                            </label>
                        </div>

                        <button
                            onClick={handleReissueInfrastructure}
                            disabled={reissuing || (!reissueOcsp && !reissueTsa && !reissueCmp)}
                            className="px-3 py-1.5 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors">
                            {reissuing ? 'Reissuing…' : 'Reissue Infrastructure Certificates'}
                        </button>

                        {reissueResult && (
                            <div className="rounded border border-green-300 dark:border-green-800 bg-green-50 dark:bg-green-900/30 p-3 max-w-3xl space-y-1">
                                <p className="text-xs text-green-900 dark:text-green-300">{reissueResult.message}</p>
                                {reissueResult.newOcspResponderSerial && (
                                    <p className="text-xs text-green-900 dark:text-green-300 font-mono">
                                        New OCSP responder: {reissueResult.newOcspResponderSerial}
                                    </p>
                                )}
                                {reissueResult.newTsaSerial && (
                                    <p className="text-xs text-green-900 dark:text-green-300 font-mono">
                                        New TSA: {reissueResult.newTsaSerial}
                                    </p>
                                )}
                                {reissueResult.newCmpSignerSerial && (
                                    <p className="text-xs text-green-900 dark:text-green-300 font-mono">
                                        New CMP signer: {reissueResult.newCmpSignerSerial}
                                    </p>
                                )}
                                {reissueResult.supersededRevoked?.length > 0 && (
                                    <p className="text-xs text-green-900 dark:text-green-300 font-mono">
                                        Revoked as superseded: {reissueResult.supersededRevoked.join(', ')}
                                    </p>
                                )}
                            </div>
                        )}

                        {reissueError && (
                            <div className="rounded border border-red-300 dark:border-red-800 bg-red-50 dark:bg-red-900/30 p-3 max-w-3xl">
                                <InlineNotice notice={reissueError} variant="line" />
                            </div>
                        )}
                    </div>
                </DetailSection>


                <DetailSection title="Quick Links">
                    <Link to={`/distribution?tab=ldap&caId=${caKey(ca)}`}
                        className="px-3 py-1 text-xs bg-blue-50 dark:bg-blue-900/50 text-blue-800 dark:text-blue-300 border border-blue-300 dark:border-blue-700 rounded hover:bg-blue-900 transition-colors inline-block">
                        LDAP Publishers
                    </Link>
                </DetailSection>
            </>)}
        </DetailPage>
    );
};

export default CaDetail;
