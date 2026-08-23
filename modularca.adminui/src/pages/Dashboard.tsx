import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiGet, apiPost, apiPostWithMfa } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import DataCard from '../components/cards/DataCard';
import StatusBadge from '../components/cards/StatusBadge';
import DetailField from '../components/cards/DetailField';
import CertificateReissueModal from '../components/CertificateReissueModal';
import { useToast } from '../context/ToastContext';
import { StepUpOps } from '@shared/generated';
import {
    canonicalizeUsages, parseListField, ekuLabel, keyUsageLabel,
    KEY_USAGE_OPTIONS, EKU_OPTIONS, EKU_ALIASES,
} from './profileHelpers';

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function certStatus(cert: any): 'active' | 'revoked' | 'expired' {
    if (cert.revoked) return 'revoked';
    if (new Date(cert.notAfter) < new Date()) return 'expired';
    return 'active';
}

function parseJsonSafe(val: string | null | undefined): string {
    if (!val) return '';
    try {
        const parsed = JSON.parse(val);
        if (Array.isArray(parsed)) return parsed.join(', ');
        if (typeof parsed === 'object') return Object.entries(parsed).map(([k, v]) => `${k}: ${v}`).join('\n');
        return String(parsed);
    } catch { return val; }
}

interface CertStats {
    total: number;
    active: number;
    expiringSoon: number;
    expired: number;
    revoked: number;
}

interface GroupStats {
    total: number;
    system: number;
    caScoped: number;
}

interface HealthIndicator {
    label: string;
    ok: boolean;
    detail?: string;
}

/// Parses a SAN list from either an array, JSON string, or null.
function parseSansForReissue(raw: any): string[] | undefined {
    if (!raw) return undefined;
    if (Array.isArray(raw)) return raw;
    if (typeof raw === 'string') {
        try {
            const parsed = JSON.parse(raw);
            if (Array.isArray(parsed)) return parsed;
        } catch {
            // fall through
        }
    }
    return undefined;
}

const Dashboard: React.FC = () => {
    const navigate = useNavigate();
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();

    // Reissue modal state
    const [reissueOpen, setReissueOpen] = useState(false);
    const [reissueTarget, setReissueTarget] = useState<{
        id: string;
        serialNumber: string;
        subjectDN: string;
        sans?: string[];
        notBefore?: string;
        notAfter?: string;
    } | null>(null);
    const [reissueLoadingId, setReissueLoadingId] = useState<string | null>(null);

    const openReissueFromCard = async (cert: any) => {
        const id = cert.certificateId;
        if (!id) {
            showToast('error', 'Certificate ID missing');
            return;
        }
        // The recent-certs card already exposes subjectDN, notBefore, notAfter,
        // serialNumber and subjectAlternativeNamesJson, so no extra fetch is required.
        if (cert.subjectDN) {
            setReissueTarget({
                id,
                serialNumber: cert.serialNumber,
                subjectDN: cert.subjectDN,
                sans: parseSansForReissue(cert.subjectAlternativeNames ?? cert.subjectAlternativeNamesJson),
                notBefore: cert.notBefore,
                notAfter: cert.notAfter,
            });
            setReissueOpen(true);
            return;
        }
        // Fallback: hydrate from the API if the card row is sparse.
        setReissueLoadingId(id);
        try {
            const full = await apiGet<any>(`/api/v1/admin/certificates/${id}`);
            setReissueTarget({
                id,
                serialNumber: full.serialNumber,
                subjectDN: full.subjectDN,
                sans: parseSansForReissue(full.subjectAlternativeNames ?? full.subjectAlternativeNamesJson),
                notBefore: full.notBefore,
                notAfter: full.notAfter,
            });
            setReissueOpen(true);
        } catch (err: any) {
            showToast('error', err?.message || 'Failed to load certificate');
        } finally {
            setReissueLoadingId(null);
        }
    };

    const handleReissueSuccess = (message: string) => {
        showToast('success', message);
    };

    const [certStats, setCertStats] = useState<CertStats | null>(null);
    const [certStatsLoading, setCertStatsLoading] = useState(true);
    const [certStatsError, setCertStatsError] = useState<string | null>(null);

    const [caList, setCaList] = useState<any[]>([]);
    const [certsByCa, setCertsByCa] = useState<Record<string, number>>({});
    const [caLoading, setCaLoading] = useState(true);
    const [caError, setCaError] = useState<string | null>(null);

    const [groupStats, setGroupStats] = useState<GroupStats | null>(null);
    const [groupsLoading, setGroupsLoading] = useState(true);
    const [groupsError, setGroupsError] = useState<string | null>(null);

    const [pendingCount, setPendingCount] = useState<number>(0);
    const [pendingLoading, setPendingLoading] = useState(true);
    const [pendingError, setPendingError] = useState<string | null>(null);

    const [health, setHealth] = useState<HealthIndicator[]>([]);

    // Fetch certificate stats
    useEffect(() => {
        setCertStatsLoading(true);
        apiGet<any>('/api/v1/admin/certificates')
            .then((data) => {
                const items: any[] = Array.isArray(data) ? data : (data.items || []);
                const now = new Date();
                const soon = new Date();
                soon.setDate(soon.getDate() + 30);

                const stats: CertStats = { total: 0, active: 0, expiringSoon: 0, expired: 0, revoked: 0 };
                const caCount: Record<string, number> = {};

                // Use totalCount from paginated response if available
                stats.total = data.total || data.totalCount || items.length;

                for (const cert of items) {
                    const s = certStatus(cert);
                    if (s === 'revoked') stats.revoked++;
                    else if (s === 'expired') stats.expired++;
                    else {
                        stats.active++;
                        const notAfter = new Date(cert.notAfter);
                        if (notAfter <= soon) stats.expiringSoon++;
                    }

                    // Count certs per issuer, keyed BOTH ways. The CA list identifies a CA by
                    // its certificate's subject DN, while a certificate identifies its issuer by
                    // the same DN string — but some rows only carry the issuing CA's id, so index
                    // both and let the lookup below try each.
                    if (cert.issuer) caCount[cert.issuer] = (caCount[cert.issuer] || 0) + 1;
                    if (cert.issuingCaId) caCount[cert.issuingCaId] = (caCount[cert.issuingCaId] || 0) + 1;
                }

                setCertStats(stats);
                setCertsByCa(caCount);
                setCertStatsLoading(false);

                // Health: expiry warnings
                const healthItems: HealthIndicator[] = [];
                healthItems.push({
                    label: 'Database',
                    ok: true,
                    detail: 'Connected (data loaded)',
                });
                if (stats.expiringSoon > 0) {
                    healthItems.push({
                        label: 'Cert Expiry',
                        ok: false,
                        detail: `${stats.expiringSoon} certificate${stats.expiringSoon !== 1 ? 's' : ''} expiring within 30 days`,
                    });
                } else {
                    healthItems.push({
                        label: 'Cert Expiry',
                        ok: true,
                        detail: 'No certificates expiring soon',
                    });
                }
                if (stats.expired > 0) {
                    healthItems.push({
                        label: 'Expired Certs',
                        ok: false,
                        detail: `${stats.expired} expired certificate${stats.expired !== 1 ? 's' : ''}`,
                    });
                }
                setHealth(healthItems);
            })
            .catch((err) => {
                setCertStatsError(err.message || 'Failed to load certificate stats');
                setCertStatsLoading(false);
                setHealth([{ label: 'Database', ok: false, detail: 'Failed to connect' }]);
            });
    }, []);

    // Fetch CA list
    useEffect(() => {
        setCaLoading(true);
        apiGet<any>('/api/v1/admin/authorities')
            .then((data) => {
                const cas = Array.isArray(data) ? data : (data.items || data.authorities || []);
                const flat: any[] = [];
                const flatten = (list: any[]) => {
                    for (const ca of list) {
                        flat.push(ca);
                        if (ca.children) flatten(ca.children);
                    }
                };
                flatten(cas);
                setCaList(flat);
                setCaLoading(false);
            })
            .catch((err) => {
                setCaError(err.message || 'Failed to load CAs');
                setCaLoading(false);
            });
    }, []);

    // Fetch group stats
    useEffect(() => {
        setGroupsLoading(true);
        apiGet<any>('/api/v1/admin/groups')
            .then((data) => {
                const groups: any[] = Array.isArray(data) ? data : (data.items || data.groups || []);
                const system = groups.filter((g) => g.isSystem || g.type === 'System').length;
                const caScoped = groups.filter((g) => g.caId || g.certificateAuthorityId || g.type === 'CA').length;
                setGroupStats({
                    total: groups.length,
                    system,
                    caScoped,
                });
                setGroupsLoading(false);
            })
            .catch((err) => {
                setGroupsError(err.message || 'Failed to load groups');
                setGroupsLoading(false);
            });
    }, []);

    // Fetch pending requests count
    useEffect(() => {
        setPendingLoading(true);
        apiGet<any>('/api/v1/admin/requests')
            .then((data) => {
                const items: any[] = Array.isArray(data) ? data : (data.items || []);
                // "Pending" = awaiting approval; matches the Certificate Requests page's Pending bucket
                // (pending / pendingapproval / partiallyapproved / null), excluding issued ones.
                const pending = items.filter((csr: any) => {
                    if (csr.issuedCertificateId) return false;
                    const s = (csr.status || '').toLowerCase();
                    return s === '' || s === 'pending' || s === 'pendingapproval' || s === 'partiallyapproved';
                });
                setPendingCount(pending.length);
                setPendingLoading(false);
            })
            .catch((err) => {
                setPendingError(err.message || 'Failed to load requests');
                setPendingLoading(false);
            });
    }, []);

    const statCardClass = 'bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-4';
    const statLabelClass = 'text-xs font-semibold text-gray-600 dark:text-gray-400 uppercase tracking-wide';
    const statValueClass = 'text-2xl font-bold text-gray-900 dark:text-white mt-1';

    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Dashboard</h1>

            {/* System Health Indicators */}
            <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg overflow-hidden">
                <div className="px-4 py-3 border-b border-gray-300 dark:border-gray-700">
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white">System Health</h3>
                </div>
                <div className="p-4 flex flex-wrap gap-4">
                    {health.length === 0 && (
                        <span className="text-sm text-gray-600 dark:text-gray-400">Checking...</span>
                    )}
                    {health.map((h) => (
                        <div key={h.label} className="flex items-center gap-2">
                            <span className={`inline-block w-2.5 h-2.5 rounded-full ${h.ok ? 'bg-green-400' : 'bg-red-400'}`} />
                            <span className="text-sm text-gray-700 dark:text-gray-300 font-medium">{h.label}</span>
                            {h.detail && <span className="text-xs text-gray-600">{h.detail}</span>}
                        </div>
                    ))}
                </div>
            </div>

            {/* Stats Row */}
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
                <div className={statCardClass}>
                    <div className={statLabelClass}>Total Certs</div>
                    <div className={statValueClass}>
                        {certStatsLoading ? '...' : certStatsError ? '-' : certStats?.total ?? 0}
                    </div>
                </div>
                <div className={statCardClass}>
                    <div className={statLabelClass}>Active</div>
                    <div className={`${statValueClass} text-green-800 dark:text-green-400`}>
                        {certStatsLoading ? '...' : certStatsError ? '-' : certStats?.active ?? 0}
                    </div>
                </div>
                <div className={statCardClass}>
                    <div className={statLabelClass}>Expiring (30d)</div>
                    <div className={`${statValueClass} ${(certStats?.expiringSoon ?? 0) > 0 ? 'text-yellow-800 dark:text-yellow-400' : 'text-gray-900 dark:text-white'}`}>
                        {certStatsLoading ? '...' : certStatsError ? '-' : certStats?.expiringSoon ?? 0}
                    </div>
                </div>
                <div className={statCardClass}>
                    <div className={statLabelClass}>Expired</div>
                    <div className={`${statValueClass} ${(certStats?.expired ?? 0) > 0 ? 'text-yellow-800 dark:text-yellow-400' : 'text-gray-900 dark:text-white'}`}>
                        {certStatsLoading ? '...' : certStatsError ? '-' : certStats?.expired ?? 0}
                    </div>
                </div>
                <div className={statCardClass}>
                    <div className={statLabelClass}>Revoked</div>
                    <div className={`${statValueClass} ${(certStats?.revoked ?? 0) > 0 ? 'text-red-800 dark:text-red-400' : 'text-gray-900 dark:text-white'}`}>
                        {certStatsLoading ? '...' : certStatsError ? '-' : certStats?.revoked ?? 0}
                    </div>
                </div>
                <div className={statCardClass}>
                    <div className={statLabelClass}>Pending CSRs</div>
                    <div className={`${statValueClass} ${pendingCount > 0 ? 'text-blue-800 dark:text-blue-400' : 'text-gray-900 dark:text-white'}`}>
                        {pendingLoading ? '...' : pendingError ? '-' : pendingCount}
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* CA Overview */}
                <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg overflow-hidden">
                    <div className="flex items-center justify-between px-4 py-3 border-b border-gray-300 dark:border-gray-700">
                        <h3 className="text-sm font-semibold text-gray-900 dark:text-white">CA Overview</h3>
                        <button
                            onClick={() => navigate('/authorities/manage')}
                            className="text-xs text-blue-800 dark:text-blue-400 hover:text-blue-300 transition-colors"
                        >
                            View All
                        </button>
                    </div>
                    <div className="max-h-80 overflow-y-auto">
                        {caLoading && <div className="p-4 text-sm text-gray-600 dark:text-gray-400 text-center">Loading...</div>}
                        {caError && <div className="p-4 text-sm text-red-800 dark:text-red-400 text-center">{caError}</div>}
                        {!caLoading && !caError && caList.length === 0 && (
                            <div className="p-4 text-sm text-gray-600 text-center">No CAs configured</div>
                        )}
                        {!caLoading && !caError && caList.map((ca) => {
                            const caKey = ca.id || ca.serialNumber || ca.certificateId;
                            const isEnabled = ca.isEnabled !== false;
                            // GET /admin/authorities projects the CA's certificate subject as
                            // `certificateSubjectDN`, not `subjectDN`. Reading the latter yielded
                            // undefined, fell back to `ca.name` ("Test CA Root CA"), and compared
                            // it against a count map keyed by full issuer DN
                            // ("CN=Test CA Root CA,O=Test CA") — which can never match, so every
                            // CA displayed "0 certs" while the page reported 14 total.
                            const count =
                                certsByCa[ca.certificateSubjectDN] ??
                                certsByCa[ca.subjectDN] ??
                                certsByCa[ca.id] ??
                                0;

                            return (
                                <div
                                    key={caKey}
                                    className="flex items-center justify-between px-4 py-3 border-b border-gray-300 dark:border-gray-700 last:border-b-0 hover:bg-gray-200/50 dark:bg-gray-700/50 transition-colors"
                                >
                                    <div className="flex items-center gap-2 min-w-0">
                                        <StatusBadge status={isEnabled ? 'active' : 'disabled'} label={ca.isRoot ? 'Root' : 'Sub'} />
                                        <span className="text-sm text-gray-800 dark:text-gray-200 truncate">{ca.name || ca.subjectDN}</span>
                                    </div>
                                    <div className="flex items-center gap-3 flex-shrink-0">
                                        <span className="text-xs text-gray-600">{count} cert{count !== 1 ? 's' : ''}</span>
                                        <StatusBadge status={isEnabled ? 'enabled' : 'disabled'} label={isEnabled ? 'Enabled' : 'Disabled'} />
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                </div>

                {/* Group Stats */}
                <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg overflow-hidden">
                    <div className="flex items-center justify-between px-4 py-3 border-b border-gray-300 dark:border-gray-700">
                        <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Group Stats</h3>
                        <button
                            onClick={() => navigate('/groups')}
                            className="text-xs text-blue-800 dark:text-blue-400 hover:text-blue-300 transition-colors"
                        >
                            View All
                        </button>
                    </div>
                    <div className="p-4">
                        {groupsLoading && <div className="text-sm text-gray-600 dark:text-gray-400 text-center">Loading...</div>}
                        {groupsError && <div className="text-sm text-red-800 dark:text-red-400 text-center">{groupsError}</div>}
                        {!groupsLoading && !groupsError && groupStats && (
                            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-center">
                                <div>
                                    <div className="text-2xl font-bold text-gray-900 dark:text-white">{groupStats.total}</div>
                                    <div className="text-xs text-gray-600 dark:text-gray-400 mt-1">Total Groups</div>
                                </div>
                                <div>
                                    <div className="text-2xl font-bold text-blue-800 dark:text-blue-400">{groupStats.system}</div>
                                    <div className="text-xs text-gray-600 dark:text-gray-400 mt-1">System</div>
                                </div>
                                <div>
                                    <div className="text-2xl font-bold text-purple-400">{groupStats.caScoped}</div>
                                    <div className="text-xs text-gray-600 dark:text-gray-400 mt-1">CA-Scoped</div>
                                </div>
                            </div>
                        )}
                    </div>
                </div>

                {/* Recent Certificates */}
                <DataCard
                    title="Recent Certificates"
                    fetchData={async () => { const r = await apiGet<any>('/api/v1/admin/certificates?pageSize=10'); return r.items || []; }}
                    keyExtractor={(c: any) => c.serialNumber || c.certificateId}
                    onViewAll={() => navigate('/certificates')}
                    maxItems={5}
                    emptyMessage="No certificates issued yet"
                    detailMode="modal"
                    modalTitle={(cert: any) => cert.subjectDN || 'Certificate Details'}
                    modalFullViewUrl={() => '/certificates'}
                    renderSummary={(cert: any) => (
                        <div className="flex items-center gap-2">
                            <StatusBadge status={certStatus(cert)} />
                            <span className="font-mono text-xs text-gray-600 dark:text-gray-400">{cert.serialNumber?.substring(0, 12)}...</span>
                            <span className="truncate">{cert.subjectDN}</span>
                        </div>
                    )}
                    renderDetail={(cert: any) => {
                        let thumbprints = cert.thumbprints;
                        try {
                            const tp = JSON.parse(cert.thumbprints);
                            thumbprints = Object.entries(tp).map(([k, v]) => `${k}: ${v}`).join('\n');
                        } catch {}

                        let sans = '';
                        try {
                            const s = JSON.parse(cert.subjectAlternativeNamesJson || '[]');
                            sans = Array.isArray(s) ? s.join(', ') : cert.subjectAlternativeNamesJson;
                        } catch { sans = cert.subjectAlternativeNamesJson || ''; }

                        return (
                            <div className="space-y-1">
                                {cert.revoked && (
                                    <div className="bg-red-50 dark:bg-red-900/30 border border-red-300 dark:border-red-700 rounded px-3 py-2 mb-3">
                                        <StatusBadge status="revoked" label="REVOKED" />
                                        <span className="text-xs text-red-800 dark:text-red-300 ml-2">{cert.revocationReason} — {formatDate(cert.revocationDate)}</span>
                                    </div>
                                )}
                                <DetailField label="Serial" value={cert.serialNumber} mono />
                                <DetailField label="Subject" value={cert.subjectDN} />
                                <DetailField label="Issuer" value={cert.issuer} />
                                <DetailField label="Not Before" value={formatDate(cert.notBefore)} />
                                <DetailField label="Not After" value={formatDate(cert.notAfter)} />
                                <DetailField label="Is CA" value={cert.isCA ? 'Yes' : 'No'} />
                                {sans && <DetailField label="SANs" value={sans} />}
                                <DetailField label="Thumbprints" value={thumbprints} mono />
                            </div>
                        );
                    }}
                    actions={(cert: any) => [
                        ...(certStatus(cert) === 'active' ? [{
                            label: 'Revoke',
                            onClick: () => apiPostWithMfa(`/api/v1/admin/certificates/${cert.certificateId}/revoke`, { certificateId: cert.certificateId, reason: 'Unspecified' }, requireStepUp, StepUpOps.RevokeCert, cert.certificateId),
                            variant: 'danger' as const,
                            confirm: 'This will permanently revoke the certificate'
                        }] : []),
                        ...(certStatus(cert) === 'active' ? [{
                            label: reissueLoadingId === cert.certificateId ? 'Loading...' : 'Reissue',
                            onClick: () => openReissueFromCard(cert),
                            variant: 'success' as const,
                        }] : []),
                    ]}
                />

                {/* Recent Audit Logs */}
                <DataCard
                    title="Recent Activity"
                    fetchData={async () => {
                        const data = await apiGet<any>('/api/v1/admin/audit?pageSize=10');
                        return data.items || [];
                    }}
                    keyExtractor={(log: any) => log.id}
                    onViewAll={() => navigate('/audit')}
                    maxItems={10}
                    emptyMessage="No audit entries"
                    detailMode="modal"
                    modalTitle={(log: any) => `${log.actionType || 'Audit Entry'}`}
                    modalFullViewUrl={() => '/audit'}
                    renderSummary={(log: any) => (
                        <div className="flex items-center gap-2 text-xs">
                            <span className="text-gray-600 min-w-[140px]">{formatDate(log.timestamp)}</span>
                            <StatusBadge status={log.success ? 'active' : 'revoked'} label={log.success ? 'OK' : 'FAIL'} />
                            <span className="text-blue-800 dark:text-blue-300">{log.actorUsername || 'system'}</span>
                            <span className="text-gray-600 dark:text-gray-400">{log.actionType}</span>
                        </div>
                    )}
                    renderDetail={(log: any) => (
                        <div className="space-y-1">
                            <DetailField label="Action" value={log.actionType} />
                            <DetailField label="Actor" value={`${log.actorUsername || 'N/A'} (${log.actorUserId || 'N/A'})`} />
                            <DetailField label="Timestamp" value={formatDate(log.timestamp)} />
                            <DetailField label="Target" value={`${log.targetEntityType || ''} ${log.targetEntityId || ''}`} />
                            <DetailField label="Source IP" value={log.sourceIp} />
                            <DetailField label="Success" value={log.success ? 'Yes' : 'No'} />
                            <DetailField label="Error" value={log.errorMessage} />
                            {log.detailsJson && <DetailField label="Details" value={parseJsonSafe(log.detailsJson)} />}
                        </div>
                    )}
                />

                {/* Pending CSRs */}
                <DataCard
                    title="Pending Certificate Requests"
                    fetchData={async () => {
                        // /admin/requests returns ALL requests; this card must show only the ones
                        // awaiting approval, otherwise issued/approved requests appear under a "pending"
                        // badge (and look like they're all still pending).
                        const data = await apiGet<any>('/api/v1/admin/requests');
                        const items: any[] = Array.isArray(data) ? data : (data?.items || []);
                        return items.filter((csr: any) => {
                            if (csr.issuedCertificateId) return false;
                            const s = (csr.status || '').toLowerCase();
                            return s === '' || s === 'pending' || s === 'pendingapproval' || s === 'partiallyapproved';
                        });
                    }}
                    keyExtractor={(csr: any) => csr.requestId || csr.id}
                    maxItems={5}
                    emptyMessage="No pending requests"
                    detailMode="modal"
                    modalTitle={(csr: any) => csr.subjectName || 'CSR Details'}
                    modalFullViewUrl={() => '/certificates/requests'}
                    renderSummary={(csr: any) => (
                        <div className="flex items-center gap-2">
                            <StatusBadge status="pending" />
                            <span className="truncate">{csr.subjectName}</span>
                            <span className="text-xs text-gray-600">{csr.keyAlgorithm} {csr.keySize}</span>
                        </div>
                    )}
                    renderDetail={(csr: any) => (
                        <div className="space-y-1">
                            <DetailField label="Subject" value={csr.subjectName} />
                            <DetailField label="Key Algorithm" value={csr.keyAlgorithm} />
                            <DetailField label="Key Size" value={csr.keySize} />
                            <DetailField label="Signature" value={csr.signatureAlgorithm} />
                            <DetailField label="SANs" value={Array.isArray(csr.subjectAlternativeNames) ? csr.subjectAlternativeNames.join(', ') : csr.subjectAlternativeNames} />
                        </div>
                    )}
                />

                {/* Signing Profiles */}
                <DataCard
                    title="Signing Profiles"
                    fetchData={() => apiGet<any[]>('/api/v1/admin/signing-profiles')}
                    keyExtractor={(p: any) => p.id}
                    emptyMessage="No signing profiles"
                    detailMode="modal"
                    modalTitle={(p: any) => p.name || 'Signing Profile'}
                    modalFullViewUrl={() => '/profiles'}
                    renderSummary={(p: any) => (
                        <div className="flex items-center gap-2">
                            {p.isDefault && <StatusBadge status="active" label="Default" />}
                            <span className="truncate font-medium">{p.name}</span>
                        </div>
                    )}
                    renderDetail={(p: any) => (
                        <div className="space-y-1">
                            <DetailField label="Name" value={p.name} />
                            <DetailField label="Description" value={p.description} />
                            <DetailField label="Allowed Algorithms" value={parseJsonSafe(p.allowedAlgorithms)} />
                            <DetailField label="Allowed EKUs" value={parseJsonSafe(p.allowedEKUs || p.allowedEkus)} />
                            <DetailField label="Max Path Length" value={p.maxPathLength?.toString()} />
                            <DetailField label="Default" value={p.isDefault ? 'Yes' : 'No'} />
                        </div>
                    )}
                />

                {/* Certificate Profiles */}
                <DataCard
                    title="Certificate Profiles"
                    fetchData={() => apiGet<any[]>('/api/v1/admin/cert-profiles')}
                    keyExtractor={(p: any) => p.id}
                    emptyMessage="No certificate profiles"
                    detailMode="modal"
                    modalTitle={(p: any) => p.name || 'Certificate Profile'}
                    modalFullViewUrl={() => '/profiles'}
                    renderSummary={(p: any) => (
                        <div className="flex items-center gap-2">
                            <StatusBadge status={p.isCaProfile ? 'active' : 'pending'} label={p.isCaProfile ? 'CA' : 'Leaf'} />
                            <span className="truncate font-medium">{p.name}</span>
                        </div>
                    )}
                    renderDetail={(p: any) => (
                        <div className="space-y-1">
                            <DetailField label="Name" value={p.name} />
                            <DetailField label="Description" value={p.description} />
                            <DetailField label="Validity Min" value={p.validityPeriodMin} />
                            <DetailField label="Validity Max" value={p.validityPeriodMax} />
                            <DetailField label="Key Usages" value={canonicalizeUsages(parseListField(p.keyUsages), KEY_USAGE_OPTIONS).map(keyUsageLabel).join(', ')} />
                            <DetailField label="Extended Key Usages" value={canonicalizeUsages(parseListField(p.extendedKeyUsages), EKU_OPTIONS, EKU_ALIASES).map(ekuLabel).join(', ')} />
                            <DetailField label="Allowed Algorithms" value={parseJsonSafe(p.allowedKeyAlgorithms)} />
                            <DetailField label="Allowed Sizes" value={parseJsonSafe(p.allowedKeySizes)} />
                            <DetailField label="CT Enabled" value={p.ctEnabled ? 'Yes' : 'No'} />
                        </div>
                    )}
                />
            </div>

            {/* Shared Reissue Modal */}
            <CertificateReissueModal
                open={reissueOpen}
                onClose={() => setReissueOpen(false)}
                onSuccess={handleReissueSuccess}
                cert={reissueTarget}
            />
        </div>
    );
};

export default Dashboard;
