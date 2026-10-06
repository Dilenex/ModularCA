import React, { useState, useEffect } from 'react';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { Link, useNavigate } from 'react-router-dom';
import { apiGet, apiPost, apiPostWithMfa } from '../api/client';
import { useScope } from '../context/ScopeContext';
import { useStepUp } from '../components/StepUpMfaContext';
import DataCard from '../components/cards/DataCard';
import { StatusBadge, Tag } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import { actionButton } from '@shared/components/actionButtons';
import { StructuredValue } from '@shared/components/StructuredValue';
import CertificateReissueModal from '../components/CertificateReissueModal';
import ConfirmModal from '../components/ConfirmModal';
import { REVOCATION_REASONS, RevocationReasonHint } from './CertificateDetail';
import { useToast } from '@shared/context/ToastContext';
import type { NoticeInput, NoticeSeverity } from '@shared/notifications/notice';
import { StepUpOps } from '@shared/generated';
import {
    canonicalizeUsages, parseListField, keyUsageLabel,
    KEY_USAGE_OPTIONS, CeilingList,
} from './profileHelpers';
import { AlgorithmSummary, KeyPolicySummary } from './profiles/KeyPolicyEditor';
import { useEkuCatalog } from '../hooks/useOidCatalog';
import type { CertificateLifecycleSummaryModel } from '@shared/generated';
import {
    attentionTone, capitalize, channelLabel, expiringLink, expiryPhrase, isoDay, lifecycleHealth, sortAttention,
    toneDotClass, toneTextClass, type LifecycleHealthItem,
} from './certLifecycle';
import { periodText } from '@shared/periodText';

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function certStatus(cert: any): 'active' | 'revoked' | 'expired' {
    if (cert.revoked) return 'revoked';
    if (new Date(cert.notAfter) < new Date()) return 'expired';
    return 'active';
}

/** CAs listed on the dashboard card; the rest are one link away. */
const CAS_SHOWN = 8;

interface GroupStats {
    total: number;
    system: number;
    caScoped: number;
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
    // Extended key usages come from the OID catalog, not a hardcoded list — see useEkuCatalog.
    const ekuCatalog = useEkuCatalog();
    const navigate = useNavigate();
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();

    // Reissue modal state
    const { caId: scopeCaId, inScope, caQuery } = useScope();

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

    // Quick revoke from the Recent Certificates card. It used to fire with a hardcoded
    // "Unspecified" reason behind a two-click confirm; the reason is a permanent, published
    // fact about the certificate, so the operator chooses it here with the same picker and
    // explanation the certificate page uses.
    const [quickRevoke, setQuickRevoke] = useState<any | null>(null);
    const [quickRevokeReason, setQuickRevokeReason] = useState('Unspecified');
    const [quickRevokeBusy, setQuickRevokeBusy] = useState(false);
    const [recentCertsKey, setRecentCertsKey] = useState(0);

    const runQuickRevoke = async () => {
        if (!quickRevoke) return;
        setQuickRevokeBusy(true);
        try {
            await apiPostWithMfa(`/api/v1/admin/certificates/${quickRevoke.certificateId}/revoke`,
                { certificateId: quickRevoke.certificateId, reason: quickRevokeReason },
                requireStepUp, StepUpOps.RevokeCert, quickRevoke.certificateId);
            showToast('success', quickRevokeReason === 'CertificateHold'
                ? 'Certificate placed on hold. Lift it from the certificate page if it turns out to be fine.'
                : 'Certificate revoked.');
            setQuickRevoke(null);
            setRecentCertsKey((k) => k + 1);
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Revocation failed');
        } finally {
            setQuickRevokeBusy(false);
        }
    };

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

    // Attention items carry no SANs, so the reissue form is filled from the full certificate.
    const openReissueForSerial = async (serial: string) => {
        setReissueLoadingId(serial);
        try {
            const full = await apiGet<any>(`/api/v1/admin/certificates/${encodeURIComponent(serial)}`);
            setReissueTarget({
                id: full.certificateId,
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

    // Takes the severity the modal reports rather than assuming success: a reissue can come back
    // with a diagnostic saying the certificate is not what was asked for, and that is not green.
    const handleReissueSuccess = (message: NoticeInput, severity?: NoticeSeverity) => {
        showToast(severity ?? 'success', message);
        setSummaryKey((k) => k + 1);
    };

    const [summary, setSummary] = useState<CertificateLifecycleSummaryModel | null>(null);
    const [certStatsLoading, setCertStatsLoading] = useState(true);
    const [certStatsError, setCertStatsError] = useState<string | null>(null);
    const [summaryKey, setSummaryKey] = useState(0);

    const [caList, setCaList] = useState<any[]>([]);
    const [caLoading, setCaLoading] = useState(true);
    const [caError, setCaError] = useState<NoticeInput | null>(null);

    const [groupStats, setGroupStats] = useState<GroupStats | null>(null);
    const [groupsLoading, setGroupsLoading] = useState(true);
    const [groupsError, setGroupsError] = useState<NoticeInput | null>(null);

    const [pendingCount, setPendingCount] = useState<number>(0);
    const [pendingLoading, setPendingLoading] = useState(true);
    const [pendingError, setPendingError] = useState<string | null>(null);

    // Counts come from the lifecycle summary, which counts every certificate in scope on the
    // server; the certificate list is paged, so counting one page was wrong past a page's worth.
    useEffect(() => {
        let cancelled = false;
        setCertStatsLoading(true);
        setCertStatsError(null);
        apiGet<CertificateLifecycleSummaryModel>(`/api/v1/admin/certificates/lifecycle-summary${caQuery()}`)
            .then((data) => { if (!cancelled) { setSummary(data); setCertStatsLoading(false); } })
            .catch((err) => { if (!cancelled) { setCertStatsError(err.message || 'Failed to load certificate stats'); setCertStatsLoading(false); } });
        return () => { cancelled = true; };
    }, [caQuery, summaryKey]);

    const now = new Date();
    const certsByCa: Record<string, number> = {};
    for (const c of summary?.byCa ?? []) certsByCa[c.caId] = c.total;
    const health: LifecycleHealthItem[] = summary
        ? [{ key: 'database', label: 'Database', tone: 'ok', detail: 'Connected', to: '' }, ...lifecycleHealth(summary, now)]
        : [];
    const attention = summary ? sortAttention(summary.attention, now) : [];

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
                setCaList(flat.filter((ca) => inScope(ca.id || ca.caId)));
                setCaLoading(false);
            })
            .catch((err) => {
                setCaError(errorNotice(err, 'Failed to load CAs'));
                setCaLoading(false);
            });
    }, [scopeCaId]); // eslint-disable-line react-hooks/exhaustive-deps

    // Fetch group stats
    useEffect(() => {
        setGroupsLoading(true);
        apiGet<any>('/api/v1/admin/groups')
            .then((data) => {
                const all: any[] = Array.isArray(data) ? data : (data.items || data.groups || []);
                // Under a CA scope, count that CA's groups only.
                const groups = scopeCaId ? all.filter((g) => inScope(g.certificateAuthorityId || g.caId)) : all;
                const system = groups.filter((g) => g.isSystemGroup).length;
                const caScoped = groups.filter((g) => g.caId || g.certificateAuthorityId || g.type === 'CA').length;
                setGroupStats({
                    total: groups.length,
                    system,
                    caScoped,
                });
                setGroupsLoading(false);
            })
            .catch((err) => {
                setGroupsError(errorNotice(err, 'Failed to load groups'));
                setGroupsLoading(false);
            });
    }, [scopeCaId]); // eslint-disable-line react-hooks/exhaustive-deps

    // Fetch pending requests count
    useEffect(() => {
        setPendingLoading(true);
        apiGet<any>(`/api/v1/admin/requests${caQuery()}`)
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
    }, [scopeCaId]); // eslint-disable-line react-hooks/exhaustive-deps

    const statCardClass = 'bg-raised border border-line rounded-lg p-4';
    const statLabelClass = 'text-xs font-semibold text-ink-muted uppercase tracking-wide';
    const statValueClass = 'text-2xl font-bold text-ink mt-1';
    const statLinkClass = `${statCardClass} block hover:bg-hover transition-colors`;
    const stat = (n: number | undefined) => (certStatsLoading ? '...' : certStatsError ? '-' : n ?? 0);
    const loudText = (t: string) => (t === 'crit' || t === 'warn' ? toneTextClass(t) : 'text-ink');
    const expiredTone = health.find((h) => h.key === 'expired')?.tone ?? 'neutral';
    const expiringTone = summary && summary.expiringWithin30DaysNotReplaced > 0
        ? (summary.expiringWithin7DaysNotReplaced > 0 ? 'crit' : 'warn')
        : 'neutral';

    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <h1 className="text-xl font-semibold text-ink">Dashboard</h1>

            {/* System Health Indicators */}
            <div className="bg-raised border border-line rounded-lg overflow-hidden">
                <div className="px-4 py-3 border-b border-line">
                    <h3 className="text-sm font-semibold text-ink">System Health</h3>
                </div>
                <div className="p-4 flex flex-wrap gap-4">
                    {health.length === 0 && !certStatsError && (
                        <span className="text-sm text-ink-muted">Checking...</span>
                    )}
                    {certStatsError && (
                        <div className="flex items-center gap-2">
                            <span className="inline-block w-2.5 h-2.5 rounded-full bg-crit" />
                            <span className="text-sm text-ink font-medium">Database</span>
                            <span className="text-xs text-ink-muted">{certStatsError}</span>
                        </div>
                    )}
                    {health.map((h) => {
                        const body = (<>
                            <span className={`inline-block w-2.5 h-2.5 rounded-full ${toneDotClass(h.tone)}`} aria-hidden="true" />
                            <span className="text-sm text-ink font-medium">{h.label}</span>
                            <span className={`text-xs ${h.tone === 'ok' || h.tone === 'neutral' ? 'text-ink-muted' : toneTextClass(h.tone)}`}>{h.detail}</span>
                        </>);
                        return h.to ? (
                            <Link key={h.key} to={h.to} className="flex items-center gap-2 rounded px-1 -mx-1 hover:bg-hover transition-colors">{body}</Link>
                        ) : (
                            <div key={h.key} className="flex items-center gap-2">{body}</div>
                        );
                    })}
                </div>
            </div>

            {/* Stats Row */}
            <div className="grid grid-cols-2 md:grid-cols-4 2xl:grid-cols-7 gap-4">
                <Link to="/certificates" className={statLinkClass}>
                    <div className={statLabelClass}>Total Certs</div>
                    <div className={statValueClass}>{stat(summary?.total)}</div>
                </Link>
                <Link to="/certificates?status=active" className={statLinkClass}>
                    <div className={statLabelClass}>Active</div>
                    <div className={`${statValueClass} text-ok`}>{stat(summary?.active)}</div>
                </Link>
                <Link to={summary && summary.expiringWithin30DaysNotReplaced === 0 ? `/certificates?status=active&notAfterTo=${isoDay(new Date(now.getTime() + 31 * 86_400_000))}` : expiringLink(30, now)} className={statLinkClass}>
                    <div className={statLabelClass}>Expiring (30d)</div>
                    <div className={`${statValueClass} ${loudText(expiringTone)}`}>{stat(summary?.expiringWithin30Days)}</div>
                    {summary && summary.expiringWithin30Days > 0 && (
                        <div className="text-xs text-ink-muted mt-0.5">{summary.expiringWithin30DaysNotReplaced} not replaced</div>
                    )}
                </Link>
                <Link to="/certificates?status=expired" className={statLinkClass}
                    title={summary ? `Replacement is checked for certificates that expired in the last ${summary.replacementWindowDays} days.` : undefined}>
                    <div className={statLabelClass}>Expired</div>
                    <div className={`${statValueClass} ${loudText(expiredTone)}`}>{stat(summary?.expired)}</div>
                    {summary && summary.expired > 0 && (
                        <div className="text-xs text-ink-muted mt-0.5">{summary.expiredNotReplaced} not replaced</div>
                    )}
                </Link>
                <Link to="/certificates?status=revoked" className={statLinkClass}>
                    <div className={statLabelClass}>Revoked</div>
                    <div className={`${statValueClass} ${(summary?.revoked ?? 0) > 0 ? 'text-crit' : 'text-ink'}`}>{stat(summary?.revoked)}</div>
                </Link>
                <div className={statCardClass}>
                    <div className={statLabelClass}>Pending CSRs</div>
                    <div className={`${statValueClass} ${pendingCount > 0 ? 'text-accent-ink' : 'text-ink'}`}>
                        {pendingLoading ? '...' : pendingError ? '-' : pendingCount}
                    </div>
                </div>
                <Link to="/groups" className={statLinkClass}>
                    <div className={statLabelClass}>Groups</div>
                    <div className={statValueClass}>{groupsLoading ? '...' : groupsError || !groupStats ? '-' : groupStats.total}</div>
                    {groupStats && !groupsError && (
                        <div className="text-xs text-ink-muted mt-0.5">{groupStats.system} system · {groupStats.caScoped} CA-scoped</div>
                    )}
                </Link>
            </div>

            {/* Needs attention: recently expired or soon expiring, with no replacement */}
            <div className="bg-raised border border-line rounded-lg overflow-hidden">
                <div className="flex items-center justify-between px-4 py-3 border-b border-line">
                    <h3 className="text-sm font-semibold text-ink">Needs attention</h3>
                    {summary && summary.attentionTotal > attention.length && (
                        <span className="text-xs text-ink-muted">Showing {attention.length} of {summary.attentionTotal}</span>
                    )}
                </div>
                {certStatsLoading && <div className="p-4 text-sm text-ink-muted text-center">Loading...</div>}
                {!certStatsLoading && summary && attention.length === 0 && (
                    <div className="px-4 py-6 text-center">
                        <div className="text-sm text-ink font-medium">Nothing needs attention</div>
                        <div className="text-xs text-ink-muted mt-1">No certificate expired in the last 30 days or expires in the next 30 without a replacement.</div>
                    </div>
                )}
                {!certStatsLoading && attention.length > 0 && (
                    <ul className="divide-y divide-line max-h-96 overflow-y-auto">
                        {attention.map((item) => {
                            const tone = attentionTone(item, now);
                            const channel = channelLabel(item.issuanceChannel);
                            return (
                                <li key={item.certificateId} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2.5">
                                    <span className={`inline-block w-2 h-2 rounded-full flex-shrink-0 ${toneDotClass(tone)}`} aria-hidden="true" />
                                    <div className="min-w-0 flex-1">
                                        <div className="flex flex-wrap items-baseline gap-x-2">
                                            <Link to={`/certificates/${item.serialNumber}`} className="text-sm text-ink font-medium truncate hover:underline">{item.commonName}</Link>
                                            <span className={`text-xs font-medium ${toneTextClass(tone)}`} title={new Date(item.notAfter).toLocaleString()}>
                                                {capitalize(expiryPhrase(item.notAfter, now))}
                                            </span>
                                        </div>
                                        <div className="flex flex-wrap items-center gap-x-2 text-xs text-ink-muted">
                                            <span>{item.caLabel || item.caName || 'Unknown CA'}</span>
                                            {channel && <span className="px-1.5 py-px rounded-sm border border-line bg-sunken text-ink-muted">{channel}</span>}
                                            {item.renewalPending && <span>Renewal request pending</span>}
                                            {item.autoRenewal === true && !item.renewalPending && <span>Auto-renewal on</span>}
                                        </div>
                                    </div>
                                    <div className="flex items-center gap-2 flex-shrink-0">
                                        <Link to={`/certificates/${item.serialNumber}`} className={actionButton}>View</Link>
                                        <button onClick={() => openReissueForSerial(item.serialNumber)} disabled={reissueLoadingId === item.serialNumber}
                                            className={actionButton}>
                                            {reissueLoadingId === item.serialNumber ? 'Loading...' : 'Reissue'}
                                        </button>
                                    </div>
                                </li>
                            );
                        })}
                    </ul>
                )}
                {summary && summary.attentionTotal > attention.length && (
                    <div className="px-4 py-2 border-t border-line text-xs">
                        <Link to="/certificates?status=expired&replaced=no" className="text-accent-ink hover:underline">Expired, not replaced</Link>
                        <span className="text-ink-muted"> · </span>
                        <Link to={expiringLink(30, now)} className="text-accent-ink hover:underline">Expiring within 30 days, not replaced</Link>
                    </div>
                )}
            </div>

            {/* Two independent columns: a card is as tall as its content, never stretched to its neighbour. */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
                <div className="space-y-6">
                    {/* CA Overview */}
                    <div className="bg-raised border border-line rounded-lg overflow-hidden">
                        <div className="flex items-center justify-between px-4 py-3 border-b border-line">
                            <h3 className="text-sm font-semibold text-ink">CA Overview</h3>
                            <button
                                onClick={() => navigate('/authorities/manage')}
                                className="text-xs text-accent-ink hover:underline transition-colors"
                            >
                                View All
                            </button>
                        </div>
                        <div>
                            {caLoading && <div className="p-4 text-sm text-ink-muted text-center">Loading...</div>}
                            {caError && <InlineNotice notice={caError} />}
                            {!caLoading && !caError && caList.length === 0 && (
                                <div className="p-4 text-sm text-ink-muted text-center">No CAs configured</div>
                            )}
                            {!caLoading && !caError && caList.slice(0, CAS_SHOWN).map((ca) => {
                                const caKey = ca.id || ca.serialNumber || ca.certificateId;
                                const isEnabled = ca.isEnabled !== false;
                                const count = certsByCa[ca.id || ca.caId] ?? 0;

                                return (
                                    <div
                                        key={caKey}
                                        className="flex items-center justify-between px-4 py-3 border-b border-line last:border-b-0 hover:bg-hover bg-sunken transition-colors"
                                    >
                                        <div className="flex items-center gap-2 min-w-0">
                                            <Tag label={ca.isRoot ? 'Root' : 'Sub'} />
                                            <span className="text-sm text-ink truncate">{ca.name || ca.subjectDN}</span>
                                        </div>
                                        <div className="flex items-center gap-3 flex-shrink-0">
                                            <span className="text-xs text-ink-muted">{count} cert{count !== 1 ? 's' : ''}</span>
                                            <StatusBadge status={isEnabled ? 'enabled' : 'disabled'} label={isEnabled ? 'Enabled' : 'Disabled'} />
                                        </div>
                                    </div>
                                );
                            })}
                            {!caLoading && !caError && caList.length > CAS_SHOWN && (
                                <div className="px-4 py-2 text-xs border-t border-line">
                                    <Link to="/authorities/manage" className="text-accent-ink hover:underline">{caList.length - CAS_SHOWN} more</Link>
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Recent Certificates */}
                    <DataCard
                        key={`recent-${scopeCaId ?? "all"}-${recentCertsKey}`}
                        title="Recent Certificates"
                        fetchData={async () => { const r = await apiGet<any>(`/api/v1/admin/certificates?pageSize=10${caQuery(true)}`); return r.items || []; }}
                        keyExtractor={(c: any) => c.serialNumber || c.certificateId}
                        onViewAll={() => navigate('/certificates')}
                        maxItems={5}
                        emptyMessage="No certificates issued yet"
                        detailMode="modal"
                        modalTitle={(cert: any) => cert.subjectDN || 'Certificate Details'}
                        modalFullViewUrl={() => '/certificates'}
                        renderSummary={(cert: any) => (
                            <div className="flex items-center gap-2">
                                {certStatus(cert) === 'expired' && cert.replaced
                                    ? <StatusBadge status="disabled" label="expired" />
                                    : <StatusBadge status={certStatus(cert)} />}
                                <span className="data-mono text-ink-muted">{cert.serialNumber?.substring(0, 12)}...</span>
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
                                        <div className="bg-crit-soft border border-crit/40 rounded px-3 py-2 mb-3">
                                            <StatusBadge status="revoked" label="Revoked" />
                                            <span className="text-xs text-crit ml-2">{cert.revocationReason} — {formatDate(cert.revocationDate)}</span>
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
                                // Opens the reason picker below; the card's own modal closes on click.
                                onClick: () => { setQuickRevokeReason('Unspecified'); setQuickRevoke(cert); },
                                variant: 'danger' as const,
                            }] : []),
                            ...(certStatus(cert) === 'active' ? [{
                                label: reissueLoadingId === cert.certificateId ? 'Loading...' : 'Reissue',
                                onClick: () => openReissueFromCard(cert),
                                variant: 'primary' as const,
                            }] : []),
                        ]}
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
                        onViewAll={() => navigate('/profiles')}
                        renderSummary={(p: any) => (
                            <div className="flex items-center gap-2">
                                {p.isDefault && <Tag label="Default" tone="accent" />}
                                <span className="truncate font-medium">{p.name}</span>
                            </div>
                        )}
                        renderDetail={(p: any) => (
                            <div className="space-y-1">
                                <DetailField label="Name" value={p.name} />
                                <DetailField label="Description" value={p.description} />
                                <div className="py-1"><span className="text-xs text-ink-muted">Allowed Algorithms</span><AlgorithmSummary items={p.allowedAlgorithms} /></div>
                                <div className="py-1"><span className="text-xs text-ink-muted">Allowed EKUs</span><CeilingList items={p.allowedEKUs || p.allowedEkus} noun="EKU" /></div>
                                <DetailField label="Max Path Length" value={p.maxPathLength?.toString()} />
                                <DetailField label="Default" value={p.isDefault ? 'Yes' : 'No'} />
                            </div>
                        )}
                    />
                </div>
                <div className="space-y-6">
                    {/* Recent Audit Logs */}
                    <DataCard
                        key={`recent-${scopeCaId ?? "all"}`}
                        title="Recent Activity"
                        fetchData={async () => {
                            const data = await apiGet<any>(`/api/v1/admin/audit?pageSize=10${caQuery(true)}`);
                            return data.items || [];
                        }}
                        keyExtractor={(log: any) => log.id}
                        onViewAll={() => navigate('/audit')}
                        maxItems={8}
                        emptyMessage="No audit entries"
                        detailMode="modal"
                        modalTitle={(log: any) => `${log.actionType || 'Audit Entry'}`}
                        modalFullViewUrl={() => '/audit'}
                        renderSummary={(log: any) => (
                            <div className="flex items-center gap-2 text-xs">
                                <span className="text-ink-muted min-w-[140px]">{formatDate(log.timestamp)}</span>
                                <StatusBadge status={log.success ? 'active' : 'revoked'} label={log.success ? 'OK' : 'Failed'} />
                                <span className="text-accent-ink">{log.actorUsername || 'system'}</span>
                                <span className="text-ink-muted">{log.actionType}</span>
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
                                {log.detailsJson && (
                                    <div className="py-1">
                                        <span className="label-caps">Details</span>
                                        <StructuredValue className="mt-1" json={log.detailsJson} />
                                    </div>
                                )}
                            </div>
                        )}
                    />

                    {/* Pending CSRs */}
                    <DataCard
                        key={`pending-${scopeCaId ?? "all"}`}
                        title="Pending Certificate Requests"
                        fetchData={async () => {
                            // /admin/requests returns ALL requests; this card must show only the ones
                            // awaiting approval, otherwise issued/approved requests appear under a "pending"
                            // badge (and look like they're all still pending).
                            const data = await apiGet<any>(`/api/v1/admin/requests${caQuery()}`);
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
                                <span className="text-xs text-ink-muted">{csr.keyAlgorithm} {csr.keySize}</span>
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

                    {/* Certificate Profiles */}
                    <DataCard
                        title="Certificate Profiles"
                        fetchData={() => apiGet<any[]>('/api/v1/admin/cert-profiles')}
                        keyExtractor={(p: any) => p.id}
                        emptyMessage="No certificate profiles"
                        detailMode="modal"
                        modalTitle={(p: any) => p.name || 'Certificate Profile'}
                        modalFullViewUrl={() => '/profiles'}
                        onViewAll={() => navigate('/profiles')}
                        renderSummary={(p: any) => (
                            <div className="flex items-center gap-2">
                                <Tag label={p.isCaProfile ? 'CA' : 'Leaf'} />
                                <span className="truncate font-medium">{p.name}</span>
                            </div>
                        )}
                        renderDetail={(p: any) => (
                            <div className="space-y-1">
                                <DetailField label="Name" value={p.name} />
                                <DetailField label="Description" value={p.description} />
                                <DetailField label="Validity Min" value={periodText(p.validityPeriodMin)} />
                                <DetailField label="Validity Max" value={periodText(p.validityPeriodMax)} />
                                <DetailField label="Key Usages" value={canonicalizeUsages(parseListField(p.keyUsages), KEY_USAGE_OPTIONS).map(keyUsageLabel).join(', ')} />
                                <DetailField label="Extended Key Usages" value={canonicalizeUsages(parseListField(p.extendedKeyUsages), ekuCatalog.options, ekuCatalog.aliases).map(ekuCatalog.label).join(', ')} />
                                <div className="py-1"><span className="text-xs text-ink-muted">Keys and signatures</span><KeyPolicySummary algorithms={p.allowedKeyAlgorithms} sizes={p.allowedKeySizes} signatures={p.allowedSignatureAlgorithms} /></div>
                                <DetailField label="CT Enabled" value={p.ctEnabled ? 'Yes' : 'No'} />
                            </div>
                        )}
                    />
                </div>
            </div>

            {/* Shared Reissue Modal */}
            <CertificateReissueModal
                open={reissueOpen}
                onClose={() => setReissueOpen(false)}
                onSuccess={handleReissueSuccess}
                cert={reissueTarget}
            />

            {/* Quick revoke — same reason picker and explanation as the certificate page */}
            <ConfirmModal
                isOpen={!!quickRevoke}
                title="Revoke Certificate"
                confirmLabel={quickRevokeReason === 'CertificateHold' ? 'Place on hold' : 'Revoke'}
                loading={quickRevokeBusy}
                onConfirm={runQuickRevoke}
                onCancel={() => setQuickRevoke(null)}
                message={quickRevoke ? (
                    <div className="space-y-3 text-left">
                        <div className="text-xs text-ink-muted">
                            <div className="break-all"><span className="font-semibold text-ink">Subject:</span> {quickRevoke.subjectDN}</div>
                            <div className="font-mono break-all"><span className="font-sans font-semibold text-ink">Serial:</span> {quickRevoke.serialNumber}</div>
                        </div>
                        <div>
                            <label htmlFor="dashboard-revoke-reason" className="block text-xs text-ink-muted mb-1">Revocation reason</label>
                            <select id="dashboard-revoke-reason" value={quickRevokeReason} onChange={(e) => setQuickRevokeReason(e.target.value)} disabled={quickRevokeBusy}
                                className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-sm text-ink focus:outline-none focus:border-accent disabled:opacity-50">
                                {REVOCATION_REASONS.map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}
                            </select>
                            <RevocationReasonHint reason={quickRevokeReason} />
                        </div>
                    </div>
                ) : ''}
            />
        </div>
    );
};

export default Dashboard;
