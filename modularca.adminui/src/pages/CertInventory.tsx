import React, { useState, useEffect, useMemo } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { Link } from 'react-router-dom';
import { apiGet } from '../api/client';
import { DataTable, type DataTableColumn } from '@shared/components/DataTable';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface CertItem {
    certificateId: string;
    serialNumber: string;
    subjectDN: string;
    issuer: string;
    notBefore: string;
    notAfter: string;
    validFrom: string;
    validTo: string;
    revoked: boolean;
    revocationReason: string;
    revocationDate: string | null;
    isCA: boolean;
    keyAlgorithm: string;
    keySize: string;
    signatureAlgorithm: string;
    keyUsages: string[];
    extendedKeyUsages: string[];
    thumbprints: string | null;
    subjectAlternativeNames: string[];
}

interface PaginatedResponse {
    total: number;
    totalPages: number;
    page: number;
    pageSize: number;
    items: CertItem[];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function certStatus(cert: CertItem): 'active' | 'revoked' | 'expired' {
    if (cert.revoked) return 'revoked';
    if (new Date(cert.notAfter) < new Date()) return 'expired';
    return 'active';
}

function formatDate(d: string | null): string {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
    });
}

function formatDateShort(d: string | null): string {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
    });
}

function monthKey(d: Date): string {
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
}

function monthLabel(key: string): string {
    const [y, m] = key.split('-');
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    return `${months[parseInt(m, 10) - 1]} ${y}`;
}

/** Get algorithm + key size from the certificate's parsed fields. */
function getAlgorithmInfo(cert: CertItem): { algorithm: string; keySize: string } {
    const algo = cert.keyAlgorithm || '';
    const size = cert.keySize || '';

    if (!algo) return { algorithm: 'Unknown', keySize: 'Unknown' };

    if (algo === 'RSA') return { algorithm: `RSA-${size || '?'}`, keySize: size || 'Unknown' };
    if (algo === 'ECDSA') {
        const curve = size === '256' ? 'P-256' : size === '384' ? 'P-384' : size === '521' ? 'P-521' : size;
        return { algorithm: `ECDSA-${curve}`, keySize: curve || 'Unknown' };
    }
    if (algo === 'Ed25519') return { algorithm: 'Ed25519', keySize: 'Ed25519' };
    if (algo === 'Ed448') return { algorithm: 'Ed448', keySize: 'Ed448' };

    return { algorithm: algo, keySize: size || 'Unknown' };
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

/** Color-coded stat card; with `to` it deep-links to the certificate list filtered to the same set. */
const StatCard: React.FC<{
    label: string;
    value: number;
    color: string;
    sub?: string;
    to?: string;
}> = ({ label, value, color, sub, to }) => {
    const body = (<>
        <span className="text-xs font-semibold text-gray-600 dark:text-gray-400 uppercase tracking-wide">{label}</span>
        <span className={`text-2xl font-bold mt-1 ${color}`}>{value}</span>
        {sub && <span className="text-[10px] text-gray-600 dark:text-gray-400 mt-0.5">{sub}</span>}
    </>);
    const frame = 'bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-4 flex flex-col';
    if (!to) return <div className={frame}>{body}</div>;
    return (
        <Link to={to} title="Open these certificates in the list" className={`${frame} hover:border-blue-400 dark:hover:border-blue-500 hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors`}>
            {body}
        </Link>
    );
};

/** yyyy-MM-dd for the certificate list's date filters, `days` from now. */
function isoDateFromNow(days: number): string {
    const d = new Date();
    d.setDate(d.getDate() + days);
    return d.toISOString().slice(0, 10);
}

/** Horizontal bar used in charts */
const HBar: React.FC<{
    label: string;
    count: number;
    max: number;
    total: number;
    barColor?: string;
}> = ({ label, count, max, total, barColor = 'bg-blue-500' }) => {
    const pct = max > 0 ? (count / max) * 100 : 0;
    const pctOfTotal = total > 0 ? ((count / total) * 100).toFixed(1) : '0.0';
    return (
        <div className="flex items-center gap-3 py-1">
            <span className="text-xs text-gray-700 dark:text-gray-300 w-28 truncate text-right">{label}</span>
            <div className="flex-1 h-5 bg-gray-200 dark:bg-gray-700 rounded overflow-hidden relative">
                <div className={`h-full ${barColor} rounded`} style={{ width: `${pct}%` }} />
            </div>
            <span className="text-xs text-gray-600 dark:text-gray-400 w-20 text-right tabular-nums">
                {count} ({pctOfTotal}%)
            </span>
        </div>
    );
};

/** Section wrapper */
const Section: React.FC<{ title: string; children: React.ReactNode }> = ({ title, children }) => (
    <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-gray-300 dark:border-gray-700">
            <h3 className="text-sm font-semibold text-gray-900 dark:text-white">{title}</h3>
        </div>
        <div className="p-4">{children}</div>
    </div>
);

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------

interface HealthSummary {
    averageScore: number;
    gradeDistribution: Record<string, number>;
}

const gradeColors: Record<string, string> = {
    A: 'bg-green-500',
    B: 'bg-blue-500',
    C: 'bg-yellow-500',
    D: 'bg-orange-500',
    F: 'bg-red-500',
};

const gradeLabelColors: Record<string, string> = {
    A: 'text-green-800 dark:text-green-400',
    B: 'text-blue-800 dark:text-blue-400',
    C: 'text-yellow-800 dark:text-yellow-400',
    D: 'text-orange-800 dark:text-orange-400',
    F: 'text-red-800 dark:text-red-400',
};

const CertInventory: React.FC = () => {
    const [certs, setCerts] = useState<CertItem[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [caFilter, setCaFilter] = useState<string | null>(null);
    const [healthSummary, setHealthSummary] = useState<HealthSummary | null>(null);
    const [healthLoading, setHealthLoading] = useState(true);

    // Fetch ALL certs by paginating through the API
    useEffect(() => {
        let cancelled = false;
        const fetchAll = async () => {
            setLoading(true);
            setError(null);
            try {
                const all: CertItem[] = [];
                let page = 1;
                const pageSize = 100;
                let totalPages = 1;
                while (page <= totalPages) {
                    const data = await apiGet<PaginatedResponse>(
                        `/api/v1/admin/certificates?page=${page}&pageSize=${pageSize}`
                    );
                    if (cancelled) return;
                    const items = Array.isArray(data) ? (data as any as CertItem[]) : (data.items || []);
                    all.push(...items);
                    totalPages = (data as any).totalPages ?? 1;
                    page++;
                }
                setCerts(all);
            } catch (e: any) {
                if (!cancelled) setError(errorNotice(e, 'Failed to load certificates'));
            } finally {
                if (!cancelled) setLoading(false);
            }
        };
        fetchAll();
        return () => { cancelled = true; };
    }, []);

    // Fetch health scores summary
    useEffect(() => {
        let cancelled = false;
        setHealthLoading(true);
        apiGet<HealthSummary>('/api/v1/admin/certificates/health/summary')
            .then((data) => {
                if (!cancelled) setHealthSummary(data);
            })
            .catch(() => {
                // Health scores are optional; silently ignore errors
            })
            .finally(() => {
                if (!cancelled) setHealthLoading(false);
            });
        return () => { cancelled = true; };
    }, []);

    // ----- Computed stats -----
    const filtered = useMemo(() => {
        if (!caFilter) return certs;
        return certs.filter(c => c.issuer === caFilter);
    }, [certs, caFilter]);

    const now = useMemo(() => new Date(), []);

    const stats = useMemo(() => {
        const s = { total: 0, active: 0, expiring30: 0, expiring60: 0, expiring90: 0, expired: 0, revoked: 0 };
        const d30 = new Date(now); d30.setDate(d30.getDate() + 30);
        const d60 = new Date(now); d60.setDate(d60.getDate() + 60);
        const d90 = new Date(now); d90.setDate(d90.getDate() + 90);

        for (const c of filtered) {
            s.total++;
            const st = certStatus(c);
            if (st === 'revoked') { s.revoked++; continue; }
            if (st === 'expired') { s.expired++; continue; }
            s.active++;
            const exp = new Date(c.notAfter);
            if (exp <= d30) s.expiring30++;
            else if (exp <= d60) s.expiring60++;
            else if (exp <= d90) s.expiring90++;
        }
        return s;
    }, [filtered, now]);

    // Deep link into the certificate list with the same filter a stat card counted (the list
    // reads status / notAfterFrom / notAfterTo / issuer from its URL). The CA filter here is an
    // issuer DN, which the list also filters on.
    const certListLink = (filter: { status?: string; notAfterFrom?: string; notAfterTo?: string }): string => {
        const params = new URLSearchParams();
        if (filter.status) params.set('status', filter.status);
        if (filter.notAfterFrom) params.set('notAfterFrom', filter.notAfterFrom);
        if (filter.notAfterTo) params.set('notAfterTo', filter.notAfterTo);
        if (caFilter) params.set('issuer', caFilter);
        const qs = params.toString();
        return qs ? `/certificates?${qs}` : '/certificates';
    };

    // Algorithm distribution
    const algoDist = useMemo(() => {
        const m: Record<string, number> = {};
        for (const c of filtered) {
            const { algorithm } = getAlgorithmInfo(c);
            m[algorithm] = (m[algorithm] || 0) + 1;
        }
        return Object.entries(m).sort((a, b) => b[1] - a[1]);
    }, [filtered]);

    // Key size distribution
    const keySizeDist = useMemo(() => {
        const m: Record<string, number> = {};
        for (const c of filtered) {
            const { keySize } = getAlgorithmInfo(c);
            m[keySize] = (m[keySize] || 0) + 1;
        }
        return Object.entries(m).sort((a, b) => b[1] - a[1]);
    }, [filtered]);

    // Expiry timeline (next 12 months)
    const expiryTimeline = useMemo(() => {
        const months: { key: string; label: string; count: number }[] = [];
        const cur = new Date(now.getFullYear(), now.getMonth(), 1);
        for (let i = 0; i < 12; i++) {
            const d = new Date(cur.getFullYear(), cur.getMonth() + i, 1);
            months.push({ key: monthKey(d), label: monthLabel(monthKey(d)), count: 0 });
        }
        const keys = new Set(months.map(m => m.key));
        for (const c of filtered) {
            if (certStatus(c) === 'revoked') continue;
            const exp = new Date(c.notAfter);
            const k = monthKey(exp);
            if (keys.has(k)) {
                const entry = months.find(m => m.key === k);
                if (entry) entry.count++;
            }
        }
        return months;
    }, [filtered, now]);

    const currentMonthKey = monthKey(now);
    const nextMonth = new Date(now.getFullYear(), now.getMonth() + 1, 1);
    const nextMonthKey = monthKey(nextMonth);

    // Per-CA breakdown
    const caBreakdown = useMemo(() => {
        const m: Record<string, { total: number; active: number; expiring: number; revoked: number }> = {};
        const d30 = new Date(now); d30.setDate(d30.getDate() + 30);
        for (const c of certs) {
            const issuer = c.issuer || 'Unknown';
            if (!m[issuer]) m[issuer] = { total: 0, active: 0, expiring: 0, revoked: 0 };
            m[issuer].total++;
            const st = certStatus(c);
            if (st === 'revoked') m[issuer].revoked++;
            else if (st === 'active') {
                m[issuer].active++;
                if (new Date(c.notAfter) <= d30) m[issuer].expiring++;
            }
        }
        return Object.entries(m).sort((a, b) => b[1].total - a[1].total);
    }, [certs, now]);

    // Recently issued (last 10 by validFrom)
    const recentlyIssued = useMemo(() => {
        return [...filtered]
            .sort((a, b) => new Date(b.validFrom).getTime() - new Date(a.validFrom).getTime())
            .slice(0, 10);
    }, [filtered]);

    // Recently revoked (last 10)
    const recentlyRevoked = useMemo(() => {
        return [...filtered]
            .filter(c => c.revoked && c.revocationDate)
            .sort((a, b) => new Date(b.revocationDate!).getTime() - new Date(a.revocationDate!).getTime())
            .slice(0, 10);
    }, [filtered]);

    // Max for bar charts
    const algoMax = algoDist.length > 0 ? algoDist[0][1] : 0;
    const keySizeMax = keySizeDist.length > 0 ? keySizeDist[0][1] : 0;
    const expiryMax = Math.max(...expiryTimeline.map(m => m.count), 1);

    // ----- Render -----
    if (loading) {
        return (
            <div className="p-6">
                <h1 className="text-2xl font-bold text-gray-900 dark:text-white mb-4">Certificate Inventory</h1>
                <div className="text-gray-600 dark:text-gray-400">Loading certificate data...</div>
            </div>
        );
    }

    if (error) {
        return (
            <div className="p-6">
                <h1 className="text-2xl font-bold text-gray-900 dark:text-white mb-4">Certificate Inventory</h1>
                <InlineNotice notice={error} />
            </div>
        );
    }

    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <div className="flex items-center justify-between">
                <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Certificate Inventory</h1>
                {caFilter && (
                    <button
                        onClick={() => setCaFilter(null)}
                        className="text-xs text-blue-800 dark:text-blue-400 hover:text-blue-300 border border-blue-400/40 rounded px-2 py-1"
                    >
                        Clear CA filter: {caFilter.length > 50 ? caFilter.substring(0, 50) + '...' : caFilter}
                    </button>
                )}
            </div>

            {/* 1. Summary Stats Bar. The expiry bands are exclusive (a certificate lands in exactly
                one), unlike the cumulative "within N days" rows on Compliance, so the labels say so. */}
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
                <StatCard label="Total" value={stats.total} color="text-gray-900 dark:text-white" to={certListLink({})} />
                <StatCard label="Active" value={stats.active} color="text-green-800 dark:text-green-400" to={certListLink({ status: 'active' })} />
                <StatCard label="Expiring 0–30 days" value={stats.expiring30} sub="active, expires within 30 days" color={stats.expiring30 > 0 ? 'text-red-800 dark:text-red-400' : 'text-gray-900 dark:text-white'} to={certListLink({ status: 'active', notAfterFrom: isoDateFromNow(0), notAfterTo: isoDateFromNow(30) })} />
                <StatCard label="Expiring 31–60 days" value={stats.expiring60} sub="active, not counted above" color={stats.expiring60 > 0 ? 'text-amber-800 dark:text-amber-400' : 'text-gray-900 dark:text-white'} to={certListLink({ status: 'active', notAfterFrom: isoDateFromNow(31), notAfterTo: isoDateFromNow(60) })} />
                <StatCard label="Expiring 61–90 days" value={stats.expiring90} sub="active, not counted above" color={stats.expiring90 > 0 ? 'text-yellow-800 dark:text-yellow-400' : 'text-gray-900 dark:text-white'} to={certListLink({ status: 'active', notAfterFrom: isoDateFromNow(61), notAfterTo: isoDateFromNow(90) })} />
                <StatCard label="Expired" value={stats.expired} color={stats.expired > 0 ? 'text-orange-800 dark:text-orange-400' : 'text-gray-900 dark:text-white'} to={certListLink({ status: 'expired' })} />
                <StatCard label="Revoked" value={stats.revoked} color={stats.revoked > 0 ? 'text-red-800 dark:text-red-400' : 'text-gray-900 dark:text-white'} to={certListLink({ status: 'revoked' })} />
            </div>

            {/* Health Scores */}
            {!healthLoading && healthSummary && (
                <Section title="Health Scores">
                    <div className="flex items-center gap-6">
                        <div className="flex flex-col items-center">
                            <span className="text-xs text-gray-600 dark:text-gray-400 mb-1">Average Score</span>
                            <span className={`text-3xl font-bold ${
                                healthSummary.averageScore >= 90 ? 'text-green-800 dark:text-green-400' :
                                healthSummary.averageScore >= 80 ? 'text-blue-800 dark:text-blue-400' :
                                healthSummary.averageScore >= 70 ? 'text-yellow-800 dark:text-yellow-400' :
                                healthSummary.averageScore >= 60 ? 'text-orange-800 dark:text-orange-400' :
                                'text-red-800 dark:text-red-400'
                            }`}>
                                {healthSummary.averageScore.toFixed(1)}
                            </span>
                        </div>
                        <div className="flex-1">
                            <span className="text-xs text-gray-600 dark:text-gray-400 mb-2 block">Grade Distribution</span>
                            {(() => {
                                const grades = ['A', 'B', 'C', 'D', 'F'];
                                const dist = healthSummary.gradeDistribution || {};
                                const total = grades.reduce((s, g) => s + (dist[g] || 0), 0);
                                if (total === 0) return <span className="text-sm text-gray-600">No data</span>;
                                return (
                                    <div>
                                        <div className="flex h-6 rounded overflow-hidden">
                                            {grades.map(g => {
                                                const count = dist[g] || 0;
                                                if (count === 0) return null;
                                                const pct = (count / total) * 100;
                                                return (
                                                    <div
                                                        key={g}
                                                        className={`${gradeColors[g]} flex items-center justify-center text-[10px] font-bold text-gray-900 dark:text-white`}
                                                        style={{ width: `${pct}%` }}
                                                        title={`${g}: ${count} (${pct.toFixed(1)}%)`}
                                                    >
                                                        {pct >= 8 ? g : ''}
                                                    </div>
                                                );
                                            })}
                                        </div>
                                        <div className="flex gap-4 mt-2">
                                            {grades.map(g => {
                                                const count = dist[g] || 0;
                                                if (count === 0) return null;
                                                return (
                                                    <span key={g} className="text-xs">
                                                        <span className={`font-semibold ${gradeLabelColors[g]}`}>{g}</span>
                                                        <span className="text-gray-600 dark:text-gray-400 ml-1">{count}</span>
                                                    </span>
                                                );
                                            })}
                                        </div>
                                    </div>
                                );
                            })()}
                        </div>
                    </div>
                </Section>
            )}

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* 2. Algorithm Distribution */}
                <Section title="Algorithm Distribution">
                    {algoDist.length === 0 ? (
                        <span className="text-sm text-gray-600">No data</span>
                    ) : (
                        <div className="space-y-1">
                            {algoDist.map(([algo, count]) => (
                                <HBar
                                    key={algo}
                                    label={algo}
                                    count={count}
                                    max={algoMax}
                                    total={stats.total}
                                    barColor={
                                        algo.startsWith('RSA') ? 'bg-blue-500' :
                                        algo.startsWith('ECDSA') ? 'bg-emerald-500' :
                                        algo.startsWith('Ed') ? 'bg-purple-500' :
                                        'bg-gray-500'
                                    }
                                />
                            ))}
                        </div>
                    )}
                    <p className="text-[10px] text-gray-600 mt-2">
                        Algorithm data is estimated from available certificate metadata.
                    </p>
                </Section>

                {/* 5. Key Size Distribution */}
                <Section title="Key Size Distribution">
                    {keySizeDist.length === 0 ? (
                        <span className="text-sm text-gray-600">No data</span>
                    ) : (
                        <div className="space-y-1">
                            {keySizeDist.map(([size, count]) => (
                                <HBar
                                    key={size}
                                    label={size}
                                    count={count}
                                    max={keySizeMax}
                                    total={stats.total}
                                    barColor={
                                        size.startsWith('P-') ? 'bg-emerald-500' :
                                        size === 'Ed25519' ? 'bg-purple-500' :
                                        parseInt(size) >= 4096 ? 'bg-blue-600' :
                                        parseInt(size) >= 2048 ? 'bg-blue-400' :
                                        parseInt(size) > 0 ? 'bg-amber-500' :
                                        'bg-gray-500'
                                    }
                                />
                            ))}
                        </div>
                    )}
                    <p className="text-[10px] text-gray-600 mt-2">
                        Key size data is estimated from available certificate metadata.
                    </p>
                </Section>
            </div>

            {/* 3. Expiry Timeline */}
            <Section title="Expiry Timeline (Next 12 Months)">
                {expiryTimeline.every(m => m.count === 0) ? (
                    <span className="text-sm text-gray-600">No certificates expiring in the next 12 months</span>
                ) : (
                    <div className="space-y-1">
                        {expiryTimeline.map(m => {
                            const isCurrentMonth = m.key === currentMonthKey;
                            const isNextMonth = m.key === nextMonthKey;
                            let barColor = 'bg-blue-500';
                            if (isCurrentMonth) barColor = 'bg-red-500';
                            else if (isNextMonth) barColor = 'bg-amber-500';
                            return (
                                <div key={m.key} className="flex items-center gap-3 py-1">
                                    <span className={`text-xs w-28 text-right truncate ${isCurrentMonth ? 'text-red-800 dark:text-red-400 font-semibold' : isNextMonth ? 'text-amber-800 dark:text-amber-400 font-semibold' : 'text-gray-700 dark:text-gray-300'}`}>
                                        {m.label}
                                    </span>
                                    <div className="flex-1 h-5 bg-gray-200 dark:bg-gray-700 rounded overflow-hidden">
                                        <div
                                            className={`h-full ${barColor} rounded`}
                                            style={{ width: `${expiryMax > 0 ? (m.count / expiryMax) * 100 : 0}%` }}
                                        />
                                    </div>
                                    <span className="text-xs text-gray-600 dark:text-gray-400 w-10 text-right tabular-nums">{m.count}</span>
                                </div>
                            );
                        })}
                    </div>
                )}
            </Section>

            {/* 4. Per-CA Breakdown */}
            <Section title="Per-CA Breakdown">
                {caBreakdown.length === 0 ? (
                    <span className="text-sm text-gray-600">No CA data</span>
                ) : (
                    <div className="overflow-x-auto">
                        <DataTable<[string, any]>
                            tableId="inventory-by-ca"
                            rows={caBreakdown}
                            rowKey={([issuer]) => issuer}
                            empty="No certificates"
                            sort={{ key: 'total', dir: 'desc' }}
                            columns={[
                                { key: 'ca', header: 'CA Name', flex: true, sortable: true, exportValue: ([issuer]) => issuer, render: ([issuer]) => <span className={`text-gray-800 dark:text-gray-200 truncate ${caFilter === issuer ? 'font-semibold' : ''}`} title={issuer}>{issuer}</span> },
                                { key: 'total', header: 'Total', defaultWidth: 90, align: 'right', sortable: true, sortValue: ([, d]) => d.total, exportValue: ([, d]) => d.total, render: ([, d]) => <span className="text-gray-700 dark:text-gray-300 tabular-nums">{d.total}</span> },
                                { key: 'active', header: 'Active', defaultWidth: 90, align: 'right', sortable: true, sortValue: ([, d]) => d.active, exportValue: ([, d]) => d.active, render: ([, d]) => <span className="text-green-800 dark:text-green-400 tabular-nums">{d.active}</span> },
                                { key: 'expiring', header: 'Expiring Soon', defaultWidth: 120, align: 'right', sortable: true, sortValue: ([, d]) => d.expiring, exportValue: ([, d]) => d.expiring, render: ([, d]) => <span className={`tabular-nums ${d.expiring > 0 ? 'text-amber-800 dark:text-amber-400' : 'text-gray-600'}`}>{d.expiring}</span> },
                                { key: 'revoked', header: 'Revoked', defaultWidth: 100, align: 'right', sortable: true, sortValue: ([, d]) => d.revoked, exportValue: ([, d]) => d.revoked, render: ([, d]) => <span className={`tabular-nums ${d.revoked > 0 ? 'text-red-800 dark:text-red-400' : 'text-gray-600'}`}>{d.revoked}</span> },
                                { key: 'filter', header: '', defaultWidth: 80, align: 'right', truncate: false, hideable: false, exportValue: () => '', render: ([issuer]) => (
                                    <button onClick={() => setCaFilter(caFilter === issuer ? null : issuer)} className="text-blue-800 dark:text-blue-400 hover:text-blue-300 text-[10px] underline">
                                        {caFilter === issuer ? 'Clear' : 'Filter'}
                                    </button>
                                ) },
                            ] as DataTableColumn<[string, any]>[]}
                        />
                    </div>
                )}
            </Section>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* 6. Recently Issued */}
                <Section title="Recently Issued">
                    {recentlyIssued.length === 0 ? (
                        <span className="text-sm text-gray-600">No certificates</span>
                    ) : (
                        <div className="overflow-x-auto">
                            <DataTable<any>
                                tableId="inventory-recently-issued"
                                rows={recentlyIssued}
                                rowKey={(c) => c.serialNumber}
                                empty="Nothing issued recently"
                                detailPath={(c) => `/certificates/${c.serialNumber}`}
                                columns={[
                                    { key: 'subject', header: 'Subject', flex: true, sortable: true, exportValue: (c) => c.subjectDN, render: (c) => <span className="text-gray-800 dark:text-gray-200 truncate" title={c.subjectDN}>{c.subjectDN}</span> },
                                    { key: 'serial', header: 'Serial', defaultWidth: 150, exportValue: (c) => c.serialNumber, render: (c) => <span className="font-mono text-gray-600 dark:text-gray-400 truncate" title={c.serialNumber}>{c.serialNumber.substring(0, 16)}...</span> },
                                    { key: 'issuer', header: 'Issuer', defaultWidth: 180, sortable: true, exportValue: (c) => c.issuer, render: (c) => <span className="text-gray-600 dark:text-gray-400 truncate" title={c.issuer}>{c.issuer}</span> },
                                    { key: 'issued', header: 'Issued', defaultWidth: 120, align: 'right', sortable: true, sortValue: (c) => c.validFrom ? new Date(c.validFrom) : null, exportValue: (c) => formatDateShort(c.validFrom), render: (c) => <span className="text-gray-600 dark:text-gray-400 whitespace-nowrap">{formatDateShort(c.validFrom)}</span> },
                                ] as DataTableColumn<any>[]}
                            />
                        </div>
                    )}
                </Section>

                {/* 7. Recently Revoked */}
                <Section title="Recently Revoked">
                    {recentlyRevoked.length === 0 ? (
                        <span className="text-sm text-gray-600">No revoked certificates</span>
                    ) : (
                        <div className="overflow-x-auto">
                            <DataTable<any>
                                tableId="inventory-recently-revoked"
                                rows={recentlyRevoked}
                                rowKey={(c) => c.serialNumber}
                                empty="Nothing revoked recently"
                                detailPath={(c) => `/certificates/${c.serialNumber}`}
                                columns={[
                                    { key: 'subject', header: 'Subject', flex: true, sortable: true, exportValue: (c) => c.subjectDN, render: (c) => <span className="text-gray-800 dark:text-gray-200 truncate" title={c.subjectDN}>{c.subjectDN}</span> },
                                    { key: 'serial', header: 'Serial', defaultWidth: 150, exportValue: (c) => c.serialNumber, render: (c) => <span className="font-mono text-gray-600 dark:text-gray-400 truncate" title={c.serialNumber}>{c.serialNumber.substring(0, 16)}...</span> },
                                    { key: 'reason', header: 'Reason', defaultWidth: 160, sortable: true, exportValue: (c) => c.revocationReason || 'Unspecified', render: (c) => <span className="text-red-800 dark:text-red-400">{c.revocationReason || 'Unspecified'}</span> },
                                    { key: 'revoked', header: 'Revoked', defaultWidth: 120, align: 'right', sortable: true, sortValue: (c) => c.revocationDate ? new Date(c.revocationDate) : null, exportValue: (c) => formatDateShort(c.revocationDate), render: (c) => <span className="text-gray-600 dark:text-gray-400 whitespace-nowrap">{formatDateShort(c.revocationDate)}</span> },
                                ] as DataTableColumn<any>[]}
                            />
                        </div>
                    )}
                </Section>
            </div>
        </div>
    );
};

export default CertInventory;
