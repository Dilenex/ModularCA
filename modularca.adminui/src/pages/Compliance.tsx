import React, { useState, useEffect, useCallback } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { Chevron } from '@shared/components/Chevron';
import { apiGet, apiPost, apiBlob } from '../api/client';
import { DataTable, type DataTableColumn } from '@shared/components/DataTable';
import { useToast } from '@shared/context/ToastContext';
import { FieldHint } from '@shared/components/forms';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface AlgorithmDistributionEntry {
    algorithm: string;
    keySize: string;
    count: number;
}

interface ExpiryForecast {
    within30Days: number;
    within60Days: number;
    within90Days: number;
    within180Days: number;
    within365Days: number;
}

interface IssuanceHistoryEntry {
    serialNumber: string;
    subjectDN: string;
    issuer: string;
    notBefore: string;
    notAfter: string;
}

interface RevocationHistoryEntry {
    serialNumber: string;
    subjectDN: string;
    issuer: string;
    revocationDate: string;
    revocationReason: string;
}

// The report still carries a static vulnerabilitySummary, but the merged page
// renders the live, interactive findings section instead — so it's omitted here.
interface ComplianceReport {
    generatedAt: string;
    fromDate: string;
    toDate: string;
    caId: string | null;
    inventory: {
        total: number;
        active: number;
        expired: number;
        revoked: number;
    };
    algorithmDistribution: AlgorithmDistributionEntry[];
    expiryForecast: ExpiryForecast;
    issuanceHistory: IssuanceHistoryEntry[];
    revocationHistory: RevocationHistoryEntry[];
}

interface VulnerabilitySummary {
    critical: number;
    warning: number;
    info: number;
    resolved: number;
}

interface Vulnerability {
    id: string;
    severity: 'Critical' | 'Warning' | 'Info';
    type: string;
    description: string;
    certificateSerial: string;
    certificateId: string;
    detectedAt: string;
    resolvedAt: string | null;
    resolved: boolean;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatDate(d: string | null): string {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
    });
}

function formatDateTime(d: string | null): string {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
    });
}

function toISODate(d: Date): string {
    return d.toISOString().split('T')[0];
}

function severityColor(severity: string): string {
    switch (severity) {
        case 'Critical': return 'bg-crit text-on-accent';
        case 'Warning': return 'bg-warn text-on-accent';
        case 'Info': return 'bg-info text-on-accent';
        default: return 'bg-sunken text-ink-muted';
    }
}

function truncate(text: string, max: number): string {
    if (!text) return '-';
    return text.length > max ? text.substring(0, max) + '...' : text;
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

const Section: React.FC<{ title: string; children: React.ReactNode; right?: React.ReactNode }> = ({ title, children, right }) => (
    <div className="bg-raised border border-line rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-line flex items-center justify-between">
            <h3 className="text-sm font-semibold text-ink">{title}</h3>
            {right}
        </div>
        <div className="p-4">{children}</div>
    </div>
);

const StatCard: React.FC<{
    label: string;
    value: number | string;
    color: string;
}> = ({ label, value, color }) => (
    <div className="bg-raised border border-line rounded-lg p-4 flex flex-col">
        <span className="text-xs font-semibold text-ink-muted uppercase tracking-wide">{label}</span>
        <span className={`text-2xl font-bold mt-1 ${color}`}>{value}</span>
    </div>
);

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------

const Compliance: React.FC = () => {
    const { showToast } = useToast();

    // --- Live compliance report (inventory / algorithms / expiry / history) ---
    const [report, setReport] = useState<ComplianceReport | null>(null);
    const [reportLoading, setReportLoading] = useState(true);
    const [reportError, setReportError] = useState<NoticeInput | null>(null);

    // --- Live vulnerability findings (interactive) ---
    const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
    const [vulnSummary, setVulnSummary] = useState<VulnerabilitySummary>({ critical: 0, warning: 0, info: 0, resolved: 0 });
    const [vulnLoading, setVulnLoading] = useState(true);
    const [vulnError, setVulnError] = useState<NoticeInput | null>(null);
    const [severityFilter, setSeverityFilter] = useState<string>('all');
    const [typeFilter, setTypeFilter] = useState<string>('all');
    const [showResolved, setShowResolved] = useState(false);
    const [resolvingIds, setResolvingIds] = useState<Set<string>>(new Set());

    // --- Export controls (scope the downloaded CSV report only) ---
    const defaultTo = new Date();
    const defaultFrom = new Date();
    defaultFrom.setDate(defaultFrom.getDate() - 30);
    const [dateFrom, setDateFrom] = useState(toISODate(defaultFrom));
    const [dateTo, setDateTo] = useState(toISODate(defaultTo));
    const [caFilter, setCaFilter] = useState('');
    const [exporting, setExporting] = useState(false);

    // History sections on-screen use a fixed default window (last 30 days). The
    // export range/CA inputs above only affect the downloaded CSV, per the merged
    // page's design — inventory/algorithm/expiry are current-state regardless.
    const loadReport = useCallback(async () => {
        setReportLoading(true);
        setReportError(null);
        try {
            const data = await apiPost<ComplianceReport>('/api/v1/admin/compliance/report', {
                fromDate: toISODate(defaultFrom),
                toDate: toISODate(defaultTo),
            });
            setReport(data);
        } catch (e: any) {
            setReportError(errorNotice(e, 'Failed to load compliance data'));
        } finally {
            setReportLoading(false);
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    const loadVulnerabilities = useCallback(async () => {
        setVulnLoading(true);
        setVulnError(null);
        try {
            const [vulnsResp, sum] = await Promise.all([
                apiGet<{ items?: Vulnerability[] } | Vulnerability[]>('/api/v1/admin/compliance?includeResolved=true'),
                apiGet<VulnerabilitySummary>('/api/v1/admin/compliance/summary'),
            ]);
            const items = Array.isArray(vulnsResp) ? vulnsResp : (vulnsResp?.items ?? []);
            setVulnerabilities(items);
            setVulnSummary(sum);
        } catch (e: any) {
            setVulnError(errorNotice(e, 'Failed to load findings'));
        } finally {
            setVulnLoading(false);
        }
    }, []);

    useEffect(() => {
        loadReport();
        loadVulnerabilities();
    }, [loadReport, loadVulnerabilities]);

    const handleResolve = async (id: string) => {
        setResolvingIds(prev => new Set(prev).add(id));
        try {
            await apiPost(`/api/v1/admin/compliance/${id}/resolve`);
            await loadVulnerabilities();
        } catch (e: any) {
            showToast('error', e.message || 'Failed to resolve finding');
        } finally {
            setResolvingIds(prev => {
                const next = new Set(prev);
                next.delete(id);
                return next;
            });
        }
    };

    // An inverted range is accepted by the server and yields a CSV with no history rows at all.
    const rangeInverted = !!(dateFrom && dateTo && dateFrom > dateTo);

    const handleExportCsv = async () => {
        if (rangeInverted) { showToast('warning', 'The "from" date is after the "to" date; the export would contain no history.'); return; }
        setExporting(true);
        try {
            const body: any = { fromDate: dateFrom, toDate: dateTo };
            if (caFilter.trim()) body.caId = caFilter.trim();

            const resp = await apiBlob('/api/v1/admin/compliance/export/csv', {
                method: 'POST',
                body: JSON.stringify(body),
            });

            const blob = await resp.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `compliance-report-${dateFrom}-to-${dateTo}.csv`;
            a.click();
            URL.revokeObjectURL(url);
        } catch (e: any) {
            showToast('error', e.message || 'CSV export failed');
        } finally {
            setExporting(false);
        }
    };

    // Derived vulnerability view
    const uniqueTypes = Array.from(new Set(vulnerabilities.map(v => v.type))).sort();
    const filteredVulns = vulnerabilities.filter(v => {
        if (!showResolved && v.resolved) return false;
        if (severityFilter !== 'all' && v.severity !== severityFilter) return false;
        if (typeFilter !== 'all' && v.type !== typeFilter) return false;
        return true;
    });

    // Algorithm distribution chart data
    const algoEntries = report?.algorithmDistribution ?? [];
    const algoMax = algoEntries.length > 0 ? Math.max(...algoEntries.map(e => e.count)) : 0;
    const algoTotal = algoEntries.reduce((s, e) => s + e.count, 0);

    // Expiry forecast entries
    const forecastEntries = report ? [
        { label: '30 days', count: report.expiryForecast.within30Days },
        { label: '60 days', count: report.expiryForecast.within60Days },
        { label: '90 days', count: report.expiryForecast.within90Days },
        { label: '180 days', count: report.expiryForecast.within180Days },
        { label: '365 days', count: report.expiryForecast.within365Days },
    ] : [];
    const forecastMax = forecastEntries.length > 0 ? Math.max(...forecastEntries.map(e => e.count), 1) : 1;

    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <div className="flex items-start justify-between gap-4 flex-wrap">
                <div>
                    <h1 className="text-xl font-semibold text-ink">Compliance</h1>
                    <p className="text-sm text-ink-muted mt-1">
                        Live certificate posture — inventory, algorithms, findings, and expiry. Export a point-in-time report below.
                    </p>
                </div>
            </div>

            {/* Export panel — scopes the downloaded CSV only */}
            <div className="bg-raised border border-line rounded-lg p-4">
                <div className="flex flex-wrap gap-4 items-end">
                    <div className="flex flex-col gap-1">
                        <label className="text-xs text-ink-muted">Export from</label>
                        <input
                            type="date"
                            value={dateFrom}
                            max={dateTo || undefined}
                            onChange={(e) => setDateFrom(e.target.value)}
                            className={`px-3 py-2 bg-raised border rounded text-sm text-ink focus:outline-none focus:border-accent ${rangeInverted ? 'border-warn' : 'border-line-strong'}`}
                        />
                    </div>
                    <div className="flex flex-col gap-1">
                        <label className="text-xs text-ink-muted">Export to</label>
                        <input
                            type="date"
                            value={dateTo}
                            min={dateFrom || undefined}
                            onChange={(e) => setDateTo(e.target.value)}
                            className={`px-3 py-2 bg-raised border rounded text-sm text-ink focus:outline-none focus:border-accent ${rangeInverted ? 'border-warn' : 'border-line-strong'}`}
                        />
                    </div>
                    <div className="flex flex-col gap-1">
                        <label className="text-xs text-ink-muted">CA Filter (optional)</label>
                        <input
                            type="text"
                            placeholder="CA ID..."
                            value={caFilter}
                            onChange={(e) => setCaFilter(e.target.value)}
                            className="px-3 py-2 bg-raised border border-line-strong rounded text-sm text-ink placeholder-ink-faint focus:outline-none focus:border-accent min-w-[200px]"
                        />
                    </div>
                    <button
                        onClick={handleExportCsv}
                        disabled={exporting || rangeInverted}
                        title={rangeInverted ? 'The "from" date is after the "to" date' : undefined}
                        className="px-4 py-2 text-sm bg-ok-soft text-ok border border-ok/40 rounded hover:bg-ok/15 transition-colors disabled:opacity-50"
                    >
                        {exporting ? 'Exporting...' : 'Export Report (CSV)'}
                    </button>
                    <span className="text-[11px] text-ink-muted self-center">
                        Issuance/revocation history in the export is bounded by this range.
                    </span>
                </div>
                {rangeInverted && (
                    <FieldHint tone="warn" className="mt-2">The "from" date is later than the "to" date, so the range contains no days and the export would hold no issuance or revocation history. Swap the two dates.</FieldHint>
                )}
            </div>

            {/* Report load error */}
            {reportError && (
                <InlineNotice notice={reportError} />
            )}

            {/* Inventory Summary */}
            <div>
                <h2 className="text-sm font-semibold text-ink mb-3 uppercase tracking-wide">Inventory Summary</h2>
                {reportLoading ? (
                    <div className="text-ink-muted text-sm">Loading inventory...</div>
                ) : (
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                        <StatCard label="Total" value={report?.inventory.total ?? 0} color="text-ink" />
                        <StatCard label="Active" value={report?.inventory.active ?? 0} color="text-ok" />
                        <StatCard label="Expired" value={report?.inventory.expired ?? 0} color="text-warn" />
                        <StatCard label="Revoked" value={report?.inventory.revoked ?? 0} color="text-crit" />
                    </div>
                )}
            </div>

            {/* Algorithm Distribution */}
            <Section title="Algorithm Distribution">
                {reportLoading ? (
                    <span className="text-sm text-ink-muted">Loading...</span>
                ) : algoEntries.length === 0 ? (
                    <span className="text-sm text-ink-muted">No data</span>
                ) : (
                    <div className="space-y-1">
                        {algoEntries.map((entry) => {
                            const pct = algoMax > 0 ? (entry.count / algoMax) * 100 : 0;
                            const pctOfTotal = algoTotal > 0 ? ((entry.count / algoTotal) * 100).toFixed(1) : '0.0';
                            const label = entry.keySize ? `${entry.algorithm} ${entry.keySize}` : entry.algorithm;
                            return (
                                <div key={label} className="flex items-center gap-3 py-1">
                                    <span className="text-xs text-ink w-36 truncate text-right">{label}</span>
                                    <div className="flex-1 h-5 bg-sunken rounded overflow-hidden">
                                        <div className="h-full bg-accent rounded" style={{ width: `${pct}%` }} />
                                    </div>
                                    <span className="text-xs text-ink-muted w-20 text-right tabular-nums">
                                        {entry.count} ({pctOfTotal}%)
                                    </span>
                                </div>
                            );
                        })}
                    </div>
                )}
            </Section>

            {/* Expiry Forecast */}
            <Section title="Expiry Forecast">
                {reportLoading ? (
                    <span className="text-sm text-ink-muted">Loading...</span>
                ) : (
                    <div className="space-y-1">
                        {/* Cumulative buckets: a certificate expiring in 20 days is counted in every row. The
                            inventory page uses exclusive bands (0–30, 31–60, 61–90), so the two pages word
                            their labels differently on purpose. */}
                        <p className="text-[11px] text-ink-muted mb-1">Each row is cumulative: "within 90 days" includes everything already counted within 30 and 60 days.</p>
                        {forecastEntries.map(item => {
                            const pct = forecastMax > 0 ? (item.count / forecastMax) * 100 : 0;
                            return (
                                <div key={item.label} className="flex items-center gap-3 py-1">
                                    <span className="text-xs text-ink w-28 text-right">Within {item.label}</span>
                                    <div className="flex-1 h-5 bg-sunken rounded overflow-hidden">
                                        <div className="h-full bg-warn rounded" style={{ width: `${pct}%` }} />
                                    </div>
                                    <span className="text-xs text-ink-muted w-10 text-right tabular-nums">{item.count}</span>
                                </div>
                            );
                        })}
                    </div>
                )}
            </Section>

            {/* Compliance findings — live interactive */}
            <div className="space-y-3">
                <h2 className="text-sm font-semibold text-ink uppercase tracking-wide">Findings</h2>

                {vulnError && (
                    <InlineNotice notice={vulnError} />
                )}

                {/* Summary cards */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    <StatCard label="Critical" value={vulnSummary.critical} color="text-crit" />
                    <StatCard label="Warning" value={vulnSummary.warning} color="text-warn" />
                    <StatCard label="Info" value={vulnSummary.info} color="text-accent-ink" />
                    <StatCard label="Resolved" value={vulnSummary.resolved} color="text-ok" />
                </div>

                {/* Filters */}
                <div className="flex flex-wrap gap-4 items-center">
                    <select
                        value={severityFilter}
                        onChange={(e) => setSeverityFilter(e.target.value)}
                        className="px-3 py-2 bg-raised border border-line-strong rounded text-sm text-ink focus:outline-none focus:border-accent"
                    >
                        <option value="all">All Severities</option>
                        <option value="Critical">Critical</option>
                        <option value="Warning">Warning</option>
                        <option value="Info">Info</option>
                    </select>

                    <select
                        value={typeFilter}
                        onChange={(e) => setTypeFilter(e.target.value)}
                        className="px-3 py-2 bg-raised border border-line-strong rounded text-sm text-ink focus:outline-none focus:border-accent"
                    >
                        <option value="all">All Types</option>
                        {uniqueTypes.map(t => (
                            <option key={t} value={t}>{t}</option>
                        ))}
                    </select>

                    <label className="flex items-center gap-2 text-sm text-ink cursor-pointer">
                        <input
                            type="checkbox"
                            checked={showResolved}
                            onChange={(e) => setShowResolved(e.target.checked)}
                            className="rounded bg-raised border-line-strong text-accent-ink focus:ring-accent focus:ring-offset-0"
                        />
                        Show resolved
                    </label>
                </div>

                {/* Findings table */}
                <div className="bg-raised border border-line rounded-lg overflow-hidden">
                    <div className="px-4 py-2.5 border-b border-line flex items-center justify-between">
                        <h3 className="text-sm font-semibold text-ink">Findings</h3>
                        <span className="text-xs text-ink-muted">{filteredVulns.length} {filteredVulns.length === 1 ? 'finding' : 'findings'}</span>
                    </div>

                    <div className="overflow-auto max-h-[28rem]">
                        <DataTable<any>
                            tableId="compliance-findings"
                            rows={filteredVulns}
                            rowKey={(v) => v.id}
                            loading={vulnLoading}
                            empty="No findings"
                            sort={{ key: 'detected', dir: 'desc' }}
                            renderExpanded={(v) => (
                                <div className="space-y-2">
                                    <div>
                                        <span className="text-xs font-semibold text-ink-muted">Full Description</span>
                                        <p className="text-sm text-ink mt-1">{v.description}</p>
                                    </div>
                                    <div className="flex gap-6 flex-wrap">
                                        <div>
                                            <span className="text-xs font-semibold text-ink-muted">Type</span>
                                            <p className="text-sm text-ink mt-1">{v.type}</p>
                                        </div>
                                        <div>
                                            <span className="text-xs font-semibold text-ink-muted">Severity</span>
                                            <p className="text-sm text-ink mt-1">{v.severity}</p>
                                        </div>
                                        <div>
                                            <span className="text-xs font-semibold text-ink-muted">Detected</span>
                                            <p className="text-sm text-ink mt-1">{formatDateTime(v.detectedAt)}</p>
                                        </div>
                                        {v.resolvedAt && (
                                            <div>
                                                <span className="text-xs font-semibold text-ink-muted">Resolved</span>
                                                <p className="text-sm text-ok mt-1">{formatDateTime(v.resolvedAt)}</p>
                                            </div>
                                        )}
                                    </div>
                                    {v.certificateId && (
                                        <div>
                                            <span className="text-xs font-semibold text-ink-muted">Certificate</span>
                                            <p className="text-sm mt-1">
                                                <a href={`/admin/certificates?search=${encodeURIComponent(v.certificateSerial || v.certificateId)}`} className="text-accent-ink hover:underline underline font-mono">
                                                    {v.certificateSerial || v.certificateId}
                                                </a>
                                            </p>
                                        </div>
                                    )}
                                </div>
                            )}
                            columns={[
                                { key: 'severity', header: 'Severity', defaultWidth: 100, truncate: false, sortable: true, exportValue: (v) => v.severity, render: (v) => <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-semibold ${severityColor(v.severity)}`}>{v.severity}</span> },
                                { key: 'type', header: 'Type', defaultWidth: 150, sortable: true, exportValue: (v) => v.type, render: (v) => <span className={`text-ink whitespace-nowrap ${v.resolved ? 'opacity-60' : ''}`}>{v.type}</span> },
                                { key: 'description', header: 'Description', flex: true, exportValue: (v) => v.description, render: (v) => <span className={`text-ink-muted truncate ${v.resolved ? 'opacity-60' : ''}`} title={v.description}>{truncate(v.description, 80)}</span> },
                                { key: 'certificate', header: 'Certificate', defaultWidth: 150, exportValue: (v) => v.certificateSerial || '', render: (v) => <span className="font-mono text-ink-muted truncate" title={v.certificateSerial}>{v.certificateSerial ? v.certificateSerial.substring(0, 16) + '…' : '—'}</span> },
                                { key: 'detected', header: 'Detected', defaultWidth: 160, sortable: true, sortValue: (v) => v.detectedAt ? new Date(v.detectedAt) : null, exportValue: (v) => formatDateTime(v.detectedAt), render: (v) => <span className="text-ink-muted whitespace-nowrap">{formatDateTime(v.detectedAt)}</span> },
                                { key: 'actions', header: '', defaultWidth: 110, align: 'right', truncate: false, hideable: false, exportValue: (v) => (v.resolved ? 'Resolved' : ''), render: (v) => v.resolved
                                    ? <span className="text-[10px] text-ok">✓ Resolved</span>
                                    : <button onClick={() => handleResolve(v.id)} disabled={resolvingIds.has(v.id)} className="px-2 py-1 text-[10px] font-medium text-ok bg-ok-soft border border-ok/40 rounded hover:bg-ok/15 transition-colors disabled:opacity-50">{resolvingIds.has(v.id) ? 'Resolving…' : 'Resolve'}</button> },
                            ] as DataTableColumn<any>[]}
                        />
                    </div>
                </div>
            </div>

            {/* Issuance / Revocation history (last 30 days) */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <Section title="Recent Issuances (30d)">
                    {reportLoading ? (
                        <span className="text-sm text-ink-muted">Loading...</span>
                    ) : (!report?.issuanceHistory || report.issuanceHistory.length === 0) ? (
                        <span className="text-sm text-ink-muted">No recent issuances</span>
                    ) : (
                        <div className="overflow-x-auto">
                            <DataTable<any>
                                tableId="compliance-issuance-history"
                                rows={report.issuanceHistory}
                                rowKey={(c, ) => `${c.serialNumber || ''}-${c.notBefore || ''}-${c.subjectDN || ''}`}
                                empty="No issuance in this period"
                                columns={[
                                    { key: 'subject', header: 'Subject', flex: true, sortable: true, exportValue: (c) => c.subjectDN, render: (c) => <span className="text-ink truncate" title={c.subjectDN}>{c.subjectDN}</span> },
                                    { key: 'serial', header: 'Serial', defaultWidth: 150, exportValue: (c) => c.serialNumber || '', render: (c) => <span className="font-mono text-ink-muted truncate" title={c.serialNumber}>{c.serialNumber ? c.serialNumber.substring(0, 16) + '...' : '-'}</span> },
                                    { key: 'issuer', header: 'Issuer', defaultWidth: 180, sortable: true, exportValue: (c) => c.issuer, render: (c) => <span className="text-ink-muted truncate" title={c.issuer}>{c.issuer}</span> },
                                    { key: 'validFrom', header: 'Valid From', defaultWidth: 160, align: 'right', sortable: true, sortValue: (c) => c.notBefore ? new Date(c.notBefore) : null, exportValue: (c) => formatDateTime(c.notBefore), render: (c) => <span className="text-ink-muted whitespace-nowrap">{formatDateTime(c.notBefore)}</span> },
                                ] as DataTableColumn<any>[]}
                            />
                        </div>
                    )}
                </Section>

                <Section title="Recent Revocations (30d)">
                    {reportLoading ? (
                        <span className="text-sm text-ink-muted">Loading...</span>
                    ) : (!report?.revocationHistory || report.revocationHistory.length === 0) ? (
                        <span className="text-sm text-ink-muted">No recent revocations</span>
                    ) : (
                        <div className="overflow-x-auto">
                            <DataTable<any>
                                tableId="compliance-revocation-history"
                                rows={report.revocationHistory}
                                rowKey={(c) => `${c.serialNumber || ''}-${c.revocationDate || ''}-${c.subjectDN || ''}`}
                                empty="No revocations in this period"
                                columns={[
                                    { key: 'subject', header: 'Subject', flex: true, sortable: true, exportValue: (c) => c.subjectDN, render: (c) => <span className="text-ink truncate" title={c.subjectDN}>{c.subjectDN}</span> },
                                    { key: 'serial', header: 'Serial', defaultWidth: 150, exportValue: (c) => c.serialNumber || '', render: (c) => <span className="font-mono text-ink-muted truncate" title={c.serialNumber}>{c.serialNumber ? c.serialNumber.substring(0, 16) + '...' : '-'}</span> },
                                    { key: 'reason', header: 'Reason', defaultWidth: 160, sortable: true, exportValue: (c) => c.revocationReason || 'Unspecified', render: (c) => <span className="text-crit">{c.revocationReason || 'Unspecified'}</span> },
                                    { key: 'revoked', header: 'Revoked', defaultWidth: 160, align: 'right', sortable: true, sortValue: (c) => c.revocationDate ? new Date(c.revocationDate) : null, exportValue: (c) => formatDateTime(c.revocationDate), render: (c) => <span className="text-ink-muted whitespace-nowrap">{formatDateTime(c.revocationDate)}</span> },
                                ] as DataTableColumn<any>[]}
                            />
                        </div>
                    )}
                </Section>
            </div>
        </div>
    );
};

export default Compliance;
