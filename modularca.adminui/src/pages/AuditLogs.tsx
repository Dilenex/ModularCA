import React, { useState, useEffect } from 'react';
import { apiGet } from '../api/client';
import StatusBadge from '../components/cards/StatusBadge';
import DetailField from '../components/cards/DetailField';
import { DataTable, DataTableColumn } from '../components/DataTable';

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

/// Renders the ACME `identifiers` field, which arrives either as a JSON array of
/// {type,value} objects (order/issuance events) or a plain domain string (challenge events).
function formatIdentifiers(raw: any): string {
    if (!raw) return '';
    if (typeof raw !== 'string') return String(raw);
    const s = raw.trim();
    if (s.startsWith('[')) {
        try {
            const arr = JSON.parse(s);
            if (Array.isArray(arr)) {
                return arr.map((i: any) => (typeof i === 'string' ? i : (i.value ?? i.Value ?? ''))).filter(Boolean).join(', ');
            }
        } catch { /* not JSON — fall through to raw */ }
    }
    return s;
}

const TABS = ['General', 'EST', 'SCEP', 'CMP', 'ACME', 'Network'] as const;
type Tab = typeof TABS[number];

type Category = 'general' | 'protocol' | 'network';
function tabCategory(tab: Tab): Category {
    if (tab === 'General') return 'general';
    if (tab === 'Network') return 'network';
    return 'protocol';
}

const okFailBadge = (log: any) => <StatusBadge status={log.success ? 'active' : 'revoked'} label={log.success ? 'OK' : 'FAIL'} />;
const networkBadge = (log: any) =>
    log.blocked ? <StatusBadge status="revoked" label="BLOCKED" />
        : log.statusCode >= 400 ? <StatusBadge status="expired" label={`${log.statusCode}`} />
            : <StatusBadge status="active" label={`${log.statusCode ?? 'OK'}`} />;

/// <summary>
/// Builds the DataTable columns for the active audit tab. General (app), protocol (EST/SCEP/CMP/ACME)
/// and network entries have distinct shapes, so each gets a tailored column set.
/// </summary>
function buildColumns(tab: Tab): DataTableColumn<any>[] {
    const cat = tabCategory(tab);
    const timeCol: DataTableColumn<any> = { key: 'time', header: 'Timestamp', defaultWidth: 170, minWidth: 140, exportValue: (l) => formatDate(l.timestamp), render: (l) => <span className="text-xs text-gray-600 dark:text-gray-400">{formatDate(l.timestamp)}</span> };

    if (cat === 'network') {
        return [
            timeCol,
            { key: 'status', header: 'Status', defaultWidth: 100, truncate: false, exportValue: (l) => (l.blocked ? 'BLOCKED' : String(l.statusCode ?? '')), render: networkBadge },
            { key: 'sourceIp', header: 'Source IP', defaultWidth: 130, exportValue: (l) => l.sourceIp || '', render: (l) => <span className={`font-mono text-xs ${l.blocked ? 'text-red-800 dark:text-red-300' : 'text-gray-700 dark:text-gray-300'}`}>{l.sourceIp}</span> },
            { key: 'method', header: 'Method', defaultWidth: 90, exportValue: (l) => l.httpMethod || '', render: (l) => <span className="text-xs text-gray-600 dark:text-gray-400 font-medium">{l.httpMethod}</span> },
            { key: 'path', header: 'Request Path', defaultWidth: 220, exportValue: (l) => l.requestPath || '', render: (l) => <span className="text-xs text-gray-600 dark:text-gray-400 truncate">{l.requestPath}</span> },
            { key: 'protocol', header: 'Protocol', defaultWidth: 100, truncate: false, exportValue: (l) => l.protocol || '', render: (l) => l.protocol ? <StatusBadge status="pending" label={l.protocol} /> : <span className="text-xs text-gray-500">-</span> },
            { key: 'caLabel', header: 'CA', defaultWidth: 120, exportValue: (l) => l.caLabel || '', render: (l) => <span className="text-xs text-gray-600 dark:text-gray-400 truncate">{l.caLabel || '-'}</span> },
        ];
    }

    if (cat === 'protocol') {
        // ACME identifies subjects by domain (identifiers), not Subject DN — which is empty
        // for everything but issuance. Swap in an Identifiers column so ACME rows are legible.
        const subjectOrIdentifiers: DataTableColumn<any> = tab === 'ACME'
            ? { key: 'identifiers', header: 'Identifiers', defaultWidth: 240, exportValue: (l) => formatIdentifiers(l.identifiers) || l.subjectDN || '', render: (l) => { const v = formatIdentifiers(l.identifiers) || l.subjectDN; return <span className="text-xs text-gray-600 dark:text-gray-400 truncate">{v || '-'}</span>; } }
            : { key: 'subjectDN', header: 'Subject DN', defaultWidth: 220, exportValue: (l) => l.subjectDN || '', render: (l) => <span className="text-xs text-gray-600 dark:text-gray-400 truncate">{l.subjectDN || '-'}</span> };
        return [
            timeCol,
            { key: 'status', header: 'Status', defaultWidth: 90, truncate: false, exportValue: (l) => (l.success ? 'OK' : 'FAIL'), render: okFailBadge },
            { key: 'operation', header: 'Operation', defaultWidth: 170, exportValue: (l) => l.operation || l.messageType || '', render: (l) => <span className="text-xs text-gray-700 dark:text-gray-300">{l.operation || l.messageType || '-'}</span> },
            subjectOrIdentifiers,
            { key: 'serial', header: 'Serial', defaultWidth: 140, exportValue: (l) => l.certificateSerial || '', render: (l) => <span className="font-mono text-xs text-gray-600 dark:text-gray-400 truncate">{l.certificateSerial || '-'}</span> },
            { key: 'caLabel', header: 'CA', defaultWidth: 120, exportValue: (l) => l.caLabel || '', render: (l) => <span className="text-xs text-gray-600 dark:text-gray-400 truncate">{l.caLabel || '-'}</span> },
        ];
    }

    // general (app)
    return [
        timeCol,
        { key: 'status', header: 'Status', defaultWidth: 90, truncate: false, exportValue: (l) => (l.success ? 'OK' : 'FAIL'), render: okFailBadge },
        { key: 'actor', header: 'Actor', defaultWidth: 150, exportValue: (l) => l.actorUsername || 'system', render: (l) => <span className="text-xs text-blue-800 dark:text-blue-300 truncate">{l.actorUsername || 'system'}</span> },
        { key: 'action', header: 'Action', defaultWidth: 190, exportValue: (l) => l.actionType || '', render: (l) => <span className="text-xs text-gray-700 dark:text-gray-300 truncate">{l.actionType}</span> },
        { key: 'target', header: 'Target', defaultWidth: 180, exportValue: (l) => `${l.targetEntityType || ''}${l.targetEntityId ? ` #${l.targetEntityId}` : ''}`, render: (l) => <span className="text-xs text-gray-600 dark:text-gray-400 truncate">{l.targetEntityType} {l.targetEntityId ? `#${String(l.targetEntityId).substring(0, 8)}` : ''}</span> },
        { key: 'sourceIp', header: 'Source IP', defaultWidth: 130, exportValue: (l) => l.sourceIp || '', render: (l) => <span className="font-mono text-xs text-gray-600 dark:text-gray-400">{l.sourceIp || '-'}</span> },
    ];
}

/* read-only drawer — dumps every populated field (DetailField hides null/empty) */
const AuditDrawer: React.FC<{ log: any }> = ({ log }) => (
    <div className="text-sm">
        <DetailField label="Timestamp" value={formatDate(log.timestamp)} />
        {Object.entries(log).filter(([k]) => k.toLowerCase() !== 'timestamp').map(([k, v]) => (
            <DetailField key={k} label={k} value={v == null ? '' : (typeof v === 'object' ? JSON.stringify(v) : String(v))} mono={typeof v === 'object' || /id$|serial|hash|ip$/i.test(k)} />
        ))}
    </div>
);

const AuditLogs: React.FC = () => {
    const [activeTab, setActiveTab] = useState<Tab>('General');
    const [logs, setLogs] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [page, setPage] = useState(1);
    const [totalPages, setTotalPages] = useState(1);
    const [dateFrom, setDateFrom] = useState('');
    const [dateTo, setDateTo] = useState('');
    const [filterCaId, setFilterCaId] = useState('');
    const [filterActionType, setFilterActionType] = useState('');
    const [filterUser, setFilterUser] = useState('');
    const [authorities, setAuthorities] = useState<any[]>([]);
    const [knownActionTypes, setKnownActionTypes] = useState<string[]>([]);
    const pageSize = 25;

    // Fetch CAs for the filter dropdown
    useEffect(() => {
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
                setAuthorities(flat);
            })
            .catch(() => {
                // Non-critical — filter just won't show CAs
            });
    }, []);

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError(null);

        const params = new URLSearchParams({ page: String(page), pageSize: String(pageSize) });
        if (dateFrom) params.set('from', dateFrom);
        if (dateTo) params.set('to', dateTo);
        if (filterCaId) params.set('caId', filterCaId);
        if (filterActionType) params.set('actionType', filterActionType);
        if (filterUser) params.set('user', filterUser);

        const path = activeTab === 'General'
            ? `/api/v1/admin/audit?${params}`
            : `/api/v1/admin/audit/${activeTab.toLowerCase()}?${params}`;

        apiGet<any>(path)
            .then((data) => {
                if (cancelled) return;
                const items = Array.isArray(data) ? data : (data.items || []);
                const total = data.totalPages || Math.ceil((data.totalCount || items.length) / pageSize) || 1;
                setLogs(items);
                setTotalPages(total);
                setLoading(false);

                // Collect unique action types for the filter dropdown
                if (activeTab === 'General') {
                    const types = new Set(knownActionTypes);
                    for (const log of items) {
                        if (log.actionType) types.add(log.actionType);
                    }
                    const sorted = Array.from(types).sort();
                    if (sorted.length !== knownActionTypes.length) {
                        setKnownActionTypes(sorted);
                    }
                }
            })
            .catch((err) => {
                if (!cancelled) {
                    setError(err.message || 'Failed to load audit logs');
                    setLoading(false);
                }
            });

        return () => { cancelled = true; };
    }, [activeTab, page, dateFrom, dateTo, filterCaId, filterActionType, filterUser]);

    const handleTabChange = (tab: Tab) => {
        setActiveTab(tab);
        setPage(1);
    };

    const columns = buildColumns(activeTab);

    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Audit Logs</h1>

            {/* Tabs */}
            <div className="flex gap-1 border-b border-gray-300 dark:border-gray-700">
                {TABS.map((tab) => (
                    <button
                        key={tab}
                        onClick={() => handleTabChange(tab)}
                        className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 ${activeTab === tab
                            ? 'text-blue-800 dark:text-blue-400 border-blue-400'
                            : 'text-gray-600 dark:text-gray-400 border-transparent hover:text-gray-700 dark:text-gray-300'
                            }`}
                    >
                        {tab}
                    </button>
                ))}
            </div>

            {/* CA Filter & Date Range Filters */}
            <div className="flex flex-wrap gap-4 items-center">
                <div className="flex items-center gap-2">
                    <label className="text-xs text-gray-600 dark:text-gray-400">CA:</label>
                    <select
                        value={filterCaId}
                        onChange={(e) => { setFilterCaId(e.target.value); setPage(1); }}
                        className="px-3 py-2 bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500"
                    >
                        <option value="">All CAs</option>
                        {authorities.map((ca) => (
                            <option key={ca.id} value={ca.id}>{ca.label || ca.commonName || ca.id}</option>
                        ))}
                    </select>
                </div>
                <div className="flex items-center gap-2">
                    <label className="text-xs text-gray-600 dark:text-gray-400">From:</label>
                    <input
                        type="date"
                        value={dateFrom}
                        onChange={(e) => { setDateFrom(e.target.value); setPage(1); }}
                        className="px-3 py-2 bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500"
                    />
                </div>
                <div className="flex items-center gap-2">
                    <label className="text-xs text-gray-600 dark:text-gray-400">To:</label>
                    <input
                        type="date"
                        value={dateTo}
                        onChange={(e) => { setDateTo(e.target.value); setPage(1); }}
                        className="px-3 py-2 bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500"
                    />
                </div>
                {activeTab === 'General' && (
                    <div className="flex items-center gap-2">
                        <label className="text-xs text-gray-600 dark:text-gray-400">Action:</label>
                        <select
                            value={filterActionType}
                            onChange={(e) => { setFilterActionType(e.target.value); setPage(1); }}
                            className="px-3 py-2 bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500"
                        >
                            <option value="">All Actions</option>
                            {knownActionTypes.map((t) => (
                                <option key={t} value={t}>{t}</option>
                            ))}
                        </select>
                    </div>
                )}
                <div className="flex items-center gap-2">
                    <label className="text-xs text-gray-600 dark:text-gray-400">User:</label>
                    <input
                        type="text"
                        value={filterUser}
                        onChange={(e) => { setFilterUser(e.target.value); setPage(1); }}
                        placeholder="Username"
                        className="px-3 py-2 bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:border-blue-500 w-36"
                    />
                </div>
                {(dateFrom || dateTo || filterCaId || filterActionType || filterUser) && (
                    <button
                        onClick={() => { setDateFrom(''); setDateTo(''); setFilterCaId(''); setFilterActionType(''); setFilterUser(''); setPage(1); }}
                        className="text-xs text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors"
                    >
                        Clear filters
                    </button>
                )}
            </div>

            <DataTable<any>
                tableId={`audit-${activeTab.toLowerCase()}`}
                title={`${activeTab} Audit Logs`}
                rows={logs}
                rowKey={(l) => l.id || `${l.timestamp}-${l.actionType || l.operation || l.messageType || ''}`}
                loading={loading}
                error={error}
                empty="No audit entries found"
                columns={columns}
                selectable
                exportFileName={`audit-${activeTab.toLowerCase()}`}
                renderDrawer={(l) => <AuditDrawer log={l} />}
                drawerTitle={(l) => l.actionType || l.operation || l.messageType || (l.requestPath ? `${l.httpMethod} ${l.requestPath}` : 'Audit entry')}
                detailPath={(l) => `/audit/${activeTab.toLowerCase()}/${l.id}`}
            />

            {/* Pagination */}
            {totalPages > 1 && (
                <div className="flex items-center justify-center gap-4">
                    <button
                        onClick={() => setPage((p) => Math.max(1, p - 1))}
                        disabled={page <= 1}
                        className="px-3 py-1 text-sm bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-700 disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                        Previous
                    </button>
                    <span className="text-sm text-gray-600 dark:text-gray-400">Page {page} of {totalPages}</span>
                    <button
                        onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                        disabled={page >= totalPages}
                        className="px-3 py-1 text-sm bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-700 disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                        Next
                    </button>
                </div>
            )}
        </div>
    );
};

export default AuditLogs;
