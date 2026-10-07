import React, { useState, useEffect, useRef } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { errorNotice } from '@shared-auth/api/notices';
import { apiGet } from '../api/client';
import { useScope } from '../context/ScopeContext';
import { FilterBar, FilterField, filterControlClass } from '@shared/components/FilterBar';
import { scopeLabel } from '../scope';
import { StatusBadge, Tag } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import { AuditFields } from '../components/AuditFields';
import { DataTable, DataTableColumn } from '@shared/components/DataTable';
import { useTableQuery } from '@shared/hooks/useTableQuery';
import { formatSort, parseSort, viewQuery, type TableQueryValues } from '@shared/tableQuery';
import { SavedViews } from '@shared/components/SavedViews';
import { InlineNotice } from '@shared/components/InlineNotice';
import { Link } from 'react-router-dom';
import { explainMsaeFailure, type MsaeAuditRow } from './msaeRefusals';
import { useAuth } from '../context/AuthContext';
import { Capabilities } from '@shared/generated';

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

const TABS = ['General', 'EST', 'SCEP', 'CMP', 'ACME', 'MSAE', 'Network'] as const;
export type Tab = typeof TABS[number];

/** What the audit list keeps in the URL. Defaults stay out of the link. */
const QUERY_DEFAULTS: TableQueryValues = { page: '1', pageSize: '25', sort: '-timestamp', tab: 'General', from: '', to: '', caId: '', actionType: '', user: '', outcome: '' };
const PAGE_SIZES = [25, 50, 100];

type Category = 'general' | 'protocol' | 'network';
function tabCategory(tab: Tab): Category {
    if (tab === 'General') return 'general';
    if (tab === 'Network') return 'network';
    return 'protocol';
}

const okFailBadge = (log: any) => <StatusBadge status={log.success ? 'active' : 'revoked'} label={log.success ? 'OK' : 'Failed'} />;
const networkBadge = (log: any) =>
    log.blocked ? <StatusBadge status="revoked" label="Blocked" />
        : log.statusCode >= 400 ? <StatusBadge status="expired" label={`${log.statusCode}`} />
            : <StatusBadge status="active" label={`${log.statusCode ?? 'OK'}`} />;

/// <summary>
/// Builds the DataTable columns for the active audit tab. General (app), protocol (EST/SCEP/CMP/ACME)
/// and network entries have distinct shapes, so each gets a tailored column set.
/// </summary>
export function buildColumns(tab: Tab): DataTableColumn<any>[] {
    const cat = tabCategory(tab);
    const timeCol: DataTableColumn<any> = { key: 'timestamp', header: 'Timestamp', defaultWidth: 170, minWidth: 140, sortable: tab === 'General', exportValue: (l) => formatDate(l.timestamp), render: (l) => <span className="text-xs text-ink-muted">{formatDate(l.timestamp)}</span> };

    if (cat === 'network') {
        return [
            timeCol,
            { key: 'status', header: 'Status', defaultWidth: 100, truncate: false, exportValue: (l) => (l.blocked ? 'BLOCKED' : String(l.statusCode ?? '')), render: networkBadge },
            { key: 'sourceIp', header: 'Source IP', defaultWidth: 130, exportValue: (l) => l.sourceIp || '', render: (l) => <span className={`data-mono ${l.blocked ? 'text-crit' : 'text-ink'}`}>{l.sourceIp}</span> },
            { key: 'method', header: 'Method', defaultWidth: 90, exportValue: (l) => l.httpMethod || '', render: (l) => <span className="text-xs text-ink-muted font-medium">{l.httpMethod}</span> },
            { key: 'path', header: 'Request Path', defaultWidth: 220, exportValue: (l) => l.requestPath || '', render: (l) => <span className="text-xs text-ink-muted truncate">{l.requestPath}</span> },
            { key: 'protocol', header: 'Protocol', defaultWidth: 100, truncate: false, exportValue: (l) => l.protocol || '', render: (l) => l.protocol ? <Tag label={l.protocol} /> : <span className="text-xs text-ink-muted">-</span> },
            { key: 'caLabel', header: 'CA', defaultWidth: 120, exportValue: (l) => l.caLabel || '', render: (l) => <span className="text-xs text-ink-muted truncate">{l.caLabel || '-'}</span> },
        ];
    }

    if (cat === 'protocol') {
        // ACME identifies subjects by domain (identifiers), not Subject DN — which is empty
        // for everything but issuance. Swap in an Identifiers column so ACME rows are legible.
        const subjectOrIdentifiers: DataTableColumn<any> = tab === 'ACME'
            ? { key: 'identifiers', header: 'Identifiers', defaultWidth: 240, exportValue: (l) => formatIdentifiers(l.identifiers) || l.subjectDN || '', render: (l) => { const v = formatIdentifiers(l.identifiers) || l.subjectDN; return <span className="text-xs text-ink-muted truncate">{v || '-'}</span>; } }
            : { key: 'subjectDN', header: 'Subject DN', defaultWidth: 220, exportValue: (l) => l.subjectDN || '', render: (l) => <span className="text-xs text-ink-muted truncate">{l.subjectDN || '-'}</span> };
        return [
            timeCol,
            { key: 'status', header: 'Status', defaultWidth: 90, truncate: false, exportValue: (l) => (l.success ? 'OK' : 'FAIL'), render: okFailBadge },
            { key: 'operation', header: 'Operation', defaultWidth: 170, exportValue: (l) => l.operation || l.messageType || '', render: (l) => <span className="text-xs text-ink">{l.operation || l.messageType || '-'}</span> },
            subjectOrIdentifiers,
            { key: 'serial', header: 'Serial', defaultWidth: 140, exportValue: (l) => l.certificateSerial || '', render: (l) => <span className="data-mono text-ink-muted truncate">{l.certificateSerial || '-'}</span> },
            { key: 'caLabel', header: 'CA', defaultWidth: 120, exportValue: (l) => l.caLabel || '', render: (l) => <span className="text-xs text-ink-muted truncate">{l.caLabel || '-'}</span> },
            ...(tab === 'MSAE' ? [
                { key: 'callerPrincipal', header: 'Caller', defaultWidth: 220, exportValue: (l: any) => l.callerPrincipal || '', render: (l: any) => <span className="data-mono text-ink-muted truncate">{l.callerPrincipal || '-'}</span> },
                { key: 'realm', header: 'Realm', defaultWidth: 180, exportValue: (l: any) => l.realm || '', render: (l: any) => <span className="data-mono text-ink-muted truncate">{l.realm || '-'}</span> },
                { key: 'authMethod', header: 'Auth', defaultWidth: 110, exportValue: (l: any) => l.authMethod || '', render: (l: any) => <span className="text-xs text-ink-muted">{l.authMethod || '-'}</span> },
                // The refusal in one phrase; the drawer and the detail page carry the explanation and the fix.
                { key: 'why', header: 'Why', headerTitle: 'What the refusal means. Open the row for the explanation and the fix.', defaultWidth: 210, exportValue: (l: any) => explainMsaeFailure(l)?.title || '', render: (l: any) => {
                    const why = explainMsaeFailure(l);
                    return why
                        ? <span title={why.explanation} className="text-xs text-warn truncate">{why.title}</span>
                        : <span className="text-xs text-ink-muted">-</span>;
                } },
            ] as DataTableColumn<any>[] : []),
        ];
    }

    // general (app)
    return [
        timeCol,
        { key: 'success', header: 'Status', defaultWidth: 90, truncate: false, sortable: true, exportValue: (l) => (l.success ? 'OK' : 'FAIL'), render: okFailBadge },
        { key: 'actorUsername', header: 'Actor', defaultWidth: 150, sortable: true, exportValue: (l) => l.actorUsername || 'system', render: (l) => <span className="text-xs text-accent-ink truncate">{l.actorUsername || 'system'}</span> },
        { key: 'actionType', header: 'Action', defaultWidth: 190, sortable: true, exportValue: (l) => l.actionType || '', render: (l) => <span className="text-xs text-ink truncate">{l.actionType}</span> },
        { key: 'target', header: 'Target', defaultWidth: 180, exportValue: (l) => `${l.targetEntityType || ''}${l.targetEntityId ? ` #${l.targetEntityId}` : ''}`, render: (l) => <span className="text-xs text-ink-muted truncate">{l.targetEntityType} {l.targetEntityId ? `#${String(l.targetEntityId).substring(0, 8)}` : ''}</span> },
        { key: 'sourceIp', header: 'Source IP', defaultWidth: 130, exportValue: (l) => l.sourceIp || '', render: (l) => <span className="data-mono text-ink-muted">{l.sourceIp || '-'}</span> },
    ];
}

/**
 * What an MSAE refusal means and what resolves it, rendered where the row lands. Null when the
 * row is not a refusal this console can explain, so callers can place it unconditionally.
 */
export const MsaeWhyNotice: React.FC<{ log: MsaeAuditRow; className?: string }> = ({ log, className = '' }) => {
    const { can } = useAuth();
    // The realm pages are system-admin only (SYSTEM_ADMIN in gates.ts).
    const why = explainMsaeFailure(log, { canOpenRealms: can(Capabilities.SystemManage) });
    if (!why) return null;
    return (
        <div className={`space-y-2 ${className}`}>
            <InlineNotice severity="warning" notice={{ title: why.title, detail: why.explanation, remediation: why.fix }} />
            {why.link && (
                <Link to={why.link.path}
                    className="inline-block px-3 py-1.5 text-xs font-medium rounded border border-warn/40 bg-warn-soft text-warn hover:bg-warn/15 transition-colors">
                    {why.link.label}
                </Link>
            )}
        </div>
    );
};

/** True when a row came from the MSAE audit table: the tab says so, or the row carries MSAE-only columns. */
function isMsaeRow(log: any, tab?: Tab): boolean {
    return tab ? tab === 'MSAE' : (log != null && typeof log === 'object' && ('authMethod' in log || 'callerPrincipal' in log));
}

const TIMESTAMP_ONLY: ReadonlySet<string> = new Set(['timestamp']);

/* read-only drawer — every populated field, JSON details as nested rows; an MSAE refusal is explained first */
export const AuditDrawer: React.FC<{ log: any; tab?: Tab }> = ({ log, tab }) => (
    <div className="text-sm">
        {isMsaeRow(log, tab) && <MsaeWhyNotice log={log} className="mb-3" />}
        <DetailField label="Timestamp" value={formatDate(log.timestamp)} />
        <AuditFields log={log} omit={TIMESTAMP_ONLY} />
    </div>
);

const AuditLogs: React.FC = () => {
    // Tab, page, sort and filters live in the URL (see useTableQuery).
    const [q, setQ] = useTableQuery('audit', QUERY_DEFAULTS);
    const activeTab: Tab = (TABS as readonly string[]).includes(q.tab) ? (q.tab as Tab) : 'General';
    const page = Math.max(1, parseInt(q.page, 10) || 1);
    const pageSize = PAGE_SIZES.includes(parseInt(q.pageSize, 10)) ? parseInt(q.pageSize, 10) : 25;
    const sort = parseSort(q.sort);
    const { from: dateFrom, to: dateTo, actionType: filterActionType } = q;
    const [logs, setLogs] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [totalPages, setTotalPages] = useState(1);
    const [totalCount, setTotalCount] = useState(0);
    // The username filter is typed; it reaches the URL after a pause.
    const [filterUser, setFilterUser] = useState(q.user);
    useEffect(() => {
        const t = setTimeout(() => { if (filterUser !== q.user) setQ({ user: filterUser }); }, 700);
        return () => clearTimeout(t);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [filterUser]);
    useEffect(() => { setFilterUser(q.user); }, [q.user]);
    // The sidebar scope pins the CA filter; the select below is locked while it does.
    const { caId: scopeCaId, caQuery, scope } = useScope();
    const scopeLocked = !!scopeCaId;
    const filterCaId = q.caId;
    // Only a change of scope clears the pin, so a deep link with ?caId= survives the first render.
    const wasLocked = useRef(scopeLocked);
    useEffect(() => {
        if (scopeLocked && q.caId !== scopeCaId) setQ({ caId: scopeCaId! });
        else if (!scopeLocked && wasLocked.current && q.caId) setQ({ caId: '' });
        wasLocked.current = scopeLocked;
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [scopeLocked, scopeCaId]);
    const [authorities, setAuthorities] = useState<any[]>([]);
    const [knownActionTypes, setKnownActionTypes] = useState<string[]>([]);

    // Every action the server can record, for the Action filter.
    useEffect(() => {
        apiGet<string[]>('/api/v1/admin/audit/action-types')
            .then((names) => setKnownActionTypes(Array.isArray(names) ? names : []))
            .catch(() => { /* the filter then offers only "Any" */ });
    }, []);

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

    // Raised by the table's Refresh button and its auto-refresh: the same load, asked for again.
    const [refreshTick, setRefreshTick] = useState(0);

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError(null);

        const params = new URLSearchParams({ page: String(page), pageSize: String(pageSize) });
        if (dateFrom) params.set('from', dateFrom);
        if (dateTo) params.set('to', dateTo);
        if (filterCaId) params.set('caId', filterCaId);
        else { const scoped = caQuery(); if (scoped.startsWith('?spaceId=')) params.set('spaceId', decodeURIComponent(scoped.slice('?spaceId='.length))); }
        if (activeTab === 'General') {
            if (filterActionType) params.set('actionType', filterActionType);
            if (q.user) params.set('actorUsername', q.user);
            if (q.outcome) params.set('success', q.outcome === 'ok' ? 'true' : 'false');
        }
        if (activeTab === 'General' && q.sort) params.set('sort', q.sort);

        const path = activeTab === 'General'
            ? `/api/v1/admin/audit?${params}`
            : `/api/v1/admin/audit/${activeTab.toLowerCase()}?${params}`;

        apiGet<any>(path)
            .then((data) => {
                if (cancelled) return;
                const items = Array.isArray(data) ? data : (data.items || []);
                const total = data.totalPages || Math.ceil((data.total || data.totalCount || items.length) / pageSize) || 1;
                setLogs(items);
                setTotalPages(total);
                setTotalCount(data.total ?? data.totalCount ?? items.length);
                setLoading(false);

            })
            .catch((err) => {
                if (!cancelled) {
                    setError(errorNotice(err, 'Failed to load audit logs'));
                    setLoading(false);
                }
            });

        return () => { cancelled = true; };
    }, [activeTab, page, pageSize, dateFrom, dateTo, filterCaId, filterActionType, q.user, q.sort, caQuery, refreshTick]);

    const handleTabChange = (tab: Tab) => setQ({ tab, sort: QUERY_DEFAULTS.sort });

    /** The current filter as a saved view sees it: tab, filters and sort, never the page. */
    const currentView = viewQuery(q, QUERY_DEFAULTS);
    const applyView = (view: string) => {
        const params = new URLSearchParams(view);
        const next: Partial<TableQueryValues> = {};
        for (const key of Object.keys(QUERY_DEFAULTS)) if (key !== 'page') next[key] = params.get(key) ?? QUERY_DEFAULTS[key];
        setQ(next);
    };

    const columns = buildColumns(activeTab);

    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <h1 className="text-xl font-semibold text-ink">Audit Logs</h1>

            {/* Tabs */}
            <div className="flex gap-1 border-b border-line">
                {TABS.map((tab) => (
                    <button
                        key={tab}
                        onClick={() => handleTabChange(tab)}
                        className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 ${activeTab === tab
                            ? 'text-accent-ink border-accent'
                            : 'text-ink-muted border-transparent hover:text-ink'
                            }`}
                    >
                        {tab}
                    </button>
                ))}
            </div>

            {/* Filters. The CA is offered only while the scope does not already name one; the action,
                outcome and user filters exist on the General log only. */}
            <FilterBar>
                {!scopeLocked && (
                    <FilterField label="CA">
                        <select value={filterCaId} onChange={(e) => setQ({ caId: e.target.value })} className={filterControlClass}>
                            <option value="">All CAs</option>
                            {authorities.map((ca) => (
                                <option key={ca.id} value={ca.id}>{ca.label || ca.commonName || ca.id}</option>
                            ))}
                        </select>
                    </FilterField>
                )}
                <FilterField label="From">
                    <input type="date" value={dateFrom} onChange={(e) => setQ({ from: e.target.value })} className={filterControlClass} />
                </FilterField>
                <FilterField label="To">
                    <input type="date" value={dateTo} onChange={(e) => setQ({ to: e.target.value })} className={filterControlClass} />
                </FilterField>
                {activeTab === 'General' && (
                    <>
                        <FilterField label="Action">
                            <select value={filterActionType} onChange={(e) => setQ({ actionType: e.target.value })} className={filterControlClass}>
                                <option value="">Any</option>
                                {knownActionTypes.map((t) => (
                                    <option key={t} value={t}>{t}</option>
                                ))}
                            </select>
                        </FilterField>
                        <FilterField label="Outcome">
                            <select value={q.outcome} onChange={(e) => setQ({ outcome: e.target.value })} className={filterControlClass}>
                                <option value="">Any</option>
                                <option value="ok">OK</option>
                                <option value="failed">Failed</option>
                            </select>
                        </FilterField>
                        <FilterField label="User">
                            <input type="text" value={filterUser} onChange={(e) => setFilterUser(e.target.value)} placeholder="Exact username" className={`${filterControlClass} w-40`} />
                        </FilterField>
                    </>
                )}
                {(dateFrom || dateTo || (!scopeLocked && filterCaId) || filterActionType || filterUser || q.outcome) && (
                    <button
                        onClick={() => { setFilterUser(''); setQ({ from: '', to: '', caId: scopeCaId ?? '', actionType: '', user: '', outcome: '' }); }}
                        className="px-3 py-2 text-sm text-ink-muted hover:text-ink transition-colors"
                    >
                        Clear filters
                    </button>
                )}
            </FilterBar>

            <SavedViews tableId="audit" current={currentView} onApply={applyView} />

            <DataTable<any>
                tableId={`audit-${activeTab.toLowerCase()}`}
                title={`${activeTab} Audit Logs`}
                rows={logs}
                rowKey={(l) => l.id || `${l.timestamp}-${l.actionType || l.operation || l.messageType || ''}`}
                loading={loading}
                error={error}
                empty={scopeCaId ? `No audit entries in ${scopeLabel(scope)}. Change the scope in the sidebar to see others.` : 'No audit entries found'}
                columns={columns}
                selectable
                exportFileName={`audit-${activeTab.toLowerCase()}`}
                onRefresh={() => setRefreshTick((t) => t + 1)}
                renderDrawer={(l) => <AuditDrawer log={l} tab={activeTab} />}
                drawerTitle={(l) => l.actionType || l.operation || l.messageType || (l.requestPath ? `${l.httpMethod} ${l.requestPath}` : 'Audit entry')}
                detailPath={(l) => `/audit/${activeTab.toLowerCase()}/${l.id}`}
                sort={activeTab === 'General' ? sort : null}
                onSortChange={activeTab === 'General' ? (next) => setQ({ sort: formatSort(next) || QUERY_DEFAULTS.sort }) : undefined}
                page={page}
                pageSize={pageSize}
                totalPages={totalPages}
                totalCount={totalCount}
                onPageChange={(n) => setQ({ page: String(n) })}
                pageSizeOptions={PAGE_SIZES}
                onPageSizeChange={(n) => setQ({ pageSize: String(n), page: '1' })}
            />

        </div>
    );
};

export default AuditLogs;
