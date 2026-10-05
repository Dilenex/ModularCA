import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Chevron } from '@shared/components/Chevron';
import { apiGet } from '../api/client';
import { useTablePrefs } from '@shared/context/TablePrefsContext';

const MIN_HEIGHT = 36;
const DEFAULT_HEIGHT = 220;
const MAX_HEIGHT_RATIO = 0.6;

// Per-source badge styling. Network is intentionally omitted — those events are not
// surfaced in this panel (see fetchLogs).
const SOURCE_STYLES: Record<string, string> = {
    App: 'text-ink-muted bg-sunken',
    EST: 'text-series-2 bg-series-2/10',
    SCEP: 'text-series-4 bg-series-4/10',
    CMP: 'text-series-1 bg-series-1/10',
    ACME: 'text-series-3 bg-series-3/10',
};

interface PanelPrefs {
    height: number;
    collapsed: boolean;
}

const LogPanel: React.FC = () => {
    // Sizing + open/closed state persist per-user (localStorage fast path + cross-device backend sync).
    const [prefs, setPrefs] = useTablePrefs<PanelPrefs>('panel:events', { height: DEFAULT_HEIGHT, collapsed: true });
    const collapsed = prefs.collapsed;

    // Live height during a drag — committed to prefs only on mouse-up so we don't write
    // localStorage / PUT the backend on every mousemove.
    const [liveHeight, setLiveHeight] = useState<number | null>(null);
    const height = liveHeight ?? prefs.height;

    const [logs, setLogs] = useState<any[]>([]);
    const [loading, setLoading] = useState(false);
    const [autoRefresh, setAutoRefresh] = useState(true);
    const [filter, setFilter] = useState('');
    const [selectedLog, setSelectedLog] = useState<any>(null);
    const panelRef = useRef<HTMLDivElement>(null);
    const dragRef = useRef<{ startY: number; startH: number; latest: number } | null>(null);
    const bottomRef = useRef<HTMLDivElement>(null);

    const fetchLogs = useCallback(async () => {
        setLoading(true);
        try {
            // Network audit is intentionally NOT fetched — those events are excluded from this panel.
            const [general, est, scep, cmp, acme, msae] = await Promise.all([
                apiGet<any>('/api/v1/admin/audit?pageSize=50').catch(() => ({ items: [] })),
                apiGet<any>('/api/v1/admin/audit/est?pageSize=50').catch(() => ({ items: [] })),
                apiGet<any>('/api/v1/admin/audit/scep?pageSize=50').catch(() => ({ items: [] })),
                apiGet<any>('/api/v1/admin/audit/cmp?pageSize=50').catch(() => ({ items: [] })),
                apiGet<any>('/api/v1/admin/audit/acme?pageSize=50').catch(() => ({ items: [] })),
                apiGet<any>('/api/v1/admin/audit/msae?pageSize=50').catch(() => ({ items: [] })),
            ]);

            const tagged = [
                ...(general.items || []).map((l: any) => ({ ...l, _source: 'App', _action: l.actionType, _actor: l.actorUsername })),
                ...(est.items || []).map((l: any) => ({ ...l, _source: 'EST', _action: l.operation, _actor: l.subjectDN })),
                ...(scep.items || []).map((l: any) => ({ ...l, _source: 'SCEP', _action: l.operation, _actor: l.subjectDN })),
                ...(cmp.items || []).map((l: any) => ({ ...l, _source: 'CMP', _action: l.messageType || l.operation, _actor: l.subjectDN })),
                ...(acme.items || []).map((l: any) => ({ ...l, _source: 'ACME', _action: l.operation, _actor: l.subjectDN || (l.accountId ? `acct:${l.accountId.substring(0, 8)}` : '') })),
                ...(msae.items || []).map((l: any) => ({ ...l, _source: 'MSAE', _action: l.operation, _actor: l.subjectDN || l.callerPrincipal })),
            ];

            tagged.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
            setLogs(tagged.slice(0, 100));
        } catch {
            // Audit DB might not be configured
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        if (!collapsed) fetchLogs();
    }, [collapsed, fetchLogs]);

    useEffect(() => {
        if (!collapsed && autoRefresh) {
            const interval = setInterval(fetchLogs, 10000);
            return () => clearInterval(interval);
        }
    }, [collapsed, autoRefresh, fetchLogs]);

    const onMouseMove = useCallback((e: MouseEvent) => {
        if (!dragRef.current) return;
        const maxH = window.innerHeight * MAX_HEIGHT_RATIO;
        const delta = dragRef.current.startY - e.clientY;
        const newH = Math.min(maxH, Math.max(MIN_HEIGHT + 40, dragRef.current.startH + delta));
        dragRef.current.latest = newH;
        setLiveHeight(newH);
    }, []);

    const onMouseUp = useCallback(() => {
        const finalH = dragRef.current?.latest;
        document.removeEventListener('mousemove', onMouseMove);
        document.removeEventListener('mouseup', onMouseUp);
        dragRef.current = null;
        setLiveHeight(null);
        // Persist the final height (the panel is necessarily open while dragging).
        if (finalH != null) setPrefs({ collapsed: false, height: finalH });
    }, [onMouseMove, setPrefs]);

    const onMouseDown = (e: React.MouseEvent) => {
        e.preventDefault();
        dragRef.current = { startY: e.clientY, startH: height, latest: height };
        document.addEventListener('mousemove', onMouseMove);
        document.addEventListener('mouseup', onMouseUp);
    };

    // Toggling open/closed persists immediately; the persisted height is preserved on re-open.
    const toggleCollapse = () => {
        setPrefs({ ...prefs, collapsed: !collapsed });
    };

    const formatTime = (ts: string) => {
        const d = new Date(ts);
        return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    };

    const formatDate = (ts: string) => {
        const d = new Date(ts);
        return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) + ' ' + formatTime(ts);
    };

    const filteredLogs = filter
        ? logs.filter(l =>
            (l._source || '').toLowerCase().includes(filter.toLowerCase()) ||
            (l._action || '').toLowerCase().includes(filter.toLowerCase()) ||
            (l._actor || '').toLowerCase().includes(filter.toLowerCase()) ||
            (l.targetEntityType || '').toLowerCase().includes(filter.toLowerCase()) ||
            (l.certificateSerial || '').toLowerCase().includes(filter.toLowerCase())
        )
        : logs;

    const thClass = 'px-2 py-1 text-left font-medium select-none';

    return (
        <div
            ref={panelRef}
            className="flex-shrink-0 bg-raised border-t border-line flex flex-col"
            style={{ height: collapsed ? MIN_HEIGHT : height }}
        >
            {/* Resize handle */}
            {!collapsed && (
                <div
                    onMouseDown={onMouseDown}
                    className="h-1 cursor-ns-resize bg-raised hover:bg-accent-hover transition-colors flex-shrink-0"
                />
            )}

            {/* Header bar */}
            <div className="flex items-center justify-between px-3 py-1.5 flex-shrink-0 border-b border-line">
                <button onClick={toggleCollapse} className="flex items-center gap-2 text-xs font-semibold text-ink-muted hover:text-ink transition-colors">
                    <span><Chevron direction={(collapsed) ? 'up' : 'down'} className="w-3 h-3" /></span>
                    <span>Events</span>
                    {logs.length > 0 && (
                        <span className="px-1.5 py-0.5 bg-raised rounded text-[10px] text-ink-muted">{logs.length}</span>
                    )}
                </button>

                {!collapsed && (
                    <div className="flex items-center gap-3">
                        <input
                            type="text"
                            value={filter}
                            onChange={(e) => setFilter(e.target.value)}
                            placeholder="Filter..."
                            className="px-2 py-1 bg-raised border border-line-strong rounded text-xs text-ink w-40 focus:outline-none focus:border-accent"
                        />
                        <label className="flex items-center gap-1 text-[10px] text-ink-muted cursor-pointer">
                            <input
                                type="checkbox"
                                checked={autoRefresh}
                                onChange={(e) => setAutoRefresh(e.target.checked)}
                                className="w-3 h-3"
                            />
                            Auto
                        </label>
                        <button
                            onClick={fetchLogs}
                            disabled={loading}
                            className="text-[10px] text-ink-muted hover:text-ink transition-colors"
                        >
                            {loading ? '⟳' : '↻'} Refresh
                        </button>
                    </div>
                )}
            </div>

            {/* Log entries */}
            {!collapsed && (
                <div className="flex-1 overflow-auto text-[11px]">
                    <table className="w-full min-w-[640px] border-collapse">
                        <thead className="sticky top-0 z-10 bg-sunken backdrop-blur text-[10px] uppercase tracking-wide text-ink-muted">
                            <tr className="border-b border-line">
                                <th className={`${thClass} w-[130px]`}>Time</th>
                                <th className="px-1 py-1 text-center font-medium w-[24px]" aria-label="Status" />
                                <th className={`${thClass} w-[56px]`}>Source</th>
                                <th className={`${thClass} w-[110px]`}>Actor</th>
                                <th className={`${thClass} w-[170px]`}>Action</th>
                                <th className={thClass}>Target</th>
                                <th className={`${thClass} w-[110px]`}>IP</th>
                            </tr>
                        </thead>
                        <tbody className="font-mono">
                            {filteredLogs.length === 0 && !loading && (
                                <tr>
                                    <td colSpan={7} className="px-3 py-4 text-center text-ink-muted font-sans">
                                        No events
                                    </td>
                                </tr>
                            )}
                            {filteredLogs.map((log) => {
                                const isSelected = selectedLog?.id === log.id;
                                return (
                                    <tr
                                        key={log.id}
                                        onClick={() => setSelectedLog(isSelected ? null : log)}
                                        className={`cursor-pointer border-b border-line transition-colors ${
                                            isSelected
                                                ? 'bg-info-soft'
                                                : 'hover:bg-hover'
                                        }`}
                                    >
                                        <td className="px-2 py-1 text-ink-muted whitespace-nowrap">
                                            {formatDate(log.timestamp)}
                                        </td>
                                        <td className="px-1 py-1 text-center whitespace-nowrap">
                                            {log.success
                                                ? <span className="text-ok">{'✓'}</span>
                                                : <span className="text-crit">{'✗'}</span>
                                            }
                                        </td>
                                        <td className="px-1 py-1 whitespace-nowrap">
                                            <span className={`px-1.5 py-0.5 rounded text-[9px] font-semibold font-sans ${SOURCE_STYLES[log._source] || SOURCE_STYLES.App}`}>
                                                {log._source}
                                            </span>
                                        </td>
                                        <td className="px-2 py-1 text-accent-ink whitespace-nowrap max-w-[110px] truncate">
                                            {log._actor || '-'}
                                        </td>
                                        <td className="px-2 py-1 text-warn whitespace-nowrap max-w-[170px] truncate">
                                            {log._action}
                                        </td>
                                        <td className="px-2 py-1 text-ink-muted truncate max-w-[220px]">
                                            {log._source === 'App'
                                                ? `${log.targetEntityType || ''}${log.targetEntityId ? ` ${log.targetEntityId.substring(0, 8)}` : ''}`
                                                : (log.certificateSerial || log.caLabel || '')
                                            }
                                        </td>
                                        <td className="px-2 py-1 text-ink-muted whitespace-nowrap">
                                            {log.sourceIp}
                                        </td>
                                    </tr>
                                );
                            })}
                        </tbody>
                    </table>

                    {/* Detail pane for selected log */}
                    {selectedLog && (
                        <div className="border-t border-line bg-ground px-3 py-2 space-y-1">
                            <div className="flex justify-between items-start">
                                <span className="text-xs font-semibold text-ink">{selectedLog._source}: {selectedLog._action}</span>
                                <button onClick={() => setSelectedLog(null)} className="text-ink-muted hover:text-ink text-xs">{'✕'}</button>
                            </div>
                            <div className="grid grid-cols-2 gap-x-4 gap-y-0.5 text-[11px]">
                                <span className="text-ink-muted">Source</span>
                                <span className="text-ink">{selectedLog._source}</span>
                                <span className="text-ink-muted">Timestamp</span>
                                <span className="text-ink">{new Date(selectedLog.timestamp).toISOString()}</span>
                                {selectedLog._source === 'App' ? (
                                    <>
                                        <span className="text-ink-muted">Actor</span>
                                        <span className="text-accent-ink">{selectedLog.actorUsername || '-'}</span>
                                        <span className="text-ink-muted">Action</span>
                                        <span className="text-ink">{selectedLog.actionType}</span>
                                        <span className="text-ink-muted">Target</span>
                                        <span className="text-ink">{selectedLog.targetEntityType} {selectedLog.targetEntityId || ''}</span>
                                    </>
                                ) : (
                                    <>
                                        <span className="text-ink-muted">Operation</span>
                                        <span className="text-ink">{selectedLog._action}</span>
                                        <span className="text-ink-muted">Subject DN</span>
                                        <span className="text-ink">{selectedLog.subjectDN || '-'}</span>
                                        <span className="text-ink-muted">Certificate</span>
                                        <span className="text-ink font-mono">{selectedLog.certificateSerial || '-'}</span>
                                        {selectedLog.keyAlgorithm && (
                                            <>
                                                <span className="text-ink-muted">Key</span>
                                                <span className="text-ink">{selectedLog.keyAlgorithm} {selectedLog.keySize}</span>
                                            </>
                                        )}
                                        {selectedLog.caLabel && (
                                            <>
                                                <span className="text-ink-muted">CA Label</span>
                                                <span className="text-ink">{selectedLog.caLabel}</span>
                                            </>
                                        )}
                                    </>
                                )}
                                <span className="text-ink-muted">Source IP</span>
                                <span className="text-ink">{selectedLog.sourceIp || '-'}</span>
                                <span className="text-ink-muted">Success</span>
                                <span className={selectedLog.success ? 'text-ok' : 'text-crit'}>{selectedLog.success ? 'Yes' : 'No'}</span>
                                {selectedLog.errorMessage && (
                                    <>
                                        <span className="text-ink-muted">Error</span>
                                        <span className="text-crit">{selectedLog.errorMessage}</span>
                                    </>
                                )}
                                <span className="text-ink-muted">ID</span>
                                <span className="text-ink-muted font-mono">{selectedLog.id}</span>
                            </div>
                        </div>
                    )}
                    <div ref={bottomRef} />
                </div>
            )}
        </div>
    );
};

export default LogPanel;
