import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { DataTable } from '@shared/components/DataTable';
import { RecordFields } from '@shared/components/RecordFields';
import { statusToneClass, type RecordDescriptor } from '@shared/records';
import { useToast } from '@shared/context/ToastContext';
import AuditTable from './AuditTable';

/**
 * The one drawer body for every descriptor-driven list: a status chip and actions in the
 * header, then Overview, Audit and Related tabs. The list's DataTable supplies the slide-over
 * chrome (title, close, "Open full page"); this renders what goes inside it.
 */
type TabKey = 'overview' | 'audit' | 'related';

export function RecordDrawer<T>({ descriptor, row }: { descriptor: RecordDescriptor<T>; row: T }) {
    const { showToast } = useToast();
    const [tab, setTab] = useState<TabKey>('overview');
    const [busy, setBusy] = useState<string | null>(null);
    const status = descriptor.status?.(row);
    const auditTarget = descriptor.audit?.target(row) ?? null;
    const related = descriptor.related ?? [];

    // A new row in the same drawer starts on the overview again.
    useEffect(() => { setTab('overview'); }, [row]);

    const tabs: Array<{ key: TabKey; label: string }> = [{ key: 'overview', label: 'Overview' }];
    if (auditTarget) tabs.push({ key: 'audit', label: 'Audit' });
    if (related.length > 0) tabs.push({ key: 'related', label: 'Related' });

    const run = async (label: string, fn: () => Promise<void> | void) => {
        setBusy(label);
        try { await fn(); }
        catch (e: any) { if (e?.message !== 'Step-up MFA cancelled') showToast('error', e?.message || `${label} failed`); }
        finally { setBusy(null); }
    };

    const toneBtn = (tone?: string) =>
        tone === 'danger' ? 'bg-red-50 dark:bg-red-900/50 text-red-800 dark:text-red-300 border-red-300 dark:border-red-700 hover:bg-red-100 dark:hover:bg-red-900'
            : tone === 'primary' ? 'bg-blue-600 text-white border-blue-600 hover:bg-blue-700'
                : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 border-gray-300 dark:border-gray-600 hover:bg-gray-200 dark:hover:bg-gray-600';

    return (
        <div className="space-y-3">
            {(status || (descriptor.actions && descriptor.actions.length > 0)) && (
                <div className="flex items-center justify-between gap-2 flex-wrap">
                    {status && (
                        <span className={`px-2 py-0.5 text-[11px] rounded border ${statusToneClass(status.tone)}`}>{status.label}</span>
                    )}
                    {descriptor.actions && descriptor.actions.length > 0 && (
                        <span className="flex items-center gap-1.5 flex-wrap">
                            {descriptor.actions.map((a) => {
                                const enabled = a.enabled ? a.enabled(row) : true;
                                return (
                                    <button key={a.label} disabled={!enabled || busy != null} onClick={() => run(a.label, () => a.run(row))}
                                        className={`px-2.5 py-1 text-xs rounded border transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${toneBtn(a.tone)}`}>
                                        {busy === a.label ? `${a.label}…` : a.label}
                                    </button>
                                );
                            })}
                        </span>
                    )}
                </div>
            )}

            {tabs.length > 1 && (
                <div className="flex gap-1 border-b border-gray-200 dark:border-gray-800">
                    {tabs.map((t) => (
                        <button key={t.key} onClick={() => setTab(t.key)}
                            className={`px-3 py-1.5 text-xs font-medium border-b-2 -mb-px transition-colors ${tab === t.key ? 'border-blue-600 text-blue-700 dark:text-blue-400' : 'border-transparent text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'}`}>
                            {t.label}
                        </button>
                    ))}
                </div>
            )}

            {tab === 'overview' && <RecordFields sections={descriptor.sections} row={row} />}
            {tab === 'audit' && auditTarget && <AuditTable tab={descriptor.audit!.tab} target={auditTarget} pageSize={10} />}
            {tab === 'related' && related.map((r) => <RelatedList key={r.title} related={r} row={row} />)}
        </div>
    );
}

function RelatedList<T>({ related, row }: { related: NonNullable<RecordDescriptor<T>['related']>[number]; row: T }) {
    const [rows, setRows] = useState<unknown[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        related.load(row)
            .then((r) => { if (!cancelled) { setRows(r); setLoading(false); } })
            .catch((e: any) => { if (!cancelled) { setError(e?.message || 'Failed to load'); setLoading(false); } });
        return () => { cancelled = true; };
    }, [related, row]);
    const d = related.descriptor;
    const listPath = related.listPath?.(row);
    return (
        <div className="space-y-1">
            <div className="flex items-center justify-between">
                <h4 className="text-[11px] font-semibold uppercase tracking-wider text-gray-500 dark:text-gray-400">{related.title}</h4>
                {listPath && <Link to={listPath} className="text-[11px] text-blue-700 dark:text-blue-400 hover:underline">Open list</Link>}
            </div>
            <DataTable<any>
                tableId={`related-${d.kind}`}
                rows={rows}
                rowKey={d.key}
                loading={loading}
                error={error}
                empty="Nothing related"
                columns={d.columns}
                disableExport
                detailPath={d.page?.path}
            />
        </div>
    );
}

/**
 * The DataTable props a descriptor supplies: columns, row identity, the drawer body, its
 * title and the full-page path. Spread it into the list's DataTable.
 */
export function recordTableProps<T>(descriptor: RecordDescriptor<T>) {
    return {
        columns: descriptor.columns,
        rowKey: descriptor.key,
        renderDrawer: (row: T) => <RecordDrawer descriptor={descriptor} row={row} />,
        drawerTitle: descriptor.title,
        detailPath: descriptor.page?.path,
    };
}
