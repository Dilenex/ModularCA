import React, { useEffect, useState } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { errorNotice } from '@shared-auth/api/notices';
import { Link } from 'react-router-dom';
import { DataTable } from '@shared/components/DataTable';
import { RecordFields } from '@shared/components/RecordFields';
import { statusToneClass, type RecordDescriptor } from '@shared/records';
import { useToast } from '@shared/context/ToastContext';
import AuditTable from './AuditTable';
import { actionButton, actionButtonDanger, actionButtonPrimary } from '@shared/components/actionButtons';
import { badgeText } from '@shared/badgeText';

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
        tone === 'danger' ? actionButtonDanger : tone === 'primary' ? actionButtonPrimary : actionButton;

    return (
        <div className="space-y-3">
            {(status || (descriptor.actions && descriptor.actions.length > 0)) && (
                <div className="flex items-center justify-between gap-2 flex-wrap">
                    {status && (
                        <span className={`inline-flex items-center px-1.5 py-px text-xs font-medium rounded-sm border ${statusToneClass(status.tone)}`}>{badgeText(status.label)}</span>
                    )}
                    {descriptor.actions && descriptor.actions.length > 0 && (
                        <span className="flex items-center gap-1.5 flex-wrap">
                            {descriptor.actions.map((a) => {
                                const enabled = a.enabled ? a.enabled(row) : true;
                                return (
                                    <button key={a.label} disabled={!enabled || busy != null} onClick={() => run(a.label, () => a.run(row))}
                                        className={toneBtn(a.tone)}>
                                        {busy === a.label ? `${a.label}…` : a.label}
                                    </button>
                                );
                            })}
                        </span>
                    )}
                </div>
            )}

            {tabs.length > 1 && (
                <div className="flex gap-1 border-b border-line">
                    {tabs.map((t) => (
                        <button key={t.key} onClick={() => setTab(t.key)}
                            className={`px-3 py-1.5 text-sm font-medium border-b-2 -mb-px transition-colors ${tab === t.key ? 'border-accent text-accent-ink' : 'border-transparent text-ink-muted hover:text-ink'}`}>
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
    const [error, setError] = useState<NoticeInput | null>(null);
    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        related.load(row)
            .then((r) => { if (!cancelled) { setRows(r); setLoading(false); } })
            .catch((e: any) => { if (!cancelled) { setError(errorNotice(e, 'Failed to load')); setLoading(false); } });
        return () => { cancelled = true; };
    }, [related, row]);
    const d = related.descriptor;
    const listPath = related.listPath?.(row);
    return (
        <div className="space-y-1">
            <div className="flex items-center justify-between">
                <h4 className="label-caps">{related.title}</h4>
                {listPath && <Link to={listPath} className="text-xs text-accent-ink hover:underline">Open list</Link>}
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
