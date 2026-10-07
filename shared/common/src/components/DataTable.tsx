/**
 * Sortable, resizable, column-configurable data table with CSV export.
 *
 * Shared because adminui and userui held near-identical 460-line copies that had already drifted
 * in the one place it mattered: userui's CSV export was missing the spreadsheet formula-injection
 * neutralisation below, so a certificate field beginning with "=" was exported as a live formula.
 * That is the more exposed of the two apps for this, since its rows are built from CSR-supplied
 * subject and SAN values.
 *
 * The preference store arrives via TablePrefsProvider rather than an imported API client — see
 * context/TablePrefsContext.tsx.
 */
import React, { useState, useEffect, useRef, useReducer, useMemo, useCallback } from 'react';
import { InlineNotice } from './InlineNotice';
import type { NoticeInput } from '../notifications/notice';
import { useNavigate } from 'react-router-dom';
import { useTablePrefs } from '../context/TablePrefsContext';
import { renameColumnKeys } from '../tablePrefsKeys';
import { AUTO_REFRESH_SECONDS, autoRefreshDue, autoRefreshLabel } from '../tableRefresh';
import { Chevron } from './Chevron';
import { Drawer } from './Drawer';
import { sortRows } from '../tableSort';
import { findRows } from '../tableFind';
import { columnTrack } from '../tableTracks';
import type { SortSpec } from '../tableQuery';

/* ── public API ───────────────────────────────────────────────────────────── */
export interface DataTableColumn<Row> {
    /** Stable key — used for width/visibility persistence and as the React key. */
    key: string;
    /** Header label. */
    header: string;
    /** Cell renderer. */
    render: (row: Row) => React.ReactNode;
    /** Value used for CSV export. Falls back to the rendered value when it's a string/number. */
    exportValue?: (row: Row) => string | number | null | undefined;
    /** Default pixel width when the user hasn't resized this column. Ignored when `flex`. */
    defaultWidth?: number;
    /** Minimum pixel width while resizing (default 60). */
    minWidth?: number;
    /** This column grows to fill remaining space until the user resizes it. */
    flex?: boolean;
    /** Allow drag-resizing (default true). */
    resizable?: boolean;
    /** Allow hiding via the columns menu (default true). */
    hideable?: boolean;
    /** Truncate overflowing cell content (default true). Set false for badge/action cells. */
    truncate?: boolean;
    /** Cell + header alignment. */
    align?: 'left' | 'right' | 'center';
    /** Header tooltip. */
    headerTitle?: string;
    /** Clicking the header sorts by this column (default false). */
    sortable?: boolean;
    /** Value to sort by client-side. Falls back to `exportValue`. Ignored when the parent sorts (onSortChange). */
    sortValue?: (row: Row) => string | number | boolean | Date | null | undefined;
}

export interface DataTableBulkAction<Row> {
    label: string;
    onClick: (selected: Row[]) => void;
    /** Only enabled when exactly one row is selected (e.g. Edit). */
    single?: boolean;
    variant?: 'default' | 'danger' | 'primary';
    /** Optional per-row guard; when it returns false for any selected row the action is disabled. */
    enabledFor?: (row: Row) => boolean;
}

export interface DataTableProps<Row> {
    /** Stable id used for persistence, e.g. "whitelists". */
    tableId: string;
    /** Column keys renamed since a layout was stored, old to new, so stored widths and hidden flags carry over. */
    renamedColumns?: Record<string, string>;
    columns: DataTableColumn<Row>[];
    rows: Row[];
    rowKey: (row: Row) => string;
    loading?: boolean;
    /** A failure to load, shown in place of the rows. A string or a structured notice. */
    error?: NoticeInput | null;
    empty?: React.ReactNode;
    title?: string;
    /** Offer a find box that narrows the rows already loaded, by the text of every column.
     *  Not for a table whose parent pages or filters on the server. */
    findable?: boolean;
    /** The table's own "+ New" button. Sits at the right end of the header's second line. */
    toolbarAction?: React.ReactNode;
    /** Asks the parent to load the rows again. When given, the header shows a Refresh button and
     *  an auto-refresh switch, and the rows stay on screen while they reload. For tables whose
     *  rows appear without the reader doing anything: logs. */
    onRefresh?: () => void;
    /** Seconds between automatic refreshes while the switch is on. */
    autoRefreshSeconds?: number;
    /** Show selection checkboxes + bulk-action toolbar. */
    selectable?: boolean;
    bulkActions?: DataTableBulkAction<Row>[];
    /** Base filename for CSV export (without extension). Defaults to tableId. */
    exportFileName?: string;
    /** Hide the CSV export button. */
    disableExport?: boolean;
    /** When provided, rows are expandable (accordion — only one open at a time) showing this panel. */
    renderExpanded?: (row: Row) => React.ReactNode;
    /** When provided, clicking a row opens a read-only slide-over drawer with this content. */
    renderDrawer?: (row: Row) => React.ReactNode;
    /**
     * Called when a row is clicked, for a caller that owns its own drawer or detail surface.
     * Makes rows clickable like `renderDrawer` does; takes precedence over the built-in drawer.
     * Exists because the built-in drawer cannot ask "discard unsaved changes?" before closing.
     */
    onRowClick?: (row: Row) => void;
    /** Drawer header title for a row (used with renderDrawer). */
    drawerTitle?: (row: Row) => React.ReactNode;
    /** Full-page detail route for a row. Shown as an "Open full page" CTA in the drawer, or
     *  navigated to directly on row-click when no drawer is provided. */
    detailPath?: (row: Row) => string;

    /* ── cross-page selection (server-paginated tables) ── */
    /** Controlled selection. When provided, the parent owns the selected key set and DataTable
     *  won't prune keys missing from the current `rows` — so selection persists across pages. */
    selectedKeys?: Set<string>;
    onSelectedKeysChange?: (next: Set<string>) => void;
    /** Total rows matching the current filter across all pages — enables the "select all N" banner. */
    totalCount?: number;
    /** Parent flag: every row matching the current filter is selected (beyond the loaded page). */
    allMatchingSelected?: boolean;
    /** User clicked "Select all N matching" in the banner. */
    onSelectAllMatching?: () => void;
    /** Clears selection (and any all-matching flag). Used by Deselect in controlled mode. */
    onClearSelection?: () => void;
    /** Override the CSV export action (e.g. to export across pages). When set, the Export button calls this. */
    onExport?: () => void;
    /** Show a busy/disabled state on the export button. */
    exporting?: boolean;

    /* ── sorting ── */
    /** The current sort. With `onSortChange` the parent owns it (server mode); without, the
     *  table sorts its rows itself and this is the initial sort. */
    sort?: SortSpec | null;
    /** Server mode: the parent re-queries with the new sort. */
    onSortChange?: (sort: SortSpec | null) => void;

    /* ── paging (server mode) ── */
    /** 1-based page; with `onPageChange` the table shows a pager and the parent fetches the page. */
    page?: number;
    pageSize?: number;
    /** Total pages, or derive from `totalCount` and `pageSize`. */
    totalPages?: number;
    onPageChange?: (page: number) => void;
    /** Offer a page-size picker with these sizes. */
    pageSizeOptions?: number[];
    onPageSizeChange?: (size: number) => void;
}

interface Prefs { widths: Record<string, number>; hidden: string[]; autoRefresh?: boolean; }

/** Stable empty set so controlled selection has a constant identity when no keys are passed. */
const EMPTY_SET: Set<string> = new Set();

/* ── component ────────────────────────────────────────────────────────────── */
export function DataTable<Row>({
    tableId, renamedColumns, columns, rows: loadedRows, rowKey, loading, error, empty, title, findable, toolbarAction, onRowClick: onRowOpen,
    onRefresh, autoRefreshSeconds = AUTO_REFRESH_SECONDS,
    selectable, bulkActions, exportFileName, disableExport, renderExpanded,
    renderDrawer, drawerTitle, detailPath,
    selectedKeys, onSelectedKeysChange, totalCount, allMatchingSelected,
    onSelectAllMatching, onClearSelection, onExport, exporting,
    sort: sortProp, onSortChange, page, pageSize, totalPages: totalPagesProp, onPageChange, pageSizeOptions, onPageSizeChange,
}: DataTableProps<Row>) {
    const navigate = useNavigate();

    const [typed, setTyped] = useState('');
    const rows = useMemo(() => (findable ? findRows(loadedRows, columns, typed) : loadedRows), [findable, loadedRows, columns, typed]);
    const narrowed = rows.length !== loadedRows.length;

    /* sorting — the parent's when it re-queries (server mode); otherwise the table's own */
    const [internalSort, setInternalSort] = useState<SortSpec | null>(sortProp ?? null);
    const sort = onSortChange ? (sortProp ?? null) : internalSort;
    const sortedRows = useMemo(() => (onSortChange ? rows : sortRows(rows, columns, sort)), [rows, columns, sort, onSortChange]);
    const toggleSort = (key: string) => {
        const next: SortSpec | null = !sort || sort.key !== key ? { key, dir: 'asc' } : sort.dir === 'asc' ? { key, dir: 'desc' } : null;
        if (onSortChange) onSortChange(next); else setInternalSort(next);
    };

    /* paging (server mode): shown when the parent owns the page */
    const totalPages = totalPagesProp ?? (totalCount != null && pageSize ? Math.max(1, Math.ceil(totalCount / pageSize)) : undefined);
    const paged = !!onPageChange && page != null;
    const expandable = !!renderExpanded;
    // A leading "open" column appears when a row can be expanded, peeked (drawer), or navigated.
    const hasRowOpen = expandable || !!renderDrawer || !!detailPath || !!onRowOpen;
    const [drawerRow, setDrawerRow] = useState<Row | null>(null);
    const [storedPrefs, setPrefs] = useTablePrefs<Prefs>(`table:${tableId}`, { widths: {}, hidden: [] });
    const prefs = useMemo(() => renameColumnKeys(storedPrefs, renamedColumns), [storedPrefs, renamedColumns]);
    const prefsRef = useRef(prefs); prefsRef.current = prefs;

    const visibleCols = useMemo(() => columns.filter((c) => !prefs.hidden.includes(c.key)), [columns, prefs.hidden]);

    // A column fills leftover horizontal space ONLY when it opts in with `flex: true`. When no
    // column does, we don't stretch an arbitrary one — instead a blank trailing spacer track (added
    // to the grid below) soaks up the slack, so every real column keeps its natural width and the
    // row packs to the left. The spacer is a layout-only track: it isn't a real column, so it stays
    // out of the CSV export and the columns menu.
    const flexKeys = useMemo(
        () => new Set(visibleCols.filter((c) => c.flex).map((c) => c.key)),
        [visibleCols],
    );
    const useSpacer = flexKeys.size === 0;

    /* accordion expansion — only one row open at a time */
    const [expandedKey, setExpandedKey] = useState<string | null>(null);
    useEffect(() => {
        if (expandedKey && !rows.some((r) => rowKey(r) === expandedKey)) setExpandedKey(null);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [rows]);

    /* selection — internal by default; controlled (persists across pages) when onSelectedKeysChange is set */
    const controlled = !!onSelectedKeysChange;
    const [internalSelected, setInternalSelected] = useState<Set<string>>(new Set());
    const selected = controlled ? (selectedKeys ?? EMPTY_SET) : internalSelected;
    const commitSelection = useCallback((next: Set<string>) => {
        if (controlled) onSelectedKeysChange!(next); else setInternalSelected(next);
    }, [controlled, onSelectedKeysChange]);
    // Drop stale keys when the row set changes (internal mode only — controlled selection spans pages).
    useEffect(() => {
        if (controlled) return;
        setInternalSelected((prev) => {
            if (prev.size === 0) return prev;
            const next = new Set<string>();
            for (const r of rows) { const k = rowKey(r); if (prev.has(k)) next.add(k); }
            return next.size === prev.size ? prev : next;
        });
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [rows, controlled]);

    const allKeys = useMemo(() => sortedRows.map(rowKey), [sortedRows, rowKey]);
    const allSelected = allKeys.length > 0 && allKeys.every((k) => selected.has(k));
    const someSelected = selected.size > 0 && !allSelected;
    const selectAllRef = useRef<HTMLInputElement>(null);
    useEffect(() => { if (selectAllRef.current) selectAllRef.current.indeterminate = someSelected && !allMatchingSelected; }, [someSelected, allMatchingSelected]);

    const toggleAll = () => {
        const next = new Set(selected);
        if (allSelected) { for (const k of allKeys) next.delete(k); } else { for (const k of allKeys) next.add(k); }
        commitSelection(next);
    };
    const toggleRow = (k: string) => { const n = new Set(selected); n.has(k) ? n.delete(k) : n.add(k); commitSelection(n); };
    const clearSelection = () => { if (controlled && onClearSelection) onClearSelection(); else commitSelection(new Set()); };
    const selectedRows = useMemo(() => sortedRows.filter((r) => selected.has(rowKey(r))), [sortedRows, selected, rowKey]);
    // When the parent has flagged "all matching" selected, the count reflects the server-wide total.
    const selectionCount = allMatchingSelected && totalCount != null ? totalCount : selected.size;

    // A table that can be refreshed keeps its rows on screen while they reload; any other shows
    // "Loading…" in their place, as does a refreshable one that has no rows yet.
    const busy = !!loading && (!onRefresh || loadedRows.length === 0);

    /* auto-refresh: the reader's choice per table, kept with the table's layout */
    const refreshRef = useRef(onRefresh); refreshRef.current = onRefresh;
    const refreshState = useRef({ selectedCount: 0, drawerOpen: false });
    refreshState.current = { selectedCount: selected.size, drawerOpen: drawerRow != null };
    const autoRefresh = !!onRefresh && !!prefs.autoRefresh;
    useEffect(() => {
        if (!autoRefresh) return;
        const timer = setInterval(() => {
            if (autoRefreshDue({ enabled: true, pageHidden: document.hidden, ...refreshState.current }))
                refreshRef.current?.();
        }, Math.max(5, autoRefreshSeconds) * 1000);
        return () => clearInterval(timer);
    }, [autoRefresh, autoRefreshSeconds]);

    /* column resize */
    const headerRefs = useRef<Record<string, HTMLDivElement | null>>({});
    const dragRef = useRef<{ key: string; startX: number; startWidth: number; w: number } | null>(null);
    const [dragging, setDragging] = useState(false);
    const [, force] = useReducer((x) => x + 1, 0);

    const onResizeStart = (e: React.MouseEvent, col: DataTableColumn<Row>) => {
        e.preventDefault(); e.stopPropagation();
        const el = headerRefs.current[col.key];
        const startWidth = el ? Math.round(el.getBoundingClientRect().width) : (prefs.widths[col.key] ?? col.defaultWidth ?? 120);
        dragRef.current = { key: col.key, startX: e.clientX, startWidth, w: startWidth };
        setDragging(true);
    };

    useEffect(() => {
        if (!dragging) return;
        const onMove = (e: MouseEvent) => {
            const d = dragRef.current; if (!d) return;
            const col = columns.find((c) => c.key === d.key);
            const min = col?.minWidth ?? 60;
            d.w = Math.max(min, Math.round(d.startWidth + (e.clientX - d.startX)));
            force();
        };
        const onUp = () => {
            const d = dragRef.current;
            if (d) setPrefs({ ...prefsRef.current, widths: { ...prefsRef.current.widths, [d.key]: d.w } });
            dragRef.current = null;
            setDragging(false);
        };
        window.addEventListener('mousemove', onMove);
        window.addEventListener('mouseup', onUp);
        return () => { window.removeEventListener('mousemove', onMove); window.removeEventListener('mouseup', onUp); };
    }, [dragging, columns, setPrefs]);

    const widthFor = (col: DataTableColumn<Row>): number | undefined => {
        if (dragRef.current && dragRef.current.key === col.key) return dragRef.current.w;
        return prefs.widths[col.key];
    };

    // A column track: filler → minmax(min, 1fr) so it expands to fill; a resized column → its px
    // width; an unsized one → its default, growing a little while there is room (columnTrack).
    // Resizing changes only the dragged column; the filler absorbs the slack and horizontal
    // scroll kicks in past `tableMinWidth`.
    const trackFor = (c: DataTableColumn<Row>): string =>
        flexKeys.has(c.key) ? `minmax(${c.minWidth ?? 80}px, 1fr)` : columnTrack(c.defaultWidth, widthFor(c));

    const gridTemplate = useMemo(() => {
        const parts: string[] = [];
        if (hasRowOpen) parts.push('32px');
        if (selectable) parts.push('36px');
        for (const c of visibleCols) parts.push(trackFor(c));
        // Trailing blank filler — only when no real column flexes — so columns left-pack and the
        // slack lands in this spacer at the far right. Collapses to 0 so it never forces scroll.
        if (useSpacer) parts.push('minmax(0, 1fr)');
        return parts.join(' ');
        // dragging/force drive live width updates via dragRef
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [visibleCols, selectable, hasRowOpen, prefs.widths, flexKeys, dragging, useSpacer]);

    // Floor width: below this the table scrolls horizontally instead of squashing fixed columns.
    // Identical for the header and every row so columns stay aligned and scroll in unison (this is
    // why we don't use content-driven `max-content`, which would let rows compute different widths).
    const tableMinWidth = useMemo(() => {
        let min = (hasRowOpen ? 32 : 0) + (selectable ? 36 : 0);
        for (const c of visibleCols) min += flexKeys.has(c.key) ? (c.minWidth ?? 80) : (widthFor(c) ?? c.defaultWidth ?? 120);
        return min;
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [visibleCols, selectable, hasRowOpen, prefs.widths, flexKeys, dragging]);

    /* column visibility menu */
    const [menuOpen, setMenuOpen] = useState(false);
    const toggleColumn = (key: string) => {
        const hidden = prefs.hidden.includes(key) ? prefs.hidden.filter((k) => k !== key) : [...prefs.hidden, key];
        setPrefs({ ...prefs, hidden });
    };
    const resetLayout = () => setPrefs({ widths: {}, hidden: [] });

    /* CSV export */
    const exportCsv = useCallback(() => {
        const rowsOut = selected.size > 0 ? selectedRows : sortedRows;
        const cols = visibleCols;
        const esc = (v: unknown) => {
            if (typeof v === 'number') return String(v);
            let s = v == null ? '' : String(v);
            // Neutralize spreadsheet formula injection (OWASP): a leading =,+,-,@,tab,CR can be
            // executed as a formula (DDE/HYPERLINK/WEBSERVICE) when the CSV is opened in Excel/Sheets.
            if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
            return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
        };
        const cellVal = (c: DataTableColumn<Row>, r: Row): string | number => {
            if (c.exportValue) { const v = c.exportValue(r); return v == null ? '' : v; }
            const rendered = c.render(r);
            return typeof rendered === 'string' || typeof rendered === 'number' ? rendered : '';
        };
        const lines = [cols.map((c) => esc(c.header)).join(',')];
        for (const r of rowsOut) lines.push(cols.map((c) => esc(cellVal(c, r))).join(','));
        const blob = new Blob(['﻿' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = `${exportFileName || tableId}.csv`;
        document.body.appendChild(a); a.click(); a.remove();
        URL.revokeObjectURL(url);
    }, [sortedRows, selectedRows, selected.size, visibleCols, exportFileName, tableId]);

    const alignCls = (a?: string) => (a === 'right' ? 'text-right justify-end' : a === 'center' ? 'text-center justify-center' : 'text-left');
    const bulkBtnCls = (v?: string) =>
        v === 'danger' ? 'bg-crit-soft text-crit border-crit/40 hover:bg-crit/15'
            : v === 'primary' ? 'bg-accent text-on-accent border-accent hover:bg-accent-hover'
                : 'bg-raised text-ink border-line-strong hover:bg-hover';

    return (
        <div className="bg-raised border border-line rounded-lg overflow-hidden">
            {/* header, first line: what the table is, and the tools for looking at it */}
            <div className="px-3 py-2 border-b border-line flex items-center justify-between gap-2 flex-wrap">
                <h3 className="text-sm font-semibold text-ink min-h-[28px] flex items-center gap-1">{title}<span className="text-ink-muted font-normal">({narrowed ? `${rows.length} of ${loadedRows.length}` : (totalCount ?? rows.length)})</span></h3>
                <div className="flex items-center gap-2">
                    {onRefresh && (
                        <>
                            <label className="inline-flex items-center gap-1.5 text-xs text-ink-muted cursor-pointer select-none"
                                title={`Reload every ${autoRefreshSeconds} seconds. Pauses while rows are ticked, a row is open, or the page is in the background.`}>
                                <input type="checkbox" checked={!!prefs.autoRefresh}
                                    onChange={(e) => setPrefs({ ...prefsRef.current, autoRefresh: e.target.checked })} />
                                {autoRefreshLabel(autoRefreshSeconds)}
                            </label>
                            <button type="button" onClick={onRefresh} disabled={!!loading}
                                className="px-2.5 py-1 text-xs rounded border border-line-strong bg-raised text-ink hover:bg-hover disabled:opacity-50 transition-colors">
                                {loading ? 'Refreshing…' : 'Refresh'}
                            </button>
                        </>
                    )}
                    {findable && (
                        <input type="search" value={typed} onChange={(e) => setTyped(e.target.value)} placeholder="Find in this table"
                            aria-label={title ? `Find in ${title}` : 'Find in this table'}
                            className="w-48 px-2.5 py-1 text-xs bg-raised border border-line-strong rounded text-ink placeholder-ink-faint focus:outline-none focus:border-accent" />
                    )}
                    <div className="relative">
                        <button onClick={() => setMenuOpen((o) => !o)}
                            className="px-2.5 py-1 text-xs rounded border border-line-strong bg-raised text-ink hover:bg-hover transition-colors inline-flex items-center gap-1">
                            Columns <Chevron direction={menuOpen ? 'up' : 'down'} className="w-2.5 h-2.5" />
                        </button>
                        {menuOpen && (
                            <>
                                <div className="fixed inset-0 z-10" onClick={() => setMenuOpen(false)} />
                                <div className="absolute right-0 mt-1 z-20 w-52 bg-raised border border-line rounded shadow-lg p-2 space-y-1">
                                    {columns.map((c) => {
                                        const hidden = prefs.hidden.includes(c.key);
                                        const locked = c.hideable === false;
                                        return (
                                            <label key={c.key} className={`flex items-center gap-2 text-xs px-1 py-0.5 rounded ${locked ? 'opacity-50' : 'cursor-pointer hover:bg-hover'}`}>
                                                <input type="checkbox" checked={!hidden} disabled={locked} onChange={() => toggleColumn(c.key)}
                                                    className="h-3.5 w-3.5 rounded border-line-strong accent-accent" />
                                                <span className="text-ink">{c.header}</span>
                                            </label>
                                        );
                                    })}
                                    <button onClick={() => { resetLayout(); setMenuOpen(false); }}
                                        className="w-full mt-1 px-1 py-1 text-[11px] text-accent-ink hover:underline text-left">Reset columns</button>
                                </div>
                            </>
                        )}
                    </div>
                    {!disableExport && (
                        <button onClick={onExport ?? exportCsv} disabled={exporting}
                            className="px-2.5 py-1 text-xs rounded border border-line-strong bg-raised text-ink hover:bg-hover transition-colors disabled:opacity-50"
                            title={onExport ? 'Export matching rows (CSV)' : (selected.size > 0 ? `Export ${selected.size} selected row(s)` : 'Export all rows')}>
                            {exporting ? 'Exporting…' : 'Export CSV'}
                        </button>
                    )}
                </div>
            </div>

            {/* header, second line: what can be done with the ticked rows, and "+ New" at the right */}
            {(selectable || toolbarAction) && (
                <div className="px-3 py-1.5 border-b border-line flex items-center gap-2 flex-wrap min-h-[36px]">
                    {selectable && (<>
                    <span className={`text-xs w-24 shrink-0 ${selected.size > 0 ? 'font-semibold text-ink' : 'text-ink-muted'}`}>
                        {selected.size > 0 ? `${selectionCount} selected` : 'None selected'}
                    </span>
                    {detailPath && (
                        <button disabled={selected.size !== 1}
                            onClick={() => { const row = selectedRows[0]; if (row) navigate(detailPath(row)); }}
                            className={`px-2.5 py-1 text-xs rounded border transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${bulkBtnCls()}`}>
                            Details
                        </button>
                    )}
                    {bulkActions?.map((a) => {
                        const disabled = selected.size === 0 || (a.single && selected.size !== 1) || (a.enabledFor ? !selectedRows.every(a.enabledFor) : false);
                        return (
                            <button key={a.label} disabled={disabled} onClick={() => a.onClick(selectedRows)}
                                className={`px-2.5 py-1 text-xs rounded border transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${bulkBtnCls(a.variant)}`}>
                                {a.label}
                            </button>
                        );
                    })}
                    {selected.size > 0
                        ? <button onClick={clearSelection} className="text-xs text-ink-muted hover:underline">Deselect</button>
                        : <span className="text-xs text-ink-faint">{detailPath || bulkActions?.length ? 'Tick rows to act on them.' : 'Tick rows to export only those.'}</span>}
                    </>)}
                    {toolbarAction && <div className="ml-auto flex items-center gap-2">{toolbarAction}</div>}
                </div>
            )}

            {/* select-all-matching banner (controlled / server-paginated tables) */}
            {selectable && controlled && totalCount != null && totalCount > allKeys.length && (allSelected || allMatchingSelected) && (
                <div className="px-3 py-2 border-b border-line bg-accent-soft text-xs text-accent-ink flex items-center gap-2 justify-center">
                    {allMatchingSelected ? (
                        <>
                            <span>All <strong>{totalCount}</strong> rows matching this filter are selected.</span>
                            <button onClick={clearSelection} className="font-semibold underline hover:no-underline">Clear selection</button>
                        </>
                    ) : (
                        <>
                            <span>All <strong>{allKeys.length}</strong> on this page are selected.</span>
                            {onSelectAllMatching && (
                                <button onClick={onSelectAllMatching} className="font-semibold underline hover:no-underline">Select all {totalCount} matching</button>
                            )}
                        </>
                    )}
                </div>
            )}

            {/* states */}
            {busy && <div className="p-4 text-sm text-ink-muted text-center">Loading…</div>}
            {error && <div className="p-3"><InlineNotice notice={error} /></div>}
            {!busy && !loading && !error && rows.length === 0 && (
                <div className="p-6 text-sm text-ink-muted text-center">
                    {loadedRows.length > 0 ? <>Nothing here matches "{typed}". <button onClick={() => setTyped('')} className="text-accent-ink hover:underline">Clear</button></> : (empty || 'No rows')}
                </div>
            )}

            {/* grid */}
            {!busy && !error && rows.length > 0 && (
                <div className="overflow-x-auto" aria-busy={!!loading}>
                    {/* header */}
                    <div className="grid items-center border-b border-line bg-sunken" style={{ gridTemplateColumns: gridTemplate, minWidth: tableMinWidth }}>
                        {hasRowOpen && <div className="py-2" />}
                        {selectable && (
                            <div className="flex items-center justify-center py-2">
                                <input ref={selectAllRef} type="checkbox" checked={allSelected} onChange={toggleAll}
                                    className="h-3.5 w-3.5 rounded border-line-strong accent-accent" />
                            </div>
                        )}
                        {visibleCols.map((c) => (
                            <div key={c.key} ref={(el) => { headerRefs.current[c.key] = el; }} title={c.headerTitle ?? (c.sortable ? `Sort by ${c.header}` : undefined)}
                                onClick={c.sortable ? () => toggleSort(c.key) : undefined}
                                role={c.sortable ? 'button' : undefined}
                                aria-sort={c.sortable && sort?.key === c.key ? (sort.dir === 'asc' ? 'ascending' : 'descending') : undefined}
                                className={`relative flex items-center gap-1 px-3 py-2 label-caps select-none overflow-hidden ${alignCls(c.align)} ${c.sortable ? 'cursor-pointer hover:text-ink' : ''}`}>
                                <span className="truncate">{c.header}</span>
                                {c.sortable && (
                                    <span aria-hidden="true" className={`text-[10px] flex-shrink-0 ${sort?.key === c.key ? 'text-accent-ink' : 'text-ink-faint'}`}>
                                        {sort?.key === c.key ? (sort.dir === 'asc' ? '\u25B2' : '\u25BC') : '\u21C5'}
                                    </span>
                                )}
                                {c.resizable !== false && !flexKeys.has(c.key) && (
                                    <div onMouseDown={(e) => onResizeStart(e, c)}
                                        className="absolute top-0 right-0 h-full w-1.5 cursor-col-resize hover:bg-accent-hover active:bg-accent-hover" />
                                )}
                            </div>
                        ))}
                        {useSpacer && <div aria-hidden className="py-2" />}
                    </div>
                    {/* rows */}
                    {sortedRows.map((r) => {
                        const k = rowKey(r);
                        const isSel = selected.has(k);
                        const isExp = expandedKey === k;
                        const onRowClick = hasRowOpen
                            ? (e: React.MouseEvent) => {
                                // Don't act when the click lands on an interactive control inside a cell.
                                if ((e.target as HTMLElement).closest('button,input,a,select,textarea,label')) return;
                                if (onRowOpen) onRowOpen(r);
                                else if (renderDrawer) setDrawerRow(r);
                                else if (expandable) setExpandedKey((cur) => (cur === k ? null : k));
                                else if (detailPath) navigate(detailPath(r));
                            }
                            : undefined;
                        return (
                            <React.Fragment key={k}>
                                <div style={{ gridTemplateColumns: gridTemplate, minWidth: tableMinWidth }} onClick={onRowClick}
                                    className={`grid items-center border-b border-line tabular-nums transition-colors ${hasRowOpen ? 'cursor-pointer' : ''} ${isSel ? 'bg-accent-soft' : isExp ? 'bg-sunken' : 'hover:bg-hover'}`}>
                                    {hasRowOpen && (
                                        <div className="flex items-center justify-center py-2 text-ink-faint select-none">
                                            <Chevron {...(expandable ? { open: isExp } : { direction: 'right' as const })} className="w-2.5 h-2.5" />
                                        </div>
                                    )}
                                    {selectable && (
                                        <div className="flex items-center justify-center py-2">
                                            <input type="checkbox" checked={isSel} onChange={() => toggleRow(k)}
                                                className="h-3.5 w-3.5 rounded border-line-strong accent-accent" />
                                        </div>
                                    )}
                                    {visibleCols.map((c) => (
                                        <div key={c.key} className={`px-3 py-2 text-sm text-ink min-w-0 overflow-hidden flex items-center ${alignCls(c.align)}`}>
                                            <div className={c.truncate === false ? 'min-w-0' : 'truncate w-full'}>{c.render(r)}</div>
                                        </div>
                                    ))}
                                    {useSpacer && <div aria-hidden />}
                                </div>
                                {isExp && renderExpanded && (
                                    <div className="border-b border-line bg-sunken px-4 py-3" style={{ minWidth: tableMinWidth }}>
                                        {renderExpanded(r)}
                                    </div>
                                )}
                            </React.Fragment>
                        );
                    })}
                </div>
            )}

            {/* pager (server mode) */}
            {paged && (
                <div className="px-3 py-2 border-t border-line flex items-center justify-between gap-3 flex-wrap text-xs text-ink-muted">
                    <span>
                        {totalCount != null ? `${totalCount} row${totalCount === 1 ? '' : 's'}` : ''}
                        {totalPages != null ? ` · page ${page} of ${totalPages}` : ` · page ${page}`}
                    </span>
                    <span className="flex items-center gap-2">
                        {pageSizeOptions && onPageSizeChange && pageSize != null && (
                            <label className="flex items-center gap-1">
                                <span>Rows</span>
                                <select value={pageSize} onChange={(e) => onPageSizeChange(Number(e.target.value))}
                                    className="px-1.5 py-0.5 rounded border border-line-strong bg-raised text-ink">
                                    {pageSizeOptions.map((n) => <option key={n} value={n}>{n}</option>)}
                                </select>
                            </label>
                        )}
                        <button onClick={() => onPageChange!(1)} disabled={page! <= 1}
                            className="px-2 py-1 rounded border border-line-strong bg-raised text-ink hover:bg-hover disabled:opacity-40 disabled:cursor-not-allowed">First</button>
                        <button onClick={() => onPageChange!(page! - 1)} disabled={page! <= 1}
                            className="px-2 py-1 rounded border border-line-strong bg-raised text-ink hover:bg-hover disabled:opacity-40 disabled:cursor-not-allowed">Previous</button>
                        <button onClick={() => onPageChange!(page! + 1)} disabled={totalPages != null ? page! >= totalPages : rows.length < (pageSize ?? 0)}
                            className="px-2 py-1 rounded border border-line-strong bg-raised text-ink hover:bg-hover disabled:opacity-40 disabled:cursor-not-allowed">Next</button>
                        {totalPages != null && (
                            <button onClick={() => onPageChange!(totalPages)} disabled={page! >= totalPages}
                                className="px-2 py-1 rounded border border-line-strong bg-raised text-ink hover:bg-hover disabled:opacity-40 disabled:cursor-not-allowed">Last</button>
                        )}
                    </span>
                </div>
            )}

            {/* read-only detail drawer */}
            {renderDrawer && (
                <Drawer
                    open={!!drawerRow}
                    onClose={() => setDrawerRow(null)}
                    title={drawerRow ? (drawerTitle ? drawerTitle(drawerRow) : 'Details') : ''}
                    footer={drawerRow && detailPath ? (
                        <button onClick={() => navigate(detailPath(drawerRow))}
                            className="w-full px-3 py-2 text-sm bg-accent text-on-accent rounded hover:bg-accent-hover transition-colors">
                            Open full page →
                        </button>
                    ) : undefined}>
                    {drawerRow ? renderDrawer(drawerRow) : null}
                </Drawer>
            )}
        </div>
    );
}

// No default export: shared/README.md rule 3. Every call site already imported the named
// binding, so nothing changes for them.
