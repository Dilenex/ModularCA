import React, { useState, useEffect, useRef, useCallback } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { errorNotice } from '@shared-auth/api/notices';
import { apiGet, apiPostWithMfa } from '../api/client';
import { recordTableProps } from '../components/RecordDrawer';
import type { RecordDescriptor } from '@shared/records';
import { useScope } from '../context/ScopeContext';
import { useToast } from '@shared/context/ToastContext';
import { useStepUp } from '../components/StepUpMfaContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DataTable, DataTableColumn } from '@shared/components/DataTable';
import { useTableQuery } from '@shared/hooks/useTableQuery';
import { formatSort, parseSort, viewQuery, type TableQueryValues } from '@shared/tableQuery';
import { SavedViews } from '@shared/components/SavedViews';
import { REVOCATION_REASONS, RevocationReasonHint } from './CertificateDetail';
import { StepUpOps } from '@shared/generated';
import { FieldHint } from '@shared/components/forms';
import { FilterBar, FilterField, filterControlClass } from '@shared/components/FilterBar';
import { Link } from 'react-router-dom';
import { capitalize, expiryHandling, expiryPhrase, expiryState, isoDay, lifecycleTone, toneTextClass } from './certLifecycle';
import { KindTabStrip, useKindTabs } from '../components/KindTabs';
import { useAuth } from '../context/AuthContext';
import { canUseSshTab } from '../authz';
import { CERT_VIEW } from '../gates';
import { SshCertificatesTab } from './SshCertificates';

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function certStatus(cert: any): 'active' | 'revoked' | 'expired' {
    if (cert.revoked) return 'revoked';
    if (new Date(cert.notAfter) < new Date()) return 'expired';
    return 'active';
}

function parseSans(raw: any): string[] | null {
    if (!raw) return null;
    if (Array.isArray(raw)) return raw;
    try { const parsed = JSON.parse(raw); if (Array.isArray(parsed)) return parsed; } catch { /* not JSON */ }
    return null;
}

const certKey = (c: any): string => c.serialNumber || c.certificateId;

/** The status chip: an expired certificate that was replaced is routine, so it is shown muted. */
function StatusChip({ cert }: { cert: any }) {
    const st = certStatus(cert);
    if (st === 'expired' && cert.replaced) return <StatusBadge status="disabled" label="expired" />;
    return <StatusBadge status={st} />;
}

/**
 * The expiry cell: the date, then for an expired or soon-expiring certificate how long ago or
 * how soon, and whether it was replaced.
 */
function ExpiryCell({ cert }: { cert: any }) {
    const now = new Date();
    const state = expiryState(cert, now);
    const show = state === 'expired' || state === 'expiring';
    const handling = expiryHandling(cert);
    const tone = lifecycleTone(cert.notAfter, !!cert.replaced || handling !== null, now);
    return (
        <div className="flex flex-col min-w-0">
            <span className="text-xs text-ink-muted">{formatDate(cert.notAfter)}</span>
            {show && (
                <span className="text-xs truncate">
                    <span className={toneTextClass(tone)}>{capitalize(expiryPhrase(cert.notAfter, now))}</span>
                    <span className="text-ink-muted"> · </span>
                    {cert.replaced
                        ? (cert.replacedBySerial
                            ? <Link to={`/certificates/${cert.replacedBySerial}`} onClick={(e) => e.stopPropagation()} className="text-accent-ink hover:underline">Replaced by <span className="font-mono">{cert.replacedBySerial}</span></Link>
                            : <span className="text-ink-muted">Replaced</span>)
                        : <span className="text-ink-muted">{handling === 'retired' ? 'Retired' : handling === 'dismissed' ? 'Warning dismissed' : 'Not replaced'}</span>}
                </span>
            )}
        </div>
    );
}

// Cross-page CSV: a fixed, complete field set (independent of which columns are visible/hidden).
/** Key algorithm families the list can be narrowed to; the server matches a family or an exact name. */
const KEY_ALGORITHM_FILTERS = ['RSA', 'ECDSA', 'Ed25519', 'Ed448', 'ML-DSA', 'SLH-DSA'];

/** The "Expiring" choices, in days. */
const EXPIRING_DAYS = [7, 30, 60, 90];
const DAY_MS = 24 * 60 * 60 * 1000;
/** The filter values for active certificates that expire within `days`, as the dashboard links them. */
const expiringWithin = (days: number, now: Date = new Date()) =>
    ({ status: 'active', notAfterFrom: '', notAfterTo: isoDay(new Date(now.getTime() + (days + 1) * DAY_MS)) });

const CSV_HEADERS = ['Serial', 'Subject', 'Issuer', 'Status', 'Not Before', 'Not After', 'Key Algorithm', 'Revoked', 'Revocation Reason', 'Replaced', 'Replaced By', 'Retired', 'Expiry Warning Dismissed'];
const csvCells = (c: any): (string | number)[] => [
    c.serialNumber || '', c.subjectDN || '', c.issuer || '', certStatus(c),
    c.notBefore || '', c.notAfter || '', c.keyAlgorithm || '', c.revoked ? 'Yes' : 'No', c.revocationReason || '',
    c.replaced ? 'Yes' : 'No', c.replacedBySerial || '', c.retiredAt || '', c.expiryWarningDismissedAt || '',
];
function downloadCsv(rows: any[], filename: string) {
    const esc = (v: unknown) => {
        if (typeof v === 'number') return String(v);
        let s = v == null ? '' : String(v);
        // Neutralize spreadsheet formula injection (OWASP): a leading =,+,-,@,tab,CR can execute in Excel/Sheets.
        if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
        return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const lines = [CSV_HEADERS.join(',')];
    for (const r of rows) lines.push(csvCells(r).map(esc).join(','));
    const blob = new Blob(['﻿' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
}

const EXPORT_PAGE_SIZE = 200;
const EXPORT_MAX_ROWS = 50000; // safety cap on a fetch-all export

/** What the certificate list keeps in the URL. Defaults stay out of the link. */
const QUERY_DEFAULTS: TableQueryValues = {
    page: '1', pageSize: '20', sort: '-notBefore',
    search: '', status: 'all', replaced: '', serial: '', san: '', issuer: '', caId: '', keyAlgorithm: '',
    notAfterFrom: '', notAfterTo: '', issuedFrom: '', issuedTo: '',
};
const PAGE_SIZES = [20, 50, 100];

/** The X.509 tab of All Certificates: the certificate list with its filters, saved views and bulk revoke. */
const X509Certificates: React.FC = () => {
    const { showToast } = useToast();
    const { requireStepUp } = useStepUp();
    // Page, sort and every filter live in the URL (see useTableQuery), so a filtered view is a
    // link and the back button walks through filter changes.
    const [q, setQ] = useTableQuery('certificates', QUERY_DEFAULTS);
    const page = Math.max(1, parseInt(q.page, 10) || 1);
    const pageSize = PAGE_SIZES.includes(parseInt(q.pageSize, 10)) ? parseInt(q.pageSize, 10) : 20;
    const sort = parseSort(q.sort);
    const statusFilter = (['active', 'revoked', 'expired'].includes(q.status) ? q.status : 'all') as 'all' | 'active' | 'revoked' | 'expired';
    const replacedFilter = q.replaced === 'yes' || q.replaced === 'no' ? q.replaced : '';
    const { caId: caIdFilter, keyAlgorithm: keyAlgorithmFilter, notAfterFrom, notAfterTo, issuedFrom, issuedTo } = q;
    // The typed filters are edited locally and written to the URL after a pause, so every
    // keystroke is not a history entry and not a request.
    const [search, setSearch] = useState(q.search);
    const [serialFilter, setSerialFilter] = useState(q.serial);
    const [sanFilter, setSanFilter] = useState(q.san);
    const [issuerFilter, setIssuerFilter] = useState(q.issuer);
    useEffect(() => {
        const t = setTimeout(() => {
            if (search !== q.search || serialFilter !== q.serial || sanFilter !== q.san || issuerFilter !== q.issuer)
                setQ({ search, serial: serialFilter, san: sanFilter, issuer: issuerFilter });
        }, 700);
        return () => clearTimeout(t);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [search, serialFilter, sanFilter, issuerFilter]);
    // A saved view or the back button changed the URL underneath the typed fields: follow it.
    useEffect(() => { setSearch(q.search); setSerialFilter(q.serial); setSanFilter(q.san); setIssuerFilter(q.issuer); }, [q.search, q.serial, q.san, q.issuer]);
    const setPage = (n: number) => setQ({ page: String(n) });

    // The console's CA scope supplies the issuing-CA filter; under a single-CA scope the
    // filter is fixed to that CA and the select below is locked to say so.
    const { scope, caId: scopeCaId, caQuery } = useScope();
    const scopeLocked = scope.kind === 'ca';
    // Follow the scope both ways: a CA scope pins the filter; widening it back clears the pin.
    // Only a change of scope clears it, so a deep link with ?caId= survives the first render.
    const wasLocked = useRef(scopeLocked);
    useEffect(() => {
        if (scopeLocked && scopeCaId && q.caId !== scopeCaId) setQ({ caId: scopeCaId });
        else if (!scopeLocked && wasLocked.current && q.caId) setQ({ caId: '' });
        wasLocked.current = scopeLocked;
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [scopeLocked, scopeCaId]);
    const [authorities, setAuthorities] = useState<any[]>([]);
    const [showAdvanced, setShowAdvanced] = useState(() =>
        ['serial', 'san', 'issuer', 'caId', 'keyAlgorithm', 'notAfterFrom', 'notAfterTo', 'issuedFrom', 'issuedTo'].some((k) => q[k]));
    const [totalPages, setTotalPages] = useState(1);
    const [totalCount, setTotalCount] = useState(0);
    const [certificates, setCertificates] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);

    // Cross-page selection (keyed by serial). Cache of every loaded row so a selected-rows export
    // has the data for keys ticked on pages no longer rendered.
    const [selectedKeys, setSelectedKeys] = useState<Set<string>>(new Set());
    const [allMatching, setAllMatching] = useState(false);
    const [exporting, setExporting] = useState(false);
    const rowCache = useRef<Map<string, any>>(new Map());
    const [reloadKey, setReloadKey] = useState(0); // bump to re-fetch the current page (after revoke)

    // Bulk revoke — one shared reason + one step-up prompt for the explicitly-selected serials.
    const [revokeOpen, setRevokeOpen] = useState(false);
    const [revokeReason, setRevokeReason] = useState('Unspecified');
    const [revokeBusy, setRevokeBusy] = useState(false);

    useEffect(() => {
        apiGet<any>('/api/v1/admin/authorities')
            .then((data) => {
                const cas = Array.isArray(data) ? data : (data.items || data.authorities || []);
                const flat: any[] = [];
                const flatten = (list: any[]) => { for (const ca of list) { flat.push(ca); if (ca.children) flatten(ca.children); } };
                flatten(cas);
                setAuthorities(flat);
            })
            .catch(() => { /* non-critical */ });
    }, []);

    // Build the query params for the active filter (page/size supplied by the caller). The
    // space scope arrives through caQuery when no single CA is pinned.
    const buildParams = useCallback((pageNum: number, size: number) => {
        const params = new URLSearchParams({ page: String(pageNum), pageSize: String(size) });
        if (q.sort) params.set('sort', q.sort);
        if (q.search) params.set('search', q.search);
        if (statusFilter !== 'all') params.set('status', statusFilter);
        if (replacedFilter) params.set('replaced', replacedFilter);
        if (q.serial) params.set('serial', q.serial);
        if (q.san) params.set('san', q.san);
        if (q.issuer) params.set('issuer', q.issuer);
        if (caIdFilter) params.set('caId', caIdFilter);
        else { const scoped = caQuery(); if (scoped.startsWith('?spaceId=')) params.set('spaceId', decodeURIComponent(scoped.slice('?spaceId='.length))); }
        if (keyAlgorithmFilter) params.set('keyAlgorithm', keyAlgorithmFilter);
        if (notAfterFrom) params.set('notAfterFrom', notAfterFrom);
        if (notAfterTo) params.set('notAfterTo', notAfterTo);
        if (issuedFrom) params.set('issuedFrom', issuedFrom);
        if (issuedTo) params.set('issuedTo', issuedTo);
        return params;
    }, [q.sort, q.search, statusFilter, replacedFilter, q.serial, q.san, q.issuer, caIdFilter, caQuery, keyAlgorithmFilter, notAfterFrom, notAfterTo, issuedFrom, issuedTo]);

    /** The current filter as a saved view sees it: filters and sort, never the page. */
    const currentView = viewQuery(q, QUERY_DEFAULTS);
    const applyView = (view: string) => {
        const params = new URLSearchParams(view);
        const next: Partial<TableQueryValues> = {};
        for (const key of Object.keys(QUERY_DEFAULTS)) if (key !== 'page') next[key] = params.get(key) ?? QUERY_DEFAULTS[key];
        setQ(next);
    };

    // Reset selection whenever the matching set changes (filter change, not page change).
    useEffect(() => {
        setSelectedKeys(new Set());
        setAllMatching(false);
        rowCache.current = new Map();
    }, [currentView, caIdFilter]);

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError(null);
        apiGet<any>(`/api/v1/admin/certificates?${buildParams(page, pageSize)}`)
            .then((data) => {
                if (cancelled) return;
                const items = Array.isArray(data) ? data : (data.items || []);
                const count = data.total ?? items.length;
                setTotalCount(count);
                setTotalPages(data.totalPages || Math.ceil(count / pageSize) || 1);
                for (const c of items) rowCache.current.set(certKey(c), c);
                setCertificates(items);
                setLoading(false);
            })
            .catch((err) => { if (!cancelled) { setError(errorNotice(err, 'Failed to load certificates')); setLoading(false); } });
        return () => { cancelled = true; };
    }, [page, pageSize, buildParams, reloadKey]);

    // Bulk-revoke the explicitly-selected serials with one reason behind a single step-up prompt.
    // (Leaf certs only — the server skips CA certs, which need the RevokeCa op / a ceremony.)
    const runBulkRevoke = async () => {
        const serials = Array.from(selectedKeys);
        if (serials.length === 0) return;
        setRevokeBusy(true);
        try {
            const res: any = await apiPostWithMfa('/api/v1/admin/certificates/bulk-revoke',
                { serialNumbers: serials, reason: revokeReason }, requireStepUp, StepUpOps.RevokeCert);
            const revoked = res?.revoked ?? 0, skipped = res?.skipped ?? 0, failed = res?.failed ?? 0;
            if (revoked > 0) showToast('success', `Revoked ${revoked} certificate${revoked === 1 ? '' : 's'}`);
            if (skipped > 0) showToast('warning', `${skipped} skipped (already revoked, CA cert, or not permitted)`);
            if (failed > 0) showToast('error', `${failed} failed to revoke`);
            if (revoked === 0 && skipped === 0 && failed === 0) showToast('info', 'No certificates revoked');
            setRevokeOpen(false);
            setSelectedKeys(new Set());
            setAllMatching(false);
            setReloadKey((k) => k + 1);
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Bulk revoke failed');
        } finally {
            setRevokeBusy(false);
        }
    };

    // A from-date after its to-date matches nothing; the server answers an empty page rather than
    // an error, so the list (and a CSV export) would silently come back empty.
    const expiresRangeInverted = !!(notAfterFrom && notAfterTo && notAfterFrom > notAfterTo);
    const issuedRangeInverted = !!(issuedFrom && issuedTo && issuedFrom > issuedTo);
    const rangeInverted = expiresRangeInverted || issuedRangeInverted;

    const handleExport = async () => {
        if (rangeInverted) { showToast('warning', 'Fix the date range first: the "after" date is later than the "before" date, so nothing matches.'); return; }
        // Specific selection across pages → export those from the cache.
        if (selectedKeys.size > 0 && !allMatching) {
            const rows = Array.from(selectedKeys).map((k) => rowCache.current.get(k)).filter(Boolean);
            downloadCsv(rows, 'certificates-selected.csv');
            return;
        }
        // "All matching" (or nothing selected) → fetch every matching page and export.
        setExporting(true);
        try {
            const first = await apiGet<any>(`/api/v1/admin/certificates?${buildParams(1, EXPORT_PAGE_SIZE)}`);
            let items: any[] = Array.isArray(first) ? first : (first.items || []);
            const count = first.total ?? items.length;
            const pages = first.totalPages || Math.ceil(count / EXPORT_PAGE_SIZE) || 1;
            const all: any[] = [...items];
            for (let pnum = 2; pnum <= pages && all.length < EXPORT_MAX_ROWS; pnum++) {
                const d = await apiGet<any>(`/api/v1/admin/certificates?${buildParams(pnum, EXPORT_PAGE_SIZE)}`);
                items = Array.isArray(d) ? d : (d.items || []);
                all.push(...items);
            }
            const capped = all.length >= EXPORT_MAX_ROWS;
            downloadCsv(all.slice(0, EXPORT_MAX_ROWS), 'certificates.csv');
            showToast('success', `Exported ${Math.min(all.length, EXPORT_MAX_ROWS)} certificate(s)${capped ? ` (capped at ${EXPORT_MAX_ROWS})` : ''}.`);
        } catch (err: any) {
            showToast('error', err.message || 'Export failed');
        } finally {
            setExporting(false);
        }
    };

    // The certificate as a record: its row, its drawer (overview, audit trail, other certificates
    // for the same subject) and its page, from one description.
    const record: RecordDescriptor<any> = {
        kind: 'certificate',
        key: certKey,
        title: (c) => (c.subjectDN || '').match(/CN=([^,]+)/)?.[1] || c.serialNumber,
        status: (c) => { const st = certStatus(c); return { label: st, tone: st === 'active' ? 'ok' : st === 'revoked' ? 'bad' : st === 'expired' ? (c.replaced ? 'neutral' : 'warn') : 'neutral' }; },
        columns: [
            { key: 'status', header: 'Status', defaultWidth: 100, truncate: false, exportValue: (c) => certStatus(c), render: (c) => <StatusChip cert={c} /> },
            { key: 'serial', header: 'Serial', defaultWidth: 180, sortable: true, exportValue: (c) => c.serialNumber, render: (c) => <span className="data-mono text-ink-muted truncate">{c.serialNumber}</span> },
            { key: 'subject', header: 'Subject', defaultWidth: 280, minWidth: 160, sortable: true, exportValue: (c) => c.subjectDN, render: (c) => <span className="text-sm text-ink truncate">{c.subjectDN}</span> },
            { key: 'keyAlg', header: 'Key Alg', defaultWidth: 110, exportValue: (c) => c.keyAlgorithm || '', render: (c) => <span className="text-xs text-ink-muted">{c.keyAlgorithm || '-'}</span> },
            { key: 'notAfter', header: 'Expires', defaultWidth: 240, minWidth: 140, sortable: true, truncate: false, exportValue: (c) => formatDate(c.notAfter), render: (c) => <ExpiryCell cert={c} /> },
        ],
        sections: [
            { fields: [
                { label: 'Serial', value: (c) => c.serialNumber, mono: true, copyable: true },
                { label: 'Subject', value: (c) => c.subjectDN },
                { label: 'Issuer', value: (c) => c.issuer },
                { label: 'Key Algorithm', value: (c) => c.keyAlgorithm },
            ] },
            { title: 'Validity', fields: [
                { label: 'Not Before', value: (c) => formatDate(c.notBefore) },
                { label: 'Not After', value: (c) => formatDate(c.notAfter) },
                { label: 'Expiry', value: (c) => { const st = expiryState(c); return st === 'expired' || st === 'expiring' ? capitalize(expiryPhrase(c.notAfter)) : null; } },
                { label: 'Replaced by', value: (c) => (c.replaced ? (c.replacedBySerial || 'A replacement you cannot view') : null), mono: true },
            ] },
            { title: 'Names', fields: [
                { label: 'SANs', value: (c) => { const sans = parseSans(c.subjectAlternativeNames); return sans && sans.length > 0 ? sans.join(', ') : null; } },
            ] },
        ],
        audit: { tab: 'General', target: (c) => (c.serialNumber ? { type: 'Certificate', id: c.serialNumber } : null) },
        related: [{
            title: 'Other certificates for this subject',
            load: async (c) => {
                const cn = (c.subjectDN || '').match(/CN=([^,]+)/)?.[1];
                if (!cn) return [];
                const r = await apiGet<any>(`/api/v1/admin/certificates?search=${encodeURIComponent(cn)}&pageSize=10`);
                return (r?.items ?? []).filter((x: any) => certKey(x) !== certKey(c));
            },
            descriptor: {
                kind: 'certificate-sibling',
                key: certKey,
                title: (c) => c.subjectDN,
                columns: [
                    { key: 'status', header: 'Status', defaultWidth: 90, truncate: false, render: (c) => <StatusBadge status={certStatus(c)} /> },
                    { key: 'serial', header: 'Serial', defaultWidth: 150, render: (c) => <span className="data-mono truncate">{c.serialNumber}</span> },
                    { key: 'notAfter', header: 'Expires', defaultWidth: 140, render: (c) => <span className="text-xs">{formatDate(c.notAfter)}</span> },
                ],
                sections: [],
                page: { path: (c) => `/certificates/${c.serialNumber}` },
            },
            listPath: (c) => { const cn = (c.subjectDN || '').match(/CN=([^,]+)/)?.[1]; return `/certificates?search=${encodeURIComponent(cn || '')}`; },
        }],
        page: { path: (c) => `/certificates/${c.serialNumber}` },
    };

    const advInput = 'w-full px-3 py-2 bg-raised border border-line-strong rounded text-sm text-ink placeholder-ink-faint focus:outline-none focus:border-accent';
    const advLabel = 'block label-caps mb-1';
    // Which "Expiring" choice the current filters amount to, if any.
    const expiringChoice = statusFilter === 'active' && !notAfterFrom
        ? (EXPIRING_DAYS.find((n) => expiringWithin(n).notAfterTo === notAfterTo) ?? '')
        : '';
    const advancedActive = !!(serialFilter || sanFilter || issuerFilter || caIdFilter || keyAlgorithmFilter || notAfterFrom || notAfterTo || issuedFrom || issuedTo);
    const clearAdvanced = () => {
        setSerialFilter(''); setSanFilter(''); setIssuerFilter('');
        setQ({ serial: '', san: '', issuer: '', caId: scopeLocked && scopeCaId ? scopeCaId : '', keyAlgorithm: '', notAfterFrom: '', notAfterTo: '', issuedFrom: '', issuedTo: '' });
    };

    return (
        <div className="space-y-4 sm:space-y-6">
            {/* Search and filters */}
            <FilterBar>
                <FilterField label="Search" grow>
                    <input type="text" placeholder="Subject, serial, SAN or issuer" value={search} onChange={(e) => setSearch(e.target.value)} className={filterControlClass} />
                </FilterField>
                <FilterField label="Status">
                    <select value={statusFilter} onChange={(e) => setQ({ status: e.target.value })} className={filterControlClass}>
                        <option value="all">Any</option>
                        <option value="active">Active</option>
                        <option value="revoked">Revoked</option>
                        <option value="expired">Expired</option>
                    </select>
                </FilterField>
                <FilterField label="Expiring">
                    <select value={expiringChoice} onChange={(e) => setQ(e.target.value ? expiringWithin(Number(e.target.value)) : { notAfterFrom: '', notAfterTo: '' })}
                        title="Active certificates that expire within the chosen number of days" className={filterControlClass}>
                        <option value="">Any time</option>
                        {EXPIRING_DAYS.map((n) => <option key={n} value={n}>Within {n} days</option>)}
                    </select>
                </FilterField>
                <FilterField label="Replacement">
                    <select value={replacedFilter} onChange={(e) => setQ({ replaced: e.target.value })}
                        title="Replaced: reissued or renewed, or a newer valid certificate from the same CA has the same subject and names" className={filterControlClass}>
                        <option value="">Any</option>
                        <option value="yes">Replaced</option>
                        <option value="no">Not replaced</option>
                    </select>
                </FilterField>
                <button onClick={() => setShowAdvanced((v) => !v)}
                    className={`px-3 py-2 text-sm rounded border transition-colors ${advancedActive ? 'bg-accent-soft text-accent-ink border-accent/40' : 'bg-raised text-ink border-line hover:bg-hover'}`}>
                    {showAdvanced ? 'Fewer filters' : 'More filters'}{advancedActive ? ' •' : ''}
                </button>
            </FilterBar>

            {/* The rest of the filters. The issuing CA is offered only while the scope does not already name one. */}
            {showAdvanced && (
                <div className="bg-raised border border-line rounded-lg p-4 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
                    <div><label className={advLabel}>Serial Number</label><input type="text" value={serialFilter} onChange={(e) => setSerialFilter(e.target.value)} placeholder="e.g. 01AB3F..." className={advInput} /></div>
                    <div><label className={advLabel}>Subject Alternative Name</label><input type="text" value={sanFilter} onChange={(e) => setSanFilter(e.target.value)} placeholder="e.g. *.example.com" className={advInput} /></div>
                    {!scopeLocked && (
                        <div>
                            <label className={advLabel}>Issuing CA</label>
                            <select value={caIdFilter} onChange={(e) => setQ({ caId: e.target.value })} className={advInput}>
                                <option value="">All CAs</option>
                                {authorities.map((ca) => <option key={ca.id} value={ca.id}>{ca.label || ca.name || ca.commonName || ca.subjectDN || ca.id}</option>)}
                            </select>
                        </div>
                    )}
                    <div>
                        <label className={advLabel}>Key Algorithm</label>
                        <select value={keyAlgorithmFilter} onChange={(e) => setQ({ keyAlgorithm: e.target.value })} className={advInput}>
                            <option value="">All Algorithms</option>
                            {KEY_ALGORITHM_FILTERS.map((a) => <option key={a} value={a}>{a}</option>)}
                        </select>
                    </div>
                    {/* A saved view can still carry an issuer name; it is shown so it can be cleared. */}
                    {issuerFilter && (
                        <div><label className={advLabel}>Issuer DN</label><input type="text" value={issuerFilter} onChange={(e) => setIssuerFilter(e.target.value)} className={advInput} /></div>
                    )}
                    <div><label className={advLabel}>Expires After</label><input type="date" value={notAfterFrom} max={notAfterTo || undefined} onChange={(e) => setQ({ notAfterFrom: e.target.value })} className={advInput} /></div>
                    <div>
                        <label className={advLabel}>Expires Before</label>
                        <input type="date" value={notAfterTo} min={notAfterFrom || undefined} onChange={(e) => setQ({ notAfterTo: e.target.value })} className={advInput} />
                        {expiresRangeInverted && <FieldHint tone="warn">"Expires After" is later than "Expires Before", so no certificate can match and the list is empty. Swap the two dates.</FieldHint>}
                    </div>
                    <div><label className={advLabel}>Issued After</label><input type="date" value={issuedFrom} max={issuedTo || undefined} onChange={(e) => setQ({ issuedFrom: e.target.value })} className={advInput} /></div>
                    <div>
                        <label className={advLabel}>Issued Before</label>
                        <input type="date" value={issuedTo} min={issuedFrom || undefined} onChange={(e) => setQ({ issuedTo: e.target.value })} className={advInput} />
                        {issuedRangeInverted && <FieldHint tone="warn">"Issued After" is later than "Issued Before", so no certificate can match and the list is empty. Swap the two dates.</FieldHint>}
                    </div>
                    {advancedActive && (
                        <div className="flex items-end">
                            <button onClick={clearAdvanced} className="px-4 py-2 text-sm text-ink-muted hover:text-ink border border-line rounded transition-colors">Clear these filters</button>
                        </div>
                    )}
                </div>
            )}

            <SavedViews tableId="certificates" current={currentView} onApply={applyView} />

            <DataTable<any>
                tableId="certificates"
                title="All Certificates"
                rows={certificates}
                loading={loading}
                error={error}
                empty="No certificates found"
                {...recordTableProps(record)}
                selectable
                bulkActions={[
                    { label: 'Revoke', variant: 'danger', onClick: () => { setRevokeReason('Unspecified'); setRevokeOpen(true); } },
                ]}
                exportFileName="certificates"
                selectedKeys={selectedKeys}
                onSelectedKeysChange={(next) => { setSelectedKeys(next); setAllMatching(false); }}
                totalCount={totalCount}
                allMatchingSelected={allMatching}
                onSelectAllMatching={() => setAllMatching(true)}
                onClearSelection={() => { setSelectedKeys(new Set()); setAllMatching(false); }}
                onExport={handleExport}
                exporting={exporting}
                sort={sort}
                onSortChange={(next) => setQ({ sort: formatSort(next) || QUERY_DEFAULTS.sort })}
                page={page}
                pageSize={pageSize}
                totalPages={totalPages}
                onPageChange={setPage}
                pageSizeOptions={PAGE_SIZES}
                onPageSizeChange={(n) => setQ({ pageSize: String(n), page: '1' })}
            />

            {/* Bulk revoke — one reason, one step-up prompt */}
            {revokeOpen && (
                <div className="fixed inset-0 z-[60] flex items-center justify-center bg-scrim" onClick={() => !revokeBusy && setRevokeOpen(false)}>
                    <div className="bg-raised border border-line rounded-lg shadow-2xl w-full max-w-md mx-4" onClick={(e) => e.stopPropagation()}>
                        <div className="px-6 py-4 border-b border-line">
                            <h3 className="text-sm font-semibold text-ink">Revoke {selectedKeys.size} certificate{selectedKeys.size === 1 ? '' : 's'}</h3>
                        </div>
                        <div className="px-6 py-4 space-y-3">
                            <p className="text-xs text-ink-muted">Every selected certificate is revoked with the same reason. CA certificates are skipped — revoke those individually. Only Certificate Hold can be lifted afterwards; every other reason is permanent.</p>
                            {allMatching && <p className="text-[11px] text-warn">Note: this revokes the {selectedKeys.size} explicitly selected on loaded pages, not every match across all pages.</p>}
                            <div className="space-y-1">
                                <label htmlFor="bulk-revoke-reason" className="block text-xs text-ink-muted">Revocation reason</label>
                                <select id="bulk-revoke-reason" value={revokeReason} onChange={(e) => setRevokeReason(e.target.value)} disabled={revokeBusy} className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-sm text-ink focus:outline-none focus:border-accent disabled:opacity-50">
                                    {REVOCATION_REASONS.map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}
                                </select>
                                <RevocationReasonHint reason={revokeReason} />
                            </div>
                        </div>
                        <div className="px-6 py-4 border-t border-line flex justify-end gap-3">
                            <button onClick={() => setRevokeOpen(false)} disabled={revokeBusy} className="px-4 py-2 text-sm bg-sunken text-ink rounded hover:bg-hover transition-colors disabled:opacity-50">Cancel</button>
                            <button onClick={runBulkRevoke} disabled={revokeBusy || selectedKeys.size === 0} className="px-4 py-2 text-sm bg-crit text-on-accent rounded hover:bg-crit-hover transition-colors disabled:opacity-50">{revokeBusy ? 'Revoking…' : `Revoke ${selectedKeys.size}`}</button>
                        </div>
                    </div>
                </div>
            )}

        </div>
    );
};

/**
 * The All Certificates page: the X.509 certificates, and on its SSH tab the SSH certificates.
 * Each tab is shown only to who can use it: the X.509 tab to who may view certificates in the
 * scope, the SSH tab to who may view them on an SSH CA.
 */
const Certificates: React.FC = () => {
    const { scope, allows } = useScope();
    const { capabilities } = useAuth();
    const { tabs, active, setActive } = useKindTabs({ x509: allows(CERT_VIEW), ssh: canUseSshTab(capabilities, 'certificates') });
    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <h1 className="text-xl font-semibold text-ink">Certificates</h1>
            <KindTabStrip tabs={tabs} active={active} onChange={setActive} />
            {active === 'X.509' && <X509Certificates />}
            {active === 'SSH' && <SshCertificatesTab scope={scope} />}
        </div>
    );
};

export default Certificates;
