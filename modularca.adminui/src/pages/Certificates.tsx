import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import { apiGet, apiPostWithMfa } from '../api/client';
import { useScope } from '../context/ScopeContext';
import { useToast } from '@shared/context/ToastContext';
import { useStepUp } from '../components/StepUpMfaContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import { DataTable, DataTableColumn } from '@shared/components/DataTable';
import { REVOCATION_REASONS } from './CertificateDetail';
import { StepUpOps } from '@shared/generated';

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

// Cross-page CSV: a fixed, complete field set (independent of which columns are visible/hidden).
const CSV_HEADERS = ['Serial', 'Subject', 'Issuer', 'Status', 'Not Before', 'Not After', 'Key Algorithm', 'Revoked', 'Revocation Reason'];
const csvCells = (c: any): (string | number)[] => [
    c.serialNumber || '', c.subjectDN || '', c.issuer || '', certStatus(c),
    c.notBefore || '', c.notAfter || '', c.keyAlgorithm || '', c.revoked ? 'Yes' : 'No', c.revocationReason || '',
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

const Certificates: React.FC = () => {
    const { showToast } = useToast();
    const { requireStepUp } = useStepUp();
    const [searchParams] = useSearchParams();
    const [search, setSearch] = useState(() => searchParams.get('search') || '');
    const [statusFilter, setStatusFilter] = useState<'all' | 'active' | 'revoked' | 'expired'>(
        () => (['active', 'revoked', 'expired'].includes(searchParams.get('status') || '') ? (searchParams.get('status') as any) : 'all'));
    const [serialFilter, setSerialFilter] = useState(() => searchParams.get('serial') || '');
    const [sanFilter, setSanFilter] = useState(() => searchParams.get('san') || '');
    const [issuerFilter, setIssuerFilter] = useState(() => searchParams.get('issuer') || '');
    // The console's CA scope supplies the issuing-CA filter; under a single-CA scope the
    // filter is fixed to that CA and the select below is locked to say so.
    const { scope, caId: scopeCaId } = useScope();
    const scopeLocked = scope.kind === 'ca';
    const [caIdFilter, setCaIdFilter] = useState(() => searchParams.get('caId') || scopeCaId || '');
    useEffect(() => {
        // Follow the scope both ways: a CA scope pins the filter, widening it back to all CAs
        // clears the pin (an explicit ?caId= in the URL still wins on first load).
        setCaIdFilter(scopeLocked && scopeCaId ? scopeCaId : '');
        setPage(1);
    }, [scopeLocked, scopeCaId]);
    const [keyAlgorithmFilter, setKeyAlgorithmFilter] = useState(() => searchParams.get('keyAlgorithm') || '');
    const [notAfterFrom, setNotAfterFrom] = useState(() => searchParams.get('notAfterFrom') || '');
    const [notAfterTo, setNotAfterTo] = useState(() => searchParams.get('notAfterTo') || '');
    const [issuedFrom, setIssuedFrom] = useState(() => searchParams.get('issuedFrom') || '');
    const [issuedTo, setIssuedTo] = useState(() => searchParams.get('issuedTo') || '');
    const [authorities, setAuthorities] = useState<any[]>([]);
    const [showAdvanced, setShowAdvanced] = useState(() =>
        ['serial', 'san', 'issuer', 'caId', 'keyAlgorithm', 'notAfterFrom', 'notAfterTo', 'issuedFrom', 'issuedTo'].some((k) => searchParams.get(k)));
    const [page, setPage] = useState(1);
    const [totalPages, setTotalPages] = useState(1);
    const [totalCount, setTotalCount] = useState(0);
    const [certificates, setCertificates] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const pageSize = 20;

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

    // Debounce the free-typing filters.
    const [dSearch, setDSearch] = useState(search);
    const [dSerial, setDSerial] = useState(serialFilter);
    const [dSan, setDSan] = useState(sanFilter);
    const [dIssuer, setDIssuer] = useState(issuerFilter);
    useEffect(() => {
        const t = setTimeout(() => { setDSearch(search); setDSerial(serialFilter); setDSan(sanFilter); setDIssuer(issuerFilter); setPage(1); }, 1500);
        return () => clearTimeout(t);
    }, [search, serialFilter, sanFilter, issuerFilter]);

    // Build the query params for the active filter (page/size supplied by the caller).
    const buildParams = useCallback((pageNum: number, size: number) => {
        const params = new URLSearchParams({ page: String(pageNum), pageSize: String(size) });
        if (dSearch) params.set('search', dSearch);
        if (statusFilter !== 'all') params.set('status', statusFilter);
        if (dSerial) params.set('serial', dSerial);
        if (dSan) params.set('san', dSan);
        if (dIssuer) params.set('issuer', dIssuer);
        if (caIdFilter) params.set('caId', caIdFilter);
        if (keyAlgorithmFilter) params.set('keyAlgorithm', keyAlgorithmFilter);
        if (notAfterFrom) params.set('notAfterFrom', notAfterFrom);
        if (notAfterTo) params.set('notAfterTo', notAfterTo);
        if (issuedFrom) params.set('issuedFrom', issuedFrom);
        if (issuedTo) params.set('issuedTo', issuedTo);
        return params;
    }, [dSearch, statusFilter, dSerial, dSan, dIssuer, caIdFilter, keyAlgorithmFilter, notAfterFrom, notAfterTo, issuedFrom, issuedTo]);

    // Reset selection whenever the matching set changes (filter change, not page change).
    useEffect(() => {
        setSelectedKeys(new Set());
        setAllMatching(false);
        rowCache.current = new Map();
    }, [dSearch, statusFilter, dSerial, dSan, dIssuer, caIdFilter, keyAlgorithmFilter, notAfterFrom, notAfterTo, issuedFrom, issuedTo]);

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError(null);
        apiGet<any>(`/api/v1/admin/certificates?${buildParams(page, pageSize)}`)
            .then((data) => {
                if (cancelled) return;
                const items = Array.isArray(data) ? data : (data.items || []);
                const count = data.totalCount ?? items.length;
                setTotalCount(count);
                setTotalPages(data.totalPages || Math.ceil(count / pageSize) || 1);
                for (const c of items) rowCache.current.set(certKey(c), c);
                setCertificates(items);
                setLoading(false);
            })
            .catch((err) => { if (!cancelled) { setError(err.message || 'Failed to load certificates'); setLoading(false); } });
        return () => { cancelled = true; };
    }, [page, buildParams, reloadKey]);

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

    const handleExport = async () => {
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
            const count = first.totalCount ?? items.length;
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

    const columns: DataTableColumn<any>[] = [
        { key: 'status', header: 'Status', defaultWidth: 100, truncate: false, exportValue: (c) => certStatus(c), render: (c) => <StatusBadge status={certStatus(c)} /> },
        { key: 'serial', header: 'Serial', defaultWidth: 180, exportValue: (c) => c.serialNumber, render: (c) => <span className="font-mono text-xs text-gray-600 dark:text-gray-400 truncate">{c.serialNumber}</span> },
        { key: 'subject', header: 'Subject', defaultWidth: 280, minWidth: 160, exportValue: (c) => c.subjectDN, render: (c) => <span className="text-sm text-gray-900 dark:text-white truncate">{c.subjectDN}</span> },
        { key: 'keyAlg', header: 'Key Alg', defaultWidth: 110, exportValue: (c) => c.keyAlgorithm || '', render: (c) => <span className="text-xs text-gray-600 dark:text-gray-400">{c.keyAlgorithm || '-'}</span> },
        { key: 'expires', header: 'Expires', defaultWidth: 160, minWidth: 120, exportValue: (c) => formatDate(c.notAfter), render: (c) => <span className="text-xs text-gray-600 dark:text-gray-400">{formatDate(c.notAfter)}</span> },
    ];

    const drawer = (c: any) => {
        const sans = parseSans(c.subjectAlternativeNames);
        return (
            <div className="text-sm">
                <DetailField label="Status" value={certStatus(c)} />
                <DetailField label="Serial" value={c.serialNumber} mono />
                <DetailField label="Subject" value={c.subjectDN} />
                <DetailField label="Issuer" value={c.issuer} />
                <DetailField label="Not Before" value={formatDate(c.notBefore)} />
                <DetailField label="Not After" value={formatDate(c.notAfter)} />
                <DetailField label="Key Algorithm" value={c.keyAlgorithm} />
                {sans && sans.length > 0 && <DetailField label="SANs" value={sans.join(', ')} />}
                <p className="text-[11px] text-gray-500 pt-3">Open the full page for extensions, downloads, revoke or reissue.</p>
            </div>
        );
    };

    const advInput = 'w-full px-3 py-2 bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:border-blue-500';
    const advLabel = 'block text-xs font-semibold text-gray-600 dark:text-gray-400 mb-1';
    const advancedActive = !!(serialFilter || sanFilter || issuerFilter || caIdFilter || keyAlgorithmFilter || notAfterFrom || notAfterTo || issuedFrom || issuedTo);
    const clearAdvanced = () => {
        setSerialFilter(''); setSanFilter(''); setIssuerFilter(''); setCaIdFilter('');
        setKeyAlgorithmFilter(''); setNotAfterFrom(''); setNotAfterTo(''); setIssuedFrom(''); setIssuedTo('');
        setDSerial(''); setDSan(''); setDIssuer(''); setPage(1);
    };

    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Certificates</h1>

            {/* Search and Filter Bar */}
            <div className="flex flex-wrap gap-4 items-center">
                <input type="text" placeholder="Search subject, serial, SAN, or issuer..." value={search} onChange={(e) => setSearch(e.target.value)}
                    className="flex-1 min-w-[250px] px-3 py-2 bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:border-blue-500" />
                <select value={statusFilter} onChange={(e) => { setStatusFilter(e.target.value as any); setPage(1); }}
                    className="px-3 py-2 bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500">
                    <option value="all">All Statuses</option>
                    <option value="active">Active</option>
                    <option value="revoked">Revoked</option>
                    <option value="expired">Expired</option>
                </select>
                <button onClick={() => setShowAdvanced((v) => !v)}
                    className={`px-3 py-2 text-sm rounded border transition-colors ${advancedActive ? 'bg-blue-50 dark:bg-blue-900/50 text-blue-800 dark:text-blue-300 border-blue-300 dark:border-blue-700' : 'bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 border-gray-300 dark:border-gray-700 hover:bg-gray-200 dark:hover:bg-gray-700'}`}>
                    {showAdvanced ? 'Hide advanced' : 'Advanced filters'}{advancedActive ? ' •' : ''}
                </button>
            </div>

            {/* Advanced filters (collapsible) */}
            {showAdvanced && (
                <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-4 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    <div><label className={advLabel}>Serial Number</label><input type="text" value={serialFilter} onChange={(e) => setSerialFilter(e.target.value)} placeholder="e.g. 01AB3F..." className={advInput} /></div>
                    <div><label className={advLabel}>Subject Alternative Name</label><input type="text" value={sanFilter} onChange={(e) => setSanFilter(e.target.value)} placeholder="e.g. *.example.com" className={advInput} /></div>
                    <div>
                        <label className={advLabel}>Issuing CA</label>
                        <select value={caIdFilter} onChange={(e) => { setCaIdFilter(e.target.value); setPage(1); }} className={advInput} disabled={scopeLocked} title={scopeLocked ? 'Set by the scope in the sidebar' : undefined}>
                            <option value="">All CAs</option>
                            {authorities.map((ca) => <option key={ca.id} value={ca.id}>{ca.label || ca.name || ca.commonName || ca.subjectDN || ca.id}</option>)}
                        </select>
                    </div>
                    <div><label className={advLabel}>Issuer DN</label><input type="text" value={issuerFilter} onChange={(e) => setIssuerFilter(e.target.value)} placeholder="e.g. CN=My CA" className={advInput} /></div>
                    <div>
                        <label className={advLabel}>Key Algorithm</label>
                        <select value={keyAlgorithmFilter} onChange={(e) => { setKeyAlgorithmFilter(e.target.value); setPage(1); }} className={advInput}>
                            <option value="">All Algorithms</option>
                            <option value="RSA">RSA</option>
                            <option value="ECDSA">ECDSA</option>
                            <option value="Ed25519">Ed25519</option>
                            <option value="Ed448">Ed448</option>
                            <option value="DSA">DSA</option>
                        </select>
                    </div>
                    <div className="hidden lg:block" />
                    <div><label className={advLabel}>Expires After</label><input type="date" value={notAfterFrom} onChange={(e) => { setNotAfterFrom(e.target.value); setPage(1); }} className={advInput} /></div>
                    <div><label className={advLabel}>Expires Before</label><input type="date" value={notAfterTo} onChange={(e) => { setNotAfterTo(e.target.value); setPage(1); }} className={advInput} /></div>
                    <div className="hidden lg:block" />
                    <div><label className={advLabel}>Issued After</label><input type="date" value={issuedFrom} onChange={(e) => { setIssuedFrom(e.target.value); setPage(1); }} className={advInput} /></div>
                    <div><label className={advLabel}>Issued Before</label><input type="date" value={issuedTo} onChange={(e) => { setIssuedTo(e.target.value); setPage(1); }} className={advInput} /></div>
                    <div className="flex items-end">
                        {advancedActive && <button onClick={clearAdvanced} className="px-4 py-2 text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white border border-gray-300 dark:border-gray-700 rounded transition-colors">Clear advanced</button>}
                    </div>
                </div>
            )}

            <DataTable<any>
                tableId="certificates"
                title="All Certificates"
                rows={certificates}
                rowKey={certKey}
                loading={loading}
                error={error}
                empty="No certificates found"
                columns={columns}
                selectable
                bulkActions={[
                    { label: 'Revoke', variant: 'danger', onClick: () => { setRevokeReason('Unspecified'); setRevokeOpen(true); } },
                ]}
                exportFileName="certificates"
                renderDrawer={drawer}
                drawerTitle={(c) => (c.subjectDN || '').match(/CN=([^,]+)/)?.[1] || c.serialNumber}
                detailPath={(c) => `/certificates/${c.serialNumber}`}
                selectedKeys={selectedKeys}
                onSelectedKeysChange={(next) => { setSelectedKeys(next); setAllMatching(false); }}
                totalCount={totalCount}
                allMatchingSelected={allMatching}
                onSelectAllMatching={() => setAllMatching(true)}
                onClearSelection={() => { setSelectedKeys(new Set()); setAllMatching(false); }}
                onExport={handleExport}
                exporting={exporting}
            />

            {/* Bulk revoke — one reason, one step-up prompt */}
            {revokeOpen && (
                <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/20 dark:bg-black/50" onClick={() => !revokeBusy && setRevokeOpen(false)}>
                    <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg shadow-2xl w-full max-w-md mx-4" onClick={(e) => e.stopPropagation()}>
                        <div className="px-6 py-4 border-b border-gray-300 dark:border-gray-700">
                            <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Revoke {selectedKeys.size} certificate{selectedKeys.size === 1 ? '' : 's'}</h3>
                        </div>
                        <div className="px-6 py-4 space-y-3">
                            <p className="text-xs text-gray-600 dark:text-gray-400">Every selected certificate is revoked with the same reason. CA certificates are skipped — revoke those individually. This cannot be undone.</p>
                            {allMatching && <p className="text-[11px] text-amber-700 dark:text-amber-400">Note: this revokes the {selectedKeys.size} explicitly selected on loaded pages, not every match across all pages.</p>}
                            <div className="space-y-1">
                                <label htmlFor="bulk-revoke-reason" className="block text-xs text-gray-600 dark:text-gray-400">Revocation reason</label>
                                <select id="bulk-revoke-reason" value={revokeReason} onChange={(e) => setRevokeReason(e.target.value)} disabled={revokeBusy} className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-400 dark:border-gray-600 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500 disabled:opacity-50">
                                    {REVOCATION_REASONS.map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}
                                </select>
                            </div>
                        </div>
                        <div className="px-6 py-4 border-t border-gray-300 dark:border-gray-700 flex justify-end gap-3">
                            <button onClick={() => setRevokeOpen(false)} disabled={revokeBusy} className="px-4 py-2 text-sm bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors disabled:opacity-50">Cancel</button>
                            <button onClick={runBulkRevoke} disabled={revokeBusy || selectedKeys.size === 0} className="px-4 py-2 text-sm bg-red-600 text-white rounded hover:bg-red-700 transition-colors disabled:opacity-50">{revokeBusy ? 'Revoking…' : `Revoke ${selectedKeys.size}`}</button>
                        </div>
                    </div>
                </div>
            )}

            {/* Pagination */}
            {totalPages > 1 && (
                <div className="flex items-center justify-center gap-4">
                    <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page <= 1}
                        className="px-3 py-1 text-sm bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-700 disabled:opacity-40 disabled:cursor-not-allowed">Previous</button>
                    <span className="text-sm text-gray-600 dark:text-gray-400">Page {page} of {totalPages}</span>
                    <button onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page >= totalPages}
                        className="px-3 py-1 text-sm bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-700 disabled:opacity-40 disabled:cursor-not-allowed">Next</button>
                </div>
            )}
        </div>
    );
};

export default Certificates;
