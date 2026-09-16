import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiGet } from '../api/client';
import { useScope } from '../context/ScopeContext';
import { accountNavItems, navSections } from '../nav';
import { CA_MANAGE, CERT_VIEW, GROUP_MANAGE, USER_MANAGE } from '../gates';
import { PORTAL } from '../portal';
import { searchPages, type PageHit } from '../search';

/**
 * The top bar's search box: one line per page, with up to a few matching records on it.
 *
 * Pages come from the navigation tables, filtered by the same gates as the sidebar, so a page
 * the caller cannot open never appears as a result. Records are looked up once the query is two
 * characters long: certificates by serial or subject through the certificate list's search
 * parameter, CAs from the caller's capabilities, and users and groups from their list
 * endpoints, each only when the caller can open the page the result leads to. A record lands
 * on the line of the page that lists it, so "Users · sam, samantha" reads as one result;
 * Enter opens the page (with the query carried into its filter where the page has one), and
 * a record chip opens that record. Arrow keys move, Escape closes; Ctrl+K (or / when nothing
 * else has focus) focuses the box.
 */
interface RecordHit {
    key: string;
    title: string;
    subtitle?: string;
    path: string;
}

/** One result line: a page, plus records that page lists. */
interface Line {
    key: string;
    title: string;
    section: string;
    /** Where Enter goes: the page, with the query prefilled when the page can take it. */
    path: string;
    records: RecordHit[];
    /** How many records matched beyond the ones shown. */
    more: number;
}

/** The page each record kind lives on, and how that page takes a query. */
const RECORD_PAGES = {
    certificate: { path: '/certificates', name: 'All Certificates', section: 'Certificates', query: (q: string) => `/certificates?search=${encodeURIComponent(q)}` },
    ca: { path: '/authorities/manage', name: 'Authorities', section: 'CA Management', query: () => '/authorities/manage' },
    user: { path: '/users', name: 'Users', section: 'Access & Identity', query: () => '/users' },
    group: { path: '/groups', name: 'Groups', section: 'Access & Identity', query: () => '/groups' },
} as const;
type RecordKind = keyof typeof RECORD_PAGES;

const MAX_RECORDS_PER_LINE = 3;
const RECORD_FETCH = 6;

const GlobalSearch: React.FC = () => {
    const navigate = useNavigate();
    const { allows, cas, inScope } = useScope();
    const [query, setQuery] = useState('');
    const [open, setOpen] = useState(false);
    const [active, setActive] = useState(0);
    const [records, setRecords] = useState<Record<RecordKind, RecordHit[]>>({ certificate: [], ca: [], user: [], group: [] });
    const [busy, setBusy] = useState(false);
    const inputRef = useRef<HTMLInputElement>(null);
    const boxRef = useRef<HTMLDivElement>(null);

    // Pages the caller may open, as the search sees them.
    const pages = useMemo(() => {
        const items = [...navSections.flatMap(s => s.items.map(i => ({ ...i, section: s.title }))), ...accountNavItems.map(i => ({ ...i, section: 'Account' }))];
        return items.filter(i => allows(i.gate));
    }, [allows]);

    const pageHits: PageHit[] = useMemo(() => searchPages(pages, query), [pages, query]);

    // Records, debounced, only in the console and only where the caller could open the result.
    useEffect(() => {
        const q = query.trim();
        if (PORTAL !== 'admin' || q.length < 2) { setRecords({ certificate: [], ca: [], user: [], group: [] }); return; }
        let cancelled = false;
        setBusy(true);
        const t = setTimeout(async () => {
            const found: Record<RecordKind, RecordHit[]> = { certificate: [], ca: [], user: [], group: [] };
            const lq = q.toLowerCase();
            if (allows(CA_MANAGE)) {
                for (const ca of cas) {
                    if (!inScope(ca.id)) continue;
                    if (ca.label.toLowerCase().includes(lq) || ca.name.toLowerCase().includes(lq))
                        found.ca.push({ key: `ca:${ca.id}`, title: ca.label || ca.name, subtitle: ca.tenantName, path: `/authorities/manage/${ca.id}` });
                }
            }
            const jobs: Promise<void>[] = [];
            if (allows(CERT_VIEW)) {
                jobs.push(apiGet<any>(`/api/v1/admin/certificates?search=${encodeURIComponent(q)}&pageSize=${RECORD_FETCH}`).then((r) => {
                    for (const c of (r?.items ?? [])) {
                        const cn = (c.subjectDN || '').match(/CN=([^,]+)/)?.[1];
                        found.certificate.push({ key: `cert:${c.serialNumber}`, title: cn || c.subjectDN || c.serialNumber, subtitle: c.serialNumber, path: `/certificates/${c.serialNumber}` });
                    }
                    if (typeof r?.total === 'number') found.certificate.length = Math.min(found.certificate.length, RECORD_FETCH);
                }).catch(() => { /* a failed lookup just yields no record hits */ }));
            }
            if (allows(USER_MANAGE)) {
                jobs.push(apiGet<any>('/api/v1/admin/users').then((r) => {
                    const users: any[] = Array.isArray(r) ? r : (r?.items ?? []);
                    for (const u of users.filter(u => (u.username || '').toLowerCase().includes(lq) || (u.email || '').toLowerCase().includes(lq)).slice(0, RECORD_FETCH)) {
                        found.user.push({ key: `user:${u.id}`, title: u.username, subtitle: u.email, path: `/users/${u.id}` });
                    }
                }).catch(() => { }));
            }
            if (allows(GROUP_MANAGE)) {
                jobs.push(apiGet<any>('/api/v1/admin/groups').then((r) => {
                    const groups: any[] = Array.isArray(r) ? r : (r?.items ?? r?.groups ?? []);
                    for (const g of groups.filter(g => inScope(g.certificateAuthorityId || g.caId) || g.isSystemGroup).filter(g => (g.displayName || g.name || '').toLowerCase().includes(lq)).slice(0, RECORD_FETCH)) {
                        found.group.push({ key: `group:${g.id}`, title: g.displayName || g.name, subtitle: g.caLabel || (g.isSystemGroup ? 'System' : undefined), path: `/groups/${g.id}` });
                    }
                }).catch(() => { }));
            }
            await Promise.all(jobs);
            if (!cancelled) { setRecords(found); setBusy(false); }
        }, 250);
        return () => { cancelled = true; clearTimeout(t); };
    }, [query, allows, cas, inScope]);

    // Fold page hits and record hits into lines: one per page, records attached to their page.
    const lines: Line[] = useMemo(() => {
        const q = query.trim();
        const byPath = new Map<string, Line>();
        const order: string[] = [];
        const lineFor = (path: string, title: string, section: string, target: string) => {
            let line = byPath.get(path);
            if (!line) {
                line = { key: `page:${path}`, title, section, path: target, records: [], more: 0 };
                byPath.set(path, line);
                order.push(path);
            }
            return line;
        };
        for (const p of pageHits) lineFor(p.path, p.name, p.section, p.path);
        for (const kind of Object.keys(RECORD_PAGES) as RecordKind[]) {
            const hits = records[kind];
            if (hits.length === 0) continue;
            const page = RECORD_PAGES[kind];
            // Only attach to a page the caller may open; a record hit on a page they cannot see is dropped.
            if (!pages.some(p => p.path === page.path)) continue;
            const line = lineFor(page.path, page.name, page.section, page.query(q));
            // A page whose records matched should carry the query into its own filter.
            if (line.records.length === 0) line.path = page.query(q);
            line.records.push(...hits.slice(0, MAX_RECORDS_PER_LINE - line.records.length));
            line.more += Math.max(0, hits.length - MAX_RECORDS_PER_LINE);
        }
        // Lines with records first, then plain page hits in their search order.
        return order.map(p => byPath.get(p)!).sort((a, b) => (b.records.length > 0 ? 1 : 0) - (a.records.length > 0 ? 1 : 0)).slice(0, 10);
    }, [pageHits, records, pages, query]);

    useEffect(() => { setActive(0); }, [lines.length, query]);

    const go = useCallback((path: string) => {
        setOpen(false);
        setQuery('');
        navigate(path);
    }, [navigate]);

    // Keyboard: Ctrl+K anywhere, or "/" outside a field, focuses the box.
    useEffect(() => {
        const onKey = (e: KeyboardEvent) => {
            const target = e.target as HTMLElement | null;
            const typing = target && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.tagName === 'SELECT' || target.isContentEditable);
            if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); inputRef.current?.focus(); setOpen(true); }
            else if (e.key === '/' && !typing) { e.preventDefault(); inputRef.current?.focus(); setOpen(true); }
        };
        window.addEventListener('keydown', onKey);
        return () => window.removeEventListener('keydown', onKey);
    }, []);

    // Click outside closes.
    useEffect(() => {
        if (!open) return;
        const onClick = (e: MouseEvent) => { if (boxRef.current && !boxRef.current.contains(e.target as Node)) setOpen(false); };
        window.addEventListener('mousedown', onClick);
        return () => window.removeEventListener('mousedown', onClick);
    }, [open]);

    const onKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
        if (e.key === 'ArrowDown') { e.preventDefault(); setOpen(true); setActive(a => Math.min(a + 1, Math.max(lines.length - 1, 0))); }
        else if (e.key === 'ArrowUp') { e.preventDefault(); setActive(a => Math.max(a - 1, 0)); }
        else if (e.key === 'Enter') { if (lines[active]) go(lines[active].path); }
        else if (e.key === 'Escape') { setOpen(false); inputRef.current?.blur(); }
    };

    return (
        <div ref={boxRef} className="relative flex-1 min-w-0 max-w-xl">
            <label htmlFor="global-search" className="sr-only">Search pages and records</label>
            <input
                id="global-search"
                ref={inputRef}
                type="search"
                value={query}
                placeholder={PORTAL === 'admin' ? 'Search pages, certificates, CAs, users…  (Ctrl+K)' : 'Search pages…  (Ctrl+K)'}
                autoComplete="off"
                onChange={(e) => { setQuery(e.target.value); setOpen(true); }}
                onFocus={() => setOpen(true)}
                onKeyDown={onKeyDown}
                role="combobox"
                aria-expanded={open && lines.length > 0}
                aria-controls="global-search-results"
                aria-activedescendant={open && lines[active] ? `gs-${lines[active].key}` : undefined}
                className="w-full px-3 py-1.5 text-sm rounded-md bg-gray-100 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 text-gray-900 dark:text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
            />
            {open && (query.trim().length > 0) && (
                <ul
                    id="global-search-results"
                    role="listbox"
                    className="absolute left-0 right-0 mt-1 max-h-96 overflow-y-auto rounded-md border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 shadow-lg z-50 text-sm"
                >
                    {lines.length === 0 && (
                        <li className="px-3 py-2 text-gray-500 dark:text-gray-400">{busy ? 'Searching…' : 'No matches'}</li>
                    )}
                    {lines.map((line, i) => (
                        <li
                            key={line.key}
                            id={`gs-${line.key}`}
                            role="option"
                            aria-selected={i === active}
                            onMouseDown={(e) => { e.preventDefault(); go(line.path); }}
                            onMouseEnter={() => setActive(i)}
                            className={`px-3 py-2 cursor-pointer flex items-center gap-3 min-w-0 ${i === active ? 'bg-blue-50 dark:bg-blue-900/40' : ''}`}
                        >
                            <span className="flex-shrink-0 min-w-0">
                                <span className="text-gray-900 dark:text-white">{line.title}</span>
                                <span className="ml-1.5 text-[10px] uppercase tracking-wider text-gray-500 dark:text-gray-400">{line.section}</span>
                            </span>
                            {line.records.length > 0 && (
                                <span className="flex items-center gap-1 min-w-0 overflow-hidden">
                                    <span className="text-gray-400 dark:text-gray-500">·</span>
                                    {line.records.map((r) => (
                                        <button
                                            key={r.key}
                                            type="button"
                                            title={r.subtitle ? `${r.title} — ${r.subtitle}` : r.title}
                                            onMouseDown={(e) => { e.preventDefault(); e.stopPropagation(); go(r.path); }}
                                            className="px-1.5 py-0.5 text-xs rounded border border-gray-300 dark:border-gray-600 bg-gray-50 dark:bg-gray-800 text-gray-800 dark:text-gray-200 hover:border-blue-400 hover:text-blue-800 dark:hover:text-blue-300 truncate max-w-[10rem]"
                                        >
                                            {r.title}
                                        </button>
                                    ))}
                                    {line.more > 0 && <span className="text-xs text-gray-500 dark:text-gray-400 whitespace-nowrap">+{line.more} more</span>}
                                </span>
                            )}
                        </li>
                    ))}
                    {busy && lines.length > 0 && <li className="px-3 py-1 text-xs text-gray-500 dark:text-gray-400">Searching records…</li>}
                </ul>
            )}
        </div>
    );
};

export default GlobalSearch;
