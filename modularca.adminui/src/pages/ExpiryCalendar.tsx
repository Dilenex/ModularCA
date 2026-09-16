import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiGet } from '../api/client';
import { useScope } from '../context/ScopeContext';

// ── types ──────────────────────────────────────────────────────────────────
interface Bucket {
    period: string;
    year: number;
    month: number;
    day: number;
    active: number;
    expiringSoon: number;
    expired: number;
    revoked: number;
    total: number;
}
interface HistogramResponse {
    granularity: string;
    buckets: Bucket[];
    totals: { active: number; expiringSoon: number; expired: number; revoked: number; total: number };
}
type Counts = Pick<Bucket, 'active' | 'expiringSoon' | 'expired' | 'revoked' | 'total'>;

// ── date helpers ───────────────────────────────────────────────────────────
const startOfMonth = (d: Date) => new Date(d.getFullYear(), d.getMonth(), 1);
const addMonths = (d: Date, n: number) => new Date(d.getFullYear(), d.getMonth() + n, 1);
const parsePeriod = (p: string) => { const [y, m] = p.split('-'); return new Date(parseInt(y), parseInt(m) - 1, 1); };
const isoDate = (d: Date) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
const emptyCounts = (): Counts => ({ active: 0, expiringSoon: 0, expired: 0, revoked: 0, total: 0 });
const addCounts = (a: Counts, b: Counts): Counts => ({
    active: a.active + b.active,
    expiringSoon: a.expiringSoon + b.expiringSoon,
    expired: a.expired + b.expired,
    revoked: a.revoked + b.revoked,
    total: a.total + b.total,
});

// ── options ────────────────────────────────────────────────────────────────
const RANGE_OPTIONS = [
    { label: '12 months', value: 12 },
    { label: '24 months', value: 24 },
    { label: '5 years', value: 60 },
    { label: 'All', value: 0 },
];
type BucketMode = 'month' | 'quarter' | 'year';
const BUCKET_OPTIONS: { label: string; value: BucketMode }[] = [
    { label: 'Month', value: 'month' },
    { label: 'Quarter', value: 'quarter' },
    { label: 'Year', value: 'year' },
];

// status colours (shared by histogram segments, calendar cells, legend)
const SEG = {
    expiringSoon: 'bg-amber-500',
    active: 'bg-green-500',
    expired: 'bg-gray-400 dark:bg-gray-500',
    revoked: 'bg-rose-600',
};

// pick the cell colour for a day by most-relevant status present
function cellColor(c: Counts): string {
    if (c.expiringSoon > 0) return SEG.expiringSoon;
    if (c.active > 0) return SEG.active;
    if (c.expired > 0) return SEG.expired;
    if (c.revoked > 0) return SEG.revoked;
    return '';
}

interface DisplayUnit {
    key: string;
    label: string;
    sublabel?: string;
    months: Date[];          // months this unit spans
    counts: Counts;
    isCurrent: boolean;      // contains the current month
}

const ExpiryCalendar: React.FC = () => {
    const navigate = useNavigate();
    const [resp, setResp] = useState<HistogramResponse | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [authorities, setAuthorities] = useState<any[]>([]);
    // The sidebar scope pins the CA filter; the select below is locked while it does.
    const { caId: scopeCaId } = useScope();
    const scopeLocked = !!scopeCaId;
    const [caId, setCaId] = useState(scopeCaId ?? '');
    useEffect(() => { setCaId(scopeCaId ?? ''); }, [scopeCaId]);
    const [rangeMonths, setRangeMonths] = useState(12);
    const [bucket, setBucket] = useState<BucketMode>('month');
    const [windowOverride, setWindowOverride] = useState<{ start: Date; end: Date } | null>(null);

    // tier-2 drill-down
    const [selectedMonth, setSelectedMonth] = useState<{ year: number; month: number } | null>(null);
    const [dayBuckets, setDayBuckets] = useState<Bucket[] | null>(null);
    const [dayLoading, setDayLoading] = useState(false);

    // CA list for the filter dropdown
    useEffect(() => {
        apiGet<any>('/api/v1/admin/authorities')
            .then((data) => {
                const cas = Array.isArray(data) ? data : (data.items || data.authorities || []);
                const flat: any[] = [];
                const flatten = (list: any[]) => { for (const ca of list) { flat.push(ca); if (ca.children) flatten(ca.children); } };
                flatten(cas);
                setAuthorities(flat);
            })
            .catch(() => { /* non-fatal: filter just stays empty */ });
    }, []);

    // monthly histogram (re-fetch only when the CA filter changes)
    useEffect(() => {
        setLoading(true);
        const params = new URLSearchParams();
        if (caId) params.set('caId', caId);
        const qs = params.toString();
        apiGet<HistogramResponse>(`/api/v1/admin/certificates/expiry-histogram${qs ? `?${qs}` : ''}`)
            .then((data) => { setResp(data); setError(null); })
            .catch((err) => setError(err.message))
            .finally(() => setLoading(false));
    }, [caId]);

    // day-level drill-down for the selected month
    useEffect(() => {
        if (!selectedMonth) { setDayBuckets(null); return; }
        setDayLoading(true);
        const from = new Date(selectedMonth.year, selectedMonth.month - 1, 1);
        const to = new Date(selectedMonth.year, selectedMonth.month, 1); // first of next month
        const params = new URLSearchParams();
        params.set('granularity', 'day');
        params.set('from', isoDate(from));
        params.set('to', isoDate(to));
        if (caId) params.set('caId', caId);
        apiGet<HistogramResponse>(`/api/v1/admin/certificates/expiry-histogram?${params.toString()}`)
            .then((data) => setDayBuckets(data.buckets))
            .catch(() => setDayBuckets([]))
            .finally(() => setDayLoading(false));
    }, [selectedMonth, caId]);

    const bucketMap = useMemo(() => {
        const m = new Map<string, Bucket>();
        resp?.buckets.forEach((b) => m.set(b.period, b));
        return m;
    }, [resp]);

    // contiguous month sequence for the active display window
    const monthSeq = useMemo(() => {
        const base = startOfMonth(new Date());
        let winStart = base;
        let winEnd = addMonths(base, rangeMonths - 1);
        if (windowOverride) {
            winStart = windowOverride.start;
            winEnd = windowOverride.end;
        } else if (rangeMonths === 0) {
            const periods = (resp?.buckets ?? []).map((b) => b.period).sort();
            if (periods.length) {
                const earliest = parsePeriod(periods[0]);
                const latest = parsePeriod(periods[periods.length - 1]);
                winStart = earliest < base ? earliest : base;
                winEnd = latest > base ? latest : base;
            } else { winEnd = base; }
        }
        const out: { date: Date; counts: Counts }[] = [];
        let cur = winStart;
        let guard = 0;
        while (cur <= winEnd && guard++ < 1200) {
            const key = `${cur.getFullYear()}-${String(cur.getMonth() + 1).padStart(2, '0')}`;
            const b = bucketMap.get(key);
            out.push({ date: cur, counts: b ?? emptyCounts() });
            cur = addMonths(cur, 1);
        }
        return out;
    }, [bucketMap, resp, rangeMonths, windowOverride]);

    // collapse months into the chosen bucket granularity
    const units = useMemo<DisplayUnit[]>(() => {
        const base = startOfMonth(new Date());
        const baseKey = `${base.getFullYear()}-${base.getMonth()}`;
        const isCur = (d: Date) => `${d.getFullYear()}-${d.getMonth()}` === baseKey;

        if (bucket === 'month') {
            return monthSeq.map(({ date, counts }) => ({
                key: isoDate(date),
                label: date.toLocaleDateString('en-US', { month: 'short' }),
                sublabel: date.getMonth() === 0 || date === monthSeq[0].date ? `'${String(date.getFullYear()).slice(2)}` : undefined,
                months: [date],
                counts,
                isCurrent: isCur(date),
            }));
        }
        const groups = new Map<string, { months: Date[]; counts: Counts }>();
        const order: string[] = [];
        for (const { date, counts } of monthSeq) {
            const gk = bucket === 'quarter'
                ? `${date.getFullYear()}-Q${Math.floor(date.getMonth() / 3) + 1}`
                : `${date.getFullYear()}`;
            if (!groups.has(gk)) { groups.set(gk, { months: [], counts: emptyCounts() }); order.push(gk); }
            const g = groups.get(gk)!;
            g.months.push(date);
            g.counts = addCounts(g.counts, counts);
        }
        return order.map((gk) => {
            const g = groups.get(gk)!;
            const first = g.months[0];
            const label = bucket === 'quarter'
                ? `Q${Math.floor(first.getMonth() / 3) + 1}`
                : `${first.getFullYear()}`;
            const sublabel = bucket === 'quarter' ? `'${String(first.getFullYear()).slice(2)}` : undefined;
            return { key: gk, label, sublabel, months: g.months, counts: g.counts, isCurrent: g.months.some(isCur) };
        });
    }, [monthSeq, bucket]);

    const maxTotal = useMemo(() => Math.max(1, ...units.map((u) => u.counts.total)), [units]);
    const windowTotals = useMemo(() => monthSeq.reduce((acc, m) => addCounts(acc, m.counts), emptyCounts()), [monthSeq]);

    // drill: year → quarter → month → day grid
    const onUnitClick = (u: DisplayUnit) => {
        if (u.counts.total === 0 && bucket === 'month') {
            // empty month: still open the grid so the user sees "nothing here"
        }
        if (bucket === 'year') {
            setBucket('quarter');
            setWindowOverride({ start: u.months[0], end: u.months[u.months.length - 1] });
        } else if (bucket === 'quarter') {
            setBucket('month');
            setWindowOverride({ start: u.months[0], end: u.months[u.months.length - 1] });
        } else {
            const d = u.months[0];
            setSelectedMonth({ year: d.getFullYear(), month: d.getMonth() + 1 });
        }
    };

    const resetView = () => { setWindowOverride(null); setBucket('month'); setSelectedMonth(null); };

    const changeBucket = (b: BucketMode) => { setBucket(b); setWindowOverride(null); };

    // deep-link a day (or the whole selected month) into the certificates list
    const drillToCerts = (from: Date, toExclusive: Date) => {
        const params = new URLSearchParams();
        params.set('notAfterFrom', isoDate(from));
        params.set('notAfterTo', isoDate(toExclusive));
        if (caId) params.set('caId', caId);
        navigate(`/certificates?${params.toString()}`);
    };

    const selControl = 'px-3 py-2 bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500';

    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <div className="flex items-start justify-between flex-wrap gap-4">
                <div>
                    <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Expiry Calendar</h1>
                    <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">Renewal load over time — find the cliffs before they hit.</p>
                </div>
                <div className="flex items-center gap-2 flex-wrap">
                    <select value={caId} onChange={(e) => setCaId(e.target.value)} className={selControl} disabled={scopeLocked} title={scopeLocked ? 'Set by the scope in the sidebar' : 'Filter by issuing CA'}>
                        <option value="">All CAs</option>
                        {authorities.map((ca) => (
                            <option key={ca.id} value={ca.id}>{ca.label || ca.name || ca.commonName || ca.subjectDN || ca.id}</option>
                        ))}
                    </select>
                    <select value={rangeMonths} onChange={(e) => { setRangeMonths(parseInt(e.target.value)); setWindowOverride(null); }} className={selControl} title="Time range">
                        {RANGE_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
                    </select>
                    <div className="inline-flex rounded border border-gray-300 dark:border-gray-700 overflow-hidden">
                        {BUCKET_OPTIONS.map((o) => (
                            <button key={o.value} onClick={() => changeBucket(o.value)}
                                className={`px-3 py-2 text-sm transition-colors ${bucket === o.value
                                    ? 'bg-blue-600 text-white'
                                    : 'bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-700'}`}>
                                {o.label}
                            </button>
                        ))}
                    </div>
                </div>
            </div>

            {/* summary tiles for the visible window */}
            {!loading && !error && (
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    {[
                        { label: 'Expiring ≤30d', value: windowTotals.expiringSoon, dot: SEG.expiringSoon, emphasis: windowTotals.expiringSoon > 0 },
                        { label: 'Active', value: windowTotals.active, dot: SEG.active },
                        { label: 'Expired', value: windowTotals.expired, dot: SEG.expired },
                        { label: 'Revoked', value: windowTotals.revoked, dot: SEG.revoked },
                    ].map((t) => (
                        <div key={t.label} className={`bg-gray-100 dark:bg-gray-800 border rounded-lg px-4 py-3 ${t.emphasis ? 'border-amber-400 dark:border-amber-500/60' : 'border-gray-300 dark:border-gray-700'}`}>
                            <div className="flex items-center gap-2 text-xs text-gray-600 dark:text-gray-400">
                                <span className={`w-2.5 h-2.5 rounded ${t.dot} inline-block`}></span>{t.label}
                            </div>
                            <div className="text-2xl font-bold text-gray-900 dark:text-white mt-1">{t.value}</div>
                        </div>
                    ))}
                </div>
            )}

            {loading && <div className="p-4 text-sm text-gray-600 dark:text-gray-400 text-center">Loading expiry data…</div>}
            {error && <div className="p-4 text-sm text-red-800 dark:text-red-400 text-center">{error}</div>}

            {/* Tier 1 — timeline histogram */}
            {!loading && !error && (
                <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-4">
                    <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
                        <h2 className="text-sm font-semibold text-gray-900 dark:text-white">
                            Expirations by {bucket}
                            <span className="ml-2 text-xs font-normal text-gray-500 dark:text-gray-400">
                                {bucket === 'month' ? 'click a bar to open its calendar' : `click a bar to drill into ${bucket === 'year' ? 'quarters' : 'months'}`}
                            </span>
                        </h2>
                        {windowOverride && (
                            <button onClick={resetView} className="text-xs px-2 py-1 rounded bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-200 hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors">
                                ← Back to full range
                            </button>
                        )}
                    </div>

                    {units.length === 0 || windowTotals.total === 0 ? (
                        <div className="py-10 text-center text-sm text-gray-500 dark:text-gray-400">No certificates expire in this window.</div>
                    ) : (
                        <div className="overflow-x-auto">
                            <div className="flex items-end gap-1 h-52 min-w-full" style={{ minWidth: units.length * 18 }}>
                                {units.map((u) => {
                                    const c = u.counts;
                                    const barPct = (c.total / maxTotal) * 100;
                                    const seg = (n: number) => (c.total > 0 ? (n / c.total) * 100 : 0);
                                    const tip = `${u.label}${u.sublabel ? ' ' + u.sublabel : ''}\nExpiring ≤30d: ${c.expiringSoon}\nActive: ${c.active}\nExpired: ${c.expired}\nRevoked: ${c.revoked}\nTotal: ${c.total}`;
                                    return (
                                        <button key={u.key} onClick={() => onUnitClick(u)} title={tip}
                                            className="group flex-1 min-w-[14px] h-full flex flex-col justify-end items-stretch cursor-pointer">
                                            <div className="relative w-full flex flex-col justify-end" style={{ height: '100%' }}>
                                                {c.total > 0 && (
                                                    <span className="text-[10px] text-center text-gray-500 dark:text-gray-400 mb-0.5 opacity-0 group-hover:opacity-100 transition-opacity">{c.total}</span>
                                                )}
                                                <div className={`w-full flex flex-col rounded-t overflow-hidden ring-blue-400 group-hover:ring-2 ${u.isCurrent ? 'ring-2 ring-blue-500' : ''}`}
                                                    style={{ height: `${barPct}%`, minHeight: c.total > 0 ? 3 : 0 }}>
                                                    {c.expiringSoon > 0 && <div className={SEG.expiringSoon} style={{ height: `${seg(c.expiringSoon)}%`, minHeight: 2 }} />}
                                                    {c.active > 0 && <div className={SEG.active} style={{ height: `${seg(c.active)}%`, minHeight: 2 }} />}
                                                    {c.expired > 0 && <div className={SEG.expired} style={{ height: `${seg(c.expired)}%`, minHeight: 2 }} />}
                                                    {c.revoked > 0 && <div className={SEG.revoked} style={{ height: `${seg(c.revoked)}%`, minHeight: 2 }} />}
                                                </div>
                                            </div>
                                            <div className={`text-[10px] text-center mt-1 leading-tight truncate ${u.isCurrent ? 'text-blue-600 dark:text-blue-400 font-semibold' : 'text-gray-500 dark:text-gray-400'}`}>
                                                {u.label}{u.sublabel && <span className="block">{u.sublabel}</span>}
                                            </div>
                                        </button>
                                    );
                                })}
                            </div>
                        </div>
                    )}

                    {/* legend */}
                    <div className="flex items-center gap-4 text-xs text-gray-600 dark:text-gray-400 mt-4 flex-wrap">
                        <span className="flex items-center gap-1"><span className={`w-3 h-3 rounded ${SEG.expiringSoon} inline-block`} /> Expiring ≤30d</span>
                        <span className="flex items-center gap-1"><span className={`w-3 h-3 rounded ${SEG.active} inline-block`} /> Active</span>
                        <span className="flex items-center gap-1"><span className={`w-3 h-3 rounded ${SEG.expired} inline-block`} /> Expired</span>
                        <span className="flex items-center gap-1"><span className={`w-3 h-3 rounded ${SEG.revoked} inline-block`} /> Revoked</span>
                        <span className="flex items-center gap-1 ml-auto"><span className="w-3 h-3 rounded ring-2 ring-blue-500 inline-block" /> Current period</span>
                    </div>
                </div>
            )}

            {/* Tier 2 — month grid drill-down */}
            {selectedMonth && (
                <MonthGrid
                    year={selectedMonth.year}
                    month={selectedMonth.month}
                    buckets={dayBuckets}
                    loading={dayLoading}
                    onClose={() => setSelectedMonth(null)}
                    onDay={(d) => drillToCerts(d, new Date(d.getFullYear(), d.getMonth(), d.getDate() + 1))}
                    onViewMonth={() => drillToCerts(
                        new Date(selectedMonth.year, selectedMonth.month - 1, 1),
                        new Date(selectedMonth.year, selectedMonth.month, 1),
                    )}
                />
            )}
        </div>
    );
};

// ── month-grid (tier 2) ─────────────────────────────────────────────────────
const WEEKDAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

interface MonthGridProps {
    year: number;
    month: number; // 1-based
    buckets: Bucket[] | null;
    loading: boolean;
    onClose: () => void;
    onDay: (d: Date) => void;
    onViewMonth: () => void;
}

const MonthGrid: React.FC<MonthGridProps> = ({ year, month, buckets, loading, onClose, onDay, onViewMonth }) => {
    const dayMap = useMemo(() => {
        const m = new Map<number, Counts>();
        (buckets ?? []).forEach((b) => m.set(b.day, b));
        return m;
    }, [buckets]);

    const firstDow = new Date(year, month - 1, 1).getDay();
    const daysInMonth = new Date(year, month, 0).getDate();
    const today = new Date();
    const isToday = (d: number) => today.getFullYear() === year && today.getMonth() + 1 === month && today.getDate() === d;

    const cells: (number | null)[] = [];
    for (let i = 0; i < firstDow; i++) cells.push(null);
    for (let d = 1; d <= daysInMonth; d++) cells.push(d);

    const monthLabel = new Date(year, month - 1, 1).toLocaleDateString('en-US', { year: 'numeric', month: 'long' });
    const monthTotal = (buckets ?? []).reduce((s, b) => s + b.total, 0);

    return (
        <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-4">
            <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
                <h2 className="text-sm font-semibold text-gray-900 dark:text-white">
                    {monthLabel}
                    <span className="ml-2 text-xs font-normal text-gray-500 dark:text-gray-400">{monthTotal} certificate{monthTotal !== 1 ? 's' : ''} expiring</span>
                </h2>
                <div className="flex items-center gap-2">
                    <button onClick={onViewMonth} className="text-xs px-2 py-1 rounded bg-blue-600 text-white hover:bg-blue-700 transition-colors">View all in Certificates</button>
                    <button onClick={onClose} className="text-xs px-2 py-1 rounded bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-200 hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors">Close</button>
                </div>
            </div>

            {loading ? (
                <div className="py-10 text-center text-sm text-gray-500 dark:text-gray-400">Loading days…</div>
            ) : (
                <>
                    <div className="grid grid-cols-7 gap-1 mb-1">
                        {WEEKDAYS.map((w) => <div key={w} className="text-[11px] text-center text-gray-500 dark:text-gray-400 font-medium py-1">{w}</div>)}
                    </div>
                    <div className="grid grid-cols-7 gap-1">
                        {cells.map((d, i) => {
                            if (d === null) return <div key={`b${i}`} />;
                            const c = dayMap.get(d);
                            const has = !!c && c.total > 0;
                            const color = c ? cellColor(c) : '';
                            const tip = c ? `${monthLabel.split(' ')[0]} ${d}\nExpiring ≤30d: ${c.expiringSoon}\nActive: ${c.active}\nExpired: ${c.expired}\nRevoked: ${c.revoked}` : undefined;
                            return (
                                <button key={d} disabled={!has} title={tip}
                                    onClick={() => has && onDay(new Date(year, month - 1, d))}
                                    className={`relative aspect-square rounded border flex flex-col items-center justify-center p-1 transition-colors
                                        ${isToday(d) ? 'border-blue-500 ring-1 ring-blue-500' : 'border-gray-300 dark:border-gray-700'}
                                        ${has ? 'cursor-pointer hover:bg-gray-200 dark:hover:bg-gray-700' : 'opacity-60 cursor-default'}`}>
                                    <span className="text-[11px] text-gray-600 dark:text-gray-400 absolute top-1 left-1.5">{d}</span>
                                    {has && (
                                        <span className={`mt-2 min-w-[1.4rem] px-1.5 py-0.5 rounded text-[11px] font-semibold text-white text-center ${color}`}>{c!.total}</span>
                                    )}
                                </button>
                            );
                        })}
                    </div>
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-3">Click a day to see those certificates in the inventory.</p>
                </>
            )}
        </div>
    );
};

export default ExpiryCalendar;
