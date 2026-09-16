import React, { useState, useEffect } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { Chevron } from '@shared/components/Chevron';
import { apiGet, apiPost, apiPut, apiDelete, apiPostWithMfa, getToken } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import { APP_VERSION } from '../version';
import { StepUpOps } from '@shared/generated';

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function daysUntil(d: string): number {
    return Math.ceil((new Date(d).getTime() - Date.now()) / (1000 * 60 * 60 * 24));
}

function formatUptime(ms: number): string {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    if (days > 0) return `${days}d ${hours % 24}h ${minutes % 60}m`;
    if (hours > 0) return `${hours}h ${minutes % 60}m`;
    return `${minutes}m ${seconds % 60}s`;
}

/* ─── Health Check Status Indicator ─── */
const HealthDot: React.FC<{ status: string }> = ({ status }) => {
    const color = status === 'healthy' ? 'bg-green-500' : status === 'degraded' ? 'bg-yellow-500' : 'bg-red-500';
    return <span className={`inline-block w-2.5 h-2.5 rounded-full ${color}`} />;
};

const healthBadgeStatus = (status: string): 'active' | 'expired' | 'revoked' => {
    if (status === 'healthy') return 'active';
    if (status === 'degraded') return 'expired';
    return 'revoked';
};

// /health/ready is the full, authorized readiness payload — the bare /health is a
// minimal anonymous shim with no checks. It needs the bearer token and returns 503
// when degraded/unhealthy, so we read the JSON body regardless of status code (a
// degraded node still has a payload worth showing).
async function fetchHealthReady(): Promise<any> {
    const token = getToken();
    const res = await fetch('/health/ready', {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    return res.json();
}

/* ─── Enhanced Health Check Card ─── */
const HealthCheckCard: React.FC = () => {
    const [health, setHealth] = useState<any>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [lastRefresh, setLastRefresh] = useState<Date>(new Date());

    const fetchHealth = () => {
        setLoading(true);
        fetchHealthReady()
            .then((data) => {
                setHealth(data);
                setError(null);
                setLastRefresh(new Date());
            })
            .catch((err) => setError(errorNotice(err, 'The request failed.')))
            .finally(() => setLoading(false));
    };

    useEffect(() => {
        fetchHealth();
        const interval = setInterval(fetchHealth, 30000);
        return () => clearInterval(interval);
    }, []);

    const renderCheckRow = (label: string, check: any) => {
        if (!check) return null;
        const status = check.status || 'unknown';
        return (
            <div className="flex items-center gap-3 py-2 border-b border-gray-300 dark:border-gray-700 last:border-b-0">
                <HealthDot status={status} />
                <span className="text-sm text-gray-900 dark:text-white min-w-[140px]">{label}</span>
                <StatusBadge status={healthBadgeStatus(status)} label={status} />
                {check.responseTimeMs !== undefined && (
                    <span className="text-xs text-gray-600 ml-auto">{check.responseTimeMs}ms</span>
                )}
                {check.daysRemaining !== undefined && (
                    <span className={`text-xs ml-auto ${check.daysRemaining <= 30 ? 'text-yellow-800 dark:text-yellow-400' : 'text-gray-600'}`}>
                        {check.daysRemaining}d remaining
                    </span>
                )}
                {check.freeSpaceGb !== undefined && (
                    <span className="text-xs text-gray-600 ml-auto">{check.freeSpaceGb} GB free</span>
                )}
                {check.error && (
                    <span className="text-xs text-red-800 dark:text-red-400 ml-auto truncate max-w-[200px]" title={check.error}>{check.error}</span>
                )}
                {check.warning && (
                    <span className="text-xs text-yellow-800 dark:text-yellow-400 ml-auto truncate max-w-[200px]" title={check.warning}>{check.warning}</span>
                )}
            </div>
        );
    };

    return (
        <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-4">
            <div className="flex items-center justify-between mb-3">
                <h2 className="text-sm font-semibold text-gray-900 dark:text-white">Health Checks</h2>
                <div className="flex items-center gap-3">
                    <span className="text-xs text-gray-600">Auto-refresh 30s</span>
                    <button onClick={fetchHealth} className="text-xs text-blue-800 dark:text-blue-400 hover:text-blue-300 transition-colors">Refresh</button>
                </div>
            </div>

            {loading && !health && <div className="text-sm text-gray-600 dark:text-gray-400">Checking...</div>}
            {error && !health && <InlineNotice notice={error} />}

            {health && (
                <div className="space-y-1">
                    <div className="flex items-center gap-2 mb-3">
                        <HealthDot status={health.status} />
                        <span className="text-lg font-bold text-gray-900 dark:text-white capitalize">{health.status}</span>
                        {health.totalDurationMs !== undefined && (
                            <span className="text-xs text-gray-600 ml-2">({Math.round(health.totalDurationMs)}ms)</span>
                        )}
                    </div>

                    {health.checks?.database && renderCheckRow('Database', health.checks.database)}
                    {health.checks?.auditDatabase && renderCheckRow('Audit Database', health.checks.auditDatabase)}
                    {health.checks?.keystore && renderCheckRow('Keystore', health.checks.keystore)}
                    {health.checks?.tlsCertificate && renderCheckRow('TLS Certificate', health.checks.tlsCertificate)}
                    {health.checks?.diskSpace && renderCheckRow('Disk Space', health.checks.diskSpace)}

                    {/* TLS Certificate details */}
                    {health.checks?.tlsCertificate?.expiresAt && (
                        <div className="mt-2 p-2 bg-gray-50/50 dark:bg-gray-900/50 rounded text-xs">
                            <span className="text-gray-600 dark:text-gray-400">TLS Cert Expires: </span>
                            <span className={health.checks.tlsCertificate.daysRemaining <= 30 ? 'text-yellow-800 dark:text-yellow-400 font-semibold' : 'text-gray-700 dark:text-gray-300'}>
                                {formatDate(health.checks.tlsCertificate.expiresAt)}
                                {health.checks.tlsCertificate.daysRemaining <= 30 && ' -- Renew soon!'}
                            </span>
                        </div>
                    )}

                    {/* Keystore details */}
                    {health.checks?.keystore?.caSigners !== undefined && (
                        <div className="mt-2 p-2 bg-gray-50/50 dark:bg-gray-900/50 rounded text-xs space-y-1">
                            <div><span className="text-gray-600 dark:text-gray-400">CA Signers: </span><span className="text-gray-700 dark:text-gray-300">{health.checks.keystore.caSigners}</span></div>
                            <div><span className="text-gray-600 dark:text-gray-400">Trusted Certs: </span><span className="text-gray-700 dark:text-gray-300">{health.checks.keystore.trustedCerts}</span></div>
                            {health.checks.keystore.expiringCaCerts > 0 && (
                                <div className="text-yellow-800 dark:text-yellow-400">Warning: {health.checks.keystore.expiringCaCerts} CA cert(s) expiring within 30 days</div>
                            )}
                        </div>
                    )}

                    <div className="text-xs text-gray-600 mt-2">
                        Last checked: {lastRefresh.toLocaleTimeString()}
                    </div>
                </div>
            )}
        </div>
    );
};

/* ─── System Status Card ─── */
const SystemStatusCard: React.FC = () => {
    // Real server uptime: fetched once from /health/ready (uptimeSeconds at fetch
    // time), then ticked locally. Re-reads on mount, so a page refresh shows the
    // actual server uptime instead of restarting a page-local stopwatch.
    const [serverUptimeMs, setServerUptimeMs] = useState<number | null>(null);
    const [uptimeError, setUptimeError] = useState<string | null>(null);
    const [fetchedAt, setFetchedAt] = useState(Date.now());
    const [now, setNow] = useState(Date.now());

    useEffect(() => {
        let active = true;
        fetchHealthReady()
            .then((data) => {
                if (!active) return;
                if (typeof data?.uptimeSeconds === 'number') {
                    setServerUptimeMs(data.uptimeSeconds * 1000);
                    setFetchedAt(Date.now());
                } else {
                    setUptimeError('readiness payload carried no uptime');
                }
            })
            .catch((err: any) => { if (active) setUptimeError(err?.message || 'request failed'); });
        const interval = setInterval(() => setNow(Date.now()), 1000);
        return () => { active = false; clearInterval(interval); };
    }, []);

    const serverUptime = serverUptimeMs != null ? serverUptimeMs + (now - fetchedAt) : null;

    return (
        <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-4">
            <h2 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">System Status</h2>
            <DetailField label="Application" value={`ModularCA v${APP_VERSION}`} />
            <DetailField label="Server Uptime" value={serverUptime != null ? formatUptime(serverUptime) : uptimeError ? `Unavailable: could not load /health/ready (${uptimeError})` : '—'} />
            <DetailField label="Current Time" value={new Date(now).toLocaleString()} />
        </div>
    );
};

/* ─── Certificate Statistics Card ─── */
const CertStatsCard: React.FC = () => {
    const [stats, setStats] = useState<{ total: number; active: number; revoked: number; expired: number; expiring30: number } | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);

    useEffect(() => {
        apiGet<any>('/api/v1/admin/certificates')
            .then((data) => {
                const certs: any[] = Array.isArray(data) ? data : (data.items || []);
                const now = new Date();
                const in30 = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
                let active = 0, revoked = 0, expired = 0, expiring30 = 0;
                certs.forEach((c) => {
                    if (c.revoked) { revoked++; }
                    else if (new Date(c.notAfter) < now) { expired++; }
                    else {
                        active++;
                        if (new Date(c.notAfter) <= in30) expiring30++;
                    }
                });
                setStats({ total: certs.length, active, revoked, expired, expiring30 });
            })
            .catch((err) => setError(errorNotice(err, 'The request failed.')))
            .finally(() => setLoading(false));
    }, []);

    const statItems = stats ? [
        { label: 'Total', value: stats.total, color: 'bg-blue-50 dark:bg-blue-900/50 text-blue-800 dark:text-blue-300 border-blue-300 dark:border-blue-700' },
        { label: 'Active', value: stats.active, color: 'bg-green-50 dark:bg-green-900/50 text-green-800 dark:text-green-300 border-green-300 dark:border-green-700' },
        { label: 'Revoked', value: stats.revoked, color: 'bg-red-50 dark:bg-red-900/50 text-red-800 dark:text-red-300 border-red-300 dark:border-red-700' },
        { label: 'Expired', value: stats.expired, color: 'bg-yellow-50 dark:bg-yellow-900/50 text-yellow-800 dark:text-yellow-300 border-yellow-300 dark:border-yellow-700' },
        { label: 'Expiring (30d)', value: stats.expiring30, color: 'bg-orange-50 dark:bg-orange-900/50 text-orange-800 dark:text-orange-300 border-orange-300 dark:border-orange-700' },
    ] : [];

    return (
        <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-4">
            <h2 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Certificate Statistics</h2>
            {loading && <div className="text-sm text-gray-600 dark:text-gray-400">Loading...</div>}
            {error && <InlineNotice notice={error} />}
            {stats && (
                <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
                    {statItems.map((s) => (
                        <div key={s.label} className={`rounded border p-3 text-center ${s.color}`}>
                            <div className="text-2xl font-bold">{s.value}</div>
                            <div className="text-xs mt-1">{s.label}</div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
};

/**
 * A fetch that failed, kept apart from a fetch that returned nothing. On the page whose job is
 * spotting broken subsystems, a dead endpoint must never read as "zero traffic" or "no
 * schedules"; the caller renders an explicit "Unavailable" state for it instead.
 */
type Fetched<T> = { ok: true; value: T } | { ok: false; error: string };

function fetched<T>(p: Promise<T>): Promise<Fetched<T>> {
    return p.then((value) => ({ ok: true as const, value })).catch((err: any) => ({ ok: false as const, error: err?.message || 'request failed' }));
}

const Unavailable: React.FC<{ what: string; error: string }> = ({ what, error }) => (
    <div className="text-xs text-red-800 dark:text-red-400" role="status">Unavailable: could not load {what} ({error}).</div>
);

/* ─── Scheduler Status Card ─── */
const SchedulerStatusCard: React.FC = () => {
    const [schedules, setSchedules] = useState<Fetched<any[]> | null>(null);
    const [features, setFeatures] = useState<Fetched<any[]> | null>(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        Promise.all([
            fetched(apiGet<any>('/api/v1/admin/crl-schedules').then((d) => (Array.isArray(d) ? d : (d.items || d.schedules || [])) as any[])),
            fetched(apiGet<any>('/api/v1/admin/features').then((d) => (Array.isArray(d) ? d : (d.items || d.features || [])) as any[])),
        ]).then(([s, f]) => {
            setSchedules(s);
            setFeatures(f);
        }).finally(() => setLoading(false));
    }, []);

    const featureList = features?.ok ? features.value : [];
    const enabledCount = featureList.filter((f) => f.enabled).length;
    const disabledCount = featureList.filter((f) => !f.enabled).length;

    return (
        <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-4">
            <h2 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Scheduler Status</h2>
            {loading && <div className="text-sm text-gray-600 dark:text-gray-400">Loading...</div>}
            {!loading && (
                <div className="space-y-3">
                    <div>
                        <span className="text-xs text-gray-600 dark:text-gray-400">CRL Schedules</span>
                        {!schedules || !schedules.ok ? (
                            <div className="mt-1"><Unavailable what="CRL schedules" error={schedules?.error || 'no response'} /></div>
                        ) : schedules.value.length === 0 ? (
                            <div className="text-sm text-gray-600 mt-1">No CRL schedules</div>
                        ) : (
                            <div className="mt-1 space-y-1">
                                {schedules.value.map((s, i) => (
                                    <div key={i} className="flex items-center gap-2 text-xs">
                                        <StatusBadge status={s.enabled ? 'enabled' : 'disabled'} />
                                        <span className="text-gray-700 dark:text-gray-300">{s.name}</span>
                                        <span className="text-gray-600 ml-auto">Last: {formatDate(s.lastGenerated || s.lastRun)}</span>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                    <div className="border-t border-gray-300 dark:border-gray-700 pt-3">
                        <span className="text-xs text-gray-600 dark:text-gray-400">Feature Flags Summary</span>
                        {!features || !features.ok ? (
                            <div className="mt-1"><Unavailable what="feature flags" error={features?.error || 'no response'} /></div>
                        ) : (
                            <div className="flex gap-3 mt-1">
                                <StatusBadge status="enabled" label={`${enabledCount} Enabled`} />
                                <StatusBadge status="disabled" label={`${disabledCount} Disabled`} />
                            </div>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
};

/* ─── Protocol Activity Card ─── */
const ProtocolActivityCard: React.FC = () => {
    type Counts = { est: Fetched<number>; scep: Fetched<number>; cmp: Fetched<number>; acme: Fetched<number>; msae: Fetched<number> };
    const [counts, setCounts] = useState<Counts | null>(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        // A failed audit endpoint is reported as such, never as a count of zero: on this page a
        // silent zero is indistinguishable from "the protocol is idle", which is the wrong answer.
        const fetchCount = (path: string): Promise<Fetched<number>> =>
            fetched(apiGet<any>(path).then((d) => {
                const items = Array.isArray(d) ? d : (d.items || d.entries || d.logs || []);
                return items.length as number;
            }));

        Promise.all([
            fetchCount('/api/v1/admin/audit/est?pageSize=100'),
            fetchCount('/api/v1/admin/audit/scep?pageSize=100'),
            fetchCount('/api/v1/admin/audit/cmp?pageSize=100'),
            fetchCount('/api/v1/admin/audit/acme?pageSize=100'),
            fetchCount('/api/v1/admin/audit/msae?pageSize=100'),
        ]).then(([est, scep, cmp, acme, msae]) => {
            setCounts({ est, scep, cmp, acme, msae });
        }).finally(() => setLoading(false));
    }, []);

    const protocols = counts ? [
        { label: 'EST', value: counts.est, color: 'bg-purple-900/50 text-purple-300 border-purple-700' },
        { label: 'SCEP', value: counts.scep, color: 'bg-indigo-900/50 text-indigo-300 border-indigo-700' },
        { label: 'CMP', value: counts.cmp, color: 'bg-teal-900/50 text-teal-300 border-teal-700' },
        { label: 'ACME', value: counts.acme, color: 'bg-cyan-900/50 text-cyan-300 border-cyan-700' },
        { label: 'MSAE', value: counts.msae, color: 'bg-sky-900/50 text-sky-300 border-sky-700' },
    ] : [];
    const failed = protocols.filter((p) => !p.value.ok);

    return (
        <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-4">
            <h2 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Protocol Activity</h2>
            {loading && <div className="text-sm text-gray-600 dark:text-gray-400">Loading...</div>}
            {counts && (
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    {protocols.map((p) => (
                        p.value.ok ? (
                            <div key={p.label} className={`rounded border p-3 text-center ${p.color}`}>
                                <div className="text-2xl font-bold">{p.value.value}</div>
                                <div className="text-xs mt-1">{p.label}</div>
                            </div>
                        ) : (
                            <div key={p.label} className="rounded border border-dashed border-red-300 dark:border-red-800 bg-red-50 dark:bg-red-900/20 p-3 text-center text-red-800 dark:text-red-300" title={p.value.error}>
                                <div className="text-sm font-semibold">Unavailable</div>
                                <div className="text-xs mt-1">{p.label}</div>
                            </div>
                        )
                    ))}
                </div>
            )}
            {failed.length > 0 && (
                <div className="mt-3 space-y-0.5">
                    {failed.map((p) => <Unavailable key={p.label} what={`${p.label} audit entries`} error={p.value.ok ? '' : p.value.error} />)}
                </div>
            )}
        </div>
    );
};

/* ─── Disaster Recovery Status Card ─── */
const DrStatusCard: React.FC = () => {
    const { requireStepUp } = useStepUp();
    const [drStatus, setDrStatus] = useState<any>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [lastRefresh, setLastRefresh] = useState<Date>(new Date());
    const [creatingBackup, setCreatingBackup] = useState(false);
    const [backupMsg, setBackupMsg] = useState<string | null>(null);

    const fetchDrStatus = () => {
        setLoading(true);
        apiGet<any>('/api/v1/admin/backup/dr-status')
            .then((data) => {
                setDrStatus(data);
                setError(null);
                setLastRefresh(new Date());
            })
            .catch((err) => setError(errorNotice(err, 'The request failed.')))
            .finally(() => setLoading(false));
    };

    useEffect(() => {
        fetchDrStatus();
        const interval = setInterval(fetchDrStatus, 30000);
        return () => clearInterval(interval);
    }, []);

    const handleCreateBackup = async () => {
        setCreatingBackup(true);
        setBackupMsg(null);
        try {
            const result = await apiPostWithMfa('/api/v1/admin/backup', {}, requireStepUp, StepUpOps.CreateBackup);
            setBackupMsg(result.message || 'Backup created successfully');
            fetchDrStatus();
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') setBackupMsg(err.message || 'Failed to create backup');
        } finally {
            setCreatingBackup(false);
        }
    };

    const readinessBadge = (readiness: string): { status: 'active' | 'expired' | 'revoked'; color: string } => {
        if (readiness === 'Ready') return { status: 'active', color: 'bg-green-50 dark:bg-green-900/50 text-green-800 dark:text-green-300 border-green-300 dark:border-green-700' };
        if (readiness === 'Warning') return { status: 'expired', color: 'bg-yellow-50 dark:bg-yellow-900/50 text-yellow-800 dark:text-yellow-300 border-yellow-300 dark:border-yellow-700' };
        return { status: 'revoked', color: 'bg-red-50 dark:bg-red-900/50 text-red-800 dark:text-red-300 border-red-300 dark:border-red-700' };
    };

    return (
        <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-4">
            <div className="flex items-center justify-between mb-3">
                <h2 className="text-sm font-semibold text-gray-900 dark:text-white">Disaster Recovery</h2>
                <div className="flex items-center gap-3">
                    <span className="text-xs text-gray-600">Auto-refresh 30s</span>
                    <button onClick={fetchDrStatus} className="text-xs text-blue-800 dark:text-blue-400 hover:text-blue-300 transition-colors">Refresh</button>
                </div>
            </div>

            {loading && !drStatus && <div className="text-sm text-gray-600 dark:text-gray-400">Checking DR status...</div>}
            {error && !drStatus && <InlineNotice notice={error} />}

            {drStatus && (
                <div className="space-y-3">
                    {/* Readiness Badge */}
                    <div className="flex items-center gap-3">
                        <span className="text-xs text-gray-600 dark:text-gray-400">DR Readiness:</span>
                        <div className={`px-2.5 py-1 rounded border text-xs font-semibold ${readinessBadge(drStatus.readiness || drStatus.drReadiness || 'Unknown').color}`}>
                            {drStatus.readiness || drStatus.drReadiness || 'Unknown'}
                        </div>
                    </div>

                    {/* Backup Stats */}
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                        <div className="bg-gray-50/50 dark:bg-gray-900/50 rounded p-3">
                            <div className="text-xs text-gray-600 dark:text-gray-400">Last Backup</div>
                            <div className="text-sm text-gray-900 dark:text-white mt-1">
                                {drStatus.lastBackupTimestamp ? formatDate(drStatus.lastBackupTimestamp) : 'Never'}
                            </div>
                        </div>
                        <div className="bg-gray-50/50 dark:bg-gray-900/50 rounded p-3">
                            <div className="text-xs text-gray-600 dark:text-gray-400">Backup Age</div>
                            <div className={`text-sm mt-1 ${drStatus.backupAgeHours > 24 ? 'text-yellow-800 dark:text-yellow-400' : 'text-gray-900 dark:text-white'}`}>
                                {drStatus.backupAgeHours !== undefined && drStatus.backupAgeHours !== null
                                    ? `${drStatus.backupAgeHours}h`
                                    : drStatus.backupAge || '-'}
                            </div>
                        </div>
                        <div className="bg-gray-50/50 dark:bg-gray-900/50 rounded p-3">
                            <div className="text-xs text-gray-600 dark:text-gray-400">Backup Count</div>
                            <div className="text-sm text-gray-900 dark:text-white mt-1">{drStatus.backupCount ?? '-'}</div>
                        </div>
                    </div>

                    {/* Issues List */}
                    {drStatus.issues && drStatus.issues.length > 0 && (
                        <div className="bg-red-50 dark:bg-red-900/20 border border-red-300 dark:border-red-800 rounded p-3">
                            <div className="text-xs font-semibold text-red-800 dark:text-red-300 mb-1">Issues</div>
                            <ul className="space-y-1">
                                {drStatus.issues.map((issue: string, i: number) => (
                                    <li key={i} className="text-xs text-red-800 dark:text-red-300 flex items-start gap-1.5">
                                        <span className="text-red-500 mt-0.5">--</span>
                                        {issue}
                                    </li>
                                ))}
                            </ul>
                        </div>
                    )}

                    {/* Create Backup Button */}
                    <div className="flex items-center gap-3">
                        <button
                            onClick={handleCreateBackup}
                            disabled={creatingBackup}
                            className="px-4 py-2 text-sm bg-blue-600 text-gray-900 dark:text-white rounded hover:bg-blue-700 disabled:opacity-50 transition-colors"
                        >
                            {creatingBackup ? 'Creating...' : 'Create Backup Now'}
                        </button>
                        {backupMsg && (
                            <span className={`text-xs ${backupMsg.includes('Failed') || backupMsg.includes('fail') ? 'text-red-800 dark:text-red-400' : 'text-green-800 dark:text-green-400'}`}>
                                {backupMsg}
                            </span>
                        )}
                    </div>

                    <div className="text-xs text-gray-600">
                        Last checked: {lastRefresh.toLocaleTimeString()}
                    </div>
                </div>
            )}
        </div>
    );
};

/* ─── System Health Page ─── */
const SystemHealth: React.FC = () => {
    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">System Health</h1>
            <HealthCheckCard />
            <DrStatusCard />
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <SystemStatusCard />
                <CertStatsCard />
            </div>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <SchedulerStatusCard />
                <ProtocolActivityCard />
            </div>
        </div>
    );
};

export default SystemHealth;
