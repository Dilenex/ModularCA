import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DataTable, DataTableColumn, DataTableBulkAction } from '@shared/components/DataTable';
import {
    type CrlScheduleEntry,
    type LdapPublisherEntry,
    type SchedulerConfigUpdate,
    type SchedulerHealth,
    type SchedulerJob,
    type SchedulerSchedules,
    getSchedulerHealth,
    getSchedulerJobs,
    getSchedulerSchedules,
    runCrlSchedule,
    runLdapSchedule,
    runSchedulerJob,
    setSchedulerJobEnabled,
    updateSchedulerConfig,
} from '../api/scheduler';
import { inputClass, labelClass } from '@shared/components/forms';

// ---------------------------------------------------------------------------
// Style helpers (match Settings/Vulnerabilities/BackupRestore conventions)
// ---------------------------------------------------------------------------

const cardClass = 'bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg';
const primaryButton = 'px-4 py-2 text-sm bg-blue-600 hover:bg-blue-700 text-white rounded transition-colors disabled:opacity-50';

// ---------------------------------------------------------------------------
// Time formatting
// ---------------------------------------------------------------------------

// The API serializes scheduler/CRL/LDAP timestamps from EF (MySQL datetime → DateTimeKind.Unspecified)
// and NCrontab (also Unspecified), i.e. UTC instants WITHOUT a trailing 'Z'. `new Date('2026-06-29T03:00:00')`
// would parse those as LOCAL time, shifting every relative label by the browser's UTC offset. Treat a
// timezone-less ISO string as UTC by appending 'Z'; leave already-zoned strings (Z or ±hh:mm) untouched.
function parseUtc(iso: string): Date {
    const hasTz = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(iso);
    return new Date(hasTz ? iso : `${iso}Z`);
}

function formatAbsoluteUtc(iso: string | null | undefined): string {
    if (!iso) return '';
    const d = parseUtc(iso);
    if (isNaN(d.getTime())) return iso;
    return d.toISOString();
}

function formatRelative(iso: string | null | undefined, now: number): string {
    if (!iso) return '-';
    const d = parseUtc(iso);
    if (isNaN(d.getTime())) return iso;
    const deltaMs = d.getTime() - now;
    const future = deltaMs >= 0;
    const abs = Math.abs(deltaMs);
    const sec = Math.floor(abs / 1000);
    const min = Math.floor(sec / 60);
    const hr = Math.floor(min / 60);
    const day = Math.floor(hr / 24);

    let unit: string;
    let value: number;
    if (sec < 60) { unit = 'second'; value = sec; }
    else if (min < 60) { unit = 'minute'; value = min; }
    else if (hr < 24) { unit = 'hour'; value = hr; }
    else { unit = 'day'; value = day; }

    const plural = value === 1 ? '' : 's';
    return future ? `in ${value} ${unit}${plural}` : `${value} ${unit}${plural} ago`;
}

const TimeCell: React.FC<{ iso: string | null | undefined; now: number }> = ({ iso, now }) => (
    <span className="text-xs text-gray-700 dark:text-gray-300" title={formatAbsoluteUtc(iso) || 'never'}>
        {formatRelative(iso, now)}
    </span>
);

// ---------------------------------------------------------------------------
// Health Strip
// ---------------------------------------------------------------------------

const HealthStrip: React.FC<{ health: SchedulerHealth | null; now: number }> = ({ health, now }) => {
    if (!health) {
        return (
            <div className={`${cardClass} p-4 text-sm text-gray-600 dark:text-gray-400`}>Loading scheduler health...</div>
        );
    }

    const lease = health.leaseHolder;
    const expiresIn = lease ? formatRelative(lease.expiresAtUtc, now) : 'no active lease';
    const instanceShort = lease ? lease.instanceId.slice(0, 12) : '-';

    const tile = (label: string, value: React.ReactNode, title?: string) => (
        <div className="flex flex-col gap-0.5 px-4 py-3 border-r border-gray-300 dark:border-gray-700 last:border-r-0 min-w-[150px]">
            <span className="text-[10px] uppercase tracking-wide text-gray-600 dark:text-gray-400">{label}</span>
            <span className="text-sm text-gray-900 dark:text-white" title={title}>{value}</span>
        </div>
    );

    return (
        <div className={`${cardClass} flex flex-wrap items-stretch overflow-hidden`}>
            {tile(
                'Lease Holder',
                <span className="font-mono">{instanceShort}{lease && lease.instanceId.length > 12 ? '...' : ''}</span>,
                lease?.instanceId,
            )}
            {tile('Lease Expires', expiresIn, lease ? formatAbsoluteUtc(lease.expiresAtUtc) : undefined)}
            {tile('Poll Interval', `${health.pollIntervalSeconds}s, fixed`)}
            {tile('Missed-Run Policy', health.missedRunPolicy || '-')}
            {tile('Default Timeout', `${health.defaultJobTimeoutSeconds}s`)}
            {tile('Failure Alert Threshold', health.consecutiveFailureAlertThreshold)}
        </div>
    );
};

// ---------------------------------------------------------------------------
// System Jobs Section
// ---------------------------------------------------------------------------

// Continuous-throttle jobs (always-on, internally rate-limited). The backend
// returns 400 if the operator tries to disable these — guard the Enable/Disable
// toolbar actions proactively instead of letting the round-trip fail.
const NON_TOGGLEABLE_JOBS = new Set<string>(['AcmeCleanup', 'ProtocolCleanup', 'TlsRenewal']);

function jobResultBadge(result: SchedulerJob['lastResult']): React.ReactElement {
    if (result === 'success') return <StatusBadge status="active" label="success" />;
    if (result === 'failed') return <StatusBadge status="revoked" label="failed" />;
    if (result === 'cancelled') return <StatusBadge status="held" label="cancelled" />;
    return <StatusBadge status="disabled" label="never run" />;
}

/* ── read-only drawer for a system job ──────────────────────────────────────── */
const JobDrawer: React.FC<{ job: SchedulerJob; now: number }> = ({ job, now }) => (
    <div className="text-sm">
        <DetailField label="Name" value={job.name} />
        <DetailField label="Status" value={job.enabled ? 'Enabled' : 'Disabled'} />
        <DetailField label="Cron" value={job.cronExpression} mono />
        <DetailField label="Timeout" value={`${job.timeoutSeconds}s`} />
        <DetailField label="Last Run" value={`${formatRelative(job.lastRunUtc, now)} (${job.lastResult ?? 'never run'})`} />
        {job.lastDurationMs != null && <DetailField label="Last Duration" value={`${job.lastDurationMs} ms`} />}
        <DetailField label="Next Run" value={formatRelative(job.nextRunUtc, now)} />
        <DetailField label="Consecutive Failures" value={String(job.consecutiveFailureCount)} />
        {job.lastError && (
            <div className="mt-2">
                <span className="text-gray-600 text-xs">Last Error</span>
                <pre className="mt-1 text-[11px] text-red-700 dark:text-red-400 whitespace-pre-wrap break-words">{job.lastError}</pre>
            </div>
        )}
    </div>
);

interface SystemJobsSectionProps {
    jobs: SchedulerJob[];
    health: SchedulerHealth | null;
    loading: boolean;
    now: number;
    onChanged: () => void;
}

const SystemJobsSection: React.FC<SystemJobsSectionProps> = ({ jobs, health, loading, now, onChanged }) => {
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();
    const [confirmRunJob, setConfirmRunJob] = useState<SchedulerJob | null>(null);
    const [running, setRunning] = useState<string | null>(null);

    const alertThreshold = health?.consecutiveFailureAlertThreshold ?? Number.MAX_SAFE_INTEGER;

    const handleRun = async (job: SchedulerJob) => {
        setRunning(job.name);
        try {
            await runSchedulerJob(job.name, requireStepUp);
            showToast('success', `Triggered ${job.name}`);
            onChanged();
        } catch (err: any) {
            if (err?.message === 'Step-up MFA cancelled') return;
            showToast('error', err?.message || 'Failed to trigger job');
        } finally {
            setRunning(null);
            setConfirmRunJob(null);
        }
    };

    const handleToggleFlag = async (job: SchedulerJob) => {
        if (NON_TOGGLEABLE_JOBS.has(job.name)) {
            showToast('error', `${job.name} is a continuous job and cannot be disabled.`);
            return;
        }
        try {
            // Toggles the SystemConfig boolean that gates this job (e.g.
            // Backup.CreateOnSchedule, AutoRenewal.Enabled). Step-up MFA gated
            // because it changes scheduler behavior on the next tick.
            await setSchedulerJobEnabled(job.name, !job.enabled, requireStepUp);
            showToast('success', `${job.name} ${job.enabled ? 'disabled' : 'enabled'}`);
            onChanged();
        } catch (err: any) {
            if (err?.message === 'Step-up MFA cancelled') return;
            showToast('error', err?.message || 'Failed to toggle job');
        }
    };

    // No column flexes — every column keeps its natural width and the DataTable's trailing spacer
    // soaks up the slack at the far right, so the row packs to the left. Last Run / Next Run sit
    // side-by-side so they read as a pair.
    const columns: DataTableColumn<SchedulerJob>[] = [
        { key: 'name', header: 'Name', defaultWidth: 180, minWidth: 140, truncate: false, exportValue: (j) => j.name, render: (j) => <span className="text-gray-900 dark:text-white truncate">{j.name}</span> },
        { key: 'status', header: 'Status', defaultWidth: 100, truncate: false, exportValue: (j) => (j.enabled ? 'enabled' : 'disabled'), render: (j) => <StatusBadge status={j.enabled ? 'enabled' : 'disabled'} /> },
        { key: 'cron', header: 'Cron', defaultWidth: 130, exportValue: (j) => j.cronExpression, render: (j) => <span className="font-mono text-xs text-gray-700 dark:text-gray-300">{j.cronExpression}</span> },
        { key: 'lastRun', header: 'Last Run', defaultWidth: 150, headerTitle: 'When this job last executed', exportValue: (j) => formatAbsoluteUtc(j.lastRunUtc), render: (j) => <TimeCell iso={j.lastRunUtc} now={now} /> },
        { key: 'nextRun', header: 'Next Run', defaultWidth: 150, headerTitle: 'Next scheduled run, computed from the cron expression', exportValue: (j) => formatAbsoluteUtc(j.nextRunUtc), render: (j) => <TimeCell iso={j.nextRunUtc} now={now} /> },
        {
            key: 'lastResult', header: 'Last Run Result', defaultWidth: 170, minWidth: 120, truncate: false, exportValue: (j) => j.lastResult ?? 'never run',
            render: (j) => (
                <div className="min-w-0">
                    {jobResultBadge(j.lastResult)}
                    {j.lastError && <div className="text-[10px] text-red-700 dark:text-red-400 truncate mt-0.5" title={j.lastError}>{j.lastError}</div>}
                </div>
            ),
        },
        {
            key: 'failures', header: 'Failures', defaultWidth: 90, exportValue: (j) => j.consecutiveFailureCount,
            render: (j) => {
                const over = j.consecutiveFailureCount >= alertThreshold;
                return (
                    <span className={`inline-block px-2 py-0.5 text-xs rounded border ${over
                        ? 'bg-red-50 text-red-800 border-red-300 dark:bg-red-900/50 dark:text-red-300 dark:border-red-700'
                        : 'bg-gray-100 text-gray-700 border-gray-300 dark:bg-gray-700/50 dark:text-gray-300 dark:border-gray-600'}`}>
                        {j.consecutiveFailureCount}
                    </span>
                );
            },
        },
        { key: 'timeout', header: 'Timeout', defaultWidth: 90, exportValue: (j) => j.timeoutSeconds, render: (j) => <span className="text-xs text-gray-700 dark:text-gray-300">{j.timeoutSeconds}s</span> },
    ];

    // Every scheduler mutation is step-up MFA gated and there's no bulk endpoint, so the
    // mutating actions are single-select (one row → one prompt) rather than looping.
    const bulkActions: DataTableBulkAction<SchedulerJob>[] = [
        { label: 'Run Now', single: true, variant: 'primary', onClick: (rows) => setConfirmRunJob(rows[0]) },
        { label: 'Enable', single: true, enabledFor: (j) => !NON_TOGGLEABLE_JOBS.has(j.name) && !j.enabled, onClick: (rows) => handleToggleFlag(rows[0]) },
        { label: 'Disable', single: true, enabledFor: (j) => !NON_TOGGLEABLE_JOBS.has(j.name) && j.enabled, onClick: (rows) => handleToggleFlag(rows[0]) },
    ];

    return (
        <section className="space-y-3">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">System Jobs</h2>
            <DataTable<SchedulerJob>
                tableId="scheduler-jobs"
                title="System Jobs"
                rows={jobs}
                rowKey={(j) => j.name}
                loading={loading}
                empty="No system jobs registered."
                columns={columns}
                selectable
                bulkActions={bulkActions}
                exportFileName="scheduler-jobs"
                renderDrawer={(j) => <JobDrawer job={j} now={now} />}
                drawerTitle={(j) => j.name}
                detailPath={(j) => `/schedules/jobs/${encodeURIComponent(j.name)}`}
            />

            <ConfirmModal
                isOpen={!!confirmRunJob}
                title="Run Job Now?"
                message={confirmRunJob ? `Trigger "${confirmRunJob.name}" out-of-band? It will run on the lease holder at the next poll tick.` : ''}
                confirmLabel="Run"
                confirmClass="px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors"
                loading={!!running}
                onConfirm={() => confirmRunJob && handleRun(confirmRunJob)}
                onCancel={() => setConfirmRunJob(null)}
            />
        </section>
    );
};

// ---------------------------------------------------------------------------
// Schedules Section (CRL + LDAP, one flat table each with a CA column)
// ---------------------------------------------------------------------------

function ldapFlags(l: LdapPublisherEntry): string {
    return [
        l.publishCACert ? 'CA' : null,
        l.publishCRL ? 'CRL' : null,
        l.publishDelta ? 'Δ' : null,
        l.publishUserCerts ? 'Users' : null,
    ].filter(Boolean).join(', ');
}

const CrlDrawer: React.FC<{ entry: CrlScheduleEntry; now: number }> = ({ entry, now }) => (
    <div className="text-sm">
        <DetailField label="CA" value={entry.caLabel || 'Unknown CA'} />
        <DetailField label="Name" value={entry.name} />
        <DetailField label="Status" value={entry.enabled ? 'Enabled' : 'Disabled'} />
        <DetailField label="Update Interval" value={entry.updateInterval} mono />
        <DetailField label="Delta Interval" value={entry.deltaInterval || ''} mono />
        <DetailField label="Is Delta" value={entry.isDelta ? 'Yes' : 'No'} />
        <DetailField label="Last Generated" value={formatRelative(entry.lastGenerated || entry.lastUpdatedUtc, now)} />
        <DetailField label="Next Update" value={formatRelative(entry.nextUpdateUtc, now)} />
        {entry.lastCrlNumber != null && <DetailField label="Last CRL Number" value={String(entry.lastCrlNumber)} />}
        <p className="text-[11px] text-gray-500 pt-3">Edit CRL schedules on the Distribution page.</p>
    </div>
);

const LdapDrawer: React.FC<{ entry: LdapPublisherEntry; now: number }> = ({ entry, now }) => (
    <div className="text-sm">
        <DetailField label="CA" value={entry.caLabel || 'Unknown CA'} />
        <DetailField label="Host" value={`${entry.host}:${entry.port}`} mono />
        <DetailField label="Base DN" value={entry.baseDn} mono />
        <DetailField label="Status" value={entry.enabled ? 'Enabled' : 'Disabled'} />
        <DetailField label="Update Interval" value={entry.updateInterval} mono />
        <DetailField label="Publishes" value={ldapFlags(entry) || 'None'} />
        <DetailField label="Last Updated" value={formatRelative(entry.lastUpdatedUtc, now)} />
        <DetailField label="Next Update" value={formatRelative(entry.nextUpdateUtc, now)} />
        <p className="text-[11px] text-gray-500 pt-3">Edit LDAP publishers on the Distribution page.</p>
    </div>
);

interface SchedulesSectionProps {
    schedules: SchedulerSchedules | null;
    loading: boolean;
    now: number;
    onChanged: () => void;
}

const SchedulesSection: React.FC<SchedulesSectionProps> = ({ schedules, loading, now, onChanged }) => {
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();
    const navigate = useNavigate();

    const crl = schedules?.crl ?? [];
    const ldap = schedules?.ldap ?? [];

    const handleRunCrl = async (entry: CrlScheduleEntry) => {
        try {
            await runCrlSchedule(entry.taskId, requireStepUp);
            showToast('success', `Triggered CRL "${entry.name}"`);
            onChanged();
        } catch (err: any) {
            if (err?.message === 'Step-up MFA cancelled') return;
            showToast('error', err?.message || 'Failed to trigger CRL run');
        }
    };

    const handleRunLdap = async (entry: LdapPublisherEntry) => {
        try {
            await runLdapSchedule(entry.id, requireStepUp);
            showToast('success', `Triggered LDAP publish (${entry.host})`);
            onChanged();
        } catch (err: any) {
            if (err?.message === 'Step-up MFA cancelled') return;
            showToast('error', err?.message || 'Failed to trigger LDAP publish');
        }
    };

    const crlColumns: DataTableColumn<CrlScheduleEntry>[] = [
        { key: 'ca', header: 'CA', defaultWidth: 160, minWidth: 120, truncate: false, exportValue: (c) => c.caLabel, render: (c) => <span className="text-gray-900 dark:text-white truncate">{c.caLabel || 'Unknown CA'}</span> },
        { key: 'name', header: 'Name', defaultWidth: 200, exportValue: (c) => c.name, render: (c) => <span className="text-gray-900 dark:text-white truncate">{c.name}</span> },
        { key: 'update', header: 'Update', defaultWidth: 110, exportValue: (c) => c.updateInterval, render: (c) => <span className="font-mono text-xs text-gray-700 dark:text-gray-300">{c.updateInterval}</span> },
        { key: 'delta', header: 'Delta', defaultWidth: 100, exportValue: (c) => c.deltaInterval || '', render: (c) => <span className="font-mono text-xs text-gray-700 dark:text-gray-300">{c.deltaInterval || '-'}</span> },
        { key: 'last', header: 'Last', defaultWidth: 140, exportValue: (c) => formatAbsoluteUtc(c.lastGenerated || c.lastUpdatedUtc), render: (c) => <TimeCell iso={c.lastGenerated || c.lastUpdatedUtc} now={now} /> },
        { key: 'next', header: 'Next', defaultWidth: 140, exportValue: (c) => formatAbsoluteUtc(c.nextUpdateUtc), render: (c) => <TimeCell iso={c.nextUpdateUtc} now={now} /> },
        { key: 'status', header: 'Status', defaultWidth: 100, truncate: false, exportValue: (c) => (c.enabled ? 'enabled' : 'disabled'), render: (c) => <StatusBadge status={c.enabled ? 'enabled' : 'disabled'} /> },
    ];

    const crlBulk: DataTableBulkAction<CrlScheduleEntry>[] = [
        { label: 'Run Now', single: true, variant: 'primary', onClick: (rows) => handleRunCrl(rows[0]) },
        { label: 'Edit on Distribution →', single: true, onClick: () => navigate('/distribution?tab=crl') },
    ];

    const ldapColumns: DataTableColumn<LdapPublisherEntry>[] = [
        { key: 'ca', header: 'CA', defaultWidth: 150, minWidth: 120, truncate: false, exportValue: (l) => l.caLabel, render: (l) => <span className="text-gray-900 dark:text-white truncate">{l.caLabel || 'Unknown CA'}</span> },
        { key: 'host', header: 'Host', defaultWidth: 170, exportValue: (l) => `${l.host}:${l.port}`, render: (l) => <span className="text-gray-900 dark:text-white truncate">{l.host}:{l.port}</span> },
        { key: 'baseDn', header: 'Base DN', defaultWidth: 240, exportValue: (l) => l.baseDn, render: (l) => <span className="font-mono text-xs text-gray-700 dark:text-gray-300 truncate">{l.baseDn}</span> },
        { key: 'update', header: 'Update', defaultWidth: 100, exportValue: (l) => l.updateInterval, render: (l) => <span className="font-mono text-xs text-gray-700 dark:text-gray-300">{l.updateInterval}</span> },
        { key: 'last', header: 'Last', defaultWidth: 130, exportValue: (l) => formatAbsoluteUtc(l.lastUpdatedUtc), render: (l) => <TimeCell iso={l.lastUpdatedUtc} now={now} /> },
        { key: 'next', header: 'Next', defaultWidth: 130, exportValue: (l) => formatAbsoluteUtc(l.nextUpdateUtc), render: (l) => <TimeCell iso={l.nextUpdateUtc} now={now} /> },
        { key: 'publishes', header: 'Publishes', defaultWidth: 120, exportValue: (l) => ldapFlags(l), render: (l) => <span className="text-xs text-gray-700 dark:text-gray-300">{ldapFlags(l) || '-'}</span> },
        { key: 'status', header: 'Status', defaultWidth: 100, truncate: false, exportValue: (l) => (l.enabled ? 'enabled' : 'disabled'), render: (l) => <StatusBadge status={l.enabled ? 'enabled' : 'disabled'} /> },
    ];

    const ldapBulk: DataTableBulkAction<LdapPublisherEntry>[] = [
        { label: 'Run Now', single: true, variant: 'primary', onClick: (rows) => handleRunLdap(rows[0]) },
        { label: 'Edit on Distribution →', single: true, onClick: (rows) => navigate(`/distribution?tab=ldap${rows[0].certificateAuthorityId ? `&caId=${rows[0].certificateAuthorityId}` : ''}`) },
    ];

    return (
        <section className="space-y-4">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Schedules</h2>
            <DataTable<CrlScheduleEntry>
                tableId="crl-schedules"
                title="CRL Schedules"
                rows={crl}
                rowKey={(c) => c.taskId}
                loading={loading && !schedules}
                empty="No CRL schedules configured."
                columns={crlColumns}
                selectable
                bulkActions={crlBulk}
                exportFileName="crl-schedules"
                renderDrawer={(c) => <CrlDrawer entry={c} now={now} />}
                drawerTitle={(c) => c.name}
            />
            <DataTable<LdapPublisherEntry>
                tableId="ldap-publishers"
                title="LDAP Publishers"
                rows={ldap}
                rowKey={(l) => l.id}
                loading={loading && !schedules}
                empty="No LDAP publishers configured."
                columns={ldapColumns}
                selectable
                bulkActions={ldapBulk}
                exportFileName="ldap-publishers"
                renderDrawer={(l) => <LdapDrawer entry={l} now={now} />}
                drawerTitle={(l) => `${l.host}:${l.port}`}
            />
        </section>
    );
};

// ---------------------------------------------------------------------------
// Scheduler Config Section
// ---------------------------------------------------------------------------

const MISSED_RUN_POLICIES = ['SkipMissed', 'RunOnce', 'RunAll'];

const SchedulerConfigSection: React.FC<{ health: SchedulerHealth | null; onChanged: () => void }> = ({ health, onChanged }) => {
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();
    const [leaseTtl, setLeaseTtl] = useState('');
    const [policy, setPolicy] = useState('SkipMissed');
    const [defaultTimeout, setDefaultTimeout] = useState('');
    const [alertThreshold, setAlertThreshold] = useState('');
    const [saving, setSaving] = useState(false);

    useEffect(() => {
        if (health) {
            setLeaseTtl(String(health.leaseTtlSeconds ?? ''));
            setPolicy(health.missedRunPolicy || 'SkipMissed');
            setDefaultTimeout(String(health.defaultJobTimeoutSeconds ?? ''));
            setAlertThreshold(String(health.consecutiveFailureAlertThreshold ?? ''));
        }
    }, [health]);

    const leaseTtlNum = parseInt(leaseTtl, 10);
    const timeoutNum = parseInt(defaultTimeout, 10);
    const thresholdNum = parseInt(alertThreshold, 10);
    const leaseTtlOk = Number.isFinite(leaseTtlNum) && leaseTtlNum >= 15;
    const timeoutOk = Number.isFinite(timeoutNum) && timeoutNum > 0;
    const thresholdOk = Number.isFinite(thresholdNum) && thresholdNum >= 1;
    const canSave = leaseTtlOk && timeoutOk && thresholdOk && !saving;

    const handleSave = async () => {
        setSaving(true);
        const body: SchedulerConfigUpdate = {
            leaseTtlSeconds: leaseTtlNum,
            missedRunPolicy: policy,
            defaultJobTimeoutSeconds: timeoutNum,
            consecutiveFailureAlertThreshold: thresholdNum,
        };
        try {
            await updateSchedulerConfig(body, requireStepUp);
            showToast('success', 'Scheduler config saved');
            onChanged();
        } catch (err: any) {
            if (err?.message === 'Step-up MFA cancelled') return;
            showToast('error', err?.message || 'Failed to save config');
        } finally {
            setSaving(false);
        }
    };

    return (
        <section className="space-y-3">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Scheduler Config</h2>
            <div className={`${cardClass} p-4 space-y-4`}>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                        <label className={labelClass}>Lease TTL (seconds, min 15)</label>
                        <input type="text" inputMode="numeric" value={leaseTtl}
                            onChange={(e) => setLeaseTtl(e.target.value.replace(/\D/g, ''))} className={inputClass} />
                        {!leaseTtlOk && <p className="text-[10px] text-red-700 dark:text-red-400 mt-1">Must be at least 15 seconds.</p>}
                    </div>
                    <div>
                        <label className={labelClass}>Missed-Run Policy</label>
                        <select value={policy} onChange={(e) => setPolicy(e.target.value)} className={inputClass}>
                            {MISSED_RUN_POLICIES.map((p) => <option key={p} value={p}>{p}</option>)}
                        </select>
                    </div>
                    <div>
                        <label className={labelClass}>Default Job Timeout (seconds)</label>
                        <input type="text" inputMode="numeric" value={defaultTimeout}
                            onChange={(e) => setDefaultTimeout(e.target.value.replace(/\D/g, ''))} className={inputClass} />
                        {!timeoutOk && <p className="text-[10px] text-red-700 dark:text-red-400 mt-1">Must be a positive integer.</p>}
                    </div>
                    <div>
                        <label className={labelClass}>Consecutive Failure Alert Threshold</label>
                        <input type="text" inputMode="numeric" value={alertThreshold}
                            onChange={(e) => setAlertThreshold(e.target.value.replace(/\D/g, ''))} className={inputClass} />
                        {!thresholdOk && <p className="text-[10px] text-red-700 dark:text-red-400 mt-1">Must be at least 1.</p>}
                    </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 opacity-60 pointer-events-none">
                    <div>
                        <label className={labelClass}>Enabled (read-only)</label>
                        <input type="text" value="true" disabled className={inputClass} />
                    </div>
                    <div>
                        <label className={labelClass}>Poll Interval (read-only)</label>
                        <input type="text" value={`${health?.pollIntervalSeconds ?? 30}s`} disabled className={inputClass} />
                    </div>
                </div>

                <div className="flex justify-end">
                    <button onClick={handleSave} disabled={!canSave} className={primaryButton}>
                        {saving ? 'Saving...' : 'Save'}
                    </button>
                </div>
            </div>
        </section>
    );
};

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

const Schedules: React.FC = () => {
    const { showToast } = useToast();
    const [health, setHealth] = useState<SchedulerHealth | null>(null);
    const [jobs, setJobs] = useState<SchedulerJob[]>([]);
    const [schedules, setSchedules] = useState<SchedulerSchedules | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [now, setNow] = useState<number>(Date.now());

    const reload = useCallback(async () => {
        setError(null);
        try {
            const [h, j, s] = await Promise.all([
                getSchedulerHealth(),
                getSchedulerJobs(),
                getSchedulerSchedules(),
            ]);
            setHealth(h);
            setJobs(j);
            setSchedules(s);
        } catch (err: any) {
            setError(err?.message || 'Failed to load scheduler data');
            showToast('error', err?.message || 'Failed to load scheduler data');
        } finally {
            setLoading(false);
        }
    }, [showToast]);

    useEffect(() => {
        reload();
    }, [reload]);

    // Tick the relative-time clock every second so the "expires in" countdown
    // and "in N minutes" labels stay live without re-fetching.
    useEffect(() => {
        const id = setInterval(() => setNow(Date.now()), 1000);
        return () => clearInterval(id);
    }, []);

    return (
        <div className="p-3 sm:p-6 space-y-6">
            <div className="flex items-center justify-between">
                <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Schedules</h1>
                <button onClick={reload} disabled={loading}
                    className="px-3 py-1.5 text-xs bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors disabled:opacity-50">
                    {loading ? 'Loading...' : 'Refresh'}
                </button>
            </div>

            {error && (
                <div className="p-3 bg-red-50 dark:bg-red-900/30 border border-red-300 dark:border-red-700 rounded text-sm text-red-800 dark:text-red-300">
                    {error}
                </div>
            )}

            <HealthStrip health={health} now={now} />
            <SystemJobsSection jobs={jobs} health={health} loading={loading} now={now} onChanged={reload} />
            <SchedulesSection schedules={schedules} loading={loading} now={now} onChanged={reload} />
            <SchedulerConfigSection health={health} onChanged={reload} />
        </div>
    );
};

export default Schedules;
