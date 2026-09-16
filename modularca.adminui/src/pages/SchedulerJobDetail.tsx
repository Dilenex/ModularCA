import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DetailPage, DetailSection } from '../components/DetailPage';
import {
    type SchedulerJob,
    type SchedulerJobUpdate,
    getSchedulerJobs,
    runSchedulerJob,
    setSchedulerJobEnabled,
    updateSchedulerJob,
} from '../api/scheduler';
import { inputClass as inputCls, labelClass as labelCls } from '@shared/components/forms';

const NON_TOGGLEABLE_JOBS = new Set<string>(['AcmeCleanup', 'ProtocolCleanup', 'TlsRenewal']);
const CRON_5_FIELD = /^\s*\S+\s+\S+\s+\S+\s+\S+\s+\S+\s*$/;

// Scheduler timestamps arrive as UTC instants without a trailing 'Z' (EF/NCrontab emit
// DateTimeKind.Unspecified). Append 'Z' so they aren't misread as local, then render in the
// viewer's local zone.
function formatDate(d: string | null) {
    if (!d) return '-';
    const hasTz = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(d);
    return new Date(hasTz ? d : `${d}Z`).toLocaleString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function jobResultBadge(result: SchedulerJob['lastResult']): React.ReactElement {
    if (result === 'success') return <StatusBadge status="active" label="success" />;
    if (result === 'failed') return <StatusBadge status="revoked" label="failed" />;
    if (result === 'cancelled') return <StatusBadge status="held" label="cancelled" />;
    return <StatusBadge status="disabled" label="never run" />;
}


/// <summary>
/// Editable detail page for a single scheduler job (keyed by name). View shows run state; Edit
/// changes the cron expression and timeout (step-up MFA). Run Now / Enable / Disable live in the
/// action bar.
/// </summary>
const SchedulerJobDetail: React.FC = () => {
    const { name } = useParams<{ name: string }>();
    const navigate = useNavigate();
    const { showToast } = useToast();
    const { requireStepUp } = useStepUp();

    const [job, setJob] = useState<SchedulerJob | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [refresh, setRefresh] = useState(0);

    const [cron, setCron] = useState('');
    const [timeout, setTimeoutVal] = useState('');
    const [initialForm, setInitialForm] = useState({ cron: '', timeout: '' });
    const [confirmRun, setConfirmRun] = useState(false);
    const [running, setRunning] = useState(false);

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError(null);
        getSchedulerJobs()
            .then((jobs) => {
                if (cancelled) return;
                const j = jobs.find((x) => x.name === name) || null;
                setJob(j);
                if (j) {
                    const seeded = { cron: j.cronExpression || '', timeout: String(j.timeoutSeconds ?? '') };
                    setCron(seeded.cron);
                    setTimeoutVal(seeded.timeout);
                    setInitialForm(seeded);
                }
                setLoading(false);
            })
            .catch((err) => { if (!cancelled) { setError(err?.message || 'Failed to load job'); setLoading(false); } });
        return () => { cancelled = true; };
    }, [name, refresh]);

    const cronShapeOk = CRON_5_FIELD.test(cron);
    const timeoutNum = parseInt(timeout, 10);
    const timeoutOk = !timeout || (Number.isFinite(timeoutNum) && timeoutNum > 0);

    const editForm = { cron, timeout };
    const dirty = JSON.stringify(editForm) !== JSON.stringify(initialForm);

    const handleSave = async () => {
        if (!job) return;
        const body: SchedulerJobUpdate = {};
        if (cron && cron !== job.cronExpression) body.cronExpression = cron;
        if (timeout && timeoutNum !== job.timeoutSeconds) body.timeoutSeconds = timeoutNum;
        try {
            await updateSchedulerJob(job.name, body, requireStepUp);
            showToast('success', `Updated ${job.name}`);
            setRefresh((r) => r + 1);
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err?.message || 'Failed to update job');
            throw err;
        }
    };

    const handleCancel = () => {
        setCron(initialForm.cron);
        setTimeoutVal(initialForm.timeout);
    };

    const doRun = async () => {
        if (!job) return;
        setRunning(true);
        try {
            await runSchedulerJob(job.name, requireStepUp);
            showToast('success', `Triggered ${job.name}`);
            setRefresh((r) => r + 1);
        } catch (err: any) {
            if (err?.message !== 'Step-up MFA cancelled') showToast('error', err?.message || 'Failed to trigger job');
        } finally {
            setRunning(false);
            setConfirmRun(false);
        }
    };

    const toggle = async () => {
        if (!job) return;
        if (NON_TOGGLEABLE_JOBS.has(job.name)) { showToast('error', `${job.name} is a continuous job and cannot be disabled.`); return; }
        try {
            await setSchedulerJobEnabled(job.name, !job.enabled, requireStepUp);
            showToast('success', `${job.name} ${job.enabled ? 'disabled' : 'enabled'}`);
            setRefresh((r) => r + 1);
        } catch (err: any) {
            if (err?.message !== 'Step-up MFA cancelled') showToast('error', err?.message || 'Failed to toggle job');
        }
    };

    if (loading) return <div className="p-6 text-sm text-gray-600 dark:text-gray-400">Loading…</div>;
    if (error) return <div className="p-6 text-sm text-red-800 dark:text-red-400">{error}</div>;
    if (!job) return (
        <div className="p-6 space-y-3">
            <p className="text-sm text-gray-600 dark:text-gray-400">Job not found.</p>
            <button onClick={() => navigate('/schedules')} className="px-3 py-1.5 text-sm bg-gray-200 dark:bg-gray-700 rounded">Back to Schedules</button>
        </div>
    );

    const toggleable = !NON_TOGGLEABLE_JOBS.has(job.name);

    return (
        <DetailPage
            breadcrumbs={[{ label: 'Schedules', to: '/schedules' }, { label: job.name }]}
            title={job.name}
            status={<StatusBadge status={job.enabled ? 'enabled' : 'disabled'} />}
            backTo="/schedules"
            editable
            onSave={handleSave}
            onCancel={handleCancel}
            saveDisabled={!dirty || !cronShapeOk || !timeoutOk}
            actions={
                <div className="flex items-center gap-2 flex-wrap">
                    <button onClick={() => setConfirmRun(true)} disabled={running}
                        className="px-3 py-1.5 text-xs bg-green-50 dark:bg-green-900/50 text-green-800 dark:text-green-300 border border-green-300 dark:border-green-700 rounded hover:bg-green-900 disabled:opacity-50 transition-colors">
                        {running ? 'Running…' : 'Run Now'}
                    </button>
                    {toggleable && (
                        <button onClick={toggle}
                            className="px-3 py-1.5 text-xs bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors">
                            {job.enabled ? 'Disable' : 'Enable'}
                        </button>
                    )}
                </div>
            }
        >
            {(mode) => (<>
                {mode === 'view' ? (
                    <DetailSection title="Job">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8">
                            <DetailField label="Name" value={job.name} />
                            <DetailField label="Status" value={job.enabled ? 'Enabled' : 'Disabled'} />
                            <DetailField label="Cron" value={job.cronExpression} mono />
                            <DetailField label="Timeout" value={`${job.timeoutSeconds}s`} />
                            <DetailField label="Last Run" value={formatDate(job.lastRunUtc)} />
                            <DetailField label="Last Result" value={<span className="inline-flex">{jobResultBadge(job.lastResult)}</span>} />
                            {job.lastDurationMs != null && <DetailField label="Last Duration" value={`${job.lastDurationMs} ms`} />}
                            <DetailField label="Next Run" value={formatDate(job.nextRunUtc)} />
                            <DetailField label="Consecutive Failures" value={String(job.consecutiveFailureCount)} />
                        </div>
                        {job.lastError && (
                            <div className="mt-2">
                                <span className="text-gray-600 text-xs">Last Error</span>
                                <pre className="mt-1 text-[11px] text-red-700 dark:text-red-400 whitespace-pre-wrap break-words">{job.lastError}</pre>
                            </div>
                        )}
                    </DetailSection>
                ) : (
                    <DetailSection title="Edit Job">
                        <div className="space-y-4 max-w-lg">
                            <div>
                                <label className={labelCls}>Cron Expression</label>
                                <input type="text" value={cron} onChange={(e) => setCron(e.target.value)} placeholder="0 */6 * * *" className={`${inputCls} font-mono`} />
                                {!cronShapeOk && cron.length > 0 && <p className="text-[10px] text-red-700 dark:text-red-400 mt-1">Must be 5 space-separated fields.</p>}
                            </div>
                            <div>
                                <label className={labelCls}>Timeout (seconds)</label>
                                <input type="text" inputMode="numeric" value={timeout} onChange={(e) => setTimeoutVal(e.target.value.replace(/\D/g, ''))} className={inputCls} />
                                {!timeoutOk && <p className="text-[10px] text-red-700 dark:text-red-400 mt-1">Timeout must be a positive integer.</p>}
                            </div>
                        </div>
                    </DetailSection>
                )}

                <ConfirmModal
                    isOpen={confirmRun}
                    title="Run Job Now?"
                    message={`Trigger "${job.name}" out-of-band? It will run on the lease holder at the next poll tick.`}
                    confirmLabel="Run"
                    confirmClass="px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors"
                    loading={running}
                    onConfirm={doRun}
                    onCancel={() => setConfirmRun(false)}
                />
            </>)}
        </DetailPage>
    );
};

export default SchedulerJobDetail;
