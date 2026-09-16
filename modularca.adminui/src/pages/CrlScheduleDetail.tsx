import React, { useEffect, useState } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { useParams, useNavigate } from 'react-router-dom';
import { apiGet, apiPutWithMfa, apiDeleteWithMfa } from '../api/client';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import ConfirmModal from '../components/ConfirmModal';
import { DetailPage, DetailSection } from '../components/DetailPage';
import { useStepUp } from '../components/StepUpMfaContext';
import { StepUpOps } from '@shared/generated';
import { FieldHint, inputClass as inputCls, labelClass as labelCls } from '@shared/components/forms';
import { OVERLAP_HINT, toTimeSpan } from './Distribution';

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

const crlId = (s: any): string => s.id || s.scheduleId || s.name;

/// <summary>
/// Editable detail page for a single CRL schedule. View shows schedule state; Edit changes the
/// update/delta intervals, overlap period and description. Enable/Disable and Delete live in the
/// action bar.
/// </summary>
const CrlScheduleDetail: React.FC = () => {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();
    const { showToast } = useToast();
    const { requireStepUp } = useStepUp();

    const [schedule, setSchedule] = useState<any | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [refresh, setRefresh] = useState(0);

    const emptyForm = { updateInterval: '', overlapPeriod: '', deltaInterval: '', description: '' };
    const [form, setForm] = useState(emptyForm);
    const [initialForm, setInitialForm] = useState(emptyForm);
    const [confirmDelete, setConfirmDelete] = useState(false);
    const [deleting, setDeleting] = useState(false);

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError(null);
        apiGet<any>('/api/v1/admin/crl-schedules')
            .then((data) => {
                if (cancelled) return;
                const list = Array.isArray(data) ? data : (data.items || data.schedules || []);
                const s = list.find((x: any) => crlId(x) === id) || null;
                setSchedule(s);
                if (s) {
                    const f = {
                        updateInterval: s.updateInterval || s.cronExpression || '',
                        overlapPeriod: s.overlapPeriod ? String(s.overlapPeriod) : '',
                        deltaInterval: s.deltaInterval || '',
                        description: s.description || '',
                    };
                    setForm(f);
                    setInitialForm(f);
                }
                setLoading(false);
            })
            .catch((err) => { if (!cancelled) { setError(errorNotice(err, 'Failed to load schedule')); setLoading(false); } });
        return () => { cancelled = true; };
    }, [id, refresh]);

    const dirty = JSON.stringify(form) !== JSON.stringify(initialForm);

    const handleSave = async () => {
        if (!schedule) return;
        // Same normaliser as the create form on Distribution: `1h`, `30m`, `1h30m`, a bare number
        // of minutes or `hh:mm:ss` all become the TimeSpan string the API binds. Posting the text
        // verbatim used to make this form demand `01:00:00` while the create form did not.
        const overlapPeriod = toTimeSpan(form.overlapPeriod);
        if (overlapPeriod === null) {
            const msg = "Overlap period must look like '1h', '30m', '1h30m', or 'hh:mm:ss'.";
            showToast('error', msg);
            throw new Error(msg);
        }
        try {
            await apiPutWithMfa(`/api/v1/admin/crl-schedules/${crlId(schedule)}`, {
                updateInterval: form.updateInterval,
                overlapPeriod,
                deltaInterval: form.deltaInterval,
                description: form.description,
                isDelta: schedule.isDelta ?? false,
            }, requireStepUp, StepUpOps.UpdateCrlSchedule, crlId(schedule));
            showToast('success', 'CRL schedule updated');
            setRefresh((r) => r + 1);
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to update schedule');
            throw err;
        }
    };

    const handleCancel = () => {
        setForm(initialForm);
    };

    const toggle = async () => {
        if (!schedule) return;
        try {
            await apiPutWithMfa(`/api/v1/admin/crl-schedules/${crlId(schedule)}/status`, { enabled: !schedule.enabled }, requireStepUp, StepUpOps.ToggleCrlSchedule, crlId(schedule));
            setRefresh((r) => r + 1);
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to update status');
        }
    };

    const doDelete = async () => {
        if (!schedule) return;
        setDeleting(true);
        try {
            await apiDeleteWithMfa(`/api/v1/admin/crl-schedules/${crlId(schedule)}`, requireStepUp, StepUpOps.DeleteCrlSchedule, crlId(schedule));
            showToast('success', 'CRL schedule deleted');
            navigate('/distribution?tab=crl');
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to delete schedule');
        } finally {
            setDeleting(false);
            setConfirmDelete(false);
        }
    };

    if (loading) return <div className="p-6 text-sm text-gray-600 dark:text-gray-400">Loading…</div>;
    if (error) return <InlineNotice notice={error} />;
    if (!schedule) return (
        <div className="p-6 space-y-3">
            <p className="text-sm text-gray-600 dark:text-gray-400">CRL schedule not found.</p>
            <button onClick={() => navigate('/distribution?tab=crl')} className="px-3 py-1.5 text-sm bg-gray-200 dark:bg-gray-700 rounded">Back to Distribution</button>
        </div>
    );

    const s = schedule;

    return (
        <DetailPage
            breadcrumbs={[{ label: 'Distribution', to: '/distribution?tab=crl' }, { label: 'CRL Schedules' }, { label: s.name }]}
            title={s.name}
            status={<StatusBadge status={s.enabled ? 'enabled' : 'disabled'} />}
            subtitle={s.caName || s.caId || undefined}
            backTo="/distribution?tab=crl"
            editable
            onSave={handleSave}
            onCancel={handleCancel}
            saveDisabled={!dirty || !form.updateInterval.trim()}
            actions={
                <div className="flex items-center gap-2 flex-wrap">
                    <button onClick={toggle} className="px-3 py-1.5 text-xs bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors">{s.enabled ? 'Disable' : 'Enable'}</button>
                    <button onClick={() => setConfirmDelete(true)} disabled={deleting} className="px-3 py-1.5 text-xs bg-red-50 dark:bg-red-900/50 text-red-800 dark:text-red-300 border border-red-300 dark:border-red-700 rounded hover:bg-red-900 disabled:opacity-50 transition-colors">Delete</button>
                </div>
            }
        >
            {(mode) => (<>
                {mode === 'view' ? (
                    <DetailSection title="CRL Schedule">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8">
                            <DetailField label="Name" value={s.name} />
                            <DetailField label="CA" value={s.caName || s.caId || '-'} />
                            <DetailField label="Status" value={s.enabled ? 'Enabled' : 'Disabled'} />
                            <DetailField label="Update interval (cron)" value={s.updateInterval || s.cronExpression} mono />
                            <DetailField label="Delta Interval" value={s.deltaInterval || '-'} mono />
                            <DetailField label="Overlap Period" value={s.overlapPeriod ? String(s.overlapPeriod) : '-'} />
                            <DetailField label="Description" value={s.description || '-'} />
                            <DetailField label="Last Generated" value={formatDate(s.lastGenerated || s.lastRun)} />
                            <DetailField label="Next Update" value={formatDate(s.nextUpdateUtc || s.nextUpdate)} />
                        </div>
                    </DetailSection>
                ) : (
                    <DetailSection title="Edit CRL Schedule">
                        <div className="space-y-4 max-w-2xl">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                <div>
                                    <label className={labelCls}>Update interval (cron)</label>
                                    <input type="text" value={form.updateInterval} onChange={(e) => setForm({ ...form, updateInterval: e.target.value })} placeholder="0 */6 * * *" className={`${inputCls} font-mono`} />
                                    <FieldHint>A five-field cron expression saying when a fresh CRL is signed and published.</FieldHint>
                                </div>
                                <div>
                                    <label className={labelCls}>Delta Interval (cron)</label>
                                    <input type="text" value={form.deltaInterval} onChange={(e) => setForm({ ...form, deltaInterval: e.target.value })} placeholder="0 * * * *" className={`${inputCls} font-mono`} />
                                </div>
                                <div>
                                    <label className={labelCls}>Overlap Period</label>
                                    <input type="text" value={form.overlapPeriod} onChange={(e) => setForm({ ...form, overlapPeriod: e.target.value })} placeholder="e.g. 1h, 30m, 1h30m" className={`${inputCls} font-mono`} />
                                    <FieldHint>{OVERLAP_HINT}</FieldHint>
                                </div>
                                <div>
                                    <label className={labelCls}>Description</label>
                                    <input type="text" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} className={inputCls} />
                                </div>
                            </div>
                        </div>
                    </DetailSection>
                )}

                <ConfirmModal
                    isOpen={confirmDelete}
                    title="Delete CRL Schedule"
                    message={`Delete "${s.name}"? This cannot be undone.`}
                    confirmLabel="Delete"
                    confirmClass="bg-red-600 hover:bg-red-700"
                    loading={deleting}
                    onConfirm={doDelete}
                    onCancel={() => setConfirmDelete(false)}
                />
            </>)}
        </DetailPage>
    );
};

export default CrlScheduleDetail;
