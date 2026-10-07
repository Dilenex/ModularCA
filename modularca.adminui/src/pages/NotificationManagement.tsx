import React, { useEffect, useState, useMemo } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { apiGet, apiPut, apiPost } from '../api/client';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import { DataTable, DataTableColumn, DataTableBulkAction } from '@shared/components/DataTable';
import { labelClass } from '@shared/components/forms';
import { Capabilities } from '@shared/generated';
import { useAuth } from '../context/AuthContext';
import { ChipListInput } from '@shared/components/ChipListInput';
import { invalidItems, listFromValue, listToCsv } from '@shared/components/chipList';
import { validateEmail } from '@shared/validators';

interface AlertConfig { enabled: boolean; minimumSeverity: string; cooldownMinutes: number; }

const NotificationManagement: React.FC = () => {
    const { can } = useAuth();
    const isSystemAdmin = can(Capabilities.SystemManage);
    const [prefs, setPrefs] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [testStatus, setTestStatus] = useState<string | null>(null);

    const [alertConfig, setAlertConfig] = useState<AlertConfig | null>(null);
    const [alertConfigLoading, setAlertConfigLoading] = useState(true);
    const [emailConfig, setEmailConfig] = useState<any | null>(null);

    // Single-row edit modal
    const [editTarget, setEditTarget] = useState<any | null>(null);
    const [editForm, setEditForm] = useState<{ recipients: string[]; daysBeforeExpiry: string; enabled: boolean; hasDays: boolean }>({ recipients: [], daysBeforeExpiry: '', enabled: true, hasDays: false });
    const [editEmailError, setEditEmailError] = useState<NoticeInput | null>(null);
    const [saving, setSaving] = useState(false);

    const loadPrefs = async () => {
        setLoading(true);
        setError(null);
        try {
            const data = await apiGet<any[]>('/api/v1/admin/notifications');
            setPrefs(Array.isArray(data) ? data : ((data as any).items || []));
        } catch (err: any) {
            setError(errorNotice(err, 'Failed to load notification preferences'));
        }
        setLoading(false);
    };

    const loadConfig = async () => {
        setAlertConfigLoading(true);
        try {
            // GET /admin/config builds its response from an anonymous object, so every key
            // goes through the camelCase naming policy: `alert`, not `Alert`. Reading the
            // PascalCase name made both guards below always false, so the alert panel showed
            // "not available" and the SMTP panel never rendered at all.
            // The full config is system-admin only; anyone else gets the email summary.
            const config = await apiGet<any>(isSystemAdmin ? '/api/v1/admin/config' : '/api/v1/admin/notifications/delivery');
            if (config.alert) {
                setAlertConfig({
                    enabled: config.alert.enabled ?? true,
                    minimumSeverity: config.alert.minimumSeverity ?? 'Warning',
                    cooldownMinutes: config.alert.cooldownMinutes ?? 5,
                });
            }
            if (config.email) setEmailConfig(config.email);
        } catch { }
        setAlertConfigLoading(false);
    };

    useEffect(() => { loadPrefs(); loadConfig(); }, [isSystemAdmin]);

    const bulkSetEnabled = async (rows: any[], enabled: boolean) => {
        const targets = rows.filter((p) => p.enabled !== enabled);
        if (targets.length === 0) { setTestStatus(`All selected are already ${enabled ? 'enabled' : 'disabled'}.`); setTimeout(() => setTestStatus(null), 3000); return; }
        let failed = 0;
        for (const p of targets) {
            try { await apiPut(`/api/v1/admin/notifications/${p.eventType}`, { enabled }); } catch { failed++; }
        }
        if (failed > 0) { setTestStatus(`${failed} of ${targets.length} could not be ${enabled ? 'enabled' : 'disabled'}; the table shows the current state.`); setTimeout(() => setTestStatus(null), 6000); }
        loadPrefs();
    };

    const openEdit = (p: any) => {
        const hasDays = p.daysBeforeExpiry !== undefined && p.daysBeforeExpiry !== null;
        setEditForm({ recipients: listFromValue(p.recipients), daysBeforeExpiry: hasDays ? String(p.daysBeforeExpiry) : '', enabled: !!p.enabled, hasDays });
        setEditEmailError(null);
        setEditTarget(p);
    };

    const recipientsInvalid = invalidItems(editForm.recipients, validateEmail).length > 0;

    const saveEdit = async () => {
        if (!editTarget) return;
        if (recipientsInvalid) return;
        setSaving(true);
        try {
            const body: any = { enabled: editForm.enabled, recipients: listToCsv(editForm.recipients) };
            if (editForm.hasDays && editForm.daysBeforeExpiry) body.daysBeforeExpiry = parseInt(editForm.daysBeforeExpiry, 10);
            await apiPut(`/api/v1/admin/notifications/${editTarget.eventType}`, body);
            setEditTarget(null);
            loadPrefs();
        } catch (err: any) {
            setEditEmailError(errorNotice(err, 'Failed to save'));
        } finally {
            setSaving(false);
        }
    };

    const sendTestEmail = async () => {
        setTestStatus('Sending...');
        try {
            await apiPost('/api/v1/admin/notifications/test');
            setTestStatus('Test email sent successfully!');
        } catch (err: any) {
            setTestStatus(`Failed: ${err.message}`);
        }
        setTimeout(() => setTestStatus(null), 5000);
    };

    const columns: DataTableColumn<any>[] = useMemo(() => [
        { key: 'status', header: 'Status', defaultWidth: 90, truncate: false, exportValue: (p) => (p.enabled ? 'Enabled' : 'Disabled'),
            render: (p) => <StatusBadge status={p.enabled ? 'enabled' : 'disabled'} /> },
        { key: 'eventType', header: 'Event', defaultWidth: 280, minWidth: 180, truncate: false, exportValue: (p) => p.eventType,
            render: (p) => (
                <div className="min-w-0">
                    <div className="text-ink font-medium truncate">{p.eventType}</div>
                    {p.description && <div className="text-xs text-ink-muted truncate">{p.description}</div>}
                </div>
            ) },
        { key: 'days', header: 'Expiry Warning', defaultWidth: 130, align: 'right', exportValue: (p) => (p.daysBeforeExpiry ?? ''),
            render: (p) => (p.daysBeforeExpiry ? `${p.daysBeforeExpiry}d` : '-') },
        { key: 'recipients', header: 'Recipients', defaultWidth: 220, exportValue: (p) => p.recipients || '',
            render: (p) => p.recipients || <span className="text-ink-muted">(admin default)</span> },
    ], []);

    const bulkActions: DataTableBulkAction<any>[] = [
        { label: 'Edit', single: true, onClick: (rows) => openEdit(rows[0]) },
        { label: 'Enable', onClick: (rows) => bulkSetEnabled(rows, true) },
        { label: 'Disable', onClick: (rows) => bulkSetEnabled(rows, false) },
    ];

    const renderDrawer = (p: any) => (
        <div className="text-sm">
            <DetailField label="Event Type" value={p.eventType} />
            <DetailField label="Status" value={<StatusBadge status={p.enabled ? 'enabled' : 'disabled'} />} />
            {p.description && <DetailField label="Description" value={p.description} />}
            {(p.daysBeforeExpiry !== undefined && p.daysBeforeExpiry !== null) && <DetailField label="Expiry Warning" value={`${p.daysBeforeExpiry} days before expiry`} />}
            <DetailField label="Recipients" value={p.recipients || '(uses admin default)'} />
            <p className="text-[11px] text-ink-muted pt-2">Select the row in the table to edit, enable, or disable.</p>
        </div>
    );


    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <div className="flex items-center justify-between">
                <h1 className="text-xl font-semibold text-ink">Email Notifications</h1>
                <button onClick={sendTestEmail} className="px-4 py-2 bg-accent text-on-accent rounded hover:bg-accent-hover text-sm">Send Test Email</button>
            </div>

            {testStatus && (
                <div className={`p-3 rounded text-sm border ${testStatus.includes('success') ? 'bg-ok-soft border-ok/40 text-ok' : testStatus === 'Sending...' ? 'bg-info-soft border-info/40 text-info' : 'bg-crit-soft border-crit/40 text-crit'}`}>
                    {testStatus}
                </div>
            )}

            <div>
                <p className="text-xs text-ink-muted mb-2">Configure which events send email notifications and to whom. Select rows to enable, disable, or edit.</p>
                <DataTable<any>
                    tableId="notification-prefs"
                    title="Notification Preferences"
                    rows={prefs}
                    rowKey={(p) => p.eventType}
                    loading={loading}
                    error={error}
                    empty="No notification preferences found"
                    columns={columns}
                    selectable
                    bulkActions={bulkActions}
                    exportFileName="notification-preferences"
                    renderDrawer={renderDrawer}
                    drawerTitle={(p) => p.eventType}
                />
            </div>

            {/* Alert Configuration (read-only summary) */}
            <div className="bg-raised border border-line rounded-lg overflow-hidden">
                <div className="px-4 py-3 border-b border-line">
                    <h3 className="text-sm font-semibold text-ink">Security Alert Configuration</h3>
                    <p className="text-xs text-ink-muted mt-1">Real-time security alerts for high-risk operations. Configured in system config.</p>
                </div>
                {alertConfigLoading && <div className="p-4 text-ink-muted text-sm text-center">Loading...</div>}
                {!alertConfigLoading && alertConfig && (
                    <div className="p-4 space-y-3">
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                            <div>
                                <label className={labelClass}>Alerting Enabled</label>
                                <div className="flex items-center gap-2">
                                    <StatusBadge status={alertConfig.enabled ? 'enabled' : 'disabled'} />
                                    <span className="text-sm text-ink">{alertConfig.enabled ? 'Active' : 'Disabled'}</span>
                                </div>
                            </div>
                            <div>
                                <label className={labelClass}>Minimum Severity</label>
                                <span className={`px-2 py-0.5 text-xs rounded border ${alertConfig.minimumSeverity === 'Critical' ? 'bg-crit-soft text-crit border-crit/40' : alertConfig.minimumSeverity === 'Warning' ? 'bg-warn-soft text-warn border-warn/40' : 'bg-info-soft text-info border-info/40'}`}>{alertConfig.minimumSeverity}</span>
                            </div>
                            <div>
                                <label className={labelClass}>Cooldown Period</label>
                                <span className="text-sm text-ink">{alertConfig.cooldownMinutes} minutes</span>
                            </div>
                        </div>
                        <p className="text-xs text-ink-muted mt-2">Alert settings are managed through the system configuration (Settings page).</p>
                    </div>
                )}
                {!alertConfigLoading && !alertConfig && (
                    <div className="p-4 text-sm text-ink-muted text-center">
                        {isSystemAdmin ? 'Alert configuration not available.' : 'Alert settings are visible to system administrators.'}
                    </div>
                )}
            </div>

            {/* Email Configuration (read-only summary) */}
            {emailConfig && (
                <div className="bg-raised border border-line rounded-lg overflow-hidden">
                    <div className="px-4 py-3 border-b border-line">
                        <h3 className="text-sm font-semibold text-ink">Email Configuration</h3>
                        <p className="text-xs text-ink-muted mt-1">SMTP configuration used for sending notification emails.</p>
                    </div>
                    <div className="p-4 grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div><label className={labelClass}>Email Sending</label><StatusBadge status={emailConfig.enabled ? 'enabled' : 'disabled'} /></div>
                        <div><label className={labelClass}>SMTP Host</label><span className="text-sm text-ink">{emailConfig.smtpHost ?? '-'}</span></div>
                        <div><label className={labelClass}>SMTP Port</label><span className="text-sm text-ink">{emailConfig.smtpPort ?? '-'}</span></div>
                        <div><label className={labelClass}>TLS</label><StatusBadge status={emailConfig.useTls ? 'enabled' : 'disabled'} /></div>
                        <div><label className={labelClass}>From Address</label><span className="text-sm text-ink">{emailConfig.fromAddress ?? '-'}</span></div>
                        <div><label className={labelClass}>Admin Recipients</label><span className="text-sm text-ink">{emailConfig.adminRecipients ?? '-'}</span></div>
                    </div>
                </div>
            )}

            {/* Single-row Edit modal */}
            {editTarget && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-scrim p-4" onClick={() => setEditTarget(null)}>
                    <div className="bg-raised border border-line rounded-xl shadow-2xl w-full max-w-lg" onClick={(e) => e.stopPropagation()}>
                        <div className="px-6 py-4 border-b border-line flex items-center justify-between">
                            <h3 className="text-lg font-bold text-ink">Edit Notification</h3>
                            <button onClick={() => setEditTarget(null)} className="text-ink-muted hover:text-ink text-xl leading-none">×</button>
                        </div>
                        <div className="p-6 space-y-4">
                            <div className="text-sm font-medium text-ink">{editTarget.eventType}</div>
                            <label className="flex items-center gap-2 text-sm text-ink">
                                <input type="checkbox" checked={editForm.enabled} onChange={(e) => setEditForm({ ...editForm, enabled: e.target.checked })} className="h-4 w-4 rounded border-line-strong text-accent-ink focus:ring-accent" />
                                Enabled
                            </label>
                            {editForm.hasDays && (
                                <div>
                                    <label className={labelClass}>Days Before Expiry</label>
                                    <div className="flex items-center gap-2">
                                        <input type="text" inputMode="numeric" value={editForm.daysBeforeExpiry}
                                            onChange={(e) => setEditForm({ ...editForm, daysBeforeExpiry: e.target.value.replace(/\D/g, '') })}
                                            className="w-24 bg-raised border border-line-strong text-ink rounded px-2 py-1 text-sm" />
                                        <div className="flex gap-1">
                                            {[90, 60, 30, 14, 7, 1].map((d) => (
                                                <button key={d} onClick={() => setEditForm({ ...editForm, daysBeforeExpiry: String(d) })}
                                                    className={`px-2 py-0.5 rounded text-xs border ${editForm.daysBeforeExpiry === String(d) ? 'bg-accent border-accent text-on-accent' : 'bg-raised border-line-strong text-ink-muted hover:border-ink-faint'}`}>{d}d</button>
                                            ))}
                                        </div>
                                    </div>
                                </div>
                            )}
                            <div>
                                <label htmlFor="notif-override-recipients" className={labelClass}>Override Recipients</label>
                                <ChipListInput id="notif-override-recipients" value={editForm.recipients} onChange={(next) => { setEditForm({ ...editForm, recipients: next }); setEditEmailError(null); }}
                                    validate={validateEmail} caseInsensitive placeholder="Leave empty to use admin defaults" />
                                {recipientsInvalid && <p className="mt-1 text-xs text-warn">Fix the addresses marked invalid before saving.</p>}
                                {editEmailError && <InlineNotice notice={editEmailError} variant="line" className="mt-1" />}
                            </div>
                        </div>
                        <div className="px-6 py-4 border-t border-line flex justify-end gap-3">
                            <button onClick={() => setEditTarget(null)} disabled={saving} className="px-4 py-2 text-sm bg-sunken text-ink rounded hover:bg-hover">Cancel</button>
                            <button onClick={saveEdit} disabled={saving || recipientsInvalid} className="px-4 py-2 text-sm font-semibold bg-accent text-on-accent rounded hover:bg-accent-hover disabled:opacity-50">{saving ? 'Saving...' : 'Save'}</button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default NotificationManagement;
