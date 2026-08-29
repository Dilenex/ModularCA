import React, { useEffect, useState, useMemo } from 'react';
import { apiGet, apiPut, apiPost } from '../api/client';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import { DataTable, DataTableColumn, DataTableBulkAction } from '@shared/components/DataTable';
import { inputClass as inputCls, labelClass } from '@shared/components/forms';

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const validateEmails = (value: string): string | null => {
    if (!value.trim()) return null;
    const emails = value.split(',').map(e => e.trim()).filter(Boolean);
    const invalid = emails.filter(e => !EMAIL_REGEX.test(e));
    return invalid.length > 0 ? `Invalid email${invalid.length > 1 ? 's' : ''}: ${invalid.join(', ')}` : null;
};

interface AlertConfig { enabled: boolean; minimumSeverity: string; cooldownMinutes: number; }

const NotificationManagement: React.FC = () => {
    const [prefs, setPrefs] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [testStatus, setTestStatus] = useState<string | null>(null);

    const [alertConfig, setAlertConfig] = useState<AlertConfig | null>(null);
    const [alertConfigLoading, setAlertConfigLoading] = useState(true);
    const [emailConfig, setEmailConfig] = useState<any | null>(null);

    // Single-row edit modal
    const [editTarget, setEditTarget] = useState<any | null>(null);
    const [editForm, setEditForm] = useState<{ recipients: string; daysBeforeExpiry: string; enabled: boolean; hasDays: boolean }>({ recipients: '', daysBeforeExpiry: '', enabled: true, hasDays: false });
    const [editEmailError, setEditEmailError] = useState<string | null>(null);
    const [saving, setSaving] = useState(false);

    const loadPrefs = async () => {
        setLoading(true);
        setError(null);
        try {
            const data = await apiGet<any[]>('/api/v1/admin/notifications');
            setPrefs(Array.isArray(data) ? data : ((data as any).items || []));
        } catch (err: any) {
            setError(err.message || 'Failed to load notification preferences');
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
            const config = await apiGet<any>('/api/v1/admin/config');
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

    useEffect(() => { loadPrefs(); loadConfig(); }, []);

    const bulkSetEnabled = async (rows: any[], enabled: boolean) => {
        const targets = rows.filter((p) => p.enabled !== enabled);
        if (targets.length === 0) { setTestStatus(`All selected are already ${enabled ? 'enabled' : 'disabled'}.`); setTimeout(() => setTestStatus(null), 3000); return; }
        for (const p of targets) {
            try { await apiPut(`/api/v1/admin/notifications/${p.eventType}`, { enabled }); } catch { }
        }
        loadPrefs();
    };

    const openEdit = (p: any) => {
        const hasDays = p.daysBeforeExpiry !== undefined && p.daysBeforeExpiry !== null;
        setEditForm({ recipients: p.recipients ?? '', daysBeforeExpiry: hasDays ? String(p.daysBeforeExpiry) : '', enabled: !!p.enabled, hasDays });
        setEditEmailError(null);
        setEditTarget(p);
    };

    const saveEdit = async () => {
        if (!editTarget) return;
        const emailErr = validateEmails(editForm.recipients);
        if (emailErr) { setEditEmailError(emailErr); return; }
        setSaving(true);
        try {
            const body: any = { enabled: editForm.enabled, recipients: editForm.recipients };
            if (editForm.hasDays && editForm.daysBeforeExpiry) body.daysBeforeExpiry = parseInt(editForm.daysBeforeExpiry, 10);
            await apiPut(`/api/v1/admin/notifications/${editTarget.eventType}`, body);
            setEditTarget(null);
            loadPrefs();
        } catch (err: any) {
            setEditEmailError(err.message || 'Failed to save');
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
                    <div className="text-gray-900 dark:text-white font-medium truncate">{p.eventType}</div>
                    {p.description && <div className="text-xs text-gray-600 truncate">{p.description}</div>}
                </div>
            ) },
        { key: 'days', header: 'Expiry Warning', defaultWidth: 130, align: 'right', exportValue: (p) => (p.daysBeforeExpiry ?? ''),
            render: (p) => (p.daysBeforeExpiry ? `${p.daysBeforeExpiry}d` : '-') },
        { key: 'recipients', header: 'Recipients', defaultWidth: 220, exportValue: (p) => p.recipients || '',
            render: (p) => p.recipients || <span className="text-gray-500">(admin default)</span> },
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
            <p className="text-[11px] text-gray-500 pt-2">Select the row in the table to edit, enable, or disable.</p>
        </div>
    );


    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <div className="flex items-center justify-between">
                <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Email Notifications</h1>
                <button onClick={sendTestEmail} className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 text-sm">Send Test Email</button>
            </div>

            {testStatus && (
                <div className={`p-3 rounded text-sm border ${testStatus.includes('success') ? 'bg-green-50 dark:bg-green-900/30 border-green-300 dark:border-green-700 text-green-800 dark:text-green-300' : testStatus === 'Sending...' ? 'bg-blue-50 dark:bg-blue-900/30 border-blue-300 dark:border-blue-700 text-blue-800 dark:text-blue-300' : 'bg-red-50 dark:bg-red-900/30 border-red-300 dark:border-red-700 text-red-800 dark:text-red-300'}`}>
                    {testStatus}
                </div>
            )}

            <div>
                <p className="text-xs text-gray-600 dark:text-gray-400 mb-2">Configure which events send email notifications and to whom. Select rows to enable, disable, or edit.</p>
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
            <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg overflow-hidden">
                <div className="px-4 py-3 border-b border-gray-300 dark:border-gray-700">
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Security Alert Configuration</h3>
                    <p className="text-xs text-gray-600 mt-1">Real-time security alerts for high-risk operations. Configured in system config.</p>
                </div>
                {alertConfigLoading && <div className="p-4 text-gray-600 dark:text-gray-400 text-sm text-center">Loading...</div>}
                {!alertConfigLoading && alertConfig && (
                    <div className="p-4 space-y-3">
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                            <div>
                                <label className={labelClass}>Alerting Enabled</label>
                                <div className="flex items-center gap-2">
                                    <StatusBadge status={alertConfig.enabled ? 'enabled' : 'disabled'} />
                                    <span className="text-sm text-gray-900 dark:text-white">{alertConfig.enabled ? 'Active' : 'Disabled'}</span>
                                </div>
                            </div>
                            <div>
                                <label className={labelClass}>Minimum Severity</label>
                                <span className={`px-2 py-0.5 text-xs rounded border ${alertConfig.minimumSeverity === 'Critical' ? 'bg-red-50 dark:bg-red-900/40 text-red-800 dark:text-red-300 border-red-300 dark:border-red-700' : alertConfig.minimumSeverity === 'Warning' ? 'bg-yellow-50 dark:bg-yellow-900/40 text-yellow-800 dark:text-yellow-300 border-yellow-300 dark:border-yellow-700' : 'bg-blue-50 dark:bg-blue-900/40 text-blue-800 dark:text-blue-300 border-blue-300 dark:border-blue-700'}`}>{alertConfig.minimumSeverity}</span>
                            </div>
                            <div>
                                <label className={labelClass}>Cooldown Period</label>
                                <span className="text-sm text-gray-900 dark:text-white">{alertConfig.cooldownMinutes} minutes</span>
                            </div>
                        </div>
                        <p className="text-xs text-gray-600 mt-2">Alert settings are managed through the system configuration (Settings page).</p>
                    </div>
                )}
                {!alertConfigLoading && !alertConfig && <div className="p-4 text-sm text-gray-600 text-center">Alert configuration not available.</div>}
            </div>

            {/* Email Configuration (read-only summary) */}
            {emailConfig && (
                <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg overflow-hidden">
                    <div className="px-4 py-3 border-b border-gray-300 dark:border-gray-700">
                        <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Email Configuration</h3>
                        <p className="text-xs text-gray-600 mt-1">SMTP configuration used for sending notification emails.</p>
                    </div>
                    <div className="p-4 grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div><label className={labelClass}>Email Sending</label><StatusBadge status={emailConfig.enabled ? 'enabled' : 'disabled'} /></div>
                        <div><label className={labelClass}>SMTP Host</label><span className="text-sm text-gray-900 dark:text-white">{emailConfig.smtpHost ?? '-'}</span></div>
                        <div><label className={labelClass}>SMTP Port</label><span className="text-sm text-gray-900 dark:text-white">{emailConfig.smtpPort ?? '-'}</span></div>
                        <div><label className={labelClass}>TLS</label><StatusBadge status={emailConfig.useTls ? 'enabled' : 'disabled'} /></div>
                        <div><label className={labelClass}>From Address</label><span className="text-sm text-gray-900 dark:text-white">{emailConfig.fromAddress ?? '-'}</span></div>
                        <div><label className={labelClass}>Admin Recipients</label><span className="text-sm text-gray-900 dark:text-white">{emailConfig.adminRecipients ?? '-'}</span></div>
                    </div>
                </div>
            )}

            {/* Single-row Edit modal */}
            {editTarget && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" onClick={() => setEditTarget(null)}>
                    <div className="bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-xl shadow-2xl w-full max-w-lg" onClick={(e) => e.stopPropagation()}>
                        <div className="px-6 py-4 border-b border-gray-300 dark:border-gray-700 flex items-center justify-between">
                            <h3 className="text-lg font-bold text-gray-900 dark:text-white">Edit Notification</h3>
                            <button onClick={() => setEditTarget(null)} className="text-gray-500 hover:text-gray-900 dark:hover:text-white text-xl leading-none">×</button>
                        </div>
                        <div className="p-6 space-y-4">
                            <div className="text-sm font-medium text-gray-900 dark:text-white">{editTarget.eventType}</div>
                            <label className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
                                <input type="checkbox" checked={editForm.enabled} onChange={(e) => setEditForm({ ...editForm, enabled: e.target.checked })} className="h-4 w-4 rounded border-gray-300 dark:border-gray-700 text-blue-600 focus:ring-blue-500" />
                                Enabled
                            </label>
                            {editForm.hasDays && (
                                <div>
                                    <label className={labelClass}>Days Before Expiry</label>
                                    <div className="flex items-center gap-2">
                                        <input type="text" inputMode="numeric" value={editForm.daysBeforeExpiry}
                                            onChange={(e) => setEditForm({ ...editForm, daysBeforeExpiry: e.target.value.replace(/\D/g, '') })}
                                            className="w-24 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 text-gray-900 dark:text-white rounded px-2 py-1 text-sm" />
                                        <div className="flex gap-1">
                                            {[90, 60, 30, 14, 7, 1].map((d) => (
                                                <button key={d} onClick={() => setEditForm({ ...editForm, daysBeforeExpiry: String(d) })}
                                                    className={`px-2 py-0.5 rounded text-xs border ${editForm.daysBeforeExpiry === String(d) ? 'bg-blue-600 border-blue-500 text-white' : 'bg-gray-100 dark:bg-gray-800 border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-400 hover:border-gray-500'}`}>{d}d</button>
                                            ))}
                                        </div>
                                    </div>
                                </div>
                            )}
                            <div>
                                <label className={labelClass}>Override Recipients (comma-separated emails)</label>
                                <input type="text" value={editForm.recipients} onChange={(e) => { setEditForm({ ...editForm, recipients: e.target.value }); setEditEmailError(validateEmails(e.target.value)); }}
                                    placeholder="Leave empty to use admin defaults" autoComplete="off" data-1p-ignore data-lpignore="true" data-bwignore
                                    className={`${inputCls} ${editEmailError ? 'border-red-500' : ''}`} />
                                {editEmailError && <p className="text-xs text-red-800 dark:text-red-400 mt-1">{editEmailError}</p>}
                            </div>
                        </div>
                        <div className="px-6 py-4 border-t border-gray-300 dark:border-gray-700 flex justify-end gap-3">
                            <button onClick={() => setEditTarget(null)} disabled={saving} className="px-4 py-2 text-sm bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600">Cancel</button>
                            <button onClick={saveEdit} disabled={saving || !!editEmailError} className="px-4 py-2 text-sm font-semibold bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50">{saving ? 'Saving...' : 'Save'}</button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default NotificationManagement;
