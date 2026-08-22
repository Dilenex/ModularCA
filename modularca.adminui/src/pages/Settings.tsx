import React, { useState, useEffect } from 'react';
import Chevron from '../components/Chevron';
import { Link } from 'react-router-dom';
import { apiGet, apiPost, apiPut, apiPutWithMfa, apiPostWithMfa } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '../context/ToastContext';
import StatusBadge from '../components/cards/StatusBadge';
import DetailField from '../components/cards/DetailField';

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

const TABS = ['General', 'Security', 'Certificates', 'Integrations', 'Logging', 'Features'] as const;
type Tab = typeof TABS[number];

/* --- Shared Form Helpers --- */
const inputClass = 'w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500';
const labelClass = 'block text-xs text-gray-600 dark:text-gray-400 mb-1';
const cardClass = 'bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg overflow-hidden';

const ConfigInput: React.FC<{ label: string; value: any; onChange: (v: string) => void; type?: string; placeholder?: string }> = ({ label, value, onChange, type = 'text', placeholder }) => (
    <div>
        <label className={labelClass}>{label}</label>
        <input type={type} value={value ?? ''} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} className={inputClass} />
    </div>
);

const ConfigTextarea: React.FC<{ label: string; value: any; onChange: (v: string) => void; placeholder?: string; rows?: number; hint?: string }> = ({ label, value, onChange, placeholder, rows = 6, hint }) => (
    <div>
        <label className={labelClass}>{label}</label>
        <textarea
            value={value ?? ''}
            onChange={(e) => onChange(e.target.value)}
            placeholder={placeholder}
            rows={rows}
            className={`${inputClass} font-mono text-xs resize-y`}
        />
        {hint && <p className="text-[10px] text-gray-600 mt-1">{hint}</p>}
    </div>
);

const ConfigNumber: React.FC<{ label: string; value: any; onChange: (v: number | string) => void; fallback?: number }> = ({ label, value, onChange, fallback = 0 }) => (
    <div>
        <label className={labelClass}>{label}</label>
        <input type="text" inputMode="numeric" value={value ?? ''} onChange={(e) => { const v = e.target.value.replace(/\D/g, ''); onChange(v === '' ? '' : parseInt(v)); }} onBlur={() => { if (!value && value !== 0) onChange(fallback); }} className={inputClass} />
    </div>
);

const ConfigToggle: React.FC<{ label: string; checked: boolean; onChange: (v: boolean) => void }> = ({ label, checked, onChange }) => (
    <div className="flex items-center justify-between">
        <label className="text-xs text-gray-600 dark:text-gray-400">{label}</label>
        <button onClick={() => onChange(!checked)} className={`relative w-11 h-6 rounded-full transition-colors ${checked ? 'bg-blue-600' : 'bg-gray-600'}`}>
            <span className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full shadow transition-transform ${checked ? 'translate-x-5' : 'translate-x-0'}`} />
        </button>
    </div>
);

const ConfigSelect: React.FC<{ label: string; value: string; options: string[]; onChange: (v: string) => void }> = ({ label, value, options, onChange }) => (
    <div>
        <label className={labelClass}>{label}</label>
        <select value={value} onChange={(e) => onChange(e.target.value)} className={inputClass}>
            {options.map((o) => <option key={o} value={o}>{o}</option>)}
        </select>
    </div>
);

const SaveButton: React.FC<{ saving: boolean; onClick: () => void; label?: string }> = ({ saving, onClick, label }) => (
    <button onClick={onClick} disabled={saving} className="px-4 py-2 text-sm bg-blue-600 text-gray-900 dark:text-white rounded hover:bg-blue-700 disabled:opacity-50 transition-colors">
        {saving ? 'Saving...' : (label || 'Save')}
    </button>
);

/* Note shown on cards whose cron schedule is owned by the Schedules page. The card's
   Save deliberately sends an empty `schedule`, which the backend patch-guards
   (`if (!IsNullOrEmpty) ...`) so a stale Settings tab can't clobber a cron edited there. */
const ScheduleMovedNote = () => (
    <p className="text-[11px] text-gray-500 dark:text-gray-500">
        The run schedule (cron) is managed on the <Link to="/schedules" className="underline hover:text-gray-700 dark:hover:text-gray-300">Schedules</Link> page.
    </p>
);

const LiveTag = () => <span className="px-1.5 py-0.5 text-[10px] font-semibold rounded bg-green-50 dark:bg-green-900/50 text-green-800 dark:text-green-400 border border-green-300 dark:border-green-800">Live</span>;
const RestartTag = () => <span className="px-1.5 py-0.5 text-[10px] font-semibold rounded bg-amber-50 dark:bg-amber-900/50 text-amber-800 dark:text-amber-400 border border-amber-300 dark:border-amber-700">Restart</span>;

const ReadOnlyTag = () => <span className="px-1.5 py-0.5 text-[10px] font-semibold rounded bg-gray-700/50 text-gray-600 border border-gray-600">Read-only</span>;

const SectionHeader: React.FC<{ title: string; expanded: boolean; onToggle: () => void; description?: string; tag?: 'live' | 'restart' | 'read-only' }> = ({ title, expanded, onToggle, description, tag }) => (
    <button onClick={onToggle} className="w-full px-4 py-3 flex items-center gap-2 text-left hover:bg-gray-200/50 dark:bg-gray-700/50 transition-colors">
        <span className="text-gray-600 text-xs"><Chevron open={expanded} className="w-3 h-3" /></span>
        <span className="text-sm font-semibold text-gray-900 dark:text-white">{title}</span>
        {description && <span className="text-xs text-gray-600 ml-2">{description}</span>}
        <span className="ml-auto">{tag === 'live' ? <LiveTag /> : tag === 'restart' ? <RestartTag /> : tag === 'read-only' ? <ReadOnlyTag /> : null}</span>
    </button>
);

/** Convert a backend List<string> to a comma-separated display string */
const listToStr = (value: any): string => (Array.isArray(value) ? value.join(', ') : (value ?? ''));
/** Convert a comma-separated display string to a string array for the backend */
const strToList = (value: string): string[] => value.split(',').map((s: string) => s.trim()).filter(Boolean);

/* --- Webhook Test Card --- */
const WebhookTestCard: React.FC = () => {
    const [sending, setSending] = useState(false);
    const [result, setResult] = useState<{ success: boolean; message: string } | null>(null);

    const handleTestWebhook = async () => {
        setSending(true);
        setResult(null);
        try {
            const data = await apiPost<any>('/api/v1/admin/notifications/test-webhook', {});
            setResult({ success: true, message: data.message || `Test webhook sent to ${data.endpointCount} endpoint(s)` });
        } catch (err: any) {
            setResult({ success: false, message: err.message || 'Failed to send test webhook' });
        } finally {
            setSending(false);
        }
    };

    return (
        <div className={cardClass}>
            <div className="p-4">
                <div className="flex items-center justify-between">
                    <div>
                        <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Webhook Test</h3>
                        <p className="text-xs text-gray-600 mt-1">
                            Send a test event to all configured webhook endpoints to verify connectivity.
                        </p>
                    </div>
                    <button
                        onClick={handleTestWebhook}
                        disabled={sending}
                        className="px-4 py-2 text-sm bg-purple-600 text-gray-900 dark:text-white rounded hover:bg-purple-700 disabled:opacity-50 transition-colors flex-shrink-0"
                    >
                        {sending ? 'Sending...' : 'Send Test Webhook'}
                    </button>
                </div>
                {result && (
                    <div className={`mt-3 p-2 rounded text-xs ${result.success ? 'bg-green-50 dark:bg-green-900/20 border border-green-300 dark:border-green-800 text-green-800 dark:text-green-300' : 'bg-red-50 dark:bg-red-900/20 border border-red-300 dark:border-red-800 text-red-800 dark:text-red-300'}`}>
                        {result.message}
                    </div>
                )}
            </div>
        </div>
    );
};

/* --- Config Tab (accepts tab prop to determine which sections to show) --- */
const ConfigTab: React.FC<{ tab: Tab }> = ({ tab }) => {
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();
    const [config, setConfig] = useState<any>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [expanded, setExpanded] = useState<string | null>(null);
    const [saving, setSaving] = useState<string | null>(null);
    const [successMsg, setSuccessMsg] = useState<string | null>(null);
    const [restarting, setRestarting] = useState(false);

    /* Password Policy state (inlined into Security tab) */
    const [policy, setPolicy] = useState<any>(null);
    const [policyLoading, setPolicyLoading] = useState(false);
    const [policyError, setPolicyError] = useState<string | null>(null);
    const [policySaving, setPolicySaving] = useState(false);

    /* Security Policy (DB) state — runtime-tunable session/lockout/MFA/OCSP knobs.
       Loaded from /admin/security-policy; saved with step-up MFA. Distinct from the
       yaml-backed middleware Security section which uses saveSection('security', ...). */
    const [securityPolicy, setSecurityPolicy] = useState<any>(null);
    const [securityPolicyLoading, setSecurityPolicyLoading] = useState(false);
    const [securityPolicyError, setSecurityPolicyError] = useState<string | null>(null);
    const [securityPolicySaving, setSecurityPolicySaving] = useState(false);

    const load = () => {
        setLoading(true);
        apiGet<any>('/api/v1/admin/config')
            .then(setConfig)
            .catch((err) => setError(err.message))
            .finally(() => setLoading(false));
    };

    const loadPolicy = () => {
        setPolicyLoading(true);
        apiGet<any>('/api/v1/admin/password-policy')
            .then(setPolicy)
            .catch((err) => setPolicyError(err.message))
            .finally(() => setPolicyLoading(false));
    };

    const loadSecurityPolicy = () => {
        setSecurityPolicyLoading(true);
        setSecurityPolicyError(null);
        apiGet<any>('/api/v1/admin/security-policy')
            .then(setSecurityPolicy)
            .catch((err) => setSecurityPolicyError(err.message))
            .finally(() => setSecurityPolicyLoading(false));
    };

    /* Protocol Rate Limits (DB) — multi-row */
    const [rateLimits, setRateLimits] = useState<any[]>([]);
    const [rateLimitsLoading, setRateLimitsLoading] = useState(false);
    const [rateLimitsError, setRateLimitsError] = useState<string | null>(null);
    const [rateLimitsSaving, setRateLimitsSaving] = useState(false);
    const loadRateLimits = () => {
        setRateLimitsLoading(true);
        setRateLimitsError(null);
        apiGet<any[]>('/api/v1/admin/rate-limit-policy')
            .then((data) => setRateLimits(Array.isArray(data) ? data : []))
            .catch((err) => setRateLimitsError(err.message))
            .finally(() => setRateLimitsLoading(false));
    };

    useEffect(() => {
        load();
        if (tab === 'Security') {
            loadPolicy();
            loadSecurityPolicy();
            loadRateLimits();
        }
    }, [tab]);

    const saveSection = async (endpoint: string, data: any, sectionKey: string) => {
        setSaving(sectionKey);
        setSuccessMsg(null);
        try {
            const result = await apiPutWithMfa(`/api/v1/admin/config/${endpoint}`, data, requireStepUp, `update-config`);
            setSuccessMsg(result.message || 'Saved');
            load();
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to save');
        } finally {
            setSaving(null);
        }
    };

    const toggle = (key: string) => setExpanded(expanded === key ? null : key);
    const update = (section: string, field: string, value: any) => {
        setConfig({ ...config, [section]: { ...config[section], [field]: value } });
    };

    if (loading) return <div className="p-4 text-sm text-gray-600 dark:text-gray-400">Loading...</div>;
    if (error) return <div className="p-4 text-sm text-red-800 dark:text-red-400">{error}</div>;
    if (!config) return null;

    /* --- Password Policy helpers --- */
    const handleSavePolicy = async () => {
        setPolicySaving(true);
        try {
            await apiPut('/api/v1/admin/password-policy', policy);
            showToast('success', 'Password policy updated');
        } catch (err: any) {
            showToast('error', err.message || 'Failed to save policy');
        } finally {
            setPolicySaving(false);
        }
    };
    const updatePolicyField = (key: string, value: any) => setPolicy({ ...policy, [key]: value });

    /* --- Security Policy (DB) helpers --- */
    const handleSaveSecurityPolicy = async () => {
        setSecurityPolicySaving(true);
        try {
            await apiPutWithMfa('/api/v1/admin/security-policy', securityPolicy, requireStepUp, 'update-config');
            showToast('success', 'Security policy updated');
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to save security policy');
        } finally {
            setSecurityPolicySaving(false);
        }
    };
    const updateSecurityPolicyField = (key: string, value: any) => setSecurityPolicy({ ...securityPolicy, [key]: value });

    /* --- Rate Limits helpers --- */
    const updateRateLimitField = (protocol: string, key: 'maxRequests' | 'windowMinutes', value: any) => {
        setRateLimits(rateLimits.map((r) => r.protocol === protocol ? { ...r, [key]: value } : r));
    };
    const handleSaveRateLimits = async () => {
        setRateLimitsSaving(true);
        try {
            const payload: Record<string, { maxRequests: number; windowMinutes: number }> = {};
            for (const row of rateLimits) {
                payload[row.protocol] = { maxRequests: row.maxRequests, windowMinutes: row.windowMinutes };
            }
            await apiPutWithMfa('/api/v1/admin/rate-limit-policy', payload, requireStepUp, 'update-config');
            showToast('success', 'Rate limit policy updated');
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to save rate limits');
        } finally {
            setRateLimitsSaving(false);
        }
    };
    const policyNumberFields = ['minLength', 'maxLength', 'minUppercase', 'minLowercase', 'minDigits', 'minSpecial', 'maxAgeDays', 'historyCount'];
    const policyBoolFields = ['requireUppercase', 'requireLowercase', 'requireDigit', 'requireSymbol'];

    return (
        <div className="space-y-2">
            {successMsg && (
                <div className="bg-green-50 dark:bg-green-900/20 border border-green-300 dark:border-green-800 rounded-lg p-3 text-xs text-green-800 dark:text-green-300">{successMsg}</div>
            )}

            {/* ================================================================ */}
            {/* GENERAL TAB                                                      */}
            {/* ================================================================ */}
            {tab === 'General' && (
                <>
                    {/* Public Domain */}
                    <div className={cardClass}>
                        <SectionHeader title="Public Domain" expanded={expanded === 'baseurl'} onToggle={() => toggle('baseurl')}
                            description={config.https?.publicDomain || 'Not configured \u2014 using request origin'} tag="restart" />
                        {expanded === 'baseurl' && (
                            <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-4">
                                <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-300 dark:border-blue-800 rounded p-3 text-xs text-blue-800 dark:text-blue-300">
                                    The public hostname used for management-UI HTTPS redirects and ACME URL binding.
                                    Must be a bare hostname or IP — no scheme, no port. Per-CA AIA/CDP base URLs are configured
                                    separately in CA Management.
                                </div>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigInput label="Public Domain" value={config.https?.publicDomain} onChange={(v) => update('https', 'publicDomain', v)} placeholder="ca.example.com" />
                                    <ConfigNumber label="Public Port (443 = omitted from URLs)" value={config.https?.publicPort} onChange={(v) => update('https', 'publicPort', v)} fallback={443} />
                                </div>
                                {config.https?.publicDomain && (
                                    <div className="text-xs text-gray-600 space-y-1">
                                        <div>HTTPS base: <code className="mono text-gray-600 dark:text-gray-400">https://{config.https.publicDomain}{config.https.publicPort && config.https.publicPort !== 443 ? `:${config.https.publicPort}` : ''}</code></div>
                                        <div>ACME directory: <code className="mono text-gray-600 dark:text-gray-400">https://{config.https.publicDomain}{config.https.publicPort && config.https.publicPort !== 443 ? `:${config.https.publicPort}` : ''}/acme/{'<label>'}/directory</code></div>
                                    </div>
                                )}
                                <SaveButton saving={saving === 'baseurl'} onClick={() => saveSection('https', config.https, 'baseurl')} />
                            </div>
                        )}
                    </div>

                    {/* HTTP */}
                    <div className={cardClass}>
                        <SectionHeader title="HTTP" expanded={expanded === 'http'} onToggle={() => toggle('http')}
                            description={`Port ${config.http?.port || 0}, Swagger ${config.http?.swaggerEnabled ? 'On' : 'Off'}`} tag="restart" />
                        {expanded === 'http' && (
                            <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigNumber label="HTTP Port (0 = disabled)" value={config.http.port} onChange={(v) => update('http', 'port', v)} />
                                    <ConfigNumber label="Public Port (behind proxy)" value={config.http.publicPort} onChange={(v) => update('http', 'publicPort', v)} fallback={0} />
                                    <ConfigInput label="CORS Origins (comma-separated)" value={config.http.corsOrigins} onChange={(v) => update('http', 'corsOrigins', v)} />
                                    <ConfigToggle label="Enable CORS" checked={config.http.enableCors ?? false} onChange={(v) => update('http', 'enableCors', v)} />
                                    <ConfigToggle label="Swagger Enabled" checked={config.http.swaggerEnabled} onChange={(v) => update('http', 'swaggerEnabled', v)} />
                                </div>
                                <p className="text-[10px] text-gray-600">Trusted Proxy CIDRs moved to the <strong>Reverse Proxy</strong> card (Security tab).</p>
                                <SaveButton saving={saving === 'http'} onClick={() => saveSection('http', config.http, 'http')} />
                            </div>
                        )}
                    </div>

                    {/* HTTPS (read-only) */}
                    <div className={cardClass}>
                        <SectionHeader title="HTTPS" expanded={expanded === 'https'} onToggle={() => toggle('https')}
                            description={`${config.https?.mode} \u2014 Port ${config.https?.port}`} tag="read-only" />
                        {expanded === 'https' && (
                            <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-2">
                                <DetailField label="Mode" value={config.https.mode} />
                                <DetailField label="Listen Address" value={config.https.listenAddress} />
                                <DetailField label="Port" value={String(config.https.port)} />
                                <DetailField label="Renewal Window" value={config.https.renewalWindow} />
                                <div className="text-xs text-gray-600 mt-2">HTTPS settings are managed via bootstrap and require a restart to change.</div>
                            </div>
                        )}
                    </div>

                    {/* Metrics */}
                    <div className={cardClass}>
                        <SectionHeader title="Metrics" expanded={expanded === 'metrics'} onToggle={() => toggle('metrics')}
                            description={config.metrics?.enabled ? `Enabled at ${config.metrics.path}` : 'Disabled'} tag="restart" />
                        {expanded === 'metrics' && (
                            <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigToggle label="Enabled" checked={config.metrics.enabled} onChange={(v) => update('metrics', 'enabled', v)} />
                                    <ConfigInput label="Path" value={config.metrics.path} onChange={(v) => update('metrics', 'path', v)} />
                                </div>
                                <SaveButton saving={saving === 'metrics'} onClick={() => saveSection('metrics', config.metrics, 'metrics')} />
                            </div>
                        )}
                    </div>

                    {/* SSH CA */}
                    <div className={cardClass}>
                        <SectionHeader title="SSH CA" expanded={expanded === 'sshCa'} onToggle={() => toggle('sshCa')}
                            description={`${config.sshCa?.sshKeygenPath || 'ssh-keygen'}`} tag="restart" />
                        {expanded === 'sshCa' && (
                            <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigInput label="ssh-keygen Path" value={config.sshCa.sshKeygenPath} onChange={(v) => update('sshCa', 'sshKeygenPath', v)} />
                                    <ConfigInput label="Key Storage Path" value={config.sshCa.keyStoragePath} onChange={(v) => update('sshCa', 'keyStoragePath', v)} />
                                </div>
                                <SaveButton saving={saving === 'sshCa'} onClick={() => saveSection('ssh-ca', config.sshCa, 'sshCa')} />
                            </div>
                        )}
                    </div>

                    {/* HSM (read-only) */}
                    <div className={cardClass}>
                        <SectionHeader title="HSM" expanded={expanded === 'hsm'} onToggle={() => toggle('hsm')}
                            description={config.hsm?.enabled ? 'Enabled' : 'Disabled'} tag="read-only" />
                        {expanded === 'hsm' && (
                            <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-2">
                                <DetailField label="Enabled" value={config.hsm?.enabled ? 'Yes' : 'No'} />
                                <DetailField label="Module Path" value={config.hsm?.modulePath || 'Not configured'} />
                                <DetailField label="Slot ID" value={config.hsm?.slotId != null ? String(config.hsm.slotId) : 'Not configured'} />
                                <div className="bg-amber-50 dark:bg-amber-900/20 border border-amber-300 dark:border-amber-800 rounded p-3 text-xs text-amber-800 dark:text-amber-300 mt-3">
                                    HSM configuration must be set in config.yaml — cannot be changed at runtime.
                                </div>
                            </div>
                        )}
                    </div>

                    {/* Backup */}
                    <div className={cardClass}>
                        <SectionHeader title="Backup" expanded={expanded === 'backup'} onToggle={() => toggle('backup')}
                            description={`Retain ${config.backup?.retentionCount ?? 0} · ${config.backup?.outputPath || 'default path'}`} tag="restart" />
                        {expanded === 'backup' && (
                            <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigInput label="Output Path" value={config.backup?.outputPath} onChange={(v) => update('backup', 'outputPath', v)} />
                                    <ConfigNumber label="Retention Count" value={config.backup?.retentionCount} onChange={(v) => update('backup', 'retentionCount', v)} />
                                    <ConfigNumber label="Max Backup Age Days" value={config.backup?.maxBackupAgeDays} onChange={(v) => update('backup', 'maxBackupAgeDays', v)} />
                                    <ConfigToggle label="Verify on Schedule" checked={config.backup?.verifyOnSchedule ?? true} onChange={(v) => update('backup', 'verifyOnSchedule', v)} />
                                    <ConfigNumber label="Verify Count" value={config.backup?.verifyCount} onChange={(v) => update('backup', 'verifyCount', v)} />
                                </div>
                                <ScheduleMovedNote />
                                <SaveButton saving={saving === 'backup'} onClick={() => saveSection('backup', { ...config.backup, schedule: '' }, 'backup')} />
                            </div>
                        )}
                    </div>

                    {/* Restart */}
                    <div className="bg-gray-100 dark:bg-gray-800 border border-yellow-300 dark:border-yellow-700/50 rounded-lg p-4">
                        <div className="flex items-center justify-between">
                            <div>
                                <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Restart Application</h3>
                                <p className="text-xs text-gray-600 mt-1">
                                    Apply pending configuration changes that require a restart (logging, HTTP, HTTPS).
                                    The application will shut down and the process manager will restart it.
                                </p>
                            </div>
                            <button
                                onClick={async () => {
                                    if (!window.confirm('Restart the ModularCA server? Active connections will be dropped.')) return;
                                    setRestarting(true);
                                    try {
                                        await apiPostWithMfa('/api/v1/admin/config/restart', {}, requireStepUp, 'restart');
                                        setSuccessMsg('Restart initiated. Reconnecting...');
                                        const poll = setInterval(async () => {
                                            try {
                                                await apiGet('/api/v1/admin/config');
                                                clearInterval(poll);
                                                setRestarting(false);
                                                setSuccessMsg('Server restarted successfully');
                                                load();
                                            } catch { /* still restarting */ }
                                        }, 2000);
                                        setTimeout(() => {
                                            clearInterval(poll);
                                            setRestarting(false);
                                        }, 60000);
                                    } catch (err: any) {
                                        showToast('error', err.message || 'Failed to restart');
                                        setRestarting(false);
                                    }
                                }}
                                disabled={restarting}
                                className="px-4 py-2 text-sm bg-yellow-600 text-gray-900 dark:text-white rounded hover:bg-yellow-700 disabled:opacity-50 transition-colors flex-shrink-0"
                            >
                                {restarting ? 'Restarting...' : 'Restart Server'}
                            </button>
                        </div>
                    </div>
                </>
            )}

            {/* ================================================================ */}
            {/* SECURITY TAB                                                     */}
            {/* ================================================================ */}
            {tab === 'Security' && (
                <>
                    {/* Login Protection — unifies the two anti-password-guessing layers
                        (account lockout in the DB policy + per-username rate limit in the
                        yaml middleware). Each layer saves to its own endpoint. */}
                    <div className={cardClass}>
                        <SectionHeader title="Login Protection" expanded={expanded === 'loginProtection'} onToggle={() => toggle('loginProtection')}
                            description={securityPolicy ? `Lockout ${securityPolicy.lockoutMinutes}m / ${securityPolicy.maxFailedLoginAttempts} tries` : 'Loading...'} />
                        {expanded === 'loginProtection' && (
                            <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-4">
                                <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-300 dark:border-blue-800 rounded p-3 text-xs text-blue-800 dark:text-blue-300">
                                    Two independent layers defend against password guessing. <strong>Account lockout</strong> disables an
                                    account after repeated failures and applies live. The <strong>per-username rate limit</strong> throttles
                                    attempts in the request pipeline and is wired at startup (restart to change). Each has its own Save.
                                </div>

                                {/* Account Lockout — DB SecurityPolicy (live) */}
                                <div className="flex items-center gap-2"><h4 className="text-xs font-semibold text-gray-600 uppercase tracking-wide">Account Lockout</h4><LiveTag /></div>
                                {securityPolicyLoading && <div className="text-sm text-gray-600 dark:text-gray-400">Loading...</div>}
                                {securityPolicyError && <div className="text-sm text-red-800 dark:text-red-400">{securityPolicyError}</div>}
                                {securityPolicy && (
                                    <>
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                            <ConfigNumber label="Max Failed Login Attempts" value={securityPolicy.maxFailedLoginAttempts} onChange={(v) => updateSecurityPolicyField('maxFailedLoginAttempts', v)} />
                                            <ConfigNumber label="Lockout Minutes (0 = permanent)" value={securityPolicy.lockoutMinutes} onChange={(v) => updateSecurityPolicyField('lockoutMinutes', v)} />
                                            <ConfigNumber label="Login Response Delay (ms)" value={securityPolicy.loginResponseDelayMs} onChange={(v) => updateSecurityPolicyField('loginResponseDelayMs', v)} />
                                        </div>
                                        <SaveButton saving={securityPolicySaving} onClick={handleSaveSecurityPolicy} label="Save Lockout" />
                                    </>
                                )}

                                {/* Per-Username Rate Limit — yaml middleware (restart) */}
                                <div className="flex items-center gap-2 pt-2"><h4 className="text-xs font-semibold text-gray-600 uppercase tracking-wide">Per-Username Rate Limit</h4><RestartTag /></div>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigNumber label="Per-Username Failure Limit" value={config.security.maxPerUsernameLoginFailures} onChange={(v) => update('security', 'maxPerUsernameLoginFailures', v)} />
                                    <ConfigNumber label="Per-Username Failure Window (min)" value={config.security.perUsernameLoginFailureWindowMinutes} onChange={(v) => update('security', 'perUsernameLoginFailureWindowMinutes', v)} />
                                </div>
                                <SaveButton saving={saving === 'security'} onClick={() => saveSection('security', config.security, 'security')} label="Save Rate Limit" />
                            </div>
                        )}
                    </div>

                    {/* Token Binding & Lifetime — refresh token lifetime (tokens) + JWT/refresh
                        binding (security middleware), previously split across two cards. */}
                    <div className={cardClass}>
                        <SectionHeader title="Token Binding & Lifetime" expanded={expanded === 'tokenBinding'} onToggle={() => toggle('tokenBinding')}
                            description={`Refresh ${config.tokens?.refreshTokenDays || 7}d — JWT IP binding: ${['Off', 'Exact', 'Subnet24'][config.security?.bindJwtToIp ?? 0]}`} />
                        {expanded === 'tokenBinding' && (
                            <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-4">
                                {/* Refresh Token Lifetime — tokens (live) */}
                                <div className="flex items-center gap-2"><h4 className="text-xs font-semibold text-gray-600 uppercase tracking-wide">Refresh Token Lifetime</h4><LiveTag /></div>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigNumber label="Refresh Token Lifetime (days)" value={config.tokens.refreshTokenDays} onChange={(v) => update('tokens', 'refreshTokenDays', v)} fallback={7} />
                                </div>
                                <SaveButton saving={saving === 'tokens'} onClick={() => saveSection('tokens', config.tokens, 'tokens')} label="Save Lifetime" />

                                {/* JWT & Refresh Binding — yaml middleware (restart) */}
                                <div className="flex items-center gap-2 pt-2"><h4 className="text-xs font-semibold text-gray-600 uppercase tracking-wide">JWT &amp; Refresh Binding</h4><RestartTag /></div>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <div>
                                        <label className="block text-xs text-gray-600 dark:text-gray-400 mb-1">JWT IP Binding</label>
                                        <select value={config.security.bindJwtToIp ?? 0} onChange={(e) => update('security', 'bindJwtToIp', parseInt(e.target.value))} className={inputClass}>
                                            <option value={0}>Off (no IP binding)</option>
                                            <option value={1}>Exact (must match issue-time IP)</option>
                                            <option value={2}>Subnet /24 (tolerant of NAT)</option>
                                        </select>
                                    </div>
                                    <ConfigToggle label="Bind Refresh Token to IP" checked={config.security.bindRefreshTokenToIp ?? true} onChange={(v) => update('security', 'bindRefreshTokenToIp', v)} />
                                    <ConfigToggle label="Bind Refresh Token to Fingerprint" checked={config.security.bindRefreshTokenToFingerprint ?? true} onChange={(v) => update('security', 'bindRefreshTokenToFingerprint', v)} />
                                    <ConfigToggle label="Allow Refresh Token Mismatch (forensic)" checked={config.security.allowRefreshTokenMismatch ?? false} onChange={(v) => update('security', 'allowRefreshTokenMismatch', v)} />
                                </div>
                                <SaveButton saving={saving === 'security'} onClick={() => saveSection('security', config.security, 'security')} label="Save Binding" />
                            </div>
                        )}
                    </div>

                    {/* Reverse Proxy — proxy mode (security) + trusted CIDRs (http), previously
                        split across the Security and HTTP cards. */}
                    <div className={cardClass}>
                        <SectionHeader title="Reverse Proxy" expanded={expanded === 'reverseProxy'} onToggle={() => toggle('reverseProxy')}
                            description={config.security?.behindReverseProxy ? 'Behind proxy' : 'Direct'} tag="restart" />
                        {expanded === 'reverseProxy' && (
                            <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-4">
                                <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-300 dark:border-blue-800 rounded p-3 text-xs text-blue-800 dark:text-blue-300">
                                    Settings for running behind a load balancer or reverse proxy. The proxy mode flag and the trusted
                                    proxy CIDRs live in different config sections, so each has its own Save.
                                </div>
                                <ConfigToggle label="Behind Reverse Proxy" checked={config.security.behindReverseProxy ?? false} onChange={(v) => update('security', 'behindReverseProxy', v)} />
                                <SaveButton saving={saving === 'security'} onClick={() => saveSection('security', config.security, 'security')} label="Save Proxy Mode" />
                                <ConfigInput label="Trusted Proxy CIDRs" value={config.http.trustedProxyCidrs} onChange={(v) => update('http', 'trustedProxyCidrs', v)} placeholder="10.0.0.0/8, 172.16.0.0/12" />
                                <SaveButton saving={saving === 'http'} onClick={() => saveSection('http', config.http, 'http')} label="Save Trusted CIDRs" />
                            </div>
                        )}
                    </div>

                    {/* Security Policy (DB) — runtime-tunable session/MFA/OCSP/approval.
                        Login lockout moved to the Login Protection card above. */}
                    <div className={cardClass}>
                        <SectionHeader title="Security Policy" expanded={expanded === 'securityPolicy'} onToggle={() => toggle('securityPolicy')}
                            description={securityPolicy ? `Session, MFA & OCSP policy` : 'Loading...'} tag="live" />
                        {expanded === 'securityPolicy' && (
                            <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-4">
                                {securityPolicyLoading && <div className="text-sm text-gray-600 dark:text-gray-400">Loading...</div>}
                                {securityPolicyError && <div className="text-sm text-red-800 dark:text-red-400">{securityPolicyError}</div>}
                                {securityPolicy && (
                                    <>
                                        <div className="bg-green-50 dark:bg-green-900/20 border border-green-300 dark:border-green-800 rounded p-3 text-xs text-green-800 dark:text-green-300">
                                            Stored in the DB-backed <code className="bg-gray-900/40 px-1 rounded">SecurityPolicy</code> table.
                                            Changes take effect on the next request scope after save (step-up MFA required).
                                        </div>
                                        <div className="text-[11px] text-gray-500 dark:text-gray-500">Login lockout moved to the <strong>Login Protection</strong> card above.</div>
                                        <h4 className="text-xs font-semibold text-gray-600 uppercase tracking-wide">Session</h4>
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                            <ConfigNumber label="Session Idle Timeout (min, 0 = none)" value={securityPolicy.sessionIdleTimeoutMinutes} onChange={(v) => updateSecurityPolicyField('sessionIdleTimeoutMinutes', v)} />
                                            <ConfigNumber label="Max Concurrent Sessions (0 = unlimited)" value={securityPolicy.maxConcurrentSessions} onChange={(v) => updateSecurityPolicyField('maxConcurrentSessions', v)} />
                                            <ConfigNumber label="Max Session Lifetime (days, 0 = unlimited)" value={securityPolicy.maxSessionLifetimeDays} onChange={(v) => updateSecurityPolicyField('maxSessionLifetimeDays', v)} />
                                        </div>
                                        <h4 className="text-xs font-semibold text-gray-600 uppercase tracking-wide pt-2">Approval &amp; mTLS</h4>
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                            <ConfigToggle label="Allow System Super Self-Approval" checked={securityPolicy.allowSystemSuperSelfApproval ?? false} onChange={(v) => updateSecurityPolicyField('allowSystemSuperSelfApproval', v)} />
                                            <ConfigToggle label="Require mTLS OCSP Check" checked={securityPolicy.requireMtlsOcspCheck ?? false} onChange={(v) => updateSecurityPolicyField('requireMtlsOcspCheck', v)} />
                                        </div>
                                        <h4 className="text-xs font-semibold text-gray-600 uppercase tracking-wide pt-2">MFA / Step-Up</h4>
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                            <ConfigNumber label="Step-Up Token TTL (sec, 30-300)" value={securityPolicy.stepUpTokenTtlSeconds} onChange={(v) => updateSecurityPolicyField('stepUpTokenTtlSeconds', v)} />
                                            <ConfigNumber label="MFA Session TTL (sec, 60-900)" value={securityPolicy.mfaSessionTtlSeconds} onChange={(v) => updateSecurityPolicyField('mfaSessionTtlSeconds', v)} />
                                            <ConfigNumber label="WebAuthn Challenge TTL (sec, 30-600)" value={securityPolicy.webAuthnChallengeTtlSeconds} onChange={(v) => updateSecurityPolicyField('webAuthnChallengeTtlSeconds', v)} />
                                            <ConfigToggle label="Require WebAuthn User Verification" checked={securityPolicy.requireWebAuthnUserVerification ?? true} onChange={(v) => updateSecurityPolicyField('requireWebAuthnUserVerification', v)} />
                                            <ConfigNumber label="Step-Up Failure Threshold" value={securityPolicy.stepUpFailureThreshold} onChange={(v) => updateSecurityPolicyField('stepUpFailureThreshold', v)} />
                                            <ConfigNumber label="Step-Up Failure Window (sec)" value={securityPolicy.stepUpFailureWindowSeconds} onChange={(v) => updateSecurityPolicyField('stepUpFailureWindowSeconds', v)} />
                                        </div>
                                        <h4 className="text-xs font-semibold text-gray-600 uppercase tracking-wide pt-2">OCSP Responder</h4>
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                            <ConfigToggle label="Allow CA Direct Signing" checked={securityPolicy.allowCaDirectSigning ?? false} onChange={(v) => updateSecurityPolicyField('allowCaDirectSigning', v)} />
                                            <ConfigToggle label="Require NoCheck Extension" checked={securityPolicy.requireNoCheckExtension ?? false} onChange={(v) => updateSecurityPolicyField('requireNoCheckExtension', v)} />
                                            <ConfigToggle label="Require Signed OCSP Requests" checked={securityPolicy.requireSignedRequests ?? false} onChange={(v) => updateSecurityPolicyField('requireSignedRequests', v)} />
                                            <ConfigNumber label="Default Good Response TTL (min)" value={securityPolicy.defaultGoodResponseTtlMinutes} onChange={(v) => updateSecurityPolicyField('defaultGoodResponseTtlMinutes', v)} />
                                            <ConfigNumber label="Default Revoked Response TTL (min)" value={securityPolicy.defaultRevokedResponseTtlMinutes} onChange={(v) => updateSecurityPolicyField('defaultRevokedResponseTtlMinutes', v)} />
                                            <ConfigNumber label="Max Single-Requests per OCSPRequest" value={securityPolicy.maxSingleRequestsPerRequest} onChange={(v) => updateSecurityPolicyField('maxSingleRequestsPerRequest', v)} />
                                        </div>
                                        <h4 className="text-xs font-semibold text-gray-600 uppercase tracking-wide pt-2">Controlled-User Ceremonies</h4>
                                        <p className="text-[11px] text-gray-500 dark:text-gray-500">
                                            <strong>User quorum</strong> = approvals required to promote / demote / delete a controlled user (admin / operator / CA-admin)
                                            when initiated by a non-super. Distinct from the <strong>key quorum</strong> (per-tenant CA-ceremony approvals, set in Tenants).
                                            The initiator is always excluded, so the effective minimum is 1 other approver.
                                        </p>
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                            <ConfigNumber label="User Quorum (min 1)" value={securityPolicy.userQuorum} onChange={(v) => updateSecurityPolicyField('userQuorum', v)} fallback={1} />
                                        </div>
                                        <SaveButton saving={securityPolicySaving} onClick={handleSaveSecurityPolicy} label="Save Security Policy" />
                                    </>
                                )}
                            </div>
                        )}
                    </div>

                    {/* Login Banner — stored on the SecurityPolicy row, edited in its own card */}
                    <div className={cardClass}>
                        <SectionHeader title="Login Banner" expanded={expanded === 'loginBanner'} onToggle={() => toggle('loginBanner')}
                            description={securityPolicy?.loginBanner ? 'Configured' : 'Not configured'} tag="live" />
                        {expanded === 'loginBanner' && (
                            <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-4">
                                {securityPolicyLoading && <div className="text-sm text-gray-600 dark:text-gray-400">Loading...</div>}
                                {securityPolicyError && <div className="text-sm text-red-800 dark:text-red-400">{securityPolicyError}</div>}
                                {securityPolicy && (
                                    <>
                                        <div className="bg-amber-50 dark:bg-amber-900/20 border border-amber-300 dark:border-amber-800 rounded p-3 text-xs text-amber-800 dark:text-amber-200">
                                            Users must acknowledge this banner before reaching the login page. Stored on the
                                            <code className="bg-gray-900/40 px-1 rounded mx-1">SecurityPolicy</code>row; step-up MFA required to save.
                                            Leave empty to skip the banner step entirely.
                                        </div>
                                        <ConfigInput
                                            label="Banner Title"
                                            value={securityPolicy.loginBannerTitle}
                                            onChange={(v) => updateSecurityPolicyField('loginBannerTitle', v)}
                                            placeholder="System Use Notification"
                                        />
                                        <ConfigTextarea
                                            label="Banner Body"
                                            value={securityPolicy.loginBanner}
                                            onChange={(v) => updateSecurityPolicyField('loginBanner', v)}
                                            placeholder={"You are accessing a restricted system...\n\nLine breaks are preserved."}
                                            rows={8}
                                            hint="Newlines render verbatim on the acknowledgment page. Leave title blank to use the default 'System Use Notification' heading."
                                        />
                                        <SaveButton saving={securityPolicySaving} onClick={handleSaveSecurityPolicy} label="Save Login Banner" />
                                    </>
                                )}
                            </div>
                        )}
                    </div>

                    {/* Password Policy (inlined) */}
                    <div className={cardClass}>
                        <SectionHeader title="Password Policy" expanded={expanded === 'passwordPolicy'} onToggle={() => toggle('passwordPolicy')}
                            description="Complexity and rotation rules" tag="live" />
                        {expanded === 'passwordPolicy' && (
                            <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-4">
                                {policyLoading && <div className="text-sm text-gray-600 dark:text-gray-400">Loading...</div>}
                                {policyError && <div className="text-sm text-red-800 dark:text-red-400">{policyError}</div>}
                                {policy && (
                                    <>
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                            {Object.entries(policy).filter(([key]) => policyNumberFields.includes(key)).map(([key, value]) => (
                                                <div key={key}>
                                                    <label className="block text-xs text-gray-600 dark:text-gray-400 mb-1">{key}</label>
                                                    <input
                                                        type="text"
                                                        inputMode="numeric"
                                                        value={value != null ? String(value) : ''}
                                                        onChange={(e) => { const v = e.target.value.replace(/\D/g, ''); updatePolicyField(key, v === '' ? '' : parseInt(v)); }}
                                                        onBlur={() => { if (!value && value !== 0) updatePolicyField(key, 0); }}
                                                        className={inputClass}
                                                    />
                                                </div>
                                            ))}
                                            {Object.entries(policy).filter(([key]) => policyBoolFields.includes(key)).map(([key, value]) => (
                                                <div key={key} className="flex items-center gap-2">
                                                    <input
                                                        type="checkbox"
                                                        checked={!!value}
                                                        onChange={(e) => updatePolicyField(key, e.target.checked)}
                                                        className="w-4 h-4 bg-gray-50 dark:bg-gray-900 border-gray-300 dark:border-gray-700 rounded"
                                                    />
                                                    <label className="text-xs text-gray-700 dark:text-gray-300">{key}</label>
                                                </div>
                                            ))}
                                        </div>
                                        <SaveButton saving={policySaving} onClick={handleSavePolicy} label="Save Policy" />
                                    </>
                                )}
                            </div>
                        )}
                    </div>

                    {/* JWT (read-only) */}
                    <div className={cardClass}>
                        <SectionHeader title="JWT" expanded={expanded === 'jwt'} onToggle={() => toggle('jwt')}
                            description={`Expiry: ${config.jwt?.expirationMinutes || 120}m`} tag="read-only" />
                        {expanded === 'jwt' && (
                            <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-2">
                                <DetailField label="Expiration (minutes)" value={String(config.jwt.expirationMinutes)} />
                                <DetailField label="Issuer" value={config.jwt.issuer} />
                                <DetailField label="Audience" value={config.jwt.audience} />
                                <DetailField label="Secret" value="***" />
                                <div className="text-xs text-gray-600 mt-2">JWT settings are managed via config.yaml and require a restart to change.</div>
                            </div>
                        )}
                    </div>

                    {/* mTLS */}
                    <div className={cardClass}>
                        <SectionHeader title="mTLS" expanded={expanded === 'mtls'} onToggle={() => toggle('mtls')}
                            description={config.mtls?.enabled ? (config.mtls.authSubdomain || 'AuthSubdomain not set') : 'Disabled'} tag="restart" />
                        {expanded === 'mtls' && (
                            <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigToggle label="Enabled" checked={config.mtls?.enabled ?? false} onChange={(v) => update('mtls', 'enabled', v)} />
                                    <ConfigInput label="Auth Subdomain" value={config.mtls?.authSubdomain} onChange={(v) => update('mtls', 'authSubdomain', v)} placeholder="mtls.ca.example.com" />
                                    <ConfigInput label="Required Paths (comma-separated)" value={listToStr(config.mtls?.requiredPaths)} onChange={(v) => update('mtls', 'requiredPaths', strToList(v))} />
                                    <div className="md:col-span-2">
                                        <ConfigInput label="Trusted CA Cert Paths (comma-separated file paths)" value={listToStr(config.mtls?.trustedCaCertPaths)} onChange={(v) => update('mtls', 'trustedCaCertPaths', strToList(v))} />
                                    </div>
                                </div>
                                <SaveButton saving={saving === 'mtls'} onClick={() => saveSection('mtls', config.mtls, 'mtls')} />
                            </div>
                        )}
                    </div>

                    {/* IP Whitelist */}
                    <div className={cardClass}>
                        <SectionHeader title="IP Whitelist" expanded={expanded === 'ipwhitelist'} onToggle={() => toggle('ipwhitelist')}
                            description={config.ipWhitelist?.enabled ? 'Enabled \u2014 managed at /admin/whitelists' : 'Disabled (master kill switch)'} tag="live" />
                        {expanded === 'ipwhitelist' && (
                            <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-4">
                                <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-300 dark:border-blue-800 rounded p-3 text-xs text-blue-800 dark:text-blue-300">
                                    CIDR allow-list rules now live in the centralized <code className="mono">Whitelists</code> table and
                                    are managed at <Link to="/whitelists" className="underline hover:text-blue-200">/admin/whitelists</Link>.
                                    This card only exposes the master kill switch and the path-based exempt list — both of which stay in
                                    <code className="mono"> config.yaml</code>.
                                </div>
                                <ConfigToggle label="Enabled (master kill switch)" checked={config.ipWhitelist?.enabled ?? true} onChange={(v) => update('ipWhitelist', 'enabled', v)} />
                                <ConfigInput label="Exempt Paths (comma-separated)" value={(config.ipWhitelist?.exemptPaths || []).join(', ')}
                                    onChange={(v) => update('ipWhitelist', 'exemptPaths', v.split(',').map((s: string) => s.trim()).filter(Boolean))}
                                    placeholder="/api/v1/auth, /api/v1/public/ca" />
                                <div className="text-xs text-gray-600">
                                    When the master switch is off, <code className="mono">IpWhitelistMiddleware</code> short-circuits to pass-through
                                    and no rule lookup happens. When on, the middleware consults the <code className="mono">Whitelists</code> table
                                    per request via the cached <code className="mono">IWhitelistService</code>. Exempt paths always pass through
                                    regardless of the master switch — they're the path-based exclusions that bypass rule evaluation entirely.
                                </div>
                                <SaveButton saving={saving === 'ipwhitelist'} onClick={() => saveSection('ip-whitelist', config.ipWhitelist, 'ipwhitelist')} />
                            </div>
                        )}
                    </div>

                    {/* Rate Limiting (DB) — per-protocol policy rows */}
                    <div className={cardClass}>
                        <SectionHeader title="Rate Limiting" expanded={expanded === 'rateLimiting'} onToggle={() => toggle('rateLimiting')}
                            description={rateLimits.length ? `${rateLimits.length} protocol rows` : 'Defaults (no overrides)'} tag="live" />
                        {expanded === 'rateLimiting' && (
                            <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-4">
                                <div className="bg-green-50 dark:bg-green-900/20 border border-green-300 dark:border-green-800 rounded p-3 text-xs text-green-800 dark:text-green-300">
                                    Per-protocol, per-IP limits stored in the DB-backed
                                    <code className="bg-gray-900/40 px-1 mx-1 rounded">ProtocolRateLimits</code> table.
                                    Protocols without a row fall back to middleware defaults. Step-up MFA required on save.
                                </div>
                                {rateLimitsLoading && <div className="text-sm text-gray-600 dark:text-gray-400">Loading...</div>}
                                {rateLimitsError && <div className="text-sm text-red-800 dark:text-red-400">{rateLimitsError}</div>}
                                {rateLimits.length > 0 && (
                                    <>
                                        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-4">
                                            {rateLimits.map((row) => (
                                                <div key={row.protocol} className="space-y-2">
                                                    <h4 className="text-xs font-semibold text-gray-900 dark:text-white uppercase tracking-wide">{row.protocol}</h4>
                                                    <ConfigNumber label="Max Requests" value={row.maxRequests}
                                                        onChange={(v) => updateRateLimitField(row.protocol, 'maxRequests', v)} fallback={100} />
                                                    <ConfigNumber label="Window Min" value={row.windowMinutes}
                                                        onChange={(v) => updateRateLimitField(row.protocol, 'windowMinutes', v)} fallback={1} />
                                                </div>
                                            ))}
                                        </div>
                                        <SaveButton saving={rateLimitsSaving} onClick={handleSaveRateLimits} label="Save Rate Limits" />
                                    </>
                                )}
                            </div>
                        )}
                    </div>

                    {/* LDAP Auth */}
                    <div className={cardClass}>
                        <SectionHeader title="LDAP Authentication" expanded={expanded === 'ldapAuth'} onToggle={() => toggle('ldapAuth')}
                            description={config.ldapAuth?.enabled ? `${config.ldapAuth.host}:${config.ldapAuth.port}` : 'Disabled'} tag="live" />
                        {expanded === 'ldapAuth' && (
                            <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigToggle label="Enabled" checked={config.ldapAuth.enabled} onChange={(v) => update('ldapAuth', 'enabled', v)} />
                                    <ConfigInput label="Host" value={config.ldapAuth.host} onChange={(v) => update('ldapAuth', 'host', v)} />
                                    <ConfigNumber label="Port" value={config.ldapAuth.port} onChange={(v) => update('ldapAuth', 'port', v)} fallback={389} />
                                    <ConfigToggle label="Use SSL" checked={config.ldapAuth.useSsl} onChange={(v) => update('ldapAuth', 'useSsl', v)} />
                                    <ConfigInput label="Search Base DN" value={config.ldapAuth.searchBaseDn} onChange={(v) => update('ldapAuth', 'searchBaseDn', v)} />
                                    <ConfigInput label="Search Filter" value={config.ldapAuth.searchFilter} onChange={(v) => update('ldapAuth', 'searchFilter', v)} />
                                    <ConfigInput label="Bind DN" value={config.ldapAuth.bindDn} onChange={(v) => update('ldapAuth', 'bindDn', v)} />
                                    {/* The bind password was previously not editable here at all, so it could
                                        only be set in config.yaml. It loads as *** when one is stored; leaving
                                        that placeholder untouched keeps the existing password. */}
                                    <ConfigInput label="Bind Password" value={config.ldapAuth.bindPassword} onChange={(v) => update('ldapAuth', 'bindPassword', v)} type="password" placeholder="Leave unchanged to keep current" />
                                    <ConfigToggle label="Group Sync Enabled" checked={config.ldapAuth.groupSyncEnabled} onChange={(v) => update('ldapAuth', 'groupSyncEnabled', v)} />
                                    <ConfigToggle label="Auto Provision Users" checked={config.ldapAuth.autoProvisionUsers} onChange={(v) => update('ldapAuth', 'autoProvisionUsers', v)} />
                                    <ConfigInput label="Group Search Base DN" value={config.ldapAuth.groupSearchBaseDn} onChange={(v) => update('ldapAuth', 'groupSearchBaseDn', v)} />
                                    <ConfigInput label="Group Search Filter" value={config.ldapAuth.groupSearchFilter} onChange={(v) => update('ldapAuth', 'groupSearchFilter', v)} />
                                    <ConfigInput label="Group Member Attribute" value={config.ldapAuth.groupMemberAttribute} onChange={(v) => update('ldapAuth', 'groupMemberAttribute', v)} />
                                    <div className="md:col-span-2">
                                        <ConfigInput label="Group to Role Mappings (JSON)" value={config.ldapAuth.groupToRoleMappings} onChange={(v) => update('ldapAuth', 'groupToRoleMappings', v)} placeholder='{"CN=Admins,DC=...": "CaAdmin"}' />
                                    </div>
                                </div>
                                <SaveButton saving={saving === 'ldapAuth'} onClick={() => saveSection('ldap-auth', config.ldapAuth, 'ldapAuth')} />
                            </div>
                        )}
                    </div>
                </>
            )}

            {/* ================================================================ */}
            {/* CERTIFICATES TAB                                                 */}
            {/* ================================================================ */}
            {tab === 'Certificates' && (
                <>
                    {/* Certificate Policy */}
                    <div className={cardClass}>
                        <SectionHeader title="Certificate Policy" expanded={expanded === 'certPolicy'} onToggle={() => toggle('certPolicy')}
                            description={config.certPolicy?.enabled ? `Min RSA ${config.certPolicy.minRsaKeySize || 2048}, Max ${config.certPolicy.maxValidityDays || 825}d` : 'Disabled'} tag="live" />
                        {expanded === 'certPolicy' && (
                            <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigToggle label="Enabled" checked={config.certPolicy?.enabled ?? false} onChange={(v) => update('certPolicy', 'enabled', v)} />
                                    <ConfigNumber label="Min RSA Key Size" value={config.certPolicy?.minRsaKeySize} onChange={(v) => update('certPolicy', 'minRsaKeySize', v)} fallback={0} />
                                    <ConfigNumber label="Max Validity Days" value={config.certPolicy?.maxValidityDays} onChange={(v) => update('certPolicy', 'maxValidityDays', v)} fallback={0} />
                                    <ConfigToggle label="Require SANs" checked={config.certPolicy?.requireSans ?? false} onChange={(v) => update('certPolicy', 'requireSans', v)} />
                                    <div className="md:col-span-2">
                                        <ConfigInput label="Forbidden Algorithms (comma-separated)" value={listToStr(config.certPolicy?.forbiddenAlgorithms)} onChange={(v) => update('certPolicy', 'forbiddenAlgorithms', strToList(v))} placeholder="MD5, SHA1" />
                                    </div>
                                    <div className="md:col-span-2">
                                        <label className={labelClass}>Algorithm Sunset Rules (one per line: &quot;RSA-2048:2030-01-01&quot;)</label>
                                        <textarea
                                            value={listToStr(config.certPolicy?.algorithmSunsetRules)}
                                            onChange={(e) => update('certPolicy', 'algorithmSunsetRules', strToList(e.target.value))}
                                            placeholder={"RSA-2048:2030-01-01\nSHA-256:2035-01-01"}
                                            rows={4}
                                            className={inputClass}
                                        />
                                    </div>
                                </div>
                                <SaveButton saving={saving === 'certPolicy'} onClick={() => saveSection('certificate-policy', config.certPolicy, 'certPolicy')} />
                            </div>
                        )}
                    </div>

                    {/* Auto-Renewal */}
                    <div className={cardClass}>
                        <SectionHeader title="Auto-Renewal" expanded={expanded === 'autoRenewal'} onToggle={() => toggle('autoRenewal')}
                            description={config.autoRenewal?.enabled ? `Renew ${config.autoRenewal.renewDaysBeforeExpiry || 30}d before expiry` : 'Disabled'} tag="live" />
                        {expanded === 'autoRenewal' && (
                            <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigToggle label="Enabled" checked={config.autoRenewal?.enabled ?? false} onChange={(v) => update('autoRenewal', 'enabled', v)} />
                                    <ConfigNumber label="Renew Days Before Expiry" value={config.autoRenewal?.renewDaysBeforeExpiry} onChange={(v) => update('autoRenewal', 'renewDaysBeforeExpiry', v)} fallback={0} />
                                    <ConfigToggle label="Auto Approve" checked={config.autoRenewal?.autoApprove ?? false} onChange={(v) => update('autoRenewal', 'autoApprove', v)} />
                                </div>
                                <ScheduleMovedNote />
                                <SaveButton saving={saving === 'autoRenewal'} onClick={() => saveSection('auto-renewal', { ...config.autoRenewal, schedule: '' }, 'autoRenewal')} />
                            </div>
                        )}
                    </div>

                    {/* Cert Expiry Notifications */}
                    <div className={cardClass}>
                        <SectionHeader title="Cert Expiry Notifications" expanded={expanded === 'certExpiryNotification'} onToggle={() => toggle('certExpiryNotification')}
                            description={config.certExpiryNotification?.enabled ? `Warn at ${config.certExpiryNotification.warningDays || '90,60,30,14,7'}d` : 'Disabled'} tag="live" />
                        {expanded === 'certExpiryNotification' && (
                            <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigToggle label="Enabled" checked={config.certExpiryNotification?.enabled ?? false} onChange={(v) => update('certExpiryNotification', 'enabled', v)} />
                                    <ConfigInput label="Warning Days (comma-separated)" value={config.certExpiryNotification?.warningDays} onChange={(v) => update('certExpiryNotification', 'warningDays', v)} placeholder="90,60,30,14,7" />
                                </div>
                                <ScheduleMovedNote />
                                <SaveButton saving={saving === 'certExpiryNotification'} onClick={() => saveSection('cert-expiry-notifications', { ...config.certExpiryNotification, schedule: '' }, 'certExpiryNotification')} />
                            </div>
                        )}
                    </div>

                    {/* Compliance Scan */}
                    <div className={cardClass}>
                        <SectionHeader title="Compliance Scan" expanded={expanded === 'complianceScan'} onToggle={() => toggle('complianceScan')}
                            description={config.complianceScan?.enabled ? `Min RSA ${config.complianceScan.minRsaKeySize || 2048}` : 'Disabled'} tag="live" />
                        {expanded === 'complianceScan' && (
                            <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-4">
                                <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-300 dark:border-blue-800 rounded p-3 text-xs text-blue-800 dark:text-blue-300">
                                    These thresholds <strong>flag existing certificates</strong> in the inventory. Issuance is enforced
                                    separately by <strong>Certificate Policy</strong> above{config.certPolicy?.enabled ? '' : ' (currently disabled)'}.
                                    Keep the two aligned to avoid surprises — the active policy baseline is shown beneath each field.
                                </div>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigToggle label="Enabled" checked={config.complianceScan?.enabled ?? false} onChange={(v) => update('complianceScan', 'enabled', v)} />
                                    <div />
                                    <div>
                                        <ConfigNumber label="Min RSA Key Size" value={config.complianceScan?.minRsaKeySize} onChange={(v) => update('complianceScan', 'minRsaKeySize', v)} fallback={0} />
                                        <p className="text-[10px] text-gray-600 mt-1">Policy: {config.certPolicy?.enabled ? `blocks issuance below ${config.certPolicy?.minRsaKeySize || 'unset'}` : 'enforcement off'}</p>
                                    </div>
                                    <div>
                                        <ConfigNumber label="Warn Over Validity Days" value={config.complianceScan?.warnOverValidityDays} onChange={(v) => update('complianceScan', 'warnOverValidityDays', v)} fallback={0} />
                                        <p className="text-[10px] text-gray-600 mt-1">Policy: {config.certPolicy?.enabled ? `caps validity at ${config.certPolicy?.maxValidityDays || 'unset'}d` : 'enforcement off'}</p>
                                    </div>
                                    <div className="md:col-span-2">
                                        <ConfigInput label="Deprecated Algorithms (comma-separated)" value={listToStr(config.complianceScan?.deprecatedAlgorithms)} onChange={(v) => update('complianceScan', 'deprecatedAlgorithms', strToList(v))} placeholder="MD5, SHA1, RSA-1024" />
                                        <p className="text-[10px] text-gray-600 mt-1">Policy forbids at issuance: {listToStr(config.certPolicy?.forbiddenAlgorithms) || 'none'}</p>
                                    </div>
                                </div>
                                <ScheduleMovedNote />
                                <SaveButton saving={saving === 'complianceScan'} onClick={() => saveSection('compliance-scan', { ...config.complianceScan, schedule: '' }, 'complianceScan')} />
                            </div>
                        )}
                    </div>
                </>
            )}

            {/* ================================================================ */}
            {/* INTEGRATIONS TAB                                                 */}
            {/* ================================================================ */}
            {tab === 'Integrations' && (
                <>
                    {/* Email / SMTP */}
                    <div className={cardClass}>
                        <SectionHeader title="Email / SMTP" expanded={expanded === 'email'} onToggle={() => toggle('email')}
                            description={config.email?.enabled ? `${config.email.authMethod} \u2014 ${config.email.smtpHost}` : 'Disabled'} tag="live" />
                        {expanded === 'email' && (
                            <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigToggle label="Enabled" checked={config.email.enabled} onChange={(v) => update('email', 'enabled', v)} />
                                    <ConfigInput label="SMTP Host" value={config.email.smtpHost} onChange={(v) => update('email', 'smtpHost', v)} placeholder="smtp.example.com" />
                                    <ConfigNumber label="SMTP Port" value={config.email.smtpPort} onChange={(v) => update('email', 'smtpPort', v)} fallback={587} />
                                    <ConfigToggle label="Use TLS" checked={config.email.useTls} onChange={(v) => update('email', 'useTls', v)} />
                                    <ConfigSelect label="Auth Method" value={config.email.authMethod || 'Password'} options={['Password', 'OAuth2Token', 'OAuth2ClientCredentials']} onChange={(v) => update('email', 'authMethod', v)} />
                                    <ConfigInput label="Username" value={config.email.username} onChange={(v) => update('email', 'username', v)} />

                                    {(config.email.authMethod === 'Password' || !config.email.authMethod) && (
                                        <ConfigInput label="Password" value={config.email.password} onChange={(v) => update('email', 'password', v)} type="password" />
                                    )}

                                    {config.email.authMethod === 'OAuth2Token' && (
                                        <ConfigInput label="OAuth2 Access Token" value={config.email.oAuth2AccessToken} onChange={(v) => update('email', 'oAuth2AccessToken', v)} type="password" />
                                    )}

                                    {config.email.authMethod === 'OAuth2ClientCredentials' && (
                                        <>
                                            <ConfigInput label="OAuth2 Client ID" value={config.email.oAuth2ClientId} onChange={(v) => update('email', 'oAuth2ClientId', v)} />
                                            <ConfigInput label="OAuth2 Client Secret" value={config.email.oAuth2ClientSecret} onChange={(v) => update('email', 'oAuth2ClientSecret', v)} type="password" />
                                            <ConfigInput label="OAuth2 Token URL" value={config.email.oAuth2TokenUrl} onChange={(v) => update('email', 'oAuth2TokenUrl', v)} placeholder="https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token" />
                                            <ConfigInput label="OAuth2 Scopes" value={config.email.oAuth2Scopes} onChange={(v) => update('email', 'oAuth2Scopes', v)} placeholder="https://outlook.office365.com/.default" />
                                        </>
                                    )}

                                    <ConfigInput label="From Address" value={config.email.fromAddress} onChange={(v) => update('email', 'fromAddress', v)} placeholder="ca@example.com" />
                                    <ConfigInput label="From Name" value={config.email.fromName} onChange={(v) => update('email', 'fromName', v)} />
                                    <div className="md:col-span-2">
                                        <ConfigInput label="Admin Recipients (comma-separated)" value={config.email.adminRecipients} onChange={(v) => update('email', 'adminRecipients', v)} placeholder="admin@example.com" />
                                    </div>
                                </div>
                                <SaveButton saving={saving === 'email'} onClick={() => saveSection('email', config.email, 'email')} />
                            </div>
                        )}
                    </div>

                    {/* Webhook */}
                    <div className={cardClass}>
                        <SectionHeader title="Webhook" expanded={expanded === 'webhook'} onToggle={() => toggle('webhook')}
                            description={config.webhook?.enabled ? `Enabled, ${config.webhook.maxRetries || 3} retries` : 'Disabled'} tag="live" />
                        {expanded === 'webhook' && (
                            <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigToggle label="Enabled" checked={config.webhook?.enabled ?? false} onChange={(v) => update('webhook', 'enabled', v)} />
                                    <ConfigNumber label="Max Retries" value={config.webhook?.maxRetries} onChange={(v) => update('webhook', 'maxRetries', v)} fallback={3} />
                                    <ConfigNumber label="Retry Delay Seconds" value={config.webhook?.retryDelaySeconds} onChange={(v) => update('webhook', 'retryDelaySeconds', v)} fallback={10} />
                                </div>
                                <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-300 dark:border-blue-800 rounded p-3 text-xs text-blue-800 dark:text-blue-300">
                                    Webhook endpoints are configured in config.yaml. These settings control the global retry behavior for all endpoints.
                                </div>
                                <SaveButton saving={saving === 'webhook'} onClick={() => saveSection('webhook', config.webhook, 'webhook')} />
                            </div>
                        )}
                    </div>

                    {/* Cert-Manager Integration */}
                    <div className={cardClass}>
                        <SectionHeader title="Cert-Manager Integration" expanded={expanded === 'certManager'} onToggle={() => toggle('certManager')}
                            description={config.certManager?.enabled ? 'Enabled' : 'Disabled'} tag="restart" />
                        {expanded === 'certManager' && (
                            <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigToggle label="Enabled" checked={config.certManager?.enabled ?? false} onChange={(v) => update('certManager', 'enabled', v)} />
                                    <ConfigInput label="API Key" value={config.certManager?.apiKey} onChange={(v) => update('certManager', 'apiKey', v)} type="password" />
                                    <ConfigInput label="Default Cert Profile ID" value={config.certManager?.defaultCertProfileId} onChange={(v) => update('certManager', 'defaultCertProfileId', v)} />
                                    <ConfigInput label="Default Signing Profile ID" value={config.certManager?.defaultSigningProfileId} onChange={(v) => update('certManager', 'defaultSigningProfileId', v)} />
                                </div>
                                <SaveButton saving={saving === 'certManager'} onClick={() => saveSection('cert-manager', config.certManager, 'certManager')} />
                            </div>
                        )}
                    </div>

                    {/* Integration API */}
                    <div className={cardClass}>
                        <SectionHeader title="Integration API" expanded={expanded === 'integrationApi'} onToggle={() => toggle('integrationApi')}
                            description={config.integrationApi?.enabled ? 'Enabled' : 'Disabled'} tag="restart" />
                        {expanded === 'integrationApi' && (
                            <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigToggle label="Enabled" checked={config.integrationApi?.enabled ?? false} onChange={(v) => update('integrationApi', 'enabled', v)} />
                                    <ConfigInput label="API Key" value={config.integrationApi?.apiKey} onChange={(v) => update('integrationApi', 'apiKey', v)} type="password" />
                                </div>
                                <SaveButton saving={saving === 'integrationApi'} onClick={() => saveSection('integration-api', config.integrationApi, 'integrationApi')} />
                            </div>
                        )}
                    </div>

                    {/* ACME Policies */}
                    <div className={cardClass}>
                        <SectionHeader title="ACME Policies" expanded={expanded === 'acme'} onToggle={() => toggle('acme')}
                            description={`EAB: ${config.acme?.externalAccountRequired ? 'Required' : 'Off'}, CAA: ${config.acme?.enforceCaa ? 'On' : 'Off'}`} tag="live" />
                        {expanded === 'acme' && (
                            <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigToggle label="External Account Required" checked={config.acme?.externalAccountRequired ?? false} onChange={(v) => update('acme', 'externalAccountRequired', v)} />
                                    <ConfigToggle label="Enforce CAA" checked={config.acme?.enforceCaa ?? false} onChange={(v) => update('acme', 'enforceCaa', v)} />
                                </div>
                                <SaveButton saving={saving === 'acme'} onClick={() => saveSection('acme-policies', config.acme, 'acme')} />
                            </div>
                        )}
                    </div>

                    {/* Policy Sync */}
                    <div className={cardClass}>
                        <SectionHeader title="Policy Sync" expanded={expanded === 'policySync'} onToggle={() => toggle('policySync')}
                            description={config.policySync?.enabled ? `Dir: ${config.policySync.policyDirectory || 'Not set'}` : 'Disabled'} tag="live" />
                        {expanded === 'policySync' && (
                            <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigToggle label="Enabled" checked={config.policySync?.enabled ?? false} onChange={(v) => update('policySync', 'enabled', v)} />
                                    <ConfigInput label="Policy Directory" value={config.policySync?.policyDirectory} onChange={(v) => update('policySync', 'policyDirectory', v)} placeholder="/etc/modular-ca/policies" />
                                    <ConfigToggle label="Sync On Startup" checked={config.policySync?.syncOnStartup ?? false} onChange={(v) => update('policySync', 'syncOnStartup', v)} />
                                </div>
                                <div className="flex gap-2">
                                    <SaveButton saving={saving === 'policySync'} onClick={() => saveSection('policy-sync', config.policySync, 'policySync')} />
                                    <button
                                        onClick={async () => {
                                            setSaving('policySyncNow');
                                            try {
                                                const result = await apiPostWithMfa('/api/v1/admin/policy/sync', {}, requireStepUp, 'policy-sync');
                                                setSuccessMsg(result.message || 'Policy sync triggered');
                                            } catch (err: any) {
                                                if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to trigger sync');
                                            } finally {
                                                setSaving(null);
                                            }
                                        }}
                                        disabled={saving === 'policySyncNow'}
                                        className="px-4 py-2 text-sm bg-purple-600 text-gray-900 dark:text-white rounded hover:bg-purple-700 disabled:opacity-50 transition-colors"
                                    >
                                        {saving === 'policySyncNow' ? 'Syncing...' : 'Sync Now'}
                                    </button>
                                </div>
                            </div>
                        )}
                    </div>

                    {/* Alert */}
                    <div className={cardClass}>
                        <SectionHeader title="Alert" expanded={expanded === 'alert'} onToggle={() => toggle('alert')}
                            description={config.alert?.enabled ? `Min severity: ${config.alert.minimumSeverity || 'Warning'}` : 'Disabled'} tag="live" />
                        {expanded === 'alert' && (
                            <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigToggle label="Enabled" checked={config.alert?.enabled ?? false} onChange={(v) => update('alert', 'enabled', v)} />
                                    <ConfigSelect label="Minimum Severity" value={config.alert?.minimumSeverity || 'Warning'} options={['Critical', 'Warning', 'Info']} onChange={(v) => update('alert', 'minimumSeverity', v)} />
                                    <ConfigNumber label="Cooldown Minutes" value={config.alert?.cooldownMinutes} onChange={(v) => update('alert', 'cooldownMinutes', v)} />
                                </div>
                                <SaveButton saving={saving === 'alert'} onClick={() => saveSection('alert', config.alert, 'alert')} />
                            </div>
                        )}
                    </div>

                    {/* Webhook Test */}
                    <WebhookTestCard />
                </>
            )}

            {/* ================================================================ */}
            {/* LOGGING TAB                                                      */}
            {/* ================================================================ */}
            {tab === 'Logging' && (
                <>
                    {/* Logging (live) */}
                    <div className={cardClass}>
                        <SectionHeader title="Logging" expanded={expanded === 'logging'} onToggle={() => toggle('logging')}
                            description={config.logging?.minLevel || 'Information'} tag="live" />
                        {expanded === 'logging' && (
                            <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-4">
                                <ConfigSelect label="Min Level" value={config.logging.minLevel || 'Information'} options={['Debug', 'Information', 'Warning', 'Error']} onChange={(v) => update('logging', 'minLevel', v)} />
                                <div className="text-xs text-gray-600">
                                    Log level changes take effect immediately — no restart needed.
                                </div>
                                <SaveButton saving={saving === 'logging'} onClick={() => saveSection('logging', { minLevel: config.logging.minLevel }, 'logging')} />
                            </div>
                        )}
                    </div>

                    {/* Log Storage (restart) */}
                    <div className={cardClass}>
                        <SectionHeader title="Log Storage" expanded={expanded === 'logStorage'} onToggle={() => toggle('logStorage')}
                            description={`${config.logging?.retentionDays || 30}d retention, ${config.logging?.maxFileSizeMb || 100}MB max`} tag="restart" />
                        {expanded === 'logStorage' && (
                            <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigInput label="File Path" value={config.logging.filePath} onChange={(v) => update('logging', 'filePath', v)} />
                                    <ConfigNumber label="Retention Days" value={config.logging.retentionDays} onChange={(v) => update('logging', 'retentionDays', v)} fallback={30} />
                                    <ConfigNumber label="Max File Size (MB)" value={config.logging.maxFileSizeMb ?? 100} onChange={(v) => update('logging', 'maxFileSizeMb', v)} fallback={100} />
                                </div>
                                <div className="text-xs text-gray-600">
                                    Log files roll daily and when they reach the max file size. Old files are deleted after the retention period.
                                </div>
                                <SaveButton saving={saving === 'logStorage'} onClick={() => saveSection('logging', config.logging, 'logStorage')} />
                            </div>
                        )}
                    </div>

                    {/* Network Audit */}
                    <div className={cardClass}>
                        <SectionHeader title="Network Audit" expanded={expanded === 'networkAudit'} onToggle={() => toggle('networkAudit')}
                            description={config.networkAudit?.enabled ? 'Enabled' : 'Disabled'} tag="restart" />
                        {expanded === 'networkAudit' && (
                            <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigToggle label="Enabled" checked={config.networkAudit?.enabled ?? false} onChange={(v) => update('networkAudit', 'enabled', v)} />
                                    <div>
                                        <ConfigToggle label="Log All Requests" checked={config.networkAudit?.logAllRequests ?? false} onChange={(v) => update('networkAudit', 'logAllRequests', v)} />
                                        {config.networkAudit?.logAllRequests && (
                                            <div className="bg-amber-50 dark:bg-amber-900/20 border border-amber-300 dark:border-amber-800 rounded p-2 text-xs text-amber-800 dark:text-amber-300 mt-2">
                                                Enabling logs ALL HTTP requests including static files. This can generate significant log volume.
                                            </div>
                                        )}
                                    </div>
                                    <div className="md:col-span-2">
                                        <ConfigInput label="Exclude Paths (comma-separated)" value={listToStr(config.networkAudit?.excludePaths)}
                                            onChange={(v) => update('networkAudit', 'excludePaths', strToList(v))}
                                            placeholder="/health,/metrics" />
                                    </div>
                                </div>
                                <SaveButton saving={saving === 'networkAudit'} onClick={() => saveSection('network-audit', config.networkAudit, 'networkAudit')} />
                            </div>
                        )}
                    </div>

                </>
            )}
        </div>
    );
};

/* --- Feature Flags Tab --- */
const FeatureFlagsTab: React.FC = () => {
    const { showToast } = useToast();
    const [features, setFeatures] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    const load = () => {
        setLoading(true);
        apiGet<any>('/api/v1/admin/features')
            .then((data) => setFeatures(Array.isArray(data) ? data : (data.items || data.features || [])))
            .catch((err) => setError(err.message))
            .finally(() => setLoading(false));
    };

    useEffect(() => { load(); }, []);

    const handleToggle = async (feature: any) => {
        try {
            await apiPut(`/api/v1/admin/features/${feature.name}`, { enabled: !feature.enabled });
            load();
        } catch (err: any) {
            showToast('error', err.message || 'Failed to update feature flag');
        }
    };

    if (loading) return <div className="p-4 text-sm text-gray-600 dark:text-gray-400">Loading...</div>;
    if (error) return <div className="p-4 text-sm text-red-800 dark:text-red-400">{error}</div>;

    return (
        <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg overflow-hidden">
            <div className="px-4 py-3 border-b border-gray-300 dark:border-gray-700">
                <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Feature Flags</h3>
            </div>
            <div className="px-4 py-3 border-b border-gray-300 dark:border-gray-700 bg-blue-50 dark:bg-blue-900/20 text-xs text-blue-800 dark:text-blue-300">
                Changes here apply <strong>live</strong> — toggling a feature takes effect immediately, no restart required.
                Items marked <RestartTag /> need a service restart before the change takes effect.
            </div>
            {features.length === 0 && (
                <div className="p-4 text-sm text-gray-600 text-center">No feature flags configured</div>
            )}
            {features.map((f) => (
                <div key={f.name} className="px-4 py-3 flex items-center justify-between border-b border-gray-300 dark:border-gray-700 last:border-b-0">
                    <div className="flex items-center gap-2">
                        <span className="text-sm text-gray-900 dark:text-white">{f.name}</span>
                        {f.description && <span className="text-xs text-gray-600">{f.description}</span>}
                        {f.requiresRestart && <RestartTag />}
                    </div>
                    <button
                        onClick={() => handleToggle(f)}
                        className={`relative w-11 h-6 rounded-full transition-colors ${f.enabled ? 'bg-blue-600' : 'bg-gray-600'}`}
                    >
                        <span
                            className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full shadow transition-transform ${f.enabled ? 'translate-x-5' : 'translate-x-0'}`}
                        />
                    </button>
                </div>
            ))}
        </div>
    );
};

/* --- Settings Page --- */
const Settings: React.FC = () => {
    const [activeTab, setActiveTab] = useState<Tab>('General');

    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Settings</h1>

            {/* Tabs */}
            <div className="flex gap-1 border-b border-gray-300 dark:border-gray-700">
                {TABS.map((tab) => (
                    <button
                        key={tab}
                        onClick={() => setActiveTab(tab)}
                        className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 ${activeTab === tab
                            ? 'text-blue-800 dark:text-blue-400 border-blue-400'
                            : 'text-gray-600 dark:text-gray-400 border-transparent hover:text-gray-700 dark:text-gray-300'
                            }`}
                    >
                        {tab}
                    </button>
                ))}
            </div>

            {/* Tab Content */}
            {activeTab === 'Features' ? <FeatureFlagsTab /> : <ConfigTab tab={activeTab} />}
        </div>
    );
};

export default Settings;
