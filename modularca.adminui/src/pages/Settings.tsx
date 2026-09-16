import React, { useState, useEffect, useRef } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { Chevron } from '@shared/components/Chevron';
import { Link, useSearchParams } from 'react-router-dom';
import { apiGet, apiPost, apiPut, apiPutWithMfa, apiPostWithMfa } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import { StepUpOps } from '@shared/generated';
import ConfirmModal from '../components/ConfirmModal';
import { inputClass, labelClass, FieldHint } from '@shared/components/forms';

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

const TABS = ['General', 'Security', 'Certificates', 'Integrations', 'Logging', 'Features'] as const;
type Tab = typeof TABS[number];

/** Element id of the Restart card on the General tab. BackupRestore links to
    `/settings#restart-application` after a restore (string repeated there rather than imported,
    so that page does not pull this lazy chunk in). */
const RESTART_ANCHOR = 'restart-application';

/* --- Shared Form Helpers --- */
const cardClass = 'bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg overflow-hidden';

/* Every primitive takes `hint`: what the value does, or what saving it causes, shown under the
   control. The label names the setting; the hint says what happens when you change it. */
const ConfigInput: React.FC<{ label: string; value: any; onChange: (v: string) => void; type?: string; placeholder?: string; hint?: React.ReactNode }> = ({ label, value, onChange, type = 'text', placeholder, hint }) => (
    <div>
        <label className={labelClass}>{label}</label>
        <input type={type} value={value ?? ''} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} className={inputClass} />
        {hint && <FieldHint>{hint}</FieldHint>}
    </div>
);

const ConfigTextarea: React.FC<{ label: string; value: any; onChange: (v: string) => void; placeholder?: string; rows?: number; hint?: React.ReactNode }> = ({ label, value, onChange, placeholder, rows = 6, hint }) => (
    <div>
        <label className={labelClass}>{label}</label>
        <textarea
            value={value ?? ''}
            onChange={(e) => onChange(e.target.value)}
            placeholder={placeholder}
            rows={rows}
            className={`${inputClass} font-mono text-xs resize-y`}
        />
        {hint && <FieldHint>{hint}</FieldHint>}
    </div>
);

const ConfigNumber: React.FC<{ label: string; value: any; onChange: (v: number | string) => void; fallback?: number; hint?: React.ReactNode }> = ({ label, value, onChange, fallback = 0, hint }) => (
    <div>
        <label className={labelClass}>{label}</label>
        <input type="text" inputMode="numeric" value={value ?? ''} onChange={(e) => { const v = e.target.value.replace(/\D/g, ''); onChange(v === '' ? '' : parseInt(v)); }} onBlur={() => { if (!value && value !== 0) onChange(fallback); }} className={inputClass} />
        {hint && <FieldHint>{hint}</FieldHint>}
    </div>
);

const ConfigToggle: React.FC<{ label: string; checked: boolean; onChange: (v: boolean) => void; hint?: React.ReactNode; hintTone?: 'muted' | 'warn' }> = ({ label, checked, onChange, hint, hintTone }) => (
    <div>
        <div className="flex items-center justify-between">
            <label className="text-xs text-gray-600 dark:text-gray-400">{label}</label>
            <button type="button" role="switch" aria-checked={checked} onClick={() => onChange(!checked)} className={`relative w-11 h-6 rounded-full transition-colors ${checked ? 'bg-blue-600' : 'bg-gray-600'}`}>
                <span className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full shadow transition-transform ${checked ? 'translate-x-5' : 'translate-x-0'}`} />
            </button>
        </div>
        {hint && <FieldHint tone={hintTone}>{hint}</FieldHint>}
    </div>
);

const ConfigSelect: React.FC<{ label: string; value: string; options: string[]; onChange: (v: string) => void; hint?: React.ReactNode }> = ({ label, value, options, onChange, hint }) => (
    <div>
        <label className={labelClass}>{label}</label>
        <select value={value} onChange={(e) => onChange(e.target.value)} className={inputClass}>
            {options.map((o) => <option key={o} value={o}>{o}</option>)}
        </select>
        {hint && <FieldHint>{hint}</FieldHint>}
    </div>
);

const SaveButton: React.FC<{ saving: boolean; onClick: () => void; label?: string; disabled?: boolean }> = ({ saving, onClick, label, disabled }) => (
    <button onClick={onClick} disabled={saving || disabled} className="px-4 py-2 text-sm bg-blue-600 text-gray-900 dark:text-white rounded hover:bg-blue-700 disabled:opacity-50 transition-colors">
        {saving ? 'Saving...' : (label || 'Save')}
    </button>
);

/* Note shown on cards whose cron schedule is owned by the scheduler job's detail page. The card's
   Save deliberately sends an empty `schedule`, which the backend patch-guards
   (`if (!IsNullOrEmpty) ...`) so a stale Settings tab can't clobber a cron edited there. */
const ScheduleMovedNote: React.FC<{ job: string }> = ({ job }) => (
    <p className="text-[11px] text-gray-500 dark:text-gray-500">
        The run schedule (cron) is edited on the{' '}
        <Link to={`/schedules/jobs/${encodeURIComponent(job)}`} className="underline hover:text-gray-700 dark:hover:text-gray-300">{job} job page</Link>
        {' '}(Schedules → open the job → Edit).
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
/** Same, for a textarea labelled "one per line" — accepts newlines and commas. */
const listToLines = (value: any): string => (Array.isArray(value) ? value.join('\n') : (value ?? ''));
const linesToList = (value: string): string[] => value.split(/[\n,]/).map((s: string) => s.trim()).filter(Boolean);

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

/* --- Password policy field metadata: human labels + what each value does --- */
const POLICY_FIELDS: Record<string, { label: string; hint: string }> = {
    minLength: { label: 'Minimum length', hint: 'Shortest password accepted. Length is the single strongest lever; 12 or more is the usual floor.' },
    maxLength: { label: 'Maximum length', hint: 'Longest password accepted. 0 means no upper limit. Keep it high; a low cap blocks passphrases.' },
    minUppercase: { label: 'Minimum uppercase letters', hint: 'Exact count required, enforced even when the "at least one uppercase" rule is off. 0 means no count is enforced.' },
    minLowercase: { label: 'Minimum lowercase letters', hint: 'Exact count required, independent of the "at least one lowercase" rule. 0 means no count is enforced.' },
    minDigits: { label: 'Minimum digits', hint: 'Exact count required, independent of the "at least one digit" rule. 0 means no count is enforced.' },
    minSpecial: { label: 'Minimum symbols', hint: 'Exact count of non-alphanumeric characters required. 0 means no count is enforced.' },
    maxAgeDays: { label: 'Maximum password age (days)', hint: 'Users must change their password this many days after setting it; the expiry is stamped at each change. 0 means passwords never expire (accounts marked "never expires" are exempt either way).' },
    historyCount: { label: 'Password history', hint: 'A new password may not match any of this many previous ones. 0 keeps no history and allows immediate reuse.' },
    requireUppercase: { label: 'Require at least one uppercase letter', hint: 'Rejects passwords with no A–Z character.' },
    requireLowercase: { label: 'Require at least one lowercase letter', hint: 'Rejects passwords with no a–z character.' },
    requireDigit: { label: 'Require at least one digit', hint: 'Rejects passwords with no 0–9 character.' },
    requireSymbol: { label: 'Require at least one symbol', hint: 'Rejects passwords made only of letters and digits.' },
};

/* --- Config Tab (accepts tab prop to determine which sections to show) --- */
const ConfigTab: React.FC<{ tab: Tab }> = ({ tab }) => {
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();
    const [config, setConfig] = useState<any>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [expanded, setExpanded] = useState<string | null>(null);
    const [saving, setSaving] = useState<string | null>(null);
    const [successMsg, setSuccessMsg] = useState<string | null>(null);
    const [restarting, setRestarting] = useState(false);

    // Restarting the server is the most destructive control on this page, and it was the
    // one place in adminui still using a native window.confirm — ConfirmModal is used in
    // thirty others. A native dialog blocks the page, cannot be styled to match, and is
    // dismissed by reflex.
    const [confirmRestart, setConfirmRestart] = useState(false);

    const doRestart = async () => {
        setConfirmRestart(false);
        setRestarting(true);
        try {
            await apiPostWithMfa('/api/v1/admin/config/restart', {}, requireStepUp, StepUpOps.Restart);
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
    };

    /* Password Policy state (inlined into Security tab) */
    const [policy, setPolicy] = useState<any>(null);
    const [policyLoading, setPolicyLoading] = useState(false);
    const [policyError, setPolicyError] = useState<NoticeInput | null>(null);
    const [policySaving, setPolicySaving] = useState(false);

    /* Security Policy (DB) state — runtime-tunable session/lockout/MFA/OCSP knobs.
       Loaded from /admin/security-policy; saved with step-up MFA. Distinct from the
       yaml-backed middleware Security section which uses saveSection('security', ...). */
    const [securityPolicy, setSecurityPolicy] = useState<any>(null);
    const [securityPolicyLoading, setSecurityPolicyLoading] = useState(false);
    const [securityPolicyError, setSecurityPolicyError] = useState<NoticeInput | null>(null);
    const [securityPolicySaving, setSecurityPolicySaving] = useState(false);

    /* Snapshots of what the server last returned, for the unsaved-changes guard. Each loader
       stamps its own key; `dirty` is true when any live buffer differs from its snapshot. */
    const saved = useRef<Record<string, string>>({});
    const snap = (key: string, value: any) => { saved.current[key] = JSON.stringify(value); };
    const differs = (key: string, value: any) => value != null && saved.current[key] !== undefined && saved.current[key] !== JSON.stringify(value);

    const load = () => {
        setLoading(true);
        apiGet<any>('/api/v1/admin/config')
            .then((c) => { setConfig(c); snap('config', c); })
            .catch((err) => setError(errorNotice(err, 'The request failed.')))
            .finally(() => setLoading(false));
    };

    const loadPolicy = () => {
        setPolicyLoading(true);
        apiGet<any>('/api/v1/admin/password-policy')
            .then((p) => { setPolicy(p); snap('policy', p); })
            .catch((err) => setPolicyError(errorNotice(err, 'The request failed.')))
            .finally(() => setPolicyLoading(false));
    };

    const loadSecurityPolicy = () => {
        setSecurityPolicyLoading(true);
        setSecurityPolicyError(null);
        apiGet<any>('/api/v1/admin/security-policy')
            .then((s) => { setSecurityPolicy(s); snap('securityPolicy', s); })
            .catch((err) => setSecurityPolicyError(errorNotice(err, 'The request failed.')))
            .finally(() => setSecurityPolicyLoading(false));
    };

    /* Protocol Rate Limits (DB) — multi-row */
    const [rateLimits, setRateLimits] = useState<any[]>([]);
    const [rateLimitsLoading, setRateLimitsLoading] = useState(false);
    const [rateLimitsError, setRateLimitsError] = useState<NoticeInput | null>(null);
    const [rateLimitsSaving, setRateLimitsSaving] = useState(false);
    const loadRateLimits = () => {
        setRateLimitsLoading(true);
        setRateLimitsError(null);
        apiGet<any[]>('/api/v1/admin/rate-limit-policy')
            .then((data) => { const rows = Array.isArray(data) ? data : []; setRateLimits(rows); snap('rateLimits', rows); })
            .catch((err) => setRateLimitsError(errorNotice(err, 'The request failed.')))
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

    // Unsaved-changes guard: the browser asks before a reload / tab close while any field on
    // the page differs from what the server last returned. In-app navigation is not guarded.
    const dirty = differs('config', config) || differs('policy', policy) || differs('securityPolicy', securityPolicy) || differs('rateLimits', rateLimits);
    useEffect(() => {
        if (!dirty) return;
        const onBeforeUnload = (e: BeforeUnloadEvent) => { e.preventDefault(); e.returnValue = ''; };
        window.addEventListener('beforeunload', onBeforeUnload);
        return () => window.removeEventListener('beforeunload', onBeforeUnload);
    }, [dirty]);

    // BackupRestore links to /settings#restart-application after a restore; scroll to the
    // card once the General tab has rendered.
    useEffect(() => {
        if (loading || tab !== 'General' || window.location.hash !== `#${RESTART_ANCHOR}`) return;
        document.getElementById(RESTART_ANCHOR)?.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }, [loading, tab]);

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

    /* PUT /config/security applies only the fields present in the body (SecurityUpdateRequest),
       so each sub-card sends just its own fields. Before this, "Save Rate Limit", "Save Binding"
       and "Save Proxy Mode" each wrote the whole section, including unsaved edits on the others. */
    const saveSecurityFields = (fields: string[], sectionKey: string) => {
        const body: Record<string, any> = {};
        for (const f of fields) body[f] = config.security[f];
        return saveSection('security', body, sectionKey);
    };

    const toggle = (key: string) => setExpanded(expanded === key ? null : key);
    const update = (section: string, field: string, value: any) => {
        setConfig({ ...config, [section]: { ...config[section], [field]: value } });
    };

    if (loading) return <div className="p-4 text-sm text-gray-600 dark:text-gray-400">Loading...</div>;
    if (error) return <InlineNotice notice={error} />;
    if (!config) return null;

    /* --- Password Policy helpers --- */
    const handleSavePolicy = async () => {
        setPolicySaving(true);
        try {
            await apiPut('/api/v1/admin/password-policy', policy);
            snap('policy', policy);
            showToast('success', 'Password policy updated');
        } catch (err: any) {
            showToast('error', err.message || 'Failed to save policy');
        } finally {
            setPolicySaving(false);
        }
    };
    const updatePolicyField = (key: string, value: any) => setPolicy({ ...policy, [key]: value });

    /* Cross-field checks the backend does not make. MaxLength 0 means "no cap", so the
       comparisons only apply when a cap is set. A policy no password can satisfy locks every
       user out at their next change. */
    const policyNum = (k: string) => (policy && typeof policy[k] === 'number' ? policy[k] : 0);
    const policyMinsTotal = policyNum('minUppercase') + policyNum('minLowercase') + policyNum('minDigits') + policyNum('minSpecial');
    const policyProblems: string[] = [];
    if (policy && policyNum('maxLength') > 0 && policyNum('minLength') > policyNum('maxLength'))
        policyProblems.push(`Minimum length (${policyNum('minLength')}) is greater than maximum length (${policyNum('maxLength')}); no password can satisfy both.`);
    if (policy && policyNum('maxLength') > 0 && policyMinsTotal > policyNum('maxLength'))
        policyProblems.push(`The character-class minimums add up to ${policyMinsTotal}, more than the maximum length (${policyNum('maxLength')}).`);
    if (policy && policyNum('minLength') === 0 && policyMinsTotal === 0)
        policyProblems.push('Minimum length is 0 and no character counts are required; an empty password would pass.');

    /* --- Security Policy (DB) helpers --- */
    const handleSaveSecurityPolicy = async () => {
        setSecurityPolicySaving(true);
        try {
            await apiPutWithMfa('/api/v1/admin/security-policy', securityPolicy, requireStepUp, StepUpOps.UpdateConfig);
            snap('securityPolicy', securityPolicy);
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
            await apiPutWithMfa('/api/v1/admin/rate-limit-policy', payload, requireStepUp, StepUpOps.UpdateConfig);
            snap('rateLimits', rateLimits);
            showToast('success', 'Rate limit policy updated');
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to save rate limits');
        } finally {
            setRateLimitsSaving(false);
        }
    };
    const policyNumberFields = ['minLength', 'maxLength', 'minUppercase', 'minLowercase', 'minDigits', 'minSpecial', 'maxAgeDays', 'historyCount'];
    const policyBoolFields = ['requireUppercase', 'requireLowercase', 'requireDigit', 'requireSymbol'];

    const ocspTtlHint = 'Clients may cache this answer for this long (nextUpdate). Longer means less responder load and slower revocation visibility.';

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
                            description={config.https?.publicDomain || 'Not configured — using request origin'} tag="restart" />
                        {expanded === 'baseurl' && (
                            <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-4">
                                <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-300 dark:border-blue-800 rounded p-3 text-xs text-blue-800 dark:text-blue-300">
                                    The public hostname used for management-UI HTTPS redirects and ACME URL binding.
                                    Must be a bare hostname or IP — no scheme, no port. Per-CA AIA/CDP base URLs are configured
                                    separately in CA Management.
                                </div>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigInput label="Public Domain" value={config.https?.publicDomain} onChange={(v) => update('https', 'publicDomain', v)} placeholder="ca.example.com"
                                        hint="Empty means URLs are built from whatever host the request arrived on, which is wrong behind a proxy and unusable for ACME JWS URL checks." />
                                    <ConfigNumber label="Public Port (443 = omitted from URLs)" value={config.https?.publicPort} onChange={(v) => update('https', 'publicPort', v)} fallback={443}
                                        hint="The port external clients reach this server on, which may differ from the listen port behind a proxy. Anything other than 443 is written into every generated URL." />
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
                                    <ConfigNumber label="HTTP Port (0 = disabled)" value={config.http.port} onChange={(v) => update('http', 'port', v)}
                                        hint="Plain-HTTP listener for CRL, OCSP and AIA fetches, which relying parties make without TLS. 0 turns it off, and those URLs stop answering." />
                                    <ConfigNumber label="Public Port (behind proxy)" value={config.http.publicPort} onChange={(v) => update('http', 'publicPort', v)} fallback={0}
                                        hint="Port external clients connect to when a proxy sits in front (proxy on 80, this process on 8080). It is written into CRL/OCSP/AIA URLs. 0 uses the listener port." />
                                    <ConfigInput label="CORS Origins (comma-separated)" value={config.http.corsOrigins} onChange={(v) => update('http', 'corsOrigins', v)}
                                        hint="HTTPS origins whose browser scripts may call this API. Only read when Enable CORS is on." />
                                    <ConfigToggle label="Enable CORS" checked={config.http.enableCors ?? false} onChange={(v) => update('http', 'enableCors', v)}
                                        hint="Allows browser pages on the listed origins to call the API. Off means every cross-origin browser request is refused, even in Development." />
                                    <ConfigToggle label="Swagger Enabled" checked={config.http.swaggerEnabled} onChange={(v) => update('http', 'swaggerEnabled', v)}
                                        hint="Publishes the interactive API documentation at /swagger to anyone who can reach the port. Leave off in production." />
                                </div>
                                <p className="text-[10px] text-gray-600">Trusted Proxy CIDRs moved to the <strong>Reverse Proxy</strong> card (Security tab).</p>
                                <SaveButton saving={saving === 'http'} onClick={() => saveSection('http', config.http, 'http')} />
                            </div>
                        )}
                    </div>

                    {/* HTTPS (read-only) */}
                    <div className={cardClass}>
                        <SectionHeader title="HTTPS" expanded={expanded === 'https'} onToggle={() => toggle('https')}
                            description={`${config.https?.mode} — Port ${config.https?.port}`} tag="read-only" />
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
                                    <ConfigToggle label="Enabled" checked={config.metrics.enabled} onChange={(v) => update('metrics', 'enabled', v)}
                                        hint="Serves Prometheus metrics at the path below. Anyone who can reach the port can scrape them; restrict at the network or whitelist level." />
                                    <ConfigInput label="Path" value={config.metrics.path} onChange={(v) => update('metrics', 'path', v)}
                                        hint="Route the scrape endpoint is mounted on. Prometheus defaults to /metrics." />
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
                                    <ConfigInput label="ssh-keygen Path" value={config.sshCa.sshKeygenPath} onChange={(v) => update('sshCa', 'sshKeygenPath', v)}
                                        hint="The OpenSSH binary used to sign SSH certificates. A bare name is resolved on PATH; if it is missing, every SSH issuance fails." />
                                    <ConfigInput label="Key Storage Path" value={config.sshCa.keyStoragePath} onChange={(v) => update('sshCa', 'keyStoragePath', v)}
                                        hint="Directory holding SSH CA private keys. Must be writable by the service and is included in backups." />
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
                                    <ConfigInput label="Output Path" value={config.backup?.outputPath} onChange={(v) => update('backup', 'outputPath', v)}
                                        hint="Directory archives are written to. A relative path resolves from the application directory, so it lives on the same disk as the data it protects." />
                                    <ConfigNumber label="Retention Count" value={config.backup?.retentionCount} onChange={(v) => update('backup', 'retentionCount', v)}
                                        hint="Archives kept on disk. When a new one is written, the oldest beyond this count are deleted." />
                                    <ConfigNumber label="Max Backup Age Days" value={config.backup?.maxBackupAgeDays} onChange={(v) => update('backup', 'maxBackupAgeDays', v)}
                                        hint="If the newest archive is older than this when the verification job runs, it raises a Critical BackupStale alert." />
                                    <ConfigToggle label="Verify on Schedule" checked={config.backup?.verifyOnSchedule ?? true} onChange={(v) => update('backup', 'verifyOnSchedule', v)}
                                        hint="Each scheduled run also opens recent archives and checks them for corruption. Off means a bad archive is found only when you need it." />
                                    <ConfigNumber label="Verify Count" value={config.backup?.verifyCount} onChange={(v) => update('backup', 'verifyCount', v)}
                                        hint="How many of the newest archives each verification run checks. 1 checks only the latest, so corruption in the one before it goes unnoticed." />
                                </div>
                                <ScheduleMovedNote job="BackupCreation" />
                                <SaveButton saving={saving === 'backup'} onClick={() => saveSection('backup', { ...config.backup, schedule: '' }, 'backup')} />
                            </div>
                        )}
                    </div>

                    {/* Restart */}
                    <div id={RESTART_ANCHOR} className="bg-gray-100 dark:bg-gray-800 border border-yellow-300 dark:border-yellow-700/50 rounded-lg p-4 scroll-mt-4">
                        <div className="flex items-center justify-between">
                            <div>
                                <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Restart Application</h3>
                                <p className="text-xs text-gray-600 mt-1">
                                    Apply pending configuration changes that require a restart (logging, HTTP, HTTPS), or bring a restored
                                    backup into service. The application will shut down and the process manager will restart it.
                                </p>
                            </div>
                            <button
                                onClick={() => setConfirmRestart(true)}
                                disabled={restarting}
                                className="px-4 py-2 text-sm bg-yellow-600 text-gray-900 dark:text-white rounded hover:bg-yellow-700 disabled:opacity-50 transition-colors flex-shrink-0"
                            >
                                {restarting ? 'Restarting...' : 'Restart Server'}
                            </button>
                        </div>
                        <ConfirmModal
                            isOpen={confirmRestart}
                            title="Restart server"
                            message="Restart the ModularCA server? Active connections will be dropped and issuance, OCSP and CRL responses will be unavailable until it comes back."
                            confirmLabel="Restart"
                            confirmClass="bg-yellow-600 hover:bg-yellow-700"
                            loading={restarting}
                            onConfirm={doRestart}
                            onCancel={() => setConfirmRestart(false)}
                        />
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
                                    attempts in the request pipeline and is wired at startup (restart to change). Each has its own Save,
                                    and each Save writes only the fields in its own group.
                                </div>

                                {/* Account Lockout — DB SecurityPolicy (live) */}
                                <div className="flex items-center gap-2"><h4 className="text-xs font-semibold text-gray-600 uppercase tracking-wide">Account Lockout</h4><LiveTag /></div>
                                {securityPolicyLoading && <div className="text-sm text-gray-600 dark:text-gray-400">Loading...</div>}
                                {securityPolicyError && <InlineNotice notice={securityPolicyError} />}
                                {securityPolicy && (
                                    <>
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                            <ConfigNumber label="Max Failed Login Attempts" value={securityPolicy.maxFailedLoginAttempts} onChange={(v) => updateSecurityPolicyField('maxFailedLoginAttempts', v)}
                                                hint="Consecutive wrong passwords before the account is locked. A correct login resets the count." />
                                            <ConfigNumber label="Lockout Minutes (0 = permanent)" value={securityPolicy.lockoutMinutes} onChange={(v) => updateSecurityPolicyField('lockoutMinutes', v)}
                                                hint="How long the lock lasts before logins are accepted again. 0 keeps the account locked until an administrator unlocks it." />
                                            <ConfigNumber label="Login Response Delay (ms)" value={securityPolicy.loginResponseDelayMs} onChange={(v) => updateSecurityPolicyField('loginResponseDelayMs', v)}
                                                hint="Minimum time a login response takes, so an unknown username and a wrong password are indistinguishable by timing. 0 disables the padding." />
                                        </div>
                                        <SaveButton saving={securityPolicySaving} onClick={handleSaveSecurityPolicy} label="Save Lockout" />
                                    </>
                                )}

                                {/* Per-Username Rate Limit — yaml middleware (restart) */}
                                <div className="flex items-center gap-2 pt-2"><h4 className="text-xs font-semibold text-gray-600 uppercase tracking-wide">Per-Username Rate Limit</h4><RestartTag /></div>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigNumber label="Per-Username Failure Limit" value={config.security.maxPerUsernameLoginFailures} onChange={(v) => update('security', 'maxPerUsernameLoginFailures', v)}
                                        hint="Failed logins allowed for one username from any number of IPs within the window before further attempts are refused. Catches many-IP attacks on a single account, which per-IP limits miss." />
                                    <ConfigNumber label="Per-Username Failure Window (min)" value={config.security.perUsernameLoginFailureWindowMinutes} onChange={(v) => update('security', 'perUsernameLoginFailureWindowMinutes', v)}
                                        hint="Length of the sliding window the failure count is measured over." />
                                </div>
                                <SaveButton saving={saving === 'securityRateLimit'} onClick={() => saveSecurityFields(['maxPerUsernameLoginFailures', 'perUsernameLoginFailureWindowMinutes'], 'securityRateLimit')} label="Save Per-Username Limit" />
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
                                <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-300 dark:border-blue-800 rounded p-3 text-xs text-blue-800 dark:text-blue-300">
                                    The lifetime lives in the <strong>tokens</strong> config section and applies live; the binding rules live in
                                    the <strong>security</strong> section and are wired at startup. Each group has its own Save, and each writes
                                    only its own fields.
                                </div>
                                {/* Refresh Token Lifetime — tokens (live) */}
                                <div className="flex items-center gap-2"><h4 className="text-xs font-semibold text-gray-600 uppercase tracking-wide">Refresh Token Lifetime</h4><LiveTag /></div>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigNumber label="Refresh Token Lifetime (days)" value={config.tokens.refreshTokenDays} onChange={(v) => update('tokens', 'refreshTokenDays', v)} fallback={7}
                                        hint="Days a session can be renewed without logging in again. A stolen refresh token stays usable for the same period, subject to the bindings below and the session caps in Security Policy." />
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
                                        <FieldHint>Ties every access token to the address it was issued to. Exact logs users out whenever their IP changes (mobile, VPN reconnects); Subnet /24 tolerates movement within one IPv4 /24 or IPv6 /64.</FieldHint>
                                    </div>
                                    <ConfigToggle label="Bind Refresh Token to IP" checked={config.security.bindRefreshTokenToIp ?? true} onChange={(v) => update('security', 'bindRefreshTokenToIp', v)}
                                        hint="A refresh attempted from a different IP than the one the token was issued to is refused and the user must log in again." />
                                    <ConfigToggle label="Bind Refresh Token to Fingerprint" checked={config.security.bindRefreshTokenToFingerprint ?? true} onChange={(v) => update('security', 'bindRefreshTokenToFingerprint', v)}
                                        hint="A refresh from a different browser or User-Agent than the issuing one is refused." />
                                    <ConfigToggle label="Allow Refresh Token Mismatch (forensic)" checked={config.security.allowRefreshTokenMismatch ?? false} onChange={(v) => update('security', 'allowRefreshTokenMismatch', v)}
                                        hintTone={config.security.allowRefreshTokenMismatch ? 'warn' : 'muted'}
                                        hint="Mismatches are written to the audit log but the refresh still succeeds. While on, the two bindings above protect nothing; use it to observe before enforcing." />
                                </div>
                                <SaveButton saving={saving === 'securityBinding'} onClick={() => saveSecurityFields(['bindJwtToIp', 'bindRefreshTokenToIp', 'bindRefreshTokenToFingerprint', 'allowRefreshTokenMismatch'], 'securityBinding')} label="Save Binding Rules" />
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
                                    Settings for running behind a load balancer or reverse proxy. The proxy mode flag lives in the
                                    <strong> security</strong> section and its Save writes only that flag. The trusted CIDRs live in the
                                    <strong> http</strong> section, so that Save writes the whole HTTP section, including any unsaved edits
                                    on the General → HTTP card.
                                </div>
                                <ConfigToggle label="Behind Reverse Proxy" checked={config.security.behindReverseProxy ?? false} onChange={(v) => update('security', 'behindReverseProxy', v)}
                                    hintTone={config.security.behindReverseProxy && !config.http.trustedProxyCidrs ? 'warn' : 'muted'}
                                    hint={config.security.behindReverseProxy && !config.http.trustedProxyCidrs
                                        ? 'On, but no trusted CIDRs are listed: only loopback is trusted, so every client will appear to come from the proxy and per-IP limits and bindings collapse onto one address.'
                                        : 'Rate limiting and IP binding use the client address from X-Forwarded-For sent by a proxy in the ranges below. If on with no proxy in front, any client can forge its address.'} />
                                <SaveButton saving={saving === 'securityProxy'} onClick={() => saveSecurityFields(['behindReverseProxy'], 'securityProxy')} label="Save Proxy Mode" />
                                <ConfigInput label="Trusted Proxy CIDRs" value={config.http.trustedProxyCidrs} onChange={(v) => update('http', 'trustedProxyCidrs', v)} placeholder="10.0.0.0/8, 172.16.0.0/12"
                                    hint="Only proxies in these ranges may set forwarded headers. Empty means loopback only. Name the actual proxy subnet, not RFC1918 wholesale." />
                                <SaveButton saving={saving === 'http'} onClick={() => saveSection('http', config.http, 'http')} label="Save HTTP Section" />
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
                                {securityPolicyError && <InlineNotice notice={securityPolicyError} />}
                                {securityPolicy && (
                                    <>
                                        <div className="bg-green-50 dark:bg-green-900/20 border border-green-300 dark:border-green-800 rounded p-3 text-xs text-green-800 dark:text-green-300">
                                            Stored in the DB-backed <code className="bg-gray-900/40 px-1 rounded">SecurityPolicy</code> table.
                                            Changes take effect on the next request scope after save (step-up MFA required).
                                        </div>
                                        <div className="text-[11px] text-gray-500 dark:text-gray-500">Login lockout moved to the <strong>Login Protection</strong> card above.</div>
                                        <h4 className="text-xs font-semibold text-gray-600 uppercase tracking-wide">Session</h4>
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                            <ConfigNumber label="Session Idle Timeout (min, 0 = none)" value={securityPolicy.sessionIdleTimeoutMinutes} onChange={(v) => updateSecurityPolicyField('sessionIdleTimeoutMinutes', v)}
                                                hint="Minutes without any request before the session ends and the user must log in again. 0 means a session never ends from inactivity." />
                                            <ConfigNumber label="Max Concurrent Sessions (0 = unlimited)" value={securityPolicy.maxConcurrentSessions} onChange={(v) => updateSecurityPolicyField('maxConcurrentSessions', v)}
                                                hint="Devices or browsers one user may be logged in from at once. Logging in beyond this ends the oldest session." />
                                            <ConfigNumber label="Max Session Lifetime (days, 0 = unlimited)" value={securityPolicy.maxSessionLifetimeDays} onChange={(v) => updateSecurityPolicyField('maxSessionLifetimeDays', v)}
                                                hint="Hard cap from first login, however active the user is; after this a fresh login is required. 0 removes the cap." />
                                        </div>
                                        <h4 className="text-xs font-semibold text-gray-600 uppercase tracking-wide pt-2">Approval &amp; mTLS</h4>
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                            <ConfigToggle label="Allow System Super Self-Approval" checked={securityPolicy.allowSystemSuperSelfApproval ?? false} onChange={(v) => updateSecurityPolicyField('allowSystemSuperSelfApproval', v)}
                                                hintTone={securityPolicy.allowSystemSuperSelfApproval ? 'warn' : 'muted'}
                                                hint="Members of system-super may approve certificate requests they submitted themselves. Keeps a single-operator install working, and removes the two-person check for those accounts." />
                                            <ConfigToggle label="Require mTLS OCSP Check" checked={securityPolicy.requireMtlsOcspCheck ?? false} onChange={(v) => updateSecurityPolicyField('requireMtlsOcspCheck', v)}
                                                hint="Client certificates presented for mTLS login are checked for revocation against the issuing CA. Off means a revoked certificate still logs in until it expires." />
                                        </div>
                                        <h4 className="text-xs font-semibold text-gray-600 uppercase tracking-wide pt-2">MFA / Step-Up</h4>
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                            <ConfigNumber label="Step-Up Token TTL (sec, 30-300)" value={securityPolicy.stepUpTokenTtlSeconds} onChange={(v) => updateSecurityPolicyField('stepUpTokenTtlSeconds', v)}
                                                hint="How long a completed step-up MFA proof stays valid for the sensitive operation it was requested for. Values outside 30–300 are clamped on save." />
                                            <ConfigNumber label="MFA Session TTL (sec, 60-900)" value={securityPolicy.mfaSessionTtlSeconds} onChange={(v) => updateSecurityPolicyField('mfaSessionTtlSeconds', v)}
                                                hint="Time allowed between a correct password and completing the MFA step; after that the login starts over. Clamped to 60–900." />
                                            <ConfigNumber label="WebAuthn Challenge TTL (sec, 30-600)" value={securityPolicy.webAuthnChallengeTtlSeconds} onChange={(v) => updateSecurityPolicyField('webAuthnChallengeTtlSeconds', v)}
                                                hint="How long a security-key prompt stays answerable before it must be requested again. Clamped to 30–600." />
                                            <ConfigToggle label="Require WebAuthn User Verification" checked={securityPolicy.requireWebAuthnUserVerification ?? true} onChange={(v) => updateSecurityPolicyField('requireWebAuthnUserVerification', v)}
                                                hint="Security keys must verify the person (PIN or biometric), not just presence. Off lets anyone holding the key authenticate with a touch." />
                                            <ConfigNumber label="Step-Up Failure Threshold" value={securityPolicy.stepUpFailureThreshold} onChange={(v) => updateSecurityPolicyField('stepUpFailureThreshold', v)}
                                                hint="Failed step-up attempts by one user within the window before step-up is locked for that user." />
                                            <ConfigNumber label="Step-Up Failure Window (sec)" value={securityPolicy.stepUpFailureWindowSeconds} onChange={(v) => updateSecurityPolicyField('stepUpFailureWindowSeconds', v)}
                                                hint="Sliding window, in seconds, over which those failures are counted." />
                                        </div>
                                        <h4 className="text-xs font-semibold text-gray-600 uppercase tracking-wide pt-2">OCSP Responder</h4>
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                            <ConfigToggle label="Allow CA Direct Signing" checked={securityPolicy.allowCaDirectSigning ?? false} onChange={(v) => updateSecurityPolicyField('allowCaDirectSigning', v)}
                                                hint="A CA with no delegated OCSP responder certificate signs responses with its own key. Off means such a CA answers Unauthorized until a responder certificate is issued." />
                                            <ConfigToggle label="Require NoCheck Extension" checked={securityPolicy.requireNoCheckExtension ?? false} onChange={(v) => updateSecurityPolicyField('requireNoCheckExtension', v)}
                                                hint="Refuse to use a delegated responder certificate that lacks id-pkix-ocsp-nocheck. Without it clients try to check the responder's own status, which can loop. Off only logs a warning." />
                                            <ConfigToggle label="Require Signed OCSP Requests" checked={securityPolicy.requireSignedRequests ?? false} onChange={(v) => updateSecurityPolicyField('requireSignedRequests', v)}
                                                hintTone={securityPolicy.requireSignedRequests ? 'warn' : 'muted'}
                                                hint="Unsigned requests are rejected with SigRequired. Browsers, OpenSSL and most TLS stacks do not sign OCSP requests, so this breaks ordinary revocation checking." />
                                            <ConfigNumber label="Default Good Response TTL (min)" value={securityPolicy.defaultGoodResponseTtlMinutes} onChange={(v) => updateSecurityPolicyField('defaultGoodResponseTtlMinutes', v)}
                                                hint={`For "good" answers. ${ocspTtlHint}`} />
                                            <ConfigNumber label="Default Revoked Response TTL (min)" value={securityPolicy.defaultRevokedResponseTtlMinutes} onChange={(v) => updateSecurityPolicyField('defaultRevokedResponseTtlMinutes', v)}
                                                hint={`For "revoked" answers. ${ocspTtlHint}`} />
                                            <ConfigNumber label="Max Single-Requests per OCSPRequest" value={securityPolicy.maxSingleRequestsPerRequest} onChange={(v) => updateSecurityPolicyField('maxSingleRequestsPerRequest', v)}
                                                hint="Certificates one OCSP request may ask about at once; larger requests are rejected. Limits the work a single request can demand." />
                                        </div>
                                        <h4 className="text-xs font-semibold text-gray-600 uppercase tracking-wide pt-2">Controlled-User Ceremonies</h4>
                                        <p className="text-[11px] text-gray-500 dark:text-gray-500">
                                            <strong>User quorum</strong> = approvals required to promote / demote / delete a controlled user (admin / operator / CA-admin)
                                            when initiated by a non-super. Distinct from the <strong>key quorum</strong> (per-tenant CA-ceremony approvals, set in Tenants).
                                            The initiator is always excluded, so the effective minimum is 1 other approver.
                                        </p>
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                            <ConfigNumber label="User Quorum (min 1)" value={securityPolicy.userQuorum} onChange={(v) => updateSecurityPolicyField('userQuorum', v)} fallback={1}
                                                hint="Approvals from other people. The initiator is always excluded, so the effective minimum is 1 other approver. Tenants and CAs may set a lower figure, never a higher one." />
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
                                {securityPolicyError && <InlineNotice notice={securityPolicyError} />}
                                {securityPolicy && (
                                    <>
                                        <div className="bg-amber-50 dark:bg-amber-900/20 border border-amber-300 dark:border-amber-800 rounded p-3 text-xs text-amber-800 dark:text-amber-200">
                                            Users must acknowledge this banner before reaching the login page. Stored on the
                                            <code className="bg-gray-900/40 px-1 rounded mx-1">SecurityPolicy</code>row; step-up MFA required to save.
                                            Leave empty to skip the banner step entirely. This Save writes the whole Security Policy row,
                                            including any unsaved edits in the Security Policy card above.
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
                                {policyError && <InlineNotice notice={policyError} />}
                                {policy && (
                                    <>
                                        <p className="text-[11px] text-gray-500 dark:text-gray-500">
                                            Applies to local accounts at their next password change; LDAP users are governed by the directory.
                                            The "require at least one" switches and the minimum counts are independent rules: a count of 2 is
                                            enforced even with its switch off, and a switch on with a count of 0 demands exactly one.
                                        </p>
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                            {Object.entries(policy).filter(([key]) => policyNumberFields.includes(key)).map(([key, value]) => (
                                                <div key={key}>
                                                    <label className={labelClass}>{POLICY_FIELDS[key]?.label ?? key}</label>
                                                    <input
                                                        type="text"
                                                        inputMode="numeric"
                                                        value={value != null ? String(value) : ''}
                                                        onChange={(e) => { const v = e.target.value.replace(/\D/g, ''); updatePolicyField(key, v === '' ? '' : parseInt(v)); }}
                                                        onBlur={() => { if (!value && value !== 0) updatePolicyField(key, 0); }}
                                                        className={inputClass}
                                                    />
                                                    {POLICY_FIELDS[key] && <FieldHint>{POLICY_FIELDS[key].hint}</FieldHint>}
                                                </div>
                                            ))}
                                            {Object.entries(policy).filter(([key]) => policyBoolFields.includes(key)).map(([key, value]) => (
                                                <div key={key}>
                                                    <div className="flex items-center gap-2">
                                                        <input
                                                            id={`pw-${key}`}
                                                            type="checkbox"
                                                            checked={!!value}
                                                            onChange={(e) => updatePolicyField(key, e.target.checked)}
                                                            className="w-4 h-4 bg-gray-50 dark:bg-gray-900 border-gray-300 dark:border-gray-700 rounded"
                                                        />
                                                        <label htmlFor={`pw-${key}`} className="text-xs text-gray-700 dark:text-gray-300">{POLICY_FIELDS[key]?.label ?? key}</label>
                                                    </div>
                                                    {POLICY_FIELDS[key] && <FieldHint className="pl-6">{POLICY_FIELDS[key].hint}</FieldHint>}
                                                </div>
                                            ))}
                                        </div>
                                        {policyProblems.map((p) => <FieldHint key={p} tone="warn">{p} Save is blocked until this is fixed.</FieldHint>)}
                                        <SaveButton saving={policySaving} disabled={policyProblems.length > 0} onClick={handleSavePolicy} label="Save Policy" />
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
                                    <ConfigToggle label="Enabled" checked={config.mtls?.enabled ?? false} onChange={(v) => update('mtls', 'enabled', v)}
                                        hint="Offers certificate-based login: connections to the auth subdomain are asked for a client certificate; every other hostname gets a normal handshake." />
                                    <ConfigInput label="Auth Subdomain" value={config.mtls?.authSubdomain} onChange={(v) => update('mtls', 'authSubdomain', v)} placeholder="mtls.ca.example.com"
                                        hint="Hostname whose TLS handshake requests a client certificate. Needs DNS pointing here and the Web TLS certificate's SANs must include it, or clients fail before login." />
                                    <ConfigInput label="Required Paths (comma-separated)" value={listToStr(config.mtls?.requiredPaths)} onChange={(v) => update('mtls', 'requiredPaths', strToList(v))}
                                        hint="Paths that refuse any request not carrying a valid client certificate, regardless of hostname." />
                                    <div className="md:col-span-2">
                                        <ConfigInput label="Trusted CA Cert Paths (comma-separated file paths)" value={listToStr(config.mtls?.trustedCaCertPaths)} onChange={(v) => update('mtls', 'trustedCaCertPaths', strToList(v))}
                                            hint="PEM files of the CAs whose certificates count as a login. A certificate from any other issuer is rejected at the handshake." />
                                    </div>
                                </div>
                                <SaveButton saving={saving === 'mtls'} onClick={() => saveSection('mtls', config.mtls, 'mtls')} />
                            </div>
                        )}
                    </div>

                    {/* IP Whitelist */}
                    <div className={cardClass}>
                        <SectionHeader title="IP Whitelist" expanded={expanded === 'ipwhitelist'} onToggle={() => toggle('ipwhitelist')}
                            description={config.ipWhitelist?.enabled ? 'Enabled — managed at /admin/whitelists' : 'Disabled (master kill switch)'} tag="live" />
                        {expanded === 'ipwhitelist' && (
                            <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-4">
                                <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-300 dark:border-blue-800 rounded p-3 text-xs text-blue-800 dark:text-blue-300">
                                    CIDR allow-list rules now live in the centralized <code className="mono">Whitelists</code> table and
                                    are managed at <Link to="/whitelists" className="underline hover:text-blue-200">/admin/whitelists</Link>.
                                    This card only exposes the master kill switch and the path-based exempt list — both of which stay in
                                    <code className="mono"> config.yaml</code>.
                                </div>
                                <ConfigToggle label="Enabled (master kill switch)" checked={config.ipWhitelist?.enabled ?? true} onChange={(v) => update('ipWhitelist', 'enabled', v)}
                                    hintTone={config.ipWhitelist?.enabled === false ? 'warn' : 'muted'}
                                    hint={config.ipWhitelist?.enabled === false
                                        ? 'Off: every rule on the Whitelists page is ignored and all addresses reach every endpoint.'
                                        : 'On: each request is matched against the Whitelists rules. Turning this off bypasses all of them at once.'} />
                                <ConfigInput label="Exempt Paths (comma-separated)" value={(config.ipWhitelist?.exemptPaths || []).join(', ')}
                                    onChange={(v) => update('ipWhitelist', 'exemptPaths', v.split(',').map((s: string) => s.trim()).filter(Boolean))}
                                    placeholder="/api/v1/auth, /api/v1/public/ca"
                                    hint="Path prefixes that always pass, whatever the rules say. A prefix here undoes any tightening of that path on the Whitelists page." />
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
                                    Each row means: one client IP may make at most <em>Max Requests</em> to that protocol within
                                    <em> Window Min</em> minutes; further requests get 429 until the window passes.
                                </div>
                                {rateLimitsLoading && <div className="text-sm text-gray-600 dark:text-gray-400">Loading...</div>}
                                {rateLimitsError && <InlineNotice notice={rateLimitsError} />}
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
                                    <ConfigToggle label="Enabled" checked={config.ldapAuth.enabled} onChange={(v) => update('ldapAuth', 'enabled', v)}
                                        hint="Logins are verified by binding to the directory as the user; a successful bind is accepted as proof of the password. Applies live, no restart." />
                                    <ConfigInput label="Host" value={config.ldapAuth.host} onChange={(v) => update('ldapAuth', 'host', v)}
                                        hint="Directory server this instance binds to. Whoever controls this host can approve any login, so change it only over a verified channel." />
                                    <ConfigNumber label="Port" value={config.ldapAuth.port} onChange={(v) => update('ldapAuth', 'port', v)} fallback={389}
                                        hint="389 for plain LDAP, 636 for LDAPS." />
                                    <ConfigToggle label="Use SSL" checked={config.ldapAuth.useSsl} onChange={(v) => update('ldapAuth', 'useSsl', v)}
                                        hintTone={config.ldapAuth.useSsl ? 'muted' : 'warn'}
                                        hint="Connects over LDAPS. Off sends the service-account password and every user's login password to the directory in clear text; there is no StartTLS path." />
                                    <ConfigInput label="Search Base DN" value={config.ldapAuth.searchBaseDn} onChange={(v) => update('ldapAuth', 'searchBaseDn', v)}
                                        hint="Subtree searched for the user's entry, e.g. OU=People,DC=example,DC=com." />
                                    <ConfigInput label="Search Filter" value={config.ldapAuth.searchFilter} onChange={(v) => update('ldapAuth', 'searchFilter', v)}
                                        hint="LDAP filter locating the user; {0} is replaced with the login name." />
                                    <ConfigInput label="Bind DN" value={config.ldapAuth.bindDn} onChange={(v) => update('ldapAuth', 'bindDn', v)}
                                        hint="Service account used to search for users before they authenticate. Blank attempts an anonymous search." />
                                    {/* The bind password was previously not editable here at all, so it could
                                        only be set in config.yaml. It loads as *** when one is stored; leaving
                                        that placeholder untouched keeps the existing password. */}
                                    <ConfigInput label="Bind Password" value={config.ldapAuth.bindPassword} onChange={(v) => update('ldapAuth', 'bindPassword', v)} type="password" placeholder="Leave unchanged to keep current"
                                        hint="Shown as *** when one is stored. Leave it as-is to keep the current password; type a new one to replace it." />
                                    <ConfigToggle label="Group Sync Enabled" checked={config.ldapAuth.groupSyncEnabled} onChange={(v) => update('ldapAuth', 'groupSyncEnabled', v)}
                                        hint="The LdapGroupSync job periodically re-reads each LDAP user's groups and applies the mappings below, granting and revoking local group membership to match." />
                                    <ConfigToggle label="Auto Provision Users" checked={config.ldapAuth.autoProvisionUsers} onChange={(v) => update('ldapAuth', 'autoProvisionUsers', v)}
                                        hint="A first successful LDAP login creates the local account automatically. Off means only users an administrator created here can log in." />
                                    <ConfigInput label="Group Search Base DN" value={config.ldapAuth.groupSearchBaseDn} onChange={(v) => update('ldapAuth', 'groupSearchBaseDn', v)}
                                        hint="Subtree searched for groups during sync." />
                                    <ConfigInput label="Group Search Filter" value={config.ldapAuth.groupSearchFilter} onChange={(v) => update('ldapAuth', 'groupSearchFilter', v)}
                                        hint="Filter selecting the groups a user belongs to; {0} is replaced with the user's DN." />
                                    <ConfigInput label="Group Member Attribute" value={config.ldapAuth.groupMemberAttribute} onChange={(v) => update('ldapAuth', 'groupMemberAttribute', v)}
                                        hint="Attribute on the user entry listing its groups (memberOf on Active Directory)." />
                                    <div className="md:col-span-2">
                                        <ConfigInput label="Group to Role Mappings (JSON)" value={config.ldapAuth.groupToRoleMappings} onChange={(v) => update('ldapAuth', 'groupToRoleMappings', v)} placeholder='{"CN=Admins,DC=...": "CaAdmin"}'
                                            hint="JSON object mapping an LDAP group DN to a local group name. LDAP groups not listed here grant nothing." />
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
                            description={config.certPolicy?.enabled ? `Min RSA ${config.certPolicy.minRsaKeySize || 2048}` : 'Disabled'} tag="live" />
                        {expanded === 'certPolicy' && (
                            <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigToggle label="Enabled" checked={config.certPolicy?.enabled ?? false} onChange={(v) => update('certPolicy', 'enabled', v)}
                                        hintTone={config.certPolicy?.enabled ? 'muted' : 'warn'}
                                        hint="These rules are checked at every issuance, whatever profile is used. Off means none of them block anything." />
                                    <ConfigNumber label="Min RSA Key Size" value={config.certPolicy?.minRsaKeySize} onChange={(v) => update('certPolicy', 'minRsaKeySize', v)} fallback={0}
                                        hint="Requests with an RSA key shorter than this are refused. 0 sets no minimum." />
                                    <ConfigToggle label="Require SANs" checked={config.certPolicy?.requireSans ?? false} onChange={(v) => update('certPolicy', 'requireSans', v)}
                                        hint="Requests without a Subject Alternative Name are refused. Browsers ignore the Common Name, so a certificate without SANs fails hostname checks anyway." />
                                    <div className="md:col-span-2">
                                        <ConfigInput label="Forbidden Algorithms (comma-separated)" value={listToStr(config.certPolicy?.forbiddenAlgorithms)} onChange={(v) => update('certPolicy', 'forbiddenAlgorithms', strToList(v))} placeholder="MD5, SHA1"
                                            hint="Signature algorithms refused at issuance, e.g. SHA1WithRSA, MD5WithRSA." />
                                    </div>
                                    <div className="md:col-span-2">
                                        <label className={labelClass}>Algorithm Sunset Rules (one per line: &quot;RSA-2048:2030-01-01&quot;)</label>
                                        <textarea
                                            value={listToLines(config.certPolicy?.algorithmSunsetRules)}
                                            onChange={(e) => update('certPolicy', 'algorithmSunsetRules', linesToList(e.target.value))}
                                            placeholder={"RSA-2048:2030-01-01\nSHA-256:2035-01-01"}
                                            rows={4}
                                            className={`${inputClass} font-mono text-xs`}
                                        />
                                        <FieldHint>From the date onward, issuance with that algorithm (or algorithm-keysize pair) is refused. Until then the rule does nothing, so sunsets can be entered years ahead.</FieldHint>
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
                                    <ConfigToggle label="Enabled" checked={config.autoRenewal?.enabled ?? false} onChange={(v) => update('autoRenewal', 'enabled', v)}
                                        hint="The AutoRenewal job creates renewal requests for certificates approaching expiry, with a fresh key pair. Off means certificates simply expire unless someone renews them." />
                                    <ConfigNumber label="Renew Days Before Expiry" value={config.autoRenewal?.renewDaysBeforeExpiry} onChange={(v) => update('autoRenewal', 'renewDaysBeforeExpiry', v)} fallback={0}
                                        hint="Certificates within this many days of expiry are renewed on the job's next run. Leave enough margin for the renewal to be approved and deployed." />
                                    <ConfigToggle label="Auto Approve" checked={config.autoRenewal?.autoApprove ?? false} onChange={(v) => update('autoRenewal', 'autoApprove', v)}
                                        hint="Renewals are issued without an administrator approving each one, unless the profile itself demands approval. Off means every renewal waits in the approval queue and expires if nobody acts." />
                                </div>
                                <ScheduleMovedNote job="AutoRenewal" />
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
                                    <ConfigToggle label="Enabled" checked={config.certExpiryNotification?.enabled ?? false} onChange={(v) => update('certExpiryNotification', 'enabled', v)}
                                        hint="The CertExpiryNotification job emails and webhooks a warning as certificates approach expiry. Needs Email or Webhook configured under Integrations to reach anyone." />
                                    <ConfigInput label="Warning Days (comma-separated)" value={config.certExpiryNotification?.warningDays} onChange={(v) => update('certExpiryNotification', 'warningDays', v)} placeholder="90,60,30,14,7"
                                        hint="A notice is sent once as a certificate crosses each of these day marks before expiry. The list is checked in order and the first match fires." />
                                </div>
                                <ScheduleMovedNote job="CertExpiryNotification" />
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
                                    <ConfigToggle label="Enabled" checked={config.complianceScan?.enabled ?? false} onChange={(v) => update('complianceScan', 'enabled', v)}
                                        hint="The Compliance job scans issued certificates and records findings. It reports; it never revokes or blocks." />
                                    <div />
                                    <div>
                                        <ConfigNumber label="Min RSA Key Size" value={config.complianceScan?.minRsaKeySize} onChange={(v) => update('complianceScan', 'minRsaKeySize', v)} fallback={0}
                                            hint="Issued certificates with a shorter RSA key are flagged as weak." />
                                        <p className="text-[10px] text-gray-600 mt-1">Policy: {config.certPolicy?.enabled ? `blocks issuance below ${config.certPolicy?.minRsaKeySize || 'unset'}` : 'enforcement off'}</p>
                                    </div>
                                    <div>
                                        <ConfigNumber label="Warn Over Validity Days" value={config.complianceScan?.warnOverValidityDays} onChange={(v) => update('complianceScan', 'warnOverValidityDays', v)} fallback={0} />
                                        <p className="text-[10px] text-gray-600 mt-1">Reports only — it never blocks issuance. The enforced ceiling is per tenant, under Tenants &amp; Quotas.</p>
                                    </div>
                                    <div className="md:col-span-2">
                                        <ConfigInput label="Deprecated Algorithms (comma-separated)" value={listToStr(config.complianceScan?.deprecatedAlgorithms)} onChange={(v) => update('complianceScan', 'deprecatedAlgorithms', strToList(v))} placeholder="MD5, SHA1, RSA-1024"
                                            hint="Issued certificates signed with these are flagged." />
                                        <p className="text-[10px] text-gray-600 mt-1">Policy forbids at issuance: {listToStr(config.certPolicy?.forbiddenAlgorithms) || 'none'}</p>
                                    </div>
                                </div>
                                <ScheduleMovedNote job="Compliance" />
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
                            description={config.email?.enabled ? `${config.email.authMethod} — ${config.email.smtpHost}` : 'Disabled'} tag="live" />
                        {expanded === 'email' && (
                            <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigToggle label="Enabled" checked={config.email.enabled} onChange={(v) => update('email', 'enabled', v)}
                                        hint="Expiry notices, alerts and approval mail go out over SMTP. Off means they are dropped silently." />
                                    <ConfigInput label="SMTP Host" value={config.email.smtpHost} onChange={(v) => update('email', 'smtpHost', v)} placeholder="smtp.example.com" />
                                    <ConfigNumber label="SMTP Port" value={config.email.smtpPort} onChange={(v) => update('email', 'smtpPort', v)} fallback={587}
                                        hint="587 for submission with STARTTLS, 465 for implicit TLS, 25 for unauthenticated relay." />
                                    <ConfigToggle label="Use TLS" checked={config.email.useTls} onChange={(v) => update('email', 'useTls', v)}
                                        hintTone={config.email.useTls ? 'muted' : 'warn'}
                                        hint="Encrypts the connection to the mail server. Off sends the credentials and every message in clear text." />
                                    <ConfigSelect label="Auth Method" value={config.email.authMethod || 'Password'} options={['Password', 'OAuth2Token', 'OAuth2ClientCredentials']} onChange={(v) => update('email', 'authMethod', v)}
                                        hint="Password: username and password. OAuth2Token: a token you obtained elsewhere, which expires and must be replaced by hand. OAuth2ClientCredentials: tokens are fetched automatically from the token URL." />
                                    <ConfigInput label="Username" value={config.email.username} onChange={(v) => update('email', 'username', v)} />

                                    {(config.email.authMethod === 'Password' || !config.email.authMethod) && (
                                        <ConfigInput label="Password" value={config.email.password} onChange={(v) => update('email', 'password', v)} type="password" />
                                    )}

                                    {config.email.authMethod === 'OAuth2Token' && (
                                        <ConfigInput label="OAuth2 Access Token" value={config.email.oAuth2AccessToken} onChange={(v) => update('email', 'oAuth2AccessToken', v)} type="password"
                                            hint="Sent as-is with each message. Mail stops when it expires." />
                                    )}

                                    {config.email.authMethod === 'OAuth2ClientCredentials' && (
                                        <>
                                            <ConfigInput label="OAuth2 Client ID" value={config.email.oAuth2ClientId} onChange={(v) => update('email', 'oAuth2ClientId', v)} />
                                            <ConfigInput label="OAuth2 Client Secret" value={config.email.oAuth2ClientSecret} onChange={(v) => update('email', 'oAuth2ClientSecret', v)} type="password" />
                                            <ConfigInput label="OAuth2 Token URL" value={config.email.oAuth2TokenUrl} onChange={(v) => update('email', 'oAuth2TokenUrl', v)} placeholder="https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
                                                hint="Token endpoint tokens are fetched from. Google: https://oauth2.googleapis.com/token" />
                                            <ConfigInput label="OAuth2 Scopes" value={config.email.oAuth2Scopes} onChange={(v) => update('email', 'oAuth2Scopes', v)} placeholder="https://outlook.office365.com/.default"
                                                hint="Space-separated. Empty defaults to the Microsoft 365 SMTP scope. Google: https://mail.google.com/" />
                                        </>
                                    )}

                                    <ConfigInput label="From Address" value={config.email.fromAddress} onChange={(v) => update('email', 'fromAddress', v)} placeholder="ca@example.com"
                                        hint="Must be an address the mail server allows this account to send as, or messages are rejected." />
                                    <ConfigInput label="From Name" value={config.email.fromName} onChange={(v) => update('email', 'fromName', v)} />
                                    <div className="md:col-span-2">
                                        <ConfigInput label="Admin Recipients (comma-separated)" value={config.email.adminRecipients} onChange={(v) => update('email', 'adminRecipients', v)} placeholder="admin@example.com"
                                            hint="Addresses that receive system alerts (backup failures, scheduler failures, security changes). Empty means alerts reach nobody by mail." />
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
                                    <ConfigToggle label="Enabled" checked={config.webhook?.enabled ?? false} onChange={(v) => update('webhook', 'enabled', v)}
                                        hint="Certificate lifecycle events are POSTed to the endpoints in config.yaml. Off means no deliveries are attempted." />
                                    <ConfigNumber label="Max Retries" value={config.webhook?.maxRetries} onChange={(v) => update('webhook', 'maxRetries', v)} fallback={3}
                                        hint="Further attempts after a failed delivery before the event is dropped." />
                                    <ConfigNumber label="Retry Delay Seconds" value={config.webhook?.retryDelaySeconds} onChange={(v) => update('webhook', 'retryDelaySeconds', v)} fallback={10}
                                        hint="Wait before the first retry; each later retry waits exponentially longer." />
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
                                    <ConfigToggle label="Enabled" checked={config.certManager?.enabled ?? false} onChange={(v) => update('certManager', 'enabled', v)}
                                        hint="Opens /api/v1/integration/cert-manager/sign to any caller presenting the API key; that caller can obtain certificates without a human approval." />
                                    <ConfigInput label="API Key" value={config.certManager?.apiKey} onChange={(v) => update('certManager', 'apiKey', v)} type="password"
                                        hint="Shared secret cert-manager sends in X-API-Key. Use a long random value; anyone holding it can request certificates." />
                                    <ConfigInput label="Default Cert Profile ID" value={config.certManager?.defaultCertProfileId} onChange={(v) => update('certManager', 'defaultCertProfileId', v)}
                                        hint="Certificate profile applied when a signing request names none." />
                                    <ConfigInput label="Default Signing Profile ID" value={config.certManager?.defaultSigningProfileId} onChange={(v) => update('certManager', 'defaultSigningProfileId', v)}
                                        hint="Decides which CA signs when the request names no signing profile." />
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
                                    <ConfigToggle label="Enabled" checked={config.integrationApi?.enabled ?? false} onChange={(v) => update('integrationApi', 'enabled', v)}
                                        hint="Opens the infrastructure-as-code endpoints (Terraform, Ansible) to any caller presenting the API key." />
                                    <ConfigInput label="API Key" value={config.integrationApi?.apiKey} onChange={(v) => update('integrationApi', 'apiKey', v)} type="password"
                                        hint="Shared secret sent in X-API-Key. Use a long random value and rotate it if it leaks." />
                                </div>
                                <SaveButton saving={saving === 'integrationApi'} onClick={() => saveSection('integration-api', config.integrationApi, 'integrationApi')} />
                            </div>
                        )}
                    </div>

                    {/* ACME Policies */}
                    <div className={cardClass}>
                        <SectionHeader title="ACME Policies" expanded={expanded === 'acme'} onToggle={() => toggle('acme')}
                            description={`EAB: ${config.acme?.externalAccountRequired ? 'Required' : 'Off'}, CAA: ${config.acme?.enforceCaa ? 'On' : 'Off'}, ToS: ${config.acme?.termsOfServiceUrl ? 'Published' : 'None'}`} tag="live" />
                        {expanded === 'acme' && (
                            <div className="p-4 border-t border-gray-300 dark:border-gray-700 space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigToggle label="External Account Required" checked={config.acme?.externalAccountRequired ?? false} onChange={(v) => update('acme', 'externalAccountRequired', v)}
                                        hint="New ACME accounts must carry an externalAccountBinding signed with a pre-shared key issued here. Clients without one cannot register, which is how you keep the directory from being open to anyone who can reach it." />
                                    <ConfigToggle label="Enforce CAA" checked={config.acme?.enforceCaa ?? false} onChange={(v) => update('acme', 'enforceCaa', v)}
                                        hint="Before issuing, the DNS CAA records for each requested name are checked; a record that does not name this CA blocks issuance. Needs working DNS resolution from this host." />
                                </div>
                                <ConfigInput label="Terms of Service URL" value={config.acme?.termsOfServiceUrl} onChange={(v) => update('acme', 'termsOfServiceUrl', v)} placeholder="https://ca.example.com/terms (leave empty to publish none)" />
                                <p className="text-xs text-gray-600 dark:text-gray-400">
                                    Setting this advertises the URL in the ACME directory <em>and</em> makes account
                                    registration require agreement. Leave it empty and clients register without agreeing —
                                    per RFC 8555 a server may only demand agreement to terms it actually publishes.
                                </p>
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
                                    <ConfigToggle label="Enabled" checked={config.policySync?.enabled ?? false} onChange={(v) => update('policySync', 'enabled', v)}
                                        hint="Profile definitions are imported from YAML files in the directory below, GitOps-style. Imported files overwrite the database copy of a profile with the same name." />
                                    <ConfigInput label="Policy Directory" value={config.policySync?.policyDirectory} onChange={(v) => update('policySync', 'policyDirectory', v)} placeholder="/etc/modular-ca/policies"
                                        hint="Directory scanned for *.yaml profile files. A relative path resolves from the application directory." />
                                    <ConfigToggle label="Sync On Startup" checked={config.policySync?.syncOnStartup ?? false} onChange={(v) => update('policySync', 'syncOnStartup', v)}
                                        hint="Import runs every time the service starts, so edits made in the UI to a file-managed profile are reverted at the next restart." />
                                </div>
                                <div className="flex gap-2">
                                    <SaveButton saving={saving === 'policySync'} onClick={() => saveSection('policy-sync', config.policySync, 'policySync')} />
                                    <button
                                        onClick={async () => {
                                            setSaving('policySyncNow');
                                            try {
                                                const result = await apiPostWithMfa('/api/v1/admin/policy/sync', {}, requireStepUp, StepUpOps.PolicySync);
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
                                    <ConfigToggle label="Enabled" checked={config.alert?.enabled ?? false} onChange={(v) => update('alert', 'enabled', v)}
                                        hint="Security and operational alerts (stale backups, failing jobs, config changes) are sent to the admin recipients and webhooks. Off means they are only logged." />
                                    <ConfigSelect label="Minimum Severity" value={config.alert?.minimumSeverity || 'Warning'} options={['Critical', 'Warning', 'Info']} onChange={(v) => update('alert', 'minimumSeverity', v)}
                                        hint="Alerts below this severity are not sent. Info includes routine events and is noisy; Critical alone would drop backup and scheduler warnings until they escalate." />
                                    <ConfigNumber label="Cooldown Minutes" value={config.alert?.cooldownMinutes} onChange={(v) => update('alert', 'cooldownMinutes', v)}
                                        hint="Repeat alerts of the same type within this window are suppressed, so a flapping condition sends one message rather than hundreds." />
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
                                <ConfigSelect label="Min Level" value={config.logging.minLevel || 'Information'} options={['Debug', 'Information', 'Warning', 'Error']} onChange={(v) => update('logging', 'minLevel', v)}
                                    hint="Events below this level are discarded. Debug records every request in detail and fills the disk quickly; Warning hides normal operation, so a quiet log no longer means a healthy service." />
                                <div className="text-xs text-gray-600">
                                    Log level changes take effect immediately — no restart needed. This Save writes only the level; the
                                    storage fields below have their own Save.
                                </div>
                                <SaveButton saving={saving === 'logging'} onClick={() => saveSection('logging', { minLevel: config.logging.minLevel }, 'logging')} label="Save Level" />
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
                                    <ConfigInput label="File Path" value={config.logging.filePath} onChange={(v) => update('logging', 'filePath', v)}
                                        hint="Log file path; the date is inserted before the extension on each daily roll. A relative path resolves from the application directory." />
                                    <ConfigNumber label="Retention Days" value={config.logging.retentionDays} onChange={(v) => update('logging', 'retentionDays', v)} fallback={30}
                                        hint="Log files older than this are deleted. The audit log is separate and is not affected." />
                                    <ConfigNumber label="Max File Size (MB)" value={config.logging.maxFileSizeMb ?? 100} onChange={(v) => update('logging', 'maxFileSizeMb', v)} fallback={100}
                                        hint="A file that reaches this size rolls to a new one, in addition to the daily roll." />
                                    <ConfigSelect label="Console Format" value={config.logging.consoleFormat || 'Auto'} options={['Auto', 'Systemd', 'Json', 'Text']} onChange={(v) => update('logging', 'consoleFormat', v)} />
                                </div>
                                <div className="text-xs text-gray-600">
                                    Log files roll daily and when they reach the max file size. Old files are deleted after the retention period.
                                    This Save writes the whole logging section, including the level above.
                                </div>
                                <div className="text-xs text-gray-600 dark:text-gray-400">
                                    <span className="font-medium">Console Format</span> controls stdout only &mdash; the log file is always JSON.
                                    <span className="font-medium"> Auto</span> picks by what is reading stdout: under systemd, one
                                    priority-prefixed line per event so <code>journalctl -p err</code> filters correctly; in a container,
                                    CLEF JSON for your log shipper; otherwise the readable template. Override only if something other than
                                    the obvious consumer is reading stdout.
                                </div>
                                <SaveButton saving={saving === 'logStorage'} onClick={() => saveSection('logging', config.logging, 'logStorage')} label="Save Logging Section" />
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
                                    <ConfigToggle label="Enabled" checked={config.networkAudit?.enabled ?? false} onChange={(v) => update('networkAudit', 'enabled', v)}
                                        hint="Every protocol and admin request is recorded (who, what, from where). Off removes the request trail auditors expect." />
                                    <div>
                                        <ConfigToggle label="Log All Requests" checked={config.networkAudit?.logAllRequests ?? false} onChange={(v) => update('networkAudit', 'logAllRequests', v)}
                                            hint="Off records protocol and admin endpoints only. On records everything, static files included." />
                                        {config.networkAudit?.logAllRequests && (
                                            <div className="bg-amber-50 dark:bg-amber-900/20 border border-amber-300 dark:border-amber-800 rounded p-2 text-xs text-amber-800 dark:text-amber-300 mt-2">
                                                Enabling logs ALL HTTP requests including static files. This can generate significant log volume.
                                            </div>
                                        )}
                                    </div>
                                    <div className="md:col-span-2">
                                        <ConfigInput label="Exclude Paths (comma-separated)" value={listToStr(config.networkAudit?.excludePaths)}
                                            onChange={(v) => update('networkAudit', 'excludePaths', strToList(v))}
                                            placeholder="/health,/metrics"
                                            hint="Path prefixes never recorded, typically health checks and metrics scrapes that would otherwise dominate the log." />
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
    // PUT /admin/features/{name} carries [RequireStepUp]; this tab is a separate component
    // from the one holding the hook above, so it needs its own.
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();
    const [features, setFeatures] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);

    const load = () => {
        setLoading(true);
        apiGet<any>('/api/v1/admin/features')
            .then((data) => setFeatures(Array.isArray(data) ? data : (data.items || data.features || [])))
            .catch((err) => setError(errorNotice(err, 'The request failed.')))
            .finally(() => setLoading(false));
    };

    useEffect(() => { load(); }, []);

    const handleToggle = async (feature: any) => {
        try {
            await apiPutWithMfa(`/api/v1/admin/features/${feature.name}`,
                { enabled: !feature.enabled }, requireStepUp, StepUpOps.UpdateFeatureFlag, feature.name);
            load();
        } catch (err: any) {
            showToast('error', err.message || 'Failed to update feature flag');
        }
    };

    if (loading) return <div className="p-4 text-sm text-gray-600 dark:text-gray-400">Loading...</div>;
    if (error) return <InlineNotice notice={error} />;

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
    // `?tab=Security` opens that tab directly so other pages can deep-link to a card.
    const [params] = useSearchParams();
    const requested = params.get('tab');
    const [activeTab, setActiveTab] = useState<Tab>(TABS.find((t) => t === requested) ?? 'General');

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
