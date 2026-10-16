import React, { useState, useEffect, useRef } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { Chevron } from '@shared/components/Chevron';
import { Link, useSearchParams } from 'react-router-dom';
import { apiGet, apiPost, apiPutWithMfa, apiPostWithMfa, getToken, forceRefresh, API_BASE } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import { useAuth } from '../context/AuthContext';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import { StepUpOps } from '@shared/generated';
import ConfirmModal from '../components/ConfirmModal';
import { ceremonyLink } from './ceremonyLinks';
import { KEY_CEREMONIES_ANCHOR, USERS_PATH, requirementWarning } from './ceremonyRefusal';
import { inputClass, labelClass, FieldHint } from '@shared/components/forms';
import { ChipListInput, type ChipSuggestion } from '@shared/components/ChipListInput';
import { invalidItems, listFromValue, listToCsv } from '@shared/components/chipList';
import {
    type Validator, validateAbsoluteFilePath, validateEmail, validateOrigin, validatePathPrefix, validatePositiveInteger,
} from '@shared/validators';
import {
    DEPRECATED_ALGORITHM_SUGGESTIONS, POLICY_SIGNATURE_ALGORITHMS, certExpiryNotificationBody, jwtIpBindingMode, warningDaysFromConfig,
} from './settingsLists';
import { LdapMappingsEditor, SunsetRulesEditor } from './SettingsTables';
import { ApiKeysPanel } from '../components/ApiKeysPanel';
import { CARD_FIELDS, type SettingsIndex, describeField, fieldBadges, fieldLocked, fieldsApply, indexSettings, secretState } from './settingsMeta';
import { actionButton } from '@shared/components/actionButtons';

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

/** Mirrors PasswordPolicyBounds on the server. */
const PASSWORD_MIN_LENGTH_FLOOR = 8;
const PASSWORD_HISTORY_MAX = 24;

const TABS = ['General', 'Security', 'Certificates', 'Integrations', 'Logging', 'Features'] as const;
type Tab = typeof TABS[number];

/** Element id of the Restart card on the General tab. BackupRestore links to
    `/settings#restart-application` after a restore (string repeated there rather than imported,
    so that page does not pull this lazy chunk in). */
const RESTART_ANCHOR = 'restart-application';

/* --- Shared Form Helpers --- */
const cardClass = 'bg-raised border border-line rounded-lg overflow-hidden';

/* Where each setting is kept and when a change to it takes effect, as the server describes it
   (GET /api/v1/admin/settings). A field names its setting with `path`, and says beside its label
   whether a saved change is live or waits for a restart. Empty until loaded, and for a field the
   server does not describe: such a field shows nothing, which is better than a guess. */
const SettingsMetaContext = React.createContext<SettingsIndex>(new Map());

const badgeTone = {
    ok: 'bg-ok-soft text-ok border-ok/40',
    warn: 'bg-warn-soft text-warn border-warn/40',
    neutral: 'bg-sunken text-ink-muted border-line-strong',
} as const;

const FieldBadges: React.FC<{ path?: string }> = ({ path }) => {
    const badges = fieldBadges(describeField(React.useContext(SettingsMetaContext), path));
    if (badges.length === 0) return null;
    return (
        <span className="inline-flex items-center gap-1 ml-2 align-middle normal-case tracking-normal">
            {badges.map((b) => (
                <span key={b.label} title={b.title} className={`px-1.5 py-0.5 text-[10px] font-semibold rounded border ${badgeTone[b.tone]}`}>{b.label}</span>
            ))}
        </span>
    );
};

/** Whether the field's setting is decided by an environment variable, so it cannot be changed here. */
const useLocked = (path?: string) => fieldLocked(describeField(React.useContext(SettingsMetaContext), path));

/* Every primitive takes `hint`: what the value does, or what saving it causes, shown under the
   control. The label names the setting; the hint says what happens when you change it. */
const ConfigInput: React.FC<{ label: string; value: any; onChange: (v: string) => void; type?: string; placeholder?: string; hint?: React.ReactNode; disabled?: boolean; path?: string }> = ({ label, value, onChange, type = 'text', placeholder, hint, disabled, path }) => {
    const locked = useLocked(path);
    return (
        <div>
            <label className={labelClass}>{label}<FieldBadges path={path} /></label>
            <input type={type} value={value ?? ''} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} className={inputClass} disabled={disabled || locked} />
            {hint && <FieldHint>{hint}</FieldHint>}
        </div>
    );
};

const ConfigTextarea: React.FC<{ label: string; value: any; onChange: (v: string) => void; placeholder?: string; rows?: number; hint?: React.ReactNode; path?: string }> = ({ label, value, onChange, placeholder, rows = 6, hint, path }) => (
    <div>
        <label className={labelClass}>{label}<FieldBadges path={path} /></label>
        <textarea
            value={value ?? ''}
            onChange={(e) => onChange(e.target.value)}
            placeholder={placeholder}
            rows={rows}
            className={`${inputClass} data-mono resize-y`}
        />
        {hint && <FieldHint>{hint}</FieldHint>}
    </div>
);

const ConfigNumber: React.FC<{ label: string; value: any; onChange: (v: number | string) => void; fallback?: number; hint?: React.ReactNode; disabled?: boolean; path?: string }> = ({ label, value, onChange, fallback = 0, hint, disabled, path }) => {
    const locked = useLocked(path);
    return (
        <div>
            <label className={labelClass}>{label}<FieldBadges path={path} /></label>
            <input type="text" inputMode="numeric" value={value ?? ''} onChange={(e) => { const v = e.target.value.replace(/\D/g, ''); onChange(v === '' ? '' : parseInt(v)); }} onBlur={() => { if (!value && value !== 0) onChange(fallback); }} className={inputClass} disabled={disabled || locked} />
            {hint && <FieldHint>{hint}</FieldHint>}
        </div>
    );
};

const ConfigToggle: React.FC<{ label: string; checked: boolean; onChange: (v: boolean) => void; hint?: React.ReactNode; hintTone?: 'muted' | 'warn'; disabled?: boolean; path?: string }> = ({ label, checked, onChange, hint, hintTone, disabled: disabledProp, path }) => {
    const disabled = useLocked(path) || disabledProp;
    return (
    <div>
        <div className="flex items-center justify-between">
            <label className="text-xs text-ink-muted">{label}<FieldBadges path={path} /></label>
            <button type="button" role="switch" aria-checked={checked} disabled={disabled} onClick={() => onChange(!checked)} className={`relative w-11 h-6 rounded-full transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${checked ? 'bg-accent' : 'bg-ink-faint'}`}>
                <span className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full transition-transform ${checked ? 'translate-x-5' : 'translate-x-0'}`} />
            </button>
        </div>
        {hint && <FieldHint tone={hintTone}>{hint}</FieldHint>}
    </div>
    );
};

const ConfigSelect: React.FC<{ label: string; value: string; options: string[]; onChange: (v: string) => void; hint?: React.ReactNode; path?: string }> = ({ label, value, options, onChange, hint, path }) => (
    <div>
        <label className={labelClass}>{label}<FieldBadges path={path} /></label>
        <select value={value} onChange={(e) => onChange(e.target.value)} className={inputClass}>
            {options.map((o) => <option key={o} value={o}>{o}</option>)}
        </select>
        {hint && <FieldHint>{hint}</FieldHint>}
    </div>
);

/* `blockedReason` disables the button and says why underneath it. */
const SaveButton: React.FC<{ saving: boolean; onClick: () => void; label?: string; disabled?: boolean; blockedReason?: string | null }> = ({ saving, onClick, label, disabled, blockedReason }) => (
    <div>
        <button onClick={onClick} disabled={saving || disabled || !!blockedReason} className="px-4 py-2 text-sm bg-accent text-on-accent rounded hover:bg-accent-hover disabled:opacity-50 transition-colors">
            {saving ? 'Saving...' : (label || 'Save')}
        </button>
        {blockedReason && <FieldHint tone="warn">{blockedReason}</FieldHint>}
    </div>
);

/* A list setting edited as chips. Invalid entries stay visible and marked; the card's Save is
   blocked on them through `listBlocked`. */
const ConfigChips: React.FC<{ label: string; value: string[]; onChange: (v: string[]) => void; validate?: Validator; suggestions?: ChipSuggestion[]; placeholder?: string; hint?: React.ReactNode; numeric?: boolean; sort?: 'asc' | 'desc'; mono?: boolean; caseInsensitive?: boolean; path?: string }> = ({ label, hint, path, ...chip }) => {
    const id = React.useId();
    return (
        <div>
            <label htmlFor={id} className={labelClass}>{label}<FieldBadges path={path} /></label>
            <ChipListInput id={id} aria-describedby={hint ? `${id}-hint` : undefined} {...chip} />
            {hint && <FieldHint id={`${id}-hint`}>{hint}</FieldHint>}
        </div>
    );
};

/* Why a card's Save is blocked: the labels of its list fields that hold invalid entries. */
const listBlocked = (fields: [string, unknown, Validator][]): string | null => {
    const bad = fields.filter(([, value, validate]) => invalidItems(listFromValue(value), validate).length > 0).map(([label]) => label);
    return bad.length ? `Fix the entries marked invalid in ${bad.join(' and ')} before saving.` : null;
};

const FORBIDDEN_ALGORITHM_SUGGESTIONS: ChipSuggestion[] = POLICY_SIGNATURE_ALGORITHMS.map((value) => ({ value }));
const DEPRECATED_SUGGESTIONS: ChipSuggestion[] = DEPRECATED_ALGORITHM_SUGGESTIONS.map((value) => ({ value }));
const validateWarningDay: Validator = (v) => validatePositiveInteger(v, 3650);

/* Note shown on cards whose cron schedule is owned by the scheduler job's detail page. The card's
   Save deliberately sends an empty `schedule`, which the backend patch-guards
   (`if (!IsNullOrEmpty) ...`) so a stale Settings tab can't clobber a cron edited there. */
const ScheduleMovedNote: React.FC<{ job: string }> = ({ job }) => (
    <p className="text-[11px] text-ink-muted">
        The run schedule (cron) is edited on the{' '}
        <Link to={`/schedules/jobs/${encodeURIComponent(job)}`} className="underline hover:text-ink">{job} job page</Link>
        {' '}(Schedules → open the job → Edit).
    </p>
);

const LiveTag = () => <span className="px-1.5 py-0.5 text-[10px] font-semibold rounded bg-ok-soft text-ok border border-ok/40">Live</span>;
const RestartTag = () => <span className="px-1.5 py-0.5 text-[10px] font-semibold rounded bg-warn-soft text-warn border border-warn/40">Restart</span>;

const ReadOnlyTag = () => <span className="px-1.5 py-0.5 text-[10px] font-semibold rounded bg-sunken text-ink-muted border border-line-strong">Read-only</span>;

const MixedTag = () => <span title="Some of these settings take effect at once and some at the next start. Each field says which." className="px-1.5 py-0.5 text-[10px] font-semibold rounded bg-sunken text-ink-muted border border-line-strong">Live and restart</span>;

const tagFor = (applies: 'live' | 'restart' | 'mixed' | 'read-only' | null | undefined) =>
    applies === 'live' ? <LiveTag /> : applies === 'restart' ? <RestartTag /> : applies === 'mixed' ? <MixedTag /> : applies === 'read-only' ? <ReadOnlyTag /> : null;

/* The tag for a group of fields: what the server says of those settings, so a heading cannot
   disagree with the fields under it. */
const AppliesTag: React.FC<{ fields: readonly string[] }> = ({ fields }) => tagFor(fieldsApply(React.useContext(SettingsMetaContext), fields));

/* `fields` are the settings the card edits (CARD_FIELDS). With them the tag is what those
   settings say; `tag` is what is shown for a card that edits none the server describes. */
const SectionHeader: React.FC<{ title: string; expanded: boolean; onToggle: () => void; description?: string; tag?: 'live' | 'restart' | 'read-only'; fields?: readonly string[] }> = ({ title, expanded, onToggle, description, tag, fields }) => {
    const described = fieldsApply(React.useContext(SettingsMetaContext), fields);
    const shown = tag === 'read-only' ? tag : described ?? tag;
    return (
        <button onClick={onToggle} className="w-full px-4 py-3 flex items-center gap-2 text-left hover:bg-hover bg-sunken transition-colors">
            <span className="text-ink-muted text-xs"><Chevron open={expanded} className="w-3 h-3" /></span>
            <span className="text-sm font-semibold text-ink">{title}</span>
            {description && <span className="text-xs text-ink-muted ml-2">{description}</span>}
            <span className="ml-auto">{tagFor(shown)}</span>
        </button>
    );
};

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
                        <h3 className="text-sm font-semibold text-ink">Webhook Test</h3>
                        <p className="text-xs text-ink-muted mt-1">
                            Send a test event to all configured webhook endpoints to verify connectivity.
                        </p>
                    </div>
                    <button
                        onClick={handleTestWebhook}
                        disabled={sending}
                        className="px-4 py-2 text-sm bg-accent text-on-accent rounded hover:bg-accent-hover disabled:opacity-50 transition-colors flex-shrink-0"
                    >
                        {sending ? 'Sending...' : 'Send Test Webhook'}
                    </button>
                </div>
                {result && (
                    <div className={`mt-3 p-2 rounded text-xs ${result.success ? 'bg-ok-soft border border-ok/40 text-ok' : 'bg-crit-soft border border-crit/40 text-crit'}`}>
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
    const { user } = useAuth();
    const { showToast } = useToast();
    const [config, setConfig] = useState<any>(null);
    const [settingsMeta, setSettingsMeta] = useState<SettingsIndex>(new Map());
    const [settingsStore, setSettingsStore] = useState<{ inUse: boolean; waitingForRestart: string[] }>({ inUse: false, waitingForRestart: [] });
    const [confirmRotateJwt, setConfirmRotateJwt] = useState(false);
    const [rotatingJwt, setRotatingJwt] = useState(false);
    const [rotateJwtError, setRotateJwtError] = useState<string | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [expanded, setExpanded] = useState<string | null>(null);
    const [saving, setSaving] = useState<string | null>(null);
    const [successMsg, setSuccessMsg] = useState<string | null>(null);
    const [restarting, setRestarting] = useState(false);
    const [ldapMappingsInvalid, setLdapMappingsInvalid] = useState(false);
    const [sunsetInvalid, setSunsetInvalid] = useState(false);

    // Restarting the server is the most destructive control on this page, and it was the
    // one place in adminui still using a native window.confirm — ConfirmModal is used in
    // thirty others. A native dialog blocks the page, cannot be styled to match, and is
    // dismissed by reflex.
    const [confirmRestart, setConfirmRestart] = useState(false);

    const restartPoll = useRef<ReturnType<typeof setTimeout> | null>(null);
    const restartTimeout = useRef<ReturnType<typeof setTimeout> | null>(null);
    const restartRun = useRef(0);
    const stopRestartPoll = () => {
        restartRun.current++;
        if (restartPoll.current) clearTimeout(restartPoll.current);
        if (restartTimeout.current) clearTimeout(restartTimeout.current);
        restartPoll.current = null;
        restartTimeout.current = null;
    };
    useEffect(() => stopRestartPoll, []);

    // Raw fetch with the current token: no refresh attempt and no 401 logout while the server is down.
    // Returns the process start on the server's clock (ms), null if the server answered without
    // an uptime, 'unauthorized' on a 401, or throws if it did not answer.
    const readServerStart = async (): Promise<number | null | 'unauthorized'> => {
        const token = getToken();
        const res = await fetch(`${API_BASE}/health/ready`, {
            headers: token ? { Authorization: `Bearer ${token}` } : {},
            cache: 'no-store',
        });
        if (res.status >= 502 && res.status <= 504 && !res.headers.get('content-type')?.includes('json')) throw new Error('gateway');
        if (res.status === 401) return 'unauthorized';
        const body = await res.json().catch(() => null);
        if (typeof body?.uptimeSeconds !== 'number' || typeof body?.timestamp !== 'string') return null;
        const now = Date.parse(body.timestamp.replace(/(\.\d{3})\d+/, '$1'));
        return Number.isNaN(now) ? null : now - body.uptimeSeconds * 1000;
    };

    const doRestart = async () => {
        setConfirmRestart(false);
        setRestarting(true);
        try {
            const first = await readServerStart().catch(() => null);
            const baseline = typeof first === 'number' ? first : null;
            await apiPostWithMfa('/api/v1/admin/config/restart', {}, requireStepUp, StepUpOps.Restart);
            setSuccessMsg('Restart initiated. Waiting for the server to come back...');
            stopRestartPoll();
            const run = restartRun.current;
            let sawDown = false;
            const finish = () => {
                stopRestartPoll();
                setRestarting(false);
                setSuccessMsg('Server restarted successfully');
                load();
            };
            // One request in flight at a time. With a baseline, success is a reply from a process that
            // started after it; without one (no uptime visible to this user), fall back to down-then-up.
            const tick = async () => {
                try {
                    let start = await readServerStart();
                    if (run !== restartRun.current) return;
                    if (start === 'unauthorized') {
                        start = null;
                        // One forced rotation per attempt, whatever the local expiry says (clock skew).
                        // A transient failure keeps the tokens; a definitive rejection ends the session.
                        if (getToken()) {
                            const token = await forceRefresh().catch(() => undefined);
                            if (run !== restartRun.current) return;
                            if (!getToken()) { stopRestartPoll(); return; }
                            if (token) {
                                const retried = await readServerStart();
                                if (run !== restartRun.current) return;
                                start = retried === 'unauthorized' ? null : retried;
                            }
                        }
                    }
                    if (baseline != null ? (start != null && start > baseline + 1000) : sawDown) {
                        finish();
                        return;
                    }
                } catch {
                    if (run !== restartRun.current) return;
                    if (!sawDown) setSuccessMsg('Server is down. Reconnecting...');
                    sawDown = true;
                }
                restartPoll.current = setTimeout(tick, 1000);
            };
            restartPoll.current = setTimeout(tick, 1000);
            restartTimeout.current = setTimeout(() => {
                stopRestartPoll();
                setRestarting(false);
                setSuccessMsg(null);
                showToast('error', sawDown
                    ? 'The server did not come back within 2 minutes. Check the host, then reload this page.'
                    : 'A restarted server was not observed within 2 minutes. Reload this page to check its state.');
            }, 120000);
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
    /* How many accounts other than this one could approve a key ceremony on an instance CA;
       null until known. Read to warn before the requirement is saved where nobody could. */
    const [instanceApprovers, setInstanceApprovers] = useState<number | null>(null);
    /* How many system super-administrators exist, to suggest leaving single-administrator
       settings once there are several; null until known. */
    const [systemSuperCount, setSystemSuperCount] = useState<number | null>(null);

    /* Snapshots of what the server last returned, for the unsaved-changes guard. Each loader
       stamps its own key; `dirty` is true when any live buffer differs from its snapshot. */
    const saved = useRef<Record<string, string>>({});
    const snap = (key: string, value: any) => { saved.current[key] = JSON.stringify(value); };
    /** The config as the server last returned it, or null. */
    const savedConfig = (): any => { try { return JSON.parse(saved.current.config ?? 'null'); } catch { return null; } };
    const differs = (key: string, value: any) => value != null && saved.current[key] !== undefined && saved.current[key] !== JSON.stringify(value);

    // Where each setting is kept and when a change takes effect. The page works without it:
    // a field then shows no badge, and the cards keep their own tags.
    const loadSettingsMeta = () => {
        apiGet<any>('/api/v1/admin/settings')
            .then((d) => {
                setSettingsMeta(indexSettings(d?.settings));
                setSettingsStore({ inUse: !!d?.storeInUse, waitingForRestart: Array.isArray(d?.waitingForRestart) ? d.waitingForRestart : [] });
            })
            .catch(() => setSettingsMeta(new Map()));
    };

    const load = () => {
        setLoading(true);
        apiGet<any>('/api/v1/admin/config')
            .then((c) => { setConfig(c); snap('config', c); })
            .catch((err) => setError(errorNotice(err, 'The request failed.')))
            .finally(() => setLoading(false));
        loadSettingsMeta();
    };

    const rotateJwtSecret = async () => {
        setRotatingJwt(true);
        setRotateJwtError(null);
        try {
            await apiPostWithMfa('/api/v1/admin/settings/jwt-secret/rotate', {}, requireStepUp, StepUpOps.RotateJwtSecret);
            loadSettingsMeta();
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') setRotateJwtError(err.message);
        } finally {
            setRotatingJwt(false);
            setConfirmRotateJwt(false);
        }
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
        apiGet<any>('/api/v1/admin/ceremonies/approvers', { toast: false })
            .then((a) => setInstanceApprovers(typeof a?.eligibleApprovers === 'number' ? a.eligibleApprovers : null))
            .catch(() => setInstanceApprovers(null));
        apiGet<any>('/api/v1/admin/security-policy/administrators', { toast: false })
            .then((a) => setSystemSuperCount(typeof a?.systemSuperCount === 'number' ? a.systemSuperCount : null))
            .catch(() => setSystemSuperCount(null));
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

    // Other pages link to /settings?tab=Security#key-ceremonies: open that card and scroll to it.
    useEffect(() => {
        if (loading || tab !== 'Security' || window.location.hash !== `#${KEY_CEREMONIES_ANCHOR}`) return;
        setExpanded('keyCeremonies');
        document.getElementById(KEY_CEREMONIES_ANCHOR)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
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

    if (loading) return <div className="p-4 text-sm text-ink-muted">Loading...</div>;
    if (error) return <InlineNotice notice={error} />;

    // The JWT secret is never sent to the console; this is what can be said of it.
    const jwtSecret = describeField(settingsMeta, 'jwt.secret');
    const jwtSecretState = secretState(jwtSecret, settingsStore.waitingForRestart);
    const jwtSecretLine = jwtSecretState === 'environment' ? 'Supplied by an environment variable on this node'
        : jwtSecretState === 'file' ? "In this host's config.yaml"
        : jwtSecretState ? `Stored, wrapped by the signer. Version ${jwtSecret?.version}, changed ${formatDate(jwtSecret?.updatedAt ?? null)} by ${jwtSecret?.updatedBy || 'unknown'}`
        : '***';
    const jwtRotateBlocked = jwtSecretState === 'environment' ? 'An environment variable supplies the secret on this node. Change it there.'
        : !settingsStore.inUse ? 'The settings have not been moved to the database on this node.'
        : null;
    if (!config) return null;

    /* --- Password Policy helpers --- */
    const handleSavePolicy = async () => {
        setPolicySaving(true);
        try {
            await apiPutWithMfa('/api/v1/admin/password-policy', policy, requireStepUp, StepUpOps.UpdateConfig);
            snap('policy', policy);
            showToast('success', 'Password policy updated');
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to save policy');
        } finally {
            setPolicySaving(false);
        }
    };
    const updatePolicyField = (key: string, value: any) => setPolicy({ ...policy, [key]: value });

    /* The bounds the server enforces (AdminPasswordPolicyController), checked before saving.
       MaxLength 0 means "no cap", so the comparisons only apply when a cap is set. A policy no
       password can satisfy locks every user out at their next change. */
    const policyNum = (k: string) => (policy && typeof policy[k] === 'number' ? policy[k] : 0);
    const policyMinsTotal = policyNum('minUppercase') + policyNum('minLowercase') + policyNum('minDigits') + policyNum('minSpecial');
    const policyProblems: string[] = [];
    if (policy && policyNum('minLength') < PASSWORD_MIN_LENGTH_FLOOR)
        policyProblems.push(`Minimum length must be at least ${PASSWORD_MIN_LENGTH_FLOOR}.`);
    if (policy && policyNum('maxLength') > 0 && policyNum('minLength') > policyNum('maxLength'))
        policyProblems.push(`Minimum length (${policyNum('minLength')}) is greater than maximum length (${policyNum('maxLength')}); no password can satisfy both.`);
    if (policy && policyNum('maxLength') > 0 && policyMinsTotal > policyNum('maxLength'))
        policyProblems.push(`The character-class minimums add up to ${policyMinsTotal}, more than the maximum length (${policyNum('maxLength')}).`);
    if (policy && policyNum('historyCount') > PASSWORD_HISTORY_MAX)
        policyProblems.push(`Password history can remember at most ${PASSWORD_HISTORY_MAX} passwords.`);

    /* --- Security Policy (DB) helpers --- */
    const handleSaveSecurityPolicy = async () => {
        setSecurityPolicySaving(true);
        try {
            // A super turning the instance's ceremony requirement off applies it directly, so the
            // server asks for the disable-ceremony-requirement step-up instead (KC-07).
            const wasRequired = saved.current.securityPolicy ? JSON.parse(saved.current.securityPolicy).requireKeyCeremony !== false : true;
            const op = user?.isSuper && wasRequired && securityPolicy.requireKeyCeremony === false
                ? StepUpOps.DisableCeremonyRequirement : StepUpOps.UpdateConfig;
            const result = await apiPutWithMfa<any>('/api/v1/admin/security-policy', securityPolicy, requireStepUp, op);
            // 202 + ceremonyId: a non-super change to the instance's key-ceremony policy waits for
            // an InstancePolicyChange ceremony; everything else was saved. Reload to show which.
            if (result?.ceremonyId) {
                showToast('info', `Instance policy change ceremony started. Approve it at ${ceremonyLink(result.ceremonyId)}`);
                loadSecurityPolicy();
            } else {
                snap('securityPolicy', securityPolicy);
                showToast('success', 'Security policy updated');
            }
        } catch (err: any) {
            if (err.message !== 'Step-up MFA cancelled') showToast('error', err.message || 'Failed to save security policy');
        } finally {
            setSecurityPolicySaving(false);
        }
    };
    const updateSecurityPolicyField = (key: string, value: any) => setSecurityPolicy({ ...securityPolicy, [key]: value });
    const instanceCeremonyWarning = securityPolicy ? requirementWarning({
        required: securityPolicy.requireKeyCeremony !== false,
        wasRequired: saved.current.securityPolicy ? JSON.parse(saved.current.securityPolicy).requireKeyCeremony !== false : true,
        approvals: Number(securityPolicy.ceremonyRequiredApprovals) || 1,
        eligibleApprovers: instanceApprovers,
        scope: 'the instance',
    }) : null;

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

    /* Cards whose list fields hold invalid entries cannot be saved until they are fixed. */
    const httpBlocked = listBlocked([['CORS Origins', config.http?.corsOrigins, validateOrigin]]);
    const mtlsBlocked = listBlocked([
        ['Required Paths', config.mtls?.requiredPaths, validatePathPrefix],
        ['Trusted CA Cert Paths', config.mtls?.trustedCaCertPaths, validateAbsoluteFilePath],
    ]);
    const ipWhitelistBlocked = listBlocked([['Exempt Paths', config.ipWhitelist?.exemptPaths, validatePathPrefix]]);
    const warningDays = warningDaysFromConfig(config.certExpiryNotification);
    const expiryBlocked = listBlocked([['Warning Days', warningDays, validateWarningDay]]);
    const emailBlocked = listBlocked([['Admin Recipients', config.email?.adminRecipients, validateEmail]]);
    const networkAuditBlocked = listBlocked([['Exclude Paths', config.networkAudit?.excludePaths, validatePathPrefix]]);

    return (
        <SettingsMetaContext.Provider value={settingsMeta}>
        <div className="space-y-2">
            {successMsg && (
                <div className="bg-ok-soft border border-ok/40 rounded-lg p-3 text-xs text-ok">{successMsg}</div>
            )}
            {settingsMeta.size > 0 && (
                <p className="text-xs text-ink-muted max-w-4xl">
                    Each setting says when a saved change takes effect. <LiveTag /> at once on this node; other nodes take it at their next start.{' '}
                    <RestartTag /> when this node next starts. Settings are kept in the database, except those marked{' '}
                    <span className={`px-1.5 py-0.5 text-[10px] font-semibold rounded border ${badgeTone.neutral}`}>This host</span>, which are in this host's config.yaml.
                </p>
            )}

            {/* ================================================================ */}
            {/* GENERAL TAB                                                      */}
            {/* ================================================================ */}
            {tab === 'General' && (
                <>
                    {/* Public Domain */}
                    <div className={cardClass}>
                        <SectionHeader fields={CARD_FIELDS.baseurl} title="Public Domain" expanded={expanded === 'baseurl'} onToggle={() => toggle('baseurl')}
                            description={config.https?.publicDomain || 'Not configured — using request origin'} tag="restart" />
                        {expanded === 'baseurl' && (
                            <div className="p-4 border-t border-line space-y-4">
                                <div className="bg-info-soft border border-info/40 rounded p-3 text-xs text-info">
                                    The public hostname used for management-UI HTTPS redirects and ACME URL binding.
                                    Must be a bare hostname or IP — no scheme, no port. Per-CA AIA/CDP base URLs are configured
                                    separately in CA Management.
                                </div>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigInput label="Public Domain" value={config.https?.publicDomain} path="https.publicDomain" onChange={(v) => update('https', 'publicDomain', v)} placeholder="ca.example.com"
                                        hint="Empty means URLs are built from whatever host the request arrived on, which is wrong behind a proxy and unusable for ACME JWS URL checks." />
                                    <ConfigNumber label="Public Port (443 = omitted from URLs)" value={config.https?.publicPort} path="https.publicPort" onChange={(v) => update('https', 'publicPort', v)} fallback={443}
                                        hint="The port external clients reach this server on, which may differ from the listen port behind a proxy. Anything other than 443 is written into every generated URL." />
                                </div>
                                {config.https?.publicDomain && (
                                    <div className="text-xs text-ink-muted space-y-1">
                                        <div>HTTPS base: <code className="mono text-ink-muted">https://{config.https.publicDomain}{config.https.publicPort && config.https.publicPort !== 443 ? `:${config.https.publicPort}` : ''}</code></div>
                                        <div>ACME directory: <code className="mono text-ink-muted">https://{config.https.publicDomain}{config.https.publicPort && config.https.publicPort !== 443 ? `:${config.https.publicPort}` : ''}/acme/{'<label>'}/directory</code></div>
                                    </div>
                                )}
                                <SaveButton saving={saving === 'baseurl'} onClick={() => saveSection('https', config.https, 'baseurl')} />
                            </div>
                        )}
                    </div>

                    {/* HTTP */}
                    <div className={cardClass}>
                        <SectionHeader fields={CARD_FIELDS.http} title="HTTP" expanded={expanded === 'http'} onToggle={() => toggle('http')}
                            description={`Port ${config.http?.port || 0}, Swagger ${config.http?.swaggerEnabled ? 'On' : 'Off'}`} tag="restart" />
                        {expanded === 'http' && (
                            <div className="p-4 border-t border-line space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigNumber label="HTTP Port (0 = disabled)" value={config.http.port} path="http.port" onChange={(v) => update('http', 'port', v)}
                                        hint="Plain-HTTP listener for CRL, OCSP and AIA fetches, which relying parties make without TLS. 0 turns it off, and those URLs stop answering." />
                                    <ConfigNumber label="Public Port (behind proxy)" value={config.http.publicPort} path="http.publicPort" onChange={(v) => update('http', 'publicPort', v)} fallback={0}
                                        hint="Port external clients connect to when a proxy sits in front (proxy on 80, this process on 8080). It is written into CRL/OCSP/AIA URLs. 0 uses the listener port." />
                                    <ConfigChips label="CORS Origins" value={listFromValue(config.http.corsOrigins)} path="http.corsOrigins" onChange={(v) => update('http', 'corsOrigins', listToCsv(v))}
                                        validate={validateOrigin} caseInsensitive mono placeholder="https://app.example.com"
                                        hint="HTTPS origins whose browser scripts may call this API, as scheme, host and optional port with no path. Plain http is accepted only for localhost. Only read when Enable CORS is on." />
                                    <ConfigToggle label="Enable CORS" checked={config.http.enableCors ?? false} path="http.enableCors" onChange={(v) => update('http', 'enableCors', v)}
                                        hint="Allows browser pages on the listed origins to call the API. Off means every cross-origin browser request is refused, even in Development." />
                                    <ConfigToggle label="Swagger Enabled" checked={config.http.swaggerEnabled} path="http.swaggerEnabled" onChange={(v) => update('http', 'swaggerEnabled', v)}
                                        hint="Publishes the interactive API documentation at /swagger to anyone who can reach the port. Leave off in production." />
                                </div>
                                <p className="text-[10px] text-ink-muted">Trusted Proxy CIDRs moved to the <strong>Reverse Proxy</strong> card (Security tab).</p>
                                <SaveButton saving={saving === 'http'} onClick={() => saveSection('http', config.http, 'http')} blockedReason={httpBlocked} />
                            </div>
                        )}
                    </div>

                    {/* HTTPS (read-only) */}
                    <div className={cardClass}>
                        <SectionHeader title="HTTPS" expanded={expanded === 'https'} onToggle={() => toggle('https')}
                            description={`${config.https?.mode} — Port ${config.https?.port}`} tag="read-only" />
                        {expanded === 'https' && (
                            <div className="p-4 border-t border-line space-y-2">
                                <DetailField label="Mode" value={config.https.mode} />
                                <DetailField label="Listen Address" value={config.https.listenAddress} />
                                <DetailField label="Port" value={String(config.https.port)} />
                                <DetailField label="Renewal Window" value={config.https.renewalWindow} />
                                <div className="text-xs text-ink-muted mt-2">HTTPS settings are managed via bootstrap and require a restart to change.</div>
                            </div>
                        )}
                    </div>

                    {/* Metrics */}
                    <div className={cardClass}>
                        <SectionHeader fields={CARD_FIELDS.metrics} title="Metrics" expanded={expanded === 'metrics'} onToggle={() => toggle('metrics')}
                            description={config.metrics?.enabled ? `Enabled at ${config.metrics.path}` : 'Disabled'} tag="restart" />
                        {expanded === 'metrics' && (
                            <div className="p-4 border-t border-line space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigToggle label="Enabled" checked={config.metrics.enabled} path="metrics.enabled" onChange={(v) => update('metrics', 'enabled', v)}
                                        hint="Serves Prometheus metrics at the path below. Anyone who can reach the port can scrape them; restrict at the network or whitelist level." />
                                    <ConfigInput label="Path" value={config.metrics.path} path="metrics.path" onChange={(v) => update('metrics', 'path', v)}
                                        hint="Route the scrape endpoint is mounted on. Prometheus defaults to /metrics." />
                                </div>
                                <SaveButton saving={saving === 'metrics'} onClick={() => saveSection('metrics', config.metrics, 'metrics')} />
                            </div>
                        )}
                    </div>

                    {/* HSM (read-only) */}
                    <div className={cardClass}>
                        <SectionHeader title="HSM" expanded={expanded === 'hsm'} onToggle={() => toggle('hsm')}
                            description={config.hsm?.enabled ? 'Enabled' : 'Disabled'} tag="read-only" />
                        {expanded === 'hsm' && (
                            <div className="p-4 border-t border-line space-y-2">
                                <DetailField label="Enabled" value={config.hsm?.enabled ? 'Yes' : 'No'} />
                                <DetailField label="Module Path" value={config.hsm?.modulePath || 'Not configured'} />
                                <DetailField label="Slot ID" value={config.hsm?.slotId != null ? String(config.hsm.slotId) : 'Not configured'} />
                                <div className="bg-warn-soft border border-warn/40 rounded p-3 text-xs text-warn mt-3">
                                    HSM configuration must be set in config.yaml — cannot be changed at runtime.
                                </div>
                            </div>
                        )}
                    </div>

                    {/* Backup */}
                    <div className={cardClass}>
                        <SectionHeader fields={CARD_FIELDS.backup} title="Backup" expanded={expanded === 'backup'} onToggle={() => toggle('backup')}
                            description={`Retain ${config.backup?.retentionCount ?? 0} · ${config.backup?.outputPath || 'default path'}`} tag="restart" />
                        {expanded === 'backup' && (
                            <div className="p-4 border-t border-line space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigInput label="Output Path" value={config.backup?.outputPath} path="backup.outputPath" onChange={(v) => update('backup', 'outputPath', v)}
                                        hint="Directory archives are written to. A relative path resolves from the application directory, so it lives on the same disk as the data it protects." />
                                    <ConfigNumber label="Retention Count" value={config.backup?.retentionCount} path="backup.retentionCount" onChange={(v) => update('backup', 'retentionCount', v)}
                                        hint="Archives kept on disk. When a new one is written, the oldest beyond this count are deleted." />
                                    <ConfigNumber label="Max Backup Age Days" value={config.backup?.maxBackupAgeDays} path="backup.maxBackupAgeDays" onChange={(v) => update('backup', 'maxBackupAgeDays', v)}
                                        hint="If the newest archive is older than this when the verification job runs, it raises a Critical BackupStale alert." />
                                    <ConfigToggle label="Verify on Schedule" checked={config.backup?.verifyOnSchedule ?? true} path="backup.verifyOnSchedule" onChange={(v) => update('backup', 'verifyOnSchedule', v)}
                                        hint="Each scheduled run also opens recent archives and checks them for corruption. Off means a bad archive is found only when you need it." />
                                    <ConfigNumber label="Verify Count" value={config.backup?.verifyCount} path="backup.verifyCount" onChange={(v) => update('backup', 'verifyCount', v)}
                                        hint="How many of the newest archives each verification run checks. 1 checks only the latest, so corruption in the one before it goes unnoticed." />
                                </div>
                                <ScheduleMovedNote job="BackupCreation" />
                                <SaveButton saving={saving === 'backup'} onClick={() => saveSection('backup', { ...config.backup, schedule: '' }, 'backup')} />
                            </div>
                        )}
                    </div>

                    {/* Restart */}
                    <div id={RESTART_ANCHOR} className="bg-raised border border-warn/40 rounded-lg p-4 scroll-mt-4">
                        <div className="flex items-center justify-between">
                            <div>
                                <h3 className="text-sm font-semibold text-ink">Restart Application</h3>
                                <p className="text-xs text-ink-muted mt-1">
                                    Applies saved changes to the settings marked Restart, takes up a rotated JWT secret, and brings a
                                    restored backup into service. The application will shut down and the process manager will restart it.
                                </p>
                            </div>
                            <button
                                onClick={() => setConfirmRestart(true)}
                                disabled={restarting}
                                className="px-4 py-2 text-sm bg-warn text-on-accent rounded hover:bg-warn-hover disabled:opacity-50 transition-colors flex-shrink-0"
                            >
                                {restarting ? 'Restarting...' : 'Restart Server'}
                            </button>
                        </div>
                        <ConfirmModal
                            isOpen={confirmRestart}
                            title="Restart server"
                            message="Restart the ModularCA server? Active connections will be dropped and issuance, OCSP and CRL responses will be unavailable until it comes back."
                            confirmLabel="Restart"
                            tone="warn"
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
                        <SectionHeader fields={CARD_FIELDS.loginProtection} title="Login Protection" expanded={expanded === 'loginProtection'} onToggle={() => toggle('loginProtection')}
                            description={securityPolicy ? `Lockout ${securityPolicy.lockoutMinutes}m / ${securityPolicy.maxFailedLoginAttempts} tries` : 'Loading...'} tag="live" />
                        {expanded === 'loginProtection' && (
                            <div className="p-4 border-t border-line space-y-4">
                                <div className="bg-info-soft border border-info/40 rounded p-3 text-xs text-info">
                                    Two independent layers defend against password guessing. <strong>Account lockout</strong> disables an
                                    account after repeated failures. The <strong>per-username rate limit</strong> throttles attempts in the
                                    request pipeline. Each has its own Save, and each Save writes only the fields in its own group.
                                </div>

                                {/* Account Lockout — the security policy, read on every login */}
                                <div className="flex items-center gap-2"><h4 className="text-xs font-semibold text-ink-muted uppercase tracking-wide">Account Lockout</h4><LiveTag /></div>
                                {securityPolicyLoading && <div className="text-sm text-ink-muted">Loading...</div>}
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

                                {/* Per-Username Rate Limit */}
                                <div className="flex items-center gap-2 pt-2"><h4 className="text-xs font-semibold text-ink-muted uppercase tracking-wide">Per-Username Rate Limit</h4><AppliesTag fields={['security.maxPerUsernameLoginFailures', 'security.perUsernameLoginFailureWindowMinutes']} /></div>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigNumber label="Per-Username Failure Limit" value={config.security.maxPerUsernameLoginFailures} path="security.maxPerUsernameLoginFailures" onChange={(v) => update('security', 'maxPerUsernameLoginFailures', v)}
                                        hint="Failed logins allowed for one username from any number of IPs within the window before further attempts are refused. Catches many-IP attacks on a single account, which per-IP limits miss." />
                                    <ConfigNumber label="Per-Username Failure Window (min)" value={config.security.perUsernameLoginFailureWindowMinutes} path="security.perUsernameLoginFailureWindowMinutes" onChange={(v) => update('security', 'perUsernameLoginFailureWindowMinutes', v)}
                                        hint="Length of the sliding window the failure count is measured over." />
                                </div>
                                <SaveButton saving={saving === 'securityRateLimit'} onClick={() => saveSecurityFields(['maxPerUsernameLoginFailures', 'perUsernameLoginFailureWindowMinutes'], 'securityRateLimit')} label="Save Per-Username Limit" />
                            </div>
                        )}
                    </div>

                    {/* Token Binding & Lifetime — refresh token lifetime (tokens) + JWT/refresh
                        binding (security middleware), previously split across two cards. */}
                    <div className={cardClass}>
                        <SectionHeader fields={CARD_FIELDS.tokenBinding} title="Token Binding & Lifetime" expanded={expanded === 'tokenBinding'} onToggle={() => toggle('tokenBinding')}
                            description={`Refresh ${config.tokens?.refreshTokenDays || 7}d — JWT IP binding: ${jwtIpBindingMode(config.security?.bindJwtToIp)}`} />
                        {expanded === 'tokenBinding' && (
                            <div className="p-4 border-t border-line space-y-4">
                                <div className="bg-info-soft border border-info/40 rounded p-3 text-xs text-info">
                                    How long a session can be renewed, and the rules that tie it to where it was issued. Each group has
                                    its own Save, and each writes only its own fields.
                                </div>
                                {/* Refresh Token Lifetime */}
                                <div className="flex items-center gap-2"><h4 className="text-xs font-semibold text-ink-muted uppercase tracking-wide">Refresh Token Lifetime</h4><AppliesTag fields={['tokens.refreshTokenDays']} /></div>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigNumber label="Refresh Token Lifetime (days, 1-30)" value={config.tokens.refreshTokenDays} path="tokens.refreshTokenDays" onChange={(v) => update('tokens', 'refreshTokenDays', v)} fallback={7}
                                        hint="Days a session can be renewed without logging in again. A stolen refresh token stays usable for the same period, subject to the bindings below and the session caps in Security Policy." />
                                </div>
                                <SaveButton saving={saving === 'tokens'} onClick={() => saveSection('tokens', config.tokens, 'tokens')} label="Save Lifetime" />

                                {/* JWT & Refresh Binding */}
                                <div className="flex items-center gap-2 pt-2"><h4 className="text-xs font-semibold text-ink-muted uppercase tracking-wide">JWT &amp; Refresh Binding</h4><AppliesTag fields={['security.bindJwtToIp', 'security.bindRefreshTokenToIp', 'security.bindRefreshTokenToFingerprint', 'security.allowRefreshTokenMismatch']} /></div>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <div>
                                        <label className="block text-xs text-ink-muted mb-1">JWT IP Binding<FieldBadges path="security.bindJwtToIp" /></label>
                                        <select value={jwtIpBindingMode(config.security.bindJwtToIp)} onChange={(e) => update('security', 'bindJwtToIp', e.target.value)} className={inputClass}>
                                            <option value="Off">Off (no IP binding)</option>
                                            <option value="Exact">Exact (must match issue-time IP)</option>
                                            <option value="Subnet24">Subnet /24 (tolerant of NAT)</option>
                                        </select>
                                        <FieldHint>Ties every access token to the address it was issued to. Exact logs users out whenever their IP changes (mobile, VPN reconnects); Subnet /24 tolerates movement within one IPv4 /24 or IPv6 /64.</FieldHint>
                                    </div>
                                    <ConfigToggle label="Bind Refresh Token to IP" checked={config.security.bindRefreshTokenToIp ?? true} path="security.bindRefreshTokenToIp" onChange={(v) => update('security', 'bindRefreshTokenToIp', v)}
                                        hint="A refresh attempted from a different IP than the one the token was issued to is refused and the user must log in again." />
                                    <ConfigToggle label="Bind Refresh Token to Fingerprint" checked={config.security.bindRefreshTokenToFingerprint ?? true} path="security.bindRefreshTokenToFingerprint" onChange={(v) => update('security', 'bindRefreshTokenToFingerprint', v)}
                                        hint="A refresh from a different browser or User-Agent than the issuing one is refused." />
                                    <ConfigToggle label="Allow Refresh Token Mismatch (forensic)" checked={config.security.allowRefreshTokenMismatch ?? false} path="security.allowRefreshTokenMismatch" onChange={(v) => update('security', 'allowRefreshTokenMismatch', v)}
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
                        <SectionHeader fields={CARD_FIELDS.reverseProxy} title="Reverse Proxy" expanded={expanded === 'reverseProxy'} onToggle={() => toggle('reverseProxy')}
                            description={config.security?.behindReverseProxy ? 'Behind proxy' : 'Direct'} tag="restart" />
                        {expanded === 'reverseProxy' && (
                            <div className="p-4 border-t border-line space-y-4">
                                <div className="bg-info-soft border border-info/40 rounded p-3 text-xs text-info">
                                    Settings for running behind a load balancer or reverse proxy. The proxy mode flag lives in the
                                    <strong> security</strong> section and its Save writes only that flag. The trusted CIDRs live in the
                                    <strong> http</strong> section, so that Save writes the whole HTTP section, including any unsaved edits
                                    on the General → HTTP card.
                                </div>
                                <ConfigToggle label="Behind Reverse Proxy" checked={config.security.behindReverseProxy ?? false} path="security.behindReverseProxy" onChange={(v) => update('security', 'behindReverseProxy', v)}
                                    hintTone={config.security.behindReverseProxy && !config.http.trustedProxyCidrs ? 'warn' : 'muted'}
                                    hint={config.security.behindReverseProxy && !config.http.trustedProxyCidrs
                                        ? 'On, but no trusted CIDRs are listed: only loopback is trusted, so every client will appear to come from the proxy and per-IP limits and bindings collapse onto one address.'
                                        : 'Rate limiting and IP binding use the client address from X-Forwarded-For sent by a proxy in the ranges below. If on with no proxy in front, any client can forge its address.'} />
                                <SaveButton saving={saving === 'securityProxy'} onClick={() => saveSecurityFields(['behindReverseProxy'], 'securityProxy')} label="Save Proxy Mode" />
                                <ConfigInput label="Trusted Proxy CIDRs" value={config.http.trustedProxyCidrs} path="http.trustedProxyCidrs" onChange={(v) => update('http', 'trustedProxyCidrs', v)} placeholder="10.0.0.0/8, 172.16.0.0/12"
                                    hint="Only proxies in these ranges may set forwarded headers. Empty means loopback only. Name the actual proxy subnet, not RFC1918 wholesale." />
                                <SaveButton saving={saving === 'http'} onClick={() => saveSection('http', config.http, 'http')} label="Save HTTP Section" blockedReason={httpBlocked} />
                            </div>
                        )}
                    </div>

                    {/* Key ceremonies: the instance's requirement, stored on the SecurityPolicy row and
                        edited in its own card so it can be found and linked to. */}
                    <div className={`${cardClass} scroll-mt-4`} id={KEY_CEREMONIES_ANCHOR}>
                        <SectionHeader title="Key Ceremonies" expanded={expanded === 'keyCeremonies'} onToggle={() => toggle('keyCeremonies')}
                            description={securityPolicy
                                ? (securityPolicy.requireKeyCeremony === false ? 'Off for instance CAs' : 'Required for instance CAs')
                                : 'Loading...'} tag="live" />
                        {expanded === 'keyCeremonies' && (
                            <div className="p-4 border-t border-line space-y-4">
                                {securityPolicyLoading && <div className="text-sm text-ink-muted">Loading...</div>}
                                {securityPolicyError && <InlineNotice notice={securityPolicyError} />}
                                {securityPolicy && (
                                    <>
                                        <p className="text-xs text-ink-muted">
                                            A key ceremony makes other administrators approve before a CA is created, revoked or deleted.
                                            Whoever starts one can never approve it, so it needs at least one other administrator. This
                                            switch covers the instance&apos;s own CAs (the system signing CA and SSH CAs). Each space has
                                            its own switch, on its page under <Link to="/spaces" className="underline">Spaces</Link>.
                                        </p>
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                            <ConfigToggle label="Require key ceremonies for instance CAs" checked={securityPolicy.requireKeyCeremony ?? true} onChange={(v) => updateSecurityPolicyField('requireKeyCeremony', v)}
                                                hintTone={securityPolicy.requireKeyCeremony === false ? 'warn' : 'muted'}
                                                hint="Creating, revoking or deleting an instance CA needs a key ceremony. Off lets an administrator do it directly." />
                                            <ConfigNumber label="Approvals required (min 1)" value={securityPolicy.ceremonyRequiredApprovals} onChange={(v) => updateSecurityPolicyField('ceremonyRequiredApprovals', v)} fallback={2}
                                                hint="Approvals from other people for a key ceremony on an instance CA. The initiator is never counted." />
                                        </div>
                                        {instanceCeremonyWarning && (
                                            <div role="alert" className="bg-warn-soft border border-warn/40 rounded p-3 text-xs text-warn">
                                                {instanceCeremonyWarning}{' '}
                                                <Link to={USERS_PATH} className="underline font-medium">Add an administrator</Link>
                                            </div>
                                        )}
                                        {!user?.isSuper && (
                                            <p className="text-[11px] text-ink-muted">
                                                Only a system super-administrator changes these directly. Saving a change opens a ceremony
                                                that another system administrator approves.
                                            </p>
                                        )}
                                        <SaveButton saving={securityPolicySaving} onClick={handleSaveSecurityPolicy} label="Save Key Ceremony Policy" />
                                    </>
                                )}
                            </div>
                        )}
                    </div>

                    {/* Security Policy (DB) — runtime-tunable session/MFA/OCSP/approval.
                        Login lockout moved to the Login Protection card above. */}
                    <div className={cardClass}>
                        <SectionHeader title="Security Policy" expanded={expanded === 'securityPolicy'} onToggle={() => toggle('securityPolicy')}
                            description={securityPolicy ? `Session, MFA & OCSP policy` : 'Loading...'} tag="live" />
                        {expanded === 'securityPolicy' && (
                            <div className="p-4 border-t border-line space-y-4">
                                {securityPolicyLoading && <div className="text-sm text-ink-muted">Loading...</div>}
                                {securityPolicyError && <InlineNotice notice={securityPolicyError} />}
                                {securityPolicy && (
                                    <>
                                        <div className="bg-ok-soft border border-ok/40 rounded p-3 text-xs text-ok">
                                            Stored in the DB-backed <code className="bg-sunken px-1 rounded">SecurityPolicy</code> table.
                                            Changes take effect on the next request scope after save (step-up MFA required).
                                        </div>
                                        <div className="text-[11px] text-ink-muted">Login lockout moved to the <strong>Login Protection</strong> card above.</div>
                                        <h4 className="text-xs font-semibold text-ink-muted uppercase tracking-wide">Session</h4>
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                            <ConfigNumber label="Session Idle Timeout (min, 0 = none)" value={securityPolicy.sessionIdleTimeoutMinutes} onChange={(v) => updateSecurityPolicyField('sessionIdleTimeoutMinutes', v)}
                                                hint="Minutes without any request before the session ends and the user must log in again. 0 means a session never ends from inactivity." />
                                            <ConfigNumber label="Max Concurrent Sessions (0 = unlimited)" value={securityPolicy.maxConcurrentSessions} onChange={(v) => updateSecurityPolicyField('maxConcurrentSessions', v)}
                                                hint="Devices or browsers one user may be logged in from at once. Logging in beyond this ends the oldest session." />
                                            <ConfigNumber label="Max Session Lifetime (days, 0 = unlimited)" value={securityPolicy.maxSessionLifetimeDays} onChange={(v) => updateSecurityPolicyField('maxSessionLifetimeDays', v)}
                                                hint="Hard cap from first login, however active the user is; after this a fresh login is required. 0 removes the cap." />
                                        </div>
                                        <h4 className="text-xs font-semibold text-ink-muted uppercase tracking-wide pt-2">Approval &amp; mTLS</h4>
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                            <ConfigToggle label="Allow System Super Self-Approval" checked={securityPolicy.allowSystemSuperSelfApproval ?? false} onChange={(v) => updateSecurityPolicyField('allowSystemSuperSelfApproval', v)}
                                                disabled={!user?.isSuper}
                                                hintTone={securityPolicy.allowSystemSuperSelfApproval ? 'warn' : 'muted'}
                                                hint={`Members of system-super may approve certificate requests they submitted themselves, and that approval completes the request whatever its profile's count; it is recorded as self-approved. Keeps a single-administrator install working, and removes the two-person check for those accounts. Setup turns it on when you answer that you alone will administer the CA.${(securityPolicy.allowSystemSuperSelfApproval && (systemSuperCount ?? 0) > 1) ? ` There are now ${systemSuperCount} system super-administrators: consider turning this off so requests need someone else's approval.` : ''}${user?.isSuper ? '' : ' Only a system super-administrator can change this.'}`} />
                                            <ConfigToggle label="Require mTLS OCSP Check" checked={securityPolicy.requireMtlsOcspCheck ?? false} onChange={(v) => updateSecurityPolicyField('requireMtlsOcspCheck', v)}
                                                hint="Client certificates presented for mTLS login are checked for revocation against the issuing CA. Off means a revoked certificate still logs in until it expires." />
                                        </div>
                                        <h4 className="text-xs font-semibold text-ink-muted uppercase tracking-wide pt-2">MFA / Step-Up</h4>
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
                                        <h4 className="text-xs font-semibold text-ink-muted uppercase tracking-wide pt-2">OCSP Responder</h4>
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
                                        <h4 className="text-xs font-semibold text-ink-muted uppercase tracking-wide pt-2">Controlled-User Ceremonies</h4>
                                        <p className="text-[11px] text-ink-muted">
                                            <strong>User quorum</strong> = approvals required to promote / demote / delete a controlled user (admin / operator / CA-admin)
                                            when initiated by a non-super. Distinct from the <strong>key quorum</strong> (CA-ceremony approvals, set per space in Spaces and for the instance in the Key Ceremonies card above).
                                            The initiator is always excluded, so the effective minimum is 1 other approver.
                                        </p>
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                            <ConfigNumber label="User Quorum (min 1)" value={securityPolicy.userQuorum} onChange={(v) => updateSecurityPolicyField('userQuorum', v)} fallback={1} disabled={!user?.isSuper}
                                                hint="Approvals from other people. The initiator is always excluded, so the effective minimum is 1 other approver. Spaces and CAs may set a lower figure, never a higher one." />
                                        </div>
                                        <h4 className="text-xs font-semibold text-ink-muted uppercase tracking-wide pt-2">Instance CA Policy</h4>
                                        <p className="text-[11px] text-ink-muted">
                                            Governs the instance's own CAs only (no space: the system signing CA, SSH CAs). Each space keeps its own
                                            policy, set in Spaces; the two are independent and nothing merges. System administrators only. The key
                                            ceremony requirement and its approvals are in the <strong>Key Ceremonies</strong> card above.
                                        </p>
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                            <ConfigNumber label="Max Cert Validity (days, 0 = unlimited)" value={securityPolicy.maxValidityDays} onChange={(v) => updateSecurityPolicyField('maxValidityDays', v)}
                                                hint="Longest validity a leaf issued by an instance CA may carry." />
                                            <ConfigSelect label="Over the ceiling" value={securityPolicy.validityCeilingBehavior || 'Shorten'} options={['Shorten', 'Refuse']} onChange={(v) => updateSecurityPolicyField('validityCeilingBehavior', v)}
                                                hint="Refuse applies to admin issuance only; enrollment protocols and automatic renewals always shorten." />
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
                            <div className="p-4 border-t border-line space-y-4">
                                {securityPolicyLoading && <div className="text-sm text-ink-muted">Loading...</div>}
                                {securityPolicyError && <InlineNotice notice={securityPolicyError} />}
                                {securityPolicy && (
                                    <>
                                        <div className="bg-warn-soft border border-warn/40 rounded p-3 text-xs text-warn">
                                            Users must acknowledge this banner before reaching the login page. Stored on the
                                            <code className="bg-sunken px-1 rounded mx-1">SecurityPolicy</code>row; step-up MFA required to save.
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
                            <div className="p-4 border-t border-line space-y-4">
                                {policyLoading && <div className="text-sm text-ink-muted">Loading...</div>}
                                {policyError && <InlineNotice notice={policyError} />}
                                {policy && (
                                    <>
                                        <p className="text-[11px] text-ink-muted">
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
                                                            className="w-4 h-4 bg-raised border-line-strong rounded"
                                                        />
                                                        <label htmlFor={`pw-${key}`} className="text-xs text-ink">{POLICY_FIELDS[key]?.label ?? key}</label>
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
                            description={`Expiry: ${config.jwt?.expirationMinutes || 120}m`} tag="restart" />
                        {expanded === 'jwt' && (
                            <div className="p-4 border-t border-line space-y-2">
                                <DetailField label="Expiration (minutes)" value={String(config.jwt.expirationMinutes)} />
                                <DetailField label="Issuer" value={config.jwt.issuer} />
                                <DetailField label="Audience" value={config.jwt.audience} />
                                <DetailField label="Secret" value={jwtSecretLine} />
                                <div className="text-xs text-ink-muted mt-2">Expiration, issuer and audience are changed on the host with the <code className="mono">--settings</code> command, and a change takes effect when the node next starts. The secret is never shown.</div>
                                {jwtSecretState === 'waiting' && (
                                    <div className="bg-warn-soft border border-warn/40 rounded p-3 text-xs text-warn">
                                        A new secret is stored and waits for a restart. This node signs and accepts sessions with the previous
                                        one until it restarts (Restart Server, on the General tab).
                                    </div>
                                )}
                                {rotateJwtError && (
                                    <div className="px-4 py-2 bg-crit-soft border border-crit/40 rounded text-crit text-sm">{rotateJwtError}</div>
                                )}
                                <div className="flex items-center gap-3 pt-2 flex-wrap">
                                    <button type="button" onClick={() => setConfirmRotateJwt(true)} disabled={rotatingJwt || !!jwtRotateBlocked} className={actionButton}>
                                        {rotatingJwt ? 'Rotating...' : 'Rotate secret'}
                                    </button>
                                    <span className="text-xs text-ink-muted">
                                        {jwtRotateBlocked || 'Generates a new secret and stores it wrapped by the signer. Each node uses it from its next start.'}
                                    </span>
                                </div>
                                <ConfirmModal
                                    isOpen={confirmRotateJwt}
                                    title="Rotate JWT secret"
                                    message="Generate a new JWT secret? It is stored now and used from each node's next start. From then on, access tokens signed with the old secret are refused, so everyone signed in has to sign in again. Until every node has restarted, a node on the old secret and one on the new do not accept each other's sessions. This cannot be undone."
                                    confirmLabel="Rotate"
                                    tone="warn"
                                    loading={rotatingJwt}
                                    onConfirm={rotateJwtSecret}
                                    onCancel={() => setConfirmRotateJwt(false)}
                                />
                            </div>
                        )}
                    </div>

                    {/* mTLS */}
                    <div className={cardClass}>
                        <SectionHeader fields={CARD_FIELDS.mtls} title="mTLS" expanded={expanded === 'mtls'} onToggle={() => toggle('mtls')}
                            description={config.mtls?.enabled ? (config.mtls.authSubdomain || 'AuthSubdomain not set') : 'Disabled'} tag="restart" />
                        {expanded === 'mtls' && (
                            <div className="p-4 border-t border-line space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigToggle label="Enabled" checked={config.mtls?.enabled ?? false} path="mtls.enabled" onChange={(v) => update('mtls', 'enabled', v)}
                                        hint="Offers certificate-based login: connections to the auth subdomain are asked for a client certificate; every other hostname gets a normal handshake." />
                                    <ConfigInput label="Auth Subdomain" value={config.mtls?.authSubdomain} path="mtls.authSubdomain" onChange={(v) => update('mtls', 'authSubdomain', v)} placeholder="mtls.ca.example.com"
                                        hint="Hostname whose TLS handshake requests a client certificate. Needs DNS pointing here and the Web TLS certificate's SANs must include it, or clients fail before login." />
                                    <ConfigChips label="Required Paths" value={listFromValue(config.mtls?.requiredPaths)} path="mtls.requiredPaths" onChange={(v) => update('mtls', 'requiredPaths', v)}
                                        validate={validatePathPrefix} mono placeholder="/api/v1/admin"
                                        hint="Path prefixes that refuse any request not carrying a valid client certificate, regardless of hostname." />
                                    <div className="md:col-span-2">
                                        <ConfigChips label="Trusted CA Cert Paths" value={listFromValue(config.mtls?.trustedCaCertPaths)} path="mtls.trustedCaCertPaths" onChange={(v) => update('mtls', 'trustedCaCertPaths', v)}
                                            validate={validateAbsoluteFilePath} mono placeholder="/etc/modularca/client-ca.pem"
                                            hint="Absolute paths of PEM files on the server, for the CAs whose certificates count as a login. A certificate from any other issuer is rejected at the handshake. Each file is checked when you save." />
                                    </div>
                                </div>
                                <SaveButton saving={saving === 'mtls'} onClick={() => saveSection('mtls', config.mtls, 'mtls')} blockedReason={mtlsBlocked} />
                            </div>
                        )}
                    </div>

                    {/* IP Whitelist */}
                    <div className={cardClass}>
                        <SectionHeader fields={CARD_FIELDS.ipwhitelist} title="IP Whitelist" expanded={expanded === 'ipwhitelist'} onToggle={() => toggle('ipwhitelist')}
                            description={config.ipWhitelist?.enabled ? 'Enabled — managed at /admin/whitelists' : 'Disabled (master kill switch)'} tag="live" />
                        {expanded === 'ipwhitelist' && (
                            <div className="p-4 border-t border-line space-y-4">
                                <div className="bg-info-soft border border-info/40 rounded p-3 text-xs text-info">
                                    CIDR allow-list rules now live in the centralized <code className="mono">Whitelists</code> table and
                                    are managed at <Link to="/whitelists" className="underline hover:text-accent-hover">/admin/whitelists</Link>.
                                    This card only exposes the master kill switch and the path-based exempt list — both of which stay in
                                    <code className="mono"> config.yaml</code>.
                                </div>
                                <ConfigToggle label="Enabled (master kill switch)" checked={config.ipWhitelist?.enabled ?? true} path="ipWhitelist.enabled" onChange={(v) => update('ipWhitelist', 'enabled', v)}
                                    hintTone={config.ipWhitelist?.enabled === false ? 'warn' : 'muted'}
                                    hint={config.ipWhitelist?.enabled === false
                                        ? 'Off: every rule on the Whitelists page is ignored and all addresses reach every endpoint.'
                                        : 'On: each request is matched against the Whitelists rules. Turning this off bypasses all of them at once.'} />
                                <ConfigChips label="Exempt Paths" value={listFromValue(config.ipWhitelist?.exemptPaths)}
                                    path="ipWhitelist.exemptPaths" onChange={(v) => update('ipWhitelist', 'exemptPaths', v)}
                                    validate={validatePathPrefix} mono placeholder="/api/v1/public/ca"
                                    hint="Path prefixes that always pass, whatever the rules say. A prefix covers every path that starts with it, and undoes any tightening of those paths on the Whitelists page." />
                                <div className="text-xs text-ink-muted">
                                    When the master switch is off, <code className="mono">IpWhitelistMiddleware</code> short-circuits to pass-through
                                    and no rule lookup happens. When on, the middleware consults the <code className="mono">Whitelists</code> table
                                    per request via the cached <code className="mono">IWhitelistService</code>. Exempt paths always pass through
                                    regardless of the master switch — they're the path-based exclusions that bypass rule evaluation entirely.
                                </div>
                                <SaveButton saving={saving === 'ipwhitelist'} onClick={() => saveSection('ip-whitelist', config.ipWhitelist, 'ipwhitelist')} blockedReason={ipWhitelistBlocked} />
                            </div>
                        )}
                    </div>

                    {/* Rate Limiting (DB) — per-protocol policy rows */}
                    <div className={cardClass}>
                        <SectionHeader title="Rate Limiting" expanded={expanded === 'rateLimiting'} onToggle={() => toggle('rateLimiting')}
                            description={rateLimits.length ? `${rateLimits.length} protocol rows` : 'Defaults (no overrides)'} tag="live" />
                        {expanded === 'rateLimiting' && (
                            <div className="p-4 border-t border-line space-y-4">
                                <div className="bg-ok-soft border border-ok/40 rounded p-3 text-xs text-ok">
                                    Per-protocol, per-IP limits stored in the DB-backed
                                    <code className="bg-sunken px-1 mx-1 rounded">ProtocolRateLimits</code> table.
                                    Protocols without a row fall back to middleware defaults. Step-up MFA required on save.
                                    Each row means: one client IP may make at most <em>Max Requests</em> to that protocol within
                                    <em> Window Min</em> minutes; further requests get 429 until the window passes.
                                </div>
                                {rateLimitsLoading && <div className="text-sm text-ink-muted">Loading...</div>}
                                {rateLimitsError && <InlineNotice notice={rateLimitsError} />}
                                {rateLimits.length > 0 && (
                                    <>
                                        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-4">
                                            {rateLimits.map((row) => (
                                                <div key={row.protocol} className="space-y-2">
                                                    <h4 className="text-xs font-semibold text-ink uppercase tracking-wide">{row.protocol}</h4>
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
                        <SectionHeader fields={CARD_FIELDS.ldapAuth} title="LDAP Authentication" expanded={expanded === 'ldapAuth'} onToggle={() => toggle('ldapAuth')}
                            description={config.ldapAuth?.enabled ? `${config.ldapAuth.host}:${config.ldapAuth.port}` : 'Disabled'} tag="live" />
                        {expanded === 'ldapAuth' && (
                            <div className="p-4 border-t border-line space-y-4">
                                {!user?.isSuper && (
                                    <p className="text-[11px] text-ink-muted">
                                        Only a system super-administrator can change the server, TLS, bind identity, search settings or group mappings, or turn LDAP sign-in on.
                                        A directory bind signs in as the local account of the same name, so whoever controls the directory can sign in as any account.
                                        You can turn LDAP sign-in off and change group sync and auto-provisioning.
                                    </p>
                                )}
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigToggle label="Enabled" checked={config.ldapAuth.enabled} path="ldapAuth.enabled" onChange={(v) => update('ldapAuth', 'enabled', v)} disabled={!user?.isSuper && !config.ldapAuth.enabled}
                                        hint="Logins are verified by binding to the directory as the user; a successful bind is accepted as proof of the password. Applies live, no restart." />
                                    <ConfigInput label="Host" value={config.ldapAuth.host} path="ldapAuth.host" onChange={(v) => update('ldapAuth', 'host', v)} disabled={!user?.isSuper}
                                        hint="Directory server this instance binds to. Whoever controls this host can approve any login, so change it only over a verified channel." />
                                    <ConfigNumber label="Port" value={config.ldapAuth.port} path="ldapAuth.port" onChange={(v) => update('ldapAuth', 'port', v)} fallback={389} disabled={!user?.isSuper}
                                        hint="389 for plain LDAP, 636 for LDAPS." />
                                    <ConfigToggle label="Use SSL" checked={config.ldapAuth.useSsl} path="ldapAuth.useSsl" onChange={(v) => update('ldapAuth', 'useSsl', v)} disabled={!user?.isSuper}
                                        hintTone={config.ldapAuth.useSsl ? 'muted' : 'warn'}
                                        hint="Connects over LDAPS. Off sends the service-account password and every user's login password to the directory in clear text; there is no StartTLS path." />
                                    <ConfigInput label="Search Base DN" value={config.ldapAuth.searchBaseDn} path="ldapAuth.searchBaseDn" onChange={(v) => update('ldapAuth', 'searchBaseDn', v)} disabled={!user?.isSuper}
                                        hint="Subtree searched for the user's entry, e.g. OU=People,DC=example,DC=com." />
                                    <ConfigInput label="Search Filter" value={config.ldapAuth.searchFilter} path="ldapAuth.searchFilter" onChange={(v) => update('ldapAuth', 'searchFilter', v)} disabled={!user?.isSuper}
                                        hint="LDAP filter locating the user; {0} is replaced with the login name." />
                                    <ConfigInput label="Bind DN" value={config.ldapAuth.bindDn} path="ldapAuth.bindDn" onChange={(v) => update('ldapAuth', 'bindDn', v)} disabled={!user?.isSuper}
                                        hint="Service account used to search for users before they authenticate. Blank attempts an anonymous search." />
                                    {/* The bind password was previously not editable here at all, so it could
                                        only be set in config.yaml. It loads as *** when one is stored; leaving
                                        that placeholder untouched keeps the existing password. */}
                                    <ConfigInput label="Bind Password" value={config.ldapAuth.bindPassword} path="ldapAuth.bindPassword" onChange={(v) => update('ldapAuth', 'bindPassword', v)} type="password" placeholder="Leave unchanged to keep current" disabled={!user?.isSuper}
                                        hint="Shown as *** when one is stored. Leave it as-is to keep the current password; type a new one to replace it." />
                                    <ConfigToggle label="Group Sync Enabled" checked={config.ldapAuth.groupSyncEnabled} path="ldapAuth.groupSyncEnabled" onChange={(v) => update('ldapAuth', 'groupSyncEnabled', v)}
                                        hint="The LdapGroupSync job periodically re-reads each LDAP user's groups and applies the mappings below, granting and revoking local group membership to match." />
                                    <ConfigToggle label="Auto Provision Users" checked={config.ldapAuth.autoProvisionUsers} path="ldapAuth.autoProvisionUsers" onChange={(v) => update('ldapAuth', 'autoProvisionUsers', v)}
                                        hint="Has no effect: an LDAP login never creates an account. Every account is created here by an administrator, and a directory bind signs in only as the existing local account of the same name." />
                                    <ConfigInput label="Group Search Base DN" value={config.ldapAuth.groupSearchBaseDn} path="ldapAuth.groupSearchBaseDn" onChange={(v) => update('ldapAuth', 'groupSearchBaseDn', v)} disabled={!user?.isSuper}
                                        hint="Subtree searched for groups during sync." />
                                    <ConfigInput label="Group Search Filter" value={config.ldapAuth.groupSearchFilter} path="ldapAuth.groupSearchFilter" onChange={(v) => update('ldapAuth', 'groupSearchFilter', v)} disabled={!user?.isSuper}
                                        hint="Filter selecting the groups a user belongs to; {0} is replaced with the user's DN." />
                                    <ConfigInput label="Group Member Attribute" value={config.ldapAuth.groupMemberAttribute} path="ldapAuth.groupMemberAttribute" onChange={(v) => update('ldapAuth', 'groupMemberAttribute', v)} disabled={!user?.isSuper}
                                        hint="Attribute on the user entry listing its groups (memberOf on Active Directory)." />
                                    <div className="md:col-span-2">
                                        <LdapMappingsEditor value={config.ldapAuth.groupToRoleMappings} savedValue={savedConfig()?.ldapAuth?.groupToRoleMappings}
                                            onChange={(v) => update('ldapAuth', 'groupToRoleMappings', v)}
                                            disabled={!user?.isSuper} onInvalidChange={setLdapMappingsInvalid} />
                                    </div>
                                </div>
                                <SaveButton saving={saving === 'ldapAuth'} onClick={() => saveSection('ldap-auth', config.ldapAuth, 'ldapAuth')}
                                    blockedReason={ldapMappingsInvalid ? 'Fix the group mappings marked in red before saving.' : null} />
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
                        <SectionHeader fields={CARD_FIELDS.certPolicy} title="Certificate Policy" expanded={expanded === 'certPolicy'} onToggle={() => toggle('certPolicy')}
                            description={config.certPolicy?.enabled ? `Min RSA ${config.certPolicy.minRsaKeySize || 2048}` : 'Disabled'} tag="live" />
                        {expanded === 'certPolicy' && (
                            <div className="p-4 border-t border-line space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigToggle label="Enabled" checked={config.certPolicy?.enabled ?? false} path="certPolicy.enabled" onChange={(v) => update('certPolicy', 'enabled', v)}
                                        hintTone={config.certPolicy?.enabled ? 'muted' : 'warn'}
                                        hint="These rules are checked at every issuance, whatever profile is used. Off means none of them block anything." />
                                    <ConfigNumber label="Min RSA Key Size" value={config.certPolicy?.minRsaKeySize} path="certPolicy.minRsaKeySize" onChange={(v) => update('certPolicy', 'minRsaKeySize', v)} fallback={0}
                                        hint="Requests with an RSA key shorter than this are refused. 0 sets no minimum." />
                                    <ConfigToggle label="Require SANs" checked={config.certPolicy?.requireSans ?? false} path="certPolicy.requireSans" onChange={(v) => update('certPolicy', 'requireSans', v)}
                                        hint="Requests without a Subject Alternative Name are refused. Browsers ignore the Common Name, so a certificate without SANs fails hostname checks anyway." />
                                    <div className="md:col-span-2">
                                        <ConfigChips label="Forbidden Algorithms" value={listFromValue(config.certPolicy?.forbiddenAlgorithms)} path="certPolicy.forbiddenAlgorithms" onChange={(v) => update('certPolicy', 'forbiddenAlgorithms', v)}
                                            suggestions={FORBIDDEN_ALGORITHM_SUGGESTIONS} caseInsensitive mono placeholder="e.g. SHA1withRSA"
                                            hint="A request whose signature algorithm has exactly one of these names is refused at issuance (case does not matter). Use the full name, such as SHA1withRSA; a fragment like SHA1 matches nothing. An algorithm the server has no name for is matched by its OID, e.g. 1.2.840.113549.1.1.4 for MD5withRSA." />
                                    </div>
                                    <div className="md:col-span-2">
                                        <SunsetRulesEditor value={config.certPolicy?.algorithmSunsetRules}
                                            onChange={(v) => update('certPolicy', 'algorithmSunsetRules', v)} onInvalidChange={setSunsetInvalid} />
                                    </div>
                                </div>
                                <SaveButton saving={saving === 'certPolicy'} onClick={() => saveSection('certificate-policy', config.certPolicy, 'certPolicy')}
                                    blockedReason={sunsetInvalid ? 'Fix the sunset rules marked in red before saving.' : null} />
                            </div>
                        )}
                    </div>

                    {/* Auto-Renewal */}
                    <div className={cardClass}>
                        <SectionHeader fields={CARD_FIELDS.autoRenewal} title="Auto-Renewal" expanded={expanded === 'autoRenewal'} onToggle={() => toggle('autoRenewal')}
                            description={config.autoRenewal?.enabled ? `Renew ${config.autoRenewal.renewDaysBeforeExpiry || 30}d before expiry` : 'Disabled'} tag="live" />
                        {expanded === 'autoRenewal' && (
                            <div className="p-4 border-t border-line space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigToggle label="Enabled" checked={config.autoRenewal?.enabled ?? false} path="autoRenewal.enabled" onChange={(v) => update('autoRenewal', 'enabled', v)}
                                        hint="The AutoRenewal job creates renewal requests for certificates approaching expiry, with a fresh key pair. Off means certificates simply expire unless someone renews them." />
                                    <ConfigNumber label="Renew Days Before Expiry" value={config.autoRenewal?.renewDaysBeforeExpiry} path="autoRenewal.renewDaysBeforeExpiry" onChange={(v) => update('autoRenewal', 'renewDaysBeforeExpiry', v)} fallback={0}
                                        hint="Certificates within this many days of expiry are renewed on the job's next run. Leave enough margin for the renewal to be approved and deployed." />
                                    <ConfigToggle label="Auto Approve" checked={config.autoRenewal?.autoApprove ?? false} path="autoRenewal.autoApprove" onChange={(v) => update('autoRenewal', 'autoApprove', v)}
                                        hint="Renewals are issued without an administrator approving each one, unless the profile itself demands approval. Off means every renewal waits in the approval queue and expires if nobody acts." />
                                </div>
                                <ScheduleMovedNote job="AutoRenewal" />
                                <SaveButton saving={saving === 'autoRenewal'} onClick={() => saveSection('auto-renewal', { ...config.autoRenewal, schedule: '' }, 'autoRenewal')} />
                            </div>
                        )}
                    </div>

                    {/* Cert Expiry Notifications */}
                    <div className={cardClass}>
                        <SectionHeader fields={CARD_FIELDS.certExpiryNotification} title="Cert Expiry Notifications" expanded={expanded === 'certExpiryNotification'} onToggle={() => toggle('certExpiryNotification')}
                            description={config.certExpiryNotification?.enabled ? (warningDays.length ? `Warn at ${warningDays.join(', ')} days` : 'No warning days set') : 'Disabled'} tag="live" />
                        {expanded === 'certExpiryNotification' && (
                            <div className="p-4 border-t border-line space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigToggle label="Enabled" checked={config.certExpiryNotification?.enabled ?? false} path="certExpiryNotification.enabled" onChange={(v) => update('certExpiryNotification', 'enabled', v)}
                                        hint="The CertExpiryNotification job emails and webhooks a warning as certificates approach expiry. The same job reminds once, 90 days ahead, of each SSH CA key due for review. Needs Email or Webhook configured under Integrations to reach anyone." />
                                    <ConfigChips label="Warning Days" value={warningDays} path="certExpiryNotification.warningDaysBeforeExpiry" onChange={(v) => update('certExpiryNotification', 'warningDaysBeforeExpiry', v)}
                                        validate={validateWarningDay} numeric sort="desc" placeholder="e.g. 30"
                                        hint="Days before expiry, from 1 to 3650. A notice is sent once as a certificate crosses each mark; the order does not matter. Empty means no notices are sent." />
                                </div>
                                <ScheduleMovedNote job="CertExpiryNotification" />
                                <SaveButton saving={saving === 'certExpiryNotification'} onClick={() => saveSection('cert-expiry-notifications', certExpiryNotificationBody(config.certExpiryNotification, warningDays), 'certExpiryNotification')} blockedReason={expiryBlocked} />
                            </div>
                        )}
                    </div>

                    {/* Compliance Scan */}
                    <div className={cardClass}>
                        <SectionHeader fields={CARD_FIELDS.complianceScan} title="Compliance Scan" expanded={expanded === 'complianceScan'} onToggle={() => toggle('complianceScan')}
                            description={config.complianceScan?.enabled ? `Min RSA ${config.complianceScan.minRsaKeySize || 2048}` : 'Disabled'} tag="live" />
                        {expanded === 'complianceScan' && (
                            <div className="p-4 border-t border-line space-y-4">
                                <div className="bg-info-soft border border-info/40 rounded p-3 text-xs text-info">
                                    These thresholds <strong>flag existing certificates</strong> in the inventory. Issuance is enforced
                                    separately by <strong>Certificate Policy</strong> above{config.certPolicy?.enabled ? '' : ' (currently disabled)'}.
                                    Keep the two aligned to avoid surprises — the active policy baseline is shown beneath each field.
                                </div>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigToggle label="Enabled" checked={config.complianceScan?.enabled ?? false} path="complianceScan.enabled" onChange={(v) => update('complianceScan', 'enabled', v)}
                                        hint="The Compliance job scans issued certificates and records findings. It reports; it never revokes or blocks." />
                                    <div />
                                    <div>
                                        <ConfigNumber label="Min RSA Key Size" value={config.complianceScan?.minRsaKeySize} path="complianceScan.minRsaKeySize" onChange={(v) => update('complianceScan', 'minRsaKeySize', v)} fallback={0}
                                            hint="Issued certificates with a shorter RSA key are flagged as weak." />
                                        <p className="text-[10px] text-ink-muted mt-1">Policy: {config.certPolicy?.enabled ? `blocks issuance below ${config.certPolicy?.minRsaKeySize || 'unset'}` : 'enforcement off'}</p>
                                    </div>
                                    <div>
                                        <ConfigNumber label="Warn Over Validity Days" value={config.complianceScan?.warnOverValidityDays} path="complianceScan.warnOverValidityDays" onChange={(v) => update('complianceScan', 'warnOverValidityDays', v)} fallback={0} />
                                        <p className="text-[10px] text-ink-muted mt-1">Reports only — it never blocks issuance. The enforced ceiling is per space, under Spaces &amp; Quotas.</p>
                                    </div>
                                    <div className="md:col-span-2">
                                        <ConfigChips label="Deprecated Algorithms" value={listFromValue(config.complianceScan?.deprecatedAlgorithms)} path="complianceScan.deprecatedAlgorithms" onChange={(v) => update('complianceScan', 'deprecatedAlgorithms', v)}
                                            suggestions={DEPRECATED_SUGGESTIONS} caseInsensitive mono placeholder="e.g. SHA1"
                                            hint="Issued certificates whose signature algorithm name contains one of these are flagged, ignoring case and hyphens: SHA1 matches SHA-1withRSA and SHA-1withECDSA." />
                                        <p className="text-[10px] text-ink-muted mt-1">Policy forbids at issuance: {listFromValue(config.certPolicy?.forbiddenAlgorithms).join(', ') || 'none'}</p>
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
                        <SectionHeader fields={CARD_FIELDS.email} title="Email / SMTP" expanded={expanded === 'email'} onToggle={() => toggle('email')}
                            description={config.email?.enabled ? `${config.email.authMethod} — ${config.email.smtpHost}` : 'Disabled'} tag="live" />
                        {expanded === 'email' && (
                            <div className="p-4 border-t border-line space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigToggle label="Enabled" checked={config.email.enabled} path="email.enabled" onChange={(v) => update('email', 'enabled', v)}
                                        hint="Expiry notices, alerts and approval mail go out over SMTP. Off means they are dropped silently." />
                                    <ConfigInput label="SMTP Host" value={config.email.smtpHost} path="email.smtpHost" onChange={(v) => update('email', 'smtpHost', v)} placeholder="smtp.example.com" />
                                    <ConfigNumber label="SMTP Port" value={config.email.smtpPort} path="email.smtpPort" onChange={(v) => update('email', 'smtpPort', v)} fallback={587}
                                        hint="587 for submission with STARTTLS, 465 for implicit TLS, 25 for unauthenticated relay." />
                                    <ConfigToggle label="Use TLS" checked={config.email.useTls} path="email.useTls" onChange={(v) => update('email', 'useTls', v)}
                                        hintTone={config.email.useTls ? 'muted' : 'warn'}
                                        hint="Encrypts the connection to the mail server. Off sends the credentials and every message in clear text." />
                                    <ConfigSelect label="Auth Method" value={config.email.authMethod || 'Password'} options={['Password', 'OAuth2Token', 'OAuth2ClientCredentials']} path="email.authMethod" onChange={(v) => update('email', 'authMethod', v)}
                                        hint="Password: username and password. OAuth2Token: a token you obtained elsewhere, which expires and must be replaced by hand. OAuth2ClientCredentials: tokens are fetched automatically from the token URL." />
                                    <ConfigInput label="Username" value={config.email.username} path="email.username" onChange={(v) => update('email', 'username', v)} />

                                    {(config.email.authMethod === 'Password' || !config.email.authMethod) && (
                                        <ConfigInput label="Password" value={config.email.password} path="email.password" onChange={(v) => update('email', 'password', v)} type="password" />
                                    )}

                                    {config.email.authMethod === 'OAuth2Token' && (
                                        <ConfigInput label="OAuth2 Access Token" value={config.email.oAuth2AccessToken} path="email.oAuth2AccessToken" onChange={(v) => update('email', 'oAuth2AccessToken', v)} type="password"
                                            hint="Sent as-is with each message. Mail stops when it expires." />
                                    )}

                                    {config.email.authMethod === 'OAuth2ClientCredentials' && (
                                        <>
                                            <ConfigInput label="OAuth2 Client ID" value={config.email.oAuth2ClientId} path="email.oAuth2ClientId" onChange={(v) => update('email', 'oAuth2ClientId', v)} />
                                            <ConfigInput label="OAuth2 Client Secret" value={config.email.oAuth2ClientSecret} path="email.oAuth2ClientSecret" onChange={(v) => update('email', 'oAuth2ClientSecret', v)} type="password" />
                                            <ConfigInput label="OAuth2 Token URL" value={config.email.oAuth2TokenUrl} path="email.oAuth2TokenUrl" onChange={(v) => update('email', 'oAuth2TokenUrl', v)} placeholder="https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
                                                hint="Token endpoint tokens are fetched from. Google: https://oauth2.googleapis.com/token" />
                                            <ConfigInput label="OAuth2 Scopes" value={config.email.oAuth2Scopes} path="email.oAuth2Scopes" onChange={(v) => update('email', 'oAuth2Scopes', v)} placeholder="https://outlook.office365.com/.default"
                                                hint="Space-separated. Empty defaults to the Microsoft 365 SMTP scope. Google: https://mail.google.com/" />
                                        </>
                                    )}

                                    <ConfigInput label="From Address" value={config.email.fromAddress} path="email.fromAddress" onChange={(v) => update('email', 'fromAddress', v)} placeholder="ca@example.com"
                                        hint="Must be an address the mail server allows this account to send as, or messages are rejected." />
                                    <ConfigInput label="From Name" value={config.email.fromName} path="email.fromName" onChange={(v) => update('email', 'fromName', v)} />
                                    <div className="md:col-span-2">
                                        <ConfigChips label="Admin Recipients" value={listFromValue(config.email.adminRecipients)} path="email.adminRecipients" onChange={(v) => update('email', 'adminRecipients', listToCsv(v))}
                                            validate={validateEmail} caseInsensitive placeholder="admin@example.com"
                                            hint="Addresses that receive system alerts (backup failures, scheduler failures, security changes). Empty means alerts reach nobody by mail." />
                                    </div>
                                </div>
                                <SaveButton saving={saving === 'email'} onClick={() => saveSection('email', config.email, 'email')} blockedReason={emailBlocked} />
                            </div>
                        )}
                    </div>

                    {/* Webhook */}
                    <div className={cardClass}>
                        <SectionHeader fields={CARD_FIELDS.webhook} title="Webhook" expanded={expanded === 'webhook'} onToggle={() => toggle('webhook')}
                            description={config.webhook?.enabled ? `Enabled, ${config.webhook.maxRetries || 3} retries` : 'Disabled'} tag="live" />
                        {expanded === 'webhook' && (
                            <div className="p-4 border-t border-line space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigToggle label="Enabled" checked={config.webhook?.enabled ?? false} path="webhook.enabled" onChange={(v) => update('webhook', 'enabled', v)}
                                        hint="Certificate lifecycle events are POSTed to the endpoints in config.yaml. Off means no deliveries are attempted." />
                                    <ConfigNumber label="Max Retries" value={config.webhook?.maxRetries} path="webhook.maxRetries" onChange={(v) => update('webhook', 'maxRetries', v)} fallback={3}
                                        hint="Further attempts after a failed delivery before the event is dropped." />
                                    <ConfigNumber label="Retry Delay Seconds" value={config.webhook?.retryDelaySeconds} path="webhook.retryDelaySeconds" onChange={(v) => update('webhook', 'retryDelaySeconds', v)} fallback={10}
                                        hint="Wait before the first retry; each later retry waits exponentially longer." />
                                </div>
                                <div className="bg-info-soft border border-info/40 rounded p-3 text-xs text-info">
                                    Webhook endpoints are configured in config.yaml. These settings control the global retry behavior for all endpoints.
                                </div>
                                <SaveButton saving={saving === 'webhook'} onClick={() => saveSection('webhook', config.webhook, 'webhook')} />
                            </div>
                        )}
                    </div>

                    {/* Cert-Manager Integration */}
                    <div className={cardClass}>
                        <SectionHeader fields={CARD_FIELDS.certManager} title="Cert-Manager Integration" expanded={expanded === 'certManager'} onToggle={() => toggle('certManager')}
                            description={config.certManager?.enabled ? 'Enabled' : 'Disabled'} tag="restart" />
                        {expanded === 'certManager' && (
                            <div className="p-4 border-t border-line space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigToggle label="Enabled" checked={config.certManager?.enabled ?? false} path="certManager.enabled" onChange={(v) => update('certManager', 'enabled', v)}
                                        hint="Opens /api/v1/integration/cert-manager/sign to any caller presenting the API key; that caller can obtain certificates without a human approval." />
                                    <ConfigInput label="API Key" value={config.certManager?.apiKey} path="certManager.apiKey" onChange={(v) => update('certManager', 'apiKey', v)} type="password"
                                        hint="The one key every client shares, sent in X-API-Key. Named keys below are the better choice: each cluster gets its own, and one can be revoked alone. This key keeps working beside them." />
                                    <ConfigInput label="Default Cert Profile ID" value={config.certManager?.defaultCertProfileId} path="certManager.defaultCertProfileId" onChange={(v) => update('certManager', 'defaultCertProfileId', v)}
                                        hint="Certificate profile applied when a signing request names none." />
                                    <ConfigInput label="Default Signing Profile ID" value={config.certManager?.defaultSigningProfileId} path="certManager.defaultSigningProfileId" onChange={(v) => update('certManager', 'defaultSigningProfileId', v)}
                                        hint="Decides which CA signs when the request names no signing profile." />
                                </div>
                                <SaveButton saving={saving === 'certManager'} onClick={() => saveSection('cert-manager', config.certManager, 'certManager')} />
                                <div className="pt-4 border-t border-line">
                                    <ApiKeysPanel integration="cert-manager" />
                                </div>
                            </div>
                        )}
                    </div>

                    {/* Integration API */}
                    <div className={cardClass}>
                        <SectionHeader fields={CARD_FIELDS.integrationApi} title="Integration API" expanded={expanded === 'integrationApi'} onToggle={() => toggle('integrationApi')}
                            description={config.integrationApi?.enabled ? 'Enabled' : 'Disabled'} tag="restart" />
                        {expanded === 'integrationApi' && (
                            <div className="p-4 border-t border-line space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigToggle label="Enabled" checked={config.integrationApi?.enabled ?? false} path="integrationApi.enabled" onChange={(v) => update('integrationApi', 'enabled', v)}
                                        hint="Opens the infrastructure-as-code endpoints (Terraform, Ansible) to any caller presenting the API key." />
                                    <ConfigInput label="API Key" value={config.integrationApi?.apiKey} path="integrationApi.apiKey" onChange={(v) => update('integrationApi', 'apiKey', v)} type="password"
                                        hint="The one key every client shares, sent in X-API-Key. Named keys below are the better choice: each tool gets its own, and one can be revoked alone. This key keeps working beside them." />
                                </div>
                                <SaveButton saving={saving === 'integrationApi'} onClick={() => saveSection('integration-api', config.integrationApi, 'integrationApi')} />
                                <div className="pt-4 border-t border-line">
                                    <ApiKeysPanel integration="integration" />
                                </div>
                            </div>
                        )}
                    </div>

                    {/* ACME Policies */}
                    <div className={cardClass}>
                        <SectionHeader fields={CARD_FIELDS.acme} title="ACME Policies" expanded={expanded === 'acme'} onToggle={() => toggle('acme')}
                            description={`EAB: ${config.acme?.externalAccountRequired ? 'Required' : 'Off'}, CAA: ${config.acme?.enforceCaa ? 'On' : 'Off'}, ToS: ${config.acme?.termsOfServiceUrl ? 'Published' : 'None'}`} tag="live" />
                        {expanded === 'acme' && (
                            <div className="p-4 border-t border-line space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigToggle label="External Account Required" checked={config.acme?.externalAccountRequired ?? false} path="acme.externalAccountRequired" onChange={(v) => update('acme', 'externalAccountRequired', v)}
                                        hint="New ACME accounts must carry an externalAccountBinding signed with a pre-shared key issued here. Clients without one cannot register, which is how you keep the directory from being open to anyone who can reach it." />
                                    <ConfigToggle label="Enforce CAA" checked={config.acme?.enforceCaa ?? false} path="acme.enforceCaa" onChange={(v) => update('acme', 'enforceCaa', v)}
                                        hint="Before issuing, the DNS CAA records for each requested name are checked; a record that does not name this CA blocks issuance. Needs working DNS resolution from this host." />
                                </div>
                                <ConfigInput label="Terms of Service URL" value={config.acme?.termsOfServiceUrl} path="acme.termsOfServiceUrl" onChange={(v) => update('acme', 'termsOfServiceUrl', v)} placeholder="https://ca.example.com/terms (leave empty to publish none)" />
                                <p className="text-xs text-ink-muted">
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
                        <SectionHeader fields={CARD_FIELDS.policySync} title="Policy Sync" expanded={expanded === 'policySync'} onToggle={() => toggle('policySync')}
                            description={config.policySync?.enabled ? `Dir: ${config.policySync.policyDirectory || 'Not set'}` : 'Disabled'} tag="live" />
                        {expanded === 'policySync' && (
                            <div className="p-4 border-t border-line space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigToggle label="Enabled" checked={config.policySync?.enabled ?? false} path="policySync.enabled" onChange={(v) => update('policySync', 'enabled', v)}
                                        hint="Profile definitions are imported from YAML files in the directory below, GitOps-style. Imported files overwrite the database copy of a profile with the same name." />
                                    <ConfigInput label="Policy Directory" value={config.policySync?.policyDirectory} path="policySync.policyDirectory" onChange={(v) => update('policySync', 'policyDirectory', v)} placeholder="/etc/modular-ca/policies"
                                        hint="Directory scanned for *.yaml profile files. A relative path resolves from the application directory." />
                                    <ConfigToggle label="Sync On Startup" checked={config.policySync?.syncOnStartup ?? false} path="policySync.syncOnStartup" onChange={(v) => update('policySync', 'syncOnStartup', v)}
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
                                        className="px-4 py-2 text-sm bg-accent text-on-accent rounded hover:bg-accent-hover disabled:opacity-50 transition-colors"
                                    >
                                        {saving === 'policySyncNow' ? 'Syncing...' : 'Sync Now'}
                                    </button>
                                </div>
                            </div>
                        )}
                    </div>

                    {/* Alert */}
                    <div className={cardClass}>
                        <SectionHeader fields={CARD_FIELDS.alert} title="Alert" expanded={expanded === 'alert'} onToggle={() => toggle('alert')}
                            description={config.alert?.enabled ? `Min severity: ${config.alert.minimumSeverity || 'Warning'}` : 'Disabled'} tag="live" />
                        {expanded === 'alert' && (
                            <div className="p-4 border-t border-line space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigToggle label="Enabled" checked={config.alert?.enabled ?? false} path="alert.enabled" onChange={(v) => update('alert', 'enabled', v)}
                                        hint="Security and operational alerts (stale backups, failing jobs, config changes) are sent to the admin recipients and webhooks. Off means they are only logged." />
                                    <ConfigSelect label="Minimum Severity" value={config.alert?.minimumSeverity || 'Warning'} options={['Critical', 'Warning', 'Info']} path="alert.minimumSeverity" onChange={(v) => update('alert', 'minimumSeverity', v)}
                                        hint="Alerts below this severity are not sent. Info includes routine events and is noisy; Critical alone would drop backup and scheduler warnings until they escalate." />
                                    <ConfigNumber label="Cooldown Minutes" value={config.alert?.cooldownMinutes} path="alert.cooldownMinutes" onChange={(v) => update('alert', 'cooldownMinutes', v)}
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
                        <SectionHeader fields={CARD_FIELDS.logging} title="Logging" expanded={expanded === 'logging'} onToggle={() => toggle('logging')}
                            description={config.logging?.minLevel || 'Information'} tag="live" />
                        {expanded === 'logging' && (
                            <div className="p-4 border-t border-line space-y-4">
                                <ConfigSelect label="Min Level" value={config.logging.minLevel || 'Information'} options={['Debug', 'Information', 'Warning', 'Error']} path="logging.minLevel" onChange={(v) => update('logging', 'minLevel', v)}
                                    hint="Events below this level are discarded. Debug records every request in detail and fills the disk quickly; Warning hides normal operation, so a quiet log no longer means a healthy service." />
                                <div className="text-xs text-ink-muted">
                                    Log level changes take effect immediately — no restart needed. This Save writes only the level; the
                                    storage fields below have their own Save.
                                </div>
                                <SaveButton saving={saving === 'logging'} onClick={() => saveSection('logging', { minLevel: config.logging.minLevel }, 'logging')} label="Save Level" />
                            </div>
                        )}
                    </div>

                    {/* Log Storage (restart) */}
                    <div className={cardClass}>
                        <SectionHeader fields={CARD_FIELDS.logStorage} title="Log Storage" expanded={expanded === 'logStorage'} onToggle={() => toggle('logStorage')}
                            description={`${config.logging?.retentionDays || 30}d retention, ${config.logging?.maxFileSizeMb || 100}MB max`} tag="restart" />
                        {expanded === 'logStorage' && (
                            <div className="p-4 border-t border-line space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigInput label="File Path" value={config.logging.filePath} path="logging.filePath" onChange={(v) => update('logging', 'filePath', v)}
                                        hint="Log file path; the date is inserted before the extension on each daily roll. A relative path resolves from the application directory." />
                                    <ConfigNumber label="Retention Days" value={config.logging.retentionDays} path="logging.retentionDays" onChange={(v) => update('logging', 'retentionDays', v)} fallback={30}
                                        hint="Log files older than this are deleted. The audit log is separate and is not affected." />
                                    <ConfigNumber label="Max File Size (MB)" value={config.logging.maxFileSizeMb ?? 100} path="logging.maxFileSizeMb" onChange={(v) => update('logging', 'maxFileSizeMb', v)} fallback={100}
                                        hint="A file that reaches this size rolls to a new one, in addition to the daily roll." />
                                    <ConfigSelect label="Console Format" value={config.logging.consoleFormat || 'Auto'} options={['Auto', 'Systemd', 'Json', 'Text']} path="logging.consoleFormat" onChange={(v) => update('logging', 'consoleFormat', v)} />
                                </div>
                                <div className="text-xs text-ink-muted">
                                    Log files roll daily and when they reach the max file size. Old files are deleted after the retention period.
                                    This Save writes the whole logging section, including the level above.
                                </div>
                                <div className="text-xs text-ink-muted">
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
                        <SectionHeader fields={CARD_FIELDS.networkAudit} title="Network Audit" expanded={expanded === 'networkAudit'} onToggle={() => toggle('networkAudit')}
                            description={config.networkAudit?.enabled ? 'Enabled' : 'Disabled'} tag="restart" />
                        {expanded === 'networkAudit' && (
                            <div className="p-4 border-t border-line space-y-4">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <ConfigToggle label="Enabled" checked={config.networkAudit?.enabled ?? false} path="networkAudit.enabled" onChange={(v) => update('networkAudit', 'enabled', v)}
                                        hint="Every protocol and admin request is recorded (who, what, from where). Off removes the request trail auditors expect." />
                                    <div>
                                        <ConfigToggle label="Log All Requests" checked={config.networkAudit?.logAllRequests ?? false} path="networkAudit.logAllRequests" onChange={(v) => update('networkAudit', 'logAllRequests', v)}
                                            hint="Off records protocol and admin endpoints only. On records everything, static files included." />
                                        {config.networkAudit?.logAllRequests && (
                                            <div className="bg-warn-soft border border-warn/40 rounded p-2 text-xs text-warn mt-2">
                                                Enabling logs ALL HTTP requests including static files. This can generate significant log volume.
                                            </div>
                                        )}
                                    </div>
                                    <div className="md:col-span-2">
                                        <ConfigChips label="Exclude Paths" value={listFromValue(config.networkAudit?.excludePaths)}
                                            path="networkAudit.excludePaths" onChange={(v) => update('networkAudit', 'excludePaths', v)}
                                            validate={validatePathPrefix} mono placeholder="/health"
                                            hint="Path prefixes never recorded, typically health checks and metrics scrapes that would otherwise dominate the log." />
                                    </div>
                                </div>
                                <SaveButton saving={saving === 'networkAudit'} onClick={() => saveSection('network-audit', config.networkAudit, 'networkAudit')} blockedReason={networkAuditBlocked} />
                            </div>
                        )}
                    </div>

                </>
            )}
        </div>
        </SettingsMetaContext.Provider>
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

    if (loading) return <div className="p-4 text-sm text-ink-muted">Loading...</div>;
    if (error) return <InlineNotice notice={error} />;

    return (
        <div className="bg-raised border border-line rounded-lg overflow-hidden">
            <div className="px-4 py-3 border-b border-line">
                <h3 className="text-sm font-semibold text-ink">Feature Flags</h3>
            </div>
            <div className="px-4 py-3 border-b border-line bg-info-soft text-xs text-info">
                Changes here apply <strong>live</strong> — toggling a feature takes effect immediately, no restart required.
                Items marked <RestartTag /> need a service restart before the change takes effect.
            </div>
            {features.length === 0 && (
                <div className="p-4 text-sm text-ink-muted text-center">No feature flags configured</div>
            )}
            {features.map((f) => (
                <div key={f.name} className="px-4 py-3 flex items-center justify-between border-b border-line last:border-b-0">
                    <div className="flex items-center gap-2">
                        <span className="text-sm text-ink">{f.name}</span>
                        {f.description && <span className="text-xs text-ink-muted">{f.description}</span>}
                        {f.requiresRestart && <RestartTag />}
                    </div>
                    <button
                        onClick={() => handleToggle(f)}
                        className={`relative w-11 h-6 rounded-full transition-colors ${f.enabled ? 'bg-accent' : 'bg-ink-faint'}`}
                    >
                        <span
                            className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full transition-transform ${f.enabled ? 'translate-x-5' : 'translate-x-0'}`}
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
            <h1 className="text-xl font-semibold text-ink">Settings</h1>

            {/* Tabs */}
            <div className="flex gap-1 border-b border-line">
                {TABS.map((tab) => (
                    <button
                        key={tab}
                        onClick={() => setActiveTab(tab)}
                        className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 ${activeTab === tab
                            ? 'text-accent-ink border-accent'
                            : 'text-ink-muted border-transparent hover:text-ink'
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
