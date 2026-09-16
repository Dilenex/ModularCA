/**
 * Self-service account page: profile edit plus the security tab.
 *
 * The two copies were 196 and 195 lines with a five-line diff, and both halves of that diff were
 * wrong in one app or the other — adminui fetched the identity/authorization endpoint to render a
 * name and an email, userui passed the step-up operation as a bare string instead of the
 * generated constant. Both were reconciled before this move.
 */
import React, { useState, useEffect } from 'react';
import { useAuthClient } from '../api/AuthClientContext';
import { useStepUp } from '../components/StepUpMfaContext';
import { useToast } from '@shared/context/ToastContext';
import { DetailField } from '@shared/components/cards/DetailField';
import { MySecurity } from './MySecurity';
import { AccessBadgesPanel } from '../components/AccessBadgesPanel';
import { StepUpOps } from '@shared/generated';

const inputClass =
    'w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:border-blue-500';
const labelClass = 'block text-xs text-gray-600 dark:text-gray-400 mb-1';

interface Account {
    id: string;
    username: string;
    email: string;
    displayName?: string | null;
    firstName?: string;
    lastName?: string;
}

/* ─── General tab: view + edit own profile ─── */
const GeneralTab: React.FC = () => {
    const { apiGet, apiPutWithMfa } = useAuthClient();
    const { requireStepUp } = useStepUp();
    const { showToast } = useToast();

    const [acct, setAcct] = useState<Account | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [mode, setMode] = useState<'view' | 'edit'>('view');
    const [saving, setSaving] = useState(false);
    const [form, setForm] = useState({ displayName: '', firstName: '', lastName: '', email: '' });

    const fillForm = (a: Account) =>
        setForm({ displayName: a.displayName || '', firstName: a.firstName || '', lastName: a.lastName || '', email: a.email || '' });

    const load = () => {
        setLoading(true);
        setError(null);
        // The self-service profile resource, and the GET that pairs with the PUT below.
        // This used to call /api/v1/me, which is the identity/authorization endpoint: it also
        // computes group memberships, effective scopes and three MFA existence checks — four
        // extra queries per page load, all of it discarded to render a name and an email.
        apiGet<Account>('/api/v1/account')
            .then((a) => { setAcct(a); fillForm(a); })
            .catch((e) => setError(e.message || 'Failed to load account'))
            .finally(() => setLoading(false));
    };
    useEffect(load, []);

    const dirty = !!acct && (
        form.displayName !== (acct.displayName || '') ||
        form.firstName !== (acct.firstName || '') ||
        form.lastName !== (acct.lastName || '') ||
        form.email !== (acct.email || '')
    );
    const emailChanged = !!acct && form.email.trim() !== (acct.email || '');

    const cancel = () => { if (acct) fillForm(acct); setMode('view'); };

    const save = async () => {
        if (!acct) return;
        setSaving(true);
        try {
            const body = {
                displayName: form.displayName,
                firstName: form.firstName,
                lastName: form.lastName,
                email: form.email.trim(),
            };
            // Step-up only fires when the email changed — the backend returns 403 { requiresStepUp }
            // in that case and apiPutWithMfa transparently prompts + retries. Other field edits save
            // on the first try with no MFA prompt.
            const res = await apiPutWithMfa<Partial<Account> & { message?: string }>(
                '/api/v1/account', body, requireStepUp, StepUpOps.ChangeEmail, acct.id,
            );
            const next: Account = {
                ...acct,
                displayName: res.displayName ?? form.displayName,
                firstName: res.firstName ?? form.firstName,
                lastName: res.lastName ?? form.lastName,
                email: res.email ?? form.email,
            };
            setAcct(next);
            fillForm(next);
            showToast('success', res.message || 'Account updated.');
            setMode('view');
        } catch (e: any) {
            if (e.message !== 'Step-up MFA cancelled') showToast('error', e.message || 'Failed to update account.');
        } finally {
            setSaving(false);
        }
    };

    if (loading && !acct) return <div className="text-sm text-gray-600 dark:text-gray-400">Loading account…</div>;
    if (error && !acct) return <div className="text-sm text-red-800 dark:text-red-400">{error}</div>;
    if (!acct) return null;

    return (
        <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg">
            <div className="px-4 py-3 border-b border-gray-300 dark:border-gray-700 flex items-center justify-between">
                <h2 className="text-sm font-semibold text-gray-900 dark:text-white">Account Details</h2>
                {mode === 'view' && (
                    <button
                        onClick={() => setMode('edit')}
                        className="px-3 py-1 text-xs bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors"
                    >
                        Edit
                    </button>
                )}
            </div>

            <div className="p-4">
                {mode === 'view' ? (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8">
                        <DetailField label="Username" value={acct.username} mono />
                        <DetailField label="Email" value={acct.email} />
                        <DetailField label="Display Name" value={acct.displayName || '—'} />
                        <DetailField label="First Name" value={acct.firstName || '—'} />
                        <DetailField label="Last Name" value={acct.lastName || '—'} />
                    </div>
                ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div className="md:col-span-2">
                            <label className={labelClass}>Username</label>
                            <input type="text" value={acct.username} disabled className={`${inputClass} opacity-60 cursor-not-allowed font-mono`} />
                            <p className="mt-1 text-[10px] text-gray-500 dark:text-gray-500">Your login identity — changed only by an administrator.</p>
                        </div>
                        <div className="md:col-span-2">
                            <label className={labelClass}>Email</label>
                            <input type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} className={inputClass} />
                            {emailChanged && (
                                <p className="mt-1 text-[10px] text-amber-700 dark:text-amber-400">Changing your email requires step-up MFA verification on save.</p>
                            )}
                        </div>
                        <div>
                            <label className={labelClass}>First Name</label>
                            <input type="text" value={form.firstName} onChange={(e) => setForm({ ...form, firstName: e.target.value })} className={inputClass} />
                        </div>
                        <div>
                            <label className={labelClass}>Last Name</label>
                            <input type="text" value={form.lastName} onChange={(e) => setForm({ ...form, lastName: e.target.value })} className={inputClass} />
                        </div>
                        <div className="md:col-span-2">
                            <label className={labelClass}>Display Name</label>
                            <input type="text" value={form.displayName} onChange={(e) => setForm({ ...form, displayName: e.target.value })} placeholder="(optional)" className={inputClass} />
                        </div>
                    </div>
                )}
            </div>

            {mode === 'edit' && (
                <div className="px-4 py-3 border-t border-gray-300 dark:border-gray-700 flex items-center justify-end gap-2">
                    <button onClick={cancel} disabled={saving} className="px-3 py-1.5 text-xs text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-700 rounded transition-colors disabled:opacity-50">
                        Cancel
                    </button>
                    <button onClick={save} disabled={!dirty || saving} className="px-4 py-1.5 text-xs font-semibold bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50 transition-colors">
                        {saving ? 'Saving…' : 'Save'}
                    </button>
                </div>
            )}
        </div>
    );
};

/* ─── Account page: General + Security tabs ─── */
export const AccountDetail: React.FC = () => {
    const [tab, setTab] = useState<'general' | 'security' | 'badges'>('general');

    const tabBtn = (key: 'general' | 'security' | 'badges', label: string) => (
        <button
            onClick={() => setTab(key)}
            className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
                tab === key
                    ? 'border-blue-600 text-blue-700 dark:text-blue-400'
                    : 'border-transparent text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
            }`}
        >
            {label}
        </button>
    );

    return (
        <div className="p-6 max-w-3xl mx-auto space-y-6">
            <div>
                <h1 className="text-2xl font-bold text-gray-900 dark:text-white">My Account</h1>
                <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">Manage your account details and security settings.</p>
            </div>

            <div className="flex gap-1 border-b border-gray-200 dark:border-gray-800">
                {tabBtn('general', 'General')}
                {tabBtn('security', 'Security')}
                {tabBtn('badges', 'Badges')}
            </div>

            {tab === 'general' && <GeneralTab />}
            {tab === 'security' && <MySecurity embedded />}
            {tab === 'badges' && <AccessBadgesPanel basePath="/api/v1/account/badges" />}
        </div>
    );
};

