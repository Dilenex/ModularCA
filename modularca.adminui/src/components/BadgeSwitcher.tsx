import React, { useState } from 'react';
import { apiPostWithMfa } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { useStepUp } from './StepUpMfaContext';
import { StepUpOps } from '@shared/generated';
import type { AccessBadgeSwitchResponse } from '@shared/generated';

/**
 * Puts an access badge on or takes it off, and reloads so every part of the console re-derives
 * itself from the new token.
 *
 * Switching mints a new access token; the session's refresh token is sent along so later
 * refreshes keep the badge. Narrowing is immediate; the server answers a broadening (taking a
 * badge off, or switching to one that keeps more) with a step-up challenge, which the MFA-aware
 * client helper turns into the usual prompt.
 */
export async function switchBadge(badgeId: string | null, requireStepUp: (operation: string, targetId?: string) => Promise<string>): Promise<void> {
    const refreshToken = localStorage.getItem('refreshToken');
    if (!refreshToken) throw new Error('No session refresh token; sign in again.');
    const result = await apiPostWithMfa<AccessBadgeSwitchResponse>(
        '/api/v1/auth/badge',
        { badgeId, refreshToken },
        requireStepUp,
        StepUpOps.SwitchBadge,
    );
    localStorage.setItem('authToken', result.token);
    localStorage.setItem('expiresAt', result.expiresAt);
    window.location.reload();
}

const NONE = '';

/**
 * The badge control in the top bar. A select when the account has badges to choose from;
 * otherwise a static "Default (no badge)" so the bar still says which hat is being worn.
 */
const BadgeSwitcher: React.FC = () => {
    const { user } = useAuth();
    const { requireStepUp } = useStepUp();
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const badges = user?.badges ?? [];
    const worn = user?.badge?.id ?? NONE;

    const choose = async (raw: string) => {
        setBusy(true);
        setError(null);
        try {
            await switchBadge(raw === NONE ? null : raw, requireStepUp);
        } catch (e: any) {
            setError(e?.message || 'Could not switch badge');
            setBusy(false);
        }
    };

    return (
        <label className="flex items-center gap-1.5 text-xs text-gray-600 dark:text-gray-400 min-w-0" title={user?.badge ? `Wearing: ${user.badge.name}` : 'Badgeless: every right this account holds'}>
            <span className="hidden md:inline">Badge:</span>
            {badges.length === 0 ? (
                <span className="px-2 py-1 text-xs rounded border border-dashed border-gray-300 dark:border-gray-700 text-gray-500 dark:text-gray-400 whitespace-nowrap">Default (no badge)</span>
            ) : (
                <select
                    id="badge-switcher"
                    aria-label="Badge"
                    value={worn}
                    disabled={busy}
                    onChange={(e) => choose(e.target.value)}
                    className={`max-w-[12rem] px-2 py-1 text-xs rounded border focus:outline-none focus:border-blue-500 disabled:opacity-60 ${
                        user?.badge
                            ? 'bg-violet-50 dark:bg-violet-900/40 border-violet-300 dark:border-violet-700 text-violet-900 dark:text-violet-100'
                            : 'bg-gray-100 dark:bg-gray-900 border-gray-300 dark:border-gray-700 text-gray-900 dark:text-white'
                    }`}
                >
                    <option value={NONE}>No badge</option>
                    {badges.map((b) => <option key={b.id} value={b.id}>{b.name}</option>)}
                </select>
            )}
            {error && <span className="text-[11px] text-red-700 dark:text-red-400 truncate" role="alert">{error}</span>}
        </label>
    );
};

export default BadgeSwitcher;
