import React, { useState } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { apiPostWithMfa } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { useStepUp } from './StepUpMfaContext';
import ConfirmModal from './ConfirmModal';
import { InfoTip } from '@shared/components/forms';
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
 * One line on what a badge is, worded as on the user detail page (UserDetail, "Badges" section)
 * so the concept reads the same wherever it appears.
 */
const BADGE_EXPLAINER = 'A badge keeps a subset of the grant sources this account already holds: a narrowed way of working without changing the grants. Switching reloads the console.';

/**
 * The badge control in the top bar. A select when the account has badges to choose from;
 * otherwise a static "Default (no badge)" so the bar still says which hat is being worn.
 *
 * A change is confirmed before it is applied, because applying it reloads the page and throws
 * away whatever is half-typed on it.
 */
const BadgeSwitcher: React.FC = () => {
    const { user } = useAuth();
    const { requireStepUp } = useStepUp();
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<NoticeInput | null>(null);
    const [pending, setPending] = useState<string | null>(null);

    const badges = user?.badges ?? [];
    const worn = user?.badge?.id ?? NONE;

    const choose = async (raw: string) => {
        setBusy(true);
        setError(null);
        try {
            await switchBadge(raw === NONE ? null : raw, requireStepUp);
        } catch (e: any) {
            setError(errorNotice(e, 'Could not switch badge'));
            setBusy(false);
        }
    };

    const pendingName = pending === null ? null : pending === NONE ? 'no badge' : (badges.find((b) => b.id === pending)?.name ?? 'that badge');
    const broadening = pending !== null && (pending === NONE || !!user?.badge);

    return (
        <div className="flex items-center min-w-0">
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
                        onChange={(e) => { if (e.target.value !== worn) setPending(e.target.value); }}
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
                <InfoTip label="What a badge is" align="right" text={BADGE_EXPLAINER} />
                {error && <InlineNotice notice={error} variant="line" />}
            </label>

            <ConfirmModal
                isOpen={pending !== null}
                title={pending === NONE ? 'Take the badge off?' : 'Switch badge?'}
                message={(
                    <>
                        <p>Switching to <strong>{pendingName}</strong> mints a new session token and reloads the console. Anything typed on this page and not yet saved is lost.</p>
                        <p className="mt-2">{BADGE_EXPLAINER}</p>
                        {broadening && <p className="mt-2">This switch keeps more rights than the one worn now, so the server will ask for a second factor first.</p>}
                    </>
                )}
                confirmLabel={busy ? 'Switching...' : 'Switch and reload'}
                confirmClass="px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors disabled:opacity-50"
                loading={busy}
                onConfirm={() => { const next = pending; setPending(null); if (next !== null) void choose(next); }}
                onCancel={() => setPending(null)}
            />
        </div>
    );
};

export default BadgeSwitcher;
