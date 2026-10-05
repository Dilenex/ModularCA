import React, { useState } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { errorNotice } from '@shared-auth/api/notices';
import { authClient, isStepUpRequired } from '../api/client';
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
 * Switching mints a new access token (the refresh token is not rotated); the session's refresh
 * token is sent along so later refreshes keep the badge. It is read and sent under the cross-tab
 * refresh lock, so it cannot be one another tab has just rotated. Narrowing is immediate; a
 * broadening (taking a badge off, or switching to one that keeps more) is answered with a step-up
 * challenge, prompted for outside the lock and then retried.
 */
export async function switchBadge(badgeId: string | null, requireStepUp: (operation: string, targetId?: string) => Promise<string>): Promise<void> {
    const post = (mfaToken?: string) => authClient.withSessionRefreshToken(async (refreshToken, request) => {
        const result = await request<AccessBadgeSwitchResponse>('/api/v1/auth/badge', {
            method: 'POST',
            body: JSON.stringify({ badgeId, refreshToken }),
            headers: mfaToken ? { 'X-MFA-Token': mfaToken } : undefined,
        });
        authClient.storeAccessToken(result.token, result.expiresAt);
    });
    try {
        await post();
    } catch (err) {
        if (!isStepUpRequired(err)) throw err;
        await post(await requireStepUp(StepUpOps.SwitchBadge));
    }
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
            <label className="flex items-center gap-1.5 text-xs text-ink-muted min-w-0" title={user?.badge ? `Wearing: ${user.badge.name}` : 'Badgeless: every right this account holds'}>
                <span className="hidden md:inline label-caps">Badge</span>
                {badges.length === 0 ? (
                    <span className="px-2 py-1 text-xs rounded border border-dashed border-line text-ink-muted whitespace-nowrap">Default (no badge)</span>
                ) : (
                    <select
                        id="badge-switcher"
                        aria-label="Badge"
                        value={worn}
                        disabled={busy}
                        onChange={(e) => { if (e.target.value !== worn) setPending(e.target.value); }}
                        className={`max-w-[12rem] px-2 py-1 text-xs rounded border focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent disabled:opacity-60 ${
                            user?.badge
                                ? 'bg-badge-worn-soft border-badge-worn/40 text-badge-worn font-medium'
                                : 'bg-raised border-line-strong text-ink'
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
                confirmClass="px-4 py-2 text-sm bg-accent text-on-accent rounded hover:bg-accent-hover transition-colors disabled:opacity-50"
                loading={busy}
                onConfirm={() => { const next = pending; setPending(null); if (next !== null) void choose(next); }}
                onCancel={() => setPending(null)}
            />
        </div>
    );
};

export default BadgeSwitcher;
