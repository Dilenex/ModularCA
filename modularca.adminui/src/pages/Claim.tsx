import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import type { NoticeInput } from '@shared/notifications/notice';
import { InlineNotice } from '@shared/components/InlineNotice';
import { apiClaimAccount } from '../api/client';
import { LOGIN_PATH } from '../portal';
import { submitClaim } from './claimFlow';

export type { ClaimedState } from './claimFlow';

/**
 * Claims an account with a one-time claim token: the token, a new password and its confirmation.
 * This is how the first administrator of an unattended install gets in when bootstrap.yaml gave a
 * claim token, and how an account given a token on the host (`--issue-claim-token`) does. On
 * success it goes to the sign-in page with the username filled in, so the usual sign-in flow
 * (login banner, MFA enrolment) follows. The checks, the request and the outcome are in
 * claimFlow.ts; this is the form.
 */
const Claim: React.FC = () => {
    const navigate = useNavigate();
    const [token, setToken] = useState('');
    const [newPassword, setNewPassword] = useState('');
    const [confirmNewPassword, setConfirmNewPassword] = useState('');
    const [error, setError] = useState<NoticeInput | null>(null);
    const [loading, setLoading] = useState(false);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError(null);
        setLoading(true);
        const outcome = await submitClaim({ token, newPassword, confirmNewPassword }, apiClaimAccount, LOGIN_PATH);
        setLoading(false);
        if (outcome.ok) navigate(outcome.to, { replace: true, state: outcome.state });
        else setError(outcome.error);
    };

    return (
        <div className="flex justify-center items-center min-h-screen bg-ground">
            <form
                onSubmit={handleSubmit}
                className="bg-raised p-8 rounded-lg w-full max-w-md space-y-6 border border-line"
            >
                <h2 className="text-2xl font-semibold text-center text-ink">Claim your account</h2>
                <p className="text-sm text-ink-muted text-center">
                    Enter the claim token you were given and choose a password. A token works once, until it expires.
                </p>

                {error && <InlineNotice notice={error} />}

                <div>
                    <label className="block text-sm font-medium text-ink" htmlFor="claim-token">Claim token</label>
                    <input
                        id="claim-token"
                        name="claim-token"
                        type="password"
                        className="w-full bg-raised border border-line-strong text-ink rounded px-3 py-2 mt-1 font-mono focus:border-accent focus:outline-none"
                        value={token}
                        onChange={e => setToken(e.target.value)}
                        required
                        autoFocus
                        autoComplete="off"
                        spellCheck={false}
                    />
                </div>

                <div>
                    <label className="block text-sm font-medium text-ink" htmlFor="claim-new-password">New password</label>
                    <input
                        id="claim-new-password"
                        name="new-password"
                        type="password"
                        className="w-full bg-raised border border-line-strong text-ink rounded px-3 py-2 mt-1 focus:border-accent focus:outline-none"
                        value={newPassword}
                        onChange={e => setNewPassword(e.target.value)}
                        required
                        autoComplete="new-password"
                    />
                </div>

                <div>
                    <label className="block text-sm font-medium text-ink" htmlFor="claim-confirm-password">Confirm new password</label>
                    <input
                        id="claim-confirm-password"
                        name="confirm-new-password"
                        type="password"
                        className="w-full bg-raised border border-line-strong text-ink rounded px-3 py-2 mt-1 focus:border-accent focus:outline-none"
                        value={confirmNewPassword}
                        onChange={e => setConfirmNewPassword(e.target.value)}
                        required
                        autoComplete="new-password"
                    />
                </div>

                <button
                    type="submit"
                    disabled={loading}
                    className="w-full bg-accent text-on-accent py-2 rounded hover:bg-accent-hover disabled:opacity-50 transition-colors"
                >
                    {loading ? 'Claiming...' : 'Claim account'}
                </button>

                <Link
                    to={LOGIN_PATH}
                    className="block w-full text-center text-ink-muted hover:text-ink text-sm transition-colors"
                >
                    Back to login
                </Link>
            </form>
        </div>
    );
};

export default Claim;
