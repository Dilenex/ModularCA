// ProtectedRoute.tsx
import React, { useEffect } from 'react';
import { isAuthenticated, isMfaSetupRequired } from './auth';
import { useAuth } from '../context/AuthContext';
import { useScope } from '../context/ScopeContext';
import type { Gate } from '../gates';
import { BASENAME, MFA_SETUP_PATH, goToLogin } from '../portal';

type Props = {
    children: React.ReactNode;
    /**
     * The capability the page needs (see gates.ts), checked at system scope or, for a scoped
     * gate, against the selected CA scope. Missing means "any authenticated user". Failing
     * the check renders an inline 403 panel instead of redirecting to login.
     */
    requires?: Gate['requires'];
    /** Whether `requires` is checked against the CA scope rather than at system scope. */
    scoped?: boolean;
};

const StatusPanel: React.FC<{ title: string; message: string; action?: React.ReactNode }> = ({ title, message, action }) => (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900 p-6">
        <div className="max-w-md w-full bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl shadow-lg p-8 text-center">
            <div className="w-16 h-16 mx-auto mb-4 bg-red-100 dark:bg-red-900/30 rounded-full flex items-center justify-center">
                <svg className="w-8 h-8 text-red-600 dark:text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
            </div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">{title}</h1>
            <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">{message}</p>
            {action}
        </div>
    </div>
);

const buttonClass = 'inline-block px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-lg transition-colors';

const ForbiddenPanel: React.FC<{ message: string }> = ({ message }) => (
    <StatusPanel
        title="Access Denied"
        message={message}
        action={<a href={`${BASENAME}/dashboard`} className={buttonClass}>Return to Dashboard</a>}
    />
);

const ProtectedRoute: React.FC<Props> = ({ children, requires, scoped }) => {
    const { user, loading, error, refresh } = useAuth();
    const { allows, scope } = useScope();

    // The sign-in pages live at the site root, outside this portal's basename, so leaving
    // for them is a full navigation rather than a router redirect. The login page brings the
    // browser back here afterwards via returnUrl.
    const signedOut = !isAuthenticated();
    const needsMfaSetup = !signedOut && isMfaSetupRequired();
    useEffect(() => {
        if (signedOut) goToLogin();
        else if (needsMfaSetup) window.location.replace(MFA_SETUP_PATH);
    }, [signedOut, needsMfaSetup]);
    if (signedOut || needsMfaSetup) return null;

    // Capability gating only applies if requested. Wait for the AuthContext to
    // hydrate before deciding so we don't flash a 403 during initial load.
    if (requires) {
        if (loading) {
            return (
                <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
                    <div className="text-sm text-gray-600 dark:text-gray-400">Loading…</div>
                </div>
            );
        }
        if (!user) {
            return (
                <StatusPanel
                    title="Could not load your account"
                    message={error || 'Failed to load user'}
                    action={<button type="button" onClick={() => { void refresh(); }} className={buttonClass}>Retry</button>}
                />
            );
        }
        if (!allows({ requires, scoped })) {
            const where = scoped
                ? (scope.kind === 'ca' ? ` on ${scope.label}` : ' on a CA in the selected scope')
                : ' at system scope';
            return <ForbiddenPanel message={`This page requires the ${requires} capability${where}.`} />;
        }
    }

    return <>{children}</>;
};

export default ProtectedRoute;
