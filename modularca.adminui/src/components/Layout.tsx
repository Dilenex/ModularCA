import React, { useState, useEffect } from 'react';
import { Chevron } from '@shared/components/Chevron';
import { Link, useLocation } from 'react-router-dom';
import { apiLogout } from '../api/client';
import { useTheme } from '@shared/context/ThemeContext';
import { useAuth } from '../context/AuthContext';
import { useScope } from '../context/ScopeContext';
import { PORTAL, PORTAL_LABEL } from '../portal';
import { scopeLabel } from '../scope';
import LogPanel from './LogPanel';
import TopBar from './TopBar';
import { switchBadge } from './BadgeSwitcher';
import { useStepUp } from './StepUpMfaContext';
import { APP_VERSION, APP_COMMIT, APP_BUILD_TIME, fetchServerVersion, isVersionDrift, type ServerVersion } from '../version';
import { SourceNotice } from '@shared/components/SourceNotice';

import { navSections } from '../nav';

const Layout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    const location = useLocation();
    const { theme, toggleTheme } = useTheme();
    const { user, loading: authLoading } = useAuth();
    const { requireStepUp } = useStepUp();
    const [badgeBusy, setBadgeBusy] = useState(false);
    const { allows, scope, linkScope } = useScope();
    const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
    const [sidebarOpen, setSidebarOpen] = useState(false);

    // Deploy-drift detection: the UI bundle and the API both stamp their version from the same
    // repo-root VERSION file, so a mismatch means they were deployed from different builds — which can
    // surface as subtle "endpoint missing / payload shape changed" bugs. Fetch the server version once
    // and warn if it differs from this bundle's build-time version.
    const [serverVersion, setServerVersion] = useState<ServerVersion | null>(null);
    const [driftDismissed, setDriftDismissed] = useState(false);

    useEffect(() => {
        let cancelled = false;
        fetchServerVersion().then((sv) => {
            if (cancelled || !sv) return;
            setServerVersion(sv);
            // Honour a prior dismissal for this exact UI/server pair so the banner doesn't nag every
            // load — but a NEW mismatch (either side bumped) re-shows it.
            try {
                if (localStorage.getItem(`modca:driftDismissed:${APP_VERSION}:${sv.version}`) === '1') {
                    setDriftDismissed(true);
                }
            } catch { /* private mode / quota — just show the banner */ }
        });
        return () => { cancelled = true; };
    }, []);

    const showDrift = isVersionDrift(serverVersion) && !driftDismissed;

    const dismissDrift = () => {
        setDriftDismissed(true);
        try {
            if (serverVersion) localStorage.setItem(`modca:driftDismissed:${APP_VERSION}:${serverVersion.version}`, '1');
        } catch { /* ignore */ }
    };

    useEffect(() => {
        setSidebarOpen(false);
    }, [location.pathname]);

    const toggleSection = (title: string) => {
        setCollapsed(prev => ({ ...prev, [title]: !prev[title] }));
    };

    // Hide nav items the user cannot reach under the selected scope. While the auth
    // context hydrates we render every link to avoid a content flash; the
    // ProtectedRoute gate and the API remain authoritative.
    const visibleSections = navSections
        .map(section => ({
            ...section,
            items: section.items.filter(item => {
                if (!item.gate) return true;
                if (authLoading) return true;
                return allows(item.gate);
            }),
        }))
        .filter(section => section.items.length > 0);

    const sidebarContent = (
        <nav className="w-56 h-full bg-white dark:bg-gray-950 text-gray-900 dark:text-white flex flex-col border-r border-gray-200 dark:border-gray-800 overflow-y-auto">
            <div className="p-4 border-b border-gray-200 dark:border-gray-800 flex-shrink-0 flex items-center justify-between">
                <Link to="/dashboard">
                    <h2 className="text-lg font-bold text-blue-800 dark:text-blue-400">
                        ModularCA{' '}
                        <span
                            className="text-[10px] font-normal text-gray-400 dark:text-gray-500 align-top select-none"
                            title={`commit ${APP_COMMIT}${APP_BUILD_TIME ? ` • built ${APP_BUILD_TIME}` : ''}`}
                        >
                            v{APP_VERSION}
                        </span>
                    </h2>
                    <p className="text-xs text-gray-600">{PORTAL_LABEL}</p>
                </Link>
                <button
                    onClick={toggleTheme}
                    className="p-1.5 rounded hover:bg-gray-200 dark:hover:bg-gray-800 transition-colors text-gray-600"
                    title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
                >
                    {theme === 'dark' ? (
                        <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><circle cx="12" cy="12" r="5" strokeWidth="2"/><path strokeWidth="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>
                    ) : (
                        <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeWidth="2" d="M21 12.79A9 9 0 1111.21 3a7 7 0 009.79 9.79z"/></svg>
                    )}
                </button>
            </div>

            <div className="flex-1 py-2 overflow-y-auto">
                {visibleSections.map(section => (
                    <div key={section.title} className="mb-1">
                        <button
                            onClick={() => toggleSection(section.title)}
                            className="w-full px-3 py-1.5 text-xs font-semibold text-gray-600 uppercase tracking-wider hover:text-gray-300 flex justify-between items-center"
                        >
                            {section.title}
                            <span className="text-[10px]"><Chevron open={!(collapsed[section.title])} className="w-3 h-3" /></span>
                        </button>

                        {!collapsed[section.title] && (
                            <ul className="px-2 space-y-0.5">
                                {section.items.map(item => {
                                    const isActive = location.pathname === item.path ||
                                        (PORTAL === 'user' && item.path !== '/dashboard' && location.pathname.startsWith(item.path));
                                    return (
                                        <li key={item.path}>
                                            <Link
                                                to={item.path}
                                                className={`flex items-center gap-2 px-3 py-1.5 rounded text-xs transition-colors ${
                                                    isActive
                                                        ? 'bg-blue-600/20 text-blue-800 dark:text-blue-300 border-l-2 border-blue-400'
                                                        : 'text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 hover:text-gray-200'
                                                }`}
                                            >
                                                {item.name}
                                            </Link>
                                        </li>
                                    );
                                })}
                            </ul>
                        )}
                    </div>
                ))}
            </div>

            <div className="p-3 border-t border-gray-200 dark:border-gray-800 flex-shrink-0 flex items-center gap-2">
                <button
                    onClick={apiLogout}
                    className="flex-1 px-3 py-2 text-sm text-gray-600 dark:text-gray-400 hover:text-red-400 hover:bg-gray-100 dark:hover:bg-gray-800 rounded transition-colors flex items-center gap-2"
                >
                    {/* Logout glyph: open door frame with an arrow exiting to the right. */}
                    <svg className="w-4 h-4 flex-shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} aria-hidden="true">
                        <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 9V5.25A2.25 2.25 0 0 0 13.5 3h-6a2.25 2.25 0 0 0-2.25 2.25v13.5A2.25 2.25 0 0 0 7.5 21h6a2.25 2.25 0 0 0 2.25-2.25V15m3 0 3-3m0 0-3-3m3 3H9" />
                    </svg>
                    Logout
                </button>
                <Link
                    to="/account"
                    title="My Account"
                    aria-label="My Account"
                    className={`px-3 py-2 rounded transition-colors ${
                        location.pathname === '/account'
                            ? 'bg-blue-600/20 text-blue-700 dark:text-blue-300'
                            : 'text-gray-600 dark:text-gray-400 hover:text-blue-600 dark:hover:text-blue-400 hover:bg-gray-100 dark:hover:bg-gray-800'
                    }`}
                >
                    {/* Account glyph: head + shoulders, matching the logout icon's size/weight. */}
                    <svg className="w-4 h-4 flex-shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} aria-hidden="true">
                        <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 6a3.75 3.75 0 1 1-7.5 0 3.75 3.75 0 0 1 7.5 0ZM4.5 20.118a7.5 7.5 0 0 1 15 0A17.933 17.933 0 0 1 12 21.75c-2.676 0-5.216-.584-7.5-1.632Z" />
                    </svg>
                </Link>
            </div>

        </nav>
    );

    return (
        <div className="flex h-screen bg-gray-50 dark:bg-gray-900 overflow-hidden">
            {/* Desktop sidebar */}
            <div className="hidden lg:block flex-shrink-0">
                {sidebarContent}
            </div>

            {/* Mobile sidebar overlay */}
            {sidebarOpen && (
                <div className="fixed inset-0 z-40 lg:hidden">
                    <div className="absolute inset-0 bg-black/50" onClick={() => setSidebarOpen(false)} />
                    <div className="relative w-56 h-full z-50">
                        {sidebarContent}
                    </div>
                </div>
            )}

            <div className="flex-1 flex flex-col overflow-hidden min-w-0">
                <TopBar onOpenSidebar={() => setSidebarOpen(true)} />
                {/* Deploy-drift banner: UI bundle and API report different versions. */}
                {showDrift && serverVersion && (
                    <div
                        role="alert"
                        className="flex items-center justify-between gap-3 px-4 py-1.5 flex-shrink-0 bg-amber-50 dark:bg-amber-900/30 border-b border-amber-300 dark:border-amber-700 text-[11px] text-amber-800 dark:text-amber-300"
                    >
                        <span>
                            <span className="font-semibold">Version mismatch.</span>{' '}
                            This console is <span className="font-mono">v{APP_VERSION}</span> but the server is{' '}
                            <span className="font-mono">v{serverVersion.version}</span>. Reload once the deploy finishes;
                            if it persists, the UI and API were built from different versions.
                        </span>
                        <div className="flex items-center gap-3 flex-shrink-0">
                            <button
                                onClick={() => window.location.reload()}
                                className="font-semibold underline hover:text-amber-900 dark:hover:text-amber-200 transition-colors"
                            >
                                Reload
                            </button>
                            <button
                                onClick={dismissDrift}
                                aria-label="Dismiss version mismatch warning"
                                className="text-amber-700 dark:text-amber-400 hover:text-amber-900 dark:hover:text-amber-200 transition-colors"
                            >
                                {'✕'}
                            </button>
                        </div>
                    </div>
                )}

                {/* A link set the scope. Say so, and offer the way back, so following a link
                    never quietly moves someone out of the scope they work in. */}
                {linkScope && (
                    <div
                        role="status"
                        className="flex items-center justify-between gap-3 px-4 py-1.5 flex-shrink-0 bg-sky-50 dark:bg-sky-900/30 border-b border-sky-300 dark:border-sky-700 text-[11px] text-sky-900 dark:text-sky-200"
                    >
                        <span>
                            <span className="font-semibold">Scope set by this link:</span> {scopeLabel(scope)}.
                            {' '}Your usual scope is {scopeLabel(linkScope.usual)}; navigating elsewhere returns to it.
                        </span>
                        <span className="flex items-center gap-3 flex-shrink-0">
                            <button onClick={linkScope.leave} className="font-semibold underline hover:text-sky-950 dark:hover:text-white transition-colors">
                                Back to {scopeLabel(linkScope.usual)}
                            </button>
                            <button onClick={linkScope.keep} className="underline hover:text-sky-950 dark:hover:text-white transition-colors">
                                Keep {scopeLabel(scope)}
                            </button>
                        </span>
                    </div>
                )}

                {/* Worn-badge banner. Persistent while a badge is worn, absent when badgeless:
                    forgetting which hat you wear is the classic failure of these features. */}
                {user?.badge && (
                    <div
                        role="status"
                        className="flex items-center justify-between gap-3 px-4 py-1.5 flex-shrink-0 bg-violet-50 dark:bg-violet-900/30 border-b border-violet-300 dark:border-violet-700 text-[11px] text-violet-900 dark:text-violet-200"
                    >
                        <span>
                            <span className="font-semibold">Wearing badge:</span> {user.badge.name}. This session holds only the rights the badge keeps.
                        </span>
                        <button
                            onClick={async () => { setBadgeBusy(true); try { await switchBadge(null, requireStepUp); } catch { setBadgeBusy(false); } }}
                            disabled={badgeBusy}
                            className="font-semibold underline hover:text-violet-950 dark:hover:text-white transition-colors disabled:opacity-60 flex-shrink-0"
                        >
                            Take off
                        </button>
                    </div>
                )}


                {/* Explicit landmark + id so a future skip-to-content link
                    can target the main region. */}
                <main id="content" role="main" className="flex-1 overflow-y-auto bg-gray-50 dark:bg-gray-900">{children}</main>
                {/* The live audit tail reads admin audit endpoints; self-service users cannot. */}
                {PORTAL === 'admin' && <LogPanel />}

                {/* AGPL section 13 source offer. In the content column rather than the sidebar:
                    sidebarContent is rendered twice (desktop rail and mobile overlay), so a copy
                    there appears twice in the DOM. The legally load-bearing copy is publicui's,
                    which is the surface an unauthenticated remote user can reach — this one is
                    here because operators are remote users too. */}
                <footer className="flex-shrink-0 border-t border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-950 px-4 py-2">
                    <SourceNotice version={__APP_VERSION__} commit={__APP_COMMIT__} />
                </footer>
            </div>
        </div>
    );
};

export default Layout;
