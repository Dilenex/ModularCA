import { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Link, Navigate, useLocation } from 'react-router-dom';
import { ScrollToTop } from '@shared/components/ScrollToTop';
import TitleManager from './components/TitleManager';
import ErrorBoundary from './components/ErrorBoundary';
import { ThemeProvider, useTheme } from '@shared/context/ThemeContext';
import { ToastProvider } from './context/ToastContext';
import Overview from './pages/Overview';
import SetupGuide from './pages/SetupGuide';
import AdminUiGuide from './pages/AdminUiGuide';
import UserUiGuide from './pages/UserUiGuide';
import PublicUiGuide from './pages/PublicUiGuide';
import SetupUiGuide from './pages/SetupUiGuide';
import AuthFlowDiagram from './pages/AuthFlowDiagram';
import CertIssuanceFlow from './pages/CertIssuanceFlow';
import CaHierarchyDiagram from './pages/CaHierarchyDiagram';
import SpaceModelDiagram from './pages/SpaceModelDiagram';
import ConfigLifecycle from './pages/ConfigLifecycle';
import ApiCategoryPage from './pages/ApiCategoryPage';
import { SourceNotice } from '@shared/components/SourceNotice';
import { createAuthClient } from '@shared-auth/api/createClient';
import { isApiError } from '@shared-auth/api/problem';
import { createSessionGate } from './sessionGate';

function loginUrl(): string {
    return `/login?returnUrl=${encodeURIComponent(window.location.pathname + window.location.search)}`;
}

const authClient = createAuthClient({ basename: '/docs', loginPath: loginUrl });

/**
 * Server-verified gate. 200 and 403 (MFA setup pending, IP policy) may read the docs; a 401 is
 * handled by the shared client (refresh, then sign-out and redirect); anything else is retryable
 * and leaves the stored session alone.
 */
async function verifySession(): Promise<'ok' | 'redirecting' | 'error'> {
    if (!authClient.getToken()) {
        window.location.href = loginUrl();
        return 'redirecting';
    }
    try {
        await authClient.apiBlob('/api/v1/me', { toast: false });
        return 'ok';
    } catch (e) {
        if (isApiError(e) && e.status === 403) return 'ok';
        if (!authClient.getToken()) return 'redirecting';
        return 'error';
    }
}

const sessionGate = createSessionGate({
    hasToken: () => !!authClient.getToken(),
    verify: verifySession,
    redirectToLogin: () => { window.location.href = loginUrl(); },
});

interface NavItem {
    label: string;
    to: string;
}

interface NavSection {
    title: string;
    items: NavItem[];
}

const navSections: NavSection[] = [
    {
        title: 'Getting Started',
        items: [
            { label: 'Overview', to: '/overview' },
            { label: 'Setup Guide', to: '/setup-guide' },
        ],
    },
    {
        title: 'API Reference',
        items: [
            { label: 'Authentication', to: '/api/authentication' },
            { label: 'Certificates', to: '/api/certificates' },
            { label: 'Certificate Requests', to: '/api/certificate-requests' },
            { label: 'CA Management', to: '/api/ca-management' },
            { label: 'SSH CA', to: '/api/ssh-ca' },
            { label: 'Profiles', to: '/api/profiles' },
            { label: 'Groups & Permissions', to: '/api/groups-permissions' },
            { label: 'Users & Accounts', to: '/api/users-accounts' },
            { label: 'Audit & Compliance', to: '/api/audit-compliance' },
            { label: 'Protocols', to: '/api/protocols' },
            { label: 'Integration', to: '/api/integration' },
            { label: 'System', to: '/api/system' },
            { label: 'Setup', to: '/api/setup' },
        ],
    },
    {
        title: 'UI Guide',
        items: [
            { label: 'Admin UI', to: '/ui/admin' },
            { label: 'User UI', to: '/ui/user' },
            { label: 'Public UI', to: '/ui/public' },
            { label: 'Setup UI', to: '/ui/setup' },
        ],
    },
    {
        title: 'Architecture',
        items: [
            { label: 'Auth Flow', to: '/architecture/auth-flow' },
            { label: 'Certificate Issuance', to: '/architecture/certificate-issuance' },
            { label: 'CA Hierarchy', to: '/architecture/ca-hierarchy' },
            { label: 'Space Model', to: '/architecture/space-model' },
            { label: 'Config Lifecycle', to: '/architecture/config-lifecycle' },
        ],
    },
];

function NavSectionGroup({ section, collapsed, onToggle, onNavigate }: {
    section: NavSection;
    collapsed: boolean;
    onToggle: () => void;
    onNavigate: () => void;
}) {
    const location = useLocation();

    return (
        <div className="mb-1">
            <button
                onClick={onToggle}
                className="w-full flex items-center justify-between px-3 py-2 text-xs font-semibold uppercase tracking-wider text-gray-500 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors"
            >
                {section.title}
                <svg
                    className={`w-3.5 h-3.5 transition-transform ${collapsed ? '' : 'rotate-90'}`}
                    fill="none" stroke="currentColor" viewBox="0 0 24 24"
                >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                </svg>
            </button>
            {!collapsed && (
                <ul className="mt-0.5 space-y-0.5">
                    {section.items.map((item) => {
                        const active = location.pathname === item.to;
                        return (
                            <li key={item.to}>
                                <Link
                                    to={item.to}
                                    onClick={onNavigate}
                                    className={`block px-3 py-1.5 pl-6 text-sm rounded-md transition-colors ${
                                        active
                                            ? 'bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 font-medium'
                                            : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 hover:text-gray-900 dark:hover:text-white'
                                    }`}
                                >
                                    {item.label}
                                </Link>
                            </li>
                        );
                    })}
                </ul>
            )}
        </div>
    );
}

function ApiIndex() {
    const section = navSections.find((s) => s.title === 'API Reference')!;
    return (
        <div className="max-w-4xl mx-auto">
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-6">API Reference</h1>
            <ul className="grid gap-2 sm:grid-cols-2">
                {section.items.map((item) => (
                    <li key={item.to}>
                        <Link
                            to={item.to}
                            className="block px-4 py-3 rounded-lg border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-950 text-gray-800 dark:text-gray-200 hover:border-blue-400 dark:hover:border-blue-500 hover:text-blue-700 dark:hover:text-blue-300 transition-colors"
                        >
                            {item.label}
                        </Link>
                    </li>
                ))}
            </ul>
        </div>
    );
}

function AppShell() {
    const { theme, toggleTheme } = useTheme();
    const [sidebarOpen, setSidebarOpen] = useState(false);
    const [collapsedSections, setCollapsedSections] = useState<Record<string, boolean>>({});
    const [authState, setAuthState] = useState<'checking' | 'ok' | 'error'>('checking');
    const [authAttempt, setAuthAttempt] = useState(0);
    const location = useLocation();

    useEffect(() => {
        let cancelled = false;
        setAuthState('checking');
        sessionGate.verify().then((result) => {
            if (cancelled || result === 'redirecting') return;
            setAuthState(result);
        });
        return () => { cancelled = true; };
    }, [authAttempt]);

    useEffect(() => sessionGate.watch(window, document), []);

    useEffect(() => {
        if (authState === 'ok') sessionGate.onNavigate();
    }, [location.pathname, location.search, authState]);

    if (authState !== 'ok') {
        return (
            <div className="flex h-screen items-center justify-center bg-gray-50 dark:bg-gray-900 text-sm text-gray-600 dark:text-gray-400">
                {authState === 'checking' ? 'Checking your session...' : (
                    <div className="text-center">
                        <p className="mb-3">Could not reach the server to verify your session.</p>
                        <button
                            onClick={() => setAuthAttempt((n) => n + 1)}
                            className="px-3 py-1.5 rounded-md bg-blue-600 text-white hover:bg-blue-700"
                        >
                            Retry
                        </button>
                    </div>
                )}
            </div>
        );
    }

    const toggleSection = (title: string) => {
        setCollapsedSections(prev => ({ ...prev, [title]: !prev[title] }));
    };

    const closeSidebar = () => setSidebarOpen(false);

    const sidebar = (
        <aside className="flex flex-col h-full bg-white dark:bg-gray-950 border-r border-gray-200 dark:border-gray-800">
            {/* Header */}
            <div className="flex items-center justify-between px-4 py-4 border-b border-gray-200 dark:border-gray-800">
                <Link to="/overview" onClick={closeSidebar} className="flex items-center gap-2.5">
                    <div className="w-7 h-7 rounded-md bg-blue-600 flex items-center justify-center">
                        <svg className="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                        </svg>
                    </div>
                    <span className="text-base font-bold text-gray-900 dark:text-white">ModularCA Docs</span>
                </Link>
                <button
                    onClick={toggleTheme}
                    className="p-1.5 rounded-md text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
                    title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
                >
                    {theme === 'dark' ? (
                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
                        </svg>
                    ) : (
                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
                        </svg>
                    )}
                </button>
            </div>

            {/* Navigation */}
            <nav className="flex-1 overflow-y-auto py-3 px-2">
                {navSections.map((section) => (
                    <NavSectionGroup
                        key={section.title}
                        section={section}
                        collapsed={!!collapsedSections[section.title]}
                        onToggle={() => toggleSection(section.title)}
                        onNavigate={closeSidebar}
                    />
                ))}
            </nav>
        </aside>
    );

    return (
        <div className="flex h-screen overflow-hidden bg-gray-50 dark:bg-gray-900">
            {/* Desktop sidebar */}
            <div className="hidden lg:block w-60 flex-shrink-0">
                {sidebar}
            </div>

            {/* Mobile overlay */}
            {sidebarOpen && (
                <div className="fixed inset-0 z-40 lg:hidden">
                    <div className="absolute inset-0 bg-black/50" onClick={closeSidebar} />
                    <div className="relative w-60 h-full z-50">
                        {sidebar}
                    </div>
                </div>
            )}

            {/* Main content */}
            <div className="flex-1 flex flex-col min-w-0">
                {/* Mobile header */}
                <header className="lg:hidden flex items-center gap-3 px-4 py-3 bg-white dark:bg-gray-950 border-b border-gray-200 dark:border-gray-800">
                    <button
                        onClick={() => setSidebarOpen(true)}
                        className="p-1.5 rounded-md text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800"
                    >
                        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
                        </svg>
                    </button>
                    <span className="text-base font-bold text-gray-900 dark:text-white">ModularCA Docs</span>
                </header>

                {/* Page content */}
                <main className="flex-1 overflow-y-auto p-6 lg:p-10">
                    <Routes>
                        <Route path="/overview" element={<Overview />} />
                        <Route path="/setup-guide" element={<SetupGuide />} />

                        {/* API Reference */}
                        <Route path="/api" element={<ApiIndex />} />
                        <Route path="/api/:category" element={<ApiCategoryPage />} />

                        {/* UI Guide */}
                        <Route path="/ui/admin" element={<AdminUiGuide />} />
                        <Route path="/ui/user" element={<UserUiGuide />} />
                        <Route path="/ui/public" element={<PublicUiGuide />} />
                        <Route path="/ui/setup" element={<SetupUiGuide />} />

                        {/* Architecture */}
                        <Route path="/architecture/auth-flow" element={<AuthFlowDiagram />} />
                        <Route path="/architecture/certificate-issuance" element={<CertIssuanceFlow />} />
                        <Route path="/architecture/ca-hierarchy" element={<CaHierarchyDiagram />} />
                        <Route path="/architecture/space-model" element={<SpaceModelDiagram />} />
                        {/* Renamed in 0.4.0; remove this redirect in 0.5. */}
                        <Route path="/architecture/tenant-model" element={<Navigate to="/architecture/space-model" replace />} />
                        <Route path="/architecture/config-lifecycle" element={<ConfigLifecycle />} />

                        {/* Default redirect */}
                        <Route path="*" element={<Navigate to="/overview" replace />} />
                    </Routes>
                </main>
            </div>

            {/* AGPL section 13 source offer — see SourceNotice. Served same-origin with the
                rest of the product, so docs readers are remote users of it too. */}
            <footer className="border-t border-gray-200 dark:border-gray-800 py-4 px-4">
                <SourceNotice version={__APP_VERSION__} commit={__APP_COMMIT__} />
            </footer>
        </div>
    );
}

export default function App() {
    return (
        <ErrorBoundary>
            <ThemeProvider>
                <ToastProvider>
                    <BrowserRouter basename="/docs">
                        <ScrollToTop />
                        <TitleManager />
                        <AppShell />
                    </BrowserRouter>
                </ToastProvider>
            </ThemeProvider>
        </ErrorBoundary>
    );
}
