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
import TenantModelDiagram from './pages/TenantModelDiagram';
import ConfigLifecycle from './pages/ConfigLifecycle';
import ApiCategoryPage from './pages/ApiCategoryPage';
import { SourceNotice } from '@shared/components/SourceNotice';

/** Check whether the user has a valid (non-expired) auth token in localStorage. */
function isAuthenticated(): boolean {
    const token = localStorage.getItem('authToken');
    if (!token) return false;

    const expiresAt = localStorage.getItem('expiresAt');
    if (expiresAt) {
        const expiry = new Date(expiresAt).getTime();
        if (expiry > 0 && expiry < Date.now()) return false;
    }

    return true;
}

/** Redirect to the console's sign-in page, preserving the current docs path as returnUrl. */
function redirectToLogin(): void {
    const returnUrl = window.location.pathname + window.location.search;
    window.location.href = `/login?returnUrl=${encodeURIComponent(returnUrl)}`;
}

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
            { label: 'Overview', to: '/docs/overview' },
            { label: 'Setup Guide', to: '/docs/setup-guide' },
        ],
    },
    {
        title: 'API Reference',
        items: [
            { label: 'Authentication', to: '/docs/api/authentication' },
            { label: 'Certificates', to: '/docs/api/certificates' },
            { label: 'Certificate Requests', to: '/docs/api/certificate-requests' },
            { label: 'CA Management', to: '/docs/api/ca-management' },
            { label: 'SSH CA', to: '/docs/api/ssh-ca' },
            { label: 'Profiles', to: '/docs/api/profiles' },
            { label: 'Groups & Permissions', to: '/docs/api/groups-permissions' },
            { label: 'Users & Accounts', to: '/docs/api/users-accounts' },
            { label: 'Audit & Compliance', to: '/docs/api/audit-compliance' },
            { label: 'Protocols', to: '/docs/api/protocols' },
            { label: 'Integration', to: '/docs/api/integration' },
            { label: 'System', to: '/docs/api/system' },
            { label: 'Setup', to: '/docs/api/setup' },
        ],
    },
    {
        title: 'UI Guide',
        items: [
            { label: 'Admin UI', to: '/docs/ui/admin' },
            { label: 'User UI', to: '/docs/ui/user' },
            { label: 'Public UI', to: '/docs/ui/public' },
            { label: 'Setup UI', to: '/docs/ui/setup' },
        ],
    },
    {
        title: 'Architecture',
        items: [
            { label: 'Auth Flow', to: '/docs/architecture/auth-flow' },
            { label: 'Certificate Issuance', to: '/docs/architecture/certificate-issuance' },
            { label: 'CA Hierarchy', to: '/docs/architecture/ca-hierarchy' },
            { label: 'Tenant Model', to: '/docs/architecture/tenant-model' },
            { label: 'Config Lifecycle', to: '/docs/architecture/config-lifecycle' },
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

function AppShell() {
    const { theme, toggleTheme } = useTheme();
    const [sidebarOpen, setSidebarOpen] = useState(false);
    const [collapsedSections, setCollapsedSections] = useState<Record<string, boolean>>({});
    const [authChecked, setAuthChecked] = useState(false);
    const location = useLocation();

    // Check authentication on mount and whenever the route changes
    useEffect(() => {
        if (!isAuthenticated()) {
            redirectToLogin();
            return;
        }
        setAuthChecked(true);
    }, [location.pathname]);

    // Don't render anything until auth is verified
    if (!authChecked) {
        return null;
    }

    const toggleSection = (title: string) => {
        setCollapsedSections(prev => ({ ...prev, [title]: !prev[title] }));
    };

    const closeSidebar = () => setSidebarOpen(false);

    const sidebar = (
        <aside className="flex flex-col h-full bg-white dark:bg-gray-950 border-r border-gray-200 dark:border-gray-800">
            {/* Header */}
            <div className="flex items-center justify-between px-4 py-4 border-b border-gray-200 dark:border-gray-800">
                <Link to="/docs/overview" onClick={closeSidebar} className="flex items-center gap-2.5">
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
                        <Route path="/architecture/tenant-model" element={<TenantModelDiagram />} />
                        <Route path="/architecture/config-lifecycle" element={<ConfigLifecycle />} />

                        {/* Default redirect */}
                        <Route path="*" element={<Navigate to="/docs/overview" replace />} />
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
