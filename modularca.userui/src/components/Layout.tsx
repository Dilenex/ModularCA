import React, { useState, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { apiLogout } from '../api/client';
import { useTheme } from '@shared/context/ThemeContext';
import { Chevron } from '@shared/components/Chevron';
import { SourceNotice } from '@shared/components/SourceNotice';

interface NavSection {
    title: string;
    items: { name: string; path: string; icon: string }[];
}

const navSections: NavSection[] = [
    {
        title: 'Overview',
        items: [
            { name: 'Dashboard', path: '/dashboard', icon: '\u2302' },
        ]
    },
    {
        title: 'Certificates',
        items: [
            { name: 'Request Certificate', path: '/request', icon: '+' },
            { name: 'My Certificates', path: '/certificates', icon: '\u2387' },
            { name: 'Request Status', path: '/requests', icon: '\u2709' },
        ]
    },
    {
        title: 'SSH',
        items: [
            { name: 'SSH Certificates', path: '/ssh', icon: '\u2318' },
        ]
    },
    {
        title: 'CA Information',
        items: [
            { name: 'Trusted CAs', path: '/authorities', icon: '\u26BF' },
        ]
    },
];

const Layout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    const location = useLocation();
    const { theme, toggleTheme } = useTheme();
    const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
    const [sidebarOpen, setSidebarOpen] = useState(false);

    useEffect(() => {
        setSidebarOpen(false);
    }, [location.pathname]);

    const toggleSection = (title: string) => {
        setCollapsed(prev => ({ ...prev, [title]: !prev[title] }));
    };

    const sidebarContent = (
        <nav className="w-56 h-full bg-white dark:bg-gray-950 text-gray-900 dark:text-white flex flex-col border-r border-gray-200 dark:border-gray-800 overflow-y-auto">
            <div className="p-4 border-b border-gray-200 dark:border-gray-800 flex-shrink-0 flex items-center justify-between">
                <Link to="/dashboard">
                    <h2 className="text-lg font-bold text-blue-800 dark:text-blue-400">ModularCA</h2>
                    <p className="text-xs text-gray-600">User Portal</p>
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
                {navSections.map(section => (
                    <div key={section.title} className="mb-1">
                        <button
                            onClick={() => toggleSection(section.title)}
                            className="w-full px-3 py-1.5 text-xs font-semibold text-gray-600 uppercase tracking-wider hover:text-gray-700 dark:text-gray-300 flex justify-between items-center"
                        >
                            {section.title}
                            <Chevron open={!collapsed[section.title]} className="w-2.5 h-2.5" />
                        </button>

                        {!collapsed[section.title] && (
                            <ul className="px-2 space-y-0.5">
                                {section.items.map(item => {
                                    const isActive = location.pathname === item.path ||
                                        (item.path !== '/dashboard' && location.pathname.startsWith(item.path));
                                    return (
                                        <li key={item.path}>
                                            <Link
                                                to={item.path}
                                                className={`flex items-center gap-2 px-3 py-1.5 rounded text-xs transition-colors ${
                                                    isActive
                                                        ? 'bg-blue-600/20 text-blue-800 dark:text-blue-300 border-l-2 border-blue-400'
                                                        : 'text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 hover:text-gray-800 dark:hover:text-gray-200'
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
                            ? 'bg-blue-600/20 text-blue-800 dark:text-blue-300'
                            : 'text-gray-600 dark:text-gray-400 hover:text-blue-600 dark:hover:text-blue-400 hover:bg-gray-100 dark:hover:bg-gray-800'
                    }`}
                >
                    {/* Account glyph: head + shoulders, matching the logout icon's size/weight. */}
                    <svg className="w-4 h-4 flex-shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} aria-hidden="true">
                        <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 6a3.75 3.75 0 1 1-7.5 0 3.75 3.75 0 0 1 7.5 0ZM4.5 20.118a7.5 7.5 0 0 1 15 0A17.933 17.933 0 0 1 12 21.75c-2.676 0-5.216-.584-7.5-1.632Z" />
                    </svg>
                </Link>
            </div>

            {/* AGPL section 13 source offer. The legally load-bearing copy is in publicui's
                footer, since that is the surface an unauthenticated remote user can reach; this
                one is here because operators are remote users too. */}
            <div className="mt-4 px-3 pb-2 border-t border-gray-200 dark:border-gray-800 pt-3">
                <SourceNotice version={__APP_VERSION__} commit={__APP_COMMIT__} />
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
                {/* Mobile header with hamburger menu */}
                <header className="lg:hidden flex items-center gap-3 px-4 py-3 bg-white dark:bg-gray-950 border-b border-gray-200 dark:border-gray-800">
                    <button
                        onClick={() => setSidebarOpen(true)}
                        className="p-1.5 rounded-md text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800"
                    >
                        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
                        </svg>
                    </button>
                    <span className="text-base font-bold text-blue-800 dark:text-blue-400">ModularCA</span>
                    <span className="text-xs text-gray-600">User Portal</span>
                </header>

                <main className="flex-1 overflow-y-auto bg-gray-50 dark:bg-gray-900">{children}</main>
            </div>
        </div>
    );
};

export default Layout;
