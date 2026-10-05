import React, { useState, useEffect } from 'react';
import { Link, useLocation, Outlet } from 'react-router-dom';
import { useTheme } from '@shared/context/ThemeContext';
import { SourceNotice } from '@shared/components/SourceNotice';

const navItems = [
    { name: 'Home', path: '/' },
    { name: 'CA Certificates', path: '/certificates' },
    { name: 'CRL Downloads', path: '/crl' },
    { name: 'ACME', path: '/acme' },
];

const Layout: React.FC = () => {
    const location = useLocation();
    const { theme, toggleTheme } = useTheme();
    const [menuOpen, setMenuOpen] = useState(false);

    useEffect(() => {
        setMenuOpen(false);
    }, [location.pathname]);

    return (
        <div className="min-h-screen bg-ground text-ink flex flex-col">
            {/* Header */}
            <header className="bg-raised border-b border-line">
                <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
                    <Link to="/" className="flex items-center gap-3">
                        <div className="w-8 h-8 bg-accent rounded-lg flex items-center justify-center font-bold text-sm text-on-accent">CA</div>
                        <div>
                            <h1 className="text-lg font-bold text-ink leading-none">ModularCA</h1>
                            <p className="text-[10px] text-ink-muted leading-none mt-0.5">Certificate Authority</p>
                        </div>
                    </Link>
                    <div className="flex items-center gap-2">
                        <nav className="hidden md:flex gap-1 items-center">
                            {navItems.map((item) => {
                                const active = item.path === '/'
                                    ? location.pathname === '/'
                                    : location.pathname.startsWith(item.path);
                                return (
                                    <Link
                                        key={item.path}
                                        to={item.path}
                                        className={`px-3 py-2 rounded text-sm transition-colors ${
                                            active
                                                ? 'bg-accent-soft text-accent-ink font-medium'
                                                : 'text-ink-muted hover:text-ink hover:bg-hover'
                                        }`}
                                    >
                                        {item.name}
                                    </Link>
                                );
                            })}
                        </nav>
                        <button
                            onClick={toggleTheme}
                            className="ml-2 p-1.5 rounded hover:bg-hover transition-colors text-ink-muted"
                            title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
                        >
                            {theme === 'dark' ? (
                                <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><circle cx="12" cy="12" r="5" strokeWidth="2"/><path strokeWidth="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>
                            ) : (
                                <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeWidth="2" d="M21 12.79A9 9 0 1111.21 3a7 7 0 009.79 9.79z"/></svg>
                            )}
                        </button>
                        <button
                            onClick={() => setMenuOpen(!menuOpen)}
                            className="md:hidden p-1.5 rounded-md text-ink-muted hover:bg-hover"
                        >
                            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
                            </svg>
                        </button>
                    </div>
                </div>
            </header>

            {menuOpen && (
                <div className="md:hidden border-b border-line bg-raised">
                    <div className="max-w-6xl mx-auto px-4 py-2 flex flex-col space-y-1">
                        {navItems.map((item) => {
                            const active = item.path === '/' ? location.pathname === '/' : location.pathname.startsWith(item.path);
                            return (
                                <Link key={item.path} to={item.path} onClick={() => setMenuOpen(false)}
                                    className={`px-3 py-2 rounded text-sm transition-colors ${active ? 'bg-accent-soft text-accent-ink font-medium' : 'text-ink-muted hover:text-ink hover:bg-hover'}`}>
                                    {item.name}
                                </Link>
                            );
                        })}
                    </div>
                </div>
            )}

            {/* Main content */}
            <main className="flex-1">
                <div className="max-w-6xl mx-auto px-4 sm:px-6 py-6 sm:py-8">
                    <Outlet />
                </div>
            </main>

            {/* Footer */}
            <footer className="bg-raised border-t border-line py-6">
                <div className="max-w-6xl mx-auto px-4 sm:px-6 flex flex-wrap items-center justify-between gap-2 text-xs text-ink-muted">
                    <span>ModularCA - Open Source Certificate Authority</span>
                    {/* AGPL section 13. This is the unauthenticated surface, so this is the
                        placement that actually satisfies "all users interacting with it
                        remotely" — the copies in the authenticated SPAs are for completeness. */}
                    <SourceNotice version={__APP_VERSION__} commit={__APP_COMMIT__} />
                </div>
            </footer>
        </div>
    );
};

export default Layout;
