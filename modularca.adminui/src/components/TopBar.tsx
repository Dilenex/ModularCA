import React from 'react';
import { useAuth } from '../context/AuthContext';
import { PORTAL, PORTAL_LABEL, OTHER_BASENAME } from '../portal';
import GlobalSearch from './GlobalSearch';
import ScopeSwitcher from './ScopeSwitcher';
import BadgeSwitcher from './BadgeSwitcher';

/**
 * The bar across the top of the content column: the site search in the middle, and on the
 * right the scope, the badge, and the way over to the other portal.
 *
 * On narrow screens the left end carries the sidebar toggle; the sidebar itself keeps the
 * wordmark, the navigation, the theme toggle and sign-out.
 */
const TopBar: React.FC<{ onOpenSidebar: () => void }> = ({ onOpenSidebar }) => {
    const { canUseAdminConsole } = useAuth();
    const showPortalSwitch = PORTAL === 'user' ? canUseAdminConsole : true;

    return (
        <header className="flex items-center gap-3 px-3 sm:px-4 py-2 bg-white dark:bg-gray-950 border-b border-gray-200 dark:border-gray-800 flex-shrink-0">
            {/* Left: sidebar toggle on small screens, wordmark so the bar reads on its own. */}
            <div className="flex items-center gap-2 flex-shrink-0 lg:min-w-[10rem]">
                <button
                    onClick={onOpenSidebar}
                    aria-label="Open navigation"
                    className="lg:hidden p-1.5 rounded-md text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800"
                >
                    <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
                    </svg>
                </button>
                <span className="lg:hidden text-base font-bold text-blue-800 dark:text-blue-400">ModularCA</span>
                <span className="hidden lg:inline text-xs text-gray-500 dark:text-gray-400">{PORTAL_LABEL}</span>
            </div>

            {/* Middle: the search, centred. */}
            <div className="flex-1 flex justify-center min-w-0">
                <GlobalSearch />
            </div>

            {/* Right: scope, badge, portal switch. */}
            <div className="flex items-center gap-3 flex-shrink-0 min-w-0">
                <ScopeSwitcher />
                <BadgeSwitcher />
                {showPortalSwitch && (
                    <a
                        href={`${OTHER_BASENAME}/dashboard`}
                        title={PORTAL === 'admin' ? 'Open the self-service portal' : 'Open the management console'}
                        className="px-2.5 py-1 text-xs rounded border border-gray-300 dark:border-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 hover:text-gray-900 dark:hover:text-white transition-colors whitespace-nowrap"
                    >
                        <span aria-hidden="true" className="mr-1">{'⇄'}</span>
                        {PORTAL === 'admin' ? 'Self-service' : 'Administration'}
                    </a>
                )}
            </div>
        </header>
    );
};

export default TopBar;
