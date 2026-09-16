import { Link, useLocation, useNavigate } from 'react-router-dom';

/**
 * Catch-all NotFound page rendered inside the authenticated Layout (either portal) when
 * the URL doesn't match any registered route. Shows the path the operator hit
 * so a typo or stale bookmark surfaces immediately, plus two actions: go back
 * (browser history) or jump to the dashboard.
 */
const NotFound: React.FC = () => {
    const location = useLocation();
    const navigate = useNavigate();

    return (
        <div className="flex flex-col items-center justify-center py-20 px-4 text-center">
            <p className="text-xs font-mono uppercase tracking-widest text-blue-600 dark:text-blue-400 mb-3">
                404 — page not found
            </p>
            <h1 className="text-3xl sm:text-4xl font-bold text-gray-900 dark:text-white mb-3">
                We couldn't find that page
            </h1>
            <p className="text-base text-gray-700 dark:text-gray-300 mb-2 max-w-xl">
                The page you requested isn't registered on this portal. This usually means a typo in the URL or a stale bookmark from an earlier version.
            </p>
            {location.pathname && (
                <p className="text-sm font-mono text-gray-500 dark:text-gray-400 mb-8 break-all">
                    {location.pathname}
                </p>
            )}
            <div className="flex flex-col sm:flex-row gap-3">
                <button
                    onClick={() => navigate(-1)}
                    className="px-5 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-200 font-medium rounded transition-colors hover:bg-gray-50 dark:hover:bg-gray-700"
                >
                    Go back
                </button>
                <Link
                    to="/dashboard"
                    className="inline-block bg-blue-600 hover:bg-blue-700 text-white font-medium px-5 py-2 rounded transition-colors"
                >
                    Return to dashboard
                </Link>
            </div>
        </div>
    );
};

export default NotFound;
