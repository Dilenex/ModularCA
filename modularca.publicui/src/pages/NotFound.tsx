import { Link, useLocation, useNavigate } from 'react-router-dom';

/**
 * Catch-all NotFound page rendered inside the public Layout when the URL doesn't
 * match any registered route. Mirrors the admin and user UIs' NotFound shape so
 * the visitor experience is consistent across all three portals — eyebrow + heading
 * + the path they hit + dual actions (browser back / landing page).
 */
const NotFound: React.FC = () => {
    const location = useLocation();
    const navigate = useNavigate();

    return (
        <div className="flex flex-col items-center justify-center py-20 px-4 text-center">
            <p className="data-mono uppercase tracking-widest text-accent-ink mb-3">
                404 — page not found
            </p>
            <h1 className="text-3xl sm:text-4xl font-bold text-ink mb-3">
                We couldn't find that page
            </h1>
            <p className="text-base text-ink mb-2 max-w-xl">
                The page you requested isn't part of this CA's public surface. This usually means a typo in the URL or a stale link from somewhere else.
            </p>
            {location.pathname && (
                <p className="data-mono text-ink-muted mb-8 break-all">
                    {location.pathname}
                </p>
            )}
            <div className="flex flex-col sm:flex-row gap-3">
                <button
                    onClick={() => navigate(-1)}
                    className="px-5 py-2 bg-raised border border-line-strong text-ink font-medium rounded transition-colors hover:bg-hover"
                >
                    Go back
                </button>
                <Link
                    to="/"
                    className="inline-block bg-accent hover:bg-accent-hover text-on-accent font-medium px-5 py-2 rounded transition-colors"
                >
                    Return to landing page
                </Link>
            </div>
        </div>
    );
};

export default NotFound;
