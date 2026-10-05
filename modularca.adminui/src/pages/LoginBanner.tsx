import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiGet } from '../api/client';

/// <summary>
/// Pre-login banner gate. Fetches the configured banner title + body from
/// /auth/login-banner. If nothing is configured, redirects straight to the
/// login page. Otherwise renders the acknowledgment screen; Accept sets a
/// session-scoped flag and forwards to /login, Decline clears any stale flag
/// and shows a terminal message. The flag is kept in sessionStorage so it
/// resets when the browser tab closes, matching AC-8's "each access attempt"
/// expectation.
/// </summary>
const LoginBanner: React.FC = () => {
    const navigate = useNavigate();
    const [title, setTitle] = useState<string>('System Use Notification');
    const [body, setBody] = useState<string | null>(null);
    const [declined, setDeclined] = useState(false);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        apiGet<{ banner: string | null; title: string | null }>('/auth/login-banner')
            .then(d => {
                if (!d.banner) {
                    // No banner configured — nothing to acknowledge; go straight to login.
                    navigate('/login', { replace: true });
                    return;
                }
                setBody(d.banner);
                if (d.title) setTitle(d.title);
            })
            .catch(() => {
                // Endpoint unreachable or server error — don't strand the user; fall through to login.
                navigate('/login', { replace: true });
            })
            .finally(() => setLoading(false));
    }, [navigate]);

    const accept = () => {
        sessionStorage.setItem('loginBannerAcknowledged', '1');
        navigate('/login', { replace: true });
    };

    const decline = () => {
        sessionStorage.removeItem('loginBannerAcknowledged');
        setDeclined(true);
    };

    if (loading) {
        return (
            <div className="flex justify-center items-center min-h-screen bg-ground">
                <div className="w-6 h-6 border-2 border-accent border-t-transparent rounded-full animate-spin" />
            </div>
        );
    }

    if (declined) {
        return (
            <div className="flex justify-center items-center min-h-screen bg-ground px-4">
                <div className="bg-raised p-8 rounded-lg shadow-lg w-full max-w-lg border border-line text-center space-y-4">
                    <h2 className="text-xl font-semibold text-ink">Access Denied</h2>
                    <p className="text-sm text-ink">
                        You have declined the system use notification. Close this browser tab to terminate the session.
                    </p>
                    <button
                        onClick={() => { setDeclined(false); }}
                        className="text-xs text-ink-muted hover:text-ink underline"
                    >
                        Go back
                    </button>
                </div>
            </div>
        );
    }

    return (
        <div className="flex justify-center items-center min-h-screen bg-ground px-4">
            <div className="bg-raised p-6 sm:p-8 rounded-lg shadow-lg w-full max-w-2xl border border-line space-y-5">
                <h2 className="text-2xl font-semibold text-center text-ink">{title}</h2>
                <div className="bg-warn-soft border border-warn/40 text-warn text-sm p-4 rounded whitespace-pre-wrap leading-relaxed max-h-[60vh] overflow-y-auto">
                    {body}
                </div>
                <div className="flex flex-col sm:flex-row gap-2 justify-end pt-2">
                    <button
                        onClick={decline}
                        className="px-4 py-2 bg-sunken hover:bg-hover text-ink text-sm rounded transition-colors"
                    >
                        Decline
                    </button>
                    <button
                        onClick={accept}
                        className="px-5 py-2 bg-accent hover:bg-accent-hover text-on-accent text-sm font-medium rounded transition-colors"
                    >
                        I Acknowledge &amp; Accept
                    </button>
                </div>
            </div>
        </div>
    );
};

export default LoginBanner;
