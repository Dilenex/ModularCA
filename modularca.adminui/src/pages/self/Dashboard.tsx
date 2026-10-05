import React, { useState, useEffect } from 'react';
import { apiGet, apiGetAllPages } from '../../api/client';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { Link } from 'react-router-dom';
import { capitalize, expiryPhrase, lifecycleTone, toneTextClass } from '../certLifecycle';

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function requestStatusType(status: string): 'active' | 'pending' | 'disabled' | 'enabled' {
    switch (status?.toLowerCase()) {
        case 'approved': return 'active';
        case 'pending': return 'pending';
        case 'rejected': return 'disabled';
        case 'issued': return 'enabled';
        default: return 'pending';
    }
}

function certStatus(cert: any): 'active' | 'revoked' | 'expired' {
    if (cert.revoked) return 'revoked';
    if (new Date(cert.notAfter) < new Date()) return 'expired';
    return 'active';
}

// Pull the username from the JWT for an immediate greeting. Deliberately avoids `sub`, which is
// the user's GUID — we want the human-readable username, not the identifier.
function parseUsername(): string | null {
    try {
        const token = localStorage.getItem('authToken');
        if (!token) return null;
        const payload = JSON.parse(atob(token.split('.')[1]));
        return payload.username || payload.unique_name || payload.name || null;
    } catch {
        return null;
    }
}

const Dashboard: React.FC = () => {
    const [certificates, setCertificates] = useState<any[]>([]);
    const [requests, setRequests] = useState<any[]>([]);
    const [loadingCerts, setLoadingCerts] = useState(true);
    const [loadingRequests, setLoadingRequests] = useState(true);
    const [errorCerts, setErrorCerts] = useState<string | null>(null);
    const [errorRequests, setErrorRequests] = useState<string | null>(null);

    // Seed with the JWT username for an instant, GUID-free greeting; the /me fetch below upgrades
    // it to the user's full name when set.
    const [greetingName, setGreetingName] = useState<string | null>(parseUsername());

    useEffect(() => {
        // Authoritative identity from the whoami endpoint (the SPA's intended source — avoids
        // trusting the JWT body). Greet by "First Last" when set, otherwise the username; never
        // the user's GUID.
        apiGet<{ username: string; firstName?: string; lastName?: string }>('/api/v1/me')
            .then((me) => {
                const fullName = [me.firstName, me.lastName].map((s) => s?.trim()).filter(Boolean).join(' ');
                setGreetingName(fullName || me.username || null);
            })
            .catch(() => { /* keep the JWT username fallback */ });

        apiGetAllPages<any>('/api/v1/user/certificates')
            .then(({ items }) => setCertificates(items))
            .catch((err) => setErrorCerts(err.message))
            .finally(() => setLoadingCerts(false));

        apiGet<any[]>('/api/v1/user/requests')
            .then((data) => setRequests(Array.isArray(data) ? data : []))
            .catch((err) => setErrorRequests(err.message))
            .finally(() => setLoadingRequests(false));
    }, []);

    const activeCerts = certificates.filter(c => certStatus(c) === 'active');
    const expiringSoon = certificates.filter(c => {
        if (certStatus(c) !== 'active') return false;
        const days = Math.ceil((new Date(c.notAfter).getTime() - Date.now()) / (1000 * 60 * 60 * 24));
        return days <= 30;
    });
    const revokedCerts = certificates.filter(c => c.revoked);
    const expiringNotReplaced = expiringSoon.filter(c => !c.replaced);

    const recentRequests = requests.slice(0, 5);

    const loading = loadingCerts || loadingRequests;

    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            {/* Welcome */}
            <div>
                <h1 className="text-xl font-semibold text-ink">
                    {greetingName ? `Welcome, ${greetingName}` : 'Welcome'}
                </h1>
                <p className="text-sm text-ink-muted mt-1">
                    Your certificate management dashboard.
                </p>
            </div>

            {/* Quick Actions */}
            <div className="flex flex-wrap gap-3">
                <Link
                    to="/request"
                    className="px-4 py-2 text-sm font-medium bg-accent text-on-accent rounded hover:bg-accent-hover transition-colors"
                >
                    Request Certificate
                </Link>
                <Link
                    to="/certificates"
                    className="px-4 py-2 text-sm font-medium bg-sunken text-ink rounded hover:bg-hover transition-colors"
                >
                    View My Certificates
                </Link>
            </div>

            {/* Statistics Cards */}
            {loading && <p className="text-sm text-ink-muted">Loading...</p>}

            {!loadingCerts && !errorCerts && (
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                    <div className="bg-raised border border-line rounded-lg p-4">
                        <p className="text-xs text-ink-muted uppercase tracking-wider">Active Certificates</p>
                        <p className="text-2xl font-bold text-ok mt-1">{activeCerts.length}</p>
                    </div>
                    <div className="bg-raised border border-line rounded-lg p-4">
                        <p className="text-xs text-ink-muted uppercase tracking-wider">Expiring Within 30 Days</p>
                        <p className={`text-2xl font-bold mt-1 ${expiringNotReplaced.length > 0 ? 'text-warn' : 'text-ink-muted'}`}>
                            {expiringSoon.length}
                        </p>
                        {expiringSoon.length > expiringNotReplaced.length && (
                            <p className="text-xs text-ink-muted mt-0.5">{expiringSoon.length - expiringNotReplaced.length} already replaced</p>
                        )}
                    </div>
                    <div className="bg-raised border border-line rounded-lg p-4">
                        <p className="text-xs text-ink-muted uppercase tracking-wider">Revoked</p>
                        <p className={`text-2xl font-bold mt-1 ${revokedCerts.length > 0 ? 'text-crit' : 'text-ink-muted'}`}>
                            {revokedCerts.length}
                        </p>
                    </div>
                </div>
            )}

            {errorCerts && (
                <p className="text-sm text-crit">Failed to load certificates: {errorCerts}</p>
            )}

            {/* Expiring Soon List */}
            {!loadingCerts && !errorCerts && expiringSoon.length > 0 && (
                <div>
                    <h2 className="text-lg font-semibold text-ink mb-3">Expiring Soon</h2>
                    <div className={`bg-raised border rounded-lg overflow-hidden ${expiringNotReplaced.length > 0 ? 'border-warn/40' : 'border-line'}`}>
                        {expiringSoon.map((cert) => {
                            const tone = lifecycleTone(cert.notAfter, !!cert.replaced);
                            return (
                                <div
                                    key={cert.serialNumber}
                                    className="px-4 py-3 flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-line last:border-b-0"
                                >
                                    <span className={`text-xs font-medium whitespace-nowrap ${toneTextClass(tone)}`}>{capitalize(expiryPhrase(cert.notAfter))}</span>
                                    <span className="text-xs text-ink-muted whitespace-nowrap">{cert.replaced ? 'Replaced' : 'Not replaced'}</span>
                                    <span className="text-sm text-ink truncate flex-1">
                                        {cert.subjectDN || cert.serialNumber}
                                    </span>
                                    <span className="text-xs text-ink-muted flex-shrink-0">
                                        Expires: {formatDate(cert.notAfter)}
                                    </span>
                                </div>
                            );
                        })}
                    </div>
                </div>
            )}

            {/* Recent Requests */}
            <div>
                <div className="flex items-center justify-between mb-3">
                    <h2 className="text-lg font-semibold text-ink">Recent Requests</h2>
                    <Link to="/requests" className="text-xs text-accent-ink hover:underline">View all</Link>
                </div>

                {loadingRequests && <p className="text-sm text-ink-muted">Loading...</p>}
                {errorRequests && <p className="text-sm text-crit">Failed to load requests: {errorRequests}</p>}

                {!loadingRequests && !errorRequests && recentRequests.length === 0 && (
                    <div className="bg-raised border border-line rounded-lg p-8 text-center">
                        <p className="text-ink-muted">No certificate requests yet.</p>
                        <Link to="/request" className="text-accent-ink text-sm hover:underline mt-2 inline-block">
                            Submit your first request
                        </Link>
                    </div>
                )}

                {!loadingRequests && !errorRequests && recentRequests.length > 0 && (
                    <div className="bg-raised border border-line rounded-lg overflow-hidden">
                        {recentRequests.map((req) => (
                            <div
                                key={req.id}
                                className="px-4 py-3 flex items-center gap-3 border-b border-line last:border-b-0"
                            >
                                <StatusBadge status={requestStatusType(req.status)} label={req.status} />
                                <span className="text-sm text-ink truncate flex-1">
                                    {req.subjectDN || '(no subject)'}
                                </span>
                                <span className="text-xs text-ink-muted flex-shrink-0">
                                    {formatDate(req.submittedAt)}
                                </span>
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
};

export default Dashboard;
