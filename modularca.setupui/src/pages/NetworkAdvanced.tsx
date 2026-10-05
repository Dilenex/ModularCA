import React from 'react';
import { useAutoFocus } from '../hooks/useAutoFocus';

export interface NetworkData {
    publicDomain: string;
    /** Null means "same as httpsBindPort" — see the backend's PublicPort ?? Port fallback. */
    httpsPublicPort: number | null;
    /** Null means "same as httpPort". */
    httpPublicPort: number | null;
    httpPort: number;
    httpsBindPort: number;
    listenAddress: string;
    mtlsEnabled: boolean;
    mtlsAuthSubdomain: string;
    backupOutputPath: string;
    backupRetentionCount: number;
    logLevel: string;
    logRetentionDays: number;
}

interface NetworkAdvancedProps {
    data: NetworkData;
    onChange: (data: NetworkData) => void;
}

const logLevels = ['Debug', 'Information', 'Warning', 'Error'];

// Rough FQDN check: not empty, not IPv4/IPv6, contains at least one dot separating
// labels. Matches deriveWebTlsDefaults() in App.tsx so the two stay consistent on
// what "counts" as an FQDN for mTLS subdomain purposes.
function isFqdn(s: string): boolean {
    const v = s.trim();
    if (!v) return false;
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(v)) return false;
    if (v.includes(':')) return false;
    return /\./.test(v) && /[a-zA-Z]/.test(v);
}

/// <summary>
/// Network and advanced configuration step for the setup wizard.
/// Includes public URL, plain-HTTP listener, mTLS, backup storage, and logging settings.
/// </summary>
const NetworkAdvanced: React.FC<NetworkAdvancedProps> = ({ data, onChange }) => {
    const autoFocusRef = useAutoFocus<HTMLInputElement>();
    const publicDomainIsFqdn = isFqdn(data.publicDomain);

    // If the public domain stops being an FQDN (empty, IP, or cleared), mTLS can't
    // work — the cert SAN can't cover a subdomain. Force the toggle off and wipe
    // the subdomain so stale state doesn't carry forward to bootstrap.
    React.useEffect(() => {
        if (publicDomainIsFqdn) return;
        if (data.mtlsEnabled || data.mtlsAuthSubdomain) {
            onChange({ ...data, mtlsEnabled: false, mtlsAuthSubdomain: '' });
        }
    }, [publicDomainIsFqdn, data.mtlsEnabled, data.mtlsAuthSubdomain]);

    return (
        <div className="space-y-6">
            <div>
                <h2 className="text-2xl font-bold text-ink">Network &amp; Advanced</h2>
                <p className="text-ink-muted mt-1">
                    Configure network settings and operational parameters.
                </p>
            </div>

            {/* Public Domain */}
            <div className="bg-info-soft border border-info/40 rounded-lg p-4 space-y-3">
                <h3 className="text-lg font-semibold text-ink">Public Domain</h3>
                <p className="text-sm text-info">
                    The public hostname (or IP) used to build certificate AIA/CDP URLs and management-UI redirects.
                    Must be reachable by relying parties.
                </p>
                <div>
                    <input
                        ref={autoFocusRef}
                        id="publicDomain"
                        type="text"
                        value={data.publicDomain}
                        onChange={e => {
                            let v = e.target.value;
                            // Strip scheme prefix if pasted
                            v = v.replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
                            onChange({ ...data, publicDomain: v });
                        }}
                        placeholder="ca.example.com"
                        className="w-full px-3 py-2 bg-raised border border-accent/40 rounded text-ink placeholder-ink-faint focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent"
                    />
                    <p className="text-xs text-accent-ink mt-1">
                        Hostname or IP only — no scheme, no port, no trailing slash.
                    </p>
                </div>
            </div>

            {/* Ports & Networking */}
            <div className="border-t border-line pt-6 space-y-4">
                <h3 className="text-lg font-semibold text-ink">Ports &amp; Networking</h3>

                <p className="text-sm text-ink-muted mb-4">
                    The <strong>HTTPS Port</strong> and <strong>HTTP Port</strong> are what the server binds to.
                    If you run behind a reverse proxy (e.g., nginx on 443 forwarding to 8443),
                    expand <em>Reverse Proxy</em> below to set the public-facing ports used in certificate URLs.
                </p>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                        <label htmlFor="httpsBindPort" className="block text-sm font-medium text-ink mb-1">
                            HTTPS Port
                        </label>
                        <input
                            id="httpsBindPort"
                            type="text"
                            inputMode="numeric"
                            value={data.httpsBindPort}
                            onChange={e => { const v = e.target.value.replace(/\D/g, ''); onChange({ ...data, httpsBindPort: v === '' ? ('' as any) : parseInt(v) }); }}
                            onBlur={() => { if (!data.httpsBindPort) onChange({ ...data, httpsBindPort: 8443 }); }}
                            className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-ink focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent"
                        />
                        <p className="text-xs text-ink-muted mt-1">Port the server listens on for HTTPS (admin UI, API, ACME). Default: 8443.</p>
                    </div>
                    <div>
                        <label htmlFor="httpPort" className="block text-sm font-medium text-ink mb-1">
                            HTTP Port
                        </label>
                        <input
                            id="httpPort"
                            type="text"
                            inputMode="numeric"
                            value={data.httpPort}
                            onChange={e => { const v = e.target.value.replace(/\D/g, ''); onChange({ ...data, httpPort: v === '' ? ('' as any) : parseInt(v) }); }}
                            onBlur={() => { if (!data.httpPort && data.httpPort !== 0) onChange({ ...data, httpPort: 8080 }); }}
                            className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-ink focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent"
                        />
                        <p className="text-xs text-ink-muted mt-1">Port the server listens on for plain HTTP (CRL, OCSP, AIA). Set to 0 to disable. Default: 8080.</p>
                    </div>
                    <div>
                        <label htmlFor="listenAddress" className="block text-sm font-medium text-ink mb-1">
                            Listen Address
                        </label>
                        <input
                            id="listenAddress"
                            type="text"
                            value={data.listenAddress}
                            onChange={e => onChange({ ...data, listenAddress: e.target.value })}
                            placeholder="0.0.0.0"
                            className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-ink placeholder-ink-faint focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent"
                        />
                        <p className="text-xs text-ink-muted mt-1">IP address to bind to. Use 0.0.0.0 for all interfaces, 127.0.0.1 for localhost only.</p>
                    </div>
                    <div className="sm:col-span-2 space-y-3">
                        <label
                            className={`flex items-start gap-3 ${publicDomainIsFqdn ? 'cursor-pointer' : 'cursor-not-allowed opacity-60'}`}
                        >
                            <input
                                type="checkbox"
                                checked={data.mtlsEnabled}
                                disabled={!publicDomainIsFqdn}
                                onChange={e => onChange({ ...data, mtlsEnabled: e.target.checked })}
                                className="mt-1 w-4 h-4 text-accent-ink bg-raised border-line-strong rounded focus:ring-accent disabled:cursor-not-allowed"
                            />
                            <div className="flex-1 min-w-0">
                                <span className="text-sm font-medium text-ink">Enable mTLS client-certificate login</span>
                                <p className="text-xs text-ink-muted mt-0.5">
                                    Allow browser users to authenticate with a client certificate issued by ModularCA. Can be toggled later via the admin UI.
                                </p>
                                {!publicDomainIsFqdn && (
                                    <p className="text-xs text-warn mt-1">
                                        Requires an FQDN for Public Domain. mTLS login is SNI-gated on a subdomain of the public hostname, which can't be expressed when the Public Domain is empty or an IP address.
                                    </p>
                                )}
                            </div>
                        </label>

                        {data.mtlsEnabled && publicDomainIsFqdn && (
                            <div>
                                <label htmlFor="mtlsAuthSubdomain" className="block text-sm font-medium text-ink mb-1">
                                    mTLS Auth Subdomain
                                </label>
                                <input
                                    id="mtlsAuthSubdomain"
                                    type="text"
                                    value={data.mtlsAuthSubdomain}
                                    onChange={e => onChange({ ...data, mtlsAuthSubdomain: e.target.value })}
                                    placeholder="mtls"
                                    className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-ink placeholder-ink-faint focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent"
                                />
                                <p className="text-xs text-ink-muted mt-1">
                                    Short form ("mtls") is joined with the Public Domain; a full FQDN ("mtls.ca.example.com") is used as-is. SNI-gated on the main HTTPS listener — no separate port. Requires DNS and the Web TLS cert SAN covering this hostname (the next step pre-fills it for you).
                                </p>
                            </div>
                        )}
                    </div>
                </div>

                {/* Reverse proxy public ports — collapsed by default */}
                <details className="text-sm mt-2">
                    <summary className="text-ink-muted cursor-pointer hover:text-ink">
                        Reverse Proxy: Public-facing ports (for URL generation)
                    </summary>
                    <p className="text-xs text-ink-muted mt-2 mb-3">
                        Only set these if a reverse proxy (nginx, HAProxy, etc.) terminates on different ports
                        than the server binds to. These values are used to build AIA, CDP, OCSP, and management
                        URLs embedded in certificates. If running direct (no proxy), leave these matching the
                        ports above.
                    </p>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div>
                            <label htmlFor="httpsPublicPort" className="block text-sm font-medium text-ink mb-1">
                                HTTPS Public Port
                            </label>
                            <input
                                id="httpsPublicPort"
                                type="text"
                                inputMode="numeric"
                                value={data.httpsPublicPort ?? ''}
                                placeholder={String(data.httpsBindPort)}
                                onChange={e => { const v = e.target.value.replace(/\D/g, ''); onChange({ ...data, httpsPublicPort: v === '' ? null : parseInt(v) }); }}
                                className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-ink focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent"
                            />
                            <p className="text-xs text-ink-muted mt-1">Port clients connect to for HTTPS. Leave blank to follow the HTTPS Port above — only set it if a proxy terminates on a different port.</p>
                        </div>
                        <div>
                            <label htmlFor="httpPublicPort" className="block text-sm font-medium text-ink mb-1">
                                HTTP Public Port
                            </label>
                            <input
                                id="httpPublicPort"
                                type="text"
                                inputMode="numeric"
                                value={data.httpPublicPort ?? ''}
                                placeholder={String(data.httpPort)}
                                onChange={e => { const v = e.target.value.replace(/\D/g, ''); onChange({ ...data, httpPublicPort: v === '' ? null : parseInt(v) }); }}
                                className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-ink focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent"
                            />
                            <p className="text-xs text-ink-muted mt-1">Port clients connect to for CRL/OCSP/AIA. Leave blank to follow the HTTP Port above — only set it if a proxy terminates on a different port.</p>
                        </div>
                    </div>
                </details>
            </div>

            {/* Backup Storage */}
            <div className="border-t border-line pt-6 space-y-4">
                <h3 className="text-lg font-semibold text-ink">Backup Storage</h3>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                        <label htmlFor="backupOutputPath" className="block text-sm font-medium text-ink mb-1">
                            Backup Output Path
                        </label>
                        <input
                            id="backupOutputPath"
                            type="text"
                            value={data.backupOutputPath}
                            onChange={e => onChange({ ...data, backupOutputPath: e.target.value })}
                            placeholder="backups"
                            className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-ink placeholder-ink-faint focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent"
                        />
                    </div>
                    <div>
                        <label htmlFor="backupRetentionCount" className="block text-sm font-medium text-ink mb-1">
                            Retention Count
                        </label>
                        <input
                            id="backupRetentionCount"
                            type="text"
                            inputMode="numeric"
                            value={data.backupRetentionCount}
                            onChange={e => { const v = e.target.value.replace(/\D/g, ''); onChange({ ...data, backupRetentionCount: v === '' ? ('' as any) : parseInt(v) }); }}
                            onBlur={() => { if (!data.backupRetentionCount) onChange({ ...data, backupRetentionCount: 10 }); }}
                            className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-ink focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent"
                        />
                    </div>
                </div>
            </div>

            {/* Logging */}
            <div className="border-t border-line pt-6 space-y-4">
                <h3 className="text-lg font-semibold text-ink">Logging</h3>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                        <label htmlFor="logLevel" className="block text-sm font-medium text-ink mb-1">
                            Log Level
                        </label>
                        <select
                            id="logLevel"
                            value={data.logLevel}
                            onChange={e => onChange({ ...data, logLevel: e.target.value })}
                            className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-ink focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent"
                        >
                            {logLevels.map(level => (
                                <option key={level} value={level}>{level}</option>
                            ))}
                        </select>
                    </div>
                    <div>
                        <label htmlFor="logRetentionDays" className="block text-sm font-medium text-ink mb-1">
                            Log Retention (days)
                        </label>
                        <input
                            id="logRetentionDays"
                            type="text"
                            inputMode="numeric"
                            value={data.logRetentionDays}
                            onChange={e => { const v = e.target.value.replace(/\D/g, ''); onChange({ ...data, logRetentionDays: v === '' ? ('' as any) : parseInt(v) }); }}
                            onBlur={() => { if (!data.logRetentionDays) onChange({ ...data, logRetentionDays: 30 }); }}
                            className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-ink focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent"
                        />
                    </div>
                </div>
            </div>
        </div>
    );
};

export default NetworkAdvanced;
