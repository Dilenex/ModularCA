import React, { useState, useEffect } from 'react';
import { apiGet } from '../api/client';

interface CaInfo {
    id: string;
    name: string;
    label: string;
    isDefault: boolean;
}

interface PublicInfo {
    publicDomain: string;
    publicHttpsBaseUrl: string;
}

const AcmeDirectory: React.FC = () => {
    const [cas, setCas] = useState<CaInfo[]>([]);
    const [selectedLabel, setSelectedLabel] = useState<string>('');
    const [directory, setDirectory] = useState<any>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    // Canonical public base URL from the server (built from Https.PublicDomain),
    // not window.location.origin — a reverse proxy may present a different host
    // than the one operators configured for external clients to use.
    const [baseUrl, setBaseUrl] = useState<string>(window.location.origin);

    // Load available CAs and the canonical public info in parallel
    useEffect(() => {
        apiGet<PublicInfo>('/api/v1/public/info')
            .then((info) => {
                if (info?.publicHttpsBaseUrl) setBaseUrl(info.publicHttpsBaseUrl);
            })
            .catch(() => {
                // Fall back to window.location.origin (already set) — don't
                // block the page on this.
            });

        apiGet<any[]>('/api/v1/public/ca')
            .then((data) => {
                // Only CAs that actually expose ACME. The API's per-CA `protocols`
                // list is already gated by per-CA config + the system ACME flag, so a
                // CA appears here only when ACME is genuinely usable against it.
                const caList = (data || [])
                    .filter((ca: any) => (ca.protocols || []).some((p: any) => p.protocol === 'ACME'))
                    .map((ca: any) => ({
                        id: ca.id,
                        name: ca.name || ca.subjectDN,
                        label: ca.label || 'default',
                        isDefault: ca.isDefault,
                    }));
                setCas(caList);
                const defaultCa = caList.find(c => c.isDefault) || caList[0];
                if (defaultCa) setSelectedLabel(defaultCa.label);
            })
            .catch((err) => setError(err.message))
            .finally(() => setLoading(false));
    }, []);

    // Load ACME directory when a CA is selected
    useEffect(() => {
        if (!selectedLabel) return;
        setLoading(true);
        setError(null);
        apiGet<any>(`/acme/${selectedLabel}/directory`)
            .then(setDirectory)
            .catch((err) => setError(err.message))
            .finally(() => setLoading(false));
    }, [selectedLabel]);

    const directoryUrl = selectedLabel ? `${baseUrl}/acme/${selectedLabel}/directory` : '';

    return (
        <div className="space-y-6">
            <div>
                <h1 className="text-xl font-semibold text-ink">ACME Directory</h1>
                <p className="text-sm text-ink-muted mt-1">
                    Use the ACME protocol to automatically obtain and renew TLS certificates.
                </p>
            </div>

            {/* No ACME-enabled CA */}
            {!loading && !error && cas.length === 0 && (
                <div className="bg-raised border border-line rounded-lg p-5">
                    <p className="text-sm text-ink-muted">
                        ACME is not enabled for any certificate authority on this deployment.
                    </p>
                </div>
            )}

            {/* CA Selector */}
            {cas.length > 1 && (
                <div className="bg-raised border border-line rounded-lg p-5">
                    <h2 className="text-sm font-semibold text-ink mb-3">Certificate Authority</h2>
                    <select
                        value={selectedLabel}
                        onChange={(e) => setSelectedLabel(e.target.value)}
                        className="w-full bg-raised border border-line-strong text-ink rounded px-3 py-2 text-sm focus:border-accent focus:outline-none"
                    >
                        {cas.map((ca) => (
                            <option key={ca.label} value={ca.label}>
                                {ca.name} {ca.isDefault ? '(default)' : ''}
                            </option>
                        ))}
                    </select>
                </div>
            )}

            {/* Directory URL */}
            {directoryUrl && (
                <div className="bg-raised border border-line rounded-lg p-5">
                    <h2 className="text-sm font-semibold text-ink mb-3">Directory URL</h2>
                    <div className="bg-sunken rounded px-4 py-3 data-mono text-accent-ink select-all">
                        {directoryUrl}
                    </div>
                </div>
            )}

            {/* Directory endpoints */}
            {loading && <p className="text-sm text-ink-muted">Loading directory...</p>}
            {error && <p className="text-sm text-crit">{error}</p>}

            {directory && (
                <div className="bg-raised border border-line rounded-lg p-5">
                    <h2 className="text-sm font-semibold text-ink mb-3">Endpoints</h2>
                    <div className="space-y-2">
                        {Object.entries(directory).filter(([k]) => k !== 'meta').map(([key, url]) => (
                            <div key={key} className="flex items-center justify-between py-1 border-b border-line last:border-b-0">
                                <span className="text-ink-muted data-mono">{key}</span>
                                <span className="text-ink data-mono">{String(url)}</span>
                            </div>
                        ))}
                    </div>
                    {directory.meta && (
                        <div className="mt-4 pt-3 border-t border-line">
                            <h3 className="text-xs font-semibold text-ink-muted mb-2">Metadata</h3>
                            <pre className="text-xs text-ink-muted bg-sunken rounded p-3 overflow-x-auto">
                                {JSON.stringify(directory.meta, null, 2)}
                            </pre>
                        </div>
                    )}
                </div>
            )}

            {/* Client examples */}
            {directoryUrl && (
                <div className="bg-raised border border-line rounded-lg p-5 space-y-4">
                    <h2 className="text-sm font-semibold text-ink">Client Configuration</h2>

                    <div>
                        <h3 className="text-xs font-semibold text-accent-ink mb-1">certbot</h3>
                        <pre className="text-xs text-ink bg-sunken rounded p-3 overflow-x-auto">
{`certbot certonly \\
  --server ${directoryUrl} \\
  --standalone \\
  -d example.com`}
                        </pre>
                    </div>

                    <div>
                        <h3 className="text-xs font-semibold text-accent-ink mb-1">acme.sh</h3>
                        <pre className="text-xs text-ink bg-sunken rounded p-3 overflow-x-auto">
{`acme.sh --issue \\
  --server ${directoryUrl} \\
  --standalone \\
  -d example.com`}
                        </pre>
                    </div>

                    <div>
                        <h3 className="text-xs font-semibold text-accent-ink mb-1">win-acme</h3>
                        <pre className="text-xs text-ink bg-sunken rounded p-3 overflow-x-auto">
{`wacs.exe --baseuri ${directoryUrl}`}
                        </pre>
                    </div>

                    <div className="text-xs text-ink-muted pt-2 border-t border-line">
                        If this CA uses a self-signed root certificate, you may need to add the
                        <code className="mx-1 px-1 bg-sunken rounded">--no-verify-ssl</code> flag
                        or install the CA certificate in your trust store first.
                    </div>
                </div>
            )}
        </div>
    );
};

export default AcmeDirectory;
