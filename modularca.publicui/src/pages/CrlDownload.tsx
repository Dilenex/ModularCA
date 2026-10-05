import React, { useState, useEffect } from 'react';
import { apiGet } from '../api/client';

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

const CrlDownload: React.FC = () => {
    const [cas, setCas] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        apiGet<any>('/api/v1/public/ca')
            .then((data) => setCas(Array.isArray(data) ? data : (data.items || [])))
            .catch((err) => setError(err.message))
            .finally(() => setLoading(false));
    }, []);

    return (
        <div className="space-y-6">
            <div>
                <h1 className="text-xl font-semibold text-ink">CRL Downloads</h1>
                <p className="text-sm text-ink-muted mt-1">
                    Download Certificate Revocation Lists (CRLs) to verify whether certificates have been revoked.
                </p>
            </div>

            {loading && <p className="text-sm text-ink-muted">Loading...</p>}
            {error && <p className="text-sm text-crit">{error}</p>}

            <div className="space-y-3">
                {cas.map((ca) => {
                    const id = ca.serialNumber || ca.serial || ca.id;
                    return (
                        <div key={id} className="bg-raised border border-line rounded-lg p-5">
                            <div className="flex items-center justify-between">
                                <div>
                                    <h3 className="text-sm font-semibold text-ink">{ca.subjectDN || ca.name}</h3>
                                    <p className="text-xs text-ink-muted mt-1">
                                        Serial: <span className="font-mono">{id}</span>
                                    </p>
                                    {ca.lastCrlGenerated && (
                                        <p className="text-xs text-ink-muted mt-0.5">
                                            Last generated: {formatDate(ca.lastCrlGenerated)}
                                        </p>
                                    )}
                                </div>
                                <div className="flex gap-2">
                                    {/* No `download` attr: let the server's Content-Disposition
                                        supply the CN-based filename, matching the cert downloads. */}
                                    <a
                                        href={`/crl/${id}`}
                                        className="px-3 py-1.5 text-xs bg-accent text-on-accent rounded hover:bg-accent-hover transition-colors"
                                    >
                                        Full CRL
                                    </a>
                                    <a
                                        href={`/crl/${id}/delta`}
                                        className="px-3 py-1.5 text-xs bg-sunken text-ink rounded hover:bg-hover transition-colors"
                                    >
                                        Delta CRL
                                    </a>
                                </div>
                            </div>
                        </div>
                    );
                })}
            </div>

            {!loading && !error && cas.length === 0 && (
                <p className="text-sm text-ink-muted text-center py-8">No CAs available.</p>
            )}

            {/* CRL Distribution Points info */}
            <div className="bg-raised border border-line rounded-lg p-5">
                <h2 className="text-sm font-semibold text-ink mb-2">CRL Distribution Points</h2>
                <p className="text-xs text-ink-muted">
                    Certificates issued by this CA include CRL Distribution Point (CDP) extensions
                    that point to these CRL URLs. Most applications will check CRLs automatically.
                </p>
            </div>
        </div>
    );
};

export default CrlDownload;
