import React, { useState, useEffect } from 'react';
import { apiGet } from '../api/client';
import { useToast } from '../context/ToastContext';
import { Chevron } from '@shared/components/Chevron';

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
}

function extractCn(subjectDn: string | null | undefined): string | null {
    if (!subjectDn) return null;
    for (const part of subjectDn.split(',')) {
        const trimmed = part.trim();
        if (trimmed.toUpperCase().startsWith('CN=')) return trimmed.substring(3).trim();
    }
    return null;
}

// Pull the filename from a Content-Disposition header so the portal saves files
// under the same formal CN-based name the server sends (e.g. "Test-Root-CA.cer"),
// matching the direct/AIA download URLs. Falls back to the supplied default.
function filenameFromContentDisposition(header: string | null, fallback: string): string {
    if (!header) return fallback;
    // Prefer RFC 5987 filename*=UTF-8''… (handles non-ASCII), then plain filename=.
    const star = header.match(/filename\*=(?:UTF-8'')?([^;]+)/i);
    if (star) {
        try { return decodeURIComponent(star[1].trim().replace(/^"|"$/g, '')); } catch { /* fall through */ }
    }
    const plain = header.match(/filename="?([^";]+)"?/i);
    return plain ? plain[1].trim() : fallback;
}

const CaCertificates: React.FC = () => {
    const { showToast } = useToast();
    const [cas, setCas] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [expanded, setExpanded] = useState<string | null>(null);

    useEffect(() => {
        apiGet<any>('/api/v1/public/ca')
            .then((data) => setCas(Array.isArray(data) ? data : (data.items || [])))
            .catch((err) => setError(err.message))
            .finally(() => setLoading(false));
    }, []);

    return (
        <div className="space-y-6">
            <div>
                <h1 className="text-2xl font-bold text-gray-900 dark:text-white">CA Certificates</h1>
                <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">Download root and intermediate CA certificates to establish trust with this CA.</p>
            </div>

            {loading && <p className="text-sm text-gray-600 dark:text-gray-400">Loading...</p>}
            {error && <p className="text-sm text-red-800 dark:text-red-400">{error}</p>}

            <div className="space-y-3">
                {cas.map((ca) => {
                    const id = ca.serialNumber || ca.serial || ca.id;
                    const friendlyName = ca.label || ca.name || extractCn(ca.subjectDN) || id;
                    const isExpanded = expanded === id;
                    return (
                        <div key={id} className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg overflow-hidden">
                            <button
                                onClick={() => setExpanded(isExpanded ? null : id)}
                                className="w-full px-5 py-4 flex items-center justify-between text-left hover:bg-gray-200/50 dark:bg-gray-700/50 dark:hover:bg-gray-700 transition-colors"
                            >
                                <div>
                                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white">{ca.subjectDN || ca.name}</h3>
                                    <p className="text-xs text-gray-600 mt-1">
                                        Serial: <span className="font-mono">{id}</span>
                                        {ca.notAfter && <> &middot; Valid until {formatDate(ca.notAfter)}</>}
                                    </p>
                                </div>
                                <Chevron open={isExpanded} className="w-2.5 h-2.5 text-gray-600" />
                            </button>
                            {isExpanded && (
                                <div className="px-5 pb-4 border-t border-gray-300 dark:border-gray-700 pt-3 space-y-3">
                                    <div className="grid grid-cols-2 gap-2 text-xs">
                                        <div><span className="text-gray-600">Issuer:</span> <span className="text-gray-700 dark:text-gray-300">{ca.issuerDN || ca.issuer || '-'}</span></div>
                                        <div><span className="text-gray-600">Not Before:</span> <span className="text-gray-700 dark:text-gray-300">{formatDate(ca.notBefore)}</span></div>
                                        <div><span className="text-gray-600">Not After:</span> <span className="text-gray-700 dark:text-gray-300">{formatDate(ca.notAfter)}</span></div>
                                        <div><span className="text-gray-600">Algorithm:</span> <span className="text-gray-700 dark:text-gray-300">{[ca.keyAlgorithm, ca.keySize].filter(Boolean).join(' ') || ca.signatureAlgorithm || '-'}</span></div>
                                    </div>
                                    <div className="flex gap-2">
                                        <button
                                            onClick={async () => {
                                                try {
                                                    const resp = await fetch(`/api/v1/public/ca/${id}`, { headers: { Accept: 'application/x-pem-file' } });
                                                    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
                                                    const pem = await resp.text();
                                                    const a = document.createElement('a');
                                                    a.href = URL.createObjectURL(new Blob([pem], { type: 'application/x-pem-file' }));
                                                    a.download = filenameFromContentDisposition(resp.headers.get('Content-Disposition'), `${friendlyName}.pem`);
                                                    a.click();
                                                } catch { showToast('error', 'Download failed'); }
                                            }}
                                            className="px-3 py-1.5 text-xs bg-blue-600 text-gray-900 dark:text-white rounded hover:bg-blue-700 transition-colors"
                                        >
                                            Download PEM
                                        </button>
                                        <button
                                            onClick={async () => {
                                                try {
                                                    const resp = await fetch(`/api/v1/public/ca/${id}`, { headers: { Accept: 'application/pkix-cert' } });
                                                    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
                                                    const blob = await resp.blob();
                                                    const a = document.createElement('a');
                                                    a.href = URL.createObjectURL(blob);
                                                    a.download = filenameFromContentDisposition(resp.headers.get('Content-Disposition'), `${friendlyName}.cer`);
                                                    a.click();
                                                } catch { showToast('error', 'Download failed'); }
                                            }}
                                            className="px-3 py-1.5 text-xs bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors"
                                        >
                                            Download DER
                                        </button>
                                    </div>
                                </div>
                            )}
                        </div>
                    );
                })}
            </div>

            {!loading && !error && cas.length === 0 && (
                <p className="text-sm text-gray-600 text-center py-8">No CA certificates available.</p>
            )}
        </div>
    );
};

export default CaCertificates;
