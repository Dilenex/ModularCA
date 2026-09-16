import React, { useState, useEffect } from 'react';
import type { NoticeInput } from '@shared/notifications/notice';
import { errorNotice } from '@shared-auth/api/notices';
import { apiBlob, apiGetAllPages } from '../../api/client';
import { useToast } from '@shared/context/ToastContext';
import { StatusBadge } from '@shared/components/cards/StatusBadge';
import { DetailField } from '@shared/components/cards/DetailField';
import { DataTable, type DataTableColumn } from '@shared/components/DataTable';

function formatDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function caStatus(cert: any): 'active' | 'revoked' | 'expired' {
    if (cert.revoked) return 'revoked';
    if (new Date(cert.notAfter) < new Date()) return 'expired';
    return 'active';
}

function statusBadgeType(s: string): 'active' | 'disabled' | 'pending' {
    if (s === 'active') return 'active';
    if (s === 'revoked') return 'disabled';
    return 'pending';
}

function caType(cert: any): string {
    // A self-signed cert (issuer == subject) is a root CA; otherwise intermediate
    if (cert.issuer && cert.subjectDN && cert.issuer === cert.subjectDN) return 'Root';
    return 'Intermediate';
}

function parseCn(dn: string): string {
    const match = dn?.match(/CN=([^,]+)/);
    return match ? match[1] : dn || '-';
}

/**
 * The SHA-256 fingerprint of the CA certificate, read from the `thumbprints` JSON the API
 * attaches to every certificate (`{"SHA 1": "...", "SHA 256": "..."}`). This page exists so a
 * user can check, out of band, that the CA they are about to trust is the one the operator
 * published; the fingerprint is the value that check is made against. Null when absent.
 */
function sha256Thumbprint(cert: { thumbprints?: string | null }): string | null {
    if (!cert.thumbprints) return null;
    try {
        const obj = JSON.parse(cert.thumbprints);
        if (typeof obj !== 'object' || obj === null) return null;
        const key = Object.keys(obj).find((k) => k.replace(/[\s-]/g, '').toUpperCase() === 'SHA256');
        const v = key ? String(obj[key]) : '';
        return /^[0-9A-Fa-f]{64}$/.test(v) ? v.toUpperCase() : null;
    } catch {
        return null;
    }
}

/** AB:CD:... grouping, the form openssl and browsers print, so it can be compared by eye. */
function colonised(hex: string): string {
    return hex.match(/.{2}/g)?.join(':') ?? hex;
}

interface CaCertificate {
    certificateId: string;
    serialNumber: string;
    subjectDN: string;
    issuer: string;
    notBefore: string;
    notAfter: string;
    keyAlgorithm: string;
    keySize: string;
    signatureAlgorithm: string;
    isCA: boolean;
    revoked: boolean;
    thumbprints?: string | null;
}

const CaInformation: React.FC = () => {
    const { showToast } = useToast();
    const [authorities, setAuthorities] = useState<CaCertificate[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<NoticeInput | null>(null);

    useEffect(() => {
        // The endpoint returns a pagination envelope — { total, page, pageSize, totalPages,
        // items } — not a bare array. The old `Array.isArray(data) ? data : []` therefore always
        // took the empty branch, so the Trusted CAs page rendered permanently blank with no
        // error to explain it. MyCertificates in this same app reads `data.items` correctly;
        // this is the sibling that did not.
        // ...and it pages at 25, so taking only the first response also capped the list.
        apiGetAllPages<CaCertificate>('/api/v1/user/authorities')
            .then(({ items }) => setAuthorities(items))
            .catch((err) => setError(errorNotice(err, 'The request failed.')))
            .finally(() => setLoading(false));
    }, []);

    const downloadBlob = (data: BlobPart, filename: string, mimeType: string) => {
        const blob = new Blob([data], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
    };

    const handleDownloadPem = async (cert: CaCertificate) => {
        try {
            // The public CA endpoint is the one that serves CA certificates (the user-scoped
            // /file route hides them); apiBlob still routes it through the shared client so the
            // same base URL, refresh and error handling apply as for the chain below.
            const resp = await apiBlob(`/api/v1/public/ca/${cert.serialNumber}`, {
                headers: { Accept: 'application/x-pem-file' }
            });
            const pem = await resp.text();
            const name = parseCn(cert.subjectDN).replace(/[^a-zA-Z0-9._-]/g, '_');
            downloadBlob(pem, `${name}.pem`, 'application/x-pem-file');
        } catch (err: any) {
            showToast('error', err.message || 'Download failed');
        }
    };

    const handleDownloadDer = async (cert: CaCertificate) => {
        try {
            const resp = await apiBlob(`/api/v1/public/ca/${cert.serialNumber}`, {
                headers: { Accept: 'application/pkix-cert' }
            });
            const blob = await resp.blob();
            const name = parseCn(cert.subjectDN).replace(/[^a-zA-Z0-9._-]/g, '_');
            downloadBlob(blob, `${name}.cer`, 'application/pkix-cert');
        } catch (err: any) {
            showToast('error', err.message || 'Download failed');
        }
    };

    const handleDownloadChain = async (cert: CaCertificate) => {
        try {
            const resp = await apiBlob(`/api/v1/user/authorities/${cert.serialNumber}/chain`);
            const chainPem = await resp.text();
            const name = parseCn(cert.subjectDN).replace(/[^a-zA-Z0-9._-]/g, '_');
            downloadBlob(chainPem, `${name}-chain.pem`, 'application/x-pem-file');
        } catch (err: any) {
            showToast('error', err.message || 'Download failed');
        }
    };

    const columns: DataTableColumn<CaCertificate>[] = [
        {
            key: 'status', header: 'Status', defaultWidth: 110, truncate: false,
            exportValue: (c) => caStatus(c),
            render: (c) => {
                const s = caStatus(c);
                return <StatusBadge status={statusBadgeType(s)} label={s.charAt(0).toUpperCase() + s.slice(1)} />;
            },
        },
        {
            key: 'type', header: 'Type', defaultWidth: 120, truncate: false,
            exportValue: (c) => caType(c),
            render: (c) => (
                <span className="px-2 py-0.5 text-xs rounded bg-gray-200 dark:bg-gray-700 text-gray-600 dark:text-gray-400 border border-gray-300 dark:border-gray-600">
                    {caType(c)}
                </span>
            ),
        },
        {
            key: 'name', header: 'Common Name', defaultWidth: 280,
            exportValue: (c) => parseCn(c.subjectDN),
            render: (c) => <span className="text-sm text-gray-900 dark:text-white truncate">{parseCn(c.subjectDN)}</span>,
        },
        {
            key: 'sha256', header: 'SHA-256 Fingerprint', defaultWidth: 260,
            exportValue: (c) => sha256Thumbprint(c) ?? '',
            render: (c) => {
                const fp = sha256Thumbprint(c);
                return fp
                    ? <span className="font-mono text-xs text-gray-600 dark:text-gray-400 truncate" title={colonised(fp)}>{colonised(fp)}</span>
                    : <span className="text-xs text-gray-500">not available</span>;
            },
        },
        {
            key: 'expires', header: 'Expires', defaultWidth: 210, truncate: false,
            exportValue: (c) => formatDate(c.notAfter),
            render: (c) => {
                const s = caStatus(c);
                const daysLeft = Math.ceil((new Date(c.notAfter).getTime() - Date.now()) / (1000 * 60 * 60 * 24));
                return (
                    <span className="text-xs text-gray-600 dark:text-gray-400 flex items-center gap-2 whitespace-nowrap">
                        {formatDate(c.notAfter)}
                        {s === 'active' && daysLeft <= 90 && <span className="text-yellow-700 dark:text-yellow-400">{daysLeft}d left</span>}
                    </span>
                );
            },
        },
    ];

    const copyFingerprint = (fp: string) =>
        navigator.clipboard.writeText(colonised(fp)).then(() => showToast('success', 'Fingerprint copied')).catch(() => showToast('error', 'Could not copy'));

    const renderExpanded = (cert: CaCertificate) => {
        const status = caStatus(cert);
        const type = caType(cert);
        const fp = sha256Thumbprint(cert);
        return (
            <div className="space-y-3">
                <div className="bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded p-3 space-y-1">
                    <div className="flex items-center justify-between gap-2">
                        <span className="text-xs font-semibold text-gray-700 dark:text-gray-300">SHA-256 fingerprint</span>
                        {fp && (
                            <button onClick={() => copyFingerprint(fp)} className="px-2 py-0.5 text-[11px] bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors">Copy</button>
                        )}
                    </div>
                    {fp ? (
                        <code className="block font-mono text-xs text-gray-900 dark:text-white break-all select-all">{colonised(fp)}</code>
                    ) : (
                        <span className="text-xs text-gray-500">The server did not include a fingerprint for this certificate.</span>
                    )}
                    <p className="text-[11px] text-gray-500 dark:text-gray-400">Compare this with the value your administrator published through another channel before trusting the download. Run <code className="font-mono">openssl x509 -noout -fingerprint -sha256 -in file.pem</code> on the file to check it matches.</p>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                    <DetailField label="Subject" value={cert.subjectDN} />
                    <DetailField label="Issuer" value={cert.issuer} />
                    <DetailField label="Serial Number" value={cert.serialNumber} mono />
                    <DetailField label="Not Before" value={formatDate(cert.notBefore)} />
                    <DetailField label="Not After" value={formatDate(cert.notAfter)} />
                    <DetailField label="Algorithm" value={`${cert.keyAlgorithm || '-'} ${cert.keySize || ''}`} />
                    <DetailField label="Signature" value={cert.signatureAlgorithm || '-'} />
                    <DetailField label="Type" value={type} />
                </div>

                {status === 'revoked' && (
                    <div className="bg-red-50 dark:bg-red-900/20 border border-red-300 dark:border-red-800 rounded p-2">
                        <span className="text-xs text-red-800 dark:text-red-400">This CA certificate has been revoked.</span>
                    </div>
                )}

                <div className="flex flex-wrap gap-2 pt-2 border-t border-gray-300 dark:border-gray-700">
                    <button
                        onClick={() => handleDownloadPem(cert)}
                        className="px-3 py-1.5 text-xs bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors"
                    >
                        PEM
                    </button>
                    <button
                        onClick={() => handleDownloadDer(cert)}
                        className="px-3 py-1.5 text-xs bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors"
                    >
                        DER
                    </button>
                    <button
                        onClick={() => handleDownloadChain(cert)}
                        className="px-3 py-1.5 text-xs bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors"
                    >
                        Trust Chain
                    </button>
                </div>
            </div>
        );
    };

    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Trusted CAs</h1>

            <DataTable<CaCertificate>
                tableId="trusted-cas"
                title="Trusted CAs"
                rows={authorities}
                rowKey={(c) => c.serialNumber}
                loading={loading}
                error={error}
                empty="No Certificate Authorities available."
                columns={columns}
                exportFileName="trusted-cas"
                renderExpanded={renderExpanded}
            />
        </div>
    );
};

export default CaInformation;
