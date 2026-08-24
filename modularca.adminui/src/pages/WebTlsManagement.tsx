import React, { useState, useEffect } from 'react';
import { apiGet, apiPostWithMfa } from '../api/client';
import { useStepUp } from '../components/StepUpMfaContext';
import { StepUpOps } from '@shared/generated';

interface WebTlsCertStatusResponse {
    serialNumber: string;
    commonName: string;
    organization: string;
    organizationalUnit: string;
    locality: string;
    state: string;
    country: string;
    sans: string[];
    notBefore: string;
    notAfter: string;
    daysUntilExpiry: number;
    isExpired: boolean;
    httpsPort: number;
    signingProfileId: string | null;
    signingProfileName: string | null;
    keyAlgorithm: string | null;
    keySize: string | null;
}

interface ReissueFormState {
    commonName: string;
    organization: string;
    organizationalUnit: string;
    locality: string;
    state: string;
    country: string;
    sansText: string;
    validityDays: number;
    signingProfileId: string;
    keyAlgorithm: string;
    keySize: string;
}

function formatDate(d: string | null | undefined): string {
    if (!d) return '-';
    return new Date(d).toLocaleString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
    });
}

const emptyForm: ReissueFormState = {
    commonName: '',
    organization: '',
    organizationalUnit: '',
    locality: '',
    state: '',
    country: '',
    sansText: '',
    validityDays: 397,
    signingProfileId: '',
    keyAlgorithm: 'ECDSA',
    keySize: '256',
};

/* ─── Current Certificate Card ─── */
const CurrentCertCard: React.FC<{
    status: WebTlsCertStatusResponse | null;
    loading: boolean;
    error: string | null;
    onRefresh: () => void;
}> = ({ status, loading, error, onRefresh }) => {
    const renderExpiryBadge = () => {
        if (!status) return null;
        if (status.isExpired) {
            return (
                <span className="inline-block px-2 py-0.5 rounded text-xs font-semibold bg-red-50 dark:bg-red-900/40 border border-red-300 dark:border-red-700 text-red-800 dark:text-red-300">
                    EXPIRED
                </span>
            );
        }
        const days = status.daysUntilExpiry;
        let cls = 'bg-green-50 dark:bg-green-900/40 border border-green-300 dark:border-green-700 text-green-800 dark:text-green-300';
        if (days <= 7) cls = 'bg-red-50 dark:bg-red-900/40 border border-red-300 dark:border-red-700 text-red-800 dark:text-red-300';
        else if (days <= 30) cls = 'bg-yellow-50 dark:bg-yellow-900/40 border border-yellow-300 dark:border-yellow-700 text-yellow-800 dark:text-yellow-300';
        return (
            <span className={`inline-block px-2 py-0.5 rounded text-xs font-semibold ${cls}`}>
                {days} day{days === 1 ? '' : 's'}
            </span>
        );
    };

    return (
        <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-6 space-y-4">
            <div className="flex items-center justify-between">
                <h3 className="text-gray-900 dark:text-white font-semibold">Current Web TLS Certificate</h3>
                <button
                    onClick={onRefresh}
                    disabled={loading}
                    className="px-3 py-1.5 bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 disabled:bg-gray-600 text-gray-700 dark:text-gray-300 text-xs font-medium rounded transition-colors"
                >
                    {loading ? 'Loading...' : 'Refresh'}
                </button>
            </div>

            {loading && (
                <div className="p-6 text-sm text-gray-600 dark:text-gray-400 text-center">
                    <div className="inline-block animate-spin rounded-full h-6 w-6 border-b-2 border-blue-500"></div>
                    <div className="mt-2">Loading certificate details...</div>
                </div>
            )}

            {error && !loading && (
                <div className="p-3 bg-red-50 dark:bg-red-900/30 border border-red-300 dark:border-red-700 rounded text-red-800 dark:text-red-300 text-sm">
                    {error}
                </div>
            )}

            {!loading && !error && status && (
                <div className="bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded p-4">
                    <dl className="grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-3 text-sm">
                        <div>
                            <dt className="text-xs text-gray-600 dark:text-gray-400">Serial Number</dt>
                            <dd className="font-mono text-xs text-gray-900 dark:text-white break-all">
                                {status.serialNumber}
                            </dd>
                        </div>
                        <div>
                            <dt className="text-xs text-gray-600 dark:text-gray-400">HTTPS Port</dt>
                            <dd className="text-gray-900 dark:text-white">{status.httpsPort}</dd>
                        </div>
                        <div>
                            <dt className="text-xs text-gray-600 dark:text-gray-400">Common Name (CN)</dt>
                            <dd className="text-gray-900 dark:text-white">{status.commonName || '-'}</dd>
                        </div>
                        <div>
                            <dt className="text-xs text-gray-600 dark:text-gray-400">Organization (O)</dt>
                            <dd className="text-gray-900 dark:text-white">{status.organization || '-'}</dd>
                        </div>
                        <div>
                            <dt className="text-xs text-gray-600 dark:text-gray-400">Organizational Unit (OU)</dt>
                            <dd className="text-gray-900 dark:text-white">{status.organizationalUnit || '-'}</dd>
                        </div>
                        <div>
                            <dt className="text-xs text-gray-600 dark:text-gray-400">Locality (L)</dt>
                            <dd className="text-gray-900 dark:text-white">{status.locality || '-'}</dd>
                        </div>
                        <div>
                            <dt className="text-xs text-gray-600 dark:text-gray-400">State (ST)</dt>
                            <dd className="text-gray-900 dark:text-white">{status.state || '-'}</dd>
                        </div>
                        <div>
                            <dt className="text-xs text-gray-600 dark:text-gray-400">Country (C)</dt>
                            <dd className="text-gray-900 dark:text-white">{status.country || '-'}</dd>
                        </div>
                        <div className="md:col-span-2">
                            <dt className="text-xs text-gray-600 dark:text-gray-400">Subject Alternative Names</dt>
                            <dd className="text-gray-900 dark:text-white">
                                {status.sans && status.sans.length > 0 ? (
                                    <ul className="font-mono text-xs space-y-0.5">
                                        {status.sans.map((san, i) => (
                                            <li key={i}>{san}</li>
                                        ))}
                                    </ul>
                                ) : (
                                    <span className="text-gray-600">(none)</span>
                                )}
                            </dd>
                        </div>
                        <div>
                            <dt className="text-xs text-gray-600 dark:text-gray-400">Signing Profile</dt>
                            <dd className="text-gray-900 dark:text-white">{status.signingProfileName || '-'}</dd>
                        </div>
                        <div>
                            <dt className="text-xs text-gray-600 dark:text-gray-400">Key Algorithm</dt>
                            <dd className="text-gray-900 dark:text-white">{status.keyAlgorithm || '-'}</dd>
                        </div>
                        <div>
                            <dt className="text-xs text-gray-600 dark:text-gray-400">Valid From</dt>
                            <dd className="text-gray-900 dark:text-white">{formatDate(status.notBefore)}</dd>
                        </div>
                        <div>
                            <dt className="text-xs text-gray-600 dark:text-gray-400">Valid To</dt>
                            <dd className="text-gray-900 dark:text-white">{formatDate(status.notAfter)}</dd>
                        </div>
                        <div className="md:col-span-2">
                            <dt className="text-xs text-gray-600 dark:text-gray-400">Days Until Expiry</dt>
                            <dd className="mt-1">{renderExpiryBadge()}</dd>
                        </div>
                    </dl>
                </div>
            )}
        </div>
    );
};

/* ─── Reissue Card ─── */
const ReissueCard: React.FC<{
    status: WebTlsCertStatusResponse | null;
    loading: boolean;
    onReissued: () => Promise<void>;
}> = ({ status, loading, onReissued }) => {
    const { requireStepUp } = useStepUp();
    const [form, setForm] = useState<ReissueFormState>(emptyForm);
    const [submitting, setSubmitting] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [success, setSuccess] = useState<string | null>(null);
    const [signingProfiles, setSigningProfiles] = useState<any[]>([]);

    // Load signing profiles for the dropdown
    useEffect(() => {
        apiGet<any>('/api/v1/admin/signing-profiles')
            .then(data => setSigningProfiles(Array.isArray(data) ? data : (data.items || [])))
            .catch(() => {});
    }, []);

    // Initialize form from loaded current cert
    useEffect(() => {
        if (status) {
            // Prefer the actual key size from the issuing CSR record. Fall back to a
            // sensible per-algorithm default only when the backend didn't supply one
            // (legacy data or non-DB-backed cert).
            const fallbackKeySize = status.keyAlgorithm === 'RSA' ? '2048'
                : status.keyAlgorithm === 'ML-DSA' ? '65'
                : status.keyAlgorithm === 'SLH-DSA' ? '128f'
                : status.keyAlgorithm === 'Ed25519' ? ''
                : '256';
            setForm({
                commonName: status.commonName ?? '',
                organization: status.organization ?? '',
                organizationalUnit: status.organizationalUnit ?? '',
                locality: status.locality ?? '',
                state: status.state ?? '',
                country: status.country ?? '',
                sansText: (status.sans ?? []).join('\n'),
                validityDays: 397,
                signingProfileId: status.signingProfileId ?? '',
                keyAlgorithm: status.keyAlgorithm ?? 'ECDSA',
                keySize: normalizeKeySize(status.keySize) || fallbackKeySize,
            });
        }
    }, [status]);

    const handleReissue = async () => {
        setError(null);
        setSuccess(null);

        // Never guess a key size. Falling back to 256 on an unparseable value is what turned a
        // P-384 reissue into a P-256 certificate without telling anyone. Ed25519 has no size.
        let keySize = 0;
        if (form.keyAlgorithm !== 'Ed25519') {
            keySize = parseInt(form.keySize, 10);
            if (!Number.isFinite(keySize) || keySize <= 0) {
                setError(`Unrecognised key size "${form.keySize}" for ${form.keyAlgorithm}. Pick one from the Key Size list.`);
                return;
            }
        }

        setSubmitting(true);
        try {
            const body = {
                commonName: form.commonName || undefined,
                organization: form.organization || undefined,
                organizationalUnit: form.organizationalUnit || undefined,
                locality: form.locality || undefined,
                state: form.state || undefined,
                country: form.country || undefined,
                sans: form.sansText
                    ? form.sansText.split('\n').map(s => s.trim()).filter(Boolean)
                    : undefined,
                validityDays: form.validityDays || undefined,
                signingProfileId: form.signingProfileId || undefined,
                keyAlgorithm: form.keyAlgorithm,
                keySize: form.keyAlgorithm === 'Ed25519' ? undefined : keySize,
            };
            const result = await apiPostWithMfa<any>(
                '/api/v1/admin/webtls/reissue',
                body,
                requireStepUp,
                StepUpOps.ReissueCert,
                'webtls',
            );
            setSuccess(result.message || `Reissued. New serial: ${result.newSerialNumber ?? 'unknown'}`);
            await onReissued();
        } catch (err: any) {
            if (err.message === 'Step-up MFA cancelled') {
                setSubmitting(false);
                return;
            }
            setError(err.message || 'Reissue failed');
        } finally {
            setSubmitting(false);
        }
    };

    const inputCls =
        'w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-400 dark:border-gray-600 rounded text-sm text-gray-900 dark:text-white focus:outline-none focus:border-blue-500';
    const labelCls = 'block text-xs text-gray-600 dark:text-gray-400 mb-1';

    return (
        <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-6 space-y-4">
            <h3 className="text-gray-900 dark:text-white font-semibold">Reissue Web TLS Certificate</h3>

            <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-300 dark:border-blue-700 rounded p-3 text-sm text-blue-800 dark:text-blue-300">
                Reissuing the Web TLS certificate validates the new subject and SANs against the
                "Web Server (ACME)" request profile and then hot-swaps the running certificate.
                No restart is required if hot-reload succeeds; otherwise the UI will tell you to
                restart the API.
            </div>

            {error && (
                <div className="p-3 bg-red-50 dark:bg-red-900/30 border border-red-300 dark:border-red-700 rounded text-red-800 dark:text-red-300 text-sm">
                    {error}
                </div>
            )}
            {success && (
                <div className="p-3 bg-green-50 dark:bg-green-900/30 border border-green-300 dark:border-green-700 rounded text-green-800 dark:text-green-300 text-sm">
                    {success}
                </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                    <label className={labelCls}>Common Name (CN)</label>
                    <input
                        type="text"
                        value={form.commonName}
                        onChange={(e) => setForm({ ...form, commonName: e.target.value })}
                        disabled={submitting || loading}
                        className={inputCls}
                    />
                </div>
                <div>
                    <label className={labelCls}>Organization (O)</label>
                    <input
                        type="text"
                        value={form.organization}
                        onChange={(e) => setForm({ ...form, organization: e.target.value })}
                        disabled={submitting || loading}
                        className={inputCls}
                    />
                </div>
                <div>
                    <label className={labelCls}>Organizational Unit (OU)</label>
                    <input
                        type="text"
                        value={form.organizationalUnit}
                        onChange={(e) => setForm({ ...form, organizationalUnit: e.target.value })}
                        disabled={submitting || loading}
                        className={inputCls}
                    />
                </div>
                <div>
                    <label className={labelCls}>Locality (L)</label>
                    <input
                        type="text"
                        value={form.locality}
                        onChange={(e) => setForm({ ...form, locality: e.target.value })}
                        disabled={submitting || loading}
                        className={inputCls}
                    />
                </div>
                <div>
                    <label className={labelCls}>State (ST)</label>
                    <input
                        type="text"
                        value={form.state}
                        onChange={(e) => setForm({ ...form, state: e.target.value })}
                        disabled={submitting || loading}
                        className={inputCls}
                    />
                </div>
                <div>
                    <label className={labelCls}>Country (C)</label>
                    <input
                        type="text"
                        value={form.country}
                        onChange={(e) => setForm({ ...form, country: e.target.value.toUpperCase() })}
                        disabled={submitting || loading}
                        maxLength={2}
                        className={inputCls}
                    />
                </div>
            </div>

            <div>
                <label className={labelCls}>Subject Alternative Names</label>
                <textarea
                    value={form.sansText}
                    onChange={(e) => setForm({ ...form, sansText: e.target.value })}
                    disabled={submitting || loading}
                    rows={5}
                    className={`${inputCls} font-mono`}
                />
                <p className="mt-1 text-xs text-gray-600 dark:text-gray-400">
                    One per line. Each entry must be prefixed with a type, e.g.{' '}
                    <code className="px-1 bg-gray-200 dark:bg-gray-900 rounded">DNS:api.example.com</code>{' '}
                    or <code className="px-1 bg-gray-200 dark:bg-gray-900 rounded">IP:10.0.0.5</code>.
                </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                    <label className={labelCls}>Validity (days)</label>
                    <input
                        type="text"
                        inputMode="numeric"
                        value={form.validityDays}
                        onChange={(e) => { const v = e.target.value.replace(/\D/g, ''); setForm({ ...form, validityDays: v === '' ? '' as any : parseInt(v, 10) }); }}
                        disabled={submitting || loading}
                        className={inputCls}
                    />
                    <p className="mt-1 text-xs text-gray-600 dark:text-gray-400">
                        Max 397 days for publicly-trusted certs.
                    </p>
                </div>
                <div>
                    <label className={labelCls}>Key Algorithm</label>
                    <select
                        value={form.keyAlgorithm}
                        onChange={(e) => {
                            const algo = e.target.value;
                            const defaultSize = algo === 'ECDSA' ? '256' : algo === 'RSA' ? '2048' : algo === 'ML-DSA' ? '65' : algo === 'SLH-DSA' ? '128f' : '';
                            setForm({ ...form, keyAlgorithm: algo, keySize: defaultSize });
                        }}
                        disabled={submitting || loading}
                        className={inputCls}
                    >
                        <option value="ECDSA">ECDSA</option>
                        <option value="RSA">RSA</option>
                        <option value="Ed25519">Ed25519</option>
                        <option value="ML-DSA">ML-DSA (FIPS 204 — Post-Quantum)</option>
                        <option value="SLH-DSA">SLH-DSA (FIPS 205 — Post-Quantum)</option>
                    </select>
                </div>
                {form.keyAlgorithm !== 'Ed25519' && (
                <div>
                    <label className={labelCls}>Key Size</label>
                    <select
                        value={form.keySize}
                        onChange={(e) => setForm({ ...form, keySize: e.target.value })}
                        disabled={submitting || loading}
                        className={inputCls}
                    >
                        {form.keyAlgorithm === 'RSA' ? (
                            <>
                                <option value="2048">2048</option>
                                <option value="3072">3072</option>
                                <option value="4096">4096</option>
                                <option value="7680">7680 (high compute)</option>
                                <option value="8192">8192 (high compute)</option>
                            </>
                        ) : form.keyAlgorithm === 'ML-DSA' ? (
                            <>
                                <option value="44">ML-DSA-44</option>
                                <option value="65">ML-DSA-65</option>
                                <option value="87">ML-DSA-87</option>
                            </>
                        ) : form.keyAlgorithm === 'SLH-DSA' ? (
                            <>
                                <option value="128f">SLH-DSA-128f</option>
                                <option value="128s">SLH-DSA-128s</option>
                                <option value="192f">SLH-DSA-192f</option>
                                <option value="192s">SLH-DSA-192s</option>
                                <option value="256f">SLH-DSA-256f</option>
                                <option value="256s">SLH-DSA-256s</option>
                            </>
                        ) : (
                            <>
                                <option value="256">P-256</option>
                                <option value="384">P-384</option>
                                <option value="521">P-521</option>
                            </>
                        )}
                    </select>
                    {form.keyAlgorithm === 'RSA' && (form.keySize === '7680' || form.keySize === '8192') && (
                        <p className="text-xs text-amber-600 dark:text-amber-400 mt-1">
                            ⚠ High-compute RSA — key generation may take 30+ seconds.
                        </p>
                    )}
                </div>
                )}
            </div>

            <div>
                <label className={labelCls}>Signing Profile (Issuing CA)</label>
                <select
                    value={form.signingProfileId}
                    onChange={(e) => setForm({ ...form, signingProfileId: e.target.value })}
                    disabled={submitting || loading}
                    className={inputCls}
                >
                    <option value="">Current ({status?.signingProfileName || 'unknown'})</option>
                    {signingProfiles.map((sp: any) => (
                        <option key={sp.id} value={sp.id}>{sp.name || sp.id}</option>
                    ))}
                </select>
                <p className="mt-1 text-xs text-gray-600 dark:text-gray-400">
                    Change the issuing CA by selecting a different signing profile.
                </p>
            </div>

            <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-300 dark:border-blue-700 rounded p-3 text-xs text-blue-800 dark:text-blue-300">
                A fresh key pair is generated on every reissue. The previous certificate is automatically revoked as Superseded.
            </div>

            <div>
                <button
                    onClick={handleReissue}
                    disabled={submitting || loading}
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 text-white text-sm font-medium rounded transition-colors"
                >
                    {submitting ? 'Reissuing...' : 'Reissue Web TLS Certificate'}
                </button>
            </div>
        </div>
    );
};

/* ─── Web TLS Management Page ─── */
/**
 * Maps a stored key-size string onto the vocabulary of the Key Size select.
 *
 * CSR records store ECDSA sizes as curve names — KeyAlgorithmPolicy.FormatKeySizeForProfile
 * turns 384 into "P-384" — but the select's options are the bare numbers. Loading a P-384
 * certificate therefore left the select with no matching option, and submit computed
 * parseInt("P-384") = NaN, fell through `|| 256`, and silently reissued the site's TLS
 * certificate with a WEAKER key than the one it replaced.
 */
function normalizeKeySize(stored: string | null | undefined): string {
    if (!stored) return '';
    const curve = stored.match(/^P-(\d+)$/i);
    return curve ? curve[1] : stored;
}

const WebTlsManagement: React.FC = () => {
    const [status, setStatus] = useState<WebTlsCertStatusResponse | null>(null);
    const [loading, setLoading] = useState(true);
    const [loadError, setLoadError] = useState<string | null>(null);

    const loadStatus = async () => {
        setLoading(true);
        setLoadError(null);
        try {
            const data = await apiGet<WebTlsCertStatusResponse>('/api/v1/admin/webtls');
            setStatus(data);
        } catch (err: any) {
            setLoadError(err.message || 'Failed to load Web TLS certificate');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        loadStatus();
    }, []);

    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Web TLS Certificate</h1>
            <p className="text-sm text-gray-600 dark:text-gray-400">
                View and reissue the TLS certificate that protects the ModularCA admin and public
                HTTPS endpoints.
            </p>

            <CurrentCertCard
                status={status}
                loading={loading}
                error={loadError}
                onRefresh={loadStatus}
            />

            <ReissueCard
                status={status}
                loading={loading}
                onReissued={loadStatus}
            />
        </div>
    );
};

export default WebTlsManagement;
