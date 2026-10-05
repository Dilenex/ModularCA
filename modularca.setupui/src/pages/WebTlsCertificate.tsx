import React from 'react';
import { useAutoFocus } from '../hooks/useAutoFocus';

export type TlsKeyAlgorithm = 'ECDSA' | 'RSA' | 'Ed25519' | 'ML-DSA' | 'SLH-DSA';

export interface WebTlsCertificateData {
    commonName: string;
    organization: string;
    organizationalUnit: string;
    locality: string;
    state: string;
    country: string;
    sans: string[];
    validityDays: number;
    keyAlgorithm: TlsKeyAlgorithm;
    keySize: string;
}

interface WebTlsCertificateProps {
    data: WebTlsCertificateData;
    onChange: (data: WebTlsCertificateData) => void;
    onResetFromNetwork: () => void;
}

/// <summary>
/// Web TLS certificate configuration step for the setup wizard.
/// Collects the subject, SANs, HTTPS port, and validity used for the
/// management UI TLS certificate issued at the end of bootstrap.
/// </summary>
const WebTlsCertificate: React.FC<WebTlsCertificateProps> = ({ data, onChange, onResetFromNetwork }) => {
    const autoFocusRef = useAutoFocus<HTMLInputElement>();
    // Local raw-text state so the textarea preserves blank lines, trailing whitespace, and
    // mid-edit cursor position. Parsing into `data.sans` only happens on blur, when we trim
    // each line and drop empty entries. Re-sync from the parent when `data.sans` changes by an
    // external path (e.g. navigating back to this step), but skip the resync while focused so
    // the user's in-progress edit isn't clobbered by our own commit round-trip.
    const [sansText, setSansText] = React.useState(data.sans.join('\n'));
    const isFocused = React.useRef(false);

    React.useEffect(() => {
        if (!isFocused.current) setSansText(data.sans.join('\n'));
    }, [data.sans]);

    const commitSans = () => {
        isFocused.current = false;
        const sans = sansText
            .split('\n')
            .map(s => s.trim())
            .filter(Boolean);
        setSansText(sans.join('\n'));
        onChange({ ...data, sans });
    };

    return (
        <div className="space-y-6">
            <div>
                <h2 className="text-2xl font-bold text-ink">Web TLS Certificate</h2>
                <p className="text-ink-muted mt-1">
                    Configure the TLS certificate that secures the ModularCA management UI and API.
                </p>
            </div>

            {/* Info box */}
            <div className="bg-info-soft border border-info/40 rounded-lg p-4 space-y-3">
                <p className="text-sm text-info">
                    This certificate is issued at the end of bootstrap using the Web TLS (Internal) request profile,
                    Main Certificate Profile, and your root CA's signing profile. The fields below will be validated
                    against the request profile's rules before the certificate is issued. Organization and
                    Organizational Unit are optional — leave them blank if the cert should not carry organizational
                    identity.
                </p>
                <div className="flex items-center justify-between gap-3 pt-1 border-t border-accent/40">
                    <p className="text-xs text-accent-ink">
                        Common Name and SANs were pre-filled from the Network step. If you've changed the Public Domain or mTLS subdomain since, re-derive them here.
                    </p>
                    <button
                        type="button"
                        onClick={onResetFromNetwork}
                        className="shrink-0 px-3 py-1.5 text-xs font-medium bg-raised border border-accent/40 text-accent-ink rounded hover:bg-accent-soft transition-colors"
                    >
                        Reset from Network settings
                    </button>
                </div>
            </div>

            {/* Subject */}
            <div className="space-y-4">
                <h3 className="text-lg font-semibold text-ink">Subject</h3>

                <div>
                    <label htmlFor="webTlsCommonName" className="block text-sm font-medium text-ink mb-1">
                        Common Name <span className="text-crit">*</span>
                    </label>
                    <input
                        ref={autoFocusRef}
                        id="webTlsCommonName"
                        type="text"
                        required
                        value={data.commonName}
                        onChange={e => onChange({ ...data, commonName: e.target.value })}
                        placeholder="modularca.local"
                        className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-ink placeholder-ink-faint focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent"
                    />
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                        <label htmlFor="webTlsOrganization" className="block text-sm font-medium text-ink mb-1">
                            Organization (O)
                        </label>
                        <input
                            id="webTlsOrganization"
                            type="text"
                            maxLength={64}
                            value={data.organization}
                            onChange={e => onChange({ ...data, organization: e.target.value })}
                            placeholder="(optional)"
                            className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-ink placeholder-ink-faint focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent"
                        />
                    </div>
                    <div>
                        <label htmlFor="webTlsOrganizationalUnit" className="block text-sm font-medium text-ink mb-1">
                            Organizational Unit (OU)
                        </label>
                        <input
                            id="webTlsOrganizationalUnit"
                            type="text"
                            maxLength={64}
                            value={data.organizationalUnit}
                            onChange={e => onChange({ ...data, organizationalUnit: e.target.value })}
                            placeholder="(optional)"
                            className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-ink placeholder-ink-faint focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent"
                        />
                    </div>
                    <div>
                        <label htmlFor="webTlsLocality" className="block text-sm font-medium text-ink mb-1">
                            Locality / City
                        </label>
                        <input
                            id="webTlsLocality"
                            type="text"
                            value={data.locality}
                            onChange={e => onChange({ ...data, locality: e.target.value })}
                            className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-ink placeholder-ink-faint focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent"
                        />
                    </div>
                    <div>
                        <label htmlFor="webTlsState" className="block text-sm font-medium text-ink mb-1">
                            State / Province
                        </label>
                        <input
                            id="webTlsState"
                            type="text"
                            value={data.state}
                            onChange={e => onChange({ ...data, state: e.target.value })}
                            className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-ink placeholder-ink-faint focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent"
                        />
                    </div>
                    <div>
                        <label htmlFor="webTlsCountry" className="block text-sm font-medium text-ink mb-1">
                            Country
                        </label>
                        <input
                            id="webTlsCountry"
                            type="text"
                            maxLength={2}
                            value={data.country}
                            onChange={e => onChange({ ...data, country: e.target.value.toUpperCase() })}
                            placeholder="US"
                            className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-ink placeholder-ink-faint focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent uppercase"
                        />
                        <p className="text-xs text-ink-muted mt-1">2-letter ISO country code.</p>
                    </div>
                </div>
            </div>

            {/* SANs */}
            <div className="border-t border-line pt-6 space-y-4">
                <h3 className="text-lg font-semibold text-ink">Subject Alternative Names</h3>

                <div>
                    <label htmlFor="webTlsSans" className="block text-sm font-medium text-ink mb-1">
                        SANs (one per line)
                    </label>
                    <textarea
                        id="webTlsSans"
                        value={sansText}
                        onChange={e => setSansText(e.target.value)}
                        onFocus={() => { isFocused.current = true; }}
                        onBlur={commitSans}
                        rows={5}
                        placeholder={'DNS:modularca.local\nDNS:localhost\nIP:127.0.0.1'}
                        className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-ink data-mono placeholder-ink-faint focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent resize-none"
                    />
                    <p className="text-xs text-ink-muted mt-1">
                        Prefix DNS names with <code className="font-mono">DNS:</code> and IP addresses with{' '}
                        <code className="font-mono">IP:</code> (for example{' '}
                        <code className="font-mono">DNS:foo.example.com</code> or{' '}
                        <code className="font-mono">IP:10.0.0.1</code>).
                    </p>
                </div>
            </div>

            {/* Key Algorithm */}
            <div className="border-t border-line pt-6 space-y-4">
                <h3 className="text-lg font-semibold text-ink">Key</h3>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                        <label htmlFor="webTlsKeyAlgo" className="block text-sm font-medium text-ink mb-1">
                            Key Algorithm
                        </label>
                        <select
                            id="webTlsKeyAlgo"
                            value={data.keyAlgorithm}
                            onChange={e => {
                                const algo = e.target.value as TlsKeyAlgorithm;
                                const defaultSize = algo === 'ECDSA' ? '256' : algo === 'RSA' ? '2048' : algo === 'ML-DSA' ? '65' : algo === 'SLH-DSA' ? '128f' : '';
                                onChange({ ...data, keyAlgorithm: algo, keySize: defaultSize });
                            }}
                            className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-ink focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent"
                        >
                            <option value="ECDSA">ECDSA (recommended)</option>
                            <option value="RSA">RSA</option>
                            <option value="Ed25519">Ed25519</option>
                            <option value="ML-DSA">ML-DSA (FIPS 204 — Post-Quantum)</option>
                            <option value="SLH-DSA">SLH-DSA (FIPS 205 — Post-Quantum)</option>
                        </select>
                    </div>
                    {data.keyAlgorithm !== 'Ed25519' && (
                    <div>
                        <label htmlFor="webTlsKeySize" className="block text-sm font-medium text-ink mb-1">
                            Key Size
                        </label>
                        <select
                            id="webTlsKeySize"
                            value={data.keySize}
                            onChange={e => onChange({ ...data, keySize: e.target.value })}
                            className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-ink focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent"
                        >
                            {data.keyAlgorithm === 'RSA' ? (
                                <>
                                    <option value="2048">2048</option>
                                    <option value="3072">3072</option>
                                    <option value="4096">4096</option>
                                    <option value="7680">7680 (high compute)</option>
                                    <option value="8192">8192 (high compute)</option>
                                </>
                            ) : data.keyAlgorithm === 'ML-DSA' ? (
                                <>
                                    <option value="44">ML-DSA-44</option>
                                    <option value="65">ML-DSA-65</option>
                                    <option value="87">ML-DSA-87</option>
                                </>
                            ) : data.keyAlgorithm === 'SLH-DSA' ? (
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
                        {data.keyAlgorithm === 'RSA' && (data.keySize === '7680' || data.keySize === '8192') && (
                            <p className="text-xs text-warn mt-1">
                                ⚠ High-compute RSA — key generation may take 30+ seconds.
                            </p>
                        )}
                    </div>
                    )}
                </div>
            </div>

            {/* Validity */}
            <div className="border-t border-line pt-6 space-y-4">
                <h3 className="text-lg font-semibold text-ink">Validity</h3>

                <div>
                    <label htmlFor="webTlsValidityDays" className="block text-sm font-medium text-ink mb-1">
                        Validity (days)
                    </label>
                    <input
                        id="webTlsValidityDays"
                        type="text"
                        inputMode="numeric"
                        value={data.validityDays}
                        onChange={e => { const v = e.target.value.replace(/\D/g, ''); onChange({ ...data, validityDays: v === '' ? ('' as any) : parseInt(v) }); }}
                        onBlur={() => { if (!data.validityDays) onChange({ ...data, validityDays: 397 }); }}
                        className="w-full px-3 py-2 bg-raised border border-line-strong rounded text-ink focus:outline-none focus:ring-2 focus:ring-accent focus:border-transparent"
                    />
                    <p className="text-xs text-ink-muted mt-1">
                        CA/Browser Forum maximum is 397 days for publicly-trusted TLS server certificates.
                    </p>
                </div>
            </div>
        </div>
    );
};

export default WebTlsCertificate;
