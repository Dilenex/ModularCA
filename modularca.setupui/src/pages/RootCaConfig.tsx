import React from 'react';
import { useAutoFocus } from '../hooks/useAutoFocus';

export type KeyAlgorithm = 'ECDSA' | 'RSA' | 'Ed25519' | 'ML-DSA' | 'SLH-DSA';

export interface RootCaData {
    commonName: string;
    organizationalUnit: string;
    locality: string;
    state: string;
    country: string;
    keyAlgorithm: KeyAlgorithm;
    keySize: string;
    validityYears: number;
}

interface RootCaConfigProps {
    data: RootCaData;
    orgName: string;
    onChange: (data: RootCaData) => void;
}

const keySizeOptions: Record<KeyAlgorithm, string[]> = {
    ECDSA: ['256', '384', '521'],
    RSA: ['2048', '3072', '4096', '7680', '8192'],
    Ed25519: [],
    'ML-DSA': ['44', '65', '87'],
    'SLH-DSA': ['128f', '128s', '192f', '192s', '256f', '256s'],
};

const RootCaConfig: React.FC<RootCaConfigProps> = ({ data, orgName, onChange }) => {
    const autoFocusRef = useAutoFocus<HTMLInputElement>();
    // The org-name -> common-name auto-fill lives in App, where the wizard state lives. It ran
    // here as a mount effect, and this component unmounts whenever the step changes: revisiting
    // the step re-ran it, and its `endsWith(' Root CA')` guard matched almost any real CA name,
    // so a hand-edited common name was silently reverted just by navigating back and forward.

    const handleAlgorithmChange = (alg: KeyAlgorithm) => {
        const sizes = keySizeOptions[alg];
        const defaultSize = alg === 'ECDSA' ? '384' : alg === 'RSA' ? '4096' : alg === 'ML-DSA' ? '65' : alg === 'SLH-DSA' ? '128f' : '';
        onChange({ ...data, keyAlgorithm: alg, keySize: sizes.length > 0 ? defaultSize : '' });
    };

    // Build subject DN preview
    const dnParts: string[] = [];
    if (data.commonName.trim()) dnParts.push(`CN=${data.commonName.trim()}`);
    if (orgName.trim()) dnParts.push(`O=${orgName.trim()}`);
    if (data.organizationalUnit.trim()) dnParts.push(`OU=${data.organizationalUnit.trim()}`);
    if (data.locality.trim()) dnParts.push(`L=${data.locality.trim()}`);
    if (data.state.trim()) dnParts.push(`ST=${data.state.trim()}`);
    if (data.country.trim()) dnParts.push(`C=${data.country.trim()}`);
    const subjectDn = dnParts.join(', ');

    return (
        <div className="space-y-6">
            <div>
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Root CA Configuration</h2>
                <p className="text-gray-600 dark:text-gray-400 mt-1">
                    Configure the root certificate authority that will anchor your PKI trust chain.
                </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="md:col-span-2">
                    <label htmlFor="cn" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Common Name <span className="text-red-500">*</span>
                    </label>
                    <input
                        ref={autoFocusRef}
                        id="cn"
                        type="text"
                        required
                        value={data.commonName}
                        onChange={e => onChange({ ...data, commonName: e.target.value })}
                        placeholder="My Root CA"
                        className="w-full px-3 py-2 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                </div>

                <div className="md:col-span-2">
                    <label htmlFor="ou" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Organizational Unit
                    </label>
                    <input
                        id="ou"
                        type="text"
                        value={data.organizationalUnit}
                        onChange={e => onChange({ ...data, organizationalUnit: e.target.value })}
                        placeholder="IT Security"
                        className="w-full px-3 py-2 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                </div>

                <div>
                    <label htmlFor="locality" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Location
                    </label>
                    <input
                        id="locality"
                        type="text"
                        value={data.locality}
                        onChange={e => onChange({ ...data, locality: e.target.value })}
                        placeholder="San Francisco"
                        className="w-full px-3 py-2 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                </div>

                <div>
                    <label htmlFor="state" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        State
                    </label>
                    <input
                        id="state"
                        type="text"
                        value={data.state}
                        onChange={e => onChange({ ...data, state: e.target.value })}
                        placeholder="California"
                        className="w-full px-3 py-2 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                </div>

                <div>
                    <label htmlFor="country" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Country
                    </label>
                    <input
                        id="country"
                        type="text"
                        value={data.country}
                        onChange={e => onChange({ ...data, country: e.target.value.toUpperCase().slice(0, 2) })}
                        placeholder="US"
                        maxLength={2}
                        className="w-full px-3 py-2 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                </div>
            </div>

            {/* Key configuration */}
            <div className="border-t border-gray-200 dark:border-gray-700 pt-6 space-y-4">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Key Configuration</h3>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                        <label htmlFor="keyAlg" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                            Key Algorithm
                        </label>
                        <select
                            id="keyAlg"
                            value={data.keyAlgorithm}
                            onChange={e => handleAlgorithmChange(e.target.value as KeyAlgorithm)}
                            className="w-full px-3 py-2 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        >
                            <option value="ECDSA">ECDSA (recommended)</option>
                            <option value="RSA">RSA</option>
                            <option value="Ed25519">Ed25519 (not trusted by browsers as a root)</option>
                            <option value="ML-DSA">ML-DSA (FIPS 204 — Post-Quantum, no browser support)</option>
                            <option value="SLH-DSA">SLH-DSA (FIPS 205 — Post-Quantum, no browser support)</option>
                        </select>
                        {(data.keyAlgorithm === 'Ed25519' || data.keyAlgorithm === 'ML-DSA' || data.keyAlgorithm === 'SLH-DSA') && (
                            <p className="text-xs text-amber-600 dark:text-amber-400 mt-2">
                                ⚠ Firefox, Chrome, and Safari reject this algorithm as a root trust anchor ({data.keyAlgorithm === 'Ed25519' ? 'SEC_ERROR_UNSUPPORTED_KEYALG on import' : 'no browser has shipped support yet'}). Pick <strong>ECDSA</strong> or <strong>RSA</strong> if end users will install this Root CA into their browser trust store.
                            </p>
                        )}
                    </div>

                    {keySizeOptions[data.keyAlgorithm].length > 0 && (
                        <div>
                            <label htmlFor="keySize" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                                Key Size
                            </label>
                            <select
                                id="keySize"
                                value={data.keySize}
                                onChange={e => onChange({ ...data, keySize: e.target.value })}
                                className="w-full px-3 py-2 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                            >
                                {keySizeOptions[data.keyAlgorithm].map(size => (
                                    <option key={size} value={size}>
                                        {(size === '7680' || size === '8192') ? `${size} (high compute)` : size}
                                    </option>
                                ))}
                            </select>
                            {(data.keySize === '7680' || data.keySize === '8192') && (
                                <p className="text-xs text-amber-600 dark:text-amber-400 mt-1">
                                    ⚠ High-compute RSA — key generation may take 30+ seconds.
                                </p>
                            )}
                        </div>
                    )}

                    <div>
                        <label htmlFor="validity" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                            Validity Period (years)
                        </label>
                        <input
                            id="validity"
                            type="text"
                            inputMode="numeric"
                            value={data.validityYears}
                            onChange={e => { const v = e.target.value.replace(/\D/g, ''); onChange({ ...data, validityYears: v === '' ? ('' as any) : parseInt(v) }); }}
                            onBlur={() => { if (!data.validityYears) onChange({ ...data, validityYears: 25 }); }}
                            className="w-full px-3 py-2 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                    </div>
                </div>
            </div>

            {/* Subject DN preview */}
            {subjectDn && (
                <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
                    <p className="text-xs font-medium text-blue-700 dark:text-blue-400 uppercase tracking-wide mb-1">Subject DN Preview</p>
                    <p className="text-sm text-blue-900 dark:text-blue-200 font-mono break-all">{subjectDn}</p>
                </div>
            )}
        </div>
    );
};

export default RootCaConfig;
