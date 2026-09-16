import React from 'react';

export interface FeaturesData {
    enableCrl: boolean;
    enableOcsp: boolean;
    enableAcme: boolean;
    enableEst: boolean;
    enableScep: boolean;
    enableCmp: boolean;
    enableMsae: boolean;
    apiCertSans: string;
    apiCertValidityYears: number;
    publicDomain: string;
    httpPort: number;
}

interface FeaturesProps {
    data: FeaturesData;
    onChange: (data: FeaturesData) => void;
}

interface FeatureToggle {
    key: keyof Pick<FeaturesData, 'enableCrl' | 'enableOcsp' | 'enableAcme' | 'enableEst' | 'enableScep' | 'enableCmp' | 'enableMsae'>;
    label: string;
    acronym: string;
    description: string;
}

const featureToggles: FeatureToggle[] = [
    { key: 'enableCrl', label: 'CRL', acronym: 'CRL', description: 'Certificate Revocation Lists - Publish lists of revoked certificates for relying parties' },
    { key: 'enableOcsp', label: 'OCSP', acronym: 'OCSP', description: 'Online Certificate Status Protocol - Real-time certificate revocation checking' },
    { key: 'enableAcme', label: 'ACME', acronym: 'ACME', description: "Automated Certificate Management Environment - Let's Encrypt-style automation" },
    { key: 'enableEst', label: 'EST', acronym: 'EST', description: 'Enrollment over Secure Transport - Modern certificate enrollment protocol (RFC 7030)' },
    { key: 'enableScep', label: 'SCEP', acronym: 'SCEP', description: 'Simple Certificate Enrollment Protocol - Legacy device enrollment support' },
    { key: 'enableCmp', label: 'CMP', acronym: 'CMP', description: 'Certificate Management Protocol - Full lifecycle certificate management (RFC 4210)' },
    { key: 'enableMsae', label: 'MSAE', acronym: 'MSAE', description: 'Windows autoenrollment - Certificate Enrollment Web Service (MS-WSTEP) for Group Policy and certreq clients' },
];

const Features: React.FC<FeaturesProps> = ({ data, onChange }) => {
    return (
        <div className="space-y-6">
            <div>
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Features</h2>
                <p className="text-gray-600 dark:text-gray-400 mt-1">
                    Enable the protocols and services your CA should support. These can be changed later.
                </p>
            </div>

            {/* Feature toggles */}
            <div className="space-y-3">
                {featureToggles.map(feature => (
                    <label
                        key={feature.key}
                        className="flex items-start gap-3 p-3 bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
                    >
                        <div className="pt-0.5">
                            <input
                                type="checkbox"
                                checked={data[feature.key] as boolean}
                                onChange={e => onChange({ ...data, [feature.key]: e.target.checked })}
                                className="w-4 h-4 text-blue-600 bg-white dark:bg-gray-900 border-gray-300 dark:border-gray-600 rounded focus:ring-blue-500"
                            />
                        </div>
                        <div className="flex-1 min-w-0">
                            <span className="text-sm font-medium text-gray-900 dark:text-white">{feature.acronym}</span>
                            <p className="text-xs text-gray-600 dark:text-gray-400 mt-0.5">{feature.description}</p>
                        </div>
                    </label>
                ))}
            </div>

            {/* API Certificate */}
            <div className="border-t border-gray-200 dark:border-gray-700 pt-6 space-y-4">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">API Certificate</h3>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                    Configure the TLS certificate that will be issued for the ModularCA API server.
                </p>

                <div>
                    <label htmlFor="sans" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Subject Alternative Names (one per line)
                    </label>
                    <textarea
                        id="sans"
                        value={data.apiCertSans}
                        onChange={e => onChange({ ...data, apiCertSans: e.target.value })}
                        rows={4}
                        className="w-full px-3 py-2 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-gray-900 dark:text-white font-mono text-sm placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-none"
                    />
                </div>

                <div>
                    <label htmlFor="apiValidity" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Validity Period (years)
                    </label>
                    <input
                        id="apiValidity"
                        type="text"
                        inputMode="numeric"
                        value={data.apiCertValidityYears}
                        onChange={e => { const v = e.target.value.replace(/\D/g, ''); onChange({ ...data, apiCertValidityYears: v === '' ? ('' as any) : parseInt(v) }); }}
                        onBlur={() => { if (!data.apiCertValidityYears) onChange({ ...data, apiCertValidityYears: 2 }); }}
                        className="w-32 px-3 py-2 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                </div>
            </div>

            {/* Network / Public Access */}
            <div className="border-t border-gray-200 dark:border-gray-700 pt-6 space-y-4">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Network</h3>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                    CRL, OCSP, and AIA endpoints must be reachable via plain HTTP (not HTTPS) per RFC 5280.
                    TLS clients cannot use HTTPS to validate the certificate they're checking.
                </p>

                <div>
                    <label htmlFor="publicDomain" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Public Base URL
                    </label>
                    <input
                        id="publicDomain"
                        type="text"
                        value={data.publicDomain}
                        onChange={e => onChange({ ...data, publicDomain: e.target.value })}
                        placeholder="http://ca.example.com"
                        className="w-full px-3 py-2 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                    <p className="text-xs text-gray-600 mt-1">
                        Embedded in certificates for AIA/CDP URLs. Must be HTTP, not HTTPS. Leave blank to auto-detect from SANs.
                    </p>
                </div>

                <div>
                    <label htmlFor="httpPort" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        HTTP Port (plain, for CRL/OCSP/AIA)
                    </label>
                    <input
                        id="httpPort"
                        type="text"
                        inputMode="numeric"
                        value={data.httpPort}
                        onChange={e => { const v = e.target.value.replace(/\D/g, ''); onChange({ ...data, httpPort: v === '' ? ('' as any) : parseInt(v) }); }}
                        onBlur={() => { if (!data.httpPort && data.httpPort !== 0) onChange({ ...data, httpPort: 80 }); }}
                        className="w-32 px-3 py-2 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                    <p className="text-xs text-gray-600 mt-1">
                        Set to 0 to disable. Default: 80.
                    </p>
                </div>
            </div>
        </div>
    );
};

export default Features;
