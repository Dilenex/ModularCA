import React from 'react';

export interface SecurityData {
    enableCrl: boolean;
    enableOcsp: boolean;
    enableAcme: boolean;
    enableEst: boolean;
    enableScep: boolean;
    enableCmp: boolean;
    enableMsae: boolean;
    maxFailedLoginAttempts: number;
    lockoutMinutes: number;
    jwtExpirationMinutes: number;
    swaggerEnabled: boolean;
    webAuthnEnabled: boolean;
    backupEnabled: boolean;
    backupSchedule: string;
}

interface SecurityFeaturesProps {
    data: SecurityData;
    onChange: (data: SecurityData) => void;
}

interface FeatureToggle {
    key: keyof Pick<SecurityData, 'enableCrl' | 'enableOcsp' | 'enableAcme' | 'enableEst' | 'enableScep' | 'enableCmp' | 'enableMsae'>;
    acronym: string;
    description: string;
}

const featureToggles: FeatureToggle[] = [
    { key: 'enableCrl', acronym: 'CRL', description: 'Certificate Revocation Lists - Publish lists of revoked certificates for relying parties' },
    { key: 'enableOcsp', acronym: 'OCSP', description: 'Online Certificate Status Protocol - Real-time certificate revocation checking' },
    { key: 'enableAcme', acronym: 'ACME', description: "Automated Certificate Management Environment - Let's Encrypt-style automation" },
    { key: 'enableEst', acronym: 'EST', description: 'Enrollment over Secure Transport - Modern certificate enrollment protocol (RFC 7030)' },
    { key: 'enableScep', acronym: 'SCEP', description: 'Simple Certificate Enrollment Protocol - Legacy device enrollment support' },
    { key: 'enableCmp', acronym: 'CMP', description: 'Certificate Management Protocol - Full lifecycle certificate management (RFC 4210)' },
    { key: 'enableMsae', acronym: 'MSAE', description: 'Windows autoenrollment - Certificate Enrollment Web Service (MS-WSTEP) for Group Policy and certreq clients' },
];

/// <summary>
/// Security and features configuration step for the setup wizard.
/// Includes protocol toggles, backup settings, WebAuthn configuration, and security parameters.
/// </summary>
const SecurityFeatures: React.FC<SecurityFeaturesProps> = ({ data, onChange }) => {
    return (
        <div className="space-y-6">
            <div>
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Security &amp; Features</h2>
                <p className="text-gray-600 dark:text-gray-400 mt-1">
                    Enable protocols, configure backup and authentication settings.
                </p>
            </div>

            {/* Protocol Toggles */}
            <div className="space-y-3">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Protocols</h3>
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

            {/* Backup */}
            <div className="border-t border-gray-200 dark:border-gray-700 pt-6 space-y-4">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Backup</h3>

                <label className="flex items-center gap-3">
                    <input
                        type="checkbox"
                        checked={data.backupEnabled}
                        onChange={e => onChange({ ...data, backupEnabled: e.target.checked })}
                        className="w-4 h-4 text-blue-600 bg-white dark:bg-gray-900 border-gray-300 dark:border-gray-600 rounded focus:ring-blue-500"
                    />
                    <span className="text-sm font-medium text-gray-900 dark:text-white">Enable automatic backups</span>
                </label>

                <div>
                    <label htmlFor="backupSchedule" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Backup Schedule (cron expression)
                    </label>
                    <input
                        id="backupSchedule"
                        type="text"
                        value={data.backupSchedule}
                        onChange={e => onChange({ ...data, backupSchedule: e.target.value })}
                        placeholder="0 2 * * *"
                        className="w-full px-3 py-2 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-gray-900 dark:text-white font-mono text-sm placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                    <p className="text-xs text-gray-600 mt-1">Default: daily at 2:00 AM (0 2 * * *)</p>
                </div>
            </div>

            {/* WebAuthn */}
            <div className="border-t border-gray-200 dark:border-gray-700 pt-6 space-y-4">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">WebAuthn / Passkeys</h3>

                <label className="flex items-center gap-3">
                    <input
                        type="checkbox"
                        checked={data.webAuthnEnabled}
                        onChange={e => onChange({ ...data, webAuthnEnabled: e.target.checked })}
                        className="w-4 h-4 text-blue-600 bg-white dark:bg-gray-900 border-gray-300 dark:border-gray-600 rounded focus:ring-blue-500"
                    />
                    <span className="text-sm font-medium text-gray-900 dark:text-white">Enable WebAuthn / Passkey authentication</span>
                </label>
            </div>

            {/* Security Settings */}
            <div className="border-t border-gray-200 dark:border-gray-700 pt-6 space-y-4">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Security Settings</h3>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                        <label htmlFor="maxFailedLogin" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                            Max Failed Login Attempts
                        </label>
                        <input
                            id="maxFailedLogin"
                            type="text"
                            inputMode="numeric"
                            value={data.maxFailedLoginAttempts}
                            onChange={e => { const v = e.target.value.replace(/\D/g, ''); onChange({ ...data, maxFailedLoginAttempts: v === '' ? ('' as any) : parseInt(v) }); }}
                            onBlur={() => { if (!data.maxFailedLoginAttempts) onChange({ ...data, maxFailedLoginAttempts: 5 }); }}
                            className="w-full px-3 py-2 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                    </div>
                    <div>
                        <label htmlFor="lockoutMinutes" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                            Lockout Duration (minutes)
                        </label>
                        <input
                            id="lockoutMinutes"
                            type="text"
                            inputMode="numeric"
                            value={data.lockoutMinutes}
                            onChange={e => { const v = e.target.value.replace(/\D/g, ''); onChange({ ...data, lockoutMinutes: v === '' ? ('' as any) : parseInt(v) }); }}
                            onBlur={() => { if (!data.lockoutMinutes) onChange({ ...data, lockoutMinutes: 15 }); }}
                            className="w-full px-3 py-2 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                    </div>
                    <div>
                        <label htmlFor="jwtExpiration" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                            JWT Lifetime (minutes)
                        </label>
                        <input
                            id="jwtExpiration"
                            type="text"
                            inputMode="numeric"
                            value={data.jwtExpirationMinutes}
                            onChange={e => { const v = e.target.value.replace(/\D/g, ''); onChange({ ...data, jwtExpirationMinutes: v === '' ? ('' as any) : parseInt(v) }); }}
                            onBlur={() => { if (!data.jwtExpirationMinutes) onChange({ ...data, jwtExpirationMinutes: 30 }); }}
                            className="w-full px-3 py-2 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                    </div>
                </div>

                <label className="flex items-center gap-3">
                    <input
                        type="checkbox"
                        checked={data.swaggerEnabled}
                        onChange={e => onChange({ ...data, swaggerEnabled: e.target.checked })}
                        className="w-4 h-4 text-blue-600 bg-white dark:bg-gray-900 border-gray-300 dark:border-gray-600 rounded focus:ring-blue-500"
                    />
                    <span className="text-sm font-medium text-gray-900 dark:text-white">Enable Swagger / OpenAPI UI</span>
                </label>
            </div>
        </div>
    );
};

export default SecurityFeatures;
