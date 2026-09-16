import React, { useState, useEffect } from 'react';
import { ThemeProvider, useTheme } from '@shared/context/ThemeContext';
import ErrorBoundary from './ErrorBoundary';
import Welcome, { type WelcomeResult } from './pages/Welcome';
import DatabaseConfig, { type DatabaseData } from './pages/DatabaseConfig';
import Organization, { type OrganizationData } from './pages/Organization';
import RootCaConfig, { type RootCaData } from './pages/RootCaConfig';
import AdminAccount, { type AdminAccountData } from './pages/AdminAccount';
import SecurityFeatures, { type SecurityData } from './pages/SecurityFeatures';
import NetworkAdvanced, { type NetworkData } from './pages/NetworkAdvanced';
import WebTlsCertificate, { type WebTlsCertificateData } from './pages/WebTlsCertificate';
import Review from './pages/Review';
import { SourceNotice } from '@shared/components/SourceNotice';

// Helper used by Review.tsx after a successful initialization
// to scrub the cleartext root MySQL password and admin password from React
// state so they don't linger in heap until the tab is closed.
function isLoopbackHostname(host: string): boolean {
    if (!host) return true;
    return host === 'localhost' || host === '127.0.0.1' || host === '[::1]' || host === '::1';
}

// Rough check: IPv4 dotted-quad or any string containing ':' (IPv6). Good enough
// to route publicDomain into IP SAN vs DNS SAN for the Web TLS cert.
function looksLikeIp(s: string): boolean {
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(s)) return true;
    if (s.includes(':')) return true;
    return false;
}

// Build default Web TLS CN + SANs derived from the Network step. DNS publicDomain
// becomes the CN and a DNS SAN; IP publicDomain becomes an IP SAN (CN stays default).
// mtlsAuthSubdomain adds a DNS SAN when mTLS is enabled — short form "mtls" is
// joined with publicDomain, FQDN form is used as-is. Order: meaningful entries
// (publicDomain + mTLS subdomain) come first, then loopback defaults — matches the
// usual cert-printout convention and the Common Name lining up with the first SAN.
function deriveWebTlsDefaults(network: NetworkData): { commonName: string; sans: string[] } {
    const pd = network.publicDomain.trim();
    const sans: string[] = [];
    let commonName = 'modularca.local';

    if (pd) {
        if (looksLikeIp(pd)) {
            sans.push(`IP:${pd}`);
        } else {
            commonName = pd;
            sans.push(`DNS:${pd}`);

            const sub = network.mtlsAuthSubdomain.trim();
            if (network.mtlsEnabled && sub) {
                const fqdn = sub.includes('.') ? sub : `${sub}.${pd}`;
                const mtlsEntry = `DNS:${fqdn}`;
                if (!sans.includes(mtlsEntry)) sans.push(mtlsEntry);
            }
        }
    }

    // Loopback defaults appended last so user-meaningful SANs lead the list.
    if (!sans.includes('DNS:localhost')) sans.push('DNS:localhost');
    if (!sans.includes('IP:127.0.0.1')) sans.push('IP:127.0.0.1');

    return { commonName, sans };
}

// Steps 0 and 1 (Welcome, Database) are not shown in the progress indicator.
// The indicator shows steps 2-8 (Organization through Review) numbered 1-7.
const STEP_WELCOME = 0;
const STEP_DATABASE = 1;
const STEP_ORGANIZATION = 2;
const STEP_ROOT_CA = 3;
const STEP_ADMIN = 4;
const STEP_SECURITY = 5;
const STEP_NETWORK = 6;
const STEP_WEB_TLS = 7;
const STEP_REVIEW = 8;

const indicatorLabels = ['Organization', 'Root CA', 'Admin', 'Security', 'Network', 'Web TLS', 'Review'];
const TOTAL_STEPS = 9; // 0-8

interface WizardData {
    database: DatabaseData;
    organization: OrganizationData;
    rootCa: RootCaData;
    admin: AdminAccountData;
    security: SecurityData;
    network: NetworkData;
    webTlsCertificate: WebTlsCertificateData;
}

const initialData: WizardData = {
    database: {
        rootHost: 'localhost',
        rootPort: 3306,
        rootUsername: 'root',
        rootPassword: '',
        appDatabase: 'modularca-app',
        appUsername: 'modularca_app',
        auditDatabase: 'modularca-audit',
        auditUsername: 'modularca_audit',
        sslMode: 'Required',
        wipeAuditDatabase: false,
    },
    organization: {
        orgName: '',
        orgDescription: '',
    },
    rootCa: {
        commonName: '',
        organizationalUnit: '',
        locality: '',
        state: '',
        country: '',
        keyAlgorithm: 'ECDSA',
        keySize: '384',
        validityYears: 25,
    },
    admin: {
        username: 'admin',
        email: '',
        password: '',
        confirmPassword: '',
    },
    security: {
        enableCrl: true,
        enableOcsp: true,
        // Matches SetupFeatures.Acme, which defaults to false on purpose: a first-run install
        // must not expose anonymous ACME enrollment because the wizard pre-ticked a box.
        enableAcme: false,
        enableEst: false,
        enableScep: false,
        enableCmp: false,
        enableMsae: false,
        maxFailedLoginAttempts: 5,
        lockoutMinutes: 15,
        jwtExpirationMinutes: 30,
        swaggerEnabled: false,
        webAuthnEnabled: true,
        backupEnabled: true,
        backupSchedule: '0 2 * * *',
    },
    network: {
        publicDomain: '',
        // Null means "same as the listener port". The backend contract is PublicPort ?? Port,
        // so sending a concrete value here defeats it: these used to be hardcoded to 8443/8080
        // and never followed the bind ports, so an operator who moved the listeners to 443/80
        // still got :8443 and :8080 baked into every certificate's CDP, AIA and OCSP URLs.
        httpsPublicPort: null,
        httpPublicPort: null,
        httpPort: 8080,
        httpsBindPort: 8443,
        listenAddress: '0.0.0.0',
        mtlsEnabled: false,
        mtlsAuthSubdomain: '',
        backupOutputPath: 'backups',
        backupRetentionCount: 10,
        logLevel: 'Information',
        logRetentionDays: 30,
    },
    webTlsCertificate: {
        commonName: '',
        organization: '',
        organizationalUnit: '',
        locality: '',
        state: '',
        country: 'US',
        sans: [],
        validityDays: 397,
        keyAlgorithm: 'ECDSA',
        keySize: '256',
    },
};

const passwordRules = [
    (pw: string) => pw.length >= 16,
    (pw: string) => /[A-Z]/.test(pw),
    (pw: string) => /[a-z]/.test(pw),
    (pw: string) => /\d/.test(pw),
    (pw: string) => /[^A-Za-z0-9]/.test(pw),
];

const WizardContent: React.FC = () => {
    const { theme, toggleTheme } = useTheme();
    const [step, setStep] = useState(STEP_WELCOME);
    const [data, setData] = useState<WizardData>(initialData);
    const [setupToken, setSetupToken] = useState('');
    // Passed from Welcome → Database step; controls whether Database auto-skips.
    const [dbStatus, setDbStatus] = useState<WelcomeResult>({ needsDbConfig: true, staleDb: false });

    // On step change, scroll back to the top. Per-step focus is handled by each
    // page's first field via the autoFocus prop, which fires reliably when the
    // field mounts — including StrictMode remounts and the Welcome step's
    // async-rendered token field — without depending on effect timing.
    useEffect(() => {
        window.scrollTo(0, 0);
    }, [step]);

    // First time the user lands on the Web TLS step, pre-fill CN + SANs from the
    // Network step so the cert request is ready-to-go. Empty CN is the sentinel
    // for "never touched"; once the user types anything in CN, we stop
    // auto-filling so going back to the Network step doesn't clobber edits.
    useEffect(() => {
        if (step !== STEP_WEB_TLS) return;
        if (data.webTlsCertificate.commonName.trim() !== '') return;
        if (data.webTlsCertificate.sans.length !== 0) return;

        const derived = deriveWebTlsDefaults(data.network);
        let cancelled = false;

        // Merge in GET /setup/defaults. That endpoint exists precisely to add the host's own
        // DNS name and the incoming Host header to the SAN list, so the issued Web TLS
        // certificate matches the address the operator actually used to reach this wizard.
        // Deriving locally from publicDomain alone missed it: reach the wizard at
        // https://ca-host.internal:8443 with publicDomain set to anything else and the cert
        // came out with no SAN for the address in the URL bar. Union, not replace -- the local
        // derivation knows publicDomain and the mTLS subdomain, which the server does not.
        (async () => {
            let serverSans: string[] = [];
            let serverCommonName = '';
            try {
                // GetDefaults runs RejectNonLocalRequest, which validates X-Setup-Token even for
                // loopback callers. Without the header this 403s every time and the merge below
                // silently degrades to the local derivation -- i.e. the whole call is dead.
                const res = await fetch('/api/v1/setup/defaults', {
                    headers: setupToken ? { 'X-Setup-Token': setupToken } : {},
                    signal: AbortSignal.timeout(5000),
                });
                if (res.ok) {
                    const body = await res.json();
                    serverSans = body?.defaultWebTlsCertificate?.sans ?? [];
                    serverCommonName = body?.defaultWebTlsCertificate?.commonName ?? '';
                }
            } catch {
                // Offline or endpoint unavailable: the local derivation alone is still usable.
            }
            if (cancelled) return;

            const seen = new Set(derived.sans.map(x => x.toLowerCase()));
            const sans = [...derived.sans];
            for (const san of serverSans) {
                if (typeof san === 'string' && san && !seen.has(san.toLowerCase())) {
                    seen.add(san.toLowerCase());
                    sans.push(san);
                }
            }

            // The local common name wins when publicDomain gave us a real one; otherwise take
            // whatever the server inferred from the request rather than 'modularca.local'.
            const commonName = derived.commonName !== 'modularca.local'
                ? derived.commonName
                : (serverCommonName || derived.commonName);

            setData(prev => ({
                ...prev,
                webTlsCertificate: { ...prev.webTlsCertificate, commonName, sans },
            }));
        })();

        return () => { cancelled = true; };
    }, [step, setupToken]);

    const canProceed = (): boolean => {
        switch (step) {
            case STEP_WELCOME: return true; // Welcome handles its own gating
            case STEP_DATABASE: return true; // Database handles its own gating
            case STEP_ORGANIZATION: return data.organization.orgName.trim().length > 0;
            case STEP_ROOT_CA: return data.rootCa.commonName.trim().length > 0;
            case STEP_ADMIN: {
                const { username, password, confirmPassword } = data.admin;
                const allRulesMet = passwordRules.every(rule => rule(password));
                return username.trim().length > 0 && allRulesMet && password === confirmPassword;
            }
            case STEP_SECURITY: {
                if (data.security.backupSchedule.trim().length === 0) return false;
                return true;
            }
            case STEP_NETWORK: return data.network.publicDomain.trim().length > 0;
            case STEP_WEB_TLS: return data.webTlsCertificate.commonName.trim().length > 0;
            case STEP_REVIEW: return true;
            default: return false;
        }
    };

    const handleNext = () => {
        if (step < TOTAL_STEPS - 1) setStep(step + 1);
    };

    const handleBack = () => {
        if (step <= STEP_WELCOME) return;
        // When going back from Organization, skip Database if it was auto-skipped
        if (step === STEP_ORGANIZATION && !dbStatus.needsDbConfig && !dbStatus.staleDb) {
            setStep(STEP_WELCOME);
        } else {
            setStep(step - 1);
        }
    };

    const handleWelcomeNext = (result: WelcomeResult) => {
        setDbStatus(result);
        setStep(STEP_DATABASE); // DatabaseConfig will auto-skip if not needed
    };

    const renderStep = () => {
        switch (step) {
            case STEP_WELCOME:
                return (
                    <Welcome
                        onNext={handleWelcomeNext}
                        setupToken={setupToken}
                        onSetupTokenChange={setSetupToken}
                    />
                );
            case STEP_DATABASE:
                return (
                    <DatabaseConfig
                        data={data.database}
                        onChange={db => setData({ ...data, database: db })}
                        setupToken={setupToken}
                        needsDbConfig={dbStatus.needsDbConfig}
                        staleDb={dbStatus.staleDb}
                        onNext={handleNext}
                    />
                );
            case STEP_ORGANIZATION:
                return (
                    <Organization
                        data={data.organization}
                        onChange={org => setData(prev => {
                            // Keep the root CA name in step with the org name only while it
                            // still holds the value we generated from the PREVIOUS org name.
                            // Once the operator edits it, it is theirs. This used to live in a
                            // mount effect inside RootCaConfig, which re-ran on every visit to
                            // that step and matched any name ending in " Root CA" -- so
                            // navigating back and forward silently reverted a hand-edited name.
                            const wasAutoFilled =
                                prev.rootCa.commonName === '' ||
                                prev.rootCa.commonName === `${prev.organization.orgName} Root CA`;
                            const nextName = org.orgName.trim();
                            return {
                                ...prev,
                                organization: org,
                                rootCa: {
                                    ...prev.rootCa,
                                    commonName: wasAutoFilled && nextName
                                        ? `${nextName} Root CA`
                                        : prev.rootCa.commonName,
                                },
                            };
                        })}
                    />
                );
            case STEP_ROOT_CA:
                return (
                    <RootCaConfig
                        data={data.rootCa}
                        orgName={data.organization.orgName}
                        onChange={rootCa => setData({ ...data, rootCa })}
                    />
                );
            case STEP_ADMIN:
                return (
                    <AdminAccount
                        data={data.admin}
                        onChange={admin => setData({ ...data, admin })}
                    />
                );
            case STEP_SECURITY:
                return (
                    <SecurityFeatures
                        data={data.security}
                        onChange={security => setData({ ...data, security })}
                    />
                );
            case STEP_NETWORK:
                return (
                    <NetworkAdvanced
                        data={data.network}
                        onChange={network => setData({ ...data, network })}
                    />
                );
            case STEP_WEB_TLS:
                return (
                    <WebTlsCertificate
                        data={data.webTlsCertificate}
                        onChange={webTlsCertificate => setData({ ...data, webTlsCertificate })}
                        onResetFromNetwork={() => {
                            const derived = deriveWebTlsDefaults(data.network);
                            setData(prev => ({
                                ...prev,
                                webTlsCertificate: {
                                    ...prev.webTlsCertificate,
                                    commonName: derived.commonName,
                                    sans: derived.sans,
                                },
                            }));
                        }}
                    />
                );
            case STEP_REVIEW:
                return (
                    <Review
                        database={data.database}
                        organization={data.organization}
                        rootCa={data.rootCa}
                        admin={data.admin}
                        security={data.security}
                        network={data.network}
                        webTlsCertificate={data.webTlsCertificate}
                        setupToken={setupToken}
                        // After a successful POST to /setup/initialize,
                        // Review calls this to wipe the cleartext root + admin passwords
                        // out of the wizard's React state.
                        onClearSecrets={() => setData(prev => ({
                            ...prev,
                            database: { ...prev.database, rootPassword: '' },
                            admin: { ...prev.admin, password: '', confirmPassword: '' },
                        }))}
                    />
                );
            default:
                return null;
        }
    };

    const isLoopback = typeof window !== 'undefined' && isLoopbackHostname(window.location.hostname);

    // Steps shown in the progress indicator (Organization through Review).
    // Map from indicator index to actual step number for completion/current tracking.
    const indicatorStepOffset = STEP_ORGANIZATION; // indicator[0] = step 2

    // Show step indicator for steps Organization and beyond (not Welcome/Database)
    const showIndicator = step >= STEP_ORGANIZATION;
    // Show Back/Next nav for configuration steps (Organization through Web TLS)
    const showNav = step >= STEP_ORGANIZATION && step < STEP_REVIEW;
    // Show Back-only for Review
    const showReviewNav = step === STEP_REVIEW;

    return (
        <div className="min-h-screen bg-gray-50 dark:bg-gray-900 transition-colors">
            {/* Explicit warning if the wizard is reached over a
                non-loopback hostname. */}
            {!isLoopback && (
                <div className="bg-yellow-100 dark:bg-yellow-900/40 border-b-2 border-yellow-400 dark:border-yellow-700 text-yellow-900 dark:text-yellow-100 px-4 py-3 text-sm text-center">
                    <strong>Warning:</strong> the setup wizard is being accessed from a non-loopback address ({window.location.hostname}). The wizard is intended to run only on the local console of the server. If this is unexpected, close this tab and verify access controls before continuing.
                </div>
            )}
            {/* Theme toggle */}
            <div className="fixed top-4 right-4 z-50">
                <button
                    onClick={toggleTheme}
                    className="p-2 rounded-lg bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white shadow-sm transition-colors"
                    aria-label="Toggle theme"
                >
                    {theme === 'dark' ? (
                        <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <circle cx="12" cy="12" r="5" />
                            <line x1="12" y1="1" x2="12" y2="3" />
                            <line x1="12" y1="21" x2="12" y2="23" />
                            <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" />
                            <line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
                            <line x1="1" y1="12" x2="3" y2="12" />
                            <line x1="21" y1="12" x2="23" y2="12" />
                            <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" />
                            <line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
                        </svg>
                    ) : (
                        <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
                        </svg>
                    )}
                </button>
            </div>

            <div className="max-w-2xl mx-auto px-3 sm:px-4 py-6 sm:py-12">
                {/* Step indicator — shown for Organization through Review */}
                {showIndicator && (
                    <div className="mb-6 sm:mb-10">
                        <div className="flex items-center justify-center overflow-x-auto pb-2">
                            {indicatorLabels.map((label, i) => {
                                const actualStep = i + indicatorStepOffset;
                                const isCompleted = actualStep < step;
                                const isCurrent = actualStep === step;
                                const isFuture = actualStep > step;
                                const showConnector = i > 0;

                                return (
                                    <React.Fragment key={i}>
                                        {showConnector && (
                                            <div
                                                className={`h-0.5 w-8 sm:w-12 ${
                                                    isCompleted ? 'bg-blue-600' : 'bg-gray-300 dark:bg-gray-700'
                                                }`}
                                            />
                                        )}
                                        <div className="flex flex-col items-center">
                                            <div
                                                className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium transition-colors ${
                                                    isCompleted
                                                        ? 'bg-blue-600 text-white'
                                                        : isCurrent
                                                        ? 'bg-blue-600 text-white ring-4 ring-blue-200 dark:ring-blue-900'
                                                        : 'bg-gray-200 dark:bg-gray-700 text-gray-600 dark:text-gray-400'
                                                }`}
                                            >
                                                {isCompleted ? (
                                                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                                                    </svg>
                                                ) : (
                                                    i + 1
                                                )}
                                            </div>
                                            <span
                                                className={`text-xs mt-1.5 hidden sm:block ${
                                                    isFuture
                                                        ? 'text-gray-600 dark:text-gray-500'
                                                        : 'text-gray-700 dark:text-gray-300'
                                                }`}
                                            >
                                                {label}
                                            </span>
                                        </div>
                                    </React.Fragment>
                                );
                            })}
                        </div>
                    </div>
                )}

                {/* Card */}
                <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl shadow-lg p-6 sm:p-8">
                    {renderStep()}
                </div>

                {/* Navigation — Back / Next */}
                {showNav && (
                    <div className="flex justify-between mt-6">
                        <button
                            onClick={handleBack}
                            className="px-6 py-2 bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-200 font-medium rounded-lg transition-colors"
                        >
                            Back
                        </button>
                        <button
                            onClick={handleNext}
                            disabled={!canProceed()}
                            className="px-6 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 dark:disabled:bg-gray-600 text-white font-medium rounded-lg transition-colors disabled:cursor-not-allowed"
                        >
                            Next
                        </button>
                    </div>
                )}

                {/* Back-only nav for Review (it has its own submit button) */}
                {showReviewNav && (
                    <div className="flex justify-start mt-6">
                        <button
                            onClick={handleBack}
                            className="px-6 py-2 bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-200 font-medium rounded-lg transition-colors"
                        >
                            Back
                        </button>
                    </div>
                )}
            </div>

            {/* AGPL section 13 source offer. The wizard is reached over the network on first
                boot, so its operator is a remote user like any other. Placed outside the step
                container so it cannot shift the wizard's own layout. */}
            <div className="mt-6 text-center">
                <SourceNotice version={__APP_VERSION__} commit={__APP_COMMIT__} />
            </div>
        </div>
    );
};

const App: React.FC = () => {
    return (
        <ErrorBoundary>
            <ThemeProvider>
                <WizardContent />
            </ThemeProvider>
        </ErrorBoundary>
    );
};

export default App;
