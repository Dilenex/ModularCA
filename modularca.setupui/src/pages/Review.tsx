import React, { useState } from 'react';
import type { OrganizationData } from './Organization';
import type { RootCaData } from './RootCaConfig';
import type { AdminAccountData } from './AdminAccount';
import type { SecurityData } from './SecurityFeatures';
import type { NetworkData } from './NetworkAdvanced';
import type { WebTlsCertificateData } from './WebTlsCertificate';

interface DatabaseConfig {
    rootHost: string;
    rootPort: number;
    rootUsername: string;
    rootPassword: string;
    appDatabase: string;
    appUsername: string;
    auditDatabase: string;
    auditUsername: string;
    sslMode: string;
    wipeAuditDatabase: boolean;
}

interface ReviewProps {
    database: DatabaseConfig;
    organization: OrganizationData;
    rootCa: RootCaData;
    admin: AdminAccountData;
    security: SecurityData;
    network: NetworkData;
    webTlsCertificate: WebTlsCertificateData;
    /** KC-11: one-time setup token to include in the X-Setup-Token header. */
    setupToken?: string;
    /**
     * Invoked once initialize succeeds so the parent wizard can
     * scrub the cleartext root MySQL password and admin password from React state.
     */
    onClearSecrets?: () => void;
}

const Review: React.FC<ReviewProps> = ({ database, organization, rootCa, admin, security, network, webTlsCertificate, setupToken, onClearSecrets }) => {
    const [submitting, setSubmitting] = useState(false);
    const [success, setSuccess] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const enabledFeatures = [
        security.enableCrl && 'CRL',
        security.enableOcsp && 'OCSP',
        security.enableAcme && 'ACME',
        security.enableEst && 'EST',
        security.enableScep && 'SCEP',
        security.enableCmp && 'CMP',
    ].filter(Boolean);

    const handleInitialize = async () => {
        setSubmitting(true);
        setError(null);

        const payload = {
            organization: {
                name: organization.orgName.trim(),
                description: organization.orgDescription.trim() || undefined,
            },
            rootCa: {
                commonName: rootCa.commonName.trim(),
                organization: organization.orgName.trim(),
                organizationalUnit: rootCa.organizationalUnit.trim() || undefined,
                locality: rootCa.locality.trim() || undefined,
                state: rootCa.state.trim() || undefined,
                country: rootCa.country.trim() || undefined,
                keyAlgorithm: rootCa.keyAlgorithm,
                // #38/#39: send the raw string so SLH-DSA variants (128f/128s/etc) and
                // Ed25519 (no parameter → null) round-trip faithfully. The backend DTO
                // is string? and parses this via SetupKeySizeParser.
                keySize: rootCa.keySize || null,
                validityYears: rootCa.validityYears,
            },
            admin: {
                username: admin.username.trim(),
                email: admin.email.trim() || undefined,
                password: admin.password,
            },
            features: {
                enableCrl: security.enableCrl,
                enableOcsp: security.enableOcsp,
                enableAcme: security.enableAcme,
                enableEst: security.enableEst,
                enableScep: security.enableScep,
                enableCmp: security.enableCmp,
            },
            security: {
                maxFailedLoginAttempts: security.maxFailedLoginAttempts,
                lockoutMinutes: security.lockoutMinutes,
                jwtExpirationMinutes: security.jwtExpirationMinutes,
                swaggerEnabled: security.swaggerEnabled,
                webAuthnEnabled: security.webAuthnEnabled,
                backupEnabled: security.backupEnabled,
                backupSchedule: security.backupSchedule.trim(),
            },
            network: {
                // Public-host fields (publicDomain, httpPort, httpsPort, *PublicPort) are
                // canonical here. SetupWebTlsCertificate carries cert-intrinsic fields only
                // (subject, SANs, key, validity) — bootstrap reads transport from request.Network.
                listenAddress: network.listenAddress.trim(),
                mtlsEnabled: network.mtlsEnabled,
                mtlsAuthSubdomain: network.mtlsAuthSubdomain.trim() || undefined,
                backupOutputPath: network.backupOutputPath.trim(),
                backupRetentionCount: network.backupRetentionCount,
                logLevel: network.logLevel,
                logRetentionDays: network.logRetentionDays,
                publicDomain: network.publicDomain.trim() || null,
                httpPort: network.httpPort,
                httpsPort: network.httpsBindPort,
                httpPublicPort: network.httpPublicPort,
                httpsPublicPort: network.httpsPublicPort,
            },
            webTlsCertificate: {
                commonName: webTlsCertificate.commonName.trim(),
                // O and OU are operator-supplied via the Web TLS step. Empty strings flow
                // through; the backend's "Web TLS (Internal)" request profile treats them as
                // Optional and skips emitting empty RDNs into the issued cert. This replaces
                // the previous DTO-default workaround where omission silently inserted
                // "ModularCA" / "IT" into every operator's cert.
                organization: webTlsCertificate.organization.trim(),
                organizationalUnit: webTlsCertificate.organizationalUnit.trim(),
                locality: webTlsCertificate.locality.trim(),
                state: webTlsCertificate.state.trim(),
                country: webTlsCertificate.country.trim().toUpperCase(),
                sans: webTlsCertificate.sans.map(s => s.trim()).filter(Boolean),
                validityDays: webTlsCertificate.validityDays,
                keyAlgorithm: webTlsCertificate.keyAlgorithm,
                keySize: parseInt(webTlsCertificate.keySize) || 256,
            },
            database: {
                rootHost: database.rootHost,
                rootPort: database.rootPort,
                rootUsername: database.rootUsername,
                rootPassword: database.rootPassword,
                appDatabase: database.appDatabase,
                appUsername: database.appUsername,
                auditDatabase: database.auditDatabase,
                auditUsername: database.auditUsername,
                sslMode: database.sslMode,
                wipeAuditDatabase: database.wipeAuditDatabase,
            },
        };

        try {
            const csrfToken = document.cookie.match(/(?:^|;\s*)CSRF-TOKEN=([^;]*)/)?.[1] || '';
            const headers: Record<string, string> = {
                'Content-Type': 'application/json',
                'X-CSRF-Token': decodeURIComponent(csrfToken),
            };
            // KC-11: include the one-time setup token
            if (setupToken) {
                headers['X-Setup-Token'] = setupToken;
            }
            const res = await fetch('/api/v1/setup/initialize', {
                method: 'POST',
                headers,
                body: JSON.stringify(payload),
            });

            if (!res.ok) {
                const body = await res.text();
                let message: string;
                try {
                    const parsed = JSON.parse(body);
                    message = parsed.message || parsed.error || parsed.title || body;
                } catch {
                    message = body || `HTTP ${res.status}`;
                }
                throw new Error(message);
            }

            setSuccess(true);
            // Scrub the cleartext root + admin passwords from
            // wizard state immediately so they don't linger in heap until the
            // tab is closed.
            onClearSecrets?.();
        } catch (err) {
            setError(err instanceof Error ? err.message : 'An unexpected error occurred');
        } finally {
            setSubmitting(false);
        }
    };

    if (success) {
        return (
            <div className="space-y-6 text-center">
                <div className="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-xl p-8">
                    <div className="flex justify-center mb-4">
                        <div className="w-16 h-16 bg-green-100 dark:bg-green-900/40 rounded-full flex items-center justify-center">
                            <svg className="w-8 h-8 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                            </svg>
                        </div>
                    </div>
                    <h2 className="text-2xl font-bold text-green-800 dark:text-green-200 mb-2">Setup Complete!</h2>
                    <p className="text-green-700 dark:text-green-300 mb-1">ModularCA has been initialized successfully.</p>
                    <p className="text-sm text-green-600 dark:text-green-400">
                        Admin username: <span className="font-mono font-semibold">{admin.username}</span>
                    </p>
                </div>
                <div className="bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg p-4">
                    <p className="text-amber-800 dark:text-amber-300 font-medium">The server is restarting out of setup mode.</p>
                    <p className="text-sm text-amber-700 dark:text-amber-400 mt-1">
                        This may take a few moments. If the login page does not load, wait a few seconds and try again.
                        If the server does not restart automatically, you may need to restart it manually.
                    </p>
                </div>
                <a
                    href="/admin/login"
                    className="inline-block px-8 py-3 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-lg transition-colors"
                >
                    Go to Login
                </a>
            </div>
        );
    }

    return (
        <div className="space-y-6">
            <div>
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Review Configuration</h2>
                <p className="text-gray-600 dark:text-gray-400 mt-1">
                    Review your settings before initializing ModularCA.
                </p>
            </div>

            {/* Organization */}
            <SummaryCard title="Organization">
                <SummaryRow label="Name" value={organization.orgName} />
                {organization.orgDescription && <SummaryRow label="Description" value={organization.orgDescription} />}
            </SummaryCard>

            {/* Root CA */}
            <SummaryCard title="Root CA">
                <SummaryRow label="Common Name" value={rootCa.commonName} />
                <SummaryRow label="Organization" value={organization.orgName} />
                {rootCa.organizationalUnit && <SummaryRow label="Organizational Unit" value={rootCa.organizationalUnit} />}
                {rootCa.locality && <SummaryRow label="Location" value={rootCa.locality} />}
                {rootCa.state && <SummaryRow label="State" value={rootCa.state} />}
                {rootCa.country && <SummaryRow label="Country" value={rootCa.country} />}
                <SummaryRow label="Key Algorithm" value={rootCa.keyAlgorithm} />
                {rootCa.keySize && <SummaryRow label="Key Size" value={rootCa.keySize} />}
                <SummaryRow label="Validity" value={`${rootCa.validityYears} years`} />
            </SummaryCard>

            {/* Admin Account */}
            <SummaryCard title="Admin Account">
                <SummaryRow label="Username" value={admin.username} />
                {admin.email && <SummaryRow label="Email" value={admin.email} />}
                <SummaryRow label="Password" value={"*".repeat(12)} />
            </SummaryCard>

            {/* Security & Features */}
            <SummaryCard title="Security &amp; Features">
                <SummaryRow label="Enabled Protocols" value={enabledFeatures.length > 0 ? enabledFeatures.join(', ') : 'None'} />
                <SummaryRow label="Max Failed Logins" value={String(security.maxFailedLoginAttempts)} />
                <SummaryRow label="Lockout Duration" value={`${security.lockoutMinutes} min`} />
                <SummaryRow label="JWT Lifetime" value={`${security.jwtExpirationMinutes} min`} />
                <SummaryRow label="Swagger UI" value={security.swaggerEnabled ? 'Enabled' : 'Disabled'} />
                <SummaryRow label="WebAuthn" value={security.webAuthnEnabled ? 'Enabled' : 'Disabled'} />
                <SummaryRow label="Backup" value={security.backupEnabled ? 'Enabled' : 'Disabled'} />
                <SummaryRow label="Backup Schedule" value={security.backupSchedule} />
            </SummaryCard>

            {/* Network */}
            <SummaryCard title="Network">
                <SummaryRow label="Public Domain" value={network.publicDomain || '(auto-detect)'} />
                <SummaryRow label="HTTPS Bind Port" value={String(network.httpsBindPort)} />
                <SummaryRow label="HTTP Port" value={String(network.httpPort)} />
                <SummaryRow label="Listen Address" value={network.listenAddress} />
                <SummaryRow label="mTLS Login" value={network.mtlsEnabled ? 'Enabled' : 'Disabled'} />
                {network.mtlsEnabled && network.mtlsAuthSubdomain && <SummaryRow label="mTLS Subdomain" value={network.mtlsAuthSubdomain} />}
                <SummaryRow label="Backup Path" value={network.backupOutputPath} />
                <SummaryRow label="Backup Retention" value={`${network.backupRetentionCount} copies`} />
                <SummaryRow label="Log Level" value={network.logLevel} />
                <SummaryRow label="Log Retention" value={`${network.logRetentionDays} days`} />
            </SummaryCard>

            {/* Web TLS Certificate */}
            <SummaryCard title="Web TLS Certificate">
                <SummaryRow label="Common Name" value={webTlsCertificate.commonName} />
                {webTlsCertificate.organization && <SummaryRow label="Organization" value={webTlsCertificate.organization} />}
                {webTlsCertificate.organizationalUnit && <SummaryRow label="Organizational Unit" value={webTlsCertificate.organizationalUnit} />}
                {webTlsCertificate.locality && <SummaryRow label="Locality" value={webTlsCertificate.locality} />}
                {webTlsCertificate.state && <SummaryRow label="State" value={webTlsCertificate.state} />}
                {webTlsCertificate.country && <SummaryRow label="Country" value={webTlsCertificate.country} />}
                <SummaryRow label="SANs" value={webTlsCertificate.sans.length > 0 ? webTlsCertificate.sans.join(', ') : '(none)'} />
                <SummaryRow label="Validity" value={`${webTlsCertificate.validityDays} days`} />
            </SummaryCard>

            {/* Error banner */}
            {error && (
                <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
                    <p className="text-sm text-red-800 dark:text-red-300">{error}</p>
                    <button
                        onClick={() => setError(null)}
                        className="mt-2 text-sm text-red-600 dark:text-red-400 underline hover:no-underline"
                    >
                        Try Again
                    </button>
                </div>
            )}

            {/* Initialize button */}
            <div className="pt-2">
                <button
                    onClick={handleInitialize}
                    disabled={submitting}
                    className="w-full py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 dark:disabled:bg-blue-800 text-white font-semibold rounded-lg transition-colors flex items-center justify-center gap-2"
                >
                    {submitting && (
                        <svg className="animate-spin h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                        </svg>
                    )}
                    {submitting ? 'Initializing...' : 'Initialize ModularCA'}
                </button>
            </div>
        </div>
    );
};

const SummaryCard: React.FC<{ title: string; children: React.ReactNode }> = ({ title, children }) => (
    <div className="bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
        <div className="px-4 py-2 bg-gray-100 dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700">
            <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300">{title}</h3>
        </div>
        <div className="px-4 py-3 space-y-2">
            {children}
        </div>
    </div>
);

const SummaryRow: React.FC<{ label: string; value: string }> = ({ label, value }) => (
    <div className="flex justify-between items-start text-sm gap-4">
        <span className="text-gray-600 dark:text-gray-400 shrink-0">{label}</span>
        <span className="text-gray-900 dark:text-white text-right break-all">{value}</span>
    </div>
);

export default Review;
