import { Link } from 'react-router-dom';

const quickLinks = [
    {
        title: 'API Reference',
        description: 'Complete REST API documentation for all ModularCA endpoints including certificates, CAs, profiles, and more.',
        to: '/docs/api/authentication',
        icon: (
            <svg className="w-8 h-8 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
            </svg>
        ),
    },
    {
        title: 'UI Guide',
        description: 'User guides for the Admin, User, Public, and Setup web interfaces.',
        to: '/docs/ui/admin',
        icon: (
            <svg className="w-8 h-8 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
            </svg>
        ),
    },
    {
        title: 'Architecture',
        description: 'Deep dives into authentication flows, certificate issuance, CA hierarchy, and the tenant model.',
        to: '/docs/architecture/auth-flow',
        icon: (
            <svg className="w-8 h-8 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" />
            </svg>
        ),
    },
];

export default function Overview() {
    return (
        <div className="max-w-4xl mx-auto">
            <div className="mb-10">
                <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-4">
                    ModularCA Documentation
                </h1>
                <p className="text-lg text-gray-600 dark:text-gray-400 leading-relaxed">
                    ModularCA is a modular, multi-tenant Certificate Authority platform built on .NET.
                    It supports X.509 and SSH certificate issuance, flexible CA hierarchies,
                    profile-based policy enforcement, and fine-grained group and role authorization.
                    This documentation covers the REST API, web interfaces, setup procedures, and
                    architectural design.
                </p>
            </div>

            {/* Feature Highlights */}
            <div className="mb-10">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-4">Feature Highlights</h2>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="p-4 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg">
                        <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-2">Post-Quantum Cryptography</h3>
                        <p className="text-sm text-gray-600 dark:text-gray-400">
                            ML-DSA and SLH-DSA algorithm support for quantum-resistant certificate issuance
                            alongside classical ECDSA and RSA.
                        </p>
                    </div>
                    <div className="p-4 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg">
                        <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-2">MFA Step-Up Verification</h3>
                        <p className="text-sm text-gray-600 dark:text-gray-400">
                            All sensitive operations (CA signing, key export, user management) require
                            MFA step-up verification before execution.
                        </p>
                    </div>
                    <div className="p-4 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg">
                        <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-2">Multi-Tenant Authorization</h3>
                        <p className="text-sm text-gray-600 dark:text-gray-400">
                            CA-scoped group authorization with auto-generated groups per CA label and
                            system groups for global access control.
                        </p>
                    </div>
                    <div className="p-4 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg">
                        <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-2">Protocol Support</h3>
                        <p className="text-sm text-gray-600 dark:text-gray-400">
                            ACME (RFC 8555), EST (RFC 7030), SCEP (RFC 8894), CMP (RFC 4210), and Windows autoenrollment (MS-WSTEP) for
                            automated certificate enrollment and management.
                        </p>
                    </div>
                    <div className="p-4 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg">
                        <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-2">SSH Certificate Authority</h3>
                        <p className="text-sm text-gray-600 dark:text-gray-400">
                            Issue and manage SSH user and host certificates with configurable principals,
                            validity periods, and key ID policies.
                        </p>
                    </div>
                    <div className="p-4 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg">
                        <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-2">Active Directory / LDAP Integration</h3>
                        <p className="text-sm text-gray-600 dark:text-gray-400">
                            LDAP authentication, group synchronization from AD, and certificate/CRL
                            publishing to directory services.
                        </p>
                    </div>
                    <div className="p-4 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg md:col-span-2">
                        <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-2">Backup Encryption</h3>
                        <p className="text-sm text-gray-600 dark:text-gray-400">
                            All backups are encrypted with AES-256-GCM. Encryption is mandatory and cannot
                            be disabled, ensuring data protection at rest for exported material.
                        </p>
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-10">
                {quickLinks.map((link) => (
                    <Link
                        key={link.title}
                        to={link.to}
                        className="block p-6 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg shadow-sm hover:shadow-md hover:border-blue-300 dark:hover:border-blue-600 transition-all"
                    >
                        <div className="mb-3">{link.icon}</div>
                        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
                            {link.title}
                        </h3>
                        <p className="text-sm text-gray-600 dark:text-gray-400">
                            {link.description}
                        </p>
                    </Link>
                ))}
            </div>

            <div className="p-4 bg-gray-100 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg">
                <div className="flex items-center gap-3">
                    <svg className="w-5 h-5 text-gray-500 dark:text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <div>
                        <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Version</span>
                        <span className="ml-2 text-sm text-gray-500 dark:text-gray-400">1.0.0-preview</span>
                    </div>
                </div>
            </div>
        </div>
    );
}
