export default function SetupGuide() {
    return (
        <div className="max-w-4xl mx-auto">
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-6">
                Setup Guide
            </h1>

            {/* Prerequisites */}
            <section className="mb-10">
                <h2 className="text-2xl font-semibold text-gray-900 dark:text-white mb-4">
                    Prerequisites
                </h2>
                <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-5">
                    <ul className="space-y-3">
                        <li className="flex items-start gap-3">
                            <span className="mt-0.5 flex-shrink-0 w-5 h-5 rounded-full bg-blue-100 dark:bg-blue-900 flex items-center justify-center">
                                <span className="w-2 h-2 rounded-full bg-blue-500" />
                            </span>
                            <div>
                                <span className="font-medium text-gray-900 dark:text-white">MySQL 8.0+</span>
                                <p className="text-sm text-gray-600 dark:text-gray-400">Required as the primary database. MariaDB 10.6+ is also supported.</p>
                            </div>
                        </li>
                        <li className="flex items-start gap-3">
                            <span className="mt-0.5 flex-shrink-0 w-5 h-5 rounded-full bg-blue-100 dark:bg-blue-900 flex items-center justify-center">
                                <span className="w-2 h-2 rounded-full bg-blue-500" />
                            </span>
                            <div>
                                <span className="font-medium text-gray-900 dark:text-white">.NET 10 SDK</span>
                                <p className="text-sm text-gray-600 dark:text-gray-400">Runtime and SDK required to build and run ModularCA.</p>
                            </div>
                        </li>
                        <li className="flex items-start gap-3">
                            <span className="mt-0.5 flex-shrink-0 w-5 h-5 rounded-full bg-blue-100 dark:bg-blue-900 flex items-center justify-center">
                                <span className="w-2 h-2 rounded-full bg-blue-500" />
                            </span>
                            <div>
                                <span className="font-medium text-gray-900 dark:text-white">Node.js 22+</span>
                                <p className="text-sm text-gray-600 dark:text-gray-400">Required only for building the web UI frontends.</p>
                            </div>
                        </li>
                    </ul>
                </div>
            </section>

            {/* Fresh Install */}
            <section className="mb-10">
                <h2 className="text-2xl font-semibold text-gray-900 dark:text-white mb-4">
                    Fresh Install (Interactive)
                </h2>
                <p className="text-gray-600 dark:text-gray-400 mb-4">
                    On a fresh install with no configuration files present, ModularCA launches a setup wizard
                    accessible via the browser.
                </p>
                <div className="space-y-4">
                    <Step number={1} title="Start the server">
                        <CodeBlock>dotnet run --project ModularCA</CodeBlock>
                        <p className="text-sm text-gray-600 dark:text-gray-400 mt-2">
                            The server detects no configuration and starts in setup mode on HTTPS port 8443.
                        </p>
                    </Step>
                    <Step number={2} title="Open the Setup Wizard">
                        <p className="text-sm text-gray-600 dark:text-gray-400">
                            Navigate to <code className="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 rounded text-sm font-mono">https://localhost:8443/setup</code> in your browser.
                            The wizard walks you through database connection, admin account creation, and root CA setup.
                        </p>
                    </Step>
                    <Step number={3} title="Complete setup">
                        <p className="text-sm text-gray-600 dark:text-gray-400">
                            After the wizard finishes, ModularCA writes its configuration files and the service
                            automatically restarts in normal mode. The setup UI is no longer accessible once setup is complete.
                        </p>
                    </Step>
                </div>
            </section>

            {/* Headless Bootstrap */}
            <section className="mb-10">
                <h2 className="text-2xl font-semibold text-gray-900 dark:text-white mb-4">
                    Headless Bootstrap
                </h2>
                <p className="text-gray-600 dark:text-gray-400 mb-4">
                    For automated deployments, ModularCA supports a headless bootstrap mode that reads
                    configuration from YAML files instead of the interactive wizard.
                </p>
                <div className="space-y-4">
                    <Step number={1} title="Prepare configuration files">
                        <p className="text-sm text-gray-600 dark:text-gray-400">
                            Create <code className="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 rounded text-sm font-mono">setup-database.yaml</code> and{' '}
                            <code className="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 rounded text-sm font-mono">bootstrap.yaml</code> in the working directory.
                        </p>
                    </Step>
                    <Step number={2} title="Run bootstrap">
                        <CodeBlock>dotnet run --project ModularCA -- --bootstrap</CodeBlock>
                        <p className="text-sm text-gray-600 dark:text-gray-400 mt-2">
                            ModularCA reads the YAML files, initializes the database, creates the admin account and
                            root CA, then exits. Start the server normally afterward.
                        </p>
                    </Step>
                </div>
            </section>

            {/* Configuration Files */}
            <section className="mb-10">
                <h2 className="text-2xl font-semibold text-gray-900 dark:text-white mb-4">
                    Configuration Files
                </h2>
                <div className="overflow-x-auto">
                    <table className="w-full text-sm border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
                        <thead>
                            <tr className="bg-gray-100 dark:bg-gray-800">
                                <th className="text-left px-4 py-3 font-semibold text-gray-900 dark:text-white">File</th>
                                <th className="text-left px-4 py-3 font-semibold text-gray-900 dark:text-white">Purpose</th>
                                <th className="text-left px-4 py-3 font-semibold text-gray-900 dark:text-white">Created</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                            <tr className="bg-white dark:bg-gray-800/50">
                                <td className="px-4 py-3 font-mono text-xs text-blue-600 dark:text-blue-400">setup-database.yaml</td>
                                <td className="px-4 py-3 text-gray-600 dark:text-gray-400">Database connection for initial setup / bootstrap</td>
                                <td className="px-4 py-3 text-gray-600 dark:text-gray-400">Before setup</td>
                            </tr>
                            <tr className="bg-white dark:bg-gray-800/50">
                                <td className="px-4 py-3 font-mono text-xs text-blue-600 dark:text-blue-400">bootstrap.yaml</td>
                                <td className="px-4 py-3 text-gray-600 dark:text-gray-400">Headless bootstrap configuration (admin user, root CA)</td>
                                <td className="px-4 py-3 text-gray-600 dark:text-gray-400">Before bootstrap</td>
                            </tr>
                            <tr className="bg-white dark:bg-gray-800/50">
                                <td className="px-4 py-3 font-mono text-xs text-blue-600 dark:text-blue-400">db.yaml</td>
                                <td className="px-4 py-3 text-gray-600 dark:text-gray-400">Runtime database connection string</td>
                                <td className="px-4 py-3 text-gray-600 dark:text-gray-400">By setup wizard</td>
                            </tr>
                            <tr className="bg-white dark:bg-gray-800/50">
                                <td className="px-4 py-3 font-mono text-xs text-blue-600 dark:text-blue-400">config.yaml</td>
                                <td className="px-4 py-3 text-gray-600 dark:text-gray-400">Main application configuration (ports, TLS, features)</td>
                                <td className="px-4 py-3 text-gray-600 dark:text-gray-400">By setup wizard</td>
                            </tr>
                            <tr className="bg-white dark:bg-gray-800/50">
                                <td className="px-4 py-3 font-mono text-xs text-blue-600 dark:text-blue-400">backup.key</td>
                                <td className="px-4 py-3 text-gray-600 dark:text-gray-400">32-byte AES-256-GCM key used for backup encryption</td>
                                <td className="px-4 py-3 text-gray-600 dark:text-gray-400">By setup wizard</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </section>

            {/* Port Configuration */}
            <section className="mb-10">
                <h2 className="text-2xl font-semibold text-gray-900 dark:text-white mb-4">
                    Port Configuration
                </h2>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <PortCard port={8443} protocol="HTTPS" description="Primary web interface and API. TLS required." />
                    <PortCard port={8080} protocol="HTTP" description="Redirect-only by default. Can serve ACME HTTP-01 challenges." />
                    <PortCard port={8444} protocol="mTLS" description="Mutual TLS endpoint for client certificate authentication." />
                </div>
            </section>

            {/* Database Configuration */}
            <section className="mb-10">
                <h2 className="text-2xl font-semibold text-gray-900 dark:text-white mb-4">
                    Database Configuration
                </h2>
                <p className="text-gray-600 dark:text-gray-400 mb-4">
                    ModularCA uses two separate MySQL databases with distinct users and permissions.
                </p>
                <div className="overflow-x-auto">
                    <table className="w-full text-sm border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
                        <thead>
                            <tr className="bg-gray-100 dark:bg-gray-800">
                                <th className="text-left px-4 py-3 font-semibold text-gray-900 dark:text-white">Database</th>
                                <th className="text-left px-4 py-3 font-semibold text-gray-900 dark:text-white">Purpose</th>
                                <th className="text-left px-4 py-3 font-semibold text-gray-900 dark:text-white">User Permissions</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                            <tr className="bg-white dark:bg-gray-800/50">
                                <td className="px-4 py-3 font-mono text-xs text-blue-600 dark:text-blue-400">modularca-app</td>
                                <td className="px-4 py-3 text-gray-600 dark:text-gray-400">Primary application data (CAs, certificates, users, groups)</td>
                                <td className="px-4 py-3 text-gray-600 dark:text-gray-400">Full read/write (all DML and DDL)</td>
                            </tr>
                            <tr className="bg-white dark:bg-gray-800/50">
                                <td className="px-4 py-3 font-mono text-xs text-blue-600 dark:text-blue-400">modularca-audit</td>
                                <td className="px-4 py-3 text-gray-600 dark:text-gray-400">Append-only audit trail</td>
                                <td className="px-4 py-3 text-gray-600 dark:text-gray-400">SELECT, INSERT, DELETE + schema (no UPDATE)</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                <p className="text-sm text-gray-500 dark:text-gray-400 mt-3">
                    The audit user has no <code className="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 rounded text-sm font-mono">UPDATE</code> grant,
                    so an existing audit row cannot be rewritten in place &mdash; that is the property the
                    separate database buys you. It <em>does</em> hold
                    <code className="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 rounded text-sm font-mono">DELETE</code>, which the
                    scheduled retention job needs to age rows out, plus
                    <code className="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 rounded text-sm font-mono">CREATE / ALTER / INDEX</code> for
                    schema migrations. Audit rows are therefore tamper-evident against modification, not
                    against deletion by something running as the audit user.
                </p>
            </section>

            {/* Backup Encryption */}
            <section className="mb-10">
                <h2 className="text-2xl font-semibold text-gray-900 dark:text-white mb-4">
                    Backup Encryption
                </h2>
                <div className="bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg p-5">
                    <div className="flex items-start gap-3">
                        <svg className="w-5 h-5 text-amber-500 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        <div>
                            <p className="font-medium text-amber-800 dark:text-amber-300 mb-2">Encryption is mandatory</p>
                            <p className="text-sm text-amber-700 dark:text-amber-400">
                                All backups are encrypted using AES-256-GCM with a 32-byte key stored
                                at <code className="px-1.5 py-0.5 bg-amber-100 dark:bg-amber-900/40 rounded text-sm font-mono">backup.key</code>.
                                Unencrypted backups are not supported. The key is generated during setup and must be
                                preserved separately to restore from backups.
                            </p>
                        </div>
                    </div>
                </div>
            </section>

            {/* Security Details */}
            <section className="mb-10">
                <h2 className="text-2xl font-semibold text-gray-900 dark:text-white mb-4">
                    Security Details
                </h2>
                <div className="space-y-4">
                    <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-5">
                        <h3 className="font-semibold text-gray-900 dark:text-white mb-2">JWT Secret</h3>
                        <p className="text-sm text-gray-600 dark:text-gray-400">
                            The JWT signing secret is auto-generated during setup as 64 random bytes, Base64-encoded
                            to an 88-character string. A minimum of 64 bytes is required for HMAC-SHA256 signatures.
                            The secret is stored in <code className="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 rounded text-sm font-mono">config.yaml</code> and
                            should never be shared or committed to version control.
                        </p>
                    </div>
                    <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-5">
                        <h3 className="font-semibold text-gray-900 dark:text-white mb-2">Scrypt Parameters</h3>
                        <p className="text-sm text-gray-600 dark:text-gray-400">
                            Keystore passphrases are derived using Scrypt with the following parameters:
                        </p>
                        <div className="mt-2 flex gap-4">
                            <span className="inline-flex items-center gap-1.5 text-xs font-mono bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 px-2.5 py-1 rounded">
                                N=65536
                            </span>
                            <span className="inline-flex items-center gap-1.5 text-xs font-mono bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 px-2.5 py-1 rounded">
                                r=8
                            </span>
                            <span className="inline-flex items-center gap-1.5 text-xs font-mono bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 px-2.5 py-1 rounded">
                                p=1
                            </span>
                        </div>
                    </div>
                    <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-5">
                        <h3 className="font-semibold text-gray-900 dark:text-white mb-2">Docs Are Not Authenticated</h3>
                        <p className="text-sm text-gray-600 dark:text-gray-400">
                            The <code className="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 rounded text-sm font-mono">/docs/</code> path
                            is readable without logging in. The middleware only rejects a request that
                            <em>carries</em> an expired or invalid bearer token &mdash; a request with no
                            <code className="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 rounded text-sm font-mono">Authorization</code> header
                            at all is served. Treat this UI as public: it describes the admin surface, the
                            config file layout, and the reset procedure. Put it behind your reverse proxy if
                            that matters in your environment.
                        </p>
                    </div>
                </div>
            </section>

            {/* Reset Procedure */}
            <section className="mb-10">
                <h2 className="text-2xl font-semibold text-gray-900 dark:text-white mb-4">
                    Reset Procedure
                </h2>
                <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-5">
                    <div className="flex items-start gap-3">
                        <svg className="w-5 h-5 text-red-500 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        <div>
                            <p className="font-medium text-red-800 dark:text-red-300 mb-2">Destructive Operation</p>
                            <p className="text-sm text-red-700 dark:text-red-400 mb-3">
                                Resetting drops all database tables and removes configuration files.
                                All certificates, CAs, and user data will be permanently deleted.
                            </p>
                            <CodeBlock variant="danger">dotnet run --project ModularCA -- --reset --force --confirm-db-name modularca-app</CodeBlock>
                            <p className="text-sm text-red-700 dark:text-red-400 mt-2">
                                There is no interactive confirmation. Both flags are mandatory and the process
                                exits 1 without them:
                                <code className="px-1.5 py-0.5 bg-red-100 dark:bg-red-900/40 rounded text-sm font-mono">--force</code> acknowledges
                                that the operation is destructive, and
                                <code className="px-1.5 py-0.5 bg-red-100 dark:bg-red-900/40 rounded text-sm font-mono">--confirm-db-name</code> requires
                                you to type the target database name, so a reset cannot be aimed at the wrong
                                one by muscle memory. Non-interactive pipelines that genuinely need an
                                unattended reset can substitute
                                <code className="px-1.5 py-0.5 bg-red-100 dark:bg-red-900/40 rounded text-sm font-mono">--ci-no-confirm</code>.
                            </p>
                            <p className="text-sm font-medium text-red-800 dark:text-red-300 mt-4 mb-2">What reset does:</p>
                            <ul className="text-sm text-red-700 dark:text-red-400 space-y-1.5 list-disc list-inside">
                                <li>Drops all tables in the <code className="px-1.5 py-0.5 bg-red-100 dark:bg-red-900/40 rounded text-sm font-mono">modularca-app</code> database</li>
                                <li>
                                    The <code className="px-1.5 py-0.5 bg-red-100 dark:bg-red-900/40 rounded text-sm font-mono">modularca-audit</code> database
                                    is append-only — old audit entries survive reset by design
                                </li>
                                <li>
                                    Deletes <code className="px-1.5 py-0.5 bg-red-100 dark:bg-red-900/40 rounded text-sm font-mono">config.yaml</code>,{' '}
                                    <code className="px-1.5 py-0.5 bg-red-100 dark:bg-red-900/40 rounded text-sm font-mono">db.yaml</code>, and{' '}
                                    <code className="px-1.5 py-0.5 bg-red-100 dark:bg-red-900/40 rounded text-sm font-mono">backup.key</code>
                                </li>
                                <li>Requires re-running the setup wizard to configure the instance again</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </section>
        </div>
    );
}

function Step({ number, title, children }: { number: number; title: string; children: React.ReactNode }) {
    return (
        <div className="flex gap-4">
            <div className="flex-shrink-0 w-8 h-8 rounded-full bg-blue-500 text-white flex items-center justify-center text-sm font-bold">
                {number}
            </div>
            <div className="flex-1 pt-0.5">
                <h3 className="font-semibold text-gray-900 dark:text-white mb-1">{title}</h3>
                {children}
            </div>
        </div>
    );
}

function CodeBlock({ children, variant }: { children: React.ReactNode; variant?: 'danger' }) {
    const bg = variant === 'danger'
        ? 'bg-red-100 dark:bg-red-900/40 border-red-200 dark:border-red-800'
        : 'bg-gray-900 dark:bg-gray-950 border-gray-700 dark:border-gray-600';
    const text = variant === 'danger'
        ? 'text-red-900 dark:text-red-300'
        : 'text-green-400';

    return (
        <pre className={`${bg} border rounded-md px-4 py-3 overflow-x-auto`}>
            <code className={`text-sm font-mono ${text}`}>{children}</code>
        </pre>
    );
}

function PortCard({ port, protocol, description }: { port: number; protocol: string; description: string }) {
    return (
        <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
            <div className="flex items-baseline gap-2 mb-2">
                <span className="text-2xl font-bold text-gray-900 dark:text-white">{port}</span>
                <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-blue-100 dark:bg-blue-900 text-blue-700 dark:text-blue-300">
                    {protocol}
                </span>
            </div>
            <p className="text-sm text-gray-600 dark:text-gray-400">{description}</p>
        </div>
    );
}
