import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { apiGet } from '../api/client';

const cards = [
    {
        title: 'CA Certificates',
        description: 'Download root and intermediate CA certificates to establish trust.',
        path: '/certificates',
        icon: '\u2387',
    },
    {
        title: 'CRL Downloads',
        description: 'Download Certificate Revocation Lists to verify certificate status.',
        path: '/crl',
        icon: '\u2716',
    },
    {
        title: 'ACME Directory',
        description: 'Automated certificate management via the ACME protocol.',
        path: '/acme',
        icon: 'A',
    },
];

const Landing: React.FC = () => {
    const [protocols, setProtocols] = useState<string[]>([]);

    useEffect(() => {
        apiGet<{ enabledProtocols?: string[] }>('/api/v1/public/info')
            .then((info) => setProtocols(info?.enabledProtocols ?? []))
            .catch(() => { /* non-blocking — just hide the section on failure */ });
    }, []);

    return (
    <div className="space-y-12">
        {/* Hero */}
        <div className="text-center py-12">
            <h1 className="text-4xl font-bold text-gray-900 dark:text-white mb-4">ModularCA</h1>
            <p className="text-lg text-gray-600 dark:text-gray-400 max-w-2xl mx-auto">
                An open-source Certificate Authority providing automated certificate management
                via ACME, EST, SCEP, CMP, and Windows autoenrollment (MSAE) protocols.
            </p>
        </div>

        {/* Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {cards.map((card) => (
                <Link
                    key={card.path}
                    to={card.path}
                    className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-6 hover:border-blue-600 transition-colors group"
                >
                    <div className="flex items-start gap-4">
                        <div className="w-10 h-10 bg-gray-200 dark:bg-gray-700 rounded-lg flex items-center justify-center text-lg text-blue-800 dark:text-blue-400 group-hover:bg-blue-600/20 transition-colors">
                            {card.icon}
                        </div>
                        <div>
                            <h2 className="text-lg font-semibold text-gray-900 dark:text-white group-hover:text-blue-300 transition-colors">
                                {card.title}
                            </h2>
                            <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">{card.description}</p>
                        </div>
                    </div>
                </Link>
            ))}
        </div>

        {/* Supported Protocols — only the ones actually enabled on this deployment */}
        {protocols.length > 0 && (
            <div className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg p-6">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Supported Protocols</h2>
                <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                    {protocols.map((p) => (
                        <div key={p} className="bg-gray-50 dark:bg-gray-900 rounded-lg p-3 text-center">
                            <span className="text-sm font-mono font-semibold text-blue-800 dark:text-blue-400">{p}</span>
                        </div>
                    ))}
                </div>
            </div>
        )}
    </div>
    );
};

export default Landing;
