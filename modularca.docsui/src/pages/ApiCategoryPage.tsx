import { useParams, Link } from 'react-router-dom';
import { useMemo } from 'react';
import EndpointCard from '../components/EndpointCard';
import type { Endpoint } from '../components/EndpointCard';

/**
 * Maps a sidebar slug to the endpoint categories it covers.
 *
 * The sidebar offers 13 coarse groupings ("certificates", "ca-management") while the endpoint
 * data carries 65 fine-grained categories ("Admin Certificates", "Admin CA", "Admin CRL"). The
 * page compared `ep.category.toLowerCase() === slug` for exact equality, so only the three
 * slugs that happened to coincide with a real category name -- authentication, integration,
 * setup -- rendered anything. The other TEN sidebar links led to an empty page with no
 * explanation.
 *
 * Grouped rather than flattened to 65 sidebar entries: the curation is the useful part.
 */
const CATEGORY_GROUPS: Record<string, string[]> = {
    'authentication': ['Authentication', 'MFA Step-Up', 'TOTP MFA', 'WebAuthn MFA', 'mTLS Authentication', 'Account'],
    'certificates': ['Admin Certificates', 'Admin Issuance', 'Admin Revocation', 'Admin Certificate Permissions', 'User Certificates', 'User CA Certificates'],
    'certificate requests': ['Admin CSR', 'Admin Request Profiles', 'User Certificate Requests', 'User Request Profiles'],
    'ca management': ['Admin CA', 'Admin CA Service URLs', 'Admin CRL', 'Admin CRL Schedules', 'Admin Trust Anchors', 'Admin Key Ceremonies', 'Admin CT Logs'],
    'ssh ca': ['Admin SSH', 'Admin SSH Profiles', 'Admin SSH Templates', 'User SSH', 'Public SSH'],
    'profiles': ['Admin Cert Profiles', 'Admin Signing Profiles', 'Admin Templates', 'Admin OID Options', 'User Signing Profiles'],
    'groups permissions': ['Admin Groups', 'Admin Quotas', 'Admin Tenants', 'User Groups'],
    'users accounts': ['Admin Users', 'Admin Password Policy', 'Admin Security Policy'],
    'audit compliance': ['Admin Audit', 'Admin Compliance', 'Admin Policy'],
    'protocols': ['ACME', 'EST', 'SCEP', 'CMP', 'Admin ACME EAB', 'Admin Protocol Configs', 'Admin Enrollment Tokens'],
    'integration': ['Integration', 'Admin LDAP', 'Admin LDAP Publisher', 'Admin LDAP Publishers', 'Admin Notifications'],
    'system': ['Admin Configuration', 'Admin Feature Flags', 'Admin Scheduler', 'Admin Backup', 'Admin Whitelists', 'Admin Rate Limit Policy'],
    'setup': ['Setup'],
    'public': ['Public', 'Public Enrollment', 'Public Short URLs'],
};

let importedEndpoints: Endpoint[] = [];
try {
    const mod = await import('../data/endpoints');
    importedEndpoints = mod.endpoints ?? [];
} catch {
    // Data file not yet created; use empty array
}

export default function ApiCategoryPage() {
    const { category } = useParams<{ category: string }>();

    const decodedCategory = category ? decodeURIComponent(category) : '';

    const endpoints: Endpoint[] = importedEndpoints;

    const normalizedCategory = decodedCategory.replace(/-/g, ' ').toLowerCase();

    const filtered = useMemo(() => {
        const wanted = CATEGORY_GROUPS[normalizedCategory];
        if (wanted) {
            const set = new Set(wanted.map((c) => c.toLowerCase()));
            return endpoints.filter((ep) => set.has(ep.category.toLowerCase()));
        }
        // Unknown slug: fall back to exact match so a category added to the data set is
        // reachable at /docs/api/<its-name> even before it is grouped in the sidebar.
        return endpoints.filter((ep) => ep.category.toLowerCase() === normalizedCategory);
    }, [endpoints, normalizedCategory]);

    return (
        <div className="max-w-4xl mx-auto">
            {/* Breadcrumb */}
            <nav className="flex items-center gap-2 text-sm text-gray-500 dark:text-gray-400 mb-6">
                <Link
                    to="/docs/api"
                    className="hover:text-blue-600 dark:hover:text-blue-400 transition-colors"
                >
                    API Reference
                </Link>
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                </svg>
                <span className="text-gray-900 dark:text-white font-medium">
                    {decodedCategory || 'Category'}
                </span>
            </nav>

            <div className="mb-8">
                <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">
                    {decodedCategory || 'Category'}
                </h1>
                <p className="text-gray-600 dark:text-gray-400">
                    {filtered.length} endpoint{filtered.length !== 1 ? 's' : ''} in this category.
                </p>
            </div>

            {filtered.length === 0 ? (
                <div className="text-center py-12">
                    <p className="text-gray-500 dark:text-gray-400 mb-4">
                        No endpoints found for category "{decodedCategory}".
                    </p>
                    <Link
                        to="/docs/api"
                        className="text-blue-600 dark:text-blue-400 hover:underline text-sm"
                    >
                        Back to API Reference
                    </Link>
                </div>
            ) : (
                <div className="space-y-2">
                    {filtered.map((ep, idx) => (
                        <EndpointCard key={`${ep.method}-${ep.path}-${idx}`} endpoint={ep} />
                    ))}
                </div>
            )}
        </div>
    );
}
