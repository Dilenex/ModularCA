import React from 'react';
import { CertificateRequestForm, type CertificateRequestEndpoints } from '../../components/CertificateRequestForm';
import { KindTabStrip, useKindTabs } from '../../components/KindTabs';
import { useAuth } from '../../context/AuthContext';
import { canUseSshTab } from '../../authz';
import { MySshRequestTab } from './MySshCertificates';

/**
 * The user portal's Request Certificate page: the shared request form against the user API.
 *
 * `/api/v1/user` has no cert-profiles listing and no validity-ceiling endpoint, and its upload
 * and request-with-key handlers take no validity window, so those endpoints are left out and
 * the form's `user` mode hides the controls that would need them. Module-level so the prop
 * keeps one identity across renders.
 */
const USER_ENDPOINTS: CertificateRequestEndpoints = {
    requestProfiles: '/api/v1/user/request-profiles',
    signingProfiles: '/api/v1/user/signing-profiles',
    parseCsr: '/api/v1/user/requests/parse-csr',
    validateAgainstProfile: '/api/v1/user/requests/validate-against-profile',
    requestWithKey: '/api/v1/user/requests/request-with-key',
    pkcs12: (requestId) => `/api/v1/user/requests/${encodeURIComponent(requestId)}/pkcs12`,
    upload: '/api/v1/user/requests/upload',
};

/**
 * The self-service Request Certificate page: the X.509 request form, and for a reader who may
 * request from an SSH CA an SSH tab with the SSH request form. A reader with no SSH tab sees no
 * tab strip.
 */
const RequestCertificate: React.FC = () => {
    const { capabilities } = useAuth();
    const { tabs, active, setActive } = useKindTabs({ x509: true, ssh: canUseSshTab(capabilities, 'selfRequest') });
    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <h1 className="text-xl font-semibold text-ink">Request Certificate</h1>
            <KindTabStrip tabs={tabs} active={active} onChange={setActive} />
            {active === 'X.509' && <CertificateRequestForm mode="user" endpoints={USER_ENDPOINTS} requestsPath="/requests" embedded />}
            {active === 'SSH' && <MySshRequestTab />}
        </div>
    );
};

export default RequestCertificate;
