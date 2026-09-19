import React from 'react';
import { CertificateRequestForm, type CertificateRequestEndpoints } from '../../components/CertificateRequestForm';

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

const RequestCertificate: React.FC = () => (
    <CertificateRequestForm mode="user" endpoints={USER_ENDPOINTS} requestsPath="/requests" />
);

export default RequestCertificate;
