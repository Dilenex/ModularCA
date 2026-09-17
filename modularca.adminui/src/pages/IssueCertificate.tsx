import React from 'react';
import { CertificateRequestForm, type CertificateRequestEndpoints } from '../components/CertificateRequestForm';

/**
 * The admin Issue Certificate page: the shared request form against the admin API.
 *
 * The admin API offers everything the form can show — the certificate-profile listing, the
 * validity window on both submit endpoints, and the ceiling pre-flight — so nothing is hidden.
 * Module-level so the prop keeps one identity across renders.
 */
const ADMIN_ENDPOINTS: CertificateRequestEndpoints = {
    requestProfiles: '/api/v1/admin/request-profiles',
    signingProfiles: '/api/v1/admin/signing-profiles',
    certProfiles: '/api/v1/admin/cert-profiles?isCaProfile=false',
    parseCsr: '/api/v1/admin/requests/parse-csr',
    validateAgainstProfile: '/api/v1/admin/requests/validate-against-profile',
    requestWithKey: '/api/v1/admin/certificates/issue-with-key',
    pkcs12: (requestId) => `/api/v1/admin/requests/${encodeURIComponent(requestId)}/pkcs12`,
    upload: '/api/v1/admin/requests/upload',
    validityCeiling: (signingProfileId, certProfileId) =>
        `/api/v1/admin/certificates/validity-ceiling?signingProfileId=${encodeURIComponent(signingProfileId)}`
        + `&certProfileId=${encodeURIComponent(certProfileId)}`,
    // The admin list returns raw rows for the profile editor's sake; validation needs the
    // effective profile after inheritance, which is what issuance applies.
    resolvedRequestProfile: (id) => `/api/v1/admin/request-profiles/${encodeURIComponent(id)}/resolved`,
};

const IssueCertificate: React.FC = () => (
    <CertificateRequestForm mode="admin" endpoints={ADMIN_ENDPOINTS} requestsPath="/certificates/requests" />
);

export default IssueCertificate;
