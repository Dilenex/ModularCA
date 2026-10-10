import React from 'react';
import { CertificateRequestForm, type CertificateRequestEndpoints } from '../components/CertificateRequestForm';
import { KindTabStrip, useKindTabs } from '../components/KindTabs';
import { useScope } from '../context/ScopeContext';
import { useAuth } from '../context/AuthContext';
import { canUseSshTab } from '../authz';
import { CERT_REQUEST } from '../gates';
import { SshSignTab } from './SshCertificates';

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
    keyOptions: (signingProfileId, certProfileId) =>
        `/api/v1/admin/certificates/key-options?signingProfileId=${encodeURIComponent(signingProfileId)}`
        + `&certProfileId=${encodeURIComponent(certProfileId)}`,
    // The admin list returns raw rows for the profile editor's sake; validation needs the
    // effective profile after inheritance, which is what issuance applies.
    resolvedRequestProfile: (id) => `/api/v1/admin/request-profiles/${encodeURIComponent(id)}/resolved`,
};

/**
 * The Request Certificate page: the X.509 request form, and on its SSH tab the Sign key form.
 * Each tab is shown only to who can use it: the X.509 tab to who may request a certificate in
 * the scope, the SSH tab to who may sign on an SSH CA.
 */
const IssueCertificate: React.FC = () => {
    const { scope, allows } = useScope();
    const { capabilities } = useAuth();
    const { tabs, active, setActive } = useKindTabs({ x509: allows(CERT_REQUEST), ssh: canUseSshTab(capabilities, 'sign') });
    return (
        <div className="p-3 sm:p-6 space-y-4 sm:space-y-6">
            <h1 className="text-xl font-semibold text-ink">Request Certificate</h1>
            <KindTabStrip tabs={tabs} active={active} onChange={setActive} />
            {active === 'X.509' && <CertificateRequestForm mode="admin" endpoints={ADMIN_ENDPOINTS} requestsPath="/certificates/requests" embedded />}
            {active === 'SSH' && <SshSignTab scope={scope} />}
        </div>
    );
};

export default IssueCertificate;
