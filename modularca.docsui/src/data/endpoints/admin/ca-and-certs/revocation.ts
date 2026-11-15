import type { ApiEndpoint } from '../../types';

export const adminRevocation: ApiEndpoint[] = [
    {
        method: 'POST',
        path: '/api/v1/admin/certificates/{certId}/revoke',
        summary: 'Revoke a certificate by its entity ID. Requires step-up MFA. CA certificate revocation may trigger a key ceremony.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Revocation',
        requestBody: [
            { name: 'certificateId', type: 'guid', required: true, description: 'The certificate entity ID to revoke' },
            { name: 'reason', type: 'RevocationReason', required: true, description: 'Revocation reason (e.g., Unspecified, KeyCompromise, CaCompromise, AffiliationChanged, Superseded, CessationOfOperation)' },
            { name: 'invalidityDate', type: 'datetime', required: false, description: 'Optional date when the key was known or suspected to be compromised' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: true, description: 'Step-up MFA token (operation: RevokeCert or RevokeCa)' },
        ],
        responseDescription: 'Revocation details including certificateId, serialNumber, newStatus, reason, previousReason (CertificateHold when a hold was made permanent, otherwise null), crlNumber, and effectiveAt. CA cert revocation may return ceremonyId when key ceremony is required.',
        notes: 'A certificate on hold is revoked permanently in place, without a release first (RFC 5280 5.3.1): the reason changes, the revocation date becomes now so the next delta CRL carries the change, and the hold date becomes the invalidity date unless invalidityDate is given. A permanently revoked certificate is refused with 409 (code MCA-RES-009), here and by the hold endpoints, as is a held certificate asked to be held again. KC-06: CA certificate revocation is ceremony-gated when the space RequireKeyCeremony flag is set. Enforces space isolation. When the ceremony could never reach its quorum, because too few accounts other than the caller can approve it, nothing is opened and the answer is 409 (code MCA-CFG-020 when nobody else can approve, MCA-CFG-021 when some can but too few); the key ceremony endpoints describe the body.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/certificates/serial/{serial}/revoke',
        summary: 'Revoke a certificate by serial number. Requires step-up MFA. CA certificate revocation may trigger a key ceremony.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Revocation',
        requestBody: [
            { name: 'serialNumber', type: 'string', required: true, description: 'The certificate serial number to revoke' },
            { name: 'reason', type: 'RevocationReason', required: true, description: 'Revocation reason (e.g., Unspecified, KeyCompromise, CaCompromise, AffiliationChanged, Superseded, CessationOfOperation)' },
            { name: 'invalidityDate', type: 'datetime', required: false, description: 'Optional date when the key was known or suspected to be compromised' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: true, description: 'Step-up MFA token (operation: RevokeCert or RevokeCa)' },
        ],
        responseDescription: 'Revocation details including certificateId, serialNumber, newStatus, reason, previousReason (CertificateHold when a hold was made permanent, otherwise null), crlNumber, and effectiveAt. CA cert revocation may return ceremonyId when key ceremony is required.',
        notes: 'A certificate on hold is revoked permanently in place, without a release first (RFC 5280 5.3.1): the reason changes, the revocation date becomes now so the next delta CRL carries the change, and the hold date becomes the invalidity date unless invalidityDate is given. A permanently revoked certificate is refused with 409 (code MCA-RES-009), here and by the hold endpoints, as is a held certificate asked to be held again. KC-06: CA certificate revocation is ceremony-gated when the space RequireKeyCeremony flag is set. Enforces space isolation. A serial that matches certificates of more than one issuer is refused with 409 (code MCA-RES-010); retry by certificate ID. When the ceremony could never reach its quorum, because too few accounts other than the caller can approve it, nothing is opened and the answer is 409 (code MCA-CFG-020 when nobody else can approve, MCA-CFG-021 when some can but too few); the key ceremony endpoints describe the body.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/certificates/{certId}/hold',
        summary: 'Place a certificate on hold (temporary revocation) by entity ID. Requires step-up MFA.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Revocation',
        requestBody: [
            { name: 'certificateId', type: 'guid', required: true, description: 'The certificate entity ID to place on hold' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: true, description: 'Step-up MFA token (operation: HoldCert)' },
        ],
        responseDescription: 'Hold details including certificateId, serialNumber, newStatus, crlNumber, and effectiveAt.',
        notes: 'Enforces space isolation via the certificate signing profile linkage.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/certificates/serial/{serial}/hold',
        summary: 'Place a certificate on hold by serial number. Requires step-up MFA.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Revocation',
        requestBody: [
            { name: 'serialNumber', type: 'string', required: true, description: 'The certificate serial number to place on hold' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: true, description: 'Step-up MFA token (operation: HoldCert)' },
        ],
        responseDescription: 'Hold details including certificateId, serialNumber, newStatus, crlNumber, and effectiveAt.',
        notes: 'Enforces space isolation via the certificate signing profile linkage. A serial that matches certificates of more than one issuer is refused with 409 (code MCA-RES-010); retry by certificate ID.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/certificates/{certId}/unhold',
        summary: 'Release a certificate from hold (reinstate) by entity ID. Requires step-up MFA.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Revocation',
        requestBody: [
            { name: 'certificateId', type: 'guid', required: true, description: 'The certificate entity ID to release from hold' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: true, description: 'Step-up MFA token (operation: UnholdCert)' },
        ],
        responseDescription: 'Reinstatement details including certificateId, serialNumber, newStatus, crlNumber, and effectiveAt.',
        notes: 'Enforces space isolation via the certificate signing profile linkage.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/certificates/serial/{serial}/unhold',
        summary: 'Release a certificate from hold (reinstate) by serial number. Requires step-up MFA.',
        auth: 'Authorize (CaOperator)',
        category: 'Admin Revocation',
        requestBody: [
            { name: 'serialNumber', type: 'string', required: true, description: 'The certificate serial number to release from hold' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: true, description: 'Step-up MFA token (operation: UnholdCert)' },
        ],
        responseDescription: 'Reinstatement details including certificateId, serialNumber, newStatus, crlNumber, and effectiveAt.',
        notes: 'Enforces space isolation via the certificate signing profile linkage. A serial that matches certificates of more than one issuer is refused with 409 (code MCA-RES-010); retry by certificate ID.',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/authorities/{caId}/revoked-serials',
        summary: 'List the serials recorded as revoked for a CA with no certificate behind them (tombstones).',
        auth: 'Authorize (cert.revoke on the CA)',
        category: 'Admin Revocation',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'An array, newest first: Id, SerialNumber, IssuerDN, Reason, RevocationDate, InvalidityDate, ListedUntil, OnCrl (false once ListedUntil has passed), Note, RecordedBy.',
        notes: 'Needs cert.revoke on the CA in the path, and on no other CA; 403 otherwise.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/authorities/{caId}/revoked-serials',
        summary: 'Record a serial as revoked for a CA with no certificate behind it. For a certificate known only from outside, such as one issued in time a rollback took away. Requires step-up MFA.',
        auth: 'Authorize (cert.revoke on the CA)',
        category: 'Admin Revocation',
        requestBody: [
            { name: 'serialNumber', type: 'string', required: true, description: 'The serial in hexadecimal, as the certificate shows it. Colons, dashes, spaces and leading zeros are ignored. At most twenty octets.' },
            { name: 'reason', type: 'RevocationReason', required: true, description: 'Revocation reason. CertificateHold is refused: a serial recorded this way cannot be released.' },
            { name: 'invalidityDate', type: 'datetime', required: false, description: 'Optional date when the key was known or suspected to be compromised' },
            { name: 'note', type: 'string', required: true, description: 'Why the serial is revoked without its certificate (at most 1000 characters). Kept with the entry and in the audit trail.' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: true, description: 'Step-up MFA token (operation: revoke-serial, target: the CA id)' },
        ],
        responseDescription: 'id, serialNumber, reason, revocationDate (now), listedUntil and crlNumber (the CRL regenerated to carry the entry, or null when the regeneration failed and the next scheduled CRL carries it).',
        notes: 'The CRL of the CA lists the serial at once, and OCSP answers for it with the recorded date and reason instead of the generic answer for a serial the CA does not know. The entry has no certificate expiry to be pruned by, so it stays on the CRL until listedUntil: the revocation date plus the longest maximum validity among the certificate profiles the CA can issue with (one year when none states one), and never past the end of the CA certificate. Refused with 409 when the CA holds a certificate with that serial (revoke the certificate instead) or the serial is already recorded; 400 for a serial that is not hexadecimal, for CertificateHold, and for a missing note. Audited as RevokedSerialRecorded, refusals included. If the certificate turns up later, adopting it moves the revocation onto the certificate and removes this entry.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/authorities/{caId}/adopted-certificates',
        summary: 'Adopt a certificate supplied from outside as a certificate of the CA, after its signature is verified under the CA key. Requires step-up MFA.',
        auth: 'Authorize (cert.revoke on the CA)',
        category: 'Admin Revocation',
        requestBody: [
            { name: 'certificate', type: 'string', required: true, description: 'The certificate, as PEM or as base64 of its DER encoding' },
            { name: 'note', type: 'string', required: true, description: 'Where the certificate came from and why it is adopted (at most 1000 characters)' },
            { name: 'revokeReason', type: 'RevocationReason', required: false, description: 'Revoke the certificate in the same step with this reason. Omit to adopt it as good. CertificateHold is refused here.' },
            { name: 'invalidityDate', type: 'datetime', required: false, description: 'Optional invalidity date of that revocation' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: true, description: 'Step-up MFA token (operation: adopt-certificate, target: the CA id)' },
        ],
        responseDescription: 'certificateId, serialNumber, subjectDN, notAfter, revoked, reason, fromTombstone (the revocation came from a serial recorded earlier, which was removed) and crlNumber.',
        notes: 'The certificate must name the CA as its issuer and its signature must verify under the key of the CA current certificate; anything else is refused with 400, as is a CA certificate (record the serial of a subordinate CA as revoked instead). 409 when the CA already holds a certificate with that serial. The adopted certificate is an ordinary certificate from then on, marked as adopted, with no profile, no request and no known requester: it appears in the certificate list, on the CRL and in OCSP like any other, and the revoke, hold and release endpoints act on it for a caller with cert.revoke on this CA. Audited as CertificateAdopted, and as CertificateRevoked when it is adopted revoked.',
    },
];
