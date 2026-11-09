import type { ApiEndpoint } from '../types';

export const publicEnrollment: ApiEndpoint[] = [
    {
        method: 'GET',
        path: '/api/v1/public/enroll/{token}',
        summary: 'Validate an enrollment token and return its configuration.',
        auth: 'Anonymous',
        category: 'Public Enrollment',
        responseDescription: 'Enrollment token details with allowed operations and profiles.',
    },
    {
        method: 'POST',
        path: '/api/v1/public/enroll/{token}',
        summary: 'Submit an enrollment request using a token.',
        auth: 'Anonymous',
        category: 'Public Enrollment',
        responseDescription: 'Issued certificate or enrollment result.',
        notes: 'A CSR whose key the system key policy refuses is answered 400 with code MCA-POL-000 and a message naming the key and the keys accepted, before the token is spent (from 0.4.3; the token used to be spent and the answer was 500). A certificate-policy refusal at issuance is answered 400 with its code as well. Every refusal (an unusable token, an unreadable CSR, a key outside the key policy, a name outside the token\'s restrictions, a request-profile refusal, a CA or profile not configured, a certificate-policy refusal at issuance) is recorded in the audit log as QrEnrollmentRejected, naming the token by its id.',
    },
    {
        method: 'GET',
        path: '/api/v1/public/enroll/{token}/page',
        summary: 'Serve the enrollment HTML page for browser-based enrollment.',
        auth: 'Anonymous',
        category: 'Public Enrollment',
        responseDescription: 'HTML enrollment page.',
    },
];
