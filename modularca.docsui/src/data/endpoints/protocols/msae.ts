import type { ApiEndpoint } from '../types';

export const msae: ApiEndpoint[] = [
    {
        method: 'POST',
        path: '/api/v1/msae/{caLabel}/cep',
        summary: 'MSAE: Certificate Enrollment Policy Web Service (MS-XCEP) - list the templates a Windows client may enroll for, with the CA certificate and enrollment URL.',
        auth: 'WS-Security UsernameToken or HTTP Basic',
        category: 'MSAE',
        responseDescription: 'SOAP GetPoliciesResponse: offered templates (OID, version, key, validity, extensions), issuing CA, and the OID table.',
    },
    {
        method: 'POST',
        path: '/api/v1/msae/{caLabel}/ces',
        summary: 'MSAE: Certificate Enrollment Web Service (MS-WSTEP) - issue a certificate for a Windows client from a SOAP RequestSecurityToken carrying a PKCS#10.',
        auth: 'WS-Security UsernameToken or HTTP Basic',
        category: 'MSAE',
        responseDescription: 'SOAP RequestSecurityTokenResponseCollection carrying the issued certificate and chain as a certs-only PKCS#7; refusals are SOAP faults.',
    },
];
