import type { ApiEndpoint } from '../types';

export const userSsh: ApiEndpoint[] = [
    {
        method: 'GET',
        path: '/api/v1/user/ssh/ca-keys',
        summary: 'List SSH CA keys designated as user CAs, filtered to CAs the user has access to.',
        auth: 'Authorize (CaUser)',
        category: 'User SSH',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Array of SSH CA keys with id, name, keyType, isUserCa, isHostCa, publicKey and maxValidityHours.',
        notes: 'The list does not say whether the signer holds a key. A key that is awaiting import into the signer, or that the signer does not hold, is listed all the same, and signing with it is refused with the reason.',
    },
    {
        method: 'POST',
        path: '/api/v1/user/ssh/sign-user',
        summary: 'Sign the caller\'s SSH public key, producing an SSH user certificate.',
        auth: 'Authorize (cert.request on the SSH CA)',
        category: 'User SSH',
        requestBody: [
            { name: 'publicKey', type: 'string', required: true, description: 'User\'s SSH public key to be signed' },
            { name: 'principals', type: 'string[]', required: true, description: 'List of principals (usernames) allowed on the certificate. At least one: the signer refuses a certificate with none (400)' },
            { name: 'sshRequestProfileId', type: 'guid', required: true, description: 'SSH request profile ID for access validation' },
            { name: 'sshSigningProfileId', type: 'guid', required: false, description: 'Optional SSH signing profile ID; derived from request profile when not specified' },
            { name: 'sshCertProfileId', type: 'guid', required: false, description: 'Optional SSH cert profile ID; derived from request profile when not specified' },
            { name: 'validityHours', type: 'int', required: false, description: 'Optional validity duration in hours' },
            { name: 'keyId', type: 'string', required: false, description: 'Optional key identifier; defaults to the user\'s username' },
            { name: 'extensions', type: 'string[]', required: false, description: 'Optional SSH extensions, as name or name=value. Omitted or empty, the signing profile\'s default extensions apply; given, they replace that set. Each must be allowed by the cert profile' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Signed SSH certificate with id, serialNumber, principals, validAfter, validBefore, signedCertificate and keyId.',
        notes: 'The caller needs cert.request on the SSH CA that the signing profile names; without it the answer is 403. A request profile that requires approval is refused (400). The signer builds and signs the certificate. Extensions are exact: the certificate carries the extensions asked for (or the signing profile\'s defaults), the signing profile\'s force-command and source-address, and the cert profile\'s required extensions, and nothing else. None is added by default, so a certificate that names no permit-* extension allows no terminal and no forwarding. A no-* name adds nothing: it withholds the matching permit-*. validAfter is five minutes before the time of issue, to allow for clock skew. 503 { error } when the signer is locked or unreachable (with Retry-After: 30), when the SSH CA key is awaiting its import into the signer (no Retry-After: an administrator has to act), or when the signer cannot serve the key. 400 { error } for a profile check that fails, a DSA public key, and a certificate the signer\'s rules refuse, with the signer\'s reason: no principals, a validity over the key\'s maximum, an unknown extension. 400 with code MCA-CFG-005 when the signer holds no key for the SSH CA.',
    },
    {
        method: 'GET',
        path: '/api/v1/user/ssh/certificates',
        summary: 'List SSH certificates issued by or for the authenticated user.',
        auth: 'Authorize (CaUser)',
        category: 'User SSH',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Array of SSH certificates with serial, key ID, principals, validity, and revocation status.',
    },
    {
        method: 'GET',
        path: '/api/v1/user/ssh/certificates/{id}/download',
        summary: 'Download a signed SSH certificate owned by the current user.',
        auth: 'Authorize (CaUser)',
        category: 'User SSH',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Signed SSH certificate content as text.',
    },
];
