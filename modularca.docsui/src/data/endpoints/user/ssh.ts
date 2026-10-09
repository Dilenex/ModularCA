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
        method: 'GET',
        path: '/api/v1/user/ssh/request-options',
        summary: 'Everything the request form needs for the caller: the key id the CA will write, and per SSH CA key the caller may request from, the login names the caller holds and the profile combinations that can be submitted.',
        auth: 'Authorize (CaUser)',
        category: 'User SSH',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: '{ keyId, caKeys }. keyId is the key id the CA writes into the caller\'s certificates, their username; null when the username cannot be one. caKeys lists each enabled SSH CA key that signs user certificates and whose CA the caller holds cert.request on: id, name, keyType, fingerprint (SHA256:...), maxValidityHours, allowOwnUsername, loginNames and profiles. loginNames lists what the caller holds on the key, by name: name, source (own, user or group), grantId, groupId, groupName, maxValidityHours (the longest certificate that may carry the name) and expiresAt (when the grant ends, or null). profiles lists the combinations that can be submitted: requestProfileId, requestProfileName, signingProfileId, signingProfileName, certProfileId, certProfileName, maxValidityHours (the smallest of the three profiles\' limits and the key\'s), maxPrincipals and unavailableLoginNames.',
        notes: 'A login name is an account the certificate lets its holder log in as. The caller holds their own username where the key allows it (allowOwnUsername; never root, which always needs a grant), and each name granted on the key to them or to a group they are in, while the grant has not ended. When several grounds give one name, the one listed is the most generous: the one that allows the latest certificate end. A combination is a request profile that requires no approval and is bound to the key\'s CA or to none, a signing profile it allows that points at the key and allows user certificates, and a certificate profile it allows; an empty allowed list means any. unavailableLoginNames are the held names the certificate profile\'s patterns do not allow, so a form can show them as unavailable with that combination instead of failing on submit. A certificate lasts at most the smallest maxValidityHours among the combination and the names chosen, and never past the earliest expiresAt among them.',
    },
    {
        method: 'POST',
        path: '/api/v1/user/ssh/sign-user',
        summary: 'Sign the caller\'s SSH public key, producing an SSH user certificate for the caller. The CA writes the key id, and every principal must be a login name the caller holds on the SSH CA key.',
        auth: 'Authorize (cert.request on the SSH CA)',
        category: 'User SSH',
        requestBody: [
            { name: 'publicKey', type: 'string', required: true, description: 'User\'s SSH public key to be signed' },
            { name: 'principals', type: 'string[]', required: true, description: 'The login names the certificate is for. At least one (400). Each must be one the caller holds on the SSH CA key: their own username where the key allows it, or a name granted to them or to a group they are in. A name that is not held is 400, naming it' },
            { name: 'sshRequestProfileId', type: 'guid', required: true, description: 'SSH request profile ID for access validation' },
            { name: 'sshSigningProfileId', type: 'guid', required: false, description: 'Optional SSH signing profile ID; derived from request profile when not specified' },
            { name: 'sshCertProfileId', type: 'guid', required: false, description: 'Optional SSH cert profile ID; derived from request profile when not specified' },
            { name: 'validityHours', type: 'int', required: false, description: 'Optional validity duration in hours. Omitted, the certificate lasts as long as the profiles, the key and the login names allow, and no longer than the earliest end among the grants used' },
            { name: 'keyId', type: 'string', required: false, description: 'Leave out. The CA writes the key id, the caller\'s username. A value is refused with 400 unless it is exactly that username' },
            { name: 'extensions', type: 'string[]', required: false, description: 'Optional SSH extensions, as name or name=value. Omitted or empty, the signing profile\'s default extensions apply; given, they replace that set. Each must be allowed by the cert profile' },
        ],
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Signed SSH certificate with id, serialNumber, principals, validAfter, validBefore, signedCertificate and keyId. keyId is the caller\'s username.',
        notes: 'The caller needs cert.request on the SSH CA that the signing profile names; without it the answer is 403. A request profile that requires approval is refused (400). The key id is what a host logs with every login (ID alice (serial N)), so the CA writes it and no request chooses it. The request options endpoint lists the login names the caller holds and the limit of each. The certificate profile\'s patterns, its maximum number of principals and the other profile checks still apply on top. Validity: over a request, signing or certificate profile\'s maximum is 400 { error }; over the limit of a login name asked for, or past the end of its grant, is 400 naming the login name and the limit. The signer builds and signs the certificate. Extensions are exact: the certificate carries the extensions asked for (or the signing profile\'s defaults), the signing profile\'s force-command and source-address, and the cert profile\'s required extensions, and nothing else. None is added by default, so a certificate that names no permit-* extension allows no terminal and no forwarding. A no-* name adds nothing: it withholds the matching permit-*. validAfter is five minutes before the time of issue, to allow for clock skew. 503 { error } when the signer is locked or unreachable (with Retry-After: 30), when the SSH CA key is awaiting its import into the signer (no Retry-After: an administrator has to act), or when the signer cannot serve the key. 400 { error } for a profile check that fails, a keyId, and no principals. 400 as problem details, with the sentence in detail, for a login name that is not held, a validity over what a login name allows, a DSA public key, and a certificate the signer\'s rules refuse, with the signer\'s reason: a validity over the key\'s maximum, an unknown extension. 400 with code MCA-CFG-005 when the signer holds no key for the SSH CA.',
    },
    {
        method: 'GET',
        path: '/api/v1/user/ssh/certificates',
        summary: 'List the SSH certificates issued for the authenticated user, whoever asked for them.',
        auth: 'Authorize (CaUser)',
        category: 'User SSH',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Array of SSH certificates, newest validity first, each with id, serialNumber, keyId, principals (a JSON array in a string), validAfter, validBefore, isRevoked, sshCaKeyId, certificateType, status (active, expired or revoked), sshCaKey { id, name, fingerprint, certificateAuthorityId }, keyFingerprint, subject { kind, userId, username, serviceLabel }, issuedBy { userId, username, selfService, sourceIp } and loginNameGrounds.',
        notes: 'A certificate an administrator signs for a user is listed for that user, not for the administrator. Certificates from before login names that the caller asked for, and that record no subject, are listed too, with subject.kind unknown or host and loginNameGrounds null. issuedBy.selfService is true when the caller asked for the certificate themselves; issuedBy.sourceIp is always null here. loginNameGrounds says why the caller held each login name when the certificate was issued: per name, name, source (own, user or group) and, for a grant, grantId, groupId, groupName, grantedByUserId, grantedByUsername, maxValidityHours and expiresAt.',
    },
    {
        method: 'GET',
        path: '/api/v1/user/ssh/certificates/{id}/download',
        summary: 'Download a signed SSH certificate that is the current user\'s: issued for them, or asked for by them before login names.',
        auth: 'Authorize (CaUser)',
        category: 'User SSH',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Signed SSH certificate content as text. 404 for a certificate that is not the caller\'s.',
    },
];
