import type { ApiEndpoint } from '../../types';

export const adminPasswordPolicy: ApiEndpoint[] = [
    {
        method: 'GET',
        path: '/api/v1/admin/password-policy',
        summary: 'Get the current password policy configuration.',
        auth: 'Authorize (SystemAdmin)',
        category: 'Admin Password Policy',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'Password policy settings, including useBundledBlocklist (whether new passwords are checked against the blocklist shipped with the product) and maxAgeDays (0 = passwords never expire).',
        notes: 'The policy applies when a password is set or changed. A stored password is never checked against it at sign-in, so a stricter policy locks nobody out. A new install starts with the NIST SP 800-63B preset: minLength 15, no required character classes, maxAgeDays 0, useBundledBlocklist true. An install made before 0.4.5 keeps the policy it has stored.',
    },
    {
        method: 'GET',
        path: '/api/v1/admin/password-policy/guidance',
        summary: 'How the stored password policy compares with NIST SP 800-63B, and what the bundled blocklist holds. Read-only.',
        auth: 'Authorize (SystemAdmin)',
        category: 'Admin Password Policy',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
        ],
        responseDescription: 'nist80063B: { preset ("nist-sp-800-63b"), name, meets, differences (one sentence each; empty when the policy meets the standard) }. bundledBlocklist: { available (whether the shipped file was found on this node), entries, fileName, inUse }. 404 when no policy is configured.',
        notes: 'A policy stricter in length than the preset still meets the standard; one with composition rules or scheduled expiry does not. The console uses this to offer the preset; nothing is changed by reading it.',
    },
    {
        method: 'POST',
        path: '/api/v1/admin/password-policy/presets/{preset}',
        summary: 'Apply a named preset to the password policy in one action. One preset: nist-sp-800-63b; any other name is answered 404 and nothing changes.',
        auth: 'Authorize (SystemAdmin)',
        category: 'Admin Password Policy',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: true, description: 'Step-up MFA token scoped to update-config.' },
        ],
        responseDescription: 'The stored password policy after the preset.',
        notes: 'nist-sp-800-63b sets exactly: minLength 15; requireUppercase, requireLowercase, requireDigit and requireSymbol false; minUppercase, minLowercase, minDigits and minSpecial 0; maxAgeDays 0 (never expires); useBundledBlocklist true. A maxLength under 64 becomes 128; 0 (no maximum) and 64 or more are kept. historyCount, dictionaryPath and dictionaryIsHashed are not touched. Every setting stays editable afterwards through PUT. Passwords already stored keep working. Audited as PasswordPolicyUpdated with the preset named. Refused in restricted and DR mode, like the PUT.',
    },
    {
        method: 'PUT',
        path: '/api/v1/admin/password-policy',
        summary: 'Update the password policy. MinLength must be at least 8 and at most MaxLength (0 = no maximum), counts must not be negative, and HistoryCount must not exceed 24. DictionaryPath names a file in config/password-dictionaries by its file name; empty clears it. UseBundledBlocklist turns the check against the blocklist shipped with the product on or off.',
        auth: 'Authorize (SystemAdmin)',
        category: 'Admin Password Policy',
        headers: [
            { name: 'Authorization', type: 'Bearer token', required: true, description: 'JWT access token from /api/v1/auth/login' },
            { name: 'X-MFA-Token', type: 'string', required: true, description: 'Step-up MFA token scoped to update-config.' },
        ],
        responseDescription: 'Updated password policy.',
        notes: 'Two blocklists, each on its own switch: the one shipped with the product (password-blocklist/bundled-blocklist.txt beside the program files; a starter list of the most common choices) when useBundledBlocklist is true, and your own file when dictionaryPath is set. Your file adds to the bundled list; it does not replace it. A new password on either is refused with "Password matches a known weak or compromised password". Matching ignores case; the bundled list also refuses one entry, or any one or two characters, repeated end to end. Both are checked on the server: no password and no hash of one is sent anywhere. maxAgeDays 0 means passwords never expire: no account is treated as expired while it stands, including one whose expiry date was stamped under an earlier policy, and a password change then clears the date.',
    },
];
