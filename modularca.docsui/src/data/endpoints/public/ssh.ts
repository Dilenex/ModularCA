import type { ApiEndpoint } from '../types';

export const publicSsh: ApiEndpoint[] = [
    {
        method: 'GET',
        path: '/api/v1/public/ssh/ca-keys',
        summary: 'List all SSH CA public keys.',
        auth: 'Anonymous',
        category: 'Public SSH',
        responseDescription: 'Array of SSH CA keys with id, name, keyType, isUserCa, isHostCa, publicKey, createdAt, krlUrl and publicKeyUrl.',
        notes: 'Also served under the shorter /ssh prefix (/ssh/ca-keys), as every route here is. The list carries public material only: it does not say where a private key is held, which the admin list does. A validation-only host serves it; it needs no signer.',
    },
    {
        method: 'GET',
        path: '/api/v1/public/ssh/ca-keys/{id}/public-key',
        summary: 'Get the public key text for a specific SSH CA key.',
        auth: 'Anonymous',
        category: 'Public SSH',
        responseDescription: 'SSH public key as plain text. 404 when there is no such key.',
    },
    {
        method: 'GET',
        path: '/api/v1/public/ssh/ca/{id}/public-key',
        summary: 'Get the public key text for a specific SSH CA key (alternate path).',
        auth: 'Anonymous',
        category: 'Public SSH',
        responseDescription: 'SSH public key as plain text. 404 when there is no such key.',
    },
    {
        method: 'GET',
        path: '/api/v1/public/ssh/ca-keys/{id}/krl',
        summary: 'Download the Key Revocation List for an SSH CA key. Made to be polled: the list is the same bytes until a certificate of the key is revoked, and a request that names its ETag is answered 304.',
        auth: 'Anonymous',
        category: 'Public SSH',
        headers: [
            { name: 'If-None-Match', type: 'entity tag', required: false, description: 'The ETag of the list the caller already has. When it names the current list, the answer is 304 with no body.' },
        ],
        responseDescription: 'Binary KRL file (application/octet-stream, revoked_keys.krl), with a strong ETag and Cache-Control: no-cache. 200 with a valid KRL for an existing key: with nothing revoked it is a KRL with no entries. 304 with the ETag and no body when If-None-Match names the current list. 404 when there is no such key or its public key cannot be read.',
        notes: 'A fetcher can install the answer as sshd\'s RevokedKeys file without a special case for "nothing revoked"; before 0.4.2 that case answered 204 with no body. The KRL is built from the key\'s public key and its revoked serials, with no signer and no private key, so a validation-only host serves it, and it is served while the signer is locked. An OpenSSH KRL is not signed: fetch it over HTTPS; a plain HTTP request is redirected. From 0.4.2 two fetches with no revocation between them return the same bytes: the list\'s krl_version is the number of revoked certificates of the key, and its generation time is the time of the newest revocation (when the key was created, while no revocation time is known), never the time of the request. The version only goes up, except after the CA\'s database is restored from a backup. The ETag is a hash of the list\'s version, its generation time and the CA public key, so it changes exactly when a certificate is revoked; the 304 is answered from one small query, without building the list. If-None-Match is compared as RFC 9110 says, so a weak form of the tag and * also match. Expired certificates stay in the list. The Admin UI guide, "Getting the revocation list to hosts", has how a host is given the list.',
    },
];
