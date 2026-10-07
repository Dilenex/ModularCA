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
        summary: 'Download the Key Revocation List for an SSH CA key.',
        auth: 'Anonymous',
        category: 'Public SSH',
        responseDescription: 'Binary KRL file (application/octet-stream, revoked_keys.krl). Always 200 with a valid KRL for an existing key: with nothing revoked it is a KRL with no entries. 404 when there is no such key or its public key cannot be read.',
        notes: 'A fetcher can install the answer as sshd\'s RevokedKeys file without a special case for "nothing revoked"; before 0.4.2 that case answered 204 with no body. The KRL is built from the key\'s public key and its revoked serials, with no signer and no private key, so a validation-only host serves it, and it is served while the signer is locked. An OpenSSH KRL is not signed: fetch it over HTTPS.',
    },
];
