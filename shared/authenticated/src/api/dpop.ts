/**
 * DPoP-style proof-of-possession for refresh-token binding.
 *
 * A non-extractable ECDSA P-256 key is generated via WebCrypto and stored in IndexedDB. The private
 * key material can never be read by JavaScript or exfiltrated (XSS, localStorage/cookie theft) — so a
 * stolen refresh token is useless without the key, which stays on this device. Per request to a
 * token-issuing / refresh endpoint we sign a short-lived proof JWT; the server binds the refresh
 * token to the key's JWK thumbprint and requires a matching proof to rotate.
 *
 * Cross-platform: pure WebCrypto + IndexedDB (all modern browsers, any OS, secure context only).
 *
 * SAFETY: proof generation MUST NOT be able to stall the auth flow — every login/refresh awaits it.
 * So all IndexedDB/WebCrypto work is wrapped in a hard timeout; on any failure or timeout we return
 * null and the caller simply omits the header (the server's soft rollout then leaves the session
 * unbound — auth still works, just without PoP).
 */

const DB_NAME = 'modularca-auth';
const STORE = 'keys';
const KEY_ID = 'dpop-es256';
const PROOF_TIMEOUT_MS = 2500;

// Single shared connection promise — avoid reopening (and leaking) a connection per operation.
let dbPromise: Promise<IDBDatabase> | null = null;

function openDb(): Promise<IDBDatabase> {
    if (dbPromise) return dbPromise;
    dbPromise = new Promise<IDBDatabase>((resolve, reject) => {
        let req: IDBOpenDBRequest;
        try {
            req = indexedDB.open(DB_NAME, 1);
        } catch (e) {
            reject(e);
            return;
        }
        req.onupgradeneeded = () => {
            const db = req.result;
            if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
        // A version-change deadlock (another tab) would otherwise hang forever — fail fast instead.
        req.onblocked = () => reject(new Error('indexeddb blocked'));
    }).catch((e) => { dbPromise = null; throw e; }); // allow a later retry if this attempt failed
    return dbPromise;
}

function idbGet<T>(key: string): Promise<T | undefined> {
    return openDb().then((db) => new Promise<T | undefined>((resolve, reject) => {
        const r = db.transaction(STORE, 'readonly').objectStore(STORE).get(key);
        r.onsuccess = () => resolve(r.result as T | undefined);
        r.onerror = () => reject(r.error);
    }));
}

function idbPut(key: string, val: unknown): Promise<void> {
    return openDb().then((db) => new Promise<void>((resolve, reject) => {
        const tx = db.transaction(STORE, 'readwrite');
        tx.objectStore(STORE).put(val, key);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
        tx.onabort = () => reject(tx.error);
    }));
}

let cached: CryptoKeyPair | null = null;

async function getKeyPair(): Promise<CryptoKeyPair> {
    if (cached) return cached;
    const existing = await idbGet<CryptoKeyPair>(KEY_ID);
    if (existing?.privateKey && existing?.publicKey) {
        cached = existing;
        return cached;
    }
    // extractable=false → the PRIVATE key cannot be exported; the public key stays exportable.
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
    await idbPut(KEY_ID, pair); // CryptoKey objects are structured-cloneable into IndexedDB
    cached = pair;
    return cached;
}

function b64url(bytes: Uint8Array): string {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
const b64urlJson = (obj: unknown) => b64url(new TextEncoder().encode(JSON.stringify(obj)));

async function buildProof(method: string, url: string): Promise<string> {
    const abs = new URL(url, window.location.origin);
    const pair = await getKeyPair();
    const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
    const header = { typ: 'dpop+jwt', alg: 'ES256', jwk: { crv: 'P-256', kty: 'EC', x: jwk.x, y: jwk.y } };
    const payload = {
        htu: abs.origin + abs.pathname,
        htm: method.toUpperCase(),
        iat: Math.floor(Date.now() / 1000),
        jti: b64url(crypto.getRandomValues(new Uint8Array(16))),
    };
    const signingInput = `${b64urlJson(header)}.${b64urlJson(payload)}`;
    const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, new TextEncoder().encode(signingInput));
    return `${signingInput}.${b64url(new Uint8Array(sig))}`;
}

/**
 * Builds a DPoP proof JWT for (method, url), signed by this device's non-extractable key.
 * Returns null (never throws, never hangs) when WebCrypto/IndexedDB is unavailable, errors, or
 * does not complete within the timeout — callers then omit the header and the session stays unbound.
 */
export async function createDpopProof(method: string, url: string): Promise<string | null> {
    try {
        if (typeof window === 'undefined' || !window.crypto?.subtle || !window.indexedDB) return null;
        return await Promise.race([
            buildProof(method, url),
            new Promise<null>((resolve) => setTimeout(() => resolve(null), PROOF_TIMEOUT_MS)),
        ]);
    } catch {
        return null;
    }
}
