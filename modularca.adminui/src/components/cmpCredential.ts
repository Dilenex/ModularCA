/**
 * Pure helpers behind the CMP shared-secret credential form on the Enrollment page.
 *
 * A CMP credential is an enrollment-token row that carries a reference value (the CMP
 * senderKID) and a PBMAC secret instead of a bearer token. The list endpoint deliberately
 * omits the secret and the token column for those rows, so the table needs a different
 * label for them, and the one-time panel after creation needs to hand the operator something
 * a client can run.
 */

export interface TokenRowLike {
    token?: string | null;
    usedForCmp?: boolean;
    cmpReferenceValue?: string | null;
    lastFourOfToken?: string | null;
}

export interface SigningProfileLike {
    id: string;
    name: string;
    issuer?: { subjectDN?: string | null } | null;
    isDefault?: boolean;
}

/** True for rows that are CMP credentials rather than bearer tokens. */
export function isCmpCredentialRow(t: TokenRowLike): boolean {
    return t.usedForCmp === true;
}

/**
 * The short label the table shows in the Token column. Bearer tokens show their prefix; CMP
 * rows show the reference value, since the secret is never returned and the reference is what
 * a client is configured with.
 */
export function tokenColumnLabel(t: TokenRowLike): string {
    if (isCmpCredentialRow(t)) {
        return `CMP · ${t.cmpReferenceValue || '(no reference)'}`;
    }
    const token = t.token || '';
    return token.length > 20 ? `${token.substring(0, 20)}…` : token;
}

/** The drawer title for a row. */
export function drawerTitle(t: TokenRowLike): string {
    if (isCmpCredentialRow(t)) {
        return `CMP credential ${t.cmpReferenceValue || ''}`.trim();
    }
    const token = t.token || '';
    return `Token ${token.substring(0, 12)}…`;
}

/** Option label for a signing profile: the name, and the issuing CA when the API supplied it. */
export function signingProfileLabel(p: SigningProfileLike): string {
    const cn = p.issuer?.subjectDN ? commonNameOf(p.issuer.subjectDN) : null;
    return cn ? `${p.name} — ${cn}` : p.name;
}

/** Extracts the CN from a DN string, or the whole DN when it has none. */
export function commonNameOf(dn: string): string {
    const m = /(?:^|,)\s*CN=([^,]+)/i.exec(dn);
    return m ? m[1].trim() : dn;
}

/**
 * The reference value must be usable as a CMP senderKID and as a shell argument. RFC 4210 puts
 * no constraint on it beyond being an octet string, but a value with whitespace or quotes
 * would need escaping in every client configuration that carries it.
 */
export function validateReferenceValue(value: string): string | null {
    const v = value.trim();
    if (v.length === 0) return 'Reference value is required.';
    if (v.length > 64) return 'Reference value must be 64 characters or fewer.';
    if (!/^[A-Za-z0-9._:@-]+$/.test(v)) return 'Use letters, digits, and . _ : @ - only.';
    return null;
}

/**
 * An initial-request command a device operator can paste. The secret is a placeholder: the
 * panel shows it separately once, and a command line is the wrong place for it.
 */
export function buildOpensslCmpCommand(origin: string, caLabel: string | null, referenceValue: string): string {
    const label = caLabel || '<ca-label>';
    return [
        'openssl cmp -cmd ir',
        `  -server ${origin}/cmp/${label}`,
        `  -ref "${referenceValue}" -secret "pass:<shared secret>"`,
        '  -subject "/CN=device.example.test"',
        '  -newkey device.key -certout device.crt',
    ].join(' \\\n');
}
