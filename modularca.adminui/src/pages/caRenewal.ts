/*
 * Renewing a CA's certificate over the key it has: what the console says will and will not
 * change, how a certificate in the CA's history is labeled, and when the action is offered.
 * The renewal itself is the server's (POST /api/v1/admin/authorities/{id}/renew-certificate).
 */

/** One certificate a CA has had, as `GET /api/v1/admin/authorities/{id}/certificates` lists it. */
export interface CaCertificateHistoryRow {
    certificateId: string;
    serialNumber: string;
    subjectDN?: string;
    issuer?: string;
    notBefore: string;
    notAfter: string;
    sha256?: string | null;
    keyId?: string | null;
    isCurrent: boolean;
    /** `Initial` or `Renewal`. */
    origin?: string;
    activatedAt?: string | null;
    supersededAt?: string | null;
    ceremonyId?: string | null;
    actor?: string | null;
    revoked?: boolean;
    expired?: boolean;
    pem?: string;
}

/** The validity a renewal may ask for, in years. The server applies the same bounds. */
export const RENEWAL_MIN_YEARS = 1;
export const RENEWAL_MAX_YEARS = 50;

/** Why the years field cannot be submitted, or null. */
export function renewalYearsProblem(years: unknown): string | null {
    const n = typeof years === 'number' ? years : Number(years);
    if (!Number.isInteger(n) || n < RENEWAL_MIN_YEARS || n > RENEWAL_MAX_YEARS)
        return `Enter a whole number of years from ${RENEWAL_MIN_YEARS} to ${RENEWAL_MAX_YEARS}.`;
    return null;
}

/**
 * Why a renewal could not extend this CA's certificate, or null when it could: a renewal has to
 * end after the current certificate, and may ask for at most 50 years. A certificate that
 * already runs further than that (the system signing CA's, as bootstrap makes it, runs 100
 * years) has nothing to renew yet, and the console says so instead of offering an action the
 * server would refuse.
 */
export function renewalCannotExtend(ca: any, now: Date = new Date()): string | null {
    const end = ca?.certificate?.notAfter ? new Date(ca.certificate.notAfter) : null;
    if (!end || Number.isNaN(end.getTime())) return null;
    const furthest = new Date(now.getTime());
    furthest.setUTCFullYear(furthest.getUTCFullYear() + RENEWAL_MAX_YEARS);
    if (end.getTime() < furthest.getTime()) return null;
    const firstYear = end.getUTCFullYear() - RENEWAL_MAX_YEARS + 1;
    return `This certificate already runs to ${end.toISOString().slice(0, 10)}. A renewal can only extend a certificate, by at most ${RENEWAL_MAX_YEARS} years from the day it is made, so there is nothing to renew before ${firstYear}. Nothing needs doing.`;
}

/** The fewest whole years a renewal has to ask for so that it ends after the current certificate. */
export function renewalMinimumYears(ca: any, now: Date = new Date()): number {
    const end = ca?.certificate?.notAfter ? new Date(ca.certificate.notAfter) : null;
    if (!end || Number.isNaN(end.getTime())) return RENEWAL_MIN_YEARS;
    for (let years = RENEWAL_MIN_YEARS; years <= RENEWAL_MAX_YEARS; years++) {
        const candidate = new Date(now.getTime());
        candidate.setUTCFullYear(candidate.getUTCFullYear() + years);
        if (candidate.getTime() > end.getTime()) return years;
    }
    return RENEWAL_MAX_YEARS;
}

/** Whether a CA is a root: it has no parent and signs its own certificate. */
export function isRootCa(ca: any): boolean {
    return !ca?.parentCaId;
}

/**
 * Why renewal is not offered for this CA, or null when it is. The server refuses the same
 * cases; saying so here spares a step-up prompt that could only end in a refusal.
 */
export function renewalUnavailable(ca: any): string | null {
    if (!ca?.certificate) return 'This CA has no certificate to renew.';
    if (ca.certificate.revoked)
        return 'This CA certificate is revoked. A revoked CA certificate is not renewed: its key is no longer trusted.';
    return null;
}

/** Whether a CA is the system signing CA, which signs the keystore files and issues nothing. */
export function isSystemSigningCa(ca: any): boolean {
    return String(ca?.label || '').toLowerCase() === 'system-signing-ca';
}

/** What a renewal keeps and what it changes, for the notice shown before it is confirmed. */
export function renewalEffects(ca: any): { stays: string[]; changes: string[]; after: string[] } {
    const root = isRootCa(ca);
    if (isSystemSigningCa(ca))
        return {
            stays: [
                'The key. No key is generated, moved or exported, and no keystore file is rewritten.',
                'Everything that is tied to the system key: the signatures and pins of the keystore files, the instance identifier, the key the hub knows this instance by, the signer journal\'s checkpoint key, and the wrapped settings and secrets.',
                'The subject name and every extension, copied from the current certificate.',
                'The earlier certificate. It stays valid until it expires and is not revoked.',
            ],
            changes: [
                'The serial number and the validity: the system signing CA gets a new certificate, signed by itself.',
            ],
            after: [
                'Nothing. No relying party holds this certificate: it issues nothing, and what it signs is checked against its key. No restart is needed.',
            ],
        };
    return {
        stays: [
            'The key. No key is generated, moved or exported.',
            'The subject name, the key identifiers, the path length, the key usage, the name constraints and the policies: every extension is copied from the current certificate.',
            'The CRL and OCSP addresses in the certificates this CA has issued. They name the CA by its label, and one CRL, signed by the same key, covers what was issued under either certificate.',
            'Every certificate this CA has issued. They validate under the new certificate and under the earlier one, which has the same name and key.',
            'The earlier certificate. It stays valid until it expires, stays downloadable at its serial, and is not revoked.',
            'Subordinate CAs. Their certificates are not renewed and keep validating.',
        ],
        changes: [
            'The serial number and the validity: the CA gets a new certificate.',
            root
                ? 'The certificate is signed by this CA itself, as a root\'s is.'
                : 'The certificate is signed by the parent CA, and cannot end after the parent\'s certificate does.',
            'From now on this CA issues under the new certificate, and its public address serves the new certificate.',
        ],
        after: root
            ? [
                'Give the new root certificate to everyone who trusts the old one: operating system and browser trust stores, devices, ACME, EST and SCEP clients, anything that pins the root. This product cannot do that for you. A relying party that keeps only the old certificate stops validating when the old certificate expires.',
                'Reissue the OCSP responder, TSA and CMP signer certificates under Infrastructure Certificates: they were issued to end no later than the earlier certificate.',
            ]
            : [
                'Nothing has to be redistributed to those who trust the root. Clients that were given this CA\'s certificate as part of a chain receive the new one with their next certificate; servers that present a stored chain keep working with the earlier one until it expires.',
                'Reissue the OCSP responder, TSA and CMP signer certificates under Infrastructure Certificates: they were issued to end no later than the earlier certificate.',
            ],
    };
}

/** Common practice, not a standard's requirement: a root is valid for up to this many years. */
export const COMMON_ROOT_VALIDITY_YEARS = 25;
/** And an intermediate for up to this many. */
export const COMMON_INTERMEDIATE_VALIDITY_YEARS = 10;
/** The reason the server asks the administrator to acknowledge before renewing an RSA key under 3072 bits past 2030. */
export const RSA_PAST_2030 = 'CaRsaKeyBelow3072Past2030';

/** One thing to know about the validity chosen for a CA certificate. */
export interface ValidityNote {
    reason: string;
    /** `warning` has to be acknowledged before a renewal goes ahead; `notice` is said and nothing more. */
    severity: 'notice' | 'warning';
    message: string;
}

/**
 * What the console says about a validity of `years` for a root or an intermediate CA certificate,
 * in a creation or a renewal dialog. `rsaBelow3072` is whether the CA's existing key is RSA under
 * 3072 bits (a renewal only: a new CA cannot have one). The server decides; this words the same
 * rule before anything is sent. Neither note refuses anything, and neither is a standard's
 * requirement for a private PKI.
 */
export function validityNotes(root: boolean, years: unknown, rsaBelow3072 = false, now: Date = new Date()): ValidityNote[] {
    const n = typeof years === 'number' ? years : Number(years);
    if (!Number.isFinite(n) || n <= 0) return [];
    const notes: ValidityNote[] = [];
    const end = new Date(now.getTime());
    end.setUTCFullYear(end.getUTCFullYear() + n);
    if (rsaBelow3072 && end.getTime() > Date.UTC(2030, 11, 31, 23, 59, 59))
        notes.push({
            reason: RSA_PAST_2030,
            severity: 'warning',
            message: `This CA's key is RSA under 3072 bits, and the new certificate would be valid until ${end.toISOString().slice(0, 4)}. NIST SP 800-57 accepts such keys only through 2030, so a certificate that runs past 2030 says the key may be relied on longer than that. It can be issued, because the CA has to stay in service while its replacement is prepared; choose a validity that ends by 2030 if you can, and plan the replacement either way.`,
        });
    const common = root ? COMMON_ROOT_VALIDITY_YEARS : COMMON_INTERMEDIATE_VALIDITY_YEARS;
    if (n > common)
        notes.push({
            reason: 'CaValidityBeyondCommonPractice',
            severity: 'notice',
            message: `More than ${common} years is longer than common practice for ${root ? 'a root' : 'an intermediate'} CA (${root ? '10 to 25' : '5 to 10'} years). No standard that binds a private CA sets a limit, so nothing is refused; a longer validity means the key is relied on for longer, and the certificate can be renewed later instead.`,
        });
    return notes;
}

/** Whether the hierarchy feed says this CA's key is RSA under 3072 bits. */
export function hasRsaBelow3072(ca: any): boolean {
    return Array.isArray(ca?.keyAdvisories) && ca.keyAdvisories.some((a: any) => a?.reason === 'CaRsaKeyBelow3072');
}

/** The badge of a certificate in the CA's history. Color says status only. */
export function historyBadge(row: Pick<CaCertificateHistoryRow, 'isCurrent' | 'revoked' | 'expired'>): { status: 'active' | 'revoked' | 'expired' | 'disabled'; label: string } {
    if (row.revoked) return { status: 'revoked', label: 'Revoked' };
    if (row.expired) return { status: 'expired', label: row.isCurrent ? 'Current, expired' : 'Expired' };
    if (row.isCurrent) return { status: 'active', label: 'Current' };
    return { status: 'disabled', label: 'Earlier, still valid' };
}

/** How a certificate became the CA's, in words. */
export function originLabel(origin: string | undefined): string {
    return origin === 'Renewal' ? 'Renewal (same key)' : 'First certificate';
}

/** The file name a certificate from the history downloads under. */
export function historyFileName(ca: any, row: Pick<CaCertificateHistoryRow, 'serialNumber'>): string {
    const base = String(ca?.label || ca?.name || 'ca').toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '') || 'ca';
    return `${base}-${row.serialNumber.toLowerCase()}.pem`;
}
