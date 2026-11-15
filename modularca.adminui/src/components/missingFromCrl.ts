import type { RecordRevokedSerialsRequest } from '@shared/generated';

/** One serial a refused CRL left out, as `revoked-serials/missing-from-crl` returns it. */
export interface MissingSerialRow {
    serialNumber: string;
    /** The reason by the name the revocation request takes. */
    reason: string;
    reasonCode: number;
    /** The revocation date the journaled CRL gives. */
    revocationDate: string;
    /** Whether the CA still holds a certificate with this serial: it is then revoked on the certificate's page. */
    certificateHeld: boolean;
}

/** The answer of `revoked-serials/missing-from-crl`. */
export interface MissingFromCrl {
    caId: string;
    /** Whether the signer refused the CA's last full CRL and has not signed one since. */
    refused: boolean;
    refusedAtUtc: string | null;
    journaledCrlNumber: number | null;
    count: number;
    consolePath: string;
    serials: MissingSerialRow[];
}

/** The element id the console path's fragment names: the section is scrolled to when the page opens on it. */
export const MISSING_FROM_CRL_ANCHOR = 'missing-from-crl';

/** The rows to show; none when no refusal stands or the answer could not be read. */
export function missingRows(answer: MissingFromCrl | null | undefined): MissingSerialRow[] {
    if (!answer?.refused || !Array.isArray(answer.serials)) return [];
    return answer.serials;
}

/** The serials that can be recorded as revoked with no certificate: those the CA holds no certificate for. */
export function recordable(rows: MissingSerialRow[]): MissingSerialRow[] {
    return rows.filter((r) => !r.certificateHeld);
}

/**
 * The request that records the given serials as revoked, each with the reason the journaled CRL
 * gives. A hold cannot be recorded for a serial with no certificate, so it is sent as unspecified.
 */
export function bulkBody(rows: MissingSerialRow[], note: string): RecordRevokedSerialsRequest {
    return {
        serials: recordable(rows).map((r) => ({
            serialNumber: r.serialNumber,
            reason: (r.reason === 'CertificateHold' ? 'Unspecified' : r.reason) as RecordRevokedSerialsRequest['serials'][number]['reason'],
        })),
        note: note.trim(),
    };
}

/** The sentence above the list. */
export function missingSummary(rows: MissingSerialRow[]): string {
    const held = rows.length - recordable(rows).length;
    const plural = rows.length === 1 ? '' : 's';
    const where = held === 0
        ? 'This CA holds no certificate for any of them: revoke the serials here.'
        : held === rows.length
            ? 'This CA holds the certificate of each: revoke each on its own page.'
            : `This CA holds the certificate of ${held} of them, which are revoked on their own pages; the other ${rows.length - held} are revoked here.`;
    return `The signer refuses to sign this CA's CRL, because it would leave out ${rows.length} serial${plural} that the last CRL it signed lists as revoked. ${where}`;
}
