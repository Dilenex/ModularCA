import type { RecordRevokedSerialsRequest, RevokeAllMissingSerialsRequest } from '@shared/generated';

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

/**
 * Whether a selection is every serial that can be recorded: that is not "the selected ones" but
 * revoke-all, which the server keeps as an act of its own. A list of one has no such difference.
 */
export function selectionIsWholeList(selected: MissingSerialRow[], rows: MissingSerialRow[]): boolean {
    const open = recordable(rows);
    if (open.length <= 1) return false;
    const chosen = new Set(recordable(selected).map((r) => r.serialNumber));
    return open.every((r) => chosen.has(r.serialNumber));
}

/** What the revoke-all dialog says and whether its button is enabled. */
export interface RevokeAllConfirmation {
    /** The CA whose serials are revoked; what the administrator has to type. */
    caName: string;
    /** How many serials will be revoked: those missing with no certificate held. */
    count: number;
    /** The CRL the signer published them on. */
    journaledCrlNumber: number | null;
    title: string;
    /** What is about to happen, a sentence each. */
    statements: string[];
    /** The label of the field the CA's name is typed into. */
    prompt: string;
    confirmLabel: string;
    /** True once the CA's name is typed exactly and a note is given. */
    canConfirm: boolean;
}

/**
 * The confirmation of revoke-all. The button stays disabled until the CA's name has been typed
 * exactly as shown (surrounding spaces aside) and a note says why. Null when there is nothing
 * to revoke.
 */
export function revokeAllConfirmation(answer: MissingFromCrl | null | undefined, caName: string, typed: string, note: string): RevokeAllConfirmation | null {
    const count = recordable(missingRows(answer)).length;
    if (count === 0 || !answer) return null;
    const plural = count === 1 ? '' : 's';
    const crl = answer.journaledCrlNumber;
    return {
        caName,
        count,
        journaledCrlNumber: crl,
        title: `Revoke all ${count} serial${plural}`,
        statements: [
            `This revokes ${count} serial${plural} for the certificate authority ${caName}.`,
            `They are revocations the signer already published${crl == null ? '' : ` on CRL number ${crl}`} for this CA, which its database no longer has.`,
            'Revoking cannot be undone: a serial recorded as revoked without its certificate stays revoked.',
        ],
        prompt: `Type the name of the certificate authority to confirm: ${caName}`,
        confirmLabel: `Revoke all ${count} serial${plural}`,
        canConfirm: caName.trim().length > 0 && typed.trim() === caName.trim() && note.trim().length > 0,
    };
}

/**
 * The revoke-all request: what was shown and confirmed, and no serial. The server works the
 * list out again and refuses when the count or the CRL number is no longer the same.
 */
export function revokeAllBody(answer: MissingFromCrl, note: string): RevokeAllMissingSerialsRequest {
    return {
        confirmedCount: recordable(missingRows(answer)).length,
        journaledCrlNumber: answer.journaledCrlNumber ?? 0,
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
