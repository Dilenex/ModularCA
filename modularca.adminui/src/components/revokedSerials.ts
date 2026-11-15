import type { AdoptCertificateRequest, RecordRevokedSerialRequest } from '@shared/generated';

/** One serial recorded as revoked with no certificate behind it, as the list endpoint returns it. */
export interface RevokedSerialRow {
    id: string;
    serialNumber: string;
    issuerDN: string;
    reason: string;
    revocationDate: string;
    invalidityDate: string | null;
    listedUntil: string;
    /** False once listedUntil has passed and the CRL no longer carries the entry. */
    onCrl: boolean;
    note: string;
    recordedBy: string;
}

/** The longest serial in hex digits: twenty octets (RFC 5280 4.1.2.2). */
const MAX_SERIAL_HEX = 40;

/** The serial as the server stores it: separators and leading zeros removed, upper case. */
export function normalizeSerial(serial: string): string {
    const cleaned = serial.replace(/[\s:-]/g, '').toUpperCase().replace(/^0+/, '');
    return cleaned.length > 0 ? cleaned : (serial.trim() ? '0' : '');
}

/**
 * The audit list filtered to the records that name one revoked serial: the record of the serial
 * itself, or a batch record that carries it among many (a large merge from the signer's journal,
 * a revoke-all).
 */
export function auditPathForSerial(serial: string): string {
    return `/audit?serial=${encodeURIComponent(normalizeSerial(serial))}`;
}

/** Why the serial as typed cannot be recorded, or null when it can. The server checks the same. */
export function serialProblem(serial: string): string | null {
    const normalized = normalizeSerial(serial);
    if (!normalized) return 'A serial number is required.';
    if (!/^[0-9A-F]+$/.test(normalized)) return 'The serial number must be hexadecimal, as the certificate shows it.';
    if (normalized === '0') return 'A serial number is a positive number.';
    if (normalized.length > MAX_SERIAL_HEX) return 'The serial number is longer than the twenty octets a certificate serial can have.';
    return null;
}

/** The request body that records a serial as revoked. */
export function tombstoneBody(serial: string, reason: string, note: string): RecordRevokedSerialRequest {
    return { serialNumber: normalizeSerial(serial), reason: reason as RecordRevokedSerialRequest['reason'], note: note.trim() };
}

/** The request body that adopts a certificate; a null reason adopts it as good. */
export function adoptionBody(certificate: string, note: string, revokeReason: string | null): AdoptCertificateRequest {
    const body: AdoptCertificateRequest = { certificate: certificate.trim(), note: note.trim() };
    if (revokeReason) body.revokeReason = revokeReason as AdoptCertificateRequest['revokeReason'];
    return body;
}
