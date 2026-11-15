/**
 * A certificate serial number as people read it: whole octets, so with a leading zero when the
 * stored form has an odd number of hex digits. The server stores a serial as minimal hex
 * (`2C06…`); OpenSSL and most other tools print the octets (`02C06…`). The consoles show the
 * second form, so a serial read here matches one read anywhere else.
 *
 * For display, copying and export only. Links and API calls keep the stored form; the server
 * takes either when a serial is typed or pasted.
 *
 * Not for SSH certificate serials, which are decimal numbers.
 */
export function displaySerial(serial: string | null | undefined): string {
    if (!serial) return '';
    if (!/^[0-9a-fA-F]+$/.test(serial)) return serial;
    return serial.length % 2 === 1 ? `0${serial}` : serial;
}
