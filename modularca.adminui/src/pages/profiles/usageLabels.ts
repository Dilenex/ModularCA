/** Display labels for the extended key usages the console knows by OID. */
export const DEFAULT_EKU_LABELS: Record<string, string> = {
    '1.3.6.1.5.5.7.3.1': 'Server Auth',
    '1.3.6.1.5.5.7.3.2': 'Client Auth',
    '1.3.6.1.5.5.7.3.3': 'Code Signing',
    '1.3.6.1.5.5.7.3.4': 'Email Protection',
    '1.3.6.1.5.5.7.3.8': 'Time Stamping',
    '1.3.6.1.5.5.7.3.9': 'OCSP Signing',
    '1.3.6.1.4.1.311.20.2.2': 'Smart Card Logon',
    '1.3.6.1.5.2.3.5': 'KDC Authentication',
};

/**
 * Display labels for the nine key usages.
 *
 * Presentation only — never persist these. `canonicalizeUsage` maps every one of them back onto
 * its canonical value, so a profile written with a label by an older build still resolves.
 */
export const KEY_USAGE_LABELS: Record<string, string> = {
    digitalSignature: 'Digital Signature',
    nonRepudiation: 'Non Repudiation',
    keyEncipherment: 'Key Encipherment',
    dataEncipherment: 'Data Encipherment',
    keyAgreement: 'Key Agreement',
    keyCertSign: 'Key Cert Sign',
    crlSign: 'CRL Sign',
    encipherOnly: 'Encipher Only',
    decipherOnly: 'Decipher Only',
};
