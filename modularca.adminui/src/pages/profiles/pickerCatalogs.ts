import type { CheckboxGroup, CheckboxOption } from '@shared/components/checkboxListModel';

/*
 * Option lists for the usage, EKU and SSH extension checkboxes. No React here, so
 * tests/modularca.web.tests can cover the grouping.
 */

/** One line per key usage, keyed by the canonical name stored in the profile. */
export const KEY_USAGE_DESCRIPTIONS: Readonly<Record<string, string>> = {
    digitalSignature: 'Signatures other than on certificates and CRLs, such as TLS handshakes and documents.',
    nonRepudiation: 'Content commitment: signatures meant as a binding statement by the signer.',
    keyEncipherment: 'Encrypts keys, as RSA key transport does.',
    dataEncipherment: 'Encrypts data directly with the public key. Rarely needed.',
    keyAgreement: 'Key agreement, as ECDH does.',
    keyCertSign: 'Signs certificates. CA certificates only.',
    crlSign: 'Signs certificate revocation lists.',
    encipherOnly: 'With Key Agreement: the agreed key may only encrypt.',
    decipherOnly: 'With Key Agreement: the agreed key may only decrypt.',
};

/** One line per well-known EKU, keyed by OID. */
export const EKU_DESCRIPTIONS: Readonly<Record<string, string>> = {
    '1.3.6.1.5.5.7.3.1': 'TLS server: identifies a web or service endpoint.',
    '1.3.6.1.5.5.7.3.2': 'TLS client: the holder authenticates to a server (mTLS, VPN, 802.1X).',
    '1.3.6.1.5.5.7.3.3': 'Signs software, drivers and scripts.',
    '1.3.6.1.5.5.7.3.4': 'S/MIME: signs and encrypts email.',
    '1.3.6.1.5.5.7.3.8': 'Signs RFC 3161 time-stamp tokens.',
    '1.3.6.1.5.5.7.3.9': 'Signs OCSP responses on behalf of the CA.',
    '1.3.6.1.5.5.7.3.36': 'Signs documents (RFC 9336).',
    '1.3.6.1.4.1.311.10.3.12': 'Signs Microsoft Office documents.',
    '1.3.6.1.4.1.311.20.2.2': 'Windows smart-card logon, on the card holder\'s certificate.',
    '1.3.6.1.5.2.3.5': 'Kerberos PKINIT, on the domain controller\'s certificate.',
};

const EKU_GROUPS: readonly { id: string; label: string; oids: readonly string[] }[] = [
    { id: 'tls', label: 'TLS', oids: ['1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2'] },
    { id: 'signing', label: 'Code and document signing', oids: ['1.3.6.1.5.5.7.3.3', '1.3.6.1.5.5.7.3.4', '1.3.6.1.5.5.7.3.8', '1.3.6.1.5.5.7.3.36', '1.3.6.1.4.1.311.10.3.12'] },
    { id: 'logon', label: 'Smart card and Kerberos', oids: ['1.3.6.1.4.1.311.20.2.2', '1.3.6.1.5.2.3.5'] },
];

/** Key usage options in the order given, with their descriptions. */
export const keyUsageOptions = (values: readonly string[], label: (v: string) => string): CheckboxOption[] =>
    values.map((v) => ({ value: v, label: label(v), description: KEY_USAGE_DESCRIPTIONS[v] }));

/**
 * Groups EKU OIDs as TLS, signing, smart card and Kerberos, and other. Anything the catalog holds
 * that no group names (OCSP signing, custom OIDs) lands in Other, in catalog order. Empty groups
 * are left out.
 */
export const groupEkuOptions = (oids: readonly string[], label: (oid: string) => string): CheckboxGroup[] => {
    const option = (oid: string): CheckboxOption => ({ value: oid, label: label(oid), detail: oid, description: EKU_DESCRIPTIONS[oid] });
    const placed = new Set<string>();
    const groups: CheckboxGroup[] = [];
    for (const g of EKU_GROUPS) {
        const members = oids.filter((o) => g.oids.includes(o));
        members.forEach((o) => placed.add(o));
        if (members.length) groups.push({ id: g.id, label: g.label, options: members.map(option) });
    }
    const rest = oids.filter((o) => !placed.has(o));
    if (rest.length) groups.push({ id: 'other', label: 'Other', options: rest.map(option) });
    return groups;
};

/**
 * Splits SSH extensions into the names a certificate carries and the no-* names, which add
 * nothing and only withhold the matching permit-*. no-touch-required is an extension in its own
 * right, so it sits with the names a certificate carries.
 */
export const groupSshExtensions = (
    extensions: readonly string[],
    describe: (ext: string) => string | undefined,
    tone?: (ext: string) => 'warn' | undefined,
): CheckboxGroup[] => {
    const option = (ext: string): CheckboxOption => ({ value: ext, label: ext, description: describe(ext), tone: tone?.(ext) });
    const withholds = (e: string) => e.startsWith('no-') && e !== 'no-touch-required';
    const permit = extensions.filter((e) => !withholds(e));
    const deny = extensions.filter(withholds);
    return [
        { id: 'permit', label: 'Permit', options: permit.map(option) },
        { id: 'deny', label: 'Withhold', options: deny.map(option) },
    ].filter((g) => g.options.length > 0);
};
