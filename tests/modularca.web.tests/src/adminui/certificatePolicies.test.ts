import { describe, expect, it } from 'vitest';
import cases from '../common/certificate-policy-cases.json';
import { validateOid } from '@shared/validators';
import {
    MAX_USER_NOTICE_LENGTH, POLICY_SUGGESTIONS, policiesFromStored, policiesToFields, policyLabel, policyRowsInvalid,
    validateCpsUri, validateUserNotice,
} from '@adminui/pages/profiles/certificatePolicies';

/**
 * The signing profile's Certificate Policies table. The per-value checks must agree with the
 * server's CertificatePolicyRules (shared cases in certificate-policy-cases.json, also read by
 * CertificatePolicyRulesTests); the load and save must round-trip the two stored fields, read the
 * per-OID critical flags as the one extension-wide checkbox, and drop what the server never used.
 */
describe('certificate policies: parity with CertificatePolicyRules', () => {
    it.each(cases.oid.accept)('accepts the OID %s', (oid) => expect(validateOid(oid)).toBeNull());
    it.each(cases.oid.reject)('refuses the OID %s', (oid) => expect(validateOid(oid)).not.toBeNull());
    it.each(cases.cpsUri.accept)('accepts the CPS URI %s', (uri) => expect(validateCpsUri(uri)).toBeNull());
    it.each(cases.cpsUri.reject)('refuses the CPS URI %s', (uri) => expect(validateCpsUri(uri)).not.toBeNull());
    it.each(cases.userNotice.accept)('accepts the notice %s', (text) => expect(validateUserNotice(text)).toBeNull());
    it.each(cases.userNotice.reject)('refuses the notice %j', (text) => expect(validateUserNotice(text)).not.toBeNull());

    it('caps a user notice at 200 characters, as the server does', () => {
        expect(MAX_USER_NOTICE_LENGTH).toBe(cases.userNotice.maxLength);
        expect(validateUserNotice('x'.repeat(200))).toBeNull();
        expect(validateUserNotice('x'.repeat(201))).toMatch(/200/);
    });
});

describe('certificate policies: load and save', () => {
    const oids = '["2.23.140.1.2.1","1.3.6.1.4.1.66874.1.1"]';

    it('round-trips OIDs and qualifiers', () => {
        const quals = '{"2.23.140.1.2.1":{"cpsUri":"https://example.com/cps","userNotice":"See the CPS."}}';
        const loaded = policiesFromStored(oids, quals);
        expect(loaded.notices).toEqual([]);
        expect(loaded.critical).toBe(false);
        expect(loaded.rows).toEqual([
            { oid: '2.23.140.1.2.1', cpsUri: 'https://example.com/cps', userNotice: 'See the CPS.' },
            { oid: '1.3.6.1.4.1.66874.1.1', cpsUri: '', userNotice: '' },
        ]);
        const out = policiesToFields(loaded);
        expect(JSON.parse(out.policyOids)).toEqual(JSON.parse(oids));
        expect(JSON.parse(out.policyQualifiersJson)).toEqual(JSON.parse(quals));
        expect(policiesFromStored(out.policyOids, out.policyQualifiersJson)).toEqual(loaded);
    });

    it('reads any critical entry as the extension-wide checkbox and writes it on every policy', () => {
        const loaded = policiesFromStored(oids, '{"1.3.6.1.4.1.66874.1.1":{"critical":true},"2.23.140.1.2.1":{"critical":false}}');
        expect(loaded.critical).toBe(true);
        const out = JSON.parse(policiesToFields(loaded).policyQualifiersJson);
        expect(out).toEqual({ '2.23.140.1.2.1': { critical: true }, '1.3.6.1.4.1.66874.1.1': { critical: true } });
        expect(JSON.parse(policiesToFields({ ...loaded, critical: false }).policyQualifiersJson)).toEqual({});
    });

    it('keeps the criticality of an entry for an unlisted OID, since the server honoured it, but drops the entry', () => {
        const loaded = policiesFromStored('["2.23.140.1.2.1"]', '{"1.2.3.4":{"cpsUri":"https://x.example/cps","critical":true}}');
        expect(loaded.critical).toBe(true);
        expect(loaded.rows).toEqual([{ oid: '2.23.140.1.2.1', cpsUri: '', userNotice: '' }]);
        expect(loaded.notices).toHaveLength(1);
        expect(loaded.notices[0]).toMatch(/1\.2\.3\.4/);
        expect(JSON.parse(policiesToFields(loaded).policyQualifiersJson)).toEqual({ '2.23.140.1.2.1': { critical: true } });
    });

    it('drops keys the server does not read, values of the wrong type, and non-object entries, with a notice each', () => {
        const loaded = policiesFromStored('["2.23.140.1.2.1","2.23.140.1.2.2"]', JSON.stringify({
            '2.23.140.1.2.1': { CpsUri: 'https://x.example/cps', userNotice: 5, critical: 'yes' },
            '2.23.140.1.2.2': 'https://x.example/cps',
        }));
        expect(loaded.rows.every((r) => !r.cpsUri && !r.userNotice)).toBe(true);
        expect(loaded.critical).toBe(false);
        expect(loaded.notices).toHaveLength(4);
        expect(loaded.notices.join(' ')).toMatch(/CpsUri/);
        expect(policiesToFields(loaded).policyQualifiersJson).toBe('{}');
    });

    it('drops qualifiers that are not a JSON object', () => {
        for (const junk of ['{', '[]', '"text"']) {
            const loaded = policiesFromStored(oids, junk);
            expect(loaded.rows).toHaveLength(2);
            expect(loaded.notices).toHaveLength(1);
        }
        expect(policiesFromStored(oids, '').notices).toEqual([]);
        expect(policiesFromStored(oids, null).notices).toEqual([]);
        expect(policiesFromStored(oids, { '2.23.140.1.2.1': { cpsUri: 'https://x.example/cps' } }).rows[0].cpsUri).toBe('https://x.example/cps');
    });

    it('lists a duplicated OID once, with a notice', () => {
        const loaded = policiesFromStored('["2.23.140.1.2.1","2.23.140.1.2.1"]', null);
        expect(loaded.rows).toHaveLength(1);
        expect(loaded.notices).toHaveLength(1);
    });

    it('keeps an invalid stored OID as a row so it is marked, not silently dropped', () => {
        const loaded = policiesFromStored('["not-an-oid"]', null);
        expect(loaded.rows.map((r) => r.oid)).toEqual(['not-an-oid']);
        expect(policyRowsInvalid(loaded.rows)).toBe(true);
    });

    it('trims values and drops blank rows on save', () => {
        const out = policiesToFields({
            rows: [{ oid: ' 2.23.140.1.2.1 ', cpsUri: ' https://x.example/cps ', userNotice: '  Hi  ' }, { oid: '', cpsUri: '', userNotice: '' }],
            critical: false,
        });
        expect(out.policyOids).toBe('["2.23.140.1.2.1"]');
        expect(out.policyQualifiersJson).toBe('{"2.23.140.1.2.1":{"cpsUri":"https://x.example/cps","userNotice":"Hi"}}');
    });

    it('offers anyPolicy and the CA/B Forum policies, each a valid OID with a label', () => {
        expect(POLICY_SUGGESTIONS.map((s) => s.value)).toEqual(['2.5.29.32.0', '2.23.140.1.2.1', '2.23.140.1.2.2', '2.23.140.1.2.3', '2.23.140.1.1']);
        expect(POLICY_SUGGESTIONS.every((s) => validateOid(s.value) === null)).toBe(true);
        expect(policyLabel('2.23.140.1.1')).toMatch(/EV/);
    });
});
