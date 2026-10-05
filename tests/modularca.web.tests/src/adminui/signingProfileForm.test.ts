import { describe, expect, it } from 'vitest';
import type { CreateSigningProfileRequest, UpdateSigningProfileRequest } from '@shared/generated';
import {
    ALGORITHMS_EMPTY_REASON, EKUS_EMPTY_REASON, ISSUER_REASON, NAME_CONSTRAINTS_REASON, POLICIES_REASON, emptyForm, formFromProfile, formToCreateBody, formToUpdateBody,
    validate,
} from '@adminui/pages/profiles/signingProfile';
import { INHERITANCE_REASON, NAME_REQUIRED_REASON } from '@adminui/pages/profiles/profileFormCore';
import { bodyKeys, dtoKeys, jsonList } from './profileFormKit';

/**
 * The signing profile form model behind /profiles/signing/new and /profiles/signing/:id. The old
 * create panel had no inheritance fields and linked allowed cert profiles with a second, step-up
 * gated call; the one model carries all of it in the body both endpoints accept.
 */

const CREATE_KEYS = dtoKeys<CreateSigningProfileRequest>({
    name: true, description: true, allowedAlgorithms: true, allowedEKUs: true, isDefault: true,
    issuerId: true, maxPathLength: true, nameConstraintsPermitted: true, nameConstraintsExcluded: true,
    policyOids: true, inhibitAnyPolicy: true, allowedCertProfileIds: true, inheritsFromId: true,
    inheritanceEnabled: true, extendedKeyUsageCritical: true, policyQualifiersJson: true,
});
const UPDATE_KEYS = dtoKeys<UpdateSigningProfileRequest>({
    name: true, description: true, allowedAlgorithms: true, allowedEKUs: true, isDefault: true,
    issuerId: true, maxPathLength: true, nameConstraintsPermitted: true, nameConstraintsExcluded: true,
    policyOids: true, inhibitAnyPolicy: true, allowedCertProfileIds: true, inheritsFromId: true,
    inheritanceEnabled: true, extendedKeyUsageCritical: true, policyQualifiersJson: true,
});

const qualifiers = '{"2.23.140.1.2.1":{"cpsUri":"https://example.com/cps"}}';
const allowedIds = ['0b6f3f0e-4444-4c4c-9a9a-000000000004', '0b6f3f0e-5555-4c4c-9a9a-000000000005'];

/** A profile as GET /api/v1/admin/signing-profiles returns it, every settable field off its default. */
const stored = {
    id: '0b6f3f0e-1111-4c4c-9a9a-000000000001',
    name: 'Issuing CA signer',
    description: 'Signs leaf certificates',
    allowedAlgorithms: '["RSA","ECDSA"]',
    allowedEKUs: '["1.3.6.1.5.5.7.3.1","1.3.6.1.5.5.7.3.2"]',
    extendedKeyUsageCritical: true,
    policyQualifiersJson: qualifiers,
    isDefault: true,
    issuerId: '0b6f3f0e-2222-4c4c-9a9a-000000000002',
    maxPathLength: 0,
    nameConstraintsPermitted: '["DNS:example.com"]',
    nameConstraintsExcluded: '["DNS:bad.example.com"]',
    policyOids: '["2.23.140.1.2.1","1.2.3.4"]',
    inhibitAnyPolicy: true,
    inheritsFromId: '0b6f3f0e-3333-4c4c-9a9a-000000000003',
    inheritanceEnabled: true,
    allowedCertProfileIds: allowedIds,
};

describe('signing profile form: shape', () => {
    it('posts exactly the CreateSigningProfileRequest fields from an empty form', () => {
        const body = formToCreateBody(emptyForm());
        expect(bodyKeys(body)).toEqual(CREATE_KEYS);
        expect(body).toEqual({
            name: '', description: '', allowedAlgorithms: '[]', allowedEKUs: '[]', isDefault: false,
            issuerId: null, maxPathLength: null, nameConstraintsPermitted: null, nameConstraintsExcluded: null,
            policyOids: '[]', inhibitAnyPolicy: false, allowedCertProfileIds: [], inheritsFromId: null,
            inheritanceEnabled: false, extendedKeyUsageCritical: false, policyQualifiersJson: '{}',
        });
    });

    it('puts exactly the UpdateSigningProfileRequest fields', () => {
        expect(bodyKeys(formToUpdateBody(formFromProfile(stored)))).toEqual(UPDATE_KEYS);
    });

    it('carries the allowed cert profiles in the create body itself', () => {
        const body = formToCreateBody({ ...emptyForm(), name: 'S', issuerId: 'ca', allowedCertProfileIds: allowedIds });
        expect(body.allowedCertProfileIds).toEqual(allowedIds);
    });
});

describe('signing profile form: round trip', () => {
    it('preserves every field of a stored profile through load and save', () => {
        const body = formToUpdateBody(formFromProfile(stored));
        expect(body.name).toBe(stored.name);
        expect(body.description).toBe(stored.description);
        expect(jsonList(body.allowedAlgorithms)).toEqual(jsonList(stored.allowedAlgorithms));
        expect(jsonList(body.allowedEKUs)).toEqual(jsonList(stored.allowedEKUs));
        expect(body.extendedKeyUsageCritical).toBe(true);
        expect(JSON.parse(String(body.policyQualifiersJson))).toEqual(JSON.parse(qualifiers));
        expect(body.isDefault).toBe(true);
        expect(body.issuerId).toBe(stored.issuerId);
        expect(body.maxPathLength).toBe(0);
        expect(body.nameConstraintsPermitted).toBe(stored.nameConstraintsPermitted);
        expect(body.nameConstraintsExcluded).toBe(stored.nameConstraintsExcluded);
        expect(jsonList(body.policyOids)).toEqual(jsonList(stored.policyOids));
        expect(body.inhibitAnyPolicy).toBe(true);
        expect(body.inheritsFromId).toBe(stored.inheritsFromId);
        expect(body.inheritanceEnabled).toBe(true);
        expect(body.allowedCertProfileIds).toEqual(allowedIds);
    });

    it('is stable: a saved body loads back into the same form', () => {
        const form = formFromProfile(stored);
        expect(formFromProfile(formToUpdateBody(form))).toEqual(form);
    });

    it('prefers the links fetched from allowed-cert-profiles over the row', () => {
        expect(formFromProfile(stored, undefined, ['only']).allowedCertProfileIds).toEqual(['only']);
    });

    it('reads the camelCase wire name allowedEKUs', () => {
        expect(formFromProfile({ allowedEKUs: '["1.3.6.1.5.5.7.3.4"]' }).allowedEkus).toEqual(['1.3.6.1.5.5.7.3.4']);
    });

    it('keeps a verbatim comma-separated algorithm list', () => {
        expect(formFromProfile({ allowedAlgorithms: 'RSA, Ed25519' }).allowedAlgorithms).toEqual(['RSA', 'Ed25519']);
    });

    it('clears an emptied max path length rather than sending zero', () => {
        expect(formToUpdateBody({ ...formFromProfile(stored), maxPathLength: '' }).maxPathLength).toBeNull();
    });
});

describe('signing profile form: validation', () => {
    it('needs a name and an issuer in both modes', () => {
        expect(validate(emptyForm(), 'create')).toEqual([NAME_REQUIRED_REASON, ISSUER_REASON]);
        expect(validate({ ...emptyForm(), name: 'S' }, 'edit')).toEqual([ISSUER_REASON]);
    });

    it('blocks an inconsistent inheritance pair', () => {
        const ok = { ...emptyForm(), name: 'S', issuerId: 'ca' };
        expect(validate({ ...ok, inheritsFromId: 'p' }, 'create')).toEqual([INHERITANCE_REASON]);
        expect(validate({ ...ok, inheritanceEnabled: true }, 'edit')).toEqual([INHERITANCE_REASON]);
    });

    it('blocks certificate policies the server would refuse, and ignores blank rows', () => {
        const ok = { ...emptyForm(), name: 'S', issuerId: 'ca' };
        const row = (oid: string, cpsUri = '', userNotice = '') => ({ oid, cpsUri, userNotice });
        expect(validate({ ...ok, policies: [row('1.2.840.x')] }, 'create')).toEqual([POLICIES_REASON]);
        expect(validate({ ...ok, policies: [row('2.23.140.1.2.1', 'ftp://example.com/cps')] }, 'edit')).toEqual([POLICIES_REASON]);
        expect(validate({ ...ok, policies: [row('2.23.140.1.2.1'), row('2.23.140.1.2.1')] }, 'edit')).toEqual([POLICIES_REASON]);
        expect(validate({ ...ok, policies: [row('', 'https://example.com/cps')] }, 'edit')).toEqual([POLICIES_REASON]);
        expect(validate({ ...ok, policies: [row('')] }, 'edit')).toEqual([]);
        expect(validate({ ...ok, policies: [row('2.23.140.1.2.1', 'https://example.com/cps', 'Relying party agreement applies.')] }, 'edit')).toEqual([]);
    });

    it('blocks name constraints the server would refuse, and ignores blank rows', () => {
        const ok = { ...emptyForm(), name: 'S', issuerId: 'ca' };
        expect(validate({ ...ok, nameConstraintsPermitted: [{ type: 'IP', value: '10.0.0.1' }] }, 'create')).toEqual([NAME_CONSTRAINTS_REASON]);
        expect(validate({ ...ok, nameConstraintsExcluded: [{ type: 'EMAIL', value: '@example.com' }] }, 'edit')).toEqual([NAME_CONSTRAINTS_REASON]);
        expect(validate({ ...ok, nameConstraintsPermitted: [{ type: 'DNS', value: '' }] }, 'edit')).toEqual([]);
    });

    it('loads stored name constraints as rows and saves them in the server spelling', () => {
        const form = formFromProfile({ ...stored, nameConstraintsPermitted: '["dns:.example.com","Email:example.com"]' });
        expect(form.nameConstraintsPermitted).toEqual([{ type: 'DNS', value: '.example.com' }, { type: 'EMAIL', value: 'example.com' }]);
        expect(formToUpdateBody(form).nameConstraintsPermitted).toBe('["DNS:.example.com","EMAIL:example.com"]');
        expect(formToUpdateBody({ ...form, nameConstraintsPermitted: [] }).nameConstraintsPermitted).toBeNull();
    });

    it('blocks Only these with no algorithm ticked', () => {
        const ok = { ...emptyForm(), name: 'S', issuerId: 'ca' };
        expect(validate({ ...ok, allowedAlgorithmsMode: 'only' }, 'create')).toEqual([ALGORITHMS_EMPTY_REASON]);
        expect(validate({ ...ok, allowedAlgorithmsMode: 'only', allowedAlgorithms: ['RSA'] }, 'edit')).toEqual([]);
    });

    it('blocks Only these with no EKU ticked', () => {
        const ok = { ...emptyForm(), name: 'S', issuerId: 'ca' };
        expect(validate({ ...ok, allowedEkusMode: 'only' }, 'edit')).toEqual([EKUS_EMPTY_REASON]);
        expect(validate({ ...ok, allowedEkusMode: 'only', allowedEkus: ['1.3.6.1.5.5.7.3.1'] }, 'edit')).toEqual([]);
    });

    it('loads empty ceilings as Any and saves Any as an empty list', () => {
        expect(formFromProfile({ allowedAlgorithms: '[]', allowedEKUs: '[]' })).toMatchObject({ allowedAlgorithmsMode: 'any', allowedEkusMode: 'any' });
        expect(formFromProfile(stored)).toMatchObject({ allowedAlgorithmsMode: 'only' });
        const any = { ...formFromProfile(stored), allowedAlgorithmsMode: 'any' as const, allowedEkusMode: 'any' as const };
        const body = formToUpdateBody(any);
        expect(body.allowedAlgorithms).toBe('[]');
        expect(body.allowedEKUs).toBe('[]');
    });

    it('sends no policies as an empty array and an empty qualifier object', () => {
        const body = formToCreateBody({ ...emptyForm(), policies: [{ oid: '', cpsUri: '', userNotice: '' }], policiesCritical: true });
        expect(body.policyOids).toBe('[]');
        expect(body.policyQualifiersJson).toBe('{}');
    });

    it('reads a comma-separated OID list written by policy sync as rows', () => {
        expect(formFromProfile({ policyOids: '2.23.140.1.2.1, 1.2.3.4' }).policies.map((r) => r.oid)).toEqual(['2.23.140.1.2.1', '1.2.3.4']);
    });
});
