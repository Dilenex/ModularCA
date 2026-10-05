import { describe, expect, it } from 'vitest';
import type { CreateRequestProfileRequest, UpdateRequestProfileRequest } from '@shared/generated';
import {
    emptyForm, formFromProfile, formToCreateBody, formToUpdateBody, validate,
} from '@adminui/pages/profiles/requestProfile';
import { INHERITANCE_REASON, NAME_REQUIRED_REASON } from '@adminui/pages/profiles/profileFormCore';
import { bodyKeys, dtoKeys } from './profileFormKit';

/**
 * The request profile form model behind /profiles/request/new and /profiles/request/:id. The old
 * create panel could not set allowed cert profiles and posted a maxValidityPeriod the DTO does not
 * have; the one model emits exactly the DTO in both modes.
 */

const CREATE_KEYS = dtoKeys<CreateRequestProfileRequest>({
    name: true, description: true, subjectDnRules: true, sanRules: true, allowedCertProfileIds: true,
    defaultCertProfileId: true, requireApproval: true, certificateAuthorityId: true, inheritsFromId: true,
    inheritanceEnabled: true,
});
const UPDATE_KEYS = dtoKeys<UpdateRequestProfileRequest>({
    name: true, description: true, subjectDnRules: true, sanRules: true, allowedCertProfileIds: true,
    defaultCertProfileId: true, requireApproval: true, certificateAuthorityId: true, inheritsFromId: true,
    inheritanceEnabled: true,
});

/** A profile as GET /api/v1/admin/request-profiles returns it, every settable field off its default. */
const stored = {
    id: '0b6f3f0e-1111-4c4c-9a9a-000000000001',
    name: 'Standard TLS Request',
    description: 'Internal services',
    subjectDnRules: [
        { field: 'CN', requirement: 'Required', regex: '^[a-z0-9.-]+$', maxLength: 64 },
        { field: 'O', requirement: 'Optional', fixedValue: 'Acme', defaultValue: 'Acme' },
    ],
    sanRules: {
        allowedTypes: ['DNS', 'IP', 'UPN'],
        required: true,
        rules: { DNS: { regex: '\\.example\\.com$', maxCount: 5 }, IP: { maxCount: 2 } },
    },
    allowedCertProfileIds: ['0b6f3f0e-4444-4c4c-9a9a-000000000004'],
    defaultCertProfileId: '0b6f3f0e-4444-4c4c-9a9a-000000000004',
    requireApproval: true,
    certificateAuthorityId: '0b6f3f0e-2222-4c4c-9a9a-000000000002',
    inheritsFromId: '0b6f3f0e-3333-4c4c-9a9a-000000000003',
    inheritanceEnabled: true,
    createdAt: '2026-09-01T00:00:00Z',
};

describe('request profile form: shape', () => {
    it('posts exactly the CreateRequestProfileRequest fields from an empty form', () => {
        const body = formToCreateBody(emptyForm());
        expect(bodyKeys(body)).toEqual(CREATE_KEYS);
        expect(body).toMatchObject({
            name: '', description: null, allowedCertProfileIds: [], defaultCertProfileId: null,
            requireApproval: false, certificateAuthorityId: null, inheritsFromId: null, inheritanceEnabled: false,
        });
        expect(body.subjectDnRules).toEqual([{ field: 'CN', requirement: 'Required' }]);
        expect(body.sanRules).toEqual({ allowedTypes: ['DNS', 'IP'], required: false, rules: {} });
    });

    it('never sends the removed maxValidityPeriod', () => {
        expect(Object.keys(formToCreateBody(emptyForm()))).not.toContain('maxValidityPeriod');
    });

    it('puts exactly the UpdateRequestProfileRequest fields', () => {
        expect(bodyKeys(formToUpdateBody(formFromProfile(stored)))).toEqual(UPDATE_KEYS);
    });
});

describe('request profile form: round trip', () => {
    it('preserves every field of a stored profile through load and save', () => {
        const body = formToUpdateBody(formFromProfile(stored));
        expect(body.name).toBe(stored.name);
        expect(body.description).toBe(stored.description);
        expect(body.subjectDnRules).toEqual(stored.subjectDnRules);
        expect(body.sanRules).toEqual(stored.sanRules);
        expect(body.allowedCertProfileIds).toEqual(stored.allowedCertProfileIds);
        expect(body.defaultCertProfileId).toBe(stored.defaultCertProfileId);
        expect(body.requireApproval).toBe(true);
        expect(body.certificateAuthorityId).toBe(stored.certificateAuthorityId);
        expect(body.inheritsFromId).toBe(stored.inheritsFromId);
        expect(body.inheritanceEnabled).toBe(true);
    });

    it('is stable: a saved body loads back into the same form', () => {
        const form = formFromProfile(stored);
        expect(formFromProfile(formToUpdateBody(form))).toEqual(form);
    });

    it('sends a cleared description and CA scope as null', () => {
        const body = formToUpdateBody({ ...formFromProfile(stored), description: '', certificateAuthorityId: '' });
        expect(body.description).toBeNull();
        expect(body.certificateAuthorityId).toBeNull();
    });
});

describe('request profile form: validation', () => {
    it('blocks an unnamed profile in both modes', () => {
        expect(validate(emptyForm(), 'create')).toEqual([NAME_REQUIRED_REASON]);
        expect(validate(emptyForm(), 'edit')).toEqual([NAME_REQUIRED_REASON]);
    });

    it('blocks an inconsistent inheritance pair', () => {
        expect(validate({ ...emptyForm(), name: 'R', inheritsFromId: 'p' }, 'create')).toEqual([INHERITANCE_REASON]);
    });

    it('passes a named, consistent profile in both modes', () => {
        const named = { ...emptyForm(), name: 'R' };
        expect(validate(named, 'create')).toEqual([]);
        expect(validate(named, 'edit')).toEqual([]);
    });
});
