import { describe, expect, it } from 'vitest';
import {
    buildCmpRequest, buildTokenRequest, defaultTokenScope, emptyEnrollmentForm, enrollmentKind,
    ENROLLMENT_PROTOCOLS, enrollmentProtocolMeta, EnrollmentFormState, RESTRICTIONS_REASON, showsQrResult,
    signingProfilesForTokenScope, tokenAcceptedAt, TOKEN_SCOPE_REASON, tokenScopeOptions, validateEnrollmentForm,
} from '@adminui/components/enrollmentForm';
import type { CaCapabilities, EffectiveCapabilities } from '@adminui/authz';
import { ALL_SCOPE, MINE_SCOPE, type Scope } from '@adminui/scope';

/**
 * The protocol catalog and field logic behind the single enrollment-credential form. The page's
 * two-button, two-form arrangement collapsed to one form whose fields follow the selected
 * protocol; these pin which protocol maps to which shape, what each request body carries, and
 * that submission is blocked until the protocol-specific fields are filled.
 */

const base: EnrollmentFormState = {
    ...emptyEnrollmentForm('instance'),
    expiresInHours: 48,
    maxUses: 5,
    subjectRestriction: [{ type: 'DN', value: 'O=Acme' }],
    sanRestriction: [{ type: 'DNS', value: 'acme.test' }],
};

// A reference validator that only rejects the empty string, so these tests exercise the form
// logic rather than the reference-character rules (those have their own tests).
const refOk = (v: string) => (v.trim() ? null : 'Reference value is required.');

describe('the protocol catalog', () => {
    it('offers exactly the four protocols, QR first and CMP last', () => {
        expect(ENROLLMENT_PROTOCOLS.map(p => p.value)).toEqual(['QR', 'EST', 'SCEP', 'CMP']);
    });

    it('maps each protocol to how it is created', () => {
        expect(enrollmentKind('QR')).toBe('token');
        expect(enrollmentKind('EST')).toBe('token');
        expect(enrollmentKind('SCEP')).toBe('token');
        expect(enrollmentKind('CMP')).toBe('cmp');
    });

    it('treats nothing-selected and unknown values as no kind', () => {
        expect(enrollmentKind('')).toBeNull();
        expect(enrollmentKind(null)).toBeNull();
        expect(enrollmentKind('ACME')).toBeNull();
        expect(enrollmentProtocolMeta('ACME')).toBeUndefined();
    });

    it('shows the QR result only for the QR protocol', () => {
        expect(showsQrResult('QR')).toBe(true);
        for (const p of ['EST', 'SCEP', 'CMP', '']) expect(showsQrResult(p)).toBe(false);
    });

    it('gives every protocol a label and a description', () => {
        for (const p of ENROLLMENT_PROTOCOLS) {
            expect(p.label.length).toBeGreaterThan(0);
            expect(p.description.length).toBeGreaterThan(0);
        }
    });
});

describe('validation', () => {
    it('requires a protocol before anything else', () => {
        expect(validateEnrollmentForm({ ...base, protocol: '' }, refOk)).toBe('Choose a protocol.');
    });

    it('accepts a token protocol with no protocol-specific fields', () => {
        for (const protocol of ['QR', 'EST', 'SCEP']) {
            expect(validateEnrollmentForm({ ...base, protocol }, refOk)).toBeNull();
        }
    });

    it('requires a reference value and a signing profile for CMP', () => {
        expect(validateEnrollmentForm({ ...base, protocol: 'CMP', referenceValue: '', signingProfileId: 'sp1' }, refOk))
            .toBe('Reference value is required.');
        expect(validateEnrollmentForm({ ...base, protocol: 'CMP', referenceValue: 'fleet', signingProfileId: '' }, refOk))
            .toContain('signing profile');
        expect(validateEnrollmentForm({ ...base, protocol: 'CMP', referenceValue: 'fleet', signingProfileId: 'sp1' }, refOk))
            .toBeNull();
    });

    it('requires a token to say where it is accepted, and not a CMP credential', () => {
        expect(validateEnrollmentForm({ ...base, protocol: 'SCEP', tokenScope: '' }, refOk)).toBe(TOKEN_SCOPE_REASON);
        expect(validateEnrollmentForm({ ...base, protocol: 'CMP', tokenScope: '', referenceValue: 'fleet', signingProfileId: 'sp1' }, refOk)).toBeNull();
    });

    it('does not demand CMP fields for a token protocol', () => {
        // referenceValue and signingProfileId are empty here, and that must be fine for EST.
        expect(validateEnrollmentForm({ ...base, protocol: 'EST', referenceValue: '', signingProfileId: '' }, refOk)).toBeNull();
    });

    it('blocks a token with an invalid restriction row', () => {
        expect(validateEnrollmentForm({ ...base, protocol: 'EST', subjectRestriction: [{ type: 'DN', value: 'Acme' }] }, refOk))
            .toBe(RESTRICTIONS_REASON);
        expect(validateEnrollmentForm({ ...base, protocol: 'EST', sanRestriction: [{ type: 'DNS', value: '*.acme.test' }] }, refOk))
            .toBe(RESTRICTIONS_REASON);
        // A blank row is dropped, not an error.
        expect(validateEnrollmentForm({ ...base, protocol: 'EST', sanRestriction: [{ type: 'DNS', value: '' }] }, refOk)).toBeNull();
    });

    it('ignores restriction rows for CMP, which sends none', () => {
        expect(validateEnrollmentForm({ ...base, protocol: 'CMP', referenceValue: 'fleet', signingProfileId: 'sp1',
            subjectRestriction: [{ type: 'DN', value: 'bad' }] }, refOk)).toBeNull();
    });

    it('sends a DN value with a space as one pattern', () => {
        const body = buildTokenRequest({ ...base, protocol: 'EST',
            subjectRestriction: [{ type: 'DNS', value: 'acme.test' }, { type: 'DN', value: 'O=Acme Corp' }] });
        expect(body.subjectRestriction).toBe('acme.test; O=Acme Corp');
    });
});

describe('request bodies', () => {
    it('the token body carries the selected protocol as the restriction', () => {
        const body = buildTokenRequest({ ...base, protocol: 'EST', signingProfileId: '' });
        expect(body).toEqual({ scope: 'Instance', scopeId: null, signingProfileId: null, expiresInHours: 48, maxUses: 5, subjectRestriction: 'O=Acme', sanRestriction: 'acme.test', protocol: 'EST' });
    });

    it('the token body carries the chosen scope and the signing profile', () => {
        const atCa = buildTokenRequest({ ...base, protocol: 'SCEP', tokenScope: 'ca:r3', signingProfileId: 'sp3' });
        expect(atCa).toMatchObject({ scope: 'Ca', scopeId: 'r3', signingProfileId: 'sp3' });
        expect(buildTokenRequest({ ...base, protocol: 'EST', tokenScope: 'space:stg' })).toMatchObject({ scope: 'Space', scopeId: 'stg' });
    });

    it('the token body sends null for blank restrictions and 0 for blank uses', () => {
        const body = buildTokenRequest({ ...base, protocol: 'QR', subjectRestriction: [], sanRestriction: [{ type: 'DNS', value: ' ' }], maxUses: '' });
        expect(body.subjectRestriction).toBeNull();
        expect(body.sanRestriction).toBeNull();
        expect(body.maxUses).toBe(0);
    });

    it('the CMP body carries only the fields the CMP endpoint takes, reference trimmed', () => {
        const body = buildCmpRequest({ ...base, protocol: 'CMP', referenceValue: '  fleet-1  ', signingProfileId: 'sp1' });
        expect(body).toEqual({ referenceValue: 'fleet-1', signingProfileId: 'sp1', expiresInHours: 48, maxUses: 5 });
        // Restrictions are not a CMP concept and must not leak into its request.
        expect(body).not.toHaveProperty('subjectRestriction');
        expect(body).not.toHaveProperty('protocol');
    });
});

describe('where a token is accepted', () => {
    const ca = (id: string, spaceId: string | null, extra: Partial<CaCapabilities> = {}): CaCapabilities => ({
        id, label: id, name: id, isSshCa: false, spaceId, spaceName: spaceId ? 'Staging' : '', spaceSlug: spaceId ?? '', capabilities: ['cert.revoke'], ...extra,
    });
    const admin: EffectiveCapabilities = {
        system: ['cert.revoke'],
        cas: [ca('inst', null), ca('r1', 'stg'), ca('r3', 'stg'), ca('ssh', null, { isSshCa: true }), ca('prod', 'prd', { spaceName: 'Prod' })],
        spaces: [{ id: 'stg', name: 'Staging', slug: 'stg', capabilities: ['cert.revoke'] }, { id: 'prd', name: 'Prod', slug: 'prd', capabilities: ['cert.revoke'] }],
    };
    const stagingScope: Scope = { kind: 'space', spaceId: 'stg', slug: 'stg', name: 'Staging' };
    const r3Scope: Scope = { kind: 'ca', caId: 'r3', label: 'r3', spaceId: 'stg', spaceSlug: 'stg' };
    const values = (scope: Scope, caps = admin) => tokenScopeOptions(scope, caps).map(o => o.value);

    it('offers the instance, every space and every CA under all CAs, but no SSH CA', () => {
        expect(values(ALL_SCOPE)).toEqual(['instance', 'space:stg', 'space:prd', 'ca:inst', 'ca:r1', 'ca:r3', 'ca:prod']);
    });

    it('offers the space and its CAs under a space, and only the CA under a CA', () => {
        expect(values(stagingScope)).toEqual(['space:stg', 'ca:r1', 'ca:r3']);
        expect(values(r3Scope)).toEqual(['ca:r3']);
        expect(values(MINE_SCOPE)).toEqual([]);
    });

    it('leaves out what the caller does not hold cert.revoke across', () => {
        const oneCa: EffectiveCapabilities = { system: [], cas: [ca('r3', 'stg'), ca('r1', 'stg', { capabilities: ['cert.view'] })], spaces: [] };
        expect(values(ALL_SCOPE, oneCa)).toEqual(['ca:r3']);
        expect(values(stagingScope, oneCa)).toEqual(['ca:r3']);
    });

    it('starts on the view’s own space or CA, or the only option', () => {
        expect(defaultTokenScope(stagingScope, tokenScopeOptions(stagingScope, admin))).toBe('space:stg');
        expect(defaultTokenScope(r3Scope, tokenScopeOptions(r3Scope, admin))).toBe('ca:r3');
        expect(defaultTokenScope(ALL_SCOPE, tokenScopeOptions(ALL_SCOPE, admin))).toBe('');
    });

    it('lists only the signing profiles issued inside the chosen scope, plus unbound ones', () => {
        const profiles = [{ id: 'p-r3', issuerId: 'cert-r3' }, { id: 'p-r1', issuerId: 'cert-r1' }, { id: 'p-free', issuerId: null }];
        const caOf = (issuer: string) => ({ 'cert-r3': 'r3', 'cert-r1': 'r1' } as Record<string, string>)[issuer];
        const r3 = tokenScopeOptions(r3Scope, admin)[0];
        expect(signingProfilesForTokenScope(profiles, r3, caOf).map(p => p.id)).toEqual(['p-r3', 'p-free']);
        const staging = tokenScopeOptions(stagingScope, admin)[0];
        expect(signingProfilesForTokenScope(profiles, staging, caOf).map(p => p.id)).toEqual(['p-r3', 'p-r1', 'p-free']);
        expect(signingProfilesForTokenScope(profiles, undefined, caOf)).toEqual([]);
    });

    it('names where a stored token is accepted', () => {
        const cas = [{ id: 'r3', label: 'staging-ca-r3' }];
        const spaces = [{ id: 'stg', name: 'Staging' }];
        expect(tokenAcceptedAt({ certificateAuthorityId: 'r3', spaceId: 'stg' }, cas, spaces)).toBe('staging-ca-r3');
        expect(tokenAcceptedAt({ spaceId: 'stg' }, cas, spaces)).toBe('Staging: any of its CAs');
        expect(tokenAcceptedAt({}, cas, spaces)).toBe('CAs not in a space');
    });
});
