import { describe, expect, it } from 'vitest';
import {
    buildCmpRequest, buildTokenRequest, emptyEnrollmentForm, enrollmentKind,
    ENROLLMENT_PROTOCOLS, enrollmentProtocolMeta, EnrollmentFormState, showsQrResult,
    validateEnrollmentForm,
} from '@adminui/components/enrollmentForm';

/**
 * The protocol catalog and field logic behind the single enrollment-credential form. The page's
 * two-button, two-form arrangement collapsed to one form whose fields follow the selected
 * protocol; these pin which protocol maps to which shape, what each request body carries, and
 * that submission is blocked until the protocol-specific fields are filled.
 */

const base: EnrollmentFormState = {
    ...emptyEnrollmentForm(),
    expiresInHours: 48,
    maxUses: 5,
    subjectRestriction: 'O=Acme',
    sanRestriction: 'acme.test',
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

    it('does not demand CMP fields for a token protocol', () => {
        // referenceValue and signingProfileId are empty here, and that must be fine for EST.
        expect(validateEnrollmentForm({ ...base, protocol: 'EST', referenceValue: '', signingProfileId: '' }, refOk)).toBeNull();
    });
});

describe('request bodies', () => {
    it('the token body carries the selected protocol as the restriction', () => {
        const body = buildTokenRequest({ ...base, protocol: 'EST' });
        expect(body).toEqual({ expiresInHours: 48, maxUses: 5, subjectRestriction: 'O=Acme', sanRestriction: 'acme.test', protocol: 'EST' });
    });

    it('the token body sends null for blank restrictions and 0 for blank uses', () => {
        const body = buildTokenRequest({ ...base, protocol: 'QR', subjectRestriction: '', sanRestriction: '', maxUses: '' });
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
