import { describe, expect, it } from 'vitest';
import { ApiError, parseProblem } from '@shared-auth/api/problem';
import {
    diagnosticNotice, diagnosticNotices, diagnosticSeverity, errorNotices, problemNotice,
    problemNotices,
} from '@shared-auth/api/notices';

/**
 * Coverage for the join between the parsed API response and the notification surface.
 *
 * The inputs here are built by `parseProblem` from the bodies the server actually writes, not
 * hand-assembled `ApiProblem` literals — an adapter tested against an object the parser never
 * produces proves nothing. The bodies mirror the ones in `problem.test.ts`, taken from
 * `RequestValidationMiddleware.cs` and the global handler in `StartModularCA.cs`.
 */

const POLICY_DETAIL =
    'Certificate policy violation(s): [ExtendedKeyUsage] The certificate profile requests ' +
    'extended key usages (clientAuth, smartcardLogon) but none of them survived resolution and ' +
    'the signing profile AllowedEKUs.';

const POLICY_BODY = JSON.stringify({
    title: 'Certificate policy violation',
    status: 400,
    detail: POLICY_DETAIL,
    violations: [
        '[ExtendedKeyUsage] The certificate profile requests extended key usages (clientAuth, ' +
        'smartcardLogon) but none of them survived resolution and the signing profile AllowedEKUs.',
    ],
    correlationId: 'a1b2c3d4',
});

const PROFILE_BODY = JSON.stringify({
    title: 'Profile does not permit these key parameters',
    status: 400,
    detail: 'Signature algorithm "SHA1withRSA" is not permitted by the signing profile.',
    parameter: 'Signature algorithm',
    supplied: 'SHA1withRSA',
    allowed: ['SHA256withRSA', 'SHA384withRSA'],
    correlationId: 'a1b2c3d4',
});

const MODEL_STATE_BODY = JSON.stringify({
    title: 'One or more validation errors occurred.',
    status: 400,
    errors: {
        NotAfter: ['The NotAfter field must be later than NotBefore.'],
        KeyAlgorithm: ['Unsupported curve.', 'Not permitted by the profile.'],
    },
});

const SANITIZED_500_BODY = JSON.stringify({
    title: 'Internal Server Error',
    status: 500,
    detail: 'An unexpected error occurred. Contact your administrator with the correlation id below.',
    correlationId: 'deadbeefcafe',
});

describe('problemNotice', () => {
    it('keeps the parts of a policy refusal in separate slots', () => {
        const notice = problemNotice(parseProblem(400, POLICY_BODY));

        expect(notice.severity).toBe('error');
        expect(notice.title).toBe('Certificate policy violation');
        expect(notice.detail).toBe(POLICY_DETAIL);
        expect(notice.correlationId).toBe('a1b2c3d4');
        // Each rule that tripped stays its own line; three violations collapsed into one sentence
        // would read as one problem.
        expect(notice.items).toHaveLength(1);
        expect(notice.items?.[0]).toContain('[ExtendedKeyUsage]');
    });

    it('scopes a profile refusal to the parameter it names, and shows what was allowed', () => {
        const notice = problemNotice(parseProblem(400, PROFILE_BODY));

        // The form can now place this under its signature-algorithm control; a form without one
        // falls back to the toast.
        expect(notice.field).toBe('Signature algorithm');
        expect(notice.items).toEqual([
            'Supplied: SHA1withRSA',
            'Allowed: SHA256withRSA, SHA384withRSA',
        ]);
    });

    it('carries the correlation id of a sanitized 500 as its own value', () => {
        const notice = problemNotice(parseProblem(500, SANITIZED_500_BODY));

        // It used to reach the operator inside the message string, where copying it meant
        // selecting the middle of a sentence. It is now a field the toast can render as a token.
        expect(notice.correlationId).toBe('deadbeefcafe');
        expect(notice.detail).toContain('An unexpected error occurred.');
    });

    it('leaves absent fields absent rather than inventing them', () => {
        const notice = problemNotice(parseProblem(404, JSON.stringify({ error: 'No such CA' })));

        expect(notice.detail).toBe('No such CA');
        expect(notice.code).toBeUndefined();
        expect(notice.items).toBeUndefined();
        expect(notice.field).toBeUndefined();
    });
});

describe('problemNotices', () => {
    it('splits model state into one notice per field, behind the summary', () => {
        const notices = problemNotices(parseProblem(400, MODEL_STATE_BODY));

        expect(notices).toHaveLength(3);
        // The summary stays first, so a surface with room for only one shows the explanation
        // rather than whichever field the server happened to serialize first.
        expect(notices[0].title).toBe('One or more validation errors occurred.');
        expect(notices[1].field).toBe('NotAfter');
        expect(notices[1].detail).toBe('The NotAfter field must be later than NotBefore.');
        expect(notices[2].field).toBe('KeyAlgorithm');
        expect(notices[2].detail).toBe('Unsupported curve. Not permitted by the profile.');
    });

    it('is just the summary when the body named no fields', () => {
        expect(problemNotices(parseProblem(400, POLICY_BODY))).toHaveLength(1);
    });
});

describe('diagnosticSeverity', () => {
    it('maps the three severities the server emits', () => {
        expect(diagnosticSeverity('info')).toBe('info');
        expect(diagnosticSeverity('Warning')).toBe('warning');
        expect(diagnosticSeverity('ERROR')).toBe('error');
    });

    it('treats an unrecognized severity as a warning, not as noise', () => {
        // A severity this build has not been taught about came from a newer server. An unknown
        // message about a certificate that is already signed is not something to render in grey.
        expect(diagnosticSeverity('critical')).toBe('warning');
        expect(diagnosticSeverity('')).toBe('warning');
    });
});

describe('diagnosticNotice', () => {
    it('carries the field so the advisory can be rendered next to the control', () => {
        const notice = diagnosticNotice({
            severity: 'warning',
            code: 'MCA-ISS-003',
            title: 'Extended key usage dropped',
            detail: 'clientAuth did not survive profile resolution.',
            remediation: 'Add clientAuth to the signing profile AllowedEKUs.',
            field: 'extendedKeyUsages',
        });

        expect(notice.severity).toBe('warning');
        expect(notice.field).toBe('extendedKeyUsages');
        expect(notice.code).toBe('MCA-ISS-003');
        expect(notice.remediation).toBe('Add clientAuth to the signing profile AllowedEKUs.');
    });

    it('drops the empty code a pre-diagnostics warnings array produces', () => {
        // readDiagnostics synthesizes `{ code: '' }` for a legacy `warnings: string[]` body;
        // rendering "[]" next to a copy button would be worse than rendering nothing.
        const notice = diagnosticNotice({ severity: 'warning', code: '', title: 'Warning', detail: 'Clamped.' });
        expect(notice.code).toBeUndefined();
    });

    it('maps a whole list in order', () => {
        const notices = diagnosticNotices([
            { severity: 'info', code: 'MCA-ISS-007', title: 'Validity clamped', detail: 'Clamped to the CA.' },
            { severity: 'warning', code: 'MCA-ISS-003', title: 'EKU dropped', detail: 'clientAuth removed.' },
        ]);
        expect(notices.map(n => n.severity)).toEqual(['info', 'warning']);
    });
});

describe('errorNotices', () => {
    it('unpacks an ApiError into the same notices the problem would produce', () => {
        const problem = parseProblem(400, MODEL_STATE_BODY);
        expect(errorNotices(new ApiError(problem))).toEqual(problemNotices(problem));
    });

    it('degrades a plain Error to its sentence', () => {
        // Most catch blocks still receive one of these — a thrown string from an older path, a
        // network failure, a step-up cancellation — and a form must be able to render them all the
        // same way without first proving what it caught.
        expect(errorNotices(new Error('Reissue failed'))).toEqual([
            { severity: 'error', detail: 'Reissue failed' },
        ]);
        expect(errorNotices('Reissue failed')).toEqual([{ severity: 'error', detail: 'Reissue failed' }]);
    });

    it('always says something, even for a thrown value that says nothing', () => {
        expect(errorNotices(null)).toEqual([{ severity: 'error', detail: 'The request failed.' }]);
        expect(errorNotices(new Error(''))).toEqual([{ severity: 'error', detail: 'The request failed.' }]);
    });
});
