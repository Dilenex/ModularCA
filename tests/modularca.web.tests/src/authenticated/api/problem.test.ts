import { describe, expect, it } from 'vitest';
import {
    ApiError, describeDiagnostics, httpTitle, isApiError, parseProblem, readDiagnostics,
} from '@shared-auth/api/problem';

/**
 * Coverage for the single funnel every API error in adminui and userui now passes through.
 *
 * Two different kinds of assertion live here, and they are worth telling apart.
 *
 * The first kind pins the *improvements*: a certificate-policy rejection must surface its
 * `detail` and keep its `violations`, a 500 must quote its correlation id. Those are the
 * behaviours the module was written for, and a regression in them is silent — the toast still
 * says something, it just says the useless thing again.
 *
 * The second kind pins the *absence of change*. Most controllers still answer `{ error: "..." }`,
 * and hundreds of call sites catch the thrown error and toast `err.message`. For those bodies
 * the new parser must produce the byte-identical string the old client produced, because a
 * rewrite of the error path that quietly reworded every existing message would be a much larger
 * change than the one that was intended. `legacyMessage` below is the old client's logic,
 * preserved so the suite can assert equality against it rather than against a hand-copied
 * literal that could be wrong in the same way the parser is.
 *
 * Payload shapes are taken from the server, not invented: ModularCA.API/Middleware/
 * RequestValidationMiddleware.cs for the problem+json family, and the global exception handler
 * in ModularCA.API/StartModularCA.cs for the sanitized 500.
 */

/**
 * The message the pre-`problem.ts` client produced for a given body.
 *
 * Reproduced verbatim from the client this module replaced — `parsed.error || parsed.message ||
 * parsed.title || body`, with the model-state branch in front. It is the oracle for the
 * no-regression tests: for a legacy body the new parser must agree with it exactly.
 */
function legacyMessage(status: number, errorBody: string): string {
    if (!errorBody) return `HTTP ${status}`;
    try {
        const parsed = JSON.parse(errorBody);
        if (parsed.errors) {
            const details = Object.entries(parsed.errors)
                .map(([f, m]) => `${f}: ${(m as string[]).join(', ')}`)
                .join('; ');
            return parsed.title ? `${parsed.title} — ${details}` : details;
        }
        return parsed.error || parsed.message || parsed.title || errorBody;
    } catch {
        return errorBody;
    }
}

/** Builds a real Headers instance carrying a correlation id, as a response would. */
function headersWithCorrelationId(id: string): Headers {
    return new Headers({ 'X-Correlation-Id': id });
}

// The exact body RequestValidationMiddleware writes for a CertificatePolicyViolationException.
const POLICY_DETAIL =
    'Certificate policy violation(s): [ExtendedKeyUsage] The certificate profile requests ' +
    'extended key usages (clientAuth, smartcardLogon) but none of them survived resolution and ' +
    'the signing profile AllowedEKUs.';

const POLICY_BODY = JSON.stringify({
    type: 'https://tools.ietf.org/html/rfc7231#section-6.5.1',
    title: 'Certificate policy violation',
    status: 400,
    detail: POLICY_DETAIL,
    violations: [
        '[ExtendedKeyUsage] The certificate profile requests extended key usages (clientAuth, ' +
        'smartcardLogon) but none of them survived resolution and the signing profile AllowedEKUs.',
    ],
    correlationId: 'a1b2c3d4',
});

// The exact body RequestValidationMiddleware writes for a ProfileValidationException.
const PROFILE_DETAIL =
    'Signature algorithm "SHA1withRSA" is not permitted by the signing profile. ' +
    'Allowed: SHA256withRSA, SHA384withRSA.';

const PROFILE_BODY = JSON.stringify({
    type: 'https://tools.ietf.org/html/rfc7231#section-6.5.1',
    title: 'Profile does not permit these key parameters',
    status: 400,
    detail: PROFILE_DETAIL,
    parameter: 'Signature algorithm',
    supplied: 'SHA1withRSA',
    allowed: ['SHA256withRSA', 'SHA384withRSA'],
    correlationId: 'a1b2c3d4',
});

// The sanitized body the global handler in StartModularCA.cs writes for any unhandled exception.
const SANITIZED_500_DETAIL =
    'An unexpected error occurred. Contact your administrator with the correlation id below.';

const SANITIZED_500_BODY = JSON.stringify({
    type: 'about:blank',
    title: 'Internal Server Error',
    status: 500,
    detail: SANITIZED_500_DETAIL,
    correlationId: 'deadbeefcafe',
});

describe('parseProblem — problem+json from RequestValidationMiddleware', () => {
    it('surfaces the detail of a certificate-policy violation instead of its title', () => {
        const p = parseProblem(400, POLICY_BODY);

        // The regression this module exists to prevent: the old client landed on `title` and
        // rendered the four words "Certificate policy violation" for a body that explained
        // exactly which EKU was dropped and why.
        expect(p.message).toBe(POLICY_DETAIL);
        expect(p.message).not.toBe('Certificate policy violation');
        expect(legacyMessage(400, POLICY_BODY)).toBe('Certificate policy violation');

        expect(p.title).toBe('Certificate policy violation');
        expect(p.detail).toBe(POLICY_DETAIL);
        expect(p.status).toBe(400);
    });

    it('keeps the violations array so a caller can render the rules individually', () => {
        const p = parseProblem(400, POLICY_BODY);

        expect(p.violations).toHaveLength(1);
        expect(p.violations?.[0]).toContain('[ExtendedKeyUsage]');
        // A 400 that already explains itself must not be padded with a correlation id.
        expect(p.message).not.toContain('a1b2c3d4');
        expect(p.correlationId).toBe('a1b2c3d4');
    });

    it('keeps parameter, supplied and allowed from a profile validation failure', () => {
        const p = parseProblem(400, PROFILE_BODY);

        expect(p.message).toBe(PROFILE_DETAIL);
        expect(p.parameter).toBe('Signature algorithm');
        expect(p.supplied).toBe('SHA1withRSA');
        expect(p.allowed).toEqual(['SHA256withRSA', 'SHA384withRSA']);
        expect(p.title).toBe('Profile does not permit these key parameters');
    });

    it('exposes the untouched body as raw for fields this interface does not name', () => {
        const p = parseProblem(400, POLICY_BODY);

        // `type` has no named field, and callers occasionally want it. The middleware also
        // grew `resourceKind` / `identifier` on its 404 branch after this module was written,
        // and raw is what keeps those reachable without a parser change.
        expect((p.raw as Record<string, unknown>).type).toBe(
            'https://tools.ietf.org/html/rfc7231#section-6.5.1',
        );
    });

    it('reads the 404 and 409 members of the validation family', () => {
        const notFound = parseProblem(
            404,
            JSON.stringify({
                type: 'https://tools.ietf.org/html/rfc7231#section-6.5.4',
                title: 'Not found',
                status: 404,
                detail: 'Certificate authority "issuing-01" does not exist.',
                resourceKind: 'Certificate authority',
                identifier: 'issuing-01',
                correlationId: 'c0ffee',
            }),
        );
        expect(notFound.message).toBe('Certificate authority "issuing-01" does not exist.');
        expect(notFound.title).toBe('Not found');
        expect((notFound.raw as Record<string, unknown>).resourceKind).toBe('Certificate authority');

        const conflict = parseProblem(
            409,
            JSON.stringify({
                title: 'Conflict',
                status: 409,
                detail: 'A certificate authority labelled "issuing-01" already exists.',
                correlationId: 'c0ffee',
            }),
        );
        expect(conflict.message).toBe('A certificate authority labelled "issuing-01" already exists.');
        expect(conflict.title).toBe('Conflict');
    });
});

describe('parseProblem — the sanitized 500', () => {
    it('appends the correlation id, which is the only actionable thing in the body', () => {
        const p = parseProblem(500, SANITIZED_500_BODY);

        expect(p.message).toBe(`${SANITIZED_500_DETAIL} (correlation id deadbeefcafe)`);
        expect(p.message).toContain('deadbeefcafe');
        expect(p.correlationId).toBe('deadbeefcafe');
        expect(p.status).toBe(500);
        // The old client rendered this as the two useless words and dropped the id entirely.
        expect(legacyMessage(500, SANITIZED_500_BODY)).toBe('Internal Server Error');
    });

    it('appends the id for any 5xx, and for a 4xx only when there is no explanation', () => {
        const withDetail = parseProblem(
            400,
            JSON.stringify({ title: 'Request rejected', detail: 'Key size 1024 is too small.', correlationId: 'abc' }),
        );
        expect(withDetail.message).toBe('Key size 1024 is too small.');

        const withoutDetail = parseProblem(400, JSON.stringify({ title: 'Request rejected', correlationId: 'abc' }));
        expect(withoutDetail.message).toBe('Request rejected (correlation id abc)');

        const serverError = parseProblem(503, JSON.stringify({ detail: 'HSM is offline.', correlationId: 'abc' }));
        expect(serverError.message).toBe('HSM is offline. (correlation id abc)');
    });
});

describe('parseProblem — legacy bodies must not change at all', () => {
    // Every shape the majority of controllers still emit. For each, the parsed message must be
    // byte-identical to what the old client produced; anything else is a silent rewording of a
    // message an operator may have been reading for months.
    const legacyCases: Array<[name: string, status: number, body: string]> = [
        ['{ error } 404', 404, JSON.stringify({ error: 'Certificate not found.' })],
        ['{ message } 400', 400, JSON.stringify({ message: 'The CSR could not be parsed.' })],
        [
            '{ error } with a long remediation sentence',
            400,
            JSON.stringify({
                error:
                    'A CA certificate must not carry an ExtendedKeyUsage extension. Requested: ' +
                    'smartcardLogon. An EKU on a CA constrains every certificate beneath it; put the ' +
                    'permitted issuance EKUs on the signing profile instead.',
            }),
        ],
        [
            'ASP.NET model state',
            400,
            JSON.stringify({
                title: 'One or more validation errors occurred.',
                status: 400,
                errors: {
                    SubjectCN: ['The SubjectCN field is required.'],
                    KeySize: ['Must be 2048 or greater.'],
                },
            }),
        ],
        ['plain text body', 503, 'Upstream CA is unreachable'],
        ['malformed JSON', 400, '{"error": "truncated'],
    ];

    it.each(legacyCases)('%s produces the identical message', (_name, status, body) => {
        expect(parseProblem(status, body).message).toBe(legacyMessage(status, body));
    });

    it('treats a legacy string as the explanation, not as the classification', () => {
        const p = parseProblem(404, JSON.stringify({ error: 'Certificate not found.' }));

        // Same message as before, but it now lands in `detail` — which is what lets the
        // correlation-id and remediation rules treat it as an explanation.
        expect(p.message).toBe('Certificate not found.');
        expect(p.detail).toBe('Certificate not found.');
        expect(p.title).toBe('Not found');
    });

    it('prefers error over message when a body carries both, as the old chain did', () => {
        const body = JSON.stringify({ error: 'from error', message: 'from message' });

        expect(parseProblem(400, body).message).toBe('from error');
        expect(parseProblem(400, body).message).toBe(legacyMessage(400, body));
    });

    it('flattens model-state errors onto the title with the same separators', () => {
        const p = parseProblem(
            400,
            JSON.stringify({
                title: 'One or more validation errors occurred.',
                errors: { SubjectCN: ['Required.'], KeySize: ['Too small.', 'Not a power of two.'] },
            }),
        );

        expect(p.message).toBe(
            'One or more validation errors occurred. — SubjectCN: Required.; KeySize: Too small., Not a power of two.',
        );
        expect(p.fieldErrors).toEqual({
            SubjectCN: ['Required.'],
            KeySize: ['Too small.', 'Not a power of two.'],
        });
    });

    it('falls back to the status title when a blank title is all the body offers', () => {
        // asText rejects a whitespace-only string, so "   " must not become the message.
        const p = parseProblem(409, JSON.stringify({ title: '   ' }));

        expect(p.title).toBe('Conflict');
        expect(p.message).toBe('Conflict');
    });
});

describe('parseProblem — bodies that are not usable JSON objects', () => {
    it('uses an empty body as nothing more than the status line', () => {
        const p = parseProblem(502, '');

        expect(p.message).toBe('Upstream error');
        expect(p.title).toBe('Upstream error');
        expect(p.detail).toBeUndefined();
        expect(p.raw).toBeUndefined();
    });

    it('treats a whitespace-only body as empty', () => {
        expect(parseProblem(502, '   \n  ').message).toBe('Upstream error');
    });

    it('uses a plain-text body as the explanation', () => {
        const p = parseProblem(503, 'Upstream CA is unreachable');

        expect(p.message).toBe('Upstream CA is unreachable');
        expect(p.detail).toBe('Upstream CA is unreachable');
        expect(p.title).toBe('Service unavailable');
        expect(p.raw).toBeUndefined();
    });

    it('keeps a truncated JSON body visible rather than swallowing it', () => {
        const p = parseProblem(400, '{"error": "truncated');

        expect(p.message).toBe('{"error": "truncated');
        expect(p.raw).toBeUndefined();
    });

    // JSON that parses but is not an object carries no fields to read, so the text itself is
    // the most informative thing available.
    it.each([
        ['null', 'null'],
        ['a number', '42'],
        ['an array', '[]'],
        ['a bare string', '"str"'],
    ])('degrades %s to its own text', (_name, body) => {
        const p = parseProblem(400, body);

        expect(p.message).toBe(body);
        expect(p.detail).toBe(body);
        expect(p.title).toBe('Request rejected');
    });

    it('never throws, whatever it is handed', () => {
        const junk: unknown[] = [
            null,
            undefined,
            '',
            '   ',
            '[]',
            'null',
            '42',
            '"str"',
            '{',
            '{"title": null, "detail": 12, "allowed": [1, 2], "errors": []}',
            JSON.stringify({ errors: 'not-an-object' }),
            JSON.stringify({ allowed: { not: 'an array' } }),
            ' ',
        ];

        for (const body of junk) {
            // An error path that can itself throw replaces the real failure with a confusing
            // one, so this property matters more than any individual message.
            expect(() => parseProblem(500, body as string)).not.toThrow();
            const p = parseProblem(500, body as string);
            expect(typeof p.message).toBe('string');
            expect(p.message.length).toBeGreaterThan(0);
        }
    });
});

describe('parseProblem — narrowing of loosely typed fields', () => {
    it('accepts a single string where an array is expected', () => {
        const p = parseProblem(400, JSON.stringify({ allowed: 'SHA256withRSA', violations: '[Validity] Too long.' }));

        expect(p.allowed).toEqual(['SHA256withRSA']);
        expect(p.violations).toEqual(['[Validity] Too long.']);
    });

    it('drops non-string members and empty arrays rather than passing them on', () => {
        const p = parseProblem(400, JSON.stringify({ allowed: ['ok', 7, null, 'fine'], violations: [] }));

        expect(p.allowed).toEqual(['ok', 'fine']);
        expect(p.violations).toBeUndefined();
    });

    it('ignores an errors value that is not a field-keyed object', () => {
        expect(parseProblem(400, JSON.stringify({ errors: 'nope' })).fieldErrors).toBeUndefined();
        expect(parseProblem(400, JSON.stringify({ errors: [] })).fieldErrors).toBeUndefined();
        expect(parseProblem(400, JSON.stringify({ errors: { Field: [] } })).fieldErrors).toBeUndefined();
        expect(parseProblem(400, JSON.stringify({ errors: { Field: 'single' } })).fieldErrors).toEqual({
            Field: ['single'],
        });
    });

    it('does not repeat the detail when it merely restates the title', () => {
        // composeMessage falls back to the title when detail is identical, so a body that sets
        // both to the same string must not render it twice or pick the wrong one.
        const p = parseProblem(400, JSON.stringify({ title: 'Conflict', detail: 'Conflict' }));

        expect(p.message).toBe('Conflict');
    });
});

describe('parseProblem — correlation id sources', () => {
    it('takes the id from the X-Correlation-Id header when the body omits it', () => {
        const p = parseProblem(500, JSON.stringify({ error: 'boom' }), headersWithCorrelationId('hdr-123'));

        expect(p.correlationId).toBe('hdr-123');
        expect(p.message).toBe('boom (correlation id hdr-123)');
    });

    it('prefers the id in the body when both carry one', () => {
        const p = parseProblem(
            500,
            JSON.stringify({ detail: 'boom', correlationId: 'body-1' }),
            headersWithCorrelationId('hdr-123'),
        );

        expect(p.correlationId).toBe('body-1');
    });

    it('still reports the id when the body is empty', () => {
        const p = parseProblem(500, '', headersWithCorrelationId('hdr-123'));

        expect(p.correlationId).toBe('hdr-123');
        expect(p.message).toBe('Server error (correlation id hdr-123)');
    });

    it('survives a headers object whose get throws', () => {
        // Synthetic responses built in tests, and some proxies, hand back a headers-like object
        // that is not a real Headers. The id is optional; the error report is not.
        const hostile = {
            get() {
                throw new Error('no headers here');
            },
        } as unknown as Headers;

        expect(() => parseProblem(500, JSON.stringify({ detail: 'boom' }), hostile)).not.toThrow();
        const p = parseProblem(500, JSON.stringify({ detail: 'boom' }), hostile);
        expect(p.correlationId).toBeUndefined();
        expect(p.message).toBe('boom');
    });

    it('tolerates an absent headers argument', () => {
        expect(parseProblem(500, JSON.stringify({ detail: 'boom' }), undefined).correlationId).toBeUndefined();
    });
});

describe('parseProblem — error codes and remediation', () => {
    it('renders code and remediation into the message an operator reads', () => {
        const p = parseProblem(
            400,
            JSON.stringify({
                title: 'Configuration does not permit this operation',
                detail: 'smartcardLogon was requested on a CA certificate.',
                code: 'MCA-CFG-000',
                remediation: 'Move it to the signing profile AllowedEKUs.',
            }),
        );

        expect(p.code).toBe('MCA-CFG-000');
        expect(p.remediation).toBe('Move it to the signing profile AllowedEKUs.');
        // The code is the part that survives a reword, so it has to be visible somewhere the
        // operator can copy it out of. Until the structured toast exists, that is the message.
        expect(p.message).toBe(
            'smartcardLogon was requested on a CA certificate. '
            + 'Move it to the signing profile AllowedEKUs. [MCA-CFG-000]',
        );
    });

    it('appends the code even when there is no remediation', () => {
        const p = parseProblem(409, JSON.stringify({
            title: 'Conflict',
            detail: 'Tenant CA quota exceeded.',
            code: 'MCA-RES-002',
        }));

        expect(p.message).toBe('Tenant CA quota exceeded. [MCA-RES-002]');
    });

    it('leaves both undefined for the legacy bodies that carry neither', () => {
        // The ~820 controller sites answering { error: "..." } have no code, and must keep
        // rendering exactly as they did rather than growing an empty bracket.
        for (const body of [POLICY_BODY, PROFILE_BODY, SANITIZED_500_BODY]) {
            const p = parseProblem(400, body);
            expect(p.code).toBeUndefined();
            expect(p.remediation).toBeUndefined();
            // Not a bare '[' check: a policy detail legitimately contains "[ExtendedKeyUsage]".
            expect(p.message).not.toMatch(/\[MCA-[A-Z]{3}-\d{3}\]$/);
        }
    });
});

describe('httpTitle', () => {
    it('gives a plainer phrase than the RFC reason for the statuses the UI shows', () => {
        expect(httpTitle(403)).toBe('Not permitted');
        expect(httpTitle(404)).toBe('Not found');
        expect(httpTitle(429)).toBe('Too many requests');
        expect(httpTitle(500)).toBe('Server error');
    });

    it('falls back to the bare status for anything unmapped', () => {
        expect(httpTitle(418)).toBe('HTTP 418');
        expect(httpTitle(0)).toBe('HTTP 0');
    });
});

describe('ApiError', () => {
    it('keeps message identical to the problem message so existing catch sites still toast it', () => {
        const problem = parseProblem(400, POLICY_BODY);
        const err = new ApiError(problem);

        expect(err.message).toBe(problem.message);
        expect(err.message).toBe(POLICY_DETAIL);
        expect(String(err)).toBe(`ApiError: ${POLICY_DETAIL}`);
    });

    it('is both an Error and an ApiError, so neither style of catch misses it', () => {
        const err = new ApiError(parseProblem(500, SANITIZED_500_BODY));

        expect(err).toBeInstanceOf(Error);
        expect(err).toBeInstanceOf(ApiError);
        expect(err.name).toBe('ApiError');
        expect(isApiError(err)).toBe(true);
        expect(isApiError(new Error('plain'))).toBe(false);
        expect(isApiError(null)).toBe(false);
        expect(isApiError('ApiError')).toBe(false);
    });

    it('mirrors the status and carries the whole problem', () => {
        const problem = parseProblem(403, JSON.stringify({ error: 'Step-up required.' }));
        const err = new ApiError(problem);

        expect(err.status).toBe(403);
        expect(err.status).toBe(problem.status);
        expect(err.problem).toBe(problem);
        expect(err.problem.detail).toBe('Step-up required.');
    });

    it('lets the client mark a step-up response after construction', () => {
        const err = new ApiError(parseProblem(403, JSON.stringify({ error: 'Step-up required.' })));

        // createClient sets this on the 403 step-up sentinel path, so it cannot be readonly.
        expect(err.requiresStepUp).toBeUndefined();
        err.requiresStepUp = true;
        expect(err.requiresStepUp).toBe(true);
    });
});

describe('readDiagnostics / describeDiagnostics', () => {
    const DROPPED = {
        severity: 'warning',
        code: 'MCA-ISS-003',
        title: 'Extended key usage dropped',
        detail: "The certificate profile requested 1.3.6.1.4.1.311.20.2.2, but the signing profile's "
            + 'AllowedEKUs does not permit it, so it was omitted from the issued certificate.',
        remediation: "Add it to the signing profile's Allowed EKUs and reissue.",
        field: 'extendedKeyUsages',
    };

    it('reads structured diagnostics off a success envelope', () => {
        const found = readDiagnostics({ pem: '-----BEGIN...', warnings: [], diagnostics: [DROPPED] });

        expect(found).toHaveLength(1);
        expect(found[0]!.code).toBe('MCA-ISS-003');
        expect(found[0]!.field).toBe('extendedKeyUsages');
    });

    it('falls back to a legacy warnings array so older responses are not silently dropped', () => {
        const found = readDiagnostics({ pem: 'x', warnings: ['Validity clamped to 2027-01-01.'] });

        expect(found).toHaveLength(1);
        expect(found[0]!.severity).toBe('warning');
        expect(found[0]!.detail).toBe('Validity clamped to 2027-01-01.');
        expect(found[0]!.code).toBe('');
    });

    it('returns nothing for the shapes that carry no diagnostics', () => {
        // A bare PEM string is what /issue used to answer on the no-warning path. Reading
        // diagnostics off it must be empty, never a throw inside a success handler.
        for (const body of ['-----BEGIN CERTIFICATE-----', null, undefined, 42, {}, { warnings: null }]) {
            expect(readDiagnostics(body)).toEqual([]);
        }
    });

    it('ignores malformed entries rather than rendering undefined at the operator', () => {
        const found = readDiagnostics({ diagnostics: [DROPPED, null, 'nope', { code: 'x' }] });

        expect(found).toHaveLength(1);
    });

    it('renders detail, remediation and code into one line', () => {
        const line = describeDiagnostics([DROPPED]);

        expect(line).toContain('1.3.6.1.4.1.311.20.2.2');
        expect(line).toContain("Add it to the signing profile's Allowed EKUs");
        expect(line.endsWith('[MCA-ISS-003]')).toBe(true);
    });

    it('omits the bracket when a legacy warning has no code', () => {
        const line = describeDiagnostics(readDiagnostics({ warnings: ['Validity clamped.'] }));

        expect(line).toBe('Validity clamped.');
    });

    it('returns an empty string for none, so callers can append unconditionally', () => {
        expect(describeDiagnostics([])).toBe('');
    });
});
