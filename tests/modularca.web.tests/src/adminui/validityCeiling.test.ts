import { describe, expect, it } from 'vitest';
import type { ValidityCeilingPreflight } from '@shared/generated';
import {
    describeCeiling, exceedsCeiling, formatIso8601Duration, toDatetimeLocalValue,
} from '@adminui/pages/validityCeiling';

/**
 * The pure half of the Issue Certificate form's validity pre-flight.
 *
 * Two things here are worth covering rather than trusting.
 *
 * The local-time conversion is the first. `<input type="datetime-local">` reads and writes LOCAL
 * wall-clock components while the ceiling arrives as a UTC instant, and building one from the other
 * through `toISOString()` is precisely the defect that once shipped in this form's `notBefore`: the
 * field opened pre-filled one UTC offset in the future, and every certificate it produced was
 * invalid to every relying party until that time arrived. A `max` built the same way would silently
 * permit an over-long request west of UTC and silently forbid a legal one east of it.
 *
 * The second is naming the binding layer. The whole reason the endpoint returns which of the three
 * limits won is that "Max 730 days" alone sends an operator to whichever screen they guess first —
 * and naming the wrong one sends them to the wrong screen with confidence, which is worse.
 */

/** A pre-flight response with the boring fields filled in; each test overrides what it is about. */
function preflight(over: Omit<Partial<ValidityCeilingPreflight>, 'resolution'> & {
    // Omit-then-re-add rather than intersecting: `Partial<T> & { resolution?: Partial<R> }`
    // intersects the two `resolution` members, so the field ends up requiring the FULL shape and
    // every override has to restate the fields it is not interested in.
    resolution?: Partial<ValidityCeilingPreflight['resolution']>;
} = {}): ValidityCeilingPreflight {
    const { resolution, ...rest } = over;
    return {
        resolution: {
            notBefore: '2026-01-01T00:00:00Z',
            effectiveNotAfter: '2028-01-01T00:00:00Z',
            effectiveMaxDays: 730,
            boundBy: 'Tenant',
            certProfileNotAfter: '2029-01-01T00:00:00Z',
            tenantNotAfter: '2028-01-01T00:00:00Z',
            issuingCaNotAfter: '2036-01-01T00:00:00Z',
            ...resolution,
        },
        signingProfileName: 'issuing-ca-signing',
        certProfileName: 'TLS Server',
        certProfileValidityPeriodMax: 'P3Y',
        issuingCaName: 'Acme Issuing CA',
        issuingCaNotAfter: '2036-01-01T00:00:00Z',
        tenantName: 'Acme Corp',
        tenantMaxValidityDays: 730,
        tenantBehavior: 'Shorten',
        tenantCeilingApplies: true,
        ...rest,
    };
}

describe('toDatetimeLocalValue', () => {
    it('emits local wall-clock components, not a UTC clock reading', () => {
        // Constructed from local components so the assertion holds in any TZ the suite runs in.
        // The failure this guards is a value offset by the host's UTC offset — which on a UTC host
        // is invisible, so the test must not depend on the host being UTC either.
        const d = new Date(2027, 2, 9, 14, 5);

        expect(toDatetimeLocalValue(d)).toBe('2027-03-09T14:05');
    });

    it('zero-pads every component', () => {
        // '2027-3-9T4:5' is not a value the input will accept, so it silently renders as empty and
        // the bound `max` quietly stops constraining anything.
        expect(toDatetimeLocalValue(new Date(2027, 0, 2, 3, 4))).toBe('2027-01-02T03:04');
    });
});

describe('formatIso8601Duration', () => {
    it('renders the common single-unit forms compactly', () => {
        expect(formatIso8601Duration('P3Y')).toBe('3y');
        expect(formatIso8601Duration('P18M')).toBe('18mo');
        expect(formatIso8601Duration('P90D')).toBe('90d');
        expect(formatIso8601Duration('PT12H')).toBe('12h');
    });

    it('reads the T separator rather than mistaking minutes for months', () => {
        // The exact misparse that once made PT30M — thirty minutes, the obvious choice for a
        // short-lived certificate — mean thirty MONTHS on the server side.
        expect(formatIso8601Duration('PT30M')).toBe('30min');
        expect(formatIso8601Duration('P30M')).toBe('30mo');
    });

    it('echoes anything it does not recognise instead of guessing', () => {
        // This string sits next to a number the operator is about to act on. Showing the raw P… the
        // profile actually stores is honest; inventing a duration is not.
        expect(formatIso8601Duration('nonsense')).toBe('nonsense');
        expect(formatIso8601Duration('P')).toBe('P');
    });

    it('treats an unset maximum as absent, for the caller to default', () => {
        expect(formatIso8601Duration(null)).toBeNull();
        expect(formatIso8601Duration(undefined)).toBeNull();
    });
});

describe('describeCeiling', () => {
    it('names the tenant, and what the profile would have allowed, when the tenant binds', () => {
        const notice = describeCeiling(preflight());

        expect(notice.text).toContain('Max 730 days');
        expect(notice.text).toContain("capped by tenant 'Acme Corp'");
        expect(notice.text).toContain('profile allows 3y');
        expect(notice.tone).toBe('info');
    });

    it('names the issuing CA and its expiry when the CA binds', () => {
        // A different remedy from the other two — renew the CA — so it must not be reported as a
        // policy ceiling.
        const notice = describeCeiling(preflight({
            resolution: { boundBy: 'IssuingCa', effectiveMaxDays: 100 },
        }));

        expect(notice.text).toContain("capped by issuing CA 'Acme Issuing CA'");
        expect(notice.text).not.toContain('capped by tenant');
    });

    it('names the certificate profile when nothing narrower applies', () => {
        const notice = describeCeiling(preflight({
            resolution: { boundBy: 'CertProfile', effectiveMaxDays: 1095 },
            tenantMaxValidityDays: 0,
        }));

        expect(notice.text).toContain("certificate profile 'TLS Server'");
        expect(notice.text).toContain('1095');
    });

    it('says a refusing tenant refuses, and warns rather than informs', () => {
        // Rendering Refuse and Shorten identically is wrong in one of the two cases: on Shorten the
        // operator gets a shorter certificate, on Refuse they get nothing.
        const notice = describeCeiling(preflight({ tenantBehavior: 'Refuse' }));

        expect(notice.text).toContain('refuses requests beyond 730 days');
        expect(notice.tone).toBe('warn');
    });

    it('mentions a refusing tenant even while the issuing CA is the narrower limit today', () => {
        // The CA stops being the constraint the moment it is renewed, and an operator who was never
        // told about the refusal meets it then.
        const notice = describeCeiling(preflight({
            tenantBehavior: 'Refuse',
            resolution: { boundBy: 'IssuingCa', effectiveMaxDays: 100 },
        }));

        expect(notice.text).toContain('refuses requests beyond');
    });

    it('does not threaten a refusal when the tenant has no ceiling to refuse against', () => {
        // 0 is unlimited and is what every tenant carries after the migration, so a tenant switched
        // to Refuse before a ceiling was ever typed in refuses nothing.
        const notice = describeCeiling(preflight({
            tenantBehavior: 'Refuse',
            tenantMaxValidityDays: 0,
            resolution: { boundBy: 'CertProfile' },
        }));

        expect(notice.text).not.toContain('refuses requests beyond');
    });

    it('leaves the picker unbounded when the ceiling has already passed', () => {
        // An expired issuing CA yields zero usable days. A `max` of the current instant would make
        // every value invalid with no explanation; the server is still the authority.
        const notice = describeCeiling(preflight({ resolution: { effectiveMaxDays: 0 } }));

        expect(notice.maxInputValue).toBe('');
    });

    it('bounds the picker with a local wall-clock value, not a UTC one', () => {
        const iso = '2028-06-15T18:30:00Z';
        const notice = describeCeiling(preflight({ resolution: { effectiveNotAfter: iso } }));

        // Expected value rebuilt from the local getters rather than from the function under test,
        // so this fails if `max` is ever derived from toISOString(). Written this way rather than
        // asserting a literal because the suite must hold in whatever timezone it runs in — and a
        // literal that only holds on a UTC host would pass on CI and hide the bug everywhere else.
        const d = new Date(iso);
        const pad = (v: number) => String(v).padStart(2, '0');
        expect(notice.maxInputValue).toBe(
            `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
            + `T${pad(d.getHours())}:${pad(d.getMinutes())}`);
    });
});

describe('exceedsCeiling', () => {
    const p = preflight({ resolution: { effectiveNotAfter: '2028-01-01T00:00:00Z' } });

    it('is true for a local value past the ceiling', () => {
        expect(exceedsCeiling(toDatetimeLocalValue(new Date('2028-06-01T00:00:00Z')), p)).toBe(true);
    });

    it('is false for a local value inside the ceiling', () => {
        expect(exceedsCeiling(toDatetimeLocalValue(new Date('2027-06-01T00:00:00Z')), p)).toBe(false);
    });

    it('is false exactly on the ceiling', () => {
        // An off-by-one here would flag a request for precisely what is permitted, which is the one
        // request where the warning most undermines trust in the rest of them.
        expect(exceedsCeiling(toDatetimeLocalValue(new Date('2028-01-01T00:00:00Z')), p)).toBe(false);
    });

    it('reports nothing while the pre-flight is unknown', () => {
        // Null means "cannot tell", not "fine". Warning on an unanswered pre-flight would put a red
        // line under every form that could not reach the endpoint.
        expect(exceedsCeiling('2030-01-01T00:00', null)).toBe(false);
    });

    it('reports nothing for an empty or unparseable value', () => {
        expect(exceedsCeiling('', p)).toBe(false);
        expect(exceedsCeiling('not-a-date', p)).toBe(false);
    });
});
