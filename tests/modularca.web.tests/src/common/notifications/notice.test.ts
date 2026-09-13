import { describe, expect, it } from 'vitest';
import {
    autoDismissMs, fieldMatches, isNotice, mergeNotices, noticeText, normalizeFieldName,
    selectFieldNotices, toNotice, unclaimedNotices, worstSeverity, type Notice,
} from '@shared/notifications/notice';

/**
 * Coverage for the decisions the notification surface makes, as opposed to how it paints them.
 *
 * Three of these are behavioural rules that nothing else enforces and that a rendering test would
 * not catch. `autoDismissMs` decides whether the dropped-EKU warning is still on screen when the
 * operator looks up — the whole reason this work happened. `normalizeFieldName` and `fieldMatches`
 * decide whether a message lands under the control it is about or in a corner of the screen; they
 * reconcile three vocabularies that no single team controls, so the cases below are drawn from the
 * actual spellings each source emits rather than from tidy examples. `mergeNotices` decides what
 * survives when several messages have to share one surface.
 */

describe('autoDismissMs', () => {
    it('keeps the historical five seconds for outcomes that matched the request', () => {
        expect(autoDismissMs('success')).toBe(5000);
        expect(autoDismissMs('info')).toBe(5000);
    });

    it('gives errors and warnings long enough to read and copy from', () => {
        // A warning means a certificate was issued that is not the one that was asked for; five
        // seconds is not long enough to read it, let alone copy the code out of it.
        expect(autoDismissMs('error')).toBeGreaterThanOrEqual(10000);
        expect(autoDismissMs('warning')).toBeGreaterThanOrEqual(10000);
    });

    it('still dismisses every severity on its own', () => {
        // These were briefly pinned open (lifetime 0). That turned every incidental refusal into
        // litter the operator had to clear by hand, a screenful of it after a bulk action. The
        // message that mattered is kept on screen by length plus Toast's hover/focus pause, not by
        // refusing to leave. A call site can still pass 0 explicitly.
        for (const severity of ['success', 'info', 'warning', 'error'] as const) {
            expect(autoDismissMs(severity), `${severity} must not be pinned open`).toBeGreaterThan(0);
        }
    });
});

describe('normalizeFieldName', () => {
    it('ignores case, which is where the diagnostic and model-state spellings differ', () => {
        expect(normalizeFieldName('extendedKeyUsages')).toBe(normalizeFieldName('ExtendedKeyUsages'));
        expect(normalizeFieldName('NotAfter')).toBe('notafter');
    });

    it('ignores the punctuation in a prose parameter name', () => {
        // ProfileValidationException names its parameter for a human: "Signature algorithm".
        expect(normalizeFieldName('Signature algorithm')).toBe('signaturealgorithm');
        expect(normalizeFieldName('signature_algorithm')).toBe('signaturealgorithm');
    });

    it('keeps only the trailing identifier of a model-state path', () => {
        // ASP.NET writes "$.notAfter" when the JSON reader rejected the value and
        // "Request.NotAfter" when the property is nested; both mean the same control.
        expect(normalizeFieldName('$.notAfter')).toBe('notafter');
        expect(normalizeFieldName('Request.NotAfter')).toBe('notafter');
        expect(normalizeFieldName('sans[2]')).toBe('sans');
        expect(normalizeFieldName('request.sans[0].value')).toBe('value');
    });

    it('returns nothing for a name with no identifier in it', () => {
        expect(normalizeFieldName('')).toBe('');
        expect(normalizeFieldName('$.')).toBe('');
        expect(normalizeFieldName('   ')).toBe('');
    });
});

describe('fieldMatches', () => {
    it('matches any of the spellings a control answers to', () => {
        expect(fieldMatches('validTo', ['notAfter', 'validTo'])).toBe(true);
        expect(fieldMatches('$.NotAfter', ['notAfter', 'validTo'])).toBe(true);
        expect(fieldMatches('notBefore', ['notAfter', 'validTo'])).toBe(false);
    });

    it('accepts a single name as well as a list', () => {
        expect(fieldMatches('extendedKeyUsages', 'extendedKeyUsages')).toBe(true);
    });

    it('never matches an absent or empty field', () => {
        // Otherwise every unscoped message would attach itself to the first control that asked,
        // and a policy refusal would appear under the Country box.
        expect(fieldMatches(undefined, ['notAfter'])).toBe(false);
        expect(fieldMatches('', ['notAfter'])).toBe(false);
        expect(fieldMatches('$.', ['notAfter'])).toBe(false);
    });

    it('does not match a control whose own name normalizes to nothing', () => {
        expect(fieldMatches('notAfter', [''])).toBe(false);
        // Both sides meaningless is the case the empty-key guard is actually for: without it the
        // two normalize to the same empty string and every such notice attaches to every such
        // control. A control with a blank alias in its list is a typo, not an invitation.
        expect(fieldMatches('$.', ['', 'notAfter'])).toBe(false);
    });
});

const FORM_NOTICES: Notice[] = [
    { severity: 'error', title: 'Request rejected', detail: 'Two fields were rejected.' },
    { severity: 'error', detail: 'Must be later than notBefore.', field: 'NotAfter' },
    { severity: 'error', detail: 'Unsupported curve.', field: 'keyAlgorithm' },
];

describe('selectFieldNotices / unclaimedNotices', () => {
    it('places a message under the control it names', () => {
        const matched = selectFieldNotices(FORM_NOTICES, ['notAfter', 'validTo']);
        expect(matched).toHaveLength(1);
        expect(matched[0].detail).toBe('Must be later than notBefore.');
    });

    it('leaves the summary and any field the form does not render to the banner', () => {
        // The form inlines notAfter but has no keyAlgorithm control. Both the explanation and the
        // orphaned field message must still be shown somewhere — silently dropping the second is
        // the exact failure this effort exists to remove.
        const banner = unclaimedNotices(FORM_NOTICES, ['notAfter', 'validTo']);
        expect(banner.map(n => n.detail)).toEqual([
            'Two fields were rejected.',
            'Unsupported curve.',
        ]);
    });

    it('is an exact partition of the input', () => {
        const claimed = ['notAfter', 'keyAlgorithm'];
        expect(
            selectFieldNotices(FORM_NOTICES, claimed).length + unclaimedNotices(FORM_NOTICES, claimed).length,
        ).toBe(FORM_NOTICES.length);
    });
});

describe('worstSeverity', () => {
    it('falls back when there is nothing to rank', () => {
        expect(worstSeverity([], 'success')).toBe('success');
        expect(worstSeverity([{ detail: 'no severity' }], 'success')).toBe('success');
    });

    it('reports the most serious entry', () => {
        expect(worstSeverity([{ severity: 'info' }, { severity: 'warning' }], 'success')).toBe('warning');
        expect(worstSeverity([{ severity: 'warning' }, { severity: 'error' }], 'success')).toBe('error');
    });

    it('does not promote a purely informational diagnostic to a warning', () => {
        // What `diagnostics.length ? 'warning' : 'success'` did on the issuance page.
        expect(worstSeverity([{ severity: 'info', detail: 'Serial assigned.' }], 'success')).toBe('info');
    });
});

describe('noticeText', () => {
    it('reads detail first and appends the code in brackets', () => {
        const text = noticeText({
            title: 'Extended key usage dropped',
            detail: 'clientAuth was removed.',
            remediation: 'Add clientAuth to the signing profile.',
            code: 'MCA-ISS-003',
        });
        expect(text).toBe(
            'Extended key usage dropped clientAuth was removed. Add clientAuth to the signing profile. [MCA-ISS-003]',
        );
    });

    it('does not repeat a title that is the same sentence as the detail', () => {
        expect(noticeText({ title: 'Timed out', detail: 'Timed out' })).toBe('Timed out');
    });

    it('quotes the correlation id last, where a reader expects it', () => {
        expect(noticeText({ detail: 'Server error', correlationId: 'deadbeef' }))
            .toBe('Server error (correlation id deadbeef)');
    });

    it('renders a code-only notice without leading whitespace', () => {
        expect(noticeText({ code: 'MCA-CFG-013' })).toBe('[MCA-CFG-013]');
        expect(noticeText({})).toBe('');
    });

    it('treats a bare string as the detail, so both arms render the same', () => {
        expect(noticeText('Saved')).toBe('Saved');
    });
});

describe('isNotice / toNotice', () => {
    it('tells the two accepted payloads apart', () => {
        expect(isNotice('Saved')).toBe(false);
        expect(isNotice({ detail: 'Saved' })).toBe(true);
    });

    it('wraps a string as a notice carrying the toast severity', () => {
        expect(toNotice('Saved', 'success')).toEqual({ detail: 'Saved', severity: 'success' });
    });

    it('leaves a notice that already states its own severity alone', () => {
        const own: Notice = { detail: 'Dropped an EKU.', severity: 'warning' };
        expect(toNotice(own, 'error')).toBe(own);
    });
});

describe('mergeNotices', () => {
    it('is just the headline when nothing else happened', () => {
        expect(mergeNotices('Certificate issued', [])).toEqual({ title: 'Certificate issued' });
    });

    it('keeps a single advisory structured, so its code stays copyable', () => {
        const merged = mergeNotices('Certificate issued for CN=host', [{
            severity: 'warning',
            title: 'Extended key usage dropped',
            detail: 'clientAuth was removed.',
            remediation: 'Add clientAuth to the signing profile.',
            code: 'MCA-ISS-003',
            field: 'extendedKeyUsages',
        }]);

        expect(merged.title).toBe('Certificate issued for CN=host');
        // The advisory's own title is folded into the detail rather than being overwritten: both
        // sentences matter, and the second one is the one that matters more.
        expect(merged.detail).toBe('Extended key usage dropped: clientAuth was removed.');
        expect(merged.code).toBe('MCA-ISS-003');
        expect(merged.remediation).toBe('Add clientAuth to the signing profile.');
        expect(merged.severity).toBe('warning');
        expect(merged.field).toBe('extendedKeyUsages');
    });

    it('lists several advisories instead of running them into one sentence', () => {
        const merged = mergeNotices('Certificate issued', [
            { severity: 'warning', detail: 'clientAuth was removed.', code: 'MCA-ISS-003' },
            { severity: 'info', detail: 'Validity clamped to the CA.', code: 'MCA-ISS-007' },
        ]);

        expect(merged.items).toEqual([
            'clientAuth was removed. [MCA-ISS-003]',
            'Validity clamped to the CA. [MCA-ISS-007]',
        ]);
        expect(merged.severity).toBe('warning');
        expect(merged.detail).toBeUndefined();
    });
});
