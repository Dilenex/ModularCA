import { describe, expect, it } from 'vitest';
import {
    CA_RSA_KEY_SIZES, MIN_CA_RSA_BITS, RECOMMENDED_SESSION_HOURS, caKeyFindings, hoursPhrase, keyAdvisoriesOf,
    refreshTokenRule, sessionMaximumAdvice,
} from '@adminui/pages/tighterDefaults';

describe('hoursPhrase', () => {
    it('says hours, and days beside them from a day up', () => {
        expect(hoursPhrase(12)).toBe('12 hours');
        expect(hoursPhrase(1)).toBe('1 hour');
        expect(hoursPhrase(24)).toBe('24 hours (1 day)');
        expect(hoursPhrase(336)).toBe('336 hours (14 days)');
        expect(hoursPhrase(36)).toBe('36 hours (1.5 days)');
    });

    it('says no maximum for 0, a negative number and nothing', () => {
        expect(hoursPhrase(0)).toBe('no maximum');
        expect(hoursPhrase(-1)).toBe('no maximum');
        expect(hoursPhrase(undefined)).toBe('no maximum');
        expect(hoursPhrase('')).toBe('no maximum');
    });

    it('reads a number typed into a field', () => {
        expect(hoursPhrase('48')).toBe('48 hours (2 days)');
    });
});

describe('sessionMaximumAdvice', () => {
    it('has nothing to say at 12 hours or less', () => {
        expect(RECOMMENDED_SESSION_HOURS).toBe(12);
        expect(sessionMaximumAdvice(12)).toBeNull();
        expect(sessionMaximumAdvice(8)).toBeNull();
        expect(sessionMaximumAdvice(1)).toBeNull();
    });

    it('offers 12 hours to an install that kept its 14 days, naming what it has', () => {
        const advice = sessionMaximumAdvice(336);
        expect(advice).toContain('NIST SP 800-63B');
        expect(advice).toContain('every 12 hours');
        expect(advice).toContain('336 hours (14 days)');
    });

    it('says an instance with no maximum never asks for a new sign-in', () => {
        expect(sessionMaximumAdvice(0)).toContain('no maximum');
    });
});

describe('refreshTokenRule', () => {
    it('always says the session maximum wins', () => {
        for (const [days, max] of [[7, 12], [7, 336], [30, 336], [7, 0]])
            expect(refreshTokenRule(days, max)).toContain('The maximum session lifetime in Security Policy wins over this setting');
    });

    it('says the setting has no effect while the maximum is the shorter', () => {
        const text = refreshTokenRule(7, 12);
        expect(text).toContain('12 hours');
        expect(text).toContain('has no effect until it is shorter than the maximum');
    });

    it('says which ends an unrefreshed and an active session when the maximum is the longer', () => {
        const text = refreshTokenRule(7, 336);
        expect(text).toContain('a session left unrefreshed ends after 7 days');
        expect(text).toContain('an active one after 336 hours (14 days)');
    });

    it('treats a maximum equal to the token lifetime as the maximum deciding', () => {
        expect(refreshTokenRule(1, 24)).toContain('has no effect');
    });

    it('says only the token lifetime and the idle timeout apply when no maximum is set', () => {
        expect(refreshTokenRule(7, 0)).toContain('No maximum is set');
        expect(refreshTokenRule(7, undefined)).toContain('No maximum is set');
    });
});

describe('CA key notices', () => {
    const advisory = { reason: 'CaRsaKeyBelow3072', message: "This CA's key is RSA 2048." };

    it('reads the notices of one CA, and none from a feed without them', () => {
        expect(keyAdvisoriesOf({ keyAdvisories: [advisory] })).toEqual([advisory]);
        expect(keyAdvisoriesOf({})).toEqual([]);
        expect(keyAdvisoriesOf(null)).toEqual([]);
        expect(keyAdvisoriesOf({ keyAdvisories: 'x' })).toEqual([]);
    });

    it('finds every CA with a notice, children and SSH CA keys included, by name', () => {
        const hierarchy = [
            { id: 'r', name: 'Zeta Root', keyAdvisories: [], children: [
                { id: 'i 1', name: 'Old Issuing', keyAdvisories: [advisory], children: [] },
            ] },
            { id: 'e', name: 'Ecdsa Root', keyAdvisories: [] },
            { id: 'd', name: 'Disabled Rsa', isEnabled: false, keyAdvisories: [advisory] },
        ];
        const sshKeys = [{ id: 's', name: 'Fleet', keyAdvisories: [advisory] }, { id: 't', name: 'New', keyAdvisories: [] }];

        const found = caKeyFindings(hierarchy, sshKeys);

        expect(found.map((f) => f.caName)).toEqual(['Disabled Rsa', 'Fleet (SSH)', 'Old Issuing']);
        expect(found.map((f) => f.link)).toEqual(['/authorities/manage/d', '/authorities/ssh/s', '/authorities/manage/i%201']);
        expect(caKeyFindings([], [])).toEqual([]);
        expect(caKeyFindings(undefined as any)).toEqual([]);
    });

    it('offers no RSA size under 3072 for a new CA', () => {
        expect(MIN_CA_RSA_BITS).toBe(3072);
        expect(CA_RSA_KEY_SIZES.map((s) => s.value)).toEqual(['3072', '4096', '7680', '8192']);
        expect(CA_RSA_KEY_SIZES.every((s) => Number(s.value) >= MIN_CA_RSA_BITS)).toBe(true);
    });
});
