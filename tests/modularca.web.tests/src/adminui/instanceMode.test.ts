import { describe, expect, it } from 'vitest';
import {
    INSTANCE_MODE_OPTIONS, instanceModeBanner, modeChangeBlocked, modeName, modeTitle, setByText,
} from '@adminui/pages/instanceMode';

const status = (over: Record<string, unknown>) => ({
    mode: 'full', source: 'default', setBy: null, reason: null, setAtUtc: null, hubConnection: false, stillWorks: '', ...over,
});

describe('instance mode', () => {
    it('offers exactly the four modes, each saying what it stops and keeps', () => {
        expect(INSTANCE_MODE_OPTIONS.map((o) => o.value)).toEqual(['full', 'restricted', 'maintenance', 'dr']);
        for (const option of INSTANCE_MODE_OPTIONS) {
            expect(option.stops.length).toBeGreaterThan(0);
            expect(option.keeps.length).toBeGreaterThan(0);
        }
        expect(INSTANCE_MODE_OPTIONS[1].keeps).toContain('revoking');
        expect(INSTANCE_MODE_OPTIONS[1].stops).toContain('ceremonies');
        // Maintenance stops issuing and keeps revocation and its checks.
        expect(INSTANCE_MODE_OPTIONS[2].stops).toContain('issuing');
        expect(INSTANCE_MODE_OPTIONS[2].keeps).toContain('Revoking');
        expect(INSTANCE_MODE_OPTIONS[2].keeps).toContain('OCSP');
        expect(INSTANCE_MODE_OPTIONS[3].stops).toContain('OCSP');
        expect(INSTANCE_MODE_OPTIONS[3].keeps).toContain('changing the mode');
    });

    it('treats a mode it does not know as DR mode, the most restrictive', () => {
        expect(modeName('full')).toBe('full');
        expect(modeName('restricted')).toBe('restricted');
        expect(modeName('dr')).toBe('dr');
        expect(modeName('maintenance')).toBe('maintenance');
        expect(modeTitle('maintenance')).toBe('Maintenance mode');
        expect(modeName('standby')).toBe('dr');
        expect(modeTitle('dr')).toBe('DR mode');
    });

    it('shows no banner in full mode or before the mode is known', () => {
        expect(instanceModeBanner(null)).toBeNull();
        expect(instanceModeBanner(status({}))).toBeNull();
    });

    it('shows a standing banner while restricted, saying who set it', () => {
        const banner = instanceModeBanner(status({ mode: 'restricted', source: 'hub' }))!;
        expect(banner.tone).toBe('warn');
        expect(banner.title).toBe('Restricted mode.');
        expect(banner.text).toContain('Issuing and revoking go on.');
        expect(banner.text).toContain('Set by the hub.');
    });

    it('shows a warning banner in maintenance mode that says revocation goes on', () => {
        const banner = instanceModeBanner(status({ mode: 'maintenance', source: 'administrator', setBy: 'root' }))!;
        expect(banner.tone).toBe('warn');
        expect(banner.title).toBe('Maintenance mode.');
        expect(banner.text).toContain('Nothing is issued. Revoking, CRLs and OCSP go on.');
    });

    it('shows a critical banner in DR mode', () => {
        const banner = instanceModeBanner(status({ mode: 'dr', source: 'administrator', setBy: 'root' }))!;
        expect(banner.tone).toBe('crit');
        expect(banner.text).toContain('Nothing is issued or revoked');
        expect(banner.text).toContain('Set by root.');
    });

    it('says who set the mode', () => {
        expect(setByText({ source: 'hub', setBy: 'alice' })).toContain('alice');
        expect(setByText({ source: 'hub', setBy: null })).toBe('the hub');
        expect(setByText({ source: 'administrator', setBy: 'bob' })).toBe('administrator bob');
        expect(setByText({ source: 'default', setBy: null })).toContain('default');
        expect(setByText({ source: 'unreadable', setBy: null })).toContain('could not be read');
    });

    it('blocks a change to the current mode and a change without a reason', () => {
        expect(modeChangeBlocked('dr', 'dr', 'x')).not.toBeNull();
        expect(modeChangeBlocked('dr', 'full', '  ')).not.toBeNull();
        expect(modeChangeBlocked('dr', 'full', 'the hub is gone')).toBeNull();
        expect(modeChangeBlocked('full', 'dr', 'x'.repeat(501))).not.toBeNull();
    });
});
