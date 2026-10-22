import { describe, expect, it } from 'vitest';
import { certExpiryNotificationBody, jwtIpBindingMode, warningDaysFromConfig, type CertExpiryNotificationBody } from '@adminui/pages/settingsLists';
import { bodyKeys, dtoKeys } from './profileFormKit';

/**
 * The Cert Expiry Notifications card on /settings.
 *
 * GET /admin/config returns the section as CertExpiryNotificationConfig, whose list is
 * `warningDaysBeforeExpiry`; PUT /admin/config/cert-expiry-notifications reads
 * CertExpiryNotificationUpdateRequest, whose list is `WarningDays` as List<int>. The page used
 * `warningDays` for both, so it showed nothing and sent a string the int list cannot bind.
 */

// CertExpiryNotificationUpdateRequest (AdminConfigController.cs).
const PUT_KEYS = ['enabled', 'warningDays', 'schedule'].sort();

describe('cert expiry notification settings', () => {
    it('reads the marks from the property GET returns', () => {
        const section = { enabled: true, warningDaysBeforeExpiry: [90, 60, 30, 14, 7, 3, 1], schedule: '0 6 * * *' };
        expect(warningDaysFromConfig(section)).toEqual(['90', '60', '30', '14', '7', '3', '1']);
        expect(warningDaysFromConfig({ warningDays: '30,7' })).toEqual([]);
        expect(warningDaysFromConfig(null)).toEqual([]);
    });

    it('sends the marks as numbers under the PUT name, and nothing else', () => {
        expect(dtoKeys<CertExpiryNotificationBody>({ enabled: true, warningDays: true, schedule: true })).toEqual(PUT_KEYS);
        const section = { enabled: true, warningDaysBeforeExpiry: ['30', '7'], schedule: '0 6 * * *' };
        const body = certExpiryNotificationBody(section, warningDaysFromConfig(section));
        expect(bodyKeys(body)).toEqual(PUT_KEYS);
        expect(body).toEqual({ enabled: true, warningDays: [30, 7], schedule: '' });
    });

    it('round-trips a loaded section unchanged', () => {
        const section = { enabled: false, warningDaysBeforeExpiry: [90, 30] };
        expect(certExpiryNotificationBody(section, warningDaysFromConfig(section)).warningDays).toEqual([90, 30]);
    });
});

describe('the JWT IP binding mode as the server sends it', () => {
    it('is read by name, whatever its case', () => {
        expect(jwtIpBindingMode('Exact')).toBe('Exact');
        expect(jwtIpBindingMode('subnet24')).toBe('Subnet24');
        expect(jwtIpBindingMode('Off')).toBe('Off');
    });

    it('is read by number, as older builds sent it', () => {
        expect(jwtIpBindingMode(0)).toBe('Off');
        expect(jwtIpBindingMode(1)).toBe('Exact');
        expect(jwtIpBindingMode(2)).toBe('Subnet24');
    });

    it('reads as Off when it is missing or unknown', () => {
        expect(jwtIpBindingMode(undefined)).toBe('Off');
        expect(jwtIpBindingMode(null)).toBe('Off');
        expect(jwtIpBindingMode('Strict')).toBe('Off');
        expect(jwtIpBindingMode(7)).toBe('Off');
    });
});
