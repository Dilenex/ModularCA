import { describe, expect, it } from 'vitest';
import { crlAvailability } from '@adminui/pages/crlAvailability';

const ca = { id: 'ca-1', certificateId: 'cert-1' };

describe('which CRLs a CA publishes', () => {
    it('offers no delta download for a CA with only a full schedule', () => {
        const schedules = [{ caCertificateId: 'cert-1', isDelta: false, deltaInterval: '' }];
        expect(crlAvailability(ca, schedules)).toEqual({ full: true, delta: false });
    });

    it('offers a delta when the full schedule names a delta interval', () => {
        const schedules = [{ caCertificateId: 'cert-1', isDelta: false, deltaInterval: '*/10 * * * *' }];
        expect(crlAvailability(ca, schedules)).toEqual({ full: true, delta: true });
    });

    it('offers a delta when the CA has a delta schedule of its own', () => {
        const schedules = [
            { caCertificateId: 'cert-1', isDelta: false },
            { caCertificateId: 'cert-1', isDelta: true },
        ];
        expect(crlAvailability(ca, schedules)).toEqual({ full: true, delta: true });
    });

    it('offers nothing for a CA with no schedule, whatever other CAs have', () => {
        const schedules = [{ caCertificateId: 'cert-2', isDelta: true, deltaInterval: '*/10 * * * *' }];
        expect(crlAvailability(ca, schedules)).toEqual({ full: false, delta: false });
    });

    it('hides nothing when the schedules could not be loaded', () => {
        expect(crlAvailability(ca, null)).toEqual({ full: true, delta: true });
    });
});
