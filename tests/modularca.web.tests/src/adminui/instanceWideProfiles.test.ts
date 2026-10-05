import { describe, expect, it } from 'vitest';
import {
    isInstanceWideCertProfile, isUnboundRequestProfile, isUnboundSigningProfile, mayChangeProfile,
} from '@adminui/pages/profiles/instanceWide';

/**
 * The console offers Edit and Delete on an instance-wide profile only to a caller holding the
 * create capability at system scope, as the server requires; a space's or CA's own profile stays
 * editable for its space admin.
 */
describe('instance-wide profiles', () => {
    it('recognises each kind', () => {
        expect(isInstanceWideCertProfile({ spaceId: null, certificateAuthorityId: null })).toBe(true);
        expect(isInstanceWideCertProfile({ spaceId: 's1', certificateAuthorityId: null })).toBe(false);
        expect(isInstanceWideCertProfile({ spaceId: null, certificateAuthorityId: 'ca1' })).toBe(false);
        expect(isUnboundSigningProfile({ issuerId: null })).toBe(true);
        expect(isUnboundSigningProfile({ issuerId: 'cert1' })).toBe(false);
        expect(isUnboundRequestProfile({ certificateAuthorityId: undefined })).toBe(true);
        expect(isUnboundRequestProfile({ certificateAuthorityId: 'ca1' })).toBe(false);
        expect(isInstanceWideCertProfile(null)).toBe(false);
    });

    it('lets only a system-scope holder change one, and anyone change a scoped one', () => {
        expect(mayChangeProfile(true, false)).toBe(false);
        expect(mayChangeProfile(true, true)).toBe(true);
        expect(mayChangeProfile(false, false)).toBe(true);
    });
});
