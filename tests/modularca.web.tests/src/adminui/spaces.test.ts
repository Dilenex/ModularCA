import { describe, expect, it } from 'vitest';
import { legacySpacePath } from '@adminui/legacyPaths';
import {
    LICENCE_RECOMMENDATION, SPACE_INTERSTITIAL, SPACES_WITHOUT_LICENCE, recommendationBeforeCreate, recommendationFromResponse,
} from '@adminui/pages/spaceCreation';

/**
 * The console said "tenant" before 0.4.0. Its pages moved to /spaces with client-side redirects
 * kept for one release, so a bookmark still lands, id and query string intact.
 */
describe('the /tenants redirects', () => {
    it('send /tenants and /tenants/:id to /spaces and /spaces/:id', () => {
        expect(legacySpacePath('/tenants')).toBe('/spaces');
        expect(legacySpacePath('/tenants/')).toBe('/spaces');
        expect(legacySpacePath('/tenants/6d1f3c2a-4b5e-4f60-8a71-0b2c3d4e5f60')).toBe('/spaces/6d1f3c2a-4b5e-4f60-8a71-0b2c3d4e5f60');
    });

    it('keep the query string, with a ?tenant= in it moved to ?space=', () => {
        expect(legacySpacePath('/tenants', '?tab=kerberos')).toBe('/spaces?tab=kerberos');
        expect(legacySpacePath('/tenants/abc', '?tab=kerberos&tenant=one')).toBe('/spaces/abc?tab=kerberos&space=one');
    });

    it('leave every other path alone', () => {
        expect(legacySpacePath('/spaces')).toBeNull();
        expect(legacySpacePath('/tenants/abc/settings')).toBeNull();
        expect(legacySpacePath('/certificates')).toBeNull();
    });
});

/**
 * The Create Space dialog: what a space is (and is not) before every create, and the licence
 * recommendation from the fifth space on, said in advance from the count and confirmed from the
 * server's answer. Creation is never refused.
 */
describe('the Create Space dialog', () => {
    it('says what a space shares and that a separate customer is a separate instance', () => {
        expect(SPACE_INTERSTITIAL).toBe(
            'Spaces delegate administration within one organisation. They share sign-in, backups, the audit trail and instance administrators. For a separate customer, create a separate instance.');
    });

    it('recommends a licence from the fifth space on, and not before', () => {
        expect(SPACES_WITHOUT_LICENCE).toBe(4);
        expect(LICENCE_RECOMMENDATION).toBe('A licence is recommended for more than four spaces.');
        for (const existing of [0, 1, 2, 3]) expect(recommendationBeforeCreate(existing)).toBeNull();
        expect(recommendationBeforeCreate(4)).toBe(LICENCE_RECOMMENDATION);
        expect(recommendationBeforeCreate(9)).toBe(LICENCE_RECOMMENDATION);
    });

    it('shows the recommendation the server returned, and nothing when it returned none', () => {
        expect(recommendationFromResponse({ id: 'x', name: 'Fifth', recommendation: LICENCE_RECOMMENDATION })).toBe(LICENCE_RECOMMENDATION);
        expect(recommendationFromResponse({ id: 'x', name: 'Fifth', recommendation: null })).toBeNull();
        expect(recommendationFromResponse({ id: 'x', name: 'Second' })).toBeNull();
        expect(recommendationFromResponse(null)).toBeNull();
        expect(recommendationFromResponse({ recommendation: '  ' })).toBeNull();
    });
});
