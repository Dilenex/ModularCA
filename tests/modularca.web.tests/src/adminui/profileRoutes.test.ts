import { describe, expect, it } from 'vitest';
import {
    NEW_PROFILE_SEGMENT, PROFILE_TABS, PROFILE_TYPES, profileDetailPath, profileDetailRoute, profileNewRoute,
    type ProfileType,
} from '@adminui/pages/profiles/profileRoutes';

/**
 * The paths App.tsx registers for the profile pages and the links the list tabs and detail pages
 * build. The router itself is not reachable from this React-free project; what is pinned here is
 * that each type's create page is a static `new` segment beside, not inside, its `:id` pattern,
 * and that Cancel on a new profile lands on the tab the type is listed under.
 */
describe('profile routes', () => {
    const types = Object.keys(PROFILE_TYPES) as ProfileType[];

    it('covers the six profile types', () => {
        expect(types.sort()).toEqual(['cert', 'request', 'signing', 'ssh-cert', 'ssh-request', 'ssh-signing']);
    });

    it('gives every type a static /new route next to its :id route', () => {
        for (const type of types) {
            expect(profileNewRoute(type)).toBe(`/profiles/${type}/${NEW_PROFILE_SEGMENT}`);
            expect(profileDetailRoute(type)).toBe(`/profiles/${type}/:id`);
            expect(profileNewRoute(type)).not.toContain(':');
        }
    });

    it('sends each type back to a tab the list page knows', () => {
        for (const type of types) {
            const { tab, listPath } = PROFILE_TYPES[type];
            expect(PROFILE_TABS).toContain(tab);
            expect(new URL(listPath, 'https://x').searchParams.get('tab')).toBe(tab);
        }
    });

    it('builds a detail link that cannot collide with the create page', () => {
        expect(profileDetailPath('cert', '0b6f3f0e-1111-4c4c-9a9a-000000000001')).toBe('/profiles/cert/0b6f3f0e-1111-4c4c-9a9a-000000000001');
    });
});
