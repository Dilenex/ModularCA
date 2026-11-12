import { describe, expect, it } from 'vitest';
import { navItemActive } from '@adminui/navActive';

describe('navItemActive', () => {
    it('lights the item whose path is the page', () => {
        expect(navItemActive('/requests', '/requests', true)).toBe(true);
        expect(navItemActive('/request', '/request', true)).toBe(true);
    });

    it('does not light an item whose path is only a prefix of another page', () => {
        // The fault: on My Requests, "Request Certificate" (/request) was lit as well.
        expect(navItemActive('/requests', '/request', true)).toBe(false);
        expect(navItemActive('/certificates-old', '/certificates', true)).toBe(false);
    });

    it('lights an item for the pages under it, when it covers them', () => {
        expect(navItemActive('/certificates/0A1B', '/certificates', true)).toBe(true);
        expect(navItemActive('/requests/42', '/requests', true)).toBe(true);
        expect(navItemActive('/certificates/0A1B', '/certificates', false)).toBe(false);
    });
});
