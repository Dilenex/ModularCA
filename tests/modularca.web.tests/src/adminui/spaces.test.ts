import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { legacySpacePath } from '@adminui/legacyPaths';
import * as spaceCreation from '@adminui/pages/spaceCreation';
import { SPACE_INTERSTITIAL } from '@adminui/pages/spaceCreation';

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
 * The Create Space dialog: what a space is (and is not) before every create. Spaces are not
 * counted, limited or licensed, so the dialog and the page say nothing about a license at any
 * number of spaces.
 */
describe('the Create Space dialog', () => {
    it('says what a space shares and that a separate customer is a separate instance', () => {
        expect(SPACE_INTERSTITIAL).toBe(
            'Spaces delegate administration within one organisation. They share sign-in, backups, the audit trail and instance administrators. For a separate customer, create a separate instance.');
    });

    it('has no license hint: the dialog module exports only what a space is', () => {
        expect(Object.keys(spaceCreation)).toEqual(['SPACE_INTERSTITIAL']);
    });

    it('says nothing about a license or a number of spaces, in the dialog module or on the page', () => {
        for (const file of ['spaceCreation.ts', 'SpacesAndQuotas.tsx']) {
            const source = readFileSync(fileURLToPath(new URL(`../../../../modularca.adminui/src/pages/${file}`, import.meta.url)), 'utf8');
            expect(source, file).not.toMatch(/recommend/i);
            expect(source, file).not.toMatch(/licen[cs]e (is|was) /i);
            expect(source, file).not.toMatch(/more than four|fifth space/i);
        }
        expect(SPACE_INTERSTITIAL).not.toMatch(/licen[cs]e/i);
    });
});
