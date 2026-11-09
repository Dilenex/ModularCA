import { describe, expect, it } from 'vitest';
import { csrfHeader, readCsrfCookie } from '@shared/csrf';

/**
 * The backend sets `__Host-CSRF-TOKEN` over HTTPS and `CSRF-TOKEN` over plain HTTP, and never
 * accepts the unprefixed one over HTTPS, so the prefixed cookie must win when both are present.
 */
describe('CSRF cookie', () => {
    it('reads the host-prefixed cookie', () => {
        expect(readCsrfCookie('theme=dark; __Host-CSRF-TOKEN=abc123')).toBe('abc123');
    });

    it('falls back to the unprefixed cookie on plain HTTP', () => {
        expect(readCsrfCookie('CSRF-TOKEN=plain')).toBe('plain');
    });

    it('prefers the prefixed cookie over a leftover unprefixed one, in either order', () => {
        expect(readCsrfCookie('CSRF-TOKEN=old; __Host-CSRF-TOKEN=new')).toBe('new');
        expect(readCsrfCookie('__Host-CSRF-TOKEN=new; CSRF-TOKEN=old')).toBe('new');
    });

    it('does not mistake another cookie whose name ends in CSRF-TOKEN', () => {
        expect(readCsrfCookie('X-CSRF-TOKEN=nope')).toBeNull();
    });

    it('decodes the value and returns null when no token is set', () => {
        expect(readCsrfCookie('__Host-CSRF-TOKEN=a%2Bb')).toBe('a+b');
        expect(readCsrfCookie('theme=dark')).toBeNull();
        expect(readCsrfCookie('')).toBeNull();
    });

    it('builds the header only when a token exists', () => {
        expect(csrfHeader('__Host-CSRF-TOKEN=t')).toEqual({ 'X-CSRF-Token': 't' });
        expect(csrfHeader('')).toEqual({});
    });
});
