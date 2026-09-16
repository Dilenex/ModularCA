import { describe, expect, it } from 'vitest';
import { searchPages } from '@adminui/search';

/**
 * Page matching behind the top bar's search: every query word must match somewhere, name
 * hits outrank keyword hits, and an empty query yields nothing rather than everything.
 */
const pages = [
    { name: 'All Certificates', path: '/certificates', section: 'Certificates', keywords: ['certs', 'revoke'] },
    { name: 'Trust Anchors', path: '/trust-anchors', section: 'CA Management', keywords: ['trust store', 'external ca', 'certificates'] },
    { name: 'Audit Logs', path: '/audit', section: 'Administration', keywords: ['events', 'history'] },
    { name: 'Web TLS Certificate', path: '/webtls', section: 'Administration' },
];

describe('searchPages', () => {
    it('returns nothing for an empty query', () => {
        expect(searchPages(pages, '')).toEqual([]);
        expect(searchPages(pages, '   ')).toEqual([]);
    });

    it('ranks a name hit above a keyword hit, and a name that starts with the query first', () => {
        expect(searchPages(pages, 'cert').map(p => p.path)).toEqual(['/certificates', '/webtls', '/trust-anchors']);
    });

    it('requires every word to match, across name, section and keywords', () => {
        expect(searchPages(pages, 'audit history').map(p => p.path)).toEqual(['/audit']);
        expect(searchPages(pages, 'audit certificates')).toEqual([]);
        expect(searchPages(pages, 'administration').map(p => p.path).sort()).toEqual(['/audit', '/webtls']);
    });

    it('matches case-insensitively and honours the limit', () => {
        expect(searchPages(pages, 'CERT', 2).map(p => p.path)).toEqual(['/certificates', '/webtls']);
    });
});
