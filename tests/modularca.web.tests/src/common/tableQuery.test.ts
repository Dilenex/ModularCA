import { describe, expect, it } from 'vitest';
import {
    formatSort, parseSort, readTableQuery, removeView, upsertView, viewQuery, writeTableQuery,
} from '@shared/tableQuery';

/**
 * A table's page, sort and filters as they travel in the URL: defaults stay out of the link,
 * the scope keys are never touched, and a saved view is a filter, never a position.
 */
const defaults = { page: '1', pageSize: '20', sort: '-notBefore', status: '', search: '' };

describe('sort', () => {
    it('parses field / -field / field:desc and formats back', () => {
        expect(parseSort('notAfter')).toEqual({ key: 'notAfter', dir: 'asc' });
        expect(parseSort('-notAfter')).toEqual({ key: 'notAfter', dir: 'desc' });
        expect(parseSort('notAfter:desc')).toEqual({ key: 'notAfter', dir: 'desc' });
        expect(parseSort('')).toBeNull();
        expect(parseSort('-')).toBeNull();
        expect(parseSort(null)).toBeNull();
        expect(formatSort({ key: 'a', dir: 'asc' })).toBe('a');
        expect(formatSort({ key: 'a', dir: 'desc' })).toBe('-a');
        expect(formatSort(null)).toBe('');
    });
});

describe('readTableQuery', () => {
    it('takes the URL value when present and the default otherwise', () => {
        expect(readTableQuery('?page=3&status=revoked&ca=staging', defaults)).toEqual({ page: '3', pageSize: '20', sort: '-notBefore', status: 'revoked', search: '' });
    });

    it('namespaces keys with a prefix', () => {
        expect(readTableQuery('?issued.page=2&page=9', { page: '1' }, 'issued')).toEqual({ page: '2' });
    });
});

describe('writeTableQuery', () => {
    it('writes only what differs from the defaults and keeps everything else', () => {
        const out = writeTableQuery('?ca=staging&other=1&page=4', { ...defaults, page: '1', status: 'expired' }, defaults);
        expect(out.toString()).toBe('ca=staging&other=1&status=expired');
    });

    it('never writes or clears the scope keys even when named as table keys', () => {
        const out = writeTableQuery('?ca=staging', { ca: 'zzz', page: '2' }, { ca: '', page: '1' });
        expect(out.toString()).toBe('ca=staging&page=2');
    });
});

describe('saved views', () => {
    it('keep filters and sort, never the page or the scope, in a stable order', () => {
        expect(viewQuery({ ...defaults, page: '5', status: 'revoked', sort: 'subject' }, defaults)).toBe('sort=subject&status=revoked');
        expect(viewQuery(defaults, defaults)).toBe('');
    });

    it('upsert replaces by name case-insensitively and sorts by name; remove drops by name', () => {
        let views = upsertView([], { name: 'Revoked', query: 'status=revoked' });
        views = upsertView(views, { name: 'Expiring', query: 'notAfterTo=x' });
        views = upsertView(views, { name: 'revoked', query: 'status=revoked&sort=subject' });
        expect(views).toEqual([{ name: 'Expiring', query: 'notAfterTo=x' }, { name: 'revoked', query: 'status=revoked&sort=subject' }]);
        expect(upsertView(views, { name: '  ', query: 'x' })).toBe(views);
        expect(removeView(views, 'Expiring')).toEqual([{ name: 'revoked', query: 'status=revoked&sort=subject' }]);
    });
});
