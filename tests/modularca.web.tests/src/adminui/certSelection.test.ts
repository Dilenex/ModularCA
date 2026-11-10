import { describe, expect, it } from 'vitest';
import { revocableSerials, selectionScopeKey } from '@adminui/pages/certSelection';

// Bug hunt 2026-11, admin console: after a space switch on the Certificates page the bulk
// selection survived, so bulk revoke acted on certificates the page no longer listed.
describe('the Certificates bulk selection', () => {
    it('changes key when the space scope changes, even with no CA filter', () => {
        // The old reset keyed on the URL filters and the CA filter only; a space scope reaches the
        // list through the scope context, so switching spaces kept the selection.
        const view = 'status=active';
        expect(selectionScopeKey(view, '', null, 'space-1')).not.toBe(selectionScopeKey(view, '', null, 'space-2'));
        expect(selectionScopeKey(view, '', null, null)).not.toBe(selectionScopeKey(view, '', null, 'space-1'));
    });

    it('changes key when the CA scope, CA filter or filters change', () => {
        const base = selectionScopeKey('status=active', '', 'ca-1', null);
        expect(selectionScopeKey('status=active', '', 'ca-2', null)).not.toBe(base);
        expect(selectionScopeKey('status=active', 'ca-9', 'ca-1', null)).not.toBe(base);
        expect(selectionScopeKey('status=revoked', '', 'ca-1', null)).not.toBe(base);
    });

    it('keeps its key for the same scope and filters', () => {
        expect(selectionScopeKey('status=active', 'ca-1', 'ca-1', null)).toBe(selectionScopeKey('status=active', 'ca-1', 'ca-1', null));
    });

    it('does not confuse values that run together', () => {
        expect(selectionScopeKey('a', 'b', null, null)).not.toBe(selectionScopeKey('ab', '', null, null));
    });
});

describe('the serials bulk revoke submits', () => {
    const listed = new Map<string, unknown>([['01', {}], ['02', {}], ['03', {}]]);

    it('submits the selected serials listed in the current scope', () => {
        expect(revocableSerials(new Set(['01', '03']), listed)).toEqual(['01', '03']);
    });

    it('drops a serial selected in another scope', () => {
        expect(revocableSerials(new Set(['01', 'from-other-space']), listed)).toEqual(['01']);
    });

    it('submits nothing when nothing selected is listed', () => {
        expect(revocableSerials(new Set(['x', 'y']), listed)).toEqual([]);
        expect(revocableSerials(new Set(), listed)).toEqual([]);
    });
});
