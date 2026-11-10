import { describe, expect, it } from 'vitest';
import { latestRequest } from '@shared/latestRequest';

/**
 * A list page's load, keyed on the scope: the response for a scope the user has already left
 * must not land on the page. These tests drive a page-shaped load with a fake fetch whose
 * responses arrive in an order the test chooses.
 */

/** A fetch whose responses the test releases one by one, in any order. */
function fakeFetch() {
    const pending = new Map<string, (rows: string[]) => void>();
    return {
        get: (url: string) => new Promise<string[]>((resolve) => { pending.set(url, resolve); }),
        respond: async (url: string, rows: string[]) => { pending.get(url)!(rows); await Promise.resolve(); await Promise.resolve(); },
    };
}

/** The shape of a console list page: one `load(scope)` writing rows into state. */
function listPage(fetch: ReturnType<typeof fakeFetch>, guarded: boolean) {
    const loads = latestRequest();
    const state = { rows: [] as string[] };
    const load = (scope: string) => {
        const current = guarded ? loads.begin() : () => true;
        state.rows = [];
        return fetch.get(`/api/v1/admin/requests?spaceId=${scope}`).then((rows) => { if (current()) state.rows = rows; });
    };
    return { state, load, loads };
}

describe('latestRequest', () => {
    it('without it, a slow response for the previous scope replaces the current one', async () => {
        // The behaviour the console had: switch from alpha to beta, alpha answers last, alpha wins.
        const fetch = fakeFetch();
        const page = listPage(fetch, false);
        void page.load('alpha');
        void page.load('beta');
        await fetch.respond('/api/v1/admin/requests?spaceId=beta', ['beta-1']);
        await fetch.respond('/api/v1/admin/requests?spaceId=alpha', ['alpha-1']);
        expect(page.state.rows).toEqual(['alpha-1']);
    });

    it('with it, the response for a scope the user has left is ignored', async () => {
        const fetch = fakeFetch();
        const page = listPage(fetch, true);
        void page.load('alpha');
        void page.load('beta');
        await fetch.respond('/api/v1/admin/requests?spaceId=beta', ['beta-1']);
        await fetch.respond('/api/v1/admin/requests?spaceId=alpha', ['alpha-1']);
        expect(page.state.rows).toEqual(['beta-1']);
    });

    it('a response that arrives in order is kept', async () => {
        const fetch = fakeFetch();
        const page = listPage(fetch, true);
        void page.load('alpha');
        await fetch.respond('/api/v1/admin/requests?spaceId=alpha', ['alpha-1']);
        expect(page.state.rows).toEqual(['alpha-1']);
    });

    it('cancel makes every load started so far stale, and a later load is current again', async () => {
        const fetch = fakeFetch();
        const page = listPage(fetch, true);
        void page.load('alpha');
        page.loads.cancel();
        await fetch.respond('/api/v1/admin/requests?spaceId=alpha', ['alpha-1']);
        expect(page.state.rows).toEqual([]);
        void page.load('beta');
        await fetch.respond('/api/v1/admin/requests?spaceId=beta', ['beta-1']);
        expect(page.state.rows).toEqual(['beta-1']);
    });

    it('each gate is independent', () => {
        const a = latestRequest();
        const b = latestRequest();
        const first = a.begin();
        b.begin();
        expect(first()).toBe(true);
        a.begin();
        expect(first()).toBe(false);
    });
});
