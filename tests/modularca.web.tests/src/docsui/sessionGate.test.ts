import { describe, expect, it, vi } from 'vitest';
import { createSessionGate, REVERIFY_AFTER_MS, type VerifyResult } from '@docsui/sessionGate';

/**
 * The docs session gate after the first /me check: navigation re-checks the stored token without
 * hitting the server, /me is re-asked only when stale or on becoming visible, and a sign-out in
 * another tab redirects this one.
 */
function setup() {
    const store = new Map<string, string>([['authToken', 'at-1'], ['refreshToken', 'rt-1'], ['expiresAt', 'x']]);
    let clock = 1_000_000;
    const verify = vi.fn(async (): Promise<VerifyResult> => 'ok');
    const redirectToLogin = vi.fn();
    const gate = createSessionGate({
        hasToken: () => store.has('authToken'),
        verify,
        redirectToLogin,
        now: () => clock,
    });
    const win = new EventTarget();
    const doc = Object.assign(new EventTarget(), { visibilityState: 'visible' });
    const unwatch = gate.watch(win, doc);
    const storageEvent = (key: string | null) => Object.assign(new Event('storage'), { key });
    return { store, gate, verify, redirectToLogin, win, doc, unwatch, storageEvent, tick: (ms: number) => { clock += ms; } };
}

describe('docs session gate', () => {
    it('redirects when another tab clears the tokens', () => {
        const t = setup();
        t.store.clear();
        t.win.dispatchEvent(t.storageEvent('authToken'));
        expect(t.redirectToLogin).toHaveBeenCalledTimes(1);
    });

    it('redirects on localStorage.clear() in another tab (null key)', () => {
        const t = setup();
        t.store.clear();
        t.win.dispatchEvent(t.storageEvent(null));
        expect(t.redirectToLogin).toHaveBeenCalledTimes(1);
    });

    it('ignores a token rotation and unrelated keys', () => {
        const t = setup();
        t.store.set('authToken', 'at-2');
        t.win.dispatchEvent(t.storageEvent('authToken'));
        t.win.dispatchEvent(t.storageEvent('theme'));
        expect(t.redirectToLogin).not.toHaveBeenCalled();
    });

    it('stops listening once unwatched', () => {
        const t = setup();
        t.unwatch();
        t.store.clear();
        t.win.dispatchEvent(t.storageEvent('authToken'));
        expect(t.redirectToLogin).not.toHaveBeenCalled();
    });

    it('redirects on navigation when the token is gone, without calling the server', () => {
        const t = setup();
        t.store.delete('authToken');
        t.gate.onNavigate();
        expect(t.redirectToLogin).toHaveBeenCalledTimes(1);
        expect(t.verify).not.toHaveBeenCalled();
    });

    it('re-verifies on navigation only once the last check is stale', async () => {
        const t = setup();
        await t.gate.verify();
        t.gate.onNavigate();
        t.gate.onNavigate();
        expect(t.verify).toHaveBeenCalledTimes(1);

        t.tick(REVERIFY_AFTER_MS + 1);
        t.gate.onNavigate();
        expect(t.verify).toHaveBeenCalledTimes(2);
    });

    it('re-verifies when the tab becomes visible again', async () => {
        const t = setup();
        await t.gate.verify();
        t.tick(60_000);
        t.doc.dispatchEvent(new Event('visibilitychange'));
        expect(t.verify).toHaveBeenCalledTimes(2);
    });

    it('shares one in-flight verification', async () => {
        const t = setup();
        await Promise.all([t.gate.verify(), t.gate.verify()]);
        expect(t.verify).toHaveBeenCalledTimes(1);
    });
});
