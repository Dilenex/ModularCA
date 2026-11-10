import { describe, expect, it } from 'vitest';
import {
    failedProfileLists, initialProtocolConfigState, itemsOf, protocolConfigReducer, saveTarget, settleProtocolConfigPage, shownConfigs,
    type ProtocolConfigEvent, type ProtocolConfigState,
} from '@adminui/pages/protocolConfigLoad';

// Bug hunt 2026-11, admin console: switching CA while a load was in flight let the previous CA's
// late response overwrite the form, and Save then wrote that CA's settings to the one selected.
const run = (events: ProtocolConfigEvent[], from: ProtocolConfigState = initialProtocolConfigState('')) =>
    events.reduce(protocolConfigReducer, from);

const A = [{ protocol: 'EST', enabled: true }];
const B = [{ protocol: 'EST', enabled: false }];

describe('Protocol Configuration loads', () => {
    it('shows the configuration that arrives for the selected CA', () => {
        const s = run([{ type: 'select', caId: 'a' }, { type: 'loaded', caId: 'a', configs: A }]);
        expect(shownConfigs(s)).toEqual(A);
        expect(s.loading).toBe(false);
    });

    it('ignores a late response for a CA that is no longer selected', () => {
        const s = run([
            { type: 'select', caId: 'a' },
            { type: 'select', caId: 'b' },
            { type: 'loaded', caId: 'b', configs: B },
            { type: 'loaded', caId: 'a', configs: A },
        ]);
        expect(s.loaded?.caId).toBe('b');
        expect(shownConfigs(s)).toEqual(B);
    });

    it('stays loading when the previous CA answers first', () => {
        // The old page cleared its loading flag on whichever response came back first, so the
        // cards rendered A's settings while B was selected.
        const s = run([
            { type: 'select', caId: 'a' },
            { type: 'select', caId: 'b' },
            { type: 'loaded', caId: 'a', configs: A },
        ]);
        expect(s.loading).toBe(true);
        expect(shownConfigs(s)).toBeNull();
    });

    it('ignores a failure for a CA that is no longer selected', () => {
        const s = run([
            { type: 'select', caId: 'a' },
            { type: 'select', caId: 'b' },
            { type: 'failed', caId: 'a' },
        ]);
        expect(s.loading).toBe(true);
    });

    it('drops what was shown as soon as another CA is selected', () => {
        const s = run([
            { type: 'select', caId: 'a' },
            { type: 'loaded', caId: 'a', configs: A },
            { type: 'select', caId: 'b' },
        ]);
        expect(shownConfigs(s)).toBeNull();
    });

    it('takes the first CA as a default only when none is selected', () => {
        expect(run([{ type: 'selectDefault', caId: 'first' }]).selectedCaId).toBe('first');
        expect(run([{ type: 'selectDefault', caId: 'first' }], initialProtocolConfigState('scoped')).selectedCaId).toBe('scoped');
    });

    it('re-selecting the shown CA keeps what is shown', () => {
        const s = run([
            { type: 'select', caId: 'a' },
            { type: 'loaded', caId: 'a', configs: A },
            { type: 'select', caId: 'a' },
        ]);
        expect(shownConfigs(s)).toEqual(A);
        expect(s.loading).toBe(false);
    });
});

// A failed load used to set the page's shared error, which also hid the CA selector, so the
// operator could not move to another CA. The failure is now its own flag: the error shows inline
// while it stands, and selecting another CA clears it.
describe('Protocol Configuration load failures', () => {
    it('marks the selected CA failed, with nothing shown, and stays on that CA', () => {
        const s = run([{ type: 'select', caId: 'a' }, { type: 'failed', caId: 'a' }]);
        expect(s.failed).toBe(true);
        expect(s.loading).toBe(false);
        expect(s.selectedCaId).toBe('a');
        expect(shownConfigs(s)).toBeNull();
    });

    it('clears the failure when another CA is selected, and shows what that CA loads', () => {
        const s = run([
            { type: 'select', caId: 'a' },
            { type: 'failed', caId: 'a' },
            { type: 'select', caId: 'b' },
        ]);
        expect(s.failed).toBe(false);
        expect(s.loading).toBe(true);
        const loaded = run([{ type: 'loaded', caId: 'b', configs: B }], s);
        expect(loaded.failed).toBe(false);
        expect(shownConfigs(loaded)).toEqual(B);
    });

    it('does not mark the current CA failed when a CA already left fails', () => {
        const s = run([
            { type: 'select', caId: 'a' },
            { type: 'select', caId: 'b' },
            { type: 'failed', caId: 'a' },
        ]);
        expect(s.failed).toBe(false);
    });

    it('starts with no failure', () => {
        expect(initialProtocolConfigState('a').failed).toBe(false);
        expect(initialProtocolConfigState('').failed).toBe(false);
    });
});

describe('Protocol Configuration saves', () => {
    const loadedA = run([{ type: 'select', caId: 'a' }, { type: 'loaded', caId: 'a', configs: A }]);

    it('saves to the CA whose settings the form shows', () => {
        expect(saveTarget(loadedA, 'a')).toBe('a');
    });

    it('refuses while a load is in flight', () => {
        expect(saveTarget(run([{ type: 'select', caId: 'b' }], loadedA), 'a')).toBeNull();
    });

    it('refuses a form loaded for a different CA than the one selected', () => {
        // The card's form was filled from A; the selector now says B. Writing either is wrong.
        const s = run([{ type: 'select', caId: 'b' }, { type: 'loaded', caId: 'b', configs: B }], loadedA);
        expect(saveTarget(s, 'a')).toBeNull();
        expect(saveTarget(s, 'b')).toBe('b');
    });

    it('refuses when nothing has loaded', () => {
        expect(saveTarget(run([{ type: 'select', caId: 'a' }]), 'a')).toBeNull();
        expect(saveTarget(run([{ type: 'select', caId: 'a' }, { type: 'failed', caId: 'a' }]), 'a')).toBeNull();
    });
});

// The page loaded the authority list and both profile lists with one Promise.all, so a failed
// profile request raised the whole-page error and hid the CA selector as though there were no
// authorities. Only the authority list failing should do that.
describe('Protocol Configuration opening loads', () => {
    const ok = (value: unknown): PromiseSettledResult<unknown> => ({ status: 'fulfilled', value });
    const no = (reason: unknown): PromiseSettledResult<unknown> => ({ status: 'rejected', reason });
    const cas = [{ id: 'a', name: 'Root' }];
    const sps = [{ id: 'sp1', name: 'TLS', issuerId: 'c1' }];
    const cps = [{ id: 'cp1', name: 'Server' }];

    it('keeps every list when all three answer', () => {
        const page = settleProtocolConfigPage([ok(cas), ok(sps), ok(cps)]);
        expect(page.authorities).toEqual({ ok: true, items: cas });
        expect(itemsOf(page.signingProfiles)).toEqual(sps);
        expect(itemsOf(page.certProfiles)).toEqual(cps);
        expect(failedProfileLists(page)).toEqual([]);
    });

    it('keeps the authorities when the signing profiles fail, and names the failed list', () => {
        const boom = new Error('500');
        const page = settleProtocolConfigPage([ok(cas), no(boom), ok(cps)]);
        expect(page.authorities.ok).toBe(true);
        expect(itemsOf(page.authorities)).toEqual(cas);
        expect(page.signingProfiles).toEqual({ ok: false, error: boom });
        expect(itemsOf(page.certProfiles)).toEqual(cps);
        expect(failedProfileLists(page)).toEqual(['signing profiles']);
    });

    it('keeps the authorities when the certificate profiles fail', () => {
        const page = settleProtocolConfigPage([ok(cas), ok(sps), no(new Error('403'))]);
        expect(page.authorities.ok).toBe(true);
        expect(page.certProfiles.ok).toBe(false);
        expect(itemsOf(page.certProfiles)).toEqual([]);
        expect(failedProfileLists(page)).toEqual(['certificate profiles']);
    });

    it('names both profile lists, in picker order, when both fail', () => {
        const page = settleProtocolConfigPage([ok(cas), no('x'), no('y')]);
        expect(page.authorities.ok).toBe(true);
        expect(failedProfileLists(page)).toEqual(['signing profiles', 'certificate profiles']);
    });

    it('reports the authority list failing on its own, with the profiles that did load', () => {
        const boom = new Error('down');
        const page = settleProtocolConfigPage([no(boom), ok(sps), ok(cps)]);
        expect(page.authorities).toEqual({ ok: false, error: boom });
        expect(itemsOf(page.signingProfiles)).toEqual(sps);
        expect(failedProfileLists(page)).toEqual([]);
    });

    it('reads lists wrapped in an object, and treats an unrecognised shape as empty rather than failed', () => {
        const page = settleProtocolConfigPage([ok({ authorities: cas }), ok({ items: sps }), ok({ profiles: cps })]);
        expect(itemsOf(page.authorities)).toEqual(cas);
        expect(itemsOf(page.signingProfiles)).toEqual(sps);
        expect(itemsOf(page.certProfiles)).toEqual(cps);
        const odd = settleProtocolConfigPage([ok(null), ok({}), ok('nope')]);
        expect(odd.authorities).toEqual({ ok: true, items: [] });
        expect(failedProfileLists(odd)).toEqual([]);
    });
});
