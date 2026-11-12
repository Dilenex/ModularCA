/**
 * The Protocol Configuration page's load-and-save state, kept out of React so the race it guards
 * against can be tested.
 *
 * Bug hunt 2026-11: switching CA (or scope) while a load was in flight let a late response for the
 * previous CA overwrite the form, and the page cleared its loading flag on whichever response came
 * back first. The cards then showed one CA's settings while Save wrote them to the CA the selector
 * named. Every response and every save now carries the CA it belongs to, and is dropped when that
 * is not the CA selected.
 */

/** The configuration rows and the CA they were read for. */
export interface LoadedProtocolConfigs {
    caId: string;
    configs: any[];
}

/** What the page holds: the CA selected, whether its load is in flight, and what has arrived. */
export interface ProtocolConfigState {
    selectedCaId: string;
    loading: boolean;
    /** The last configuration accepted, or null while none is shown for the selected CA. */
    loaded: LoadedProtocolConfigs | null;
    /**
     * Whether the selected CA's load failed. The page shows the error inline and keeps the CA
     * selector usable, so the operator can move to another CA; selecting one clears it.
     */
    failed: boolean;
}

export type ProtocolConfigEvent =
    /** The operator, or the console scope, picked a CA. */
    | { type: 'select'; caId: string }
    /** The authority list arrived; its first CA is taken only when none is selected yet. */
    | { type: 'selectDefault'; caId: string }
    /** A load for `caId` answered. */
    | { type: 'loaded'; caId: string; configs: any[] }
    /** A load for `caId` failed. */
    | { type: 'failed'; caId: string };

/** The state before anything has loaded, starting on the scoped CA when there is one. */
export function initialProtocolConfigState(selectedCaId: string): ProtocolConfigState {
    return { selectedCaId, loading: !!selectedCaId, loaded: null, failed: false };
}

/**
 * Applies one event. A response or failure for a CA other than the one selected is ignored, so a
 * slow answer for the previous CA can neither paint the form nor end the current load.
 */
export function protocolConfigReducer(state: ProtocolConfigState, event: ProtocolConfigEvent): ProtocolConfigState {
    switch (event.type) {
        case 'select':
            if (event.caId === state.selectedCaId) return state;
            return { selectedCaId: event.caId, loading: !!event.caId, loaded: null, failed: false };
        case 'selectDefault':
            if (state.selectedCaId || !event.caId) return state;
            return { selectedCaId: event.caId, loading: true, loaded: null, failed: false };
        case 'loaded':
            if (event.caId !== state.selectedCaId) return state;
            return { ...state, loading: false, loaded: { caId: event.caId, configs: event.configs }, failed: false };
        case 'failed':
            if (event.caId !== state.selectedCaId) return state;
            return { ...state, loading: false, loaded: null, failed: true };
        default:
            return state;
    }
}

/** The rows to render, or null while none belong to the selected CA. */
export function shownConfigs(state: ProtocolConfigState): any[] | null {
    return !state.loading && state.loaded && state.loaded.caId === state.selectedCaId ? state.loaded.configs : null;
}

/**
 * The CA a save may write to, or null when it must be refused: a load is in flight, nothing is
 * shown, or the form was filled from a different CA than the one now selected.
 *
 * @param formCaId The CA whose configuration filled the form being saved.
 */
export function saveTarget(state: ProtocolConfigState, formCaId: string): string | null {
    if (state.loading || !state.loaded) return null;
    if (state.loaded.caId !== state.selectedCaId || formCaId !== state.selectedCaId) return null;
    return state.selectedCaId;
}

/**
 * One of the page's lists as the page holds it: the items when the request answered, or the
 * failure when it did not. A failed list is never an empty one, so the page can tell "this CA has
 * no profiles" from "the profiles could not be read".
 */
export type PageList =
    | { ok: true; items: any[] }
    | { ok: false; error: unknown };

/** The three lists the page loads together when it opens. */
export interface ProtocolConfigPageData {
    authorities: PageList;
    signingProfiles: PageList;
    certProfiles: PageList;
}

/** Reads a list response that is either an array or an object carrying one under a known key. */
function listOf(data: any, keys: string[]): any[] {
    if (Array.isArray(data)) return data;
    for (const key of keys) if (Array.isArray(data?.[key])) return data[key];
    return [];
}

/** Turns one settled request into a {@link PageList}, reading its items under the given keys. */
function settledList(result: PromiseSettledResult<any>, keys: string[]): PageList {
    return result.status === 'fulfilled'
        ? { ok: true, items: listOf(result.value, keys) }
        : { ok: false, error: result.reason };
}

/**
 * Sorts out the page's opening loads, settled independently.
 *
 * Bug hunt 2026-11: the page loaded the authority list, the signing profiles and the certificate
 * profiles with one Promise.all, so a failed profile request raised the whole-page error, which
 * hid the CA selector as if there were no authorities. Only the authority list leaves nothing to
 * select; a profile list that fails is reported inline and its picker disabled, and the rest of
 * the page stays usable.
 */
export function settleProtocolConfigPage(
    results: [PromiseSettledResult<any>, PromiseSettledResult<any>, PromiseSettledResult<any>],
): ProtocolConfigPageData {
    const [authorities, signingProfiles, certProfiles] = results;
    return {
        authorities: settledList(authorities, ['items', 'authorities']),
        signingProfiles: settledList(signingProfiles, ['items', 'profiles']),
        certProfiles: settledList(certProfiles, ['items', 'profiles']),
    };
}

/** The items of a list, or an empty array when it failed. */
export function itemsOf(list: PageList): any[] {
    return list.ok ? list.items : [];
}

/**
 * The profile lists that failed to load, by the name the page shows for each, in the order the
 * pickers appear. Empty when both answered.
 */
export function failedProfileLists(data: Pick<ProtocolConfigPageData, 'signingProfiles' | 'certProfiles'>): string[] {
    const failed: string[] = [];
    if (!data.signingProfiles.ok) failed.push('signing profiles');
    if (!data.certProfiles.ok) failed.push('certificate profiles');
    return failed;
}
