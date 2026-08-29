import React, { createContext, useContext } from 'react';
import type { createAuthClient } from './createClient';

/**
 * Supplies the app's authenticated API client to shared pages.
 *
 * Shared *components* have so far taken the one or two calls they need as props — `StepUpMfaModal`
 * takes `apiPost`, `TablePrefsProvider` takes `apiGet`/`apiPut`. That stops scaling at page level:
 * `MySecurity` alone uses eight of the client's functions, and threading eight props through
 * every consumer would be worse than the duplication it replaces.
 *
 * So a page reaches for the whole client through context instead. There is still exactly one
 * client per app, created in that app's `api/client.ts` with its own route basename, and the
 * provider is what hands it to shared code rather than shared code importing it — which it cannot
 * do, and which is the rule that keeps the boundary honest.
 */

/** The full surface returned by {@link createAuthClient}. */
export type AuthClient = ReturnType<typeof createAuthClient>;

const AuthClientContext = createContext<AuthClient | null>(null);

/** Mount once at the app root, above any shared page. */
export const AuthClientProvider: React.FC<{
    client: AuthClient;
    children: React.ReactNode;
}> = ({ client, children }) => (
    <AuthClientContext.Provider value={client}>{children}</AuthClientContext.Provider>
);

/**
 * Returns the consuming app's API client.
 *
 * Throws when no provider is mounted. That is deliberate and unlike `useTablePrefs`, which
 * degrades to local storage: a page that cannot reach the API has nothing to render and no
 * meaningful fallback, so failing at mount with a clear message beats every call site throwing
 * `undefined is not a function` somewhere further in.
 */
export function useAuthClient(): AuthClient {
    const client = useContext(AuthClientContext);
    if (!client) {
        throw new Error(
            'useAuthClient() requires an <AuthClientProvider> above it. Mount one at the app root ' +
            'with the client from this app\'s api/client.ts.',
        );
    }
    return client;
}
