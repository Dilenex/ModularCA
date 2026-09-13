import React from 'react';

/**
 * The AGPL section 13 source-code offer, rendered in every SPA's footer.
 *
 * Section 13 requires that anyone who modifies ModularCA and lets others interact with it over a
 * network prominently offer those users the Corresponding Source of their modified version. Three
 * things follow from the wording, and each shapes this component:
 *
 *  - *"all users interacting with it remotely"* — so this has to appear on the unauthenticated
 *    surface too, not only behind a login. publicui is the load-bearing placement; the others
 *    matter because operators and tenant staff are remote users as well.
 *  - *"the Corresponding Source"* — of the running build, not of whatever `main` happens to be.
 *    So the notice names the version and commit, taken from the build-time constants each SPA
 *    already carries, rather than linking to a moving branch.
 *  - *"of your version"* — so the URL is operator configuration, fetched from the server. A
 *    hardcoded upstream link would be worse than none for a modified deployment: the page would
 *    assert source availability that does not match the binary, on that operator's behalf, to
 *    their own users.
 *
 * The notice never renders empty. If the config fetch fails, the upstream fallback is shown —
 * wrong for a modified build, but a visible statement someone can correct, which a blank footer
 * is not.
 */

export {
    UPSTREAM_SOURCE_URL, DEFAULT_LICENSE, sourceUrlForCommit, noticesUrlForCommit,
    type SourceInfo,
} from './sourceUrls';
import { UPSTREAM_SOURCE_URL, DEFAULT_LICENSE, sourceUrlForCommit, noticesUrlForCommit } from './sourceUrls';
import type { SourceInfo } from './sourceUrls';

/** Props for {@link SourceNotice}. */
export interface SourceNoticeProps {
    /** Running version, from the SPA's `__APP_VERSION__` build constant. */
    version: string;
    /** Short commit of the running build, from `__APP_COMMIT__`. May be "unknown". */
    commit?: string;
    /**
     * Pre-fetched source info. Omit and the component fetches `/api/v1/public/info` itself,
     * which is anonymous and therefore available to every SPA including the setup wizard.
     */
    info?: SourceInfo;
    /** Extra classes for the wrapper, so each app can match its own footer. */
    className?: string;
}

/**
 * Renders "ModularCA v0.1.0-rc4 · Source code (a3f9c21) · AGPL-3.0-only".
 */
export const SourceNotice: React.FC<SourceNoticeProps> = ({
    version,
    commit,
    info,
    className = '',
}) => {
    const [fetched, setFetched] = React.useState<SourceInfo | null>(info ?? null);

    React.useEffect(() => {
        if (info) { setFetched(info); return; }

        let cancelled = false;
        // Relative path: every SPA is served same-origin in Staging/Release builds, which is the
        // only configuration a remote user ever reaches.
        fetch('/api/v1/public/info', { credentials: 'same-origin' })
            .then(r => (r.ok ? r.json() : null))
            .then(body => {
                if (cancelled || !body) return;
                const url = typeof body.sourceCodeUrl === 'string' ? body.sourceCodeUrl : '';
                const license = typeof body.license === 'string' ? body.license : '';
                setFetched({
                    sourceCodeUrl: url || UPSTREAM_SOURCE_URL,
                    license: license || DEFAULT_LICENSE,
                });
            })
            .catch(() => { /* fallback below; a failed fetch must not blank the notice */ });

        return () => { cancelled = true; };
    }, [info]);

    const sourceCodeUrl = fetched?.sourceCodeUrl || UPSTREAM_SOURCE_URL;
    const license = fetched?.license || DEFAULT_LICENSE;
    const href = sourceUrlForCommit(sourceCodeUrl, commit ?? '');
    const showCommit = !!commit && commit !== 'unknown';

    return (
        <div className={`text-xs text-gray-600 dark:text-gray-400 ${className}`}>
            <span>ModularCA </span>
            <span className="font-mono">v{version}</span>
            <span aria-hidden="true"> · </span>
            <a
                href={href}
                target="_blank"
                rel="noopener noreferrer"
                className="underline hover:text-gray-900 dark:hover:text-gray-100"
            >
                Source code
            </a>
            {showCommit && (
                <>
                    <span> (</span>
                    <span className="font-mono select-all">{commit}</span>
                    <span>)</span>
                </>
            )}
            <span aria-hidden="true"> · </span>
            <span>{license}</span>
            {/* The components inside this build are MIT, BSD and Apache-2.0, and each of those
                permits redistribution on the condition that its notice travels with the binary.
                The notices ship in the distribution, but a file in /opt that nobody opens is a
                disclosure only in theory — this is the version a reader can actually reach. The
                link follows the same commit as the source link above, so it describes the build
                being run rather than whatever is on the default branch today. */}
            <span aria-hidden="true"> · </span>
            <a
                href={noticesUrlForCommit(sourceCodeUrl, commit ?? '')}
                target="_blank"
                rel="noopener noreferrer"
                className="underline hover:text-gray-900 dark:hover:text-gray-100"
            >
                Third-party notices
            </a>
        </div>
    );
};
