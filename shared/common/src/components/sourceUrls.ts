/**
 * The constants and URL construction behind the AGPL section 13 source offer and the third-party
 * notices link.
 *
 * Split out of SourceNotice.tsx so it can be tested. The test project deliberately carries no
 * React, so anything importing a .tsx is unreachable from it — and these are exactly the functions
 * that must not be trusted to inspection: they build the links that discharge a licence obligation,
 * and a wrong one fails silently because a 404 in a footer is something nobody reports.
 */

/** Canonical upstream repository, mirroring `SourceCodeConfig.UpstreamUrl` on the server. */
export const UPSTREAM_SOURCE_URL = 'https://github.com/Dilenex/ModularCA';

/** Default SPDX identifier, mirroring `SourceCodeConfig.License`. */
export const DEFAULT_LICENSE = 'AGPL-3.0-only';

/** The subset of `/api/v1/public/info` this component needs. */
export interface SourceInfo {
    /** Where the Corresponding Source for the running build can be obtained. */
    sourceCodeUrl: string;
    /** SPDX identifier of the terms this deployment is offered under. */
    license: string;
}

/**
 * Builds a link that identifies the running build rather than a moving branch.
 *
 * For a GitHub or GitLab URL a known commit becomes a permalink to that exact tree. Anything
 * else — a self-hosted Gitea, a tarball, a plain directory listing — is returned untouched,
 * because guessing another forge's URL layout would produce confidently broken links. The commit
 * is still displayed beside it either way, so the reader can always tell what to ask for.
 */
export function sourceUrlForCommit(baseUrl: string, commit: string): string {
    const url = (baseUrl || UPSTREAM_SOURCE_URL).replace(/\/+$/, '');
    if (!commit || commit === 'unknown') return url;

    if (/^https:\/\/(www\.)?github\.com\//i.test(url)) return `${url}/tree/${commit}`;
    if (/^https:\/\/(www\.)?gitlab\.com\//i.test(url)) return `${url}/-/tree/${commit}`;
    return url;
}

/**
 * Link to the third-party notices for the exact build being run.
 *
 * A sibling of {@link sourceUrlForCommit} and deliberately as conservative: a known forge gets a
 * commit-pinned path, and anything else falls back to the repository root rather than a guessed
 * one. The notices describe the components inside THIS binary, so a link to whatever sits on the
 * default branch today would eventually describe a different set of components than the build the
 * reader is actually looking at.
 */
export function noticesUrlForCommit(baseUrl: string, commit: string): string {
    const url = (baseUrl || UPSTREAM_SOURCE_URL).replace(/\/+$/, '');
    const ref = commit && commit !== 'unknown' ? commit : null;

    if (/^https:\/\/(www\.)?github\.com\//i.test(url)) {
        return ref ? `${url}/blob/${ref}/THIRD-PARTY-NOTICES.md` : `${url}/blob/HEAD/THIRD-PARTY-NOTICES.md`;
    }
    if (/^https:\/\/(www\.)?gitlab\.com\//i.test(url)) {
        return ref ? `${url}/-/blob/${ref}/THIRD-PARTY-NOTICES.md` : `${url}/-/blob/HEAD/THIRD-PARTY-NOTICES.md`;
    }
    return url;
}
