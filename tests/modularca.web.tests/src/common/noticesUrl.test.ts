import { describe, expect, it } from 'vitest';
import { noticesUrlForCommit, sourceUrlForCommit, UPSTREAM_SOURCE_URL } from '@shared/components/sourceUrls';

/**
 * The third-party notices link in every SPA footer.
 *
 * The notices exist because the components inside this binary are MIT, BSD and Apache-2.0, and
 * each of those permits redistribution only on the condition that its notice travels with the
 * binary. The file ships in the tarball and the .deb, but a file in /opt that nobody opens is a
 * disclosure in theory only — the footer link is the version a reader can actually reach, which
 * makes a broken one a compliance problem rather than a cosmetic one.
 *
 * Two properties matter and neither is obvious from reading the function. It must pin to the
 * running commit, because the notices describe the components in THIS build and a link to the
 * default branch drifts away from that silently. And it must refuse to guess at an unknown forge,
 * for the same reason {@link sourceUrlForCommit} does: a confidently wrong URL is worse than an
 * obviously incomplete one, because nobody investigates a link that looks right.
 */
describe('noticesUrlForCommit', () => {
    const GH = 'https://github.com/Dilenex/ModularCA';

    it('pins to the running commit on GitHub', () => {
        expect(noticesUrlForCommit(GH, 'a3f9c21'))
            .toBe(`${GH}/blob/a3f9c21/THIRD-PARTY-NOTICES.md`);
    });

    it('pins to the running commit on GitLab', () => {
        expect(noticesUrlForCommit('https://gitlab.com/acme/modularca', 'a3f9c21'))
            .toBe('https://gitlab.com/acme/modularca/-/blob/a3f9c21/THIRD-PARTY-NOTICES.md');
    });

    it('falls back to HEAD when the commit is unknown', () => {
        // A tarball build reports "unknown" rather than a commit. HEAD still reaches a real file,
        // which beats a 404 built from the literal string "unknown".
        expect(noticesUrlForCommit(GH, 'unknown')).toBe(`${GH}/blob/HEAD/THIRD-PARTY-NOTICES.md`);
        expect(noticesUrlForCommit(GH, '')).toBe(`${GH}/blob/HEAD/THIRD-PARTY-NOTICES.md`);
    });

    it('returns an unknown forge untouched rather than inventing a path', () => {
        // A self-hosted Gitea, a plain directory listing, an internal mirror. Appending GitHub's
        // /blob/ layout to one of those produces a link that looks deliberate and 404s.
        const selfHosted = 'https://git.example.internal/pki/modularca';
        expect(noticesUrlForCommit(selfHosted, 'a3f9c21')).toBe(selfHosted);
    });

    it('falls back to upstream when the operator has configured no source URL', () => {
        // A deployment that never set SourceCode.Url still owes its users a reachable disclosure.
        expect(noticesUrlForCommit('', 'a3f9c21'))
            .toBe(`${UPSTREAM_SOURCE_URL}/blob/a3f9c21/THIRD-PARTY-NOTICES.md`);
    });

    it('tolerates a trailing slash on the configured URL', () => {
        // Operator-entered configuration; the double slash would still resolve on GitHub but
        // reads as sloppy in a legal notice.
        expect(noticesUrlForCommit(`${GH}/`, 'a3f9c21'))
            .toBe(`${GH}/blob/a3f9c21/THIRD-PARTY-NOTICES.md`);
    });

    it('points at the same commit as the source-code link beside it', () => {
        // The two links sit next to each other in the footer and claim to describe one build.
        // They must not be able to drift to different revisions.
        const commit = 'deadbee';
        expect(noticesUrlForCommit(GH, commit)).toContain(commit);
        expect(sourceUrlForCommit(GH, commit)).toContain(commit);
    });
});
