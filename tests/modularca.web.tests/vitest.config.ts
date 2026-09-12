import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

/**
 * Resolves a path relative to this config file.
 *
 * The aliases below have to be absolute: vitest resolves an alias replacement against the
 * importing file, not against the config, so a relative replacement would point somewhere
 * different for a test nested one directory deeper.
 */
const fromHere = (relative: string) => fileURLToPath(new URL(relative, import.meta.url));

/**
 * Test-runner configuration for the shared SPA TypeScript.
 *
 * The two aliases are the whole reason this file exists. `shared/common/src` and
 * `shared/authenticated/src` have no package.json — the five SPAs reach them through tsconfig
 * `paths` plus a matching Vite alias, so a runner that does not repeat the mapping cannot even
 * import the modules under test. Repeating it here also guarantees that a test and the app
 * bundle load the same file rather than two copies that can drift apart.
 *
 * Keep these in step with tsconfig.json's `paths`: TypeScript resolves imports through that
 * list and vitest resolves them through this one, and a mismatch shows up as a suite that
 * typechecks but will not run (or the reverse).
 */
export default defineConfig({
    resolve: {
        alias: [
            // Regex rather than a bare string so `@shared-auth/...` can never be captured by the
            // shorter `@shared` prefix — the trailing slash in the pattern is load-bearing.
            { find: /^@shared\//, replacement: fromHere('../../shared/common/src/') },
            { find: /^@shared-auth\//, replacement: fromHere('../../shared/authenticated/src/') },
        ],
    },
    test: {
        // Node, not jsdom: the modules covered so far are pure logic, and Node 24 already
        // supplies the web types they touch (Headers, Response, URL). Add jsdom as a per-file
        // `// @vitest-environment jsdom` pragma if a suite needs a document, rather than paying
        // the startup cost on every file.
        environment: 'node',
        include: ['src/**/*.test.ts'],
    },
});
