import { describe, expect, it } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';

/**
 * Fails if an SPA renders a shared component without telling Tailwind to scan that shared tree.
 *
 * This exists because of a bug that shipped silently. Tailwind v4 generates a rule only for class
 * names it finds by scanning source files, and its automatic detection covers the package the
 * stylesheet lives in — never a sibling directory. `shared/common` and `shared/authenticated` sit
 * outside all five SPA packages, so every utility used *only* by a shared component was dropped
 * from the bundle. 117 of them in adminui alone.
 *
 * The markup rendered perfectly; only the styling was missing, so nothing errored and nothing
 * logged. What it looked like from the outside was two unrelated product defects:
 *
 *   - DataTable's column-resize handle is a 6px strip sized by `w-1.5` and anchored by `right-0`.
 *     With neither rule emitted it collapsed to a zero-area element, so the grab target did not
 *     exist and the tables appeared to have no resize feature at all.
 *   - The toast viewport is positioned by `z-[100]` and `w-[calc(100vw-2rem)]`, both used nowhere
 *     but Toast.tsx. Without them notifications lost their stacking context, so every success and
 *     failure message in both admin and user UIs was raised and then never seen.
 *
 * Each app also carried a leftover v3-style `tailwind.config.cjs` declaring its own `content`
 * globs, which read as an authoritative answer to "what gets scanned" while v4 ignored the file
 * entirely — it loads one only when a stylesheet asks for it with `@config`. Those were deleted
 * alongside this test, after confirming the emitted CSS was byte-identical without them.
 *
 * Checking the built CSS would catch the same class of regression, but only after a build and only
 * for classes a test already knows to look for. Checking the declaration is cheap, runs everywhere,
 * and fails on the cause instead of one of its symptoms.
 */
describe('every SPA scans the shared trees it imports from', () => {
    const ROOT = resolve(__dirname, '../../../..');

    /** Import alias → the shared directory it resolves to, as written in vite.config.ts. */
    const TREES: ReadonlyArray<{ alias: string; dir: string }> = [
        { alias: '@shared/', dir: 'common' },
        { alias: '@shared-auth/', dir: 'authenticated' },
    ];

    const apps = readdirSync(ROOT)
        .filter((d) => d.startsWith('modularca.') && d.endsWith('ui'))
        .filter((d) => statSync(join(ROOT, d)).isDirectory());

    /** Every TypeScript source file under an app, recursively. */
    function sources(dir: string, out: string[] = []): string[] {
        for (const entry of readdirSync(dir)) {
            const full = join(dir, entry);
            if (statSync(full).isDirectory()) {
                if (entry !== 'node_modules' && entry !== 'dist') sources(full, out);
            } else if (/\.tsx?$/.test(entry)) {
                out.push(full);
            }
        }
        return out;
    }

    it('finds the SPA packages', () => {
        // Guards the guard: a wrong ROOT would make every assertion below vacuously pass.
        expect(apps.length).toBeGreaterThanOrEqual(5);
    });

    it.each(apps)('%s', (app) => {
        const css = readFileSync(join(ROOT, app, 'src', 'index.css'), 'utf8');
        const src = sources(join(ROOT, app, 'src')).map((f) => readFileSync(f, 'utf8'));

        for (const { alias, dir } of TREES) {
            if (!src.some((s) => s.includes(alias))) continue;

            // Accept any quoting or trailing-slash spelling of the path — the point is that the
            // tree is declared, not that it is spelled one particular way.
            const declared = new RegExp(String.raw`@source\s+["'][^"']*shared/${dir}/src/?["']`);

            expect(
                declared.test(css),
                `${app} imports from "${alias}" but ${app}/src/index.css has no ` +
                `@source for shared/${dir}/src — every class used only by those components ` +
                `will be missing from the bundle.`,
            ).toBe(true);
        }
    });
});
