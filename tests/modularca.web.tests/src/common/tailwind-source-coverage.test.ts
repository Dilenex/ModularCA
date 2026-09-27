import { describe, expect, it } from 'vitest';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';

/**
 * Fails if an SPA renders a shared component without telling Tailwind to scan it. Coverage is
 * judged per file, following imports transitively, so an app may scan a narrower subtree (or none)
 * when what it imports carries no class names — docsui imports only `@shared-auth/api`.
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
describe('every SPA scans the shared code it renders', () => {
    const ROOT = resolve(__dirname, '../../../..');

    /** Import alias → the shared directory it resolves to, as written in vite.config.ts. */
    const TREES: ReadonlyArray<{ alias: string; dir: string }> = [
        { alias: '@shared/', dir: join(ROOT, 'shared', 'common', 'src') },
        { alias: '@shared-auth/', dir: join(ROOT, 'shared', 'authenticated', 'src') },
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

    const specifiers = (text: string) =>
        [...text.matchAll(/(?:from\s+|import\s*\(\s*|import\s+)["']([^"']+)["']/g)].map((m) => m[1]);

    function resolveFile(base: string): string | null {
        for (const candidate of [base, `${base}.ts`, `${base}.tsx`, join(base, 'index.ts'), join(base, 'index.tsx')]) {
            if (existsSync(candidate) && statSync(candidate).isFile()) return candidate;
        }
        return null;
    }

    /** Resolves a specifier to a shared file, or null when it points anywhere else. */
    function resolveShared(spec: string, fromFile: string | null): string | null {
        for (const { alias, dir } of TREES) {
            if (spec.startsWith(alias)) return resolveFile(join(dir, spec.slice(alias.length)));
        }
        if (fromFile && spec.startsWith('.')) return resolveFile(resolve(dirname(fromFile), spec));
        return null;
    }

    /** Every shared file an app reaches, following aliases and relative imports transitively. */
    function sharedClosure(app: string): string[] {
        const seen = new Set<string>();
        const queue: string[] = [];
        for (const file of sources(join(ROOT, app, 'src'))) {
            for (const spec of specifiers(readFileSync(file, 'utf8'))) {
                const hit = resolveShared(spec, null);
                if (hit) queue.push(hit);
            }
        }
        while (queue.length) {
            const file = queue.pop()!;
            if (seen.has(file)) continue;
            seen.add(file);
            for (const spec of specifiers(readFileSync(file, 'utf8'))) {
                const hit = resolveShared(spec, file);
                if (hit) queue.push(hit);
            }
        }
        return [...seen];
    }

    it('finds the SPA packages', () => {
        // Guards the guard: a wrong ROOT would make every assertion below vacuously pass.
        // Four since the user portal merged into modularca.adminui (September 2026).
        expect(apps.length).toBeGreaterThanOrEqual(4);
    });

    it('finds styled shared files reached from adminui', () => {
        expect(sharedClosure('modularca.adminui').some((f) => /className/.test(readFileSync(f, 'utf8')))).toBe(true);
    });

    it.each(apps)('%s', (app) => {
        const cssPath = join(ROOT, app, 'src', 'index.css');
        const css = readFileSync(cssPath, 'utf8');
        const scanned = [...css.matchAll(/@source\s+["']([^"']+)["']/g)]
            .map((m) => resolve(dirname(cssPath), m[1]));

        for (const file of sharedClosure(app)) {
            if (!/className/.test(readFileSync(file, 'utf8'))) continue;
            const covered = scanned.some((dir) => {
                const rel = relative(dir, file);
                return !!rel && !rel.startsWith('..') && !isAbsolute(rel);
            });
            expect(
                covered,
                `${app} renders ${relative(ROOT, file)} but ${app}/src/index.css has no @source ` +
                `covering it — every class used only there will be missing from the bundle.`,
            ).toBe(true);
        }
    });
});
