import { describe, expect, it } from 'vitest';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

/**
 * Runs scripts/ledger-contrast.mjs: every text/background pairing in the SPA sources must reach
 * WCAG 2.x contrast (4.5:1, or 3:1 for large or bold text) in both the light and the dark theme,
 * `text-on-accent` must sit on an accent or status fill, and a fill must say what text it carries.
 *
 * The codemod that moved the console onto the Ledger tokens mapped "white text on a solid fill" to
 * `text-on-accent`, which is white in light mode and near-black in dark mode, so the same class on
 * the wrong surface is invisible in one theme and fine in the other. Nobody notices in the theme
 * they happen to use. Exceptions go in scripts/ledger-contrast.allowlist.json with a reason.
 */
interface Finding {
    file: string;
    line: number;
    kind: string;
    classes: string;
    text: string | null;
    bg: string;
    light: number | null;
    dark: number | null;
}

interface ContrastLint {
    lint(): Finding[];
    failures(findings: Finding[]): { fails: Finding[]; stale: { file: string; match: string }[] };
    checkClasses(classes: string): string[];
    loadTheme(): { light: Record<string, number[]>; dark: Record<string, number[]> };
    ratio(a: number[], b: number[]): number;
}

const SCRIPT = resolve(__dirname, '../../../../scripts/ledger-contrast.mjs');
const load = async () => (await import(/* @vite-ignore */ pathToFileURL(SCRIPT).href)) as ContrastLint;

describe('Ledger colour pairings are readable in both themes', () => {
    it('reads the theme and measures contrast the WCAG way', async () => {
        const m = await load();
        const theme = m.loadTheme();
        expect(theme.light.raised).toBeDefined();
        expect(theme.dark.raised).not.toEqual(theme.light.raised);
        expect(m.ratio([0, 0, 0, 1], [255, 255, 255, 1])).toBeCloseTo(21, 5);
    });

    it('catches the pairings it exists for', async () => {
        // Guards the guard: a lint that never fires would pass the sweep below vacuously.
        const m = await load();
        expect(m.checkClasses('px-2 bg-raised text-on-accent')).toContain('on-accent-off-solid');
        expect(m.checkClasses('bg-crit hover:bg-crit-hover')).toContain('solid-text');
        expect(m.checkClasses('px-2 bg-accent text-ink')).toContain('solid-text');
        expect(m.checkClasses('px-2 bg-accent text-on-accent hover:bg-accent-hover')).toEqual([]);
        expect(m.checkClasses('px-2 bg-warn-soft text-warn')).toEqual([]);
    });

    it('finds no failing pairing outside the allowlist', async () => {
        const m = await load();
        const all = m.lint();
        expect(all.length).toBeGreaterThan(0);
        const { fails, stale } = m.failures(all);
        const fmt = (f: Finding) => `${f.file}:${f.line} [${f.kind}] ${f.text ?? '(no text)'} on ${f.bg} light ${f.light} dark ${f.dark}: "${f.classes}"`;
        expect(fails.map(fmt), 'run `node scripts/ledger-contrast.mjs` for the full report').toEqual([]);
        expect(stale.map(s => `${s.file}: ${s.match}`), 'remove these entries from scripts/ledger-contrast.allowlist.json').toEqual([]);
    }, 120_000);
});
