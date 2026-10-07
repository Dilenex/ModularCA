import { describe, expect, it } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';

/**
 * Fails when a stock Tailwind colour utility (`bg-gray-800`, `text-blue-600`, `dark:border-red-700`
 * ...) appears in the SPA sources beyond the per-file allowance in ledger-palette.allowlist.json.
 *
 * Colour comes from the Ledger tokens in shared/common/src/theme/ledger.css (`bg-raised`,
 * `text-ink-muted`, `border-line`, `bg-accent`, `text-crit` ...), which switch with the `.dark`
 * class by themselves. A stock class bypasses that: it needs a hand-written `dark:` twin, and the
 * two drift apart one copy-paste at a time, which is how the console ended up with ~10,800 of them
 * and a gray-900 label on a blue button. `node scripts/ledger-codemod.mjs` rewrites most new ones.
 *
 * The allowlist is a ratchet. A file may carry at most its listed count, and a count that has
 * dropped must be lowered in the JSON, so a removed residual cannot quietly come back.
 */
describe('UI sources use Ledger tokens, not stock colour utilities', () => {
    const ROOT = resolve(__dirname, '../../../..');
    const DIRS = [
        'modularca.adminui/src', 'modularca.publicui/src', 'modularca.setupui/src', 'modularca.docsui/src',
        'shared/common/src', 'shared/authenticated/src',
    ];
    const HTML = ['modularca.adminui', 'modularca.publicui', 'modularca.setupui', 'modularca.docsui'].map(d => `${d}/index.html`);

    const STOCK = new RegExp(
        '(?<![A-Za-z0-9_-])(?:[^\\s"\'`:]+:)*' +
        '(?:bg|text|border(?:-[xytrblse])?|ring(?:-offset)?|divide|outline|fill|stroke|placeholder|from|via|to|shadow|accent|caret|decoration)-' +
        '(?:gray|slate|zinc|neutral|stone|blue|sky|indigo|violet|purple|red|green|emerald|yellow|amber|orange|teal|cyan)-\\d{2,3}(?![0-9])',
        'g',
    );

    const allowlist: Record<string, number> = JSON.parse(
        readFileSync(resolve(__dirname, 'ledger-palette.allowlist.json'), 'utf8'),
    );

    function collect(dir: string, out: string[] = []): string[] {
        for (const entry of readdirSync(dir)) {
            const full = join(dir, entry);
            if (statSync(full).isDirectory()) {
                if (entry === 'node_modules' || entry === 'dist') continue;
                collect(full, out);
            } else if (/\.tsx?$/.test(entry)) {
                out.push(full);
            }
        }
        return out;
    }

    const rel = (f: string) => f.slice(ROOT.length + 1).replace(/\\/g, '/');
    const files = [...DIRS.flatMap(d => collect(resolve(ROOT, d))), ...HTML.map(h => resolve(ROOT, h))];
    const counts = new Map<string, string[]>();
    for (const f of files) {
        const hits = readFileSync(f, 'utf8').match(STOCK) ?? [];
        if (hits.length) counts.set(rel(f), hits);
    }

    it('finds the UI sources', () => {
        // Guards the guard: a wrong ROOT would make the assertions below pass vacuously.
        expect(files.length).toBeGreaterThan(100);
        expect(STOCK.test('dark:hover:bg-gray-700')).toBe(true);
        STOCK.lastIndex = 0;
    });

    it('no file exceeds its allowance', () => {
        const over = [...counts]
            .filter(([f, hits]) => hits.length > (allowlist[f] ?? 0))
            .map(([f, hits]) => `${f}: ${hits.length} (allowed ${allowlist[f] ?? 0}) e.g. ${hits.slice(0, 3).join(' ')}`);
        expect(over, `stock colour utilities found; use the Ledger tokens or run scripts/ledger-codemod.mjs:\n${over.join('\n')}`)
            .toEqual([]);
    });

    it('the allowlist only shrinks', () => {
        const stale = Object.entries(allowlist)
            .filter(([f, n]) => (counts.get(f)?.length ?? 0) < n)
            .map(([f, n]) => `${f}: allowed ${n}, now ${counts.get(f)?.length ?? 0}`);
        expect(stale, `lower these entries in ledger-palette.allowlist.json (delete them at 0):\n${stale.join('\n')}`)
            .toEqual([]);
    });
});
