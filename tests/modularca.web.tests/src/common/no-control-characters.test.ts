import { describe, expect, it } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';

/**
 * Fails if shared source contains control characters that a mangled escape would leave behind.
 *
 * This exists because of a bug that cost an evening. The API client tested response content types
 * with `/\bjson\b/i`, and a scripted edit processed that text as a non-raw string, turning the
 * two characters `\` and `b` into a single 0x08 byte. The regex became `/‹BS›json‹BS›/i`, which
 * cannot match `application/json`, so every JSON response in both SPAs was handed to callers as
 * an unparsed string.
 *
 * What made it expensive was not the bug but its invisibility. `grep` prints the line as
 * `/json/i`, a diff looks correct, a code review passes, and TypeScript is perfectly happy — a
 * regex containing a backspace is valid. The failure surfaced three files away as
 * "map is not a function", "can't access property replace", and a button that silently did
 * nothing, none of which point anywhere near a content-type check.
 *
 * Only `\t`, `\n` and `\r` are legitimate in this source. Anything else in the C0 range is either
 * a mangled escape or something that has no business in a text file.
 */
describe('shared source contains no stray control characters', () => {
    const ROOT = resolve(__dirname, '../../../..');
    const DIRS = ['shared/common/src', 'shared/authenticated/src'];
    const EXTENSIONS = ['.ts', '.tsx'];

    /** Every source file under the shared trees, recursively. */
    function collect(dir: string, out: string[] = []): string[] {
        for (const entry of readdirSync(dir)) {
            const full = join(dir, entry);
            if (statSync(full).isDirectory()) {
                if (entry === 'node_modules' || entry === 'generated') continue;
                collect(full, out);
            } else if (EXTENSIONS.some(e => entry.endsWith(e))) {
                out.push(full);
            }
        }
        return out;
    }

    const files = DIRS.flatMap(d => collect(resolve(ROOT, d)));

    it('finds source files to check', () => {
        // Guards the guard: a broken path would make every assertion below vacuously pass.
        expect(files.length).toBeGreaterThan(5);
    });

    it.each([7, 8, 11, 12].map(c => String.fromCharCode(c)))(
        'no file contains %j',
        (ch) => {
            const offenders = files
                .filter(f => readFileSync(f, 'utf8').includes(ch))
                .map(f => f.slice(ROOT.length + 1));

            expect(offenders, `control character ${JSON.stringify(ch)} found in: ${offenders.join(', ')}`)
                .toEqual([]);
        },
    );

    it('the content-type check in the API client is intact', () => {
        // The specific line that broke, pinned by behaviour rather than by text: whatever the
        // regex is, it must match the content types this API actually returns.
        const src = readFileSync(resolve(ROOT, 'shared/authenticated/src/api/createClient.ts'), 'utf8');
        const match = src.match(/if \(!(\/[^/]+\/i)\.test\(contentType\)\)/);

        expect(match, 'could not find the content-type guard in createClient.ts').not.toBeNull();

        // eslint-disable-next-line no-eval
        const re: RegExp = (0, eval)(match![1]);
        for (const ct of [
            'application/json',
            'application/json; charset=utf-8',
            'application/problem+json',
            'text/json',
        ]) {
            expect(re.test(ct), `${re} failed to match ${ct}`).toBe(true);
        }
        for (const ct of ['application/x-pem-file', 'text/plain', 'application/pkix-cert', '']) {
            expect(re.test(ct), `${re} wrongly matched ${ct}`).toBe(false);
        }
    });
});
