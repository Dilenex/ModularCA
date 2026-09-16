#!/usr/bin/env node
/*
 * Generates TypeScript sources under shared/common/src/generated/ from the C# backend, so the
 * front ends stop hand-maintaining copies of contracts the server owns.
 *
 * Why this exists
 * ---------------
 * Every SPA re-declares the server's vocabulary by hand: step-up operation strings as bare
 * literals, key-usage spellings as partial alias tables, request bodies as ad-hoc object
 * literals. Nothing checks any of it. The failures that produces are not type errors, they are
 * silent behaviour changes:
 *
 *   - `delete-eab-key` was sent by the admin UI for months while StepUpOps.All did not contain
 *     it. The server answered 400 invalid_step_up_operation and the key could not be deleted.
 *   - modularca.adminui/src/pages/profileHelpers.tsx carries a KEY_USAGE_ALIASES table with four
 *     entries. UsageCatalogResolver.Synonyms has eleven. Spellings the UI cannot resolve are
 *     DROPPED by canonicalizeUsages, so a profile seeded with "Key Certificate Signing" shows
 *     its toggles off and the next save writes the usage out of the profile.
 *
 * scripts/wire_contract.py catches pure casing drift between the two sides. It structurally
 * cannot catch a name that is simply absent, or a value that is spelled a different way. This
 * generator removes that whole class by making the C# declaration the only declaration.
 *
 * What it reads
 * -------------
 *   ModularCA.Shared/Enums/StepUpOps.cs      -> generated/stepUpOps.ts
 *   ModularCA.Shared/Authorization/Capabilities.cs -> generated/capabilities.ts
 *   ModularCA.Shared/Utils/UsageCatalogResolver.cs
 *     + ModularCA.Shared/Utils/KeyUsageFriendlyNames.cs
 *                                            -> generated/usageVocabulary.ts
 *   ModularCA.Shared/Enums/*.cs (real enums) -> generated/enums.ts
 *   ModularCA.Shared/Models/ ** /*.cs        -> generated/models.ts
 *
 * Parsing is regex over a scrubbed copy of each file (comments and string bodies blanked,
 * offsets preserved) — the same technique scripts/wire_contract.py uses and the reason
 * Models/Config/DbConfig.cs, whose entire body is commented out, contributes nothing.
 *
 * Usage
 * -----
 *   node scripts/generate-shared-types.mjs           write (idempotent; only rewrites on change)
 *   node scripts/generate-shared-types.mjs --check   exit 1 if output would change (CI / build)
 *
 * Runs from the API's BuildWebUIs MSBuild target, before any SPA is typechecked, so generated
 * output can never lag the C# it came from.
 */
import { readFileSync, writeFileSync, mkdirSync, readdirSync, statSync } from 'node:fs';
import { resolve, dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const OUT_DIR = resolve(ROOT, 'shared', 'common', 'src', 'generated');
const CHECK = process.argv.includes('--check');

const warnings = [];
const warn = (msg) => warnings.push(msg);

// --------------------------------------------------------------------------- //
// C# scrubber
// --------------------------------------------------------------------------- //

/**
 * Blanks the CONTENT of comments, strings and char literals while preserving length and
 * newlines, so later regexes cannot match inside them and reported line numbers stay true.
 *
 * Necessary rather than merely tidy: Models/Config/DbConfig.cs declares DbConfig and DbInstance
 * entirely inside a block comment, and the live definitions of both live in SystemConfig.cs.
 * Without scrubbing the generator would emit the stale commented-out shapes and shadow the real
 * ones.
 */
function scrub(src) {
    const out = src.split('');
    const n = src.length;
    let i = 0;
    const blank = (from, to) => {
        for (let k = from; k < to && k < n; k++) if (out[k] !== '\n') out[k] = ' ';
    };
    while (i < n) {
        const c = src[i];
        const next = src[i + 1];
        if (c === '/' && next === '/') {
            let j = i;
            while (j < n && src[j] !== '\n') j++;
            blank(i, j);
            i = j;
        } else if (c === '/' && next === '*') {
            const end = src.indexOf('*/', i + 2);
            const j = end === -1 ? n : end + 2;
            blank(i, j);
            i = j;
        } else if (c === '@' && next === '"') {
            // Verbatim string: "" is an escaped quote.
            let j = i + 2;
            while (j < n) {
                if (src[j] === '"' && src[j + 1] === '"') { j += 2; continue; }
                if (src[j] === '"') { j++; break; }
                j++;
            }
            blank(i + 1, j - 1);
            i = j;
        } else if (c === '"' || c === "'") {
            let j = i + 1;
            while (j < n) {
                if (src[j] === '\\') { j += 2; continue; }
                if (src[j] === c || src[j] === '\n') { j++; break; }
                j++;
            }
            blank(i + 1, j - 1);
            i = j;
        } else {
            i++;
        }
    }
    return out.join('');
}

/** Returns the index just past the `}` matching the `{` at `open`, or -1. */
function matchBrace(src, open) {
    let depth = 0;
    for (let i = open; i < src.length; i++) {
        if (src[i] === '{') depth++;
        else if (src[i] === '}') {
            depth--;
            if (depth === 0) return i;
        }
    }
    return -1;
}

// --------------------------------------------------------------------------- //
// Naming
// --------------------------------------------------------------------------- //

/**
 * Port of System.Text.Json's JsonNamingPolicy.CamelCase, which the API installs globally.
 *
 * It lowercases only the LEADING RUN of capitals and stops before the last capital of that run
 * when a lowercase letter follows. That is why the wire name is `allowedEKUs`, not
 * `allowedEkus`, and why `subjectDN` keeps its tail. This is the same algorithm
 * scripts/wire_contract.py implements, which was validated against a real .NET oracle over
 * 1,223 property names with zero mismatches.
 */
function camelCase(name) {
    if (!name || name[0] !== name[0].toUpperCase() || !/[A-Z]/.test(name[0])) return name;
    const chars = [...name];
    for (let i = 0; i < chars.length; i++) {
        const c = chars[i];
        if (!/[A-Z]/.test(c)) break;
        if (i > 0 && i + 1 < chars.length && !/[A-Z]/.test(chars[i + 1])) break;
        chars[i] = c.toLowerCase();
    }
    return chars.join('');
}

const BANNER = (source) => `// <auto-generated>
//   DO NOT EDIT. Regenerate with:  node scripts/generate-shared-types.mjs
//   Source of truth: ${source}
//   The build runs this generator and fails if the checked-in output is stale.
// </auto-generated>
`;

// --------------------------------------------------------------------------- //
// 0. Capabilities
// --------------------------------------------------------------------------- //

function generateCapabilities() {
    const path = resolve(ROOT, 'ModularCA.Shared', 'Authorization', 'Capabilities.cs');
    const raw = readFileSync(path, 'utf-8');
    const src = scrub(raw);

    const consts = [];
    const constRe = /public\s+const\s+string\s+(\w+)\s*=\s*"/g;
    let m;
    while ((m = constRe.exec(src)) !== null) {
        const valueStart = m.index + m[0].length;
        const valueEnd = raw.indexOf('"', valueStart);
        consts.push({ name: m[1], value: raw.slice(valueStart, valueEnd) });
    }
    if (!consts.length) throw new Error('Capabilities.cs: no const string members found');

    const lines = [];
    lines.push(BANNER('ModularCA.Shared/Authorization/Capabilities.cs'));
    lines.push(`/**
 * Every capability the authorization model knows, as the server spells it.
 *
 * The console gates its navigation and pages on these, matched against the per-scope sets in
 * \`GET /api/v1/me\`'s \`capabilities\` payload. Use the constants rather than string literals:
 * a literal typo silently hides a page, a constant typo does not compile.
 */`);
    lines.push('export const Capabilities = {');
    for (const c of consts) lines.push(`    ${c.name}: '${c.value}',`);
    lines.push('} as const;');
    lines.push('');
    lines.push('/** Union of every capability string. */');
    lines.push('export type Capability = (typeof Capabilities)[keyof typeof Capabilities];');
    lines.push('');
    lines.push('/** Every capability, for exhaustiveness checks. */');
    lines.push('export const CAPABILITIES_ALL: readonly Capability[] = Object.values(Capabilities);');
    lines.push('');
    return { file: 'capabilities.ts', content: lines.join('\n') };
}

// --------------------------------------------------------------------------- //
// 1. StepUpOps
// --------------------------------------------------------------------------- //

function generateStepUpOps() {
    const path = resolve(ROOT, 'ModularCA.Shared', 'Enums', 'StepUpOps.cs');
    const raw = readFileSync(path, 'utf-8');
    const src = scrub(raw);

    // Constants: name -> wire value. Scrubbing blanked the literal bodies, so read values from
    // the raw text at the same offsets.
    const consts = [];
    const constRe = /public\s+const\s+string\s+(\w+)\s*=\s*"/g;
    let m;
    while ((m = constRe.exec(src)) !== null) {
        const valueStart = m.index + m[0].length;
        const valueEnd = raw.indexOf('"', valueStart);
        consts.push({ name: m[1], value: raw.slice(valueStart, valueEnd) });
    }
    if (!consts.length) throw new Error('StepUpOps.cs: no const string members found');

    // Membership of the two IReadOnlySet initializers, read as C# identifier references.
    const setMembers = (setName) => {
        const anchor = src.indexOf(`All`) >= 0 ? 0 : 0; // placeholder; located below
        const decl = new RegExp(`IReadOnlySet<string>\\s+${setName}\\s*=[^{]*\\{`).exec(src);
        if (!decl) throw new Error(`StepUpOps.cs: set '${setName}' not found`);
        const open = decl.index + decl[0].length - 1;
        const close = matchBrace(src, open);
        const body = src.slice(open + 1, close);
        return new Set(
            body.split(',').map((s) => s.trim()).filter((s) => /^\w+$/.test(s)),
        );
    };

    const all = setMembers('All');
    const viaMtls = setMembers('AllowedViaMtls');

    // A constant that exists but is absent from All is exactly the DeleteEabKey defect: the
    // client can name it, MfaStepUpController refuses to mint a token for it, and the operation
    // is unreachable. Surface it loudly rather than generating a usable-looking constant.
    const orphans = consts.filter((c) => !all.has(c.name));
    for (const o of orphans) {
        warn(
            `StepUpOps.${o.name} ("${o.value}") is declared but missing from StepUpOps.All. ` +
            `MfaStepUpController will reject it with 400 invalid_step_up_operation. ` +
            `It is generated into STEP_UP_OPS_UNREGISTERED, not StepUpOps.`,
        );
    }

    const registered = consts.filter((c) => all.has(c.name));
    const lines = [];
    lines.push(BANNER('ModularCA.Shared/Enums/StepUpOps.cs'));
    lines.push(`/**
 * Every step-up-MFA operation the server will mint a token for.
 *
 * Only operations present in the C# \`StepUpOps.All\` allow-list appear here. A constant that is
 * declared in C# but left out of that set is unreachable — \`MfaStepUpController\` answers
 * \`400 invalid_step_up_operation\` — so it is deliberately NOT emitted as a usable value; see
 * \`STEP_UP_OPS_UNREGISTERED\` below.
 *
 * Use these instead of string literals. A literal typo produces a runtime 400 that reads like an
 * MFA failure; a constant typo does not compile.
 */`);
    lines.push('export const StepUpOps = {');
    for (const c of registered) lines.push(`    ${c.name}: '${c.value}',`);
    lines.push('} as const;');
    lines.push('');
    lines.push('/** Union of every valid step-up operation string. */');
    lines.push('export type StepUpOp = (typeof StepUpOps)[keyof typeof StepUpOps];');
    lines.push('');
    lines.push('/** Every valid operation, for allow-list checks and exhaustiveness tests. */');
    lines.push('export const STEP_UP_OPS_ALL: readonly StepUpOp[] = Object.values(StepUpOps);');
    lines.push('');
    lines.push(`/**
 * The subset a client certificate may authorize. Mirrors \`StepUpOps.AllowedViaMtls\` /
 * \`MfaStepUpController.AllowedMtlsStepUpOperations\`: MFA enrollment only. Destructive
 * operations require TOTP or WebAuthn even when the caller holds a valid client certificate.
 */`);
    lines.push('export const STEP_UP_OPS_VIA_MTLS: readonly StepUpOp[] = [');
    for (const c of registered.filter((c) => viaMtls.has(c.name))) {
        lines.push(`    StepUpOps.${c.name},`);
    }
    lines.push('];');
    lines.push('');
    lines.push(`/**
 * Declared in C# but absent from \`StepUpOps.All\`, so the server refuses to issue a token for
 * them. Present here only so the drift is visible: an entry in this list is a backend bug, and
 * any UI sending one of these strings shows the user an MFA prompt that can never succeed.
 */`);
    lines.push('export const STEP_UP_OPS_UNREGISTERED: readonly string[] = [');
    for (const o of orphans) lines.push(`    '${o.value}',`);
    lines.push('];');
    lines.push('');

    return { file: 'stepUpOps.ts', content: lines.join('\n') };
}

// --------------------------------------------------------------------------- //
// 2. Usage vocabulary
// --------------------------------------------------------------------------- //

function generateUsageVocabulary() {
    const resolverPath = resolve(ROOT, 'ModularCA.Shared', 'Utils', 'UsageCatalogResolver.cs');
    const kufPath = resolve(ROOT, 'ModularCA.Shared', 'Utils', 'KeyUsageFriendlyNames.cs');
    const rRaw = readFileSync(resolverPath, 'utf-8');
    const rSrc = scrub(rRaw);

    // Synonyms dictionary: ["from"] = "to", read back out of the raw text.
    const synDecl = /Dictionary<string,\s*string>\s+Synonyms\s*=[^{]*\{/.exec(rSrc);
    if (!synDecl) throw new Error('UsageCatalogResolver.cs: Synonyms dictionary not found');
    const synOpen = synDecl.index + synDecl[0].length - 1;
    const synClose = matchBrace(rSrc, synOpen);
    const synonyms = [];
    const entryRe = /\[\s*"/g;
    entryRe.lastIndex = synOpen;
    let e;
    while ((e = entryRe.exec(rSrc)) !== null && e.index < synClose) {
        const keyStart = e.index + e[0].length;
        const keyEnd = rRaw.indexOf('"', keyStart);
        const assign = rSrc.indexOf('"', rSrc.indexOf('=', keyEnd));
        const valStart = assign + 1;
        const valEnd = rRaw.indexOf('"', valStart);
        synonyms.push([rRaw.slice(keyStart, keyEnd), rRaw.slice(valStart, valEnd)]);
    }
    if (!synonyms.length) throw new Error('UsageCatalogResolver.cs: Synonyms parsed empty');

    // Canonical key usages: the switch arms of KeyUsageFriendlyNames.Parse, which is the set the
    // certificate builder can actually emit bits for.
    const kRaw = readFileSync(kufPath, 'utf-8');
    const kSrc = scrub(kRaw);
    const keyUsages = [];
    const armRe = /=>\s*KeyUsage\.(\w+)/g;
    let a;
    while ((a = armRe.exec(kSrc)) !== null) {
        if (!keyUsages.includes(a[1])) keyUsages.push(a[1]);
    }
    if (!keyUsages.length) throw new Error('KeyUsageFriendlyNames.cs: no KeyUsage arms found');

    const lines = [];
    lines.push(BANNER('ModularCA.Shared/Utils/UsageCatalogResolver.cs + KeyUsageFriendlyNames.cs'));
    lines.push(`/**
 * The X.509 usage vocabulary, generated from the server's own resolver.
 *
 * The same usage reaches this system under at least three spellings — the bootstrap seeder's
 * display names ("Key Certificate Signing"), the OIDOptions catalog's camelCase ("keyCertSign"),
 * and old UI labels ("Key Cert Sign"). Collapsing case and punctuation reconciles most of them,
 * but several differ in actual WORDS and need the synonym table below.
 *
 * The admin UI previously carried a four-entry hand-written subset of that table. Because
 * \`canonicalizeUsages\` DROPS anything it cannot resolve, a profile written with a spelling the
 * UI did not know showed its toggle off and the next save removed the usage from the profile.
 * The usages that drift this way — keyCertSign, crlSign, ocspSigning — are precisely the ones a
 * CA depends on.
 */`);
    lines.push('');
    lines.push(`/**
 * Collapses a usage identifier to a comparison key: lowercase, non-alphanumerics removed.
 * Port of \`UsageCatalogResolver.Normalize\`. "Server Auth", "serverAuth" and "server_auth" all
 * reduce to \`serverauth\`.
 */`);
    lines.push('export function normalizeUsage(value: string | null | undefined): string {');
    lines.push("    if (!value) return '';");
    lines.push("    return value.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();");
    lines.push('}');
    lines.push('');
    lines.push(`/**
 * Word-level synonyms normalization alone cannot bridge. Keys and values are already-normalized
 * forms; both sides of a comparison are put through \`canonicalizeUsage\` so they meet at the
 * same key regardless of which vocabulary each came from.
 */`);
    lines.push('export const USAGE_SYNONYMS: Readonly<Record<string, string>> = {');
    for (const [k, v] of synonyms) lines.push(`    ${k}: '${v}',`);
    lines.push('};');
    lines.push('');
    lines.push(`/**
 * Normalizes, then folds word-level synonyms. Port of \`UsageCatalogResolver.Canonicalize\` —
 * the key the server compares on. Two spellings name the same usage exactly when this returns
 * the same string for both.
 */`);
    lines.push('export function canonicalizeUsage(value: string | null | undefined): string {');
    lines.push('    const normalized = normalizeUsage(value);');
    lines.push('    return USAGE_SYNONYMS[normalized] ?? normalized;');
    lines.push('}');
    lines.push('');
    lines.push(`/**
 * True when two spellings name the same X.509 usage. This is the comparison the UI must use
 * before deciding a stored usage is unrecognized — an exact string compare matches nothing
 * across vocabularies.
 */`);
    lines.push('export function sameUsage(a: string, b: string): boolean {');
    lines.push('    return canonicalizeUsage(a) === canonicalizeUsage(b);');
    lines.push('}');
    lines.push('');
    lines.push(`/**
 * The nine RFC 5280 §4.2.1.3 key-usage bits \`KeyUsageFriendlyNames.Parse\` can resolve. A
 * spelling that canonicalizes outside this set cannot be issued, so the UI must not offer it.
 */`);
    lines.push('export const KEY_USAGE_NAMES = [');
    for (const k of keyUsages) lines.push(`    '${k.charAt(0).toLowerCase()}${k.slice(1)}',`);
    lines.push('] as const;');
    lines.push('');
    lines.push('export type KeyUsageName = (typeof KEY_USAGE_NAMES)[number];');
    lines.push('');

    return { file: 'usageVocabulary.ts', content: lines.join('\n') };
}

// --------------------------------------------------------------------------- //
// 3. Enums
// --------------------------------------------------------------------------- //

/** Walks a directory tree collecting .cs files, skipping build output. */
function csFiles(dir) {
    const out = [];
    for (const entry of readdirSync(dir)) {
        if (entry === 'obj' || entry === 'bin' || entry === 'node_modules') continue;
        const full = join(dir, entry);
        if (statSync(full).isDirectory()) out.push(...csFiles(full));
        else if (entry.endsWith('.cs')) out.push(full);
    }
    return out;
}

const ENUM_RE = /public\s+enum\s+(\w+)\s*(?::\s*\w+\s*)?\{/g;

function collectEnums(files) {
    const enums = [];
    for (const file of files) {
        const src = scrub(readFileSync(file, 'utf-8'));
        ENUM_RE.lastIndex = 0;
        let m;
        while ((m = ENUM_RE.exec(src)) !== null) {
            const open = src.indexOf('{', m.index + m[0].length - 1);
            const close = matchBrace(src, open);
            const body = src.slice(open + 1, close);
            const members = [];
            let implicitNext = 0;
            for (const part of body.split(',')) {
                const t = part.trim();
                if (!t) continue;
                const em = /^(\w+)\s*(?:=\s*(-?\d+))?$/.exec(t);
                if (!em) continue;
                const value = em[2] !== undefined ? Number(em[2]) : implicitNext;
                implicitNext = value + 1;
                members.push({ name: em[1], value });
            }
            if (members.length) {
                enums.push({ name: m[1], members, source: relative(ROOT, file).replace(/\\/g, '/') });
            }
            ENUM_RE.lastIndex = close;
        }
    }
    return enums;
}

function generateEnums(enums) {
    const lines = [];
    lines.push(BANNER('ModularCA.Shared/Enums/*.cs and Models/**/*.cs'));
    lines.push(`/**
 * C# enums as they appear on the wire.
 *
 * \`StartModularCA.cs\` installs a global \`JsonStringEnumConverter\`, so every enum crosses the
 * boundary as its MEMBER NAME, not its number. Each enum therefore becomes a string-literal
 * union; the numeric values are exported separately only where the number itself is part of a
 * standard (RFC 5280 §5.3.1 revocation reason codes, for instance) and a caller may need it.
 *
 * Consequence worth stating: sending \`0\` where the server expects \`"Unspecified"\` binds to the
 * default rather than failing, which is why these must not be hand-typed.
 */`);
    lines.push('');
    for (const e of enums.slice().sort((a, b) => a.name.localeCompare(b.name))) {
        lines.push(`/** From \`${e.source}\`. */`);
        lines.push(`export const ${e.name} = {`);
        for (const mem of e.members) lines.push(`    ${mem.name}: '${mem.name}',`);
        lines.push('} as const;');
        lines.push(`export type ${e.name} = (typeof ${e.name})[keyof typeof ${e.name}];`);
        lines.push('');
        // Numeric codes are emitted whenever any member was given an explicit value: that is the
        // signal the number carries meaning outside C#.
        if (e.members.some((mem, i) => mem.value !== i)) {
            lines.push(`/** Underlying numeric values of \`${e.name}\`, which are protocol-significant. */`);
            lines.push(`export const ${e.name}Code: Readonly<Record<${e.name}, number>> = {`);
            for (const mem of e.members) lines.push(`    ${mem.name}: ${mem.value},`);
            lines.push('};');
            lines.push('');
        }
    }
    return { file: 'enums.ts', content: lines.join('\n') };
}

// --------------------------------------------------------------------------- //
// 4. Models
// --------------------------------------------------------------------------- //

const PRIMITIVES = {
    string: 'string', String: 'string',
    bool: 'boolean', Boolean: 'boolean',
    int: 'number', long: 'number', short: 'number', byte: 'number', sbyte: 'number',
    uint: 'number', ulong: 'number', ushort: 'number',
    decimal: 'number', double: 'number', float: 'number', Int32: 'number', Int64: 'number',
    // Guid, DateTime and TimeSpan all serialize as strings. Typing them as `string` rather than
    // aliasing to Date is deliberate: JSON.parse never produces a Date, so a `Date` type here
    // would be a lie every consumer would have to work around.
    Guid: 'string', DateTime: 'string', DateTimeOffset: 'string',
    TimeSpan: 'string', DateOnly: 'string', TimeOnly: 'string',
    // byte[] is base64 in System.Text.Json.
    object: 'unknown', dynamic: 'unknown', JsonElement: 'unknown', JsonNode: 'unknown',
};

const SEQUENCES = new Set([
    'List', 'IList', 'IReadOnlyList', 'ICollection', 'IReadOnlyCollection',
    'IEnumerable', 'HashSet', 'ISet', 'IReadOnlySet', 'Collection', 'Queue', 'Stack',
]);
const MAPS = new Set([
    'Dictionary', 'IDictionary', 'IReadOnlyDictionary', 'ConcurrentDictionary', 'SortedDictionary',
]);

/** Splits `string, List<int>` on top-level commas only. */
function splitGenericArgs(inner) {
    const parts = [];
    let depth = 0;
    let start = 0;
    for (let i = 0; i < inner.length; i++) {
        const c = inner[i];
        if (c === '<') depth++;
        else if (c === '>') depth--;
        else if (c === ',' && depth === 0) {
            parts.push(inner.slice(start, i));
            start = i + 1;
        }
    }
    parts.push(inner.slice(start));
    return parts.map((p) => p.trim());
}

/**
 * Maps a C# type expression to TypeScript.
 *
 * `known` is the set of generated interface/enum names. A named type outside it is reported as
 * UNRESOLVED rather than guessed or widened to `unknown`, and the caller drops the property.
 *
 * Failing closed matters here. `CertificateAuthorityIdentity` holds an `IPrivateKeyHandle` and
 * `CertificateExportOptions.Chain` holds BouncyCastle `X509Certificate` objects — neither can
 * cross the wire in any form a browser can construct. Typing them `unknown` would compile and
 * then invite a caller to populate a field the server cannot deserialize. Dropping the property
 * is honest, and a type left with nothing to say is dropped entirely by the caller.
 */
function mapType(csharp, known, context) {
    let t = csharp.trim();
    let nullable = false;
    while (t.endsWith('?')) { nullable = true; t = t.slice(0, -1).trim(); }
    // Strip namespace qualification: Org.BouncyCastle.X509.X509Certificate -> X509Certificate.
    const bare = (s) => s.includes('.') && !s.includes('<') ? s.slice(s.lastIndexOf('.') + 1) : s;

    let ts;
    let unresolved = null;
    if (t === 'byte[]') {
        ts = 'string'; // base64
    } else if (t.endsWith('[]')) {
        const el = mapType(t.slice(0, -2), known, context);
        ts = `${el.ts}[]`;
        unresolved = el.unresolved;
    } else if (t.includes('<')) {
        const open = t.indexOf('<');
        const generic = bare(t.slice(0, open));
        const args = splitGenericArgs(t.slice(open + 1, t.lastIndexOf('>')));
        if (SEQUENCES.has(generic) && args.length === 1) {
            const el = mapType(args[0], known, context);
            ts = `${el.ts}[]`;
            unresolved = el.unresolved;
        } else if (MAPS.has(generic) && args.length === 2) {
            const k = mapType(args[0], known, context);
            const v = mapType(args[1], known, context);
            ts = `Record<${k.ts === 'number' ? 'number' : 'string'}, ${v.ts}>`;
            unresolved = k.unresolved ?? v.unresolved;
        } else {
            ts = 'unknown';
            unresolved = t;
        }
    } else {
        const name = bare(t);
        if (PRIMITIVES[name]) ts = PRIMITIVES[name];
        else if (known.has(name)) ts = name;
        else {
            ts = 'unknown';
            unresolved = t;
        }
    }
    return { ts, nullable, unresolved };
}

const TYPE_DECL_RE =
    /(?:^|\n)\s*public\s+((?:sealed\s+|abstract\s+|partial\s+|static\s+|readonly\s+)*)(record\s+class|record\s+struct|record|class|struct)\s+(\w+)\s*(\([^)]*\))?\s*(?::\s*([^{;]+))?\s*(\{|;)/g;

const PROP_RE = /public\s+(required\s+)?([A-Za-z0-9_<>,\[\]\?\. ]+?)\s+(\w+)\s*\{\s*get\s*;/g;

function collectModels(files) {
    const types = [];
    for (const file of files) {
        const raw = readFileSync(file, 'utf-8');
        const src = scrub(raw);
        const rel = relative(ROOT, file).replace(/\\/g, '/');
        TYPE_DECL_RE.lastIndex = 0;
        let m;
        while ((m = TYPE_DECL_RE.exec(src)) !== null) {
            const [, modifiers, , name, ctorParams, baseList, terminator] = m;
            if (/\bstatic\b/.test(modifiers)) continue;

            const bases = (baseList ?? '')
                .split(',')
                .map((s) => s.trim())
                .filter(Boolean)
                .map((s) => (s.includes('<') ? s.slice(0, s.indexOf('<')) : s));

            let body = '';
            let rawBody = '';
            if (terminator === '{') {
                const open = src.indexOf('{', m.index + m[0].length - 1);
                const close = matchBrace(src, open);
                body = src.slice(open + 1, close);
                // `scrub` preserves length exactly, so the same offsets index the original text.
                // That is how attribute arguments — blanked in `body` — are recovered verbatim.
                rawBody = raw.slice(open + 1, close);
                TYPE_DECL_RE.lastIndex = close;
            }

            // Nested types are collected by the same sweep on the next iteration; strip their
            // bodies so their members are not attributed to the outer type. The replacement is
            // space-for-space, so offsets into `rawBody` stay valid.
            const ownBody = stripNestedBodies(body);

            const props = [];
            if (ctorParams) props.push(...parsePositional(ctorParams, rel, name));
            props.push(...parseProperties(ownBody, rawBody, rel, name));

            types.push({ name, bases, props, source: rel });
        }
    }
    return types;
}

/** Blanks the bodies of nested type declarations so only the outer type's members remain. */
function stripNestedBodies(body) {
    const nested = /(?:^|\n)\s*public\s+(?:sealed\s+|abstract\s+|partial\s+|static\s+|readonly\s+)*(?:record\s+class|record\s+struct|record|class|struct|enum|interface)\s+\w+[^{;]*\{/g;
    let out = body;
    let m;
    while ((m = nested.exec(out)) !== null) {
        const open = out.indexOf('{', m.index + m[0].length - 1);
        const close = matchBrace(out, open);
        if (close === -1) break;
        out = out.slice(0, open + 1) + ' '.repeat(close - open - 1) + out.slice(close);
        nested.lastIndex = close;
    }
    return out;
}

function parsePositional(ctorParams, rel, typeName) {
    const inner = ctorParams.slice(1, -1).trim();
    if (!inner) return [];
    return splitGenericArgs(inner)
        .map((p) => {
            const cleaned = p.replace(/=.*$/, '').trim();
            const sp = cleaned.lastIndexOf(' ');
            if (sp === -1) return null;
            return {
                csType: cleaned.slice(0, sp).trim(),
                name: cleaned.slice(sp + 1).trim(),
                required: !cleaned.slice(0, sp).trim().endsWith('?'),
                wire: null,
                context: `${rel} ${typeName}`,
            };
        })
        .filter(Boolean);
}

/**
 * `body` is the scrubbed type body; `rawBody` is the SAME byte range of the original file, so an
 * index valid in one is valid in the other. Property matching runs on the scrubbed copy (a
 * default value like `= "public bool X { get;"` must not be mistaken for a declaration) while
 * attribute arguments are read back out of the raw copy, where the string bodies survive.
 */
function parseProperties(body, rawBody, rel, typeName) {
    const props = [];
    PROP_RE.lastIndex = 0;
    let m;
    while ((m = PROP_RE.exec(body)) !== null) {
        const [, requiredKw, csType, name] = m;
        if (csType.trim() === 'static' || /\breturn\b/.test(csType)) continue;

        // Attributes belong to this property only if no earlier member intervenes, so the window
        // starts after the previous `;` or `}` rather than at a fixed line count.
        const windowStart = Math.max(0, m.index - 600);
        const scrubbedWindow = body.slice(windowStart, m.index);
        const cut = Math.max(scrubbedWindow.lastIndexOf(';'), scrubbedWindow.lastIndexOf('}'));
        const attrStart = windowStart + cut + 1;
        const attrs = rawBody.slice(attrStart, m.index);

        // A bare [JsonIgnore] removes the property from the wire entirely. The conditional form,
        // [JsonIgnore(Condition = WhenWritingNull)], only omits nulls — the property still exists.
        if (/\[\s*JsonIgnore\s*\]/.test(attrs)) continue;

        const wm = /JsonPropertyName\s*\(\s*"([^"]+)"\s*\)/.exec(attrs);
        const wire = wm ? wm[1] : null;

        props.push({
            csType: csType.trim(),
            name,
            required: !!requiredKw || !csType.trim().endsWith('?'),
            wire,
            context: `${rel} ${typeName}.${name}`,
        });
    }
    return props;
}

function generateModels(types, enums) {
    const known = new Set([...types.map((t) => t.name), ...enums.map((e) => e.name)]);

    // Resolve every property first, dropping any whose C# type has no wire representation.
    for (const t of types) {
        t.fields = [];
        for (const p of t.props) {
            const mapped = mapType(p.csType, known, p.context);
            if (mapped.unresolved) {
                warn(`${p.context}: dropped — '${mapped.unresolved}' has no wire representation`);
                continue;
            }
            t.fields.push({ ...p, ...mapped });
        }
    }

    // A type left with no fields of its own and no base among the generated models is not a wire
    // DTO. Two shapes land here and both should: `Worker : BackgroundService`, a leftover
    // template in Models/Config/ScheduleDefinition.cs, and `CertificateAuthorityIdentity`, whose
    // only members are a BouncyCastle certificate and a private-key handle.
    const emitted = types.filter(
        (t) => t.fields.length > 0 || t.bases.some((b) => known.has(b)),
    );
    for (const t of types) {
        if (!emitted.includes(t)) warn(`${t.source}: skipping '${t.name}' (nothing serializable)`);
    }

    const emittedNames = new Set(emitted.map((t) => t.name));
    const dupes = emitted.map((t) => t.name).filter((n, i, a) => a.indexOf(n) !== i);
    for (const d of new Set(dupes)) {
        warn(`duplicate type name '${d}' — declared in ${emitted.filter((t) => t.name === d).map((t) => t.source).join(', ')}`);
    }

    const lines = [];
    lines.push(BANNER('ModularCA.Shared/Models/**/*.cs'));
    lines.push("import type * as E from './enums';");
    lines.push('');
    lines.push(`/**
 * Wire shapes for the DTOs in \`ModularCA.Shared.Models\`.
 *
 * Property names are the names the server actually emits: \`JsonNamingPolicy.CamelCase\` is
 * applied globally, and it lowercases only the LEADING run of capitals — so \`SubjectDN\` is
 * \`subjectDN\` on the wire, not \`subjectDn\`. Hand-written interfaces get that wrong routinely,
 * and the result is a property that reads \`undefined\` with no error anywhere.
 *
 * A C# nullable property becomes \`?: T | null\`: it may be omitted from a request and may be
 * present-but-null in a response, and both need to typecheck.
 */`);
    lines.push('');

    const seen = new Set();
    for (const t of emitted.slice().sort((a, b) => a.name.localeCompare(b.name))) {
        if (seen.has(t.name)) continue;
        seen.add(t.name);
        const extend = t.bases.filter((b) => emittedNames.has(b));
        lines.push(`/** From \`${t.source}\`. */`);
        lines.push(
            `export interface ${t.name}${extend.length ? ` extends ${extend.join(', ')}` : ''} {`,
        );
        for (const p of t.fields) {
            const { ts, nullable } = p;
            const isEnum = enums.some((e) => e.name === ts.replace(/\[\]$/, ''));
            const tsName = isEnum ? ts.replace(/^(\w+)/, 'E.$1') : ts;
            const wire = p.wire ?? camelCase(p.name);
            const optional = nullable || !p.required;
            lines.push(`    ${wire}${optional ? '?' : ''}: ${tsName}${nullable ? ' | null' : ''};`);
        }
        lines.push('}');
        lines.push('');
    }

    return { file: 'models.ts', content: lines.join('\n') };
}

// --------------------------------------------------------------------------- //
// Drive
// --------------------------------------------------------------------------- //

const modelFiles = csFiles(resolve(ROOT, 'ModularCA.Shared', 'Models'));
const enumFiles = [
    ...csFiles(resolve(ROOT, 'ModularCA.Shared', 'Enums')),
    ...modelFiles,
];

const enums = collectEnums(enumFiles);
const types = collectModels(modelFiles);

const outputs = [
    generateCapabilities(),
    generateStepUpOps(),
    generateUsageVocabulary(),
    generateEnums(enums),
    generateModels(types, enums),
];

outputs.push({
    file: 'index.ts',
    content:
        BANNER('scripts/generate-shared-types.mjs') +
        `/** Everything generated from the C# backend. Import from '@shared/generated'. */\n` +
        outputs.map((o) => `export * from './${o.file.replace(/\.ts$/, '')}';`).join('\n') +
        '\n',
});

mkdirSync(OUT_DIR, { recursive: true });

let stale = 0;
for (const { file, content } of outputs) {
    const path = join(OUT_DIR, file);
    let existing = null;
    try { existing = readFileSync(path, 'utf-8'); } catch { /* new file */ }
    const normalized = content.replace(/\r\n/g, '\n');
    if (existing !== null && existing.replace(/\r\n/g, '\n') === normalized) continue;
    stale++;
    if (CHECK) {
        console.error(`[gen-types] STALE: shared/common/src/generated/${file}`);
    } else {
        writeFileSync(path, normalized);
        console.log(`[gen-types] wrote shared/common/src/generated/${file}`);
    }
}

for (const w of warnings) console.warn(`[gen-types] ${w}`);

console.log(
    `[gen-types] ${types.length} types, ${enums.length} enums from ${modelFiles.length} C# files ` +
    `(${stale} output file${stale === 1 ? '' : 's'} ${CHECK ? 'stale' : 'updated'})`,
);

if (CHECK && stale > 0) {
    console.error(
        '[gen-types] Generated TypeScript is out of date with the C# sources. ' +
        'Run: node scripts/generate-shared-types.mjs',
    );
    process.exit(1);
}
