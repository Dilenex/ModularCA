#!/usr/bin/env node
/**
 * Rewrites stock Tailwind colour utilities in the SPA sources onto the Ledger theme tokens
 * declared in shared/common/src/theme/ledger.css.
 *
 * Every string literal and template-literal chunk in the .ts/.tsx sources is treated as a class
 * list. Within one literal, classes that differ only by the `dark:` variant form a pair
 * (`bg-white dark:bg-gray-800`), and the pair collapses to a single token that switches with the
 * `.dark` class by itself (`bg-raised`). A lone light-only or dark-only class maps to the role
 * its shade implies. Anything whose role cannot be decided is left alone and listed by --report.
 *
 *   node scripts/ledger-codemod.mjs            # rewrite in place
 *   node scripts/ledger-codemod.mjs --check    # exit 1 if any file would change
 *   node scripts/ledger-codemod.mjs --report   # also list what was left alone
 *   node scripts/ledger-codemod.mjs --stats    # also list every applied mapping with counts
 *
 * Idempotent: the tokens it writes are not stock utilities, so a second run finds nothing.
 * TypeScript is borrowed from modularca.adminui/node_modules so the script adds no dependency.
 */
import { createRequire } from 'node:module';
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const CHECK = process.argv.includes('--check');
const REPORT = process.argv.includes('--report');
const STATS = process.argv.includes('--stats');

const TS_HOSTS = ['modularca.adminui', 'modularca.docsui', 'modularca.setupui', 'modularca.publicui', 'tests/modularca.web.tests'];
const tsHost = TS_HOSTS.find(h => existsSync(join(ROOT, h, 'node_modules', 'typescript', 'package.json')));
if (!tsHost) {
    console.error('typescript not found; run `npm ci` in modularca.adminui first.');
    process.exit(2);
}
const ts = createRequire(join(ROOT, tsHost, 'package.json'))('typescript');

const DIRS = [
    'modularca.adminui/src', 'modularca.publicui/src', 'modularca.setupui/src', 'modularca.docsui/src',
    'shared/common/src', 'shared/authenticated/src',
];

/* ── Class grammar ─────────────────────────────────────────────────────────── */

const NEUTRAL = ['gray', 'slate', 'zinc', 'neutral', 'stone'];
/** Fixed semantic kind per colour family. `blue` is decided per literal (accent or info). */
const FAMILY_KIND = {
    red: 'crit', rose: 'crit',
    green: 'ok', emerald: 'ok',
    yellow: 'warn', amber: 'warn', orange: 'warn',
    sky: 'info', cyan: 'info',
    teal: 'accent', indigo: 'accent', violet: 'accent', purple: 'accent',
};
const FAMILIES = [...NEUTRAL, 'blue', ...Object.keys(FAMILY_KIND)].join('|');
const CLASS_RE = new RegExp(
    '^((?:[^\\s:]+:)*)' +
    '(bg|text|border(?:-[xytrblse])?|ring-offset|ring|divide|outline|fill|stroke|placeholder|from|via|to|shadow|decoration|caret|accent)-' +
    `(?:(${FAMILIES})-(\\d{2,3})|(white|black))` +
    '(?:/(\\d+))?$',
);

function parse(tok) {
    const m = tok.match(CLASS_RE);
    if (!m) return null;
    const variants = m[1] ? m[1].slice(0, -1).split(':') : [];
    const dark = variants.includes('dark');
    const rest = variants.filter(v => v !== 'dark');
    return {
        tok,
        dark,
        variants: rest,
        prefix: rest.length ? rest.join(':') + ':' : '',
        prop: m[2],
        family: m[3] ?? m[5],
        shade: m[4] ? Number(m[4]) : (m[5] === 'white' ? 0 : 1000),
        alpha: m[6] ? Number(m[6]) : null,
    };
}

const isHoverish = c => c.variants.some(v => /hover|active/.test(v));
const isNeutral = c => NEUTRAL.includes(c.family) || c.family === 'white' || c.family === 'black';
const propBase = p => (p.startsWith('border') || p === 'divide' || p === 'outline') ? 'border'
    : (p === 'fill' || p === 'stroke' || p === 'decoration' || p === 'caret' || p === 'accent') ? 'text' : p;

/** Soft = a tint: light 50-200, dark 800+ or any translucent dark shade. */
const isSoftBg = c => c.dark ? (c.shade >= 800 || (c.alpha != null && c.shade >= 600)) : (c.shade <= 200 || (c.alpha != null && c.alpha <= 40) || c.shade >= 800);

/* ── Literal context ───────────────────────────────────────────────────────── */

function contextOf(classes, tokens, tag) {
    const ctx = { input: false, code: false, solidBg: false, blueMode: 'accent', blueSoft: false, softKinds: new Set() };
    ctx.input = ['input', 'select', 'textarea'].includes(tag)
        || tokens.some(t => /(^|:)placeholder-/.test(t) || /(^|:)focus:border-/.test(t));
    ctx.code = ['code', 'pre', 'kbd', 'samp'].includes(tag) || tokens.includes('font-mono') || tokens.includes('data-mono');
    // A callout is a pale box with a thick coloured edge; that edge is not a selection marker.
    const callout = tokens.some(t => /^border-[lrtb]-\d/.test(t));
    let blueSelect = false;
    const passive = c => !(isHoverish(c) || c.variants.some(v => v === 'disabled' || v.startsWith('file') || v.startsWith('focus')));
    for (const c of classes) {
        if (!passive(c)) continue;
        if (c.prop === 'bg' && !isNeutral(c) && !c.dark && c.shade >= 500 && c.shade <= 700 && (c.alpha == null || c.alpha >= 80)) ctx.solidBg = true;
        if (c.family === 'blue') {
            if (c.prop === 'bg' && isSoftBg(c)) ctx.blueSoft = true;
            if ((c.prop === 'border' || c.prop === 'ring') && c.shade >= 400 && c.shade <= 600 && !c.dark && !callout) blueSelect = true;
        }
    }
    ctx.blueMode = ctx.blueSoft && !blueSelect ? 'info' : 'accent';
    for (const c of classes) {
        if (passive(c) && c.prop === 'bg' && !isNeutral(c) && isSoftBg(c)) ctx.softKinds.add(kindOf(c, ctx));
    }
    return ctx;
}

function kindOf(c, ctx) {
    if (c.family === 'blue') {
        if (c.variants.some(v => v.startsWith('focus'))) return 'accent';
        if (c.prop === 'text' && isHoverish(c)) return 'accent';
        if (c.prop === 'text' && !ctx.blueSoft) {
            // Deep blue text paired with a pale dark-mode shade reads as an informational heading;
            // mid blue is a link or an interactive affordance.
            if (!c.dark && c.shade >= 800) return 'info';
            if (c.dark && c.shade <= 300) return 'info';
            return 'accent';
        }
        return ctx.blueMode;
    }
    return FAMILY_KIND[c.family];
}

/* ── Roles ─────────────────────────────────────────────────────────────────── */

const SOLID_HOVER = { accent: 'accent-hover', crit: 'crit-hover', ok: 'ok-hover', warn: 'warn-hover', info: null };
const INK = { accent: 'accent-ink', info: 'info', crit: 'crit', ok: 'ok', warn: 'warn' };

/** Role of a single neutral class, or null when its role cannot be decided alone. */
function neutralRole(c, ctx) {
    const s = c.shade, p = propBase(c.prop), hov = isHoverish(c);
    const disabled = c.variants.includes('disabled');
    if (c.family === 'black') return null;
    if (p === 'bg') {
        if (disabled) return 'ink-faint';
        if (c.variants.some(v => v.startsWith('file'))) return hov ? 'hover' : 'sunken';
        if (hov) {
            if (!c.dark && s <= 300) return 'hover';
            if (c.dark && s >= 500 && s <= 900) return 'hover';
            return null;
        }
        if (ctx.input) {
            if (!c.dark && s <= 200) return 'raised';
            if (c.dark && s >= 700) return 'raised';
        }
        if (ctx.code && ((!c.dark && s <= 200) || (c.dark && s >= 700))) return 'sunken';
        if (!c.dark) {
            if (s === 0) return 'raised';
            if (s === 50) return c.alpha != null ? 'sunken' : 'ground';
            if (s === 100 || s === 200) return 'sunken';
            if (s === 300) return 'line';
            if (c.alpha != null && s >= 600) return 'sunken';
            if (s === 400 || s === 500) return 'ink-faint';
            return null;
        }
        if (s === 950 || s === 900) return c.alpha != null ? 'sunken' : 'ground';
        if (s === 800) return c.alpha != null ? 'sunken' : 'raised';
        if (s === 700) return 'sunken';
        if (s === 600) return 'line-strong';
        if (s === 500) return 'ink-faint';
        return null;
    }
    if (p === 'text') {
        if (!hov && !c.dark && s === 0) return 'on-accent';
        if (ctx.solidBg && !hov && ((!c.dark && s >= 900) || (c.dark && s <= 100))) return 'on-accent';
        if (hov) {
            if (!c.dark && s >= 600) return 'ink';
            if (c.dark && s <= 300) return 'ink';
            if (!c.dark && s <= 300) return 'ink';
            return null;
        }
        if (!c.dark) {
            if (s === 0) return null;
            if (s >= 700) return 'ink';
            if (s >= 500) return 'ink-muted';
            if (s >= 300) return 'ink-faint';
            return null;
        }
        if (s <= 300) return 'ink';
        if (s === 400) return 'ink-muted';
        if (s <= 700) return 'ink-faint';
        return null;
    }
    if (p === 'border') {
        if (hov) return s >= 400 && s <= 600 ? 'ink-faint' : 'line-strong';
        if (!c.dark) {
            if (s <= 200) return 'line';
            if (s === 300) return ctx.input ? 'line-strong' : 'line';
            if (s <= 600) return 'line-strong';
            return null;
        }
        if (s >= 700) return ctx.input && s === 700 && c.alpha == null ? 'line-strong' : 'line';
        if (s >= 500) return 'line-strong';
        return null;
    }
    if (p === 'placeholder') return 'ink-faint';
    if (p === 'ring') return s === 0 ? null : 'line-strong';
    if (p === 'ring-offset') return (s === 0 || s >= 800) ? 'raised' : null;
    return null;
}

/** Role of a single chromatic class. */
function chromaRole(c, ctx) {
    const k = kindOf(c, ctx);
    const s = c.shade, p = propBase(c.prop), hov = isHoverish(c);
    if (c.variants.includes('disabled')) return p === 'bg' ? 'ink-faint' : null;
    if (p === 'bg') {
        if (hov) {
            const soft = isSoftBg(c) || (!c.dark && s >= 800);
            if (soft) return ctx.softKinds.has(k) ? `${k}/15` : `${k}-soft`;
            return SOLID_HOVER[k];
        }
        if (isSoftBg(c)) return `${k}-soft`;
        if (c.dark && s >= 500) return k;
        if (!c.dark && s >= 300) return k;
        return null;
    }
    if (p === 'text') {
        if (c.prop === 'fill' || c.prop === 'stroke' || c.prop === 'accent') return k;
        if (hov) return k === 'accent' ? 'accent-hover' : INK[k];
        return INK[k];
    }
    if (p === 'border') {
        const strong = c.dark ? (s >= 400 && s <= 500) : (s >= 400 && s <= 700);
        if (hov) return k;
        if (!strong) return `${k}/40`;
        return c.alpha != null ? `${k}/${c.alpha}` : k;
    }
    if (p === 'ring') return k === 'info' && c.family === 'blue' ? 'accent' : k;
    if (p === 'ring-offset') return null;
    if (p === 'placeholder') return null;
    return null;
}

const role = (c, ctx) => isNeutral(c) ? neutralRole(c, ctx) : chromaRole(c, ctx);

/**
 * Pairs whose two halves would map to different roles on their own, decided here by what the
 * pair is used for across the codebase.
 */
const PAIRS = {
    'text|gray-500|gray-500': 'ink-muted',
    'text|gray-600|gray-300': 'ink-muted',
    'text|gray-400|gray-400': 'ink-faint',
    'text|gray-400|gray-600': 'ink-faint',
    'text|blue-800|blue-400': 'accent-ink',
    'text|blue-900|blue-400': 'accent-ink',
    'text|blue-700|blue-300': 'accent-ink',
    'text|blue-600|blue-300': 'accent-ink',
    'bg|gray-100|gray-900': 'sunken',
    'bg|gray-50|gray-800': 'sunken',
    'bg|gray-200|gray-800': 'sunken',
    'bg|white|gray-900': 'raised',
    'bg|white|gray-950': 'raised',
    'bg|gray-100|gray-800': 'raised',
    'bg|gray-50|gray-700': 'sunken',
    'bg|gray-50|gray-900/40': 'sunken',
    'bg|gray-50|gray-900/50': 'sunken',
    'bg|gray-50|gray-900/60': 'sunken',
    'bg|gray-50|gray-900/95': 'sunken',
    'bg|gray-50|gray-800/60': 'sunken',
    'bg|gray-200|gray-900': 'sunken',
    'bg|gray-300|gray-700': 'line',
    'bg|white|gray-800/50': 'raised',
    'border|gray-300|gray-600': 'line-strong',
    'text|gray-600|gray-500': 'ink-muted',
    'text|gray-600|gray-600': 'ink-muted',
    'text|gray-700|gray-400': 'ink',
    'border|gray-300|gray-800': 'line',
};

/* ── Rewriting one literal ─────────────────────────────────────────────────── */

const applied = new Map();
const leftovers = new Map();
const note = (map, key, where) => {
    const e = map.get(key) ?? { n: 0, where };
    e.n++;
    map.set(key, e);
};

/**
 * Identifiers set in `font-mono text-sm` or `font-mono text-xs` become `data-mono`: Plex Mono at 13px
 * with tabular figures. Mono text at an arbitrary size (text-[11px]) keeps it.
 */
function monoPass(text, lockFirst, lockLast) {
    const toks = text.split(/\s+/).filter(Boolean);
    if (lockFirst && !/^\s/.test(text)) toks.shift();
    if (lockLast && !/\s$/.test(text)) toks.pop();
    if (!toks.includes('font-mono')) return text;
    const size = toks.filter(t => /^text-(xs|sm|base|lg|xl|\d?xl|\[)/.test(t));
    if (size.length !== 1 || (size[0] !== 'text-sm' && size[0] !== 'text-xs')) return text;
    const drop = new RegExp(`\\s+${size[0]}(?=\\s|$)|^${size[0]}\\s+`);
    return text
        .replace(/(^|\s)font-mono(?=\s|$)/, '$1data-mono')
        .replace(drop, '');
}

/**
 * Rewrites the class list `text` (the inside of one literal). `lockFirst`/`lockLast` protect a
 * token glued to a `${...}` boundary, which is only part of a class name.
 */
function rewrite(text, lockFirst, lockLast, where, tag) {
    text = monoPass(text, lockFirst, lockLast);
    const parts = text.split(/(\s+)/);
    const tokIdx = [];
    for (let i = 0; i < parts.length; i++) if (parts[i] && !/^\s+$/.test(parts[i])) tokIdx.push(i);
    if (!tokIdx.length) return text;
    const locked = new Set();
    if (lockFirst && !/^\s/.test(text)) locked.add(tokIdx[0]);
    if (lockLast && !/\s$/.test(text)) locked.add(tokIdx[tokIdx.length - 1]);

    const parsed = new Map();
    for (const i of tokIdx) {
        if (locked.has(i)) continue;
        const c = parse(parts[i]);
        if (c) parsed.set(i, c);
    }
    if (!parsed.size) return text;
    const ctx = contextOf([...parsed.values()], tokIdx.map(i => parts[i]), tag);

    const groups = new Map();
    for (const [i, c] of parsed) {
        const key = c.prefix + '|' + c.prop;
        if (!groups.has(key)) groups.set(key, []);
        groups.get(key).push(i);
    }

    const out = new Map();
    const remove = new Set();
    for (const idxs of groups.values()) {
        const cs = idxs.map(i => parsed.get(i));
        const L = cs.filter(c => !c.dark), D = cs.filter(c => c.dark);
        const name = c => c.family + (c.family === 'white' || c.family === 'black' ? '' : '-' + c.shade) + (c.alpha != null ? '/' + c.alpha : '');
        // A lone bg-white is a QR code's quiet zone or a switch knob: it must stay white in both themes.
        if (!D.length && L.length === 1 && L[0].prop === 'bg' && L[0].family === 'white' && L[0].alpha == null) continue;
        let target = null;
        const pairable = !cs[0].prefix && !((ctx.input || ctx.code) && propBase(cs[0].prop) === 'bg');
        if (pairable && L.length === 1 && D.length === 1) target = PAIRS[`${propBase(L[0].prop)}|${name(L[0])}|${name(D[0])}`] ?? null;
        if (!target) {
            const roles = [...new Set(cs.map(c => role(c, ctx)))];
            if (roles.length === 1 && roles[0]) {
                target = roles[0];
            } else if (L.length && D.length) {
                const lr = [...new Set(L.map(c => role(c, ctx)))];
                const dr = [...new Set(D.map(c => role(c, ctx)))];
                if (lr.length === 1 && lr[0] && (dr.includes(null) || dr.length > 1)) target = null;
                else if (lr.length === 1 && lr[0] && dr.length === 1 && dr[0]) {
                    // Both halves resolve but disagree: the light half was the designed one.
                    target = lr[0];
                    note(leftovers, `pair resolved by light half: ${cs.map(c => c.tok).join(' ')} -> ${lr[0]} (dark said ${dr[0]})`, where);
                }
            }
        }
        if (!target) {
            note(leftovers, cs.map(c => c.tok).join(' '), where);
            continue;
        }
        const first = Math.min(...idxs);
        const prop = cs[0].prop;
        const tok = `${cs[0].prefix}${prop}-${target}`;
        note(applied, `${cs.map(c => c.tok).join(' ')} -> ${tok}`, where);
        out.set(first, tok);
        for (const i of idxs) if (i !== first) remove.add(i);
    }

    const seen = new Set(tokIdx.filter(i => !out.has(i) && !remove.has(i)).map(i => parts[i]));
    for (const i of [...out.keys()].sort((a, b) => a - b)) {
        const tok = out.get(i);
        if (seen.has(tok)) remove.add(i);
        else { parts[i] = tok; seen.add(tok); }
    }
    if (!remove.size) return parts.join('');
    // Rebuild from the surviving tokens, each keeping the separator that preceded it.
    const lead = /^\s*/.exec(text)[0], trail = /\s*$/.exec(text)[0];
    let body = '';
    for (const i of tokIdx) {
        if (remove.has(i)) continue;
        const sep = i > 0 && /^\s+$/.test(parts[i - 1]) ? parts[i - 1] : '';
        body += body ? (sep || ' ') + parts[i] : parts[i];
    }
    return body ? lead + body + trail : lead + (trail === lead ? '' : trail);
}

/* ── Files ─────────────────────────────────────────────────────────────────── */

function collect(dir, out = []) {
    for (const entry of readdirSync(dir)) {
        const full = join(dir, entry);
        if (statSync(full).isDirectory()) {
            if (entry === 'node_modules' || entry === 'generated' || entry === 'dist') continue;
            collect(full, out);
        } else if (/\.tsx?$/.test(entry) && !entry.endsWith('.d.ts') && !/\.test\.tsx?$/.test(entry)) {
            out.push(full);
        }
    }
    return out;
}

/** The intrinsic element a className literal is written on, when it is written directly on one. */
function jsxTag(node) {
    let n = node.parent;
    for (let depth = 0; n && depth < 8; depth++, n = n.parent) {
        if (ts.isJsxAttribute(n)) {
            const el = n.parent?.parent;
            if (el && (ts.isJsxOpeningElement(el) || ts.isJsxSelfClosingElement(el)) && ts.isIdentifier(el.tagName)) {
                const t = el.tagName.text;
                return /^[a-z]/.test(t) ? t : null;
            }
            return null;
        }
        if (ts.isJsxElement(n) || ts.isBlock(n) || ts.isSourceFile(n)) return null;
    }
    return null;
}

function transform(file) {
    const src = readFileSync(file, 'utf8');
    const sf = ts.createSourceFile(file, src, ts.ScriptTarget.Latest, true, file.endsWith('x') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
    const edits = [];
    const visit = node => {
        let open = 0, close = 0, lockFirst = false, lockLast = false;
        if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) { open = 1; close = 1; }
        else if (ts.isTemplateHead(node)) { open = 1; close = 2; lockLast = true; }
        else if (ts.isTemplateMiddle(node)) { open = 1; close = 2; lockFirst = true; lockLast = true; }
        else if (ts.isTemplateTail(node)) { open = 1; close = 1; lockFirst = true; }
        if (open) {
            const start = node.getStart(sf), end = node.end;
            const inner = src.slice(start + open, end - close);
            const line = sf.getLineAndCharacterOfPosition(start).line + 1;
            const next = rewrite(inner, lockFirst, lockLast, `${relative(ROOT, file).replace(/\\/g, '/')}:${line}`, jsxTag(node));
            if (next !== inner) edits.push([start + open, end - close, next]);
        }
        ts.forEachChild(node, visit);
    };
    visit(sf);
    if (!edits.length) return null;
    let out = src;
    for (const [a, b, text] of edits.sort((x, y) => y[0] - x[0])) out = out.slice(0, a) + text + out.slice(b);
    return out;
}

const files = DIRS.flatMap(d => existsSync(join(ROOT, d)) ? collect(join(ROOT, d)) : []);
const changed = [];
for (const f of files) {
    const next = transform(f);
    if (next == null) continue;
    changed.push(relative(ROOT, f).replace(/\\/g, '/'));
    if (!CHECK) writeFileSync(f, next);
}

const dump = (title, map) => {
    console.log(`\n${title}`);
    for (const [k, v] of [...map].sort((a, b) => b[1].n - a[1].n)) console.log(`${String(v.n).padStart(5)}  ${k}   (${v.where})`);
};
if (STATS) dump('Applied mappings', applied);
if (REPORT) dump('Left alone (role ambiguous)', leftovers);

if (CHECK) {
    if (changed.length) {
        console.log(`${changed.length} file(s) carry classes the codemod would rewrite:`);
        for (const f of changed) console.log(`  ${f}`);
        process.exit(1);
    }
    console.log('ledger-codemod: nothing to rewrite.');
} else {
    console.log(`ledger-codemod: rewrote ${changed.length} file(s).`);
}
