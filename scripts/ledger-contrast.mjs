#!/usr/bin/env node
/**
 * Contrast lint for the Ledger colour tokens (shared/common/src/theme/ledger.css).
 *
 * Every class expression in the SPA sources (string literals, template literals with their
 * conditional branches expanded, and the class constants they reference) is resolved to the text
 * and background tokens it sets, per state (base, hover:, disabled:, ...). Each text token is
 * judged against the background in the same class string; without one, against the nearest JSX
 * ancestor's background, or else the surface it most likely sits on (`raised`, or `ground` for
 * page-level elements). Both themes, WCAG 2.x relative luminance, `/NN` opacity composited over
 * that backdrop. Placeholder, disabled and `ink-faint` text is exempt and only reported (`--exempt`).
 *
 *   node scripts/ledger-contrast.mjs            # list failures
 *   node scripts/ledger-contrast.mjs --check    # exit 1 on any failure not in the allowlist
 *   node scripts/ledger-contrast.mjs --exempt   # also list exempt (faint, placeholder, disabled) pairs
 *   node scripts/ledger-contrast.mjs --json     # machine-readable result
 *
 * Kinds of failure:
 *   contrast           a text/background pair below 4.5:1 (3:1 for large or bold text) in a theme
 *   on-accent-off-solid text-on-accent without an accent or status solid fill under it
 *   solid-text         a solid fill (bg-accent, bg-crit, ...) whose text is not on-accent, or unset
 *
 * Large text (text-lg and up, or semibold/bold at text-base and up) needs 3:1; everything else,
 * label-caps included, 4.5:1.
 *
 * Exceptions live in scripts/ledger-contrast.allowlist.json as { file, match, reason } entries,
 * where `match` is a substring of the class string.
 */
import { createRequire } from 'node:module';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const CHECK = process.argv.includes('--check');
const JSON_OUT = process.argv.includes('--json');
const SHOW_EXEMPT = process.argv.includes('--exempt');

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
const THEME = join(ROOT, 'shared/common/src/theme/ledger.css');
const ALLOWLIST = join(ROOT, 'scripts/ledger-contrast.allowlist.json');

/* ── Theme ─────────────────────────────────────────────────────────────────── */

function parseColor(v) {
    v = v.trim();
    let m = v.match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/i);
    if (m) {
        const h = m[1].length === 3 ? [...m[1]].map(c => c + c).join('') : m[1];
        return [0, 2, 4].map(i => parseInt(h.slice(i, i + 2), 16)).concat(1);
    }
    m = v.match(/^rgba?\(\s*([\d.]+)[\s,]+([\d.]+)[\s,]+([\d.]+)\s*(?:[/,]\s*([\d.]+)(%?))?\s*\)$/);
    if (m) {
        const a = m[4] == null ? 1 : Number(m[4]) / (m[5] ? 100 : 1);
        return [Number(m[1]), Number(m[2]), Number(m[3]), a];
    }
    return null;
}

function parseBlock(css, selector) {
    const re = new RegExp(`(?:^|\\n)\\s*${selector.replace('.', '\\.')}\\s*\\{([^}]*)\\}`);
    const m = css.match(re);
    if (!m) throw new Error(`ledger.css: no ${selector} block`);
    const out = {};
    for (const d of m[1].matchAll(/--([a-z0-9-]+)\s*:\s*([^;]+);/g)) {
        const c = parseColor(d[2]);
        if (c) out[d[1]] = c;
    }
    return out;
}

export function loadTheme(file = THEME) {
    const css = readFileSync(file, 'utf8');
    const light = parseBlock(css, ':root');
    const dark = { ...light, ...parseBlock(css, '.dark') };
    for (const t of [light, dark]) {
        t.white = [255, 255, 255, 1];
        t.black = [0, 0, 0, 1];
    }
    return { light, dark };
}

const over = (fg, bg) => {
    const a = fg[3];
    return [0, 1, 2].map(i => fg[i] * a + bg[i] * (1 - a)).concat(1);
};
const lum = c => {
    const [r, g, b] = c.slice(0, 3).map(v => {
        v /= 255;
        return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
    });
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
};
export const ratio = (a, b) => {
    const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p);
    return (x + 0.05) / (y + 0.05);
};

/* ── Class grammar ─────────────────────────────────────────────────────────── */

const FRAGMENT = /^(?:[^\s:]+:)*(?:bg|text|border(?:-[xytrblse])?|ring|ring-offset|divide|outline|fill|stroke|from|via|to)-[a-z0-9/-]+$/;
const SOLID = new Set(['ink-muted', 'accent', 'accent-hover', 'ok', 'ok-hover', 'warn', 'warn-hover', 'crit', 'crit-hover', 'info', 'badge-worn']);
const RESPONSIVE = new Set(['sm', 'md', 'lg', 'xl', '2xl', 'print', 'motion-safe', 'motion-reduce']);
const LARGE = /^text-(lg|[2-9]?xl)$/;

let THEME_NAMES = null;

/** `hover:bg-accent/15` -> { prop: 'bg', name: 'accent', alpha: 0.15, state: ['hover'] }, or null. */
function parseClass(tok) {
    const m = tok.match(/^((?:[^\s:]+:)*)(bg|text|placeholder)-([a-z0-9-]+)(?:\/(\d+))?$/);
    if (!m || !THEME_NAMES.has(m[3]) && m[3] !== 'transparent') return null;
    let state = m[1] ? m[1].slice(0, -1).split(':').filter(v => !RESPONSIVE.has(v)) : [];
    let prop = m[2];
    if (prop === 'placeholder') { prop = 'text'; state = [...state, 'placeholder']; }
    return { tok, prop, name: m[3], alpha: m[4] ? Number(m[4]) / 100 : 1, state: [...new Set(state)].sort() };
}

const isExemptState = s => s.some(v => v.startsWith('disabled') || v.includes('placeholder'));

/** The token of `list` whose state is the largest subset of `state`, or every such token on a tie. */
function bestFor(list, state) {
    let best = [], size = -1;
    for (const t of list) {
        if (!t.state.every(v => state.includes(v))) continue;
        if (t.state.length > size) { best = [t]; size = t.state.length; }
        else if (t.state.length === size) best.push(t);
    }
    return best;
}

/**
 * Judges one class string. Returns findings; `tokens` carry the line of the literal they came from.
 */
function judge(tokens, theme, opts) {
    const words = tokens.map(t => t.s);
    const classes = tokens.map(t => ({ ...parseClass(t.s), line: t.line })).filter(c => c.prop);
    if (words.includes('label-caps') && !classes.some(c => c.prop === 'text' && !c.state.length)) {
        const at = tokens.find(t => t.s === 'label-caps');
        classes.push({ tok: 'label-caps', prop: 'text', name: 'ink-muted', alpha: 1, state: [], line: at.line });
    }
    const texts = classes.filter(c => c.prop === 'text' && c.name !== 'transparent');
    const bgs = classes.filter(c => c.prop === 'bg' && c.name !== 'transparent');
    if (!texts.length && !bgs.length) return [];

    const large = words.some(w => LARGE.test(w))
        || (words.some(w => w === 'font-semibold' || w === 'font-bold') && words.includes('text-base'));
    const pageLevel = opts.tag === 'main' || opts.tag === 'body' || words.some(w => w === 'min-h-screen' || w === 'min-h-dvh');
    const surface = pageLevel ? 'ground' : 'raised';
    // Needs no text colour: a childless element, a small dot or bar, or a colour-only fragment
    // (`bg-warn`) that is composed into a class string somewhere this lint cannot follow.
    const decorative = opts.selfClosing || words.some(w => /^(h|size)-(px|0\.5|1|1\.5|2|2\.5|3)$/.test(w))
        || (!opts.classAttr && words.every(w => FRAGMENT.test(w)));

    const states = new Map();
    for (const c of [...texts, ...bgs]) states.set(c.state.join(':'), c.state);
    if (!states.has('')) states.set('', []);

    // With no background of its own, text sits on the nearest ancestor's (when one is known).
    const inherited = (opts.inherited?.length ? opts.inherited : [null])
        .filter(i => !i || !opts.binds || agree(i.binds, opts.binds));
    const out = [];
    for (const [ii, inh] of (inherited.length ? inherited : [null]).entries()) {
        for (const state of states.values()) {
            const ts_ = bestFor(texts, state);
            const bs = bestFor(bgs, state);
            if (!ts_.length) {
                if (ii) continue;
                for (const b of bs) {
                    if (!SOLID.has(b.name) || b.alpha < 1 || decorative || state.some(v => v.includes('placeholder'))) continue;
                    out.push({ kind: 'solid-text', state, text: null, bg: b, line: b.line });
                }
                continue;
            }
            const bgList = bs.length ? bs : [inh];
            for (const t of ts_) {
                for (const b of bgList) {
                    const solid = b && SOLID.has(b.name) && b.alpha === 1;
                    const line = (b && !b.inherited && b.line > t.line ? b.line : t.line);
                    const m = measure(t, b, inh, surface, theme, large);
                    if (t.name === 'on-accent' && !solid) {
                        if (isExemptState(state) && m.light >= 3 && m.dark >= 3) {
                            out.push({ kind: 'exempt', state, text: t, bg: b, line, ...m });
                            continue;
                        }
                        out.push({ kind: 'on-accent-off-solid', state, text: t, bg: b, line, ...m });
                        continue;
                    }
                    if (solid && t.name !== 'on-accent' && !isExemptState(state)) {
                        out.push({ kind: 'solid-text', state, text: t, bg: b, line, ...m });
                        continue;
                    }
                    if (m.light >= m.need && m.dark >= m.need) continue;
                    const exempt = t.name === 'ink-faint' || isExemptState(state);
                    out.push({ kind: exempt ? 'exempt' : 'contrast', state, text: t, bg: b, line, ...m });
                }
            }
        }
    }
    return out.map(f => ({ ...f, surface }));
}

/** Contrast of text `t` on background `b`, laid over the inherited background `inh` over `surface`. */
function measure(t, b, inh, surface, theme, large) {
    const res = {};
    const lay = (th, c, back) => over([...th[c.name].slice(0, 3), th[c.name][3] * c.alpha], back);
    for (const mode of ['light', 'dark']) {
        const th = theme[mode];
        let back = th[surface];
        if (inh) back = lay(th, inh, back);
        if (b && b !== inh) back = lay(th, b, back);
        const fg = lay(th, t, back);
        res[mode] = Math.round(ratio(fg, back) * 100) / 100;
    }
    res.need = large ? 3 : 4.5;
    return res;
}

/* ── Sources ───────────────────────────────────────────────────────────────── */

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

const MAX_VARIANTS = 256;
const UNKNOWN = [[]];

/** Cartesian product of alternative piece-lists. */
/**
 * `map[key]` lookups record which entry they took as a { bind: [key, entry] } piece, so two
 * lookups with the same key (`bg[tone]`, `text[tone]`) only combine entries that match.
 */
export const bindsOf = pieces => {
    const m = new Map();
    for (const p of pieces) if (p.bind) m.set(p.bind[0], p.bind[1]);
    return m;
};
export const agree = (x, y) => [...x].every(([k, v]) => !y.has(k) || y.get(k) === v);

/** Cartesian product of alternative piece-lists, skipping combinations whose lookups disagree. */
function product(lists) {
    let acc = [[]];
    for (const alts of lists) {
        const next = [];
        for (const a of acc) {
            const ab = bindsOf(a);
            for (const b of alts) {
                if (next.length >= MAX_VARIANTS) break;
                if (ab.size && !agree(ab, bindsOf(b))) continue;
                next.push(a.concat(b));
            }
        }
        acc = next;
    }
    return acc;
}

const isLiteral = n => ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n);

const unwrap = n => {
    while (n && (ts.isAsExpression(n) || ts.isParenthesizedExpression(n) || ts.isNonNullExpression(n) || ts.isSatisfiesExpression?.(n))) n = n.expression;
    return n;
};

/** Whether a binding name (identifier or destructuring pattern) declares `name`. */
function binds(b, name) {
    if (ts.isIdentifier(b)) return b.text === name;
    if (ts.isObjectBindingPattern(b) || ts.isArrayBindingPattern(b)) return b.elements.some(e => ts.isBindingElement(e) && binds(e.name, name));
    return false;
}

/** The expressions a function can return (not descending into nested functions). */
function returnsOf(fn) {
    if (!fn.body) return [];
    if (!ts.isBlock(fn.body)) return [fn.body];
    const out = [];
    const walk = n => {
        if (ts.isReturnStatement(n) && n.expression) out.push(n.expression);
        if (!ts.isFunctionLike(n)) ts.forEachChild(n, walk);
    };
    ts.forEachChild(fn.body, walk);
    return out;
}

class SourceFile {
    constructor(file, exportsByName) {
        this.file = file;
        this.rel = relative(ROOT, file).replace(/\\/g, '/');
        this.src = readFileSync(file, 'utf8');
        this.sf = ts.createSourceFile(file, this.src, ts.ScriptTarget.Latest, true, file.endsWith('x') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
        this.exportsByName = exportsByName;
        const exported = s => s.modifiers?.some(m => m.kind === ts.SyntaxKind.ExportKeyword);
        const add = (name, entry) => {
            if (!exportsByName.has(name)) exportsByName.set(name, []);
            exportsByName.get(name).push(entry);
        };
        for (const st of this.sf.statements) {
            if (ts.isVariableStatement(st) && exported(st) && (st.declarationList.flags & ts.NodeFlags.Const)) {
                for (const d of st.declarationList.declarations) {
                    if (ts.isIdentifier(d.name) && d.initializer) add(d.name.text, { owner: this, init: d.initializer });
                }
            }
            if (ts.isFunctionDeclaration(st) && st.name && exported(st)) add(st.name.text, { owner: this, fn: st });
        }
    }

    line(node) {
        return this.sf.getLineAndCharacterOfPosition(node.getStart(this.sf)).line + 1;
    }

    /**
     * What an identifier refers to, by lexical scope: { owner, init } for a const, { owner, fn }
     * for a function, or null (a parameter, a `let`, or anything not statically known).
     */
    resolve(id) {
        const name = id.text;
        for (let n = id.parent; n; n = n.parent) {
            if (ts.isFunctionLike(n) && n.parameters?.some(p => binds(p.name, name))) return null;
            const stmts = (ts.isBlock(n) || ts.isSourceFile(n) || ts.isModuleBlock(n) || ts.isCaseClause(n) || ts.isDefaultClause(n)) ? n.statements : null;
            if (!stmts) continue;
            for (const st of stmts) {
                if (ts.isVariableStatement(st)) {
                    for (const d of st.declarationList.declarations) {
                        if (!binds(d.name, name)) continue;
                        if (!(st.declarationList.flags & ts.NodeFlags.Const) || !ts.isIdentifier(d.name) || !d.initializer) return null;
                        const init = unwrap(d.initializer);
                        if (ts.isArrowFunction(init) || ts.isFunctionExpression(init)) return { owner: this, fn: init };
                        return { owner: this, init: d.initializer };
                    }
                }
                if (ts.isFunctionDeclaration(st) && st.name?.text === name) return { owner: this, fn: st };
            }
        }
        const ext = this.exportsByName.get(name);
        if (ext?.length !== 1) return null;
        const e = ext[0];
        if (e.init) {
            const init = unwrap(e.init);
            if (ts.isArrowFunction(init) || ts.isFunctionExpression(init)) return { owner: e.owner, fn: init };
        }
        return e;
    }

    /** Every class string `node` can evaluate to, as lists of { s, line } pieces. */
    alts(node, consumed, depth = 0) {
        if (depth > 12) return UNKNOWN;
        const rec = n => this.alts(n, consumed, depth + 1);
        if (isLiteral(node)) return [[{ s: node.text, line: this.line(node) }]];
        if (ts.isTemplateExpression(node)) {
            const lists = [[[{ s: node.head.text, line: this.line(node.head) }]]];
            for (const span of node.templateSpans) {
                lists.push(rec(span.expression));
                lists.push([[{ s: span.literal.text, line: this.line(span.literal) }]]);
            }
            return product(lists);
        }
        if (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) || ts.isNonNullExpression(node)
            || ts.isSatisfiesExpression?.(node)) return rec(node.expression);
        if (ts.isConditionalExpression(node)) return [...rec(node.whenTrue), ...rec(node.whenFalse)].slice(0, MAX_VARIANTS);
        if (ts.isBinaryExpression(node)) {
            const op = node.operatorToken.kind;
            if (op === ts.SyntaxKind.AmpersandAmpersandToken) return [...rec(node.right), []];
            if (op === ts.SyntaxKind.BarBarToken || op === ts.SyntaxKind.QuestionQuestionToken) return [...rec(node.left), ...rec(node.right)].slice(0, MAX_VARIANTS);
            if (op === ts.SyntaxKind.PlusToken) return product([rec(node.left), rec(node.right)]);
            return UNKNOWN;
        }
        if (ts.isIdentifier(node)) {
            const r = this.resolve(node);
            if (!r?.init) return UNKNOWN;
            consumed.add(r.init);
            return r.owner.alts(r.init, consumed, depth + 1);
        }
        if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
            const objAlts = this.objectOf(node.expression, consumed);
            if (!objAlts) return UNKNOWN;
            const { owner, obj } = objAlts;
            const key = ts.isPropertyAccessExpression(node) ? node.name.text
                : (isLiteral(node.argumentExpression) ? node.argumentExpression.text : null);
            const out = [];
            for (const p of obj.properties) {
                if (!ts.isPropertyAssignment(p)) continue;
                const pname = p.name && (ts.isIdentifier(p.name) || isLiteral(p.name)) ? p.name.text : null;
                if (key != null && pname !== key) continue;
                const bind = key == null && pname != null ? [{ s: '', bind: [node.argumentExpression.getText(), pname] }] : [];
                for (const alt of owner.alts(p.initializer, consumed, depth + 1)) out.push(bind.concat(alt));
            }
            return out.length ? out.slice(0, MAX_VARIANTS) : UNKNOWN;
        }
        if (ts.isCallExpression(node)) {
            const callee = node.expression;
            // [...].join(' ')
            if (ts.isPropertyAccessExpression(callee) && callee.name.text === 'join' && ts.isArrayLiteralExpression(callee.expression)) {
                const sep = node.arguments[0] && isLiteral(node.arguments[0]) ? node.arguments[0].text : ',';
                const lists = [];
                callee.expression.elements.forEach((e, i) => {
                    if (i) lists.push([[{ s: sep, line: 0 }]]);
                    lists.push(rec(e));
                });
                return product(lists);
            }
            // cn(...) / clsx(...) style joiners
            if (ts.isIdentifier(callee) && /^(cn|clsx|cx|classNames|classes)$/.test(callee.text)) {
                const lists = [];
                node.arguments.forEach((a, i) => {
                    if (i) lists.push([[{ s: ' ', line: 0 }]]);
                    lists.push(rec(a));
                });
                return product(lists);
            }
            // inputClass.replace(...) and similar: keep the receiver's classes.
            if (ts.isPropertyAccessExpression(callee) && /^(replace|replaceAll|trim)$/.test(callee.name.text)) return rec(callee.expression);
            // A local helper (statusClass(s), usageBarColor(p)): anything it can return.
            if (ts.isIdentifier(callee)) {
                const r = this.resolve(callee);
                if (!r?.fn) return UNKNOWN;
                const out = [];
                for (const e of returnsOf(r.fn)) {
                    consumed.add(e);
                    out.push(...r.owner.alts(e, consumed, depth + 1));
                }
                return out.length ? out.slice(0, MAX_VARIANTS) : UNKNOWN;
            }
            return UNKNOWN;
        }
        return UNKNOWN;
    }

    objectOf(expr, consumed) {
        expr = unwrap(expr);
        if (!ts.isIdentifier(expr)) return null;
        const r = this.resolve(expr);
        const init = unwrap(r?.init);
        if (!init || !ts.isObjectLiteralExpression(init)) return null;
        consumed.add(r.init);
        return { owner: r.owner, obj: init };
    }
}

/** The className expression of a JSX element, or null. */
function classAttr(opening) {
    for (const p of opening.attributes.properties) {
        if (!ts.isJsxAttribute(p) || p.name.getText() !== 'className' || !p.initializer) continue;
        if (ts.isStringLiteral(p.initializer)) return p.initializer;
        if (ts.isJsxExpression(p.initializer) && p.initializer.expression) return p.initializer.expression;
    }
    return null;
}

const SETS_TEXT = /(^|[\s'"`:])(text-[a-z]|label-caps)/;

/** Whether JSX children render text that takes its colour from the element above them. */
function hasUncolouredText(children) {
    for (const c of children) {
        if (ts.isJsxText(c)) { if (c.text.trim()) return true; continue; }
        if (ts.isJsxExpression(c)) {
            if (!c.expression) continue;
            if (!c.expression.getText().includes('<')) return true;
            // {cond && <span ...>}: look inside the JSX it renders.
            let found = false;
            const walk = n => {
                if (found) return;
                if (ts.isJsxElement(n) || ts.isJsxSelfClosingElement(n) || ts.isJsxFragment(n)) {
                    if (hasUncolouredText([n])) found = true;
                    return;
                }
                ts.forEachChild(n, walk);
            };
            walk(c.expression);
            if (found) return true;
            continue;
        }
        if (ts.isJsxFragment(c)) { if (hasUncolouredText(c.children)) return true; continue; }
        if (ts.isJsxElement(c)) {
            const expr = classAttr(c.openingElement);
            if (expr && SETS_TEXT.test(expr.getText())) continue;
            const name = c.openingElement.tagName.getText();
            if (name === 'svg') continue;
            if (hasUncolouredText(c.children)) return true;
        }
    }
    return false;
}

/** Unprefixed backgrounds an expanded class expression sets, one entry per alternative (null: none). */
function baseBackgrounds(sfile, expr) {
    const found = new Map();
    let bare = false;
    for (const pieces of sfile.alts(expr, new Set())) {
        const bgs = pieces.map(p => p.s).join('').split(/\s+/).map(parseClass)
            .filter(c => c && c.prop === 'bg' && !c.state.length && c.name !== 'transparent');
        const binds = bindsOf(pieces);
        if (!bgs.length) bare = true;
        for (const c of bgs) {
            const k = c.tok + '|' + [...binds].join(',');
            if (!found.has(k)) found.set(k, { ...c, inherited: true, line: 0, binds });
        }
    }
    if (!found.size) return null;
    return bare ? [...found.values(), null] : [...found.values()];
}

/**
 * Where a class expression is used: the intrinsic tag it is written on, whether that element has
 * no children (an icon, a dot, a switch track), and the backgrounds of its nearest JSX ancestor
 * that sets one.
 */
function jsxTarget(node, sfile) {
    const none = { tag: null, selfClosing: false, inherited: null };
    let n = node.parent, el = null;
    for (let depth = 0; n && depth < 10; depth++, n = n.parent) {
        if (ts.isJsxAttribute(n)) {
            const e = n.parent?.parent;
            if (e && (ts.isJsxOpeningElement(e) || ts.isJsxSelfClosingElement(e))) el = e;
            break;
        }
        if (ts.isJsxElement(n) || ts.isBlock(n) || ts.isSourceFile(n)) break;
    }
    if (!el) return none;
    if (!ts.isJsxOpeningElement(el) && !ts.isJsxSelfClosingElement(el)) return none;
    const tagName = ts.isIdentifier(el.tagName) ? el.tagName.text : null;
    const tag = tagName && /^[a-z]/.test(tagName) ? tagName : null;
    // An element with no text of its own (an icon, a dot, a switch track, a box around an icon)
    // needs no text colour; text in a child that sets its own colour does not count.
    const selfClosing = !!tag && !['input', 'textarea', 'select'].includes(tag)
        && !(ts.isJsxOpeningElement(el) && hasUncolouredText(el.parent.children));
    let inherited = null;
    let a = ts.isJsxOpeningElement(el) ? el.parent.parent : el.parent;
    for (let depth = 0; a && depth < 60; depth++, a = a.parent) {
        if (ts.isSourceFile(a) || ts.isFunctionDeclaration(a) || ts.isClassDeclaration(a) || ts.isVariableStatement(a)
            || ts.isMethodDeclaration(a) || (ts.isArrowFunction(a) && ts.isVariableDeclaration(a.parent))) break;
        if (!ts.isJsxElement(a)) continue;
        const expr = classAttr(a.openingElement);
        const bgs = expr && baseBackgrounds(sfile, expr);
        if (bgs) { inherited = bgs; break; }
    }
    return { tag, selfClosing, inherited };
}

const COMBINATOR = n => ts.isConditionalExpression(n) || ts.isParenthesizedExpression(n) || ts.isTemplateSpan(n)
    || ts.isTemplateExpression(n) || ts.isAsExpression(n) || ts.isNonNullExpression(n)
    || (ts.isBinaryExpression(n) && [ts.SyntaxKind.AmpersandAmpersandToken, ts.SyntaxKind.BarBarToken,
        ts.SyntaxKind.QuestionQuestionToken, ts.SyntaxKind.PlusToken].includes(n.operatorToken.kind))
    || (ts.isCallExpression(n) && ts.isIdentifier(n.expression) && /^(cn|clsx|cx|classNames|classes)$/.test(n.expression.text))
    || ts.isArrayLiteralExpression(n)
    || (ts.isPropertyAccessExpression(n) && n.name.text === 'join' && ts.isArrayLiteralExpression(n.expression))
    || (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && n.expression.name.text === 'join');

/** Climbs from a literal to the outermost expression that combines it into one class string. */
function rootOf(node) {
    let n = node;
    while (n.parent && COMBINATOR(n.parent)) {
        // The condition of a ternary is not part of the class string.
        if (ts.isConditionalExpression(n.parent) && n.parent.condition === n) break;
        n = n.parent;
    }
    if (ts.isTemplateSpan(n) || ts.isPropertyAccessExpression(n)) n = n.parent;
    return n;
}

const COLOURISH = /(^|[\s:])(bg|text|placeholder)-[a-z]|label-caps/;

/** Judges one literal class string as if written in a className attribute; returns the finding kinds. */
export function checkClasses(classes, opts = {}) {
    const theme = loadTheme();
    THEME_NAMES = new Set(Object.keys(theme.light));
    const tokens = classes.split(/\s+/).filter(Boolean).map(s => ({ s, line: 1 }));
    return judge(tokens, theme, { tag: null, selfClosing: false, inherited: null, classAttr: true, ...opts }).map(f => f.kind);
}

/** Every finding (failures and exempt pairs) across the SPA sources. */
export function lint() {
    const theme = loadTheme();
    THEME_NAMES = new Set(Object.keys(theme.light));
    const exportsByName = new Map();
    const files = DIRS.flatMap(d => existsSync(join(ROOT, d)) ? collect(join(ROOT, d)) : []);
    const sources = files.map(f => new SourceFile(f, exportsByName));

    const consumed = new Set();
    const expanded = [];
    for (const sfile of sources) {
        const roots = new Set();
        const visit = node => {
            if (isLiteral(node) || ts.isTemplateExpression(node)) roots.add(rootOf(node));
            if (ts.isJsxAttribute(node) && node.initializer && ts.isJsxExpression(node.initializer) && node.initializer.expression
                && /class/i.test(node.name.getText(sfile.sf))) {
                roots.add(node.initializer.expression);
            }
            ts.forEachChild(node, visit);
        };
        visit(sfile.sf);
        for (const root of roots) expanded.push({ sfile, root, alts: sfile.alts(root, consumed) });
    }

    const findings = [];
    for (const { sfile, root, alts } of expanded) {
        // A constant is judged inside the expressions that use it, not on its own.
        if (consumed.has(root)) continue;
        const target = jsxTarget(root, sfile);
        const attr = ts.isJsxAttribute(root.parent) ? root.parent
            : ts.isJsxExpression(root.parent) && ts.isJsxAttribute(root.parent.parent) ? root.parent.parent : null;
        target.classAttr = !!attr && /class/i.test(attr.name.getText());
        const seen = new Set();
        for (const pieces of alts) {
            const text = pieces.map(p => p.s).join('');
            if (!COLOURISH.test(text)) continue;
            // Re-tokenise across pieces so a class glued across a ${} boundary is whole.
            const tokens = [];
            let cur = null;
            for (const p of pieces) {
                for (const part of p.s.split(/(\s+)/)) {
                    if (!part) continue;
                    if (/^\s+$/.test(part)) { cur = null; continue; }
                    if (cur) cur.s += part;
                    else { cur = { s: part, line: p.line || sfile.line(root) }; tokens.push(cur); }
                }
            }
            for (const f of judge(tokens, theme, { ...target, binds: bindsOf(pieces) })) {
                const key = [f.kind, f.line, f.state.join(':'), f.text?.tok, f.bg?.tok].join('|');
                if (seen.has(key)) continue;
                seen.add(key);
                findings.push({
                    file: sfile.rel,
                    line: f.line || sfile.line(root),
                    kind: f.kind,
                    classes: tokens.map(t => t.s).join(' '),
                    state: f.state.join(':') || 'base',
                    text: f.text?.tok ?? null,
                    bg: f.bg ? (f.bg.inherited ? `(ancestor ${f.bg.tok})` : f.bg.tok) : `(${f.surface})`,
                    light: f.light ?? null,
                    dark: f.dark ?? null,
                    need: f.need ?? null,
                });
            }
        }
    }
    // The same pair reached through two roots (a constant and its user) is one finding.
    const uniq = new Map();
    for (const f of findings) uniq.set([f.file, f.line, f.kind, f.state, f.text, f.bg, f.classes].join('|'), f);
    return [...uniq.values()].sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
}

export function loadAllowlist() {
    if (!existsSync(ALLOWLIST)) return [];
    return JSON.parse(readFileSync(ALLOWLIST, 'utf8'));
}

export function failures(findings = lint(), allow = loadAllowlist()) {
    const used = new Set();
    const fails = findings.filter(f => {
        if (f.kind === 'exempt') return false;
        const i = allow.findIndex(a => a.file === f.file && f.classes.includes(a.match));
        if (i >= 0) { used.add(i); return false; }
        return true;
    });
    const stale = allow.filter((_, i) => !used.has(i));
    return { fails, stale };
}

const fmt = f => `${f.file}:${f.line}  [${f.kind}${f.state !== 'base' ? ' ' + f.state : ''}]  ${f.text ?? '(no text)'} on ${f.bg}`
    + (f.light != null ? `  light ${f.light.toFixed(2)} dark ${f.dark.toFixed(2)} (need ${f.need})` : '')
    + `\n      "${f.classes}"`;

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    const all = lint();
    const { fails, stale } = failures(all);
    const exempt = all.filter(f => f.kind === 'exempt');
    if (JSON_OUT) {
        console.log(JSON.stringify({ fails, stale, exempt }, null, 2));
    } else {
        for (const f of fails) console.log(fmt(f));
        if (SHOW_EXEMPT) {
            console.log('\nExempt (faint, placeholder or disabled text), reported only:');
            for (const f of exempt) console.log(fmt(f));
        }
        const byKind = {};
        for (const f of fails) byKind[f.kind] = (byKind[f.kind] ?? 0) + 1;
        console.log(`\nledger-contrast: ${fails.length} failure(s) ${JSON.stringify(byKind)}, ${exempt.length} exempt, ${stale.length} stale allowlist entr${stale.length === 1 ? 'y' : 'ies'}.`);
        for (const s of stale) console.log(`  stale allowlist entry: ${s.file} "${s.match}"`);
    }
    if (CHECK && (fails.length || stale.length)) process.exit(1);
}
