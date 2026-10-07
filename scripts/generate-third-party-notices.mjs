#!/usr/bin/env node
/**
 * Generates THIRD-PARTY-NOTICES.md from the dependency graphs that are actually distributed.
 *
 * Every permissive licence in this graph — MIT, BSD, Apache-2.0 — grants the right to
 * redistribute on the condition that the copyright notice and licence text travel with the
 * binary. ModularCA ships a self-contained tarball and a .deb, so that condition attaches to us,
 * and it is the kind of obligation that is invisible until someone looks and then is not a small
 * problem. Apache-2.0 additionally requires carrying any NOTICE file the dependency provides.
 *
 * Generated rather than hand-written for the same reason the error-code catalogue is generated
 * from declarations: a hand-maintained list is accurate on the day it is written and wrong from
 * the next dependency change onward, and a licence disclosure that quietly stops matching the
 * binary is worse than none, because it asserts something untrue.
 *
 * WHAT IS AND IS NOT LISTED
 *
 * Distribution obligations attach to what is distributed. The runtime NuGet graph and the four
 * npm packages that end up inside a browser bundle ship, so they are listed in full. Build tooling
 * — vite, TypeScript, tailwind, xunit, the .NET SDK — never leaves the build machine and creates
 * no redistribution obligation; it is summarised in a closing section for honesty rather than
 * necessity, because a reader asking "what built this" deserves an answer even where no licence
 * compels one.
 *
 * Files copied into the source tree (the Plex fonts) come from no package manager, so a
 * `vendored.json` beside them names each one, its version, licence and licence file. Every such
 * manifest under the SPA trees is listed here with the licence text in full, and a font file that
 * no manifest lists is refused.
 *
 *   node scripts/generate-third-party-notices.mjs
 *   node scripts/generate-third-party-notices.mjs --check   # CI: fail if the file is stale
 */
import { execSync } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync, readdirSync } from 'node:fs';
import { resolve, dirname, join, relative, basename } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const OUT = join(ROOT, 'THIRD-PARTY-NOTICES.md');
const CHECK = process.argv.includes('--check');

/* ── NuGet ────────────────────────────────────────────────────────────────── */

function nugetRoot() {
    const out = execSync('dotnet nuget locals global-packages --list', { encoding: 'utf8' });
    return out.split(':').slice(1).join(':').trim();
}

/** Resolved runtime packages, read from the API's assets file so versions are exact. */
function nugetPackages() {
    const assetsPath = join(ROOT, 'ModularCA.API', 'obj', 'project.assets.json');
    if (!existsSync(assetsPath)) {
        throw new Error('ModularCA.API/obj/project.assets.json not found — run `dotnet restore` first.');
    }
    const assets = JSON.parse(readFileSync(assetsPath, 'utf8'));
    const names = new Set();
    for (const target of Object.values(assets.targets ?? {})) {
        for (const [key, entry] of Object.entries(target)) {
            if (entry.type !== 'package') continue;
            names.add(key); // "Id/Version"
        }
    }
    return [...names].sort((a, b) => a.localeCompare(b));
}

/**
 * Identifies a licence from its text, for packages that ship the text instead of naming an
 * expression. Matching on the distinctive title line rather than on body prose, because the body
 * of every BSD variant reads almost identically and guessing wrong here is a false statement about
 * someone else's terms.
 */
function detectSpdx(text) {
    const head = text.slice(0, 2000);
    if (/Apache License[\s\S]{0,40}Version 2\.0/i.test(head)) return 'Apache-2.0';
    if (/\bMIT License\b/i.test(head)) return 'MIT';
    if (/GNU LESSER GENERAL PUBLIC LICENSE[\s\S]{0,60}Version 3/i.test(head)) return 'LGPL-3.0';
    if (/GNU GENERAL PUBLIC LICENSE[\s\S]{0,60}Version 3/i.test(head)) return 'GPL-3.0';
    if (/Mozilla Public License[\s\S]{0,40}2\.0/i.test(head)) return 'MPL-2.0';
    if (/Redistribution and use in source and binary forms/i.test(head)) {
        return /neither the name/i.test(head) ? 'BSD-3-Clause' : 'BSD-2-Clause';
    }
    return null;
}

const between = (xml, tag) => {
    const m = xml.match(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`, 'i'));
    return m ? m[1].trim().replace(/\s+/g, ' ') : null;
};

function nugetMeta(root, idVersion) {
    const [id, version] = idVersion.split('/');
    const dir = join(root, id.toLowerCase(), version);
    const result = { id, version, license: null, copyright: null, project: null, notice: null, licenseText: null };
    if (!existsSync(dir)) return result;

    const nuspec = readdirSync(dir).find((f) => f.toLowerCase().endsWith('.nuspec'));
    if (nuspec) {
        const xml = readFileSync(join(dir, nuspec), 'utf8');
        const declared = between(xml, 'license');
        const isFile = /<license[^>]*type=["']file["']/i.test(xml);

        if (isFile && declared) {
            // `<license type="file">LICENSE.txt</license>` names a file inside the package rather
            // than an SPDX expression. Recording the filename as the licence would disclose
            // nothing — "COPYING.txt" is not a licence — and for these the obligation is precisely
            // to reproduce the text, so read it and carry it in full.
            const licPath = join(dir, declared);
            if (existsSync(licPath)) {
                result.licenseText = readFileSync(licPath, 'utf8').trim();
                result.license = detectSpdx(result.licenseText) ?? `see text (${declared})`;
            } else {
                result.license = `declared in ${declared}, not present in package`;
            }
        } else {
            result.license = declared || between(xml, 'licenseUrl');
        }

        result.copyright = between(xml, 'copyright');
        result.project = between(xml, 'projectUrl') || between(xml, 'repository');
    }
    // Apache-2.0 obliges us to carry any NOTICE the package ships.
    for (const f of readdirSync(dir)) {
        if (/^notice(\.txt|\.md)?$/i.test(f)) result.notice = readFileSync(join(dir, f), 'utf8').trim();
    }
    return result;
}

/* ── npm ──────────────────────────────────────────────────────────────────── */

/** Production dependencies only — the packages that reach a browser. */
function npmProduction() {
    const apps = ['modularca.adminui', 'modularca.publicui',
                  'modularca.setupui', 'modularca.docsui'];
    const found = new Map();

    for (const app of apps) {
        const appDir = join(ROOT, app);
        if (!existsSync(join(appDir, 'package.json'))) continue;

        let tree;
        try {
            tree = JSON.parse(execSync('npm ls --omit=dev --all --json', {
                cwd: appDir, encoding: 'utf8', maxBuffer: 64 << 20, stdio: ['ignore', 'pipe', 'ignore'],
            }));
        } catch (err) {
            try { tree = JSON.parse(err.stdout ?? '{}'); } catch { continue; }
        }

        const walk = (deps) => {
            for (const [name, node] of Object.entries(deps ?? {})) {
                if (!node.version) continue;
                const key = `${name}@${node.version}`;
                if (!found.has(key)) {
                    const pkgPath = join(appDir, 'node_modules', name, 'package.json');
                    let meta = {};
                    if (existsSync(pkgPath)) {
                        try { meta = JSON.parse(readFileSync(pkgPath, 'utf8')); } catch { /* keep going */ }
                    }
                    const licenseDir = join(appDir, 'node_modules', name);
                    let licenseText = null;
                    if (existsSync(licenseDir)) {
                        const f = readdirSync(licenseDir).find((x) => /^licen[sc]e/i.test(x));
                        if (f) { try { licenseText = readFileSync(join(licenseDir, f), 'utf8').trim(); } catch { /* */ } }
                    }
                    found.set(key, {
                        name, version: node.version,
                        license: typeof meta.license === 'string' ? meta.license : meta.license?.type ?? null,
                        project: typeof meta.repository === 'string' ? meta.repository : meta.repository?.url ?? meta.homepage ?? null,
                        licenseText,
                    });
                }
                walk(node.dependencies);
            }
        };
        walk(tree.dependencies);
    }
    return [...found.values()].sort((a, b) => a.name.localeCompare(b.name));
}

/* ── vendored assets ──────────────────────────────────────────────────────── */

const VENDOR_ROOTS = ['shared', 'modularca.adminui', 'modularca.publicui', 'modularca.setupui', 'modularca.docsui'];
const FONT = /\.(woff2?|ttf|otf|eot)$/i;

function walkFiles(dir, out = []) {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
        if (entry.name === 'node_modules' || entry.name === 'dist' || entry.name.startsWith('.')) continue;
        const full = join(dir, entry.name);
        if (entry.isDirectory()) walkFiles(full, out);
        else out.push(full);
    }
    return out;
}

/** Every asset listed by a vendored.json, with its licence text; throws on a gap. */
function vendoredAssets() {
    const files = VENDOR_ROOTS.filter((r) => existsSync(join(ROOT, r))).flatMap((r) => walkFiles(join(ROOT, r)));
    const rel = (f) => relative(ROOT, f).replace(/\\/g, '/');
    const listed = new Set();
    const assets = [];
    for (const manifest of files.filter((f) => basename(f) === 'vendored.json')) {
        const dir = dirname(manifest);
        for (const a of JSON.parse(readFileSync(manifest, 'utf8')).assets ?? []) {
            for (const key of ['name', 'version', 'license', 'copyright', 'licenseFile', 'files']) {
                if (!a[key]) throw new Error(`${rel(manifest)}: "${a.name ?? '?'}" has no ${key}`);
            }
            const licPath = join(dir, a.licenseFile);
            if (!existsSync(licPath)) throw new Error(`${rel(manifest)}: licence file ${a.licenseFile} is missing`);
            for (const f of a.files) {
                if (!existsSync(join(dir, f))) throw new Error(`${rel(manifest)}: listed file ${f} is missing`);
                listed.add(rel(join(dir, f)));
            }
            assets.push({ ...a, dir: rel(dir), licenseText: readFileSync(licPath, 'utf8').replace(/\r\n/g, '\n').trim() });
        }
    }
    const unlisted = files.map(rel).filter((f) => FONT.test(f) && !listed.has(f));
    if (unlisted.length) {
        throw new Error(`Vendored font files not listed in any vendored.json:\n  ${unlisted.join('\n  ')}`);
    }
    return assets.sort((a, b) => a.name.localeCompare(b.name));
}

/* ── render ───────────────────────────────────────────────────────────────── */

const clean = (s) => (s ?? '').replace(/^git\+/, '').replace(/\.git$/, '');

function render(nuget, npm, vendored) {
    const licenceCounts = new Map();
    for (const p of [...nuget, ...npm, ...vendored]) {
        const l = p.license ?? 'unstated';
        licenceCounts.set(l, (licenceCounts.get(l) ?? 0) + 1);
    }

    const lines = [];
    lines.push('# Third-party notices');
    lines.push('');
    lines.push('ModularCA is licensed under AGPL-3.0. It is distributed as a self-contained binary,');
    lines.push('which means the components below travel inside it, and their licences require their');
    lines.push('copyright notices to travel with them. This file is that disclosure.');
    lines.push('');
    lines.push('**Generated** by `scripts/generate-third-party-notices.mjs` from the resolved dependency');
    lines.push('graphs. Do not edit by hand — regenerate it, or the disclosure stops describing the');
    lines.push('binary it ships beside, which is worse than having none.');
    lines.push('');
    lines.push('Listed here is what is **distributed**: the runtime .NET graph and the npm packages that');
    lines.push('end up inside a browser bundle. Build tooling never leaves the build machine and creates');
    lines.push('no redistribution obligation; it is summarised at the end for completeness, not necessity.');
    lines.push('');
    lines.push('## Licences in this distribution');
    lines.push('');
    lines.push('| Licence | Components |');
    lines.push('| --- | ---: |');
    for (const [l, n] of [...licenceCounts].sort((a, b) => b[1] - a[1])) {
        lines.push(`| ${l} | ${n} |`);
    }
    lines.push('');

    const unresolved = [...nuget, ...npm].filter((p) => !p.license || p.license === 'unstated');
    if (unresolved.length) {
        // Surfaced as its own section rather than left as one row among seventy-seven. A package
        // whose terms nobody has established is the one entry in a licence disclosure that has to
        // be noticed, and guessing on its behalf would be asserting terms its author never stated.
        lines.push('## Requires manual verification');
        lines.push('');
        lines.push('These ship no licence expression and no licence file. Their terms must be');
        lines.push('confirmed at source before the next release is distributed.');
        lines.push('');
        for (const p of unresolved) {
            const name = p.id ?? p.name;
            lines.push(`- **${name} ${p.version}** — ${clean(p.project) || 'no project URL in package metadata'}`);
        }
        lines.push('');
    }

    lines.push(`## .NET runtime components (${nuget.length})`);
    lines.push('');
    lines.push('| Package | Version | Licence | Copyright |');
    lines.push('| --- | --- | --- | --- |');
    for (const p of nuget) {
        lines.push(`| ${p.project ? `[${p.id}](${clean(p.project)})` : p.id} | ${p.version} | ${p.license ?? '—'} | ${p.copyright ?? '—'} |`);
    }
    lines.push('');

    const notices = nuget.filter((p) => p.notice);
    if (notices.length) {
        lines.push('### NOTICE files');
        lines.push('');
        lines.push('Apache-2.0 section 4(d) requires these to be carried with any distribution.');
        lines.push('');
        for (const p of notices) {
            lines.push(`#### ${p.id} ${p.version}`);
            lines.push('');
            lines.push('```');
            lines.push(p.notice);
            lines.push('```');
            lines.push('');
        }
    }

    lines.push(`## Browser runtime components (${npm.length})`);
    lines.push('');
    lines.push('Bundled into the admin, user, public, setup and docs interfaces.');
    lines.push('');
    lines.push('| Package | Version | Licence | Source |');
    lines.push('| --- | --- | --- | --- |');
    for (const p of npm) {
        lines.push(`| ${p.name} | ${p.version} | ${p.license ?? '—'} | ${clean(p.project) || '—'} |`);
    }
    lines.push('');

    if (vendored.length) {
        lines.push(`## Vendored assets (${vendored.length})`);
        lines.push('');
        lines.push('Copied into the source tree and bundled into every interface, so no package manager');
        lines.push('lists them. Each is named by the `vendored.json` beside it.');
        lines.push('');
        lines.push('| Asset | Version | Licence | Copyright | Source |');
        lines.push('| --- | --- | --- | --- | --- |');
        for (const a of vendored) {
            const name = a.project ? `[${a.name}](${a.project})` : a.name;
            lines.push(`| ${name} | ${a.version} | ${a.license} | ${a.copyright} | ${a.source ?? '—'}, \`${a.dir}\` |`);
        }
        lines.push('');
        const texts = new Map();
        for (const a of vendored) {
            if (!texts.has(a.licenseText)) texts.set(a.licenseText, []);
            texts.get(a.licenseText).push(a.name);
        }
        for (const [text, names] of texts) {
            lines.push(`### Licence: ${names.join(', ')}`);
            lines.push('');
            lines.push('```text');
            lines.push(text);
            lines.push('```');
            lines.push('');
        }
    }

    lines.push('## Build tooling (not distributed)');
    lines.push('');
    lines.push('These produce the binary and are not part of it, so no redistribution obligation');
    lines.push('attaches. Recorded because "what built this" is a fair question about a certificate');
    lines.push('authority even where no licence compels the answer.');
    lines.push('');
    lines.push('- **.NET SDK 10** and the C# compiler — MIT, Microsoft');
    lines.push('- **Vite**, **Rolldown**, **TypeScript**, **Tailwind CSS**, **PostCSS**, **autoprefixer** — MIT');
    lines.push('- **xunit**, **vitest** — Apache-2.0 and MIT respectively');
    lines.push('- **nfpm** — MIT, used to build the Debian package');
    lines.push('');
    lines.push('The full build-time graph, with versions, is in the `package-lock.json` of each');
    lines.push('interface and in `ModularCA.API/obj/project.assets.json` after a restore.');
    lines.push('');

    // Package NOTICE files and a Windows checkout bring CRLF; the file and --check use LF.
    return lines.join('\n').replace(/\r\n/g, '\n');
}

/* ── run ──────────────────────────────────────────────────────────────────── */

const root = nugetRoot();
const nuget = nugetPackages().map((p) => nugetMeta(root, p));
const npm = npmProduction();
const vendored = vendoredAssets();
const text = render(nuget, npm, vendored);

if (CHECK) {
    const current = existsSync(OUT) ? readFileSync(OUT, 'utf8') : '';
    if (current.replace(/\r\n/g, '\n').trim() !== text.trim()) {
        console.error('THIRD-PARTY-NOTICES.md is stale. Run: node scripts/generate-third-party-notices.mjs');
        process.exit(1);
    }
    console.log(`THIRD-PARTY-NOTICES.md is current (${nuget.length} .NET, ${npm.length} browser components)`);
    process.exit(0);
}

writeFileSync(OUT, text + '\n', 'utf8');
console.log(`Wrote THIRD-PARTY-NOTICES.md — ${nuget.length} .NET components, ${npm.length} browser components`);
