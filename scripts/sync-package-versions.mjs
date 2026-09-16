#!/usr/bin/env node
/*
 * Syncs every UI package.json "version" field to the canonical repo-root VERSION file, so npm
 * metadata can't drift from the version baked into the .NET assemblies (Directory.Build.props) and the
 * UI bundles (vite `define`). The repo-root VERSION file is the SINGLE source of truth.
 *
 * Idempotent: only rewrites a package.json when its version differs, and edits just the version
 * string in place (regex) so existing formatting/indentation is preserved — no noisy full reformat.
 *
 * Runs automatically as the first step of the API's BuildWebUIs MSBuild target. Can also be run by
 * hand after bumping VERSION:  node scripts/sync-package-versions.mjs
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const version = readFileSync(resolve(root, 'VERSION'), 'utf-8').trim();

const uis = [
    'modularca.adminui',
    'modularca.publicui',
    'modularca.setupui',
    'modularca.docsui',
];

let changed = 0;
for (const ui of uis) {
    const pkgPath = resolve(root, ui, 'package.json');
    let raw;
    try {
        raw = readFileSync(pkgPath, 'utf-8');
    } catch {
        console.warn(`[sync-version] skip ${ui} (no readable package.json)`);
        continue;
    }
    // Replace only the FIRST "version": "..." (the top-level package version; dependency entries use
    // "<name>": "<range>", not a "version" key), preserving surrounding formatting.
    const updated = raw.replace(/("version"\s*:\s*)"[^"]*"/, `$1"${version}"`);
    if (updated === raw) continue;
    writeFileSync(pkgPath, updated);
    console.log(`[sync-version] ${ui}: version -> ${version}`);
    changed++;
}

console.log(`[sync-version] done (${changed} updated, canonical version = ${version})`);
