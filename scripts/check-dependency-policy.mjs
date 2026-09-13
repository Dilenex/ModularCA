#!/usr/bin/env node
/**
 * Enforces on the npm graph the dependency policy the NuGet graph has always had.
 *
 * `Directory.Build.props` audits every resolved NuGet package at every severity and promotes HIGH
 * and CRITICAL to build errors, which is why the C# graph carries zero advisories. The five SPAs
 * had no equivalent check of any kind — that asymmetry is the entire reason GitHub reported 110
 * npm advisories on the default branch and none from .NET.
 *
 * Two rules, each of which exists because of something that actually happened here:
 *
 *   SOAK   No resolved version may be younger than MIN_AGE_DAYS. npm supply-chain compromises are
 *          typically published, spotted and pulled within hours to days, so declining to adopt
 *          anything inside that window turns most of that attack class into a non-event. The rule
 *          exists because a vite security release three days old was nearly committed here on the
 *          reasoning that it fixed an advisory — which is precisely the reasoning an attacker
 *          publishing a malicious patch release is counting on.
 *
 *   AUDIT  No advisory may affect a PRODUCTION dependency. Dev-only advisories are printed and do
 *          not fail the build, deliberately: the ones present need attacker-controlled build
 *          configuration, and a gate left permanently red over unreachable findings teaches
 *          everyone to ignore it, which costs more than it saves.
 *
 * A package announced as compromised reaches us through the same advisory feed `npm audit` reads
 * — malicious-code advisories are published there as critical — so AUDIT covers that for anything
 * that ships, and the dev-only report keeps the rest visible.
 *
 * Publish dates come from the registry over HTTPS rather than from `npm view`: Node refuses to
 * execFile `npm.cmd` without a shell on Windows (EINVAL), which silently turned every lookup in
 * the first version of this script into "unverified" while it reported success.
 *
 *   node scripts/check-dependency-policy.mjs
 *   node scripts/check-dependency-policy.mjs --days 14
 *   node scripts/check-dependency-policy.mjs --allow vite@8.3.0
 */
import { execSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const PROJECTS = [
    'modularca.adminui',
    'modularca.userui',
    'modularca.publicui',
    'modularca.setupui',
    'modularca.docsui',
    'tests/modularca.web.tests',
];

const arg = (flag, fallback) => {
    const i = process.argv.indexOf(flag);
    return i > -1 ? process.argv[i + 1] : fallback;
};

const MIN_AGE_DAYS = Number(arg('--days', 7));

/**
 * Versions exempted from the soak rule, as `name@version`.
 *
 * Each entry is a decision someone made once and should be able to explain later, so each carries
 * its reason. An exemption is not a general "trust this package" — it names one exact version, so
 * the next release of the same package faces the rule again.
 */
const SOAK_EXEMPTIONS = new Map([
    ['vite@8.3.0',
     'Security release fixing a server.fs.deny bypass and an NTLM disclosure, both Windows '
     + 'dev-server only. Adopted at 3 days by explicit decision: vite is among the most-downloaded '
     + 'packages in the ecosystem and a security release of it is heavily scrutinised, so the '
     + 'window in which a compromise would go unnoticed is unusually short. One-time exception.'],
]);

for (const extra of process.argv.filter((a, i) => process.argv[i - 1] === '--allow')) {
    SOAK_EXEMPTIONS.set(extra, 'Allowed on the command line for this run only.');
}

/* ── publish dates ────────────────────────────────────────────────────────── */

const dateCache = new Map();

async function publishDate(name, version) {
    if (!dateCache.has(name)) {
        dateCache.set(name, (async () => {
            const url = `https://registry.npmjs.org/${name.replace('/', '%2F')}`;
            const res = await fetch(url, { headers: { accept: 'application/json' } });
            if (!res.ok) throw new Error(`registry returned ${res.status}`);
            return (await res.json()).time ?? {};
        })());
    }
    const times = await dateCache.get(name);
    return times[version] ?? null;
}

/** Every (name, version) the lockfile resolves. Excludes the project root and workspace links. */
function resolvedVersions(project) {
    const lockPath = join(ROOT, project, 'package-lock.json');
    if (!existsSync(lockPath)) return [];
    const lock = JSON.parse(readFileSync(lockPath, 'utf8'));
    const out = [];
    for (const [path, entry] of Object.entries(lock.packages ?? {})) {
        if (!path || !entry.version || entry.link) continue;
        const name = entry.name ?? path.split('node_modules/').pop();
        if (name) out.push({ name, version: entry.version });
    }
    return out;
}

/** Runs tasks with bounded concurrency; the registry does not need 700 sockets. */
async function pooled(items, limit, fn) {
    const results = [];
    let cursor = 0;
    await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
        while (cursor < items.length) {
            const i = cursor++;
            results[i] = await fn(items[i]);
        }
    }));
    return results;
}

/* ── advisories ───────────────────────────────────────────────────────────── */

/**
 * Advisories affecting production dependencies only.
 *
 * `--omit=dev` is what makes this precise rather than a judgement call in this script: npm
 * resolves the production subgraph itself and reports only what survives it. Everything omitted
 * is build tooling that cannot reach a browser.
 */
function audit(project, omitDev) {
    const cmd = `npm audit --json${omitDev ? ' --omit=dev' : ''}`;
    let raw;
    try {
        raw = execSync(cmd, { cwd: join(ROOT, project), encoding: 'utf8', maxBuffer: 64 << 20, stdio: ['ignore', 'pipe', 'ignore'] });
    } catch (err) {
        // npm audit exits non-zero whenever it finds anything, and still writes the report out.
        raw = err.stdout ?? '';
    }
    try { return JSON.parse(raw); } catch { return null; }
}

/* ── run ──────────────────────────────────────────────────────────────────── */

const unique = new Map();
for (const project of PROJECTS) {
    for (const { name, version } of resolvedVersions(project)) {
        const key = `${name}@${version}`;
        if (!unique.has(key)) unique.set(key, { name, version, project });
    }
}

console.log(`Dependency policy — minimum age ${MIN_AGE_DAYS} days, no advisories in production deps`);
console.log(`Checking ${unique.size} resolved package versions across ${PROJECTS.length} projects\n`);

const now = Date.now();
const tooYoung = [];
const unverified = [];
const exempted = [];

await pooled([...unique.values()], 12, async ({ name, version, project }) => {
    const key = `${name}@${version}`;
    let stamp;
    try {
        stamp = await publishDate(name, version);
    } catch (err) {
        unverified.push({ key, project, why: err.message });
        return;
    }
    if (!stamp) { unverified.push({ key, project, why: 'no publish date for this version' }); return; }

    const ageDays = (now - Date.parse(stamp)) / 86_400_000;
    if (ageDays >= MIN_AGE_DAYS) return;

    if (SOAK_EXEMPTIONS.has(key)) {
        exempted.push({ key, ageDays: ageDays.toFixed(1), published: stamp.slice(0, 10) });
        return;
    }
    tooYoung.push({ key, project, ageDays: ageDays.toFixed(1), published: stamp.slice(0, 10) });
});

let failed = false;

if (tooYoung.length) {
    failed = true;
    console.log(`SOAK FAILURE — ${tooYoung.length} version(s) younger than ${MIN_AGE_DAYS} days:`);
    for (const t of tooYoung.sort((a, b) => a.ageDays - b.ageDays)) {
        console.log(`  ${t.key.padEnd(48)} published ${t.published} (${t.ageDays}d)  [${t.project}]`);
    }
    console.log('\n  A version this new has not been exposed long enough for a compromised release to');
    console.log('  have been noticed and pulled. Wait, pin the previous version, or add a reasoned');
    console.log('  entry to SOAK_EXEMPTIONS naming the exact version.\n');
} else {
    console.log(`SOAK OK — every resolved version is at least ${MIN_AGE_DAYS} days old`);
}

for (const e of exempted) {
    console.log(`  exempted: ${e.key} (${e.ageDays}d, published ${e.published}) — ${SOAK_EXEMPTIONS.get(e.key).split('.')[0]}.`);
}

if (unverified.length) {
    failed = true;
    console.log(`\nUNVERIFIED — ${unverified.length} version(s) could not be dated:`);
    for (const u of unverified.slice(0, 20)) console.log(`  ${u.key.padEnd(48)} ${u.why}`);
    console.log('\n  Unverified is not the same as fine — re-run when the registry is reachable.\n');
}

const prodFindings = [];
const devCounts = [];
for (const project of PROJECTS) {
    if (!existsSync(join(ROOT, project, 'package.json'))) continue;

    const prod = audit(project, true);
    if (prod === null) {
        failed = true;
        console.log(`\nAUDIT FAILURE — could not audit ${project}`);
        continue;
    }
    for (const [name, v] of Object.entries(prod.vulnerabilities ?? {})) {
        prodFindings.push({
            project, name, severity: v.severity,
            via: (v.via ?? []).map((x) => (typeof x === 'object' ? x.title : x)).filter(Boolean),
        });
    }

    const all = audit(project, false);
    const counts = all?.metadata?.vulnerabilities;
    if (counts?.total) devCounts.push({ project, counts });
}

if (prodFindings.length) {
    failed = true;
    console.log(`\nAUDIT FAILURE — ${prodFindings.length} advisory/advisories in PRODUCTION dependencies:`);
    for (const f of prodFindings) {
        console.log(`  ${f.name.padEnd(32)} ${String(f.severity).padEnd(9)} [${f.project}]`);
        for (const t of f.via.slice(0, 3)) console.log(`      - ${t}`);
    }
    console.log('\n  These reach a browser. Fix or replace them.\n');
} else {
    console.log('\nAUDIT OK — no advisories in any production dependency');
}

if (devCounts.length) {
    console.log('\nDev-only advisories (informational — build tooling, not shipped):');
    for (const d of devCounts) {
        const c = d.counts;
        console.log(`  ${d.project.padEnd(28)} total ${c.total}  critical ${c.critical}  high ${c.high}  moderate ${c.moderate}  low ${c.low}`);
    }
}

process.exit(failed ? 1 : 0);
