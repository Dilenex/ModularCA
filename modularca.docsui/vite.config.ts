import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { execSync } from 'node:child_process';

// Version provenance — single source of truth is the repo-root VERSION file (also read by the .NET
// Directory.Build.props). Injected as compile-time constants; typed in src/vite-env.d.ts. Bump ./VERSION only.
function versionDefine(): Record<string, string> {
  const root = resolve(process.cwd(), '..');
  const version = readFileSync(resolve(root, 'VERSION'), 'utf-8').trim();
  let commit = 'unknown';
  try {
    commit = execSync('git rev-parse --short HEAD', { cwd: root, stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim();
  } catch { /* not a git checkout — provenance commit stays "unknown" */ }
  return {
    __APP_VERSION__: JSON.stringify(version),
    __APP_COMMIT__: JSON.stringify(commit),
    __APP_BUILD_TIME__: JSON.stringify(new Date().toISOString()),
  };
}

// Shared code lives above this project root (see ../shared/README.md). The bundler needs
// the alias; the dev server additionally needs fs.allow, because Vite refuses to serve
// files outside the project root unless told to.
const sharedCommon = resolve(process.cwd(), '..', 'shared', 'common', 'src');

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
        '@shared': sharedCommon,
        // shared/common sits outside this package, so resolution from a file inside it walks up
        // to the repo root and finds no node_modules. Point React and the router at THIS app's
        // copies. That also guarantees a single React instance in the bundle - two copies break
        // hooks in ways that are painful to diagnose.
        react: resolve(process.cwd(), 'node_modules', 'react'),
        'react-dom': resolve(process.cwd(), 'node_modules', 'react-dom'),
        'react-router-dom': resolve(process.cwd(), 'node_modules', 'react-router-dom'),
    },
  },
  base: '/docs/',
  define: versionDefine(),
  build: {
    // Sourcemaps are built when MODULARCA_SOURCEMAP=1, which the csproj sets for the Staging
    // configuration only. Release stays lean.
    //
    // Worth having: a minified stack like `te.map is not a function` at `index-DbKwh5kT.js:14`
    // cost hours of reverse-engineering bundles by hand to reach a one-line bug. With a sourcemap
    // it is a filename and a line number. The usual argument against shipping them — exposing
    // source — does not apply here: this project is AGPL-3.0 and the source is published. Size is
    // the only real cost, which is why it is off for Release rather than off entirely.
    sourcemap: process.env.MODULARCA_SOURCEMAP === '1',
  },
  server: {
    fs: { allow: ['..'] },
    host: '0.0.0.0',
    port: 3004
  }
});
