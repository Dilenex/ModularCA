import { defineConfig } from 'vite';
import plugin from '@vitejs/plugin-react';
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

// https://vitejs.dev/config/
// Shared code lives above this project root (see ../shared/README.md). The bundler needs
// the alias; the dev server additionally needs fs.allow, because Vite refuses to serve
// files outside the project root unless told to.
const sharedCommon = resolve(process.cwd(), '..', 'shared', 'common', 'src');
// Auth-aware code. Aliased ONLY in adminui and userui — setupui runs before
// authentication exists and docsui/publicui are anonymous, so for them the specifier
// simply does not resolve. The boundary is enforced by wiring, not by convention.
const sharedAuth = resolve(process.cwd(), '..', 'shared', 'authenticated', 'src');

export default defineConfig({
    plugins: [plugin()],
    resolve: {
        alias: {
            '@shared': sharedCommon,
        '@shared-auth': sharedAuth,
            // shared/common sits outside this package, so resolution from a file inside it walks up
            // to the repo root and finds no node_modules. Point React and the router at THIS app's
            // copies. That also guarantees a single React instance in the bundle - two copies break
            // hooks in ways that are painful to diagnose.
            react: resolve(process.cwd(), 'node_modules', 'react'),
            'react-dom': resolve(process.cwd(), 'node_modules', 'react-dom'),
            'react-router-dom': resolve(process.cwd(), 'node_modules', 'react-router-dom'),
            // Same reason as React above: shared/common/src/utils/qrcode.ts imports this,
            // and resolution from a file there finds no node_modules on the way up.
            'qrcode-generator': resolve(process.cwd(), 'node_modules', 'qrcode-generator'),
        },
    },
    base: '/user/',
    define: versionDefine(),
    build: {
        sourcemap: false,
    },
    server: {
        // Vite refuses to serve files above the project root unless told to; shared/common
        // sits one level up.
        fs: { allow: ['..'] },
        port: 53013,
    }
})
