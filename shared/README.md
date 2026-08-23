# shared/ — code shared across the ModularCA front ends

Five independent Vite SPAs (`modularca.adminui`, `docsui`, `publicui`, `setupui`, `userui`) live in
this repo. Anything they all need used to be copy-pasted between them, and the copies drifted —
which is not a tidiness problem but a correctness one. Two of the worst findings in the August 2026
review were exactly this shape: `userui/api/client.ts` never received the single-flight refresh
guard or DPoP binding that `adminui` has, and `userui/StepUpMfaModal.tsx` stayed TOTP-only, locking
security-key users out of every step-up action.

## Layout

| Module | Alias | Consumed by | Contents |
|---|---|---|---|
| `shared/common` | `@shared/*` | **all five** SPAs | Pure utilities, presentational primitives, and generated backend contracts. No auth, no API client, no session state. |
| `shared/authenticated` | `@shared-auth/*` | `adminui`, `userui` **only** | Auth-aware code: API client, step-up MFA, session handling. Not yet created — see Roadmap. |

Inside `shared/common/src`:

| Path | Contents |
|---|---|
| `hostname.ts` | DNS name helpers. |
| `components/`, `context/` | React primitives every SPA rendered identically: `Chevron`, `Toast`, `ScrollToTop`, `ThemeContext`. |
| `generated/` | **Machine-generated. Do not edit.** DTO interfaces, enums, `StepUpOps`, and the X.509 usage vocabulary, all derived from C#. See below. |

The split is enforced by wiring: `@shared-auth/*` is only aliased in the two SPAs entitled to it, so
`setupui` (which runs before authentication exists) and `docsui` (nearly static) cannot import auth
machinery even by accident. The specifier simply will not resolve there.

## How it is wired

No npm workspace, no package manager change. Each SPA resolves the alias twice:

- `vite.config.ts` — `resolve.alias` for the bundler, plus `server.fs.allow` so the dev server may
  read files above the project root.
- the SPA's effective tsconfig — `paths`, so `tsc` and editors resolve the same specifier.

Both layers additionally alias `react`, `react-dom` and `react-router-dom` onto the consuming
app's own `node_modules`. This is not optional: a file in `shared/common` resolves its imports by
walking UP from its own location, reaches the repo root, and finds no `node_modules` at all — so
without those entries neither `tsc` nor the bundler can resolve `react` from a shared component.
Pointing them at the consuming app also guarantees a single React instance in the bundle.

Note the TypeScript entries map to `@types/react`, not `react`: mapping to the runtime package
makes TS resolve `react/index.js` directly and stop consulting `@types`, which turns every hook
and every JSX element into `any`.

This was chosen over npm workspaces deliberately. Workspaces are the more conventional answer, but
they require a root `package.json`, change how all five SPAs install, and touch the
`.esproj → npm run build` integration. The alias achieves the same sharing with far less blast
radius, and migrating to workspaces later does not change a single import — `@shared/x` stays
`@shared/x`.

It is safe to share React components this way only because all five SPAs pin identical
`react` / `vite` / `typescript` versions. **If those ever diverge, revisit this** — two React copies
in one bundle break hooks in ways that are painful to diagnose.

## Rules

1. **`shared/common` imports nothing app-specific.** No API client, no router, no auth context.
   If it needs one of those, it belongs in `shared/authenticated` or in the SPA.
2. **Every export carries a doc comment explaining *why* it is shared**, not just what it does.
   The reason is usually "these copies drifted and it caused a bug" — worth recording.
3. **No default exports.** Named exports keep the call sites greppable across five SPAs.
4. **Changing a shared file affects all consumers.** Typecheck every SPA that aliases it, not just
   the one you are working in.

## Roadmap

Phase 1 (done) — scaffold plus `looksLikeHostname`, replacing three drifted copies.

Phase 2 (done) — `scripts/generate-shared-types.mjs` writes `shared/common/src/generated/` from
the C# sources: DTO interfaces from `ModularCA.Shared.Models`, enums as string-literal unions
(the API installs a global `JsonStringEnumConverter`, so enums cross the wire as member names),
the `StepUpOps` allow-list, and the X.509 usage vocabulary ported from `UsageCatalogResolver`.
It runs from the API's `BuildWebUIs` target before any SPA typechecks, and `--check` fails
instead of writing, for CI.

Property names come from a port of `JsonNamingPolicy.CamelCase`, which lowercases only the
LEADING run of capitals — `SubjectDN` is `subjectDN` on the wire, not `subjectDn`. That is the
detail hand-written interfaces get wrong, and `scripts/wire_contract.py` structurally cannot
catch a key that is simply absent rather than miscased.

Phase 3 (done) — the React primitives above, plus the step-up call sites migrated from bare
string literals to the generated `StepUpOps` constants.

Phase 4 — create `shared/authenticated` and reconcile `api/client.ts` and `StepUpMfaModal.tsx`.
Sharing those *is* the fix for the two findings at the top of this file, but it needs real
design: `publicui` is anonymous and legitimately different, so the client needs a capability flag
rather than one shape for everyone.

## Generated code

`shared/common/src/generated/` is written by `scripts/generate-shared-types.mjs` and checked in,
so `tsc` and editors work without running Node first and so drift is visible in review.

    node scripts/generate-shared-types.mjs           # write (idempotent)
    node scripts/generate-shared-types.mjs --check   # exit 1 if output is stale

Two behaviours are deliberate and worth knowing:

- **Unmappable properties are dropped, not widened to `unknown`.** `CertificateAuthorityIdentity`
  holds an `IPrivateKeyHandle`; `CertificateExportOptions.Chain` holds BouncyCastle certificates.
  Neither can cross the wire in any form a browser can construct. Typing them `unknown` would
  compile and then invite a caller to populate a field the server cannot deserialize. A type left
  with nothing serializable is skipped entirely.
- **A `StepUpOps` constant missing from `StepUpOps.All` is not emitted as a usable value.** It
  goes into `STEP_UP_OPS_UNREGISTERED` instead, because the server answers
  `400 invalid_step_up_operation` for it — the exact shape of the `delete-eab-key` defect, where
  the admin UI sent an operation for months that could never succeed.
