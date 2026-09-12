# modularca.web.tests

Unit tests for the TypeScript the SPAs share — `shared/common/src` and `shared/authenticated/src`.

It sits under `tests/` as a sibling of `ModularCA.Tests` (xUnit) so the repo has one obvious
place to look for tests regardless of which language they are written in. It is a **separate npm
package** with its own `node_modules`, rather than a `test` script inside one of the five SPAs,
for two reasons: the shared directories belong to no single app, so hanging their tests off
`modularca.adminui` would be arbitrary; and none of the five app packages should carry a test
runner into a production `npm ci`.

It is deliberately **not** in `ModularCA.sln` — it builds with npm, not MSBuild, and adding it
would put a project in the solution that `dotnet build` cannot do anything with.

## Running

```
cd tests/modularca.web.tests
npm install        # first time only
npm test           # single run, non-zero exit on failure — this is the CI entry point
npm run test:watch # re-runs affected suites on save
npm run typecheck  # tsc -b, same strictness as the SPAs
```

`npm test` is a full run and exits non-zero on the first failing suite, so it can be wired into CI
as-is.

## Adding a suite

Mirror the layout of the tree you are testing, dropping the `src` segment:

| Module under test                            | Test file                                |
| -------------------------------------------- | ---------------------------------------- |
| `shared/authenticated/src/api/problem.ts`     | `src/authenticated/api/problem.test.ts`  |
| `shared/common/src/validation/subject.ts`     | `src/common/validation/subject.test.ts`  |

Import through the same aliases the apps use — `@shared/*` for `shared/common/src` and
`@shared-auth/*` for `shared/authenticated/src`. Those are declared twice: in `tsconfig.json`
`paths` for the typechecker and in `vitest.config.ts` `resolve.alias` for the runtime resolver.
**Change both together**; a mismatch shows up as a suite that typechecks but will not run, or the
reverse. Importing a shared module by relative path works but is discouraged, because it is then
no longer obvious that the test and the app bundle are loading the same file.

Only `src/**/*.test.ts` is collected.

## Environment

Suites run under the Node environment. Node 24 already provides the web types the current
modules touch (`Headers`, `Response`, `URL`), and nothing here needs a DOM yet. A suite that does
— anything touching `document`, `localStorage`, or React — should add jsdom as a devDependency
and opt in per file:

```ts
// @vitest-environment jsdom
```

Per-file rather than globally, so one component suite does not slow every pure-logic suite down.

## What is covered

- `src/authenticated/api/problem.test.ts` — `parseProblem`, `httpTitle`, `ApiError`,
  `isApiError`. Every error-body shape the API emits: RFC 7807 from
  `RequestValidationMiddleware`, the sanitized 500 from `StartModularCA.cs`, legacy
  `{ error }` / `{ message }`, ASP.NET model state, plain text, empty, malformed, and non-object
  JSON. The suite carries its own copy of the *previous* client's message logic (`legacyMessage`)
  and asserts byte-identical output for legacy bodies — that no-regression property is the point
  of those cases, since hundreds of call sites toast `err.message` unchanged.

- `src/common/notifications/notice.test.ts` — `autoDismissMs`, `normalizeFieldName`,
  `fieldMatches`, `selectFieldNotices`, `unclaimedNotices`, `worstSeverity`, `noticeText`,
  `toNotice`, `mergeNotices`. The decisions the notification surface makes, as opposed to how it
  paints them: whether a warning is still on screen when the operator looks up, and whether a
  message lands under the control it names or in a corner. The field cases use the spellings each
  source actually emits (`extendedKeyUsages`, `$.notAfter`, `"Signature algorithm"`), because
  reconciling three vocabularies nobody owns end to end is the part that breaks quietly.

- `src/authenticated/api/notices.test.ts` — `problemNotice`, `problemNotices`,
  `diagnosticSeverity`, `diagnosticNotice`, `diagnosticNotices`, `errorNotices`. The join between
  the parsed response and the notification surface. Inputs are built by `parseProblem` from the
  bodies the server writes rather than hand-assembled `ApiProblem` literals: an adapter tested
  against an object the parser never produces proves nothing.
