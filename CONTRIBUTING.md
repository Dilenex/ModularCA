# Contributing to ModularCA

Thanks for your interest in contributing! ModularCA is an enterprise Certificate
Authority — security-critical software — so contributions are reviewed with care.
This guide covers how to build the project, the conventions we follow, and how to
get changes merged.

## Reporting Security Issues

**Do not open public issues for security vulnerabilities.** Follow the process in
[SECURITY.md](SECURITY.md) instead.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By
participating, you agree to uphold it.

## Project Layout

ModularCA is a .NET solution (`ModularCA.sln`) plus several React/TypeScript
single-page apps:

| Project | What it is |
| ------- | ---------- |
| `ModularCA.API` | ASP.NET Core host, controllers, middleware, startup |
| `ModularCA.Core` | Issuance, protocols, scheduling, audit, business logic |
| `ModularCA.Auth` | Authentication, password policy, JWT, authorization |
| `ModularCA.Keystore` | Software keystore + PKCS#11/HSM key handling |
| `ModularCA.Bootstrap` | First-run setup, database provisioning, seeding |
| `ModularCA.Database` | EF Core `DbContext`s and migrations |
| `ModularCA.Shared` | Entities, DTOs, enums, interfaces, utilities |
| `modularca.adminui` | Console: management at `/admin`, self-service at `/user` (one bundle) |
| `modularca.publicui` | Public CA info / CRL / OCSP / ACME directory |
| `modularca.docsui` | Documentation site |
| `modularca.setupui` | First-run setup wizard |

## Prerequisites

- The .NET SDK targeted by the projects (see the `*.csproj` `TargetFramework`).
- Node.js LTS + npm (for the frontends).
- A PostgreSQL 14+ server for running the API locally.

## Building

Backend:

```bash
dotnet restore ModularCA.sln
dotnet build ModularCA.sln
```

Each frontend builds independently, e.g.:

```bash
cd modularca.adminui
npm install
npm run build      # or: npm run dev  for a local dev server
```

Repeat for `modularca.publicui`, `modularca.docsui`, and
`modularca.setupui`.

## Running Tests

Build the solution first (the API tests load `ModularCA.API` from its build
output), then run the test project:

```bash
dotnet build ModularCA.sln
dotnet test tests/ModularCA.Tests --no-build                         # everything
dotnet test tests/ModularCA.Tests --no-build --filter "Tier!=Slow"   # the fast tier
```

- **Everything** is what CI runs and what a release needs. With a PostgreSQL
  test server it takes about 13 minutes on a 12-core Windows workstation
  (6,459 tests). The PostgreSQL tests are opt-in: set `MODULARCA_TEST_PG` to a
  connection string for a server where the user may create roles and databases
  (never one that holds data), otherwise they are reported as skipped.
- **The fast tier** leaves out the tests tagged `[Trait("Tier", "Slow")]`: the
  PostgreSQL tests, the restore drill and the shell-script tests. It takes about
  4 minutes (6,304 tests) and is the one to run after each merge.

How the run is ordered, for anyone adding a slow test:

- The PostgreSQL test classes are spread over six collections, the lanes
  (`TestUtils/PostgresLane.cs`); put a new class in the lane with the least in
  it and tag it `Category=PostgreSQL` and `Tier=Slow`. The lanes start when the
  rest of the suite has finished, and the two restore drills after the lanes
  (`TestUtils/PhasedTestFramework.cs`).
- A test that only needs the migrated schema takes a copy of a template
  database (`PostgresTestDatabase.CreateMigratedAsync`) instead of running the
  migrations; a test about migrating runs its own.

Please add or update tests for any behavior you change, especially anything that
touches issuance, validation, revocation, authentication, authorization, or
cryptography.

## Database Migrations

The schema is managed with EF Core migrations under
`ModularCA.Database/Migrations`. If your change alters the model, generate a
migration rather than editing the schema by hand:

```bash
dotnet ef migrations add <DescriptiveName> --project ModularCA.Database --startup-project ModularCA.Database --context ModularCADbContext
```

Use a clear, descriptive migration name. The baseline migrations are frozen and must never
be regenerated or edited. For the audit context, preconditions and the upgrade test, see
"Schema changes after the baselines" in `docs/architecture/postgresql-migration.md`.

A migration runs as the runtime role that owns its database, on every install, with nothing
else in reach. So it names no role and never uses `SET ROLE`, `GRANT`, `REVOKE`,
`ALTER DEFAULT PRIVILEGES` or `OWNER TO`. It creates no schema, role or database. It adds no
extension to the audit context, and none except `citext` to the application context. It never
combines `suppressTransaction: true` with a `FailIf` precondition. The reasons are in "Who owns
the schema" in the same document.

## Coding Conventions

- **Match the surrounding code** — naming, formatting, and structure should be
  consistent with the file you are editing.
- **Keep XML doc comments current.** When you add or change a public C# method or
  class, add or update its `/// <summary>` so the docs stay accurate.
- Prefer existing shared utilities over reinventing them — for example,
  cryptographic key/algorithm decisions should route through the existing key
  algorithm policy rather than introducing local helpers.
- Security-relevant defaults must stay **secure by default**. Do not add bypasses,
  accept-all validators, default credentials, or anything that weakens the default
  posture. New crypto code paths that accept an algorithm identifier from the wire
  must allow-list, not deny-list.

## Submitting Changes

1. Fork the repository and create a topic branch off `main`.
2. Make focused commits with clear messages.
3. Ensure `dotnet build`, `dotnet test`, and the relevant frontend builds pass.
4. Open a pull request describing **what** changed and **why**. Link any related
   issue. For user-facing or security-relevant changes, call out the impact.
5. A maintainer will review. Please be responsive to feedback — security review
   may take an extra round.

### Sign-off

We use the [Developer Certificate of Origin](https://developercertificate.org/).
Add a `Signed-off-by` line to each commit (`git commit -s`) to certify you wrote
the code or otherwise have the right to submit it under the project license.

## License and the CLA

ModularCA is licensed under the GNU Affero General Public License v3.0 (see
[LICENSE](LICENSE)), and is also offered under a commercial licence to organisations
that cannot accept the AGPL.

Offering both is only possible if one party holds the necessary rights to every line.
The Developer Certificate of Origin above certifies that you may submit your work — it
does **not** grant the rights needed to also offer it commercially. So contributions
additionally require a signed **Contributor License Agreement**: see [CLA.md](CLA.md).

You keep the copyright in your contribution. The CLA grants a licence alongside it, so
your work can ship under both the AGPL and the commercial licence. Without it a
contribution cannot be merged — not out of bureaucracy, but because accepting one
would leave part of the project unable to be licensed on the terms the rest is.
