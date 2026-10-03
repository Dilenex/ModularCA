# Moving to PostgreSQL

Status: design, 2026-09-18. Target 0.3.1. 0.3.0 ships on MariaDB as it stands.

## Why

The data access layer is the least supportable thing in the product. Pomelo, the MySQL provider,
last had a commit in August 2025, has no release for the framework this product targets, and shows
no sign of one while Entity Framework 11 is already a release candidate. Every other dependency
has a maintainer to call.

PostgreSQL replaces that with a provider that is ahead of the framework rather than behind it, and
with a commercial support market rather than a single vendor: a customer can buy support from EDB,
Crunchy, Percona or their own cloud, and change their mind later without changing database. For a
product sold to other people, that is an answer worth having.

It is not a free move, and the cost is not the provider. Thirty-one migrations on the application
context and a further set on the audit context are MySQL-specific down to their identity columns,
and roughly four hundred lines of MySQL SQL live in bootstrap, backup, restore and the setup
wizard. That work is the same whoever the new provider is.

## Shape

**One provider, not two.** PostgreSQL replaces MariaDB rather than joining it. Supporting both
means two migration sets forever and an abstraction over every piece of database-specific SQL, for
a product that controls its own deployments.

**One migration per context — until 0.4.0.** Once production and staging had applied these
baselines, they were frozen, and schema changes since arrive as migrations (see
`instance-tenancy.md`, "Decisions for 0.4.0"). A clean install applies a single `InitialCreate` for the
application context and a single one for the audit context, generated fresh from the model. The
thirty-one existing migrations describe how a MariaDB schema was built up over time and have no
meaning against a database that never had them.

**One supported upgrade path, and it is narrow.** A deployment moves in three steps: upgrade to
0.3.0 on MariaDB, which applies every existing migration and leaves the schema at a single known
version; run the helper, which copies that schema's data into a fresh PostgreSQL database; start
0.3.1 against PostgreSQL. The helper therefore only ever has to understand one schema version,
which is what makes it a script rather than a product. 0.3.1 refuses a MySQL connection string
with a message naming this document, and the helper refuses a source it does not recognise.

## What will actually bite

These are in the order I expect them to cost time, not the order they appear in the code.

**Case sensitivity is a behaviour change, not a data change.** MySQL's default collation is
case-insensitive; PostgreSQL's is not. There are forty-nine unique indexes, many on usernames, CA
labels, profile names and tenant hostnames. Existing data is clean, because MariaDB refused the
duplicates. The risk is the opposite: a lookup that used to match regardless of case stops
matching. Signing in as `Admin` against a row that says `admin` is the obvious one, and a CA label
or hostname resolved from a URL is the subtle one. Every such column needs a deliberate decision:
normalise on write and compare exactly, or index on a lowered expression. Doing nothing is the one
option that silently changes who can sign in.

### As built

Done, and neither of the two options above is what it became. Both of them decide the question in
the *queries*, and that is the part nobody can finish: a unique index on `lower(col)` only helps a
lookup written to use it, and normalising on write only helps a lookup that remembers to normalise
its argument too. Miss one site out of the hundreds that exist and it is case-sensitive again,
silently, with the index sitting there looking correct.

So the answer is a column type instead. `citext` folds case inside the type, so equality, `LIKE`
and the unique index all behave as they did on MySQL and no query has to know. The decision is
recorded per column in `TextCaseSensitivity`, which is the registry the rest of this hangs off, and
`TextCaseSensitivityTests` fails the build when a text column comes under a uniqueness constraint
without appearing in one of its two sets. That test is the real deliverable: the original problem
was a schema that inherited one answer for every column at once, and what replaces it has to be a
thing that cannot be inherited by accident again.

Thirty-nine columns fold case. The ones that matter are the identifiers a person or a client types:
usernames and email addresses, space slugs and CA labels as they appear in enrollment URLs,
hostnames from a `Host` header or an SNI extension, Kerberos realms, role and group names. Then
distinguished names and hex serials, where RFC 4518 already says case does not distinguish, and
where the consequence is concrete rather than cosmetic — `(SerialNumber, Issuer)` is what stops one
certificate being imported twice, and `(IssuerName, CrlNumber)` is what stops one issuer publishing
two different CRLs under a single number.

Nine columns deliberately do not, and this is the direction the move *fixes* rather than breaks.
Refresh tokens, ACME replay nonces, account key thumbprints and FIDO2 credential identifiers are
base64 or base64url, where case carries information. MySQL compared all of them case-insensitively,
which for a bearer token is a straight halving of the alphabet it was drawn from, and for a nonce or
a thumbprint invents collisions between values that are genuinely different. Each entry carries its
reason in the registry, because case-sensitive is the direction that can break a client that used to
work, so it is the direction that has to be argued for.

Two things worth recording because they were not in the plan:

- A sweep of unique indexes is not the whole question. A text **primary key** asks it too, through
  a different API, and `SchedulerLeases.Name` and `SchedulerJobState.JobName` are both text primary
  keys that a unique-index-only pass walks straight past. The lease is what stops two nodes running
  one scheduled job at once; two spellings of a job name would be two leases, and both nodes would
  hold one and believe they held it alone. The detector reads primary and alternate keys as well
  now, which is how those two were found.
- `citext` takes no length modifier, so every converted `character varying(n)` would have quietly
  become unbounded. Each one gained a `length(col) <= n` check constraint carrying the same limit
  the model already declared, so the case fix does not buy a ten-thousand-character username.

The type has to exist before the first `CREATE TABLE`, so `InitialCreate` opens with
`CREATE EXTENSION IF NOT EXISTS citext` — and bootstrap and the migration helper create it first
anyway, as the app role (under `SET ROLE`), so the extension belongs to the database's owner and the
migration's own copy is a no-op. That works because `citext` is a trusted extension (PostgreSQL 13
and later) and the app role owns its database. This is the one
new deployment requirement: `citext` ships in `postgresql-contrib`, and is available on every
managed PostgreSQL service checked.

It follows that the helper gains a preflight check. For every case-insensitive column it groups the
source rows by the folded value and refuses if any two collide — which MariaDB should have made
impossible, and is exactly the sort of thing to confirm rather than assume before a one-way copy.

**The audit hash chain must survive the copy.** Rows are chained, so they must be inserted in
order and verify afterwards. The helper verifies the chain on the destination before it reports
success, and refuses to finish if it does not. A migration that quietly breaks the audit is worse
than one that fails.

**Concurrency tokens do not port.** The MySQL row version is a `TIMESTAMP(6)` the provider
maintains. PostgreSQL's equivalent is the system `xmin` column, mapped differently. Every entity
carrying a concurrency token needs remapping, and optimistic concurrency needs testing rather than
assuming.

**Types that look equivalent and are not.** Identifiers stored as `char(36)` become a native
`uuid`; booleans stored as `tinyint(1)` become `boolean`; binary columns become `bytea` and must
come across byte-identical, because they carry protected key material, raw certificates and
wrapped secrets. Timestamps are the classic trap: Npgsql is strict about UTC, and a value that
arrives with the wrong kind is a silent hour rather than an error.

**Everything outside Entity Framework.** Bootstrap creates a database and grants rights, and
PostgreSQL has roles rather than user-at-host. Backup shells out to `mysqldump` and restore to its
counterpart; both become the PostgreSQL tools, which changes the archive's contents and so the
restore path for archives taken before the move. The direct driver is used in six files beyond
the provider, including the setup wizard and backup.

## The helper

A separate command rather than something the node does at startup, because it runs while nothing
is running and its failure must be loud.

It takes a MariaDB connection and a PostgreSQL connection, refuses a destination that is not
empty, refuses a source whose schema is not 0.3.0, and copies table by table in dependency order,
preserving every identifier. It then verifies: row counts per table, the audit chain, and a sample
of certificates re-parsed from their stored bytes and compared to their stored fingerprints. It
reports what it did and what it checked, and it never writes to the source.

Keystores are files and are not touched, which removes the most dangerous part of the problem from
its scope entirely.

One column is not copied across as it stands. `EnrollmentTokens.Token` held the enrollment token
itself on MariaDB and holds a SHA-256 hash of it on PostgreSQL, so the helper must hash each value
as it copies it rather than moving it; the tokens stay usable and stop being readable, which is the
whole point of the change. `EnrollmentTokens.CmpSecretWrapped` is the other half of that split and
is new, so for a CMP row the helper hands the source `Token` value to the signer to wrap and puts
the blob there — PBMAC needs the secret itself, so it has to be recoverable, and the signer is now
what can recover it — with the hash in `Token` as for every other row, and the secret's last four
characters in `CmpSecretLastFour` for the console.

## Order of work

1. The provider swap, both contexts, single migrations, and the configuration that names them.
2. The database-specific SQL: bootstrap, backup, restore, setup wizard, and the six files using
   the driver directly.
3. ~~The case-sensitivity decision, applied per column, with tests that fail if a lookup becomes
   case-sensitive where it was not.~~ Done — see **As built** above.
4. ~~The helper~~ Built — see **The helper, as built** below. The rehearsal against a copy of
   staging is still to do, and is the first thing a PostgreSQL instance is needed for.
5. A rehearsal against a copy of production before anything touches production.


## The helper, as built

`ModularCA.Migrate`, published as `modularca-migrate`. It is the only project in the solution that
still references MySqlConnector, and the only one that may: the node refuses a MariaDB connection
outright, which is precisely why the last reading of one has to happen somewhere else.

### The destination rule changed

The design said the helper "refuses a destination that is not empty". That conflated the server
with the database, and no one dedicates a PostgreSQL cluster to a single application. The rule is
now **the two target databases and the two login roles must not exist**, which is narrower in what
it demands and stronger in what it gives:

- The helper creates the databases, so it sets their encoding and collation rather than inheriting
  whatever `template1` was left as. That is not housekeeping — `citext` folds case through a
  locale-dependent `lower()`, so the case rules the model declares are only true if the database
  agrees with them. They are created `ENCODING 'UTF8' TEMPLATE template0`, and the resulting
  collation is printed.
- A failed run can drop what it made, because it knows it made it. Had it accepted a pre-existing
  empty database, dropping it would be presumptuous, and the operator would be left clearing up by
  hand before every retry.

**Roles are the part a database-name check misses.** A PostgreSQL role is cluster-wide, so on a
shared server the databases can be free while the role names are not, and the existing-role
behaviour elsewhere in the product is to rotate the password — which, on a role belonging to a
neighbouring application, is a quiet outage for somebody else. So roles are held to the same rule
and the helper never takes one over.

### What it checks before it creates anything

In order, and it collects every refusal rather than stopping at the first, so an operator fixes one
set of problems instead of discovering them one run at a time:

- The source is really MariaDB, by asking it, not by trusting the port.
- The source schema is 0.3.0 and nothing else. One schema to understand is what keeps this a script.
- No CMP enrollment token is still live (see below).
- No case collisions, swept per case-insensitive column against the source.
- The server is PostgreSQL 14 or newer, the oldest release ModularCA supports. (13 is where
  `citext` became trusted and `DROP DATABASE WITH (FORCE)` arrived, the two facts the rest of the
  design rests on.)
- `citext` is available in `pg_available_extensions`. Missing contrib is a packaging problem and
  insufficient rights are a permissions problem, and the two failures read nothing alike.
- The administrative role has `CREATEDB` and `CREATEROLE`. Neither is transactional, so neither can
  be tested by trying it and rolling back; the catalogue is the only honest answer.
- Neither target database nor either target role exists, and none of the four names collide with
  each other or with the administrative account.

`--dry-run` stops after all of it. Nothing outside the operator's terminal has changed at that
point, which is what makes the whole preflight readable at a time when acting on it is free.

### The copy lands in the baselines, then upgrades (0.4.0)

The helper copies into the frozen baselines, not into the current model. Until 0.4.0 it built the
latest schema and copied by the current model's table and column names. Once migrations followed
the baselines, that broke in two ways. Data a later migration transforms never went through that
migration: the copied system tenant was never folded by `FoldSystemTenant`. And a column a later
migration renames would have been left behind without a word.

So the run now goes:

1. `DestinationBuilder.BuildAsync` applies only `20260919181506_InitialCreate` and
   `20260919181510_InitialAuditSchema` (`PostgresRoleLayout.AppBaselineMigration` and
   `AuditBaselineMigration`). It runs as the runtime roles, through
   `SchemaVersionGate.ApplyBaselineForBootstrapAsync`, on the same migration connection the control
   role and bootstrap use (`MigrationConnection`).
2. The copier writes into the baseline tables. Its table and column list is
   `ModelIntrospection.AppCopyTables()` and `AuditCopyTables()`. Both are read from the baseline
   migrations' own target models, never from the current `DbContext` model. The preflight
   case-collision sweep reads the baseline's unique keys and `citext` columns the same way.
   `BaselineCopyTests` pins the whole copy plan by digest.
3. Verification runs at the baseline stage, while source and destination still have the same
   shape: row counts, certificates, the audit chain and the sequence reset.
4. `DestinationBuilder.ApplyUpgradeMigrationsAsync` then applies every later migration, the
   application database's first. It uses `SchemaVersionGate.ApplyPendingAsync` as the runtime
   roles, after the same model-drift and unknown-migration checks the control role makes. It then
   proves ownership again. The copied 0.3.0 rows go through `RetireTenantHostnames`,
   `FoldSystemTenant`, `InstanceUniqueCaNames`, `RenameTenantToSpace` and every later migration
   exactly as an upgraded install's rows do, so a copied CA keeps its space under the new names.
5. Only then is the configuration written.

A precondition that refuses the copied data, such as `FoldSystemTenant` P1 and P3 to P9,
`InstanceUniqueCaNames` P1 to P5 or `RenameTenantToSpace` P1 and P2, fails the run. The message names the migration, quotes its
`RAISE` text, and lists what was committed before it. The usual rollback then drops both databases
and the three roles, or `--keep-on-failure` leaves them for inspection. Fix the data on the 0.3.0
source and run again. The preflight tenant-hostname refusal stays, so that one shape is still
refused before anything is created. `MigrationRun` holds this order, and `MigrationRunTests` pins it
with fake stages.

### Foreign keys, and why there is no topological sort

The constraints are dropped before the copy and added back after it. Ordering the tables so that no
constraint is ever violated cannot express a table that references itself — a certificate whose
issuer is another certificate — and the usual alternative, suppressing constraints with
`session_replication_role`, needs a superuser, which this helper deliberately does not require.
Re-adding a constraint makes PostgreSQL scan and validate it, so the referential integrity of the
copy is checked by the server rather than asserted by us. They are restored in a `finally`: a
destination left without its foreign keys would look like a working database and behave like a
corrupt one.

### Live CMP credentials are refused, not migrated

On 0.3.0 the `Token` column held the token itself, and for a CMP row that value *is* the PBMAC
shared secret. On 0.3.1 the token column holds a hash and the secret lives wrapped under a key only
the signer can use, so carrying a live CMP credential across would mean wrapping it — which would
mean handing a one-way copy tool a keystore and its passphrase. The credential is short-lived and
cheap to re-issue, so the helper refuses while any CMP token is unrevoked and unexpired, and says
to revoke and re-issue. Revoked and expired rows migrate normally with no secret: their history is
worth keeping and their secret is not.

That is the single functional limitation, and it is deliberate. It keeps the helper free of the
keystore entirely.

### What it verifies before reporting success

A copy that reports success and is subtly wrong is worse than one that fails, because the source
gets decommissioned on the strength of the report. Four kinds of evidence:

- Foreign keys, validated by the server as they are restored.
- Row counts per table, source against destination, at the baseline stage before any later
  migration changes the rows.
- Certificates re-parsed from the bytes that crossed and checked against the serial stored beside
  them — the proof that the `bytea` round trip was byte-exact, on the data where one flipped byte
  matters most, and the closest available proxy for the key material in the same columns.
- The audit hash chain re-verified end to end, per chain.

And before any of that, **every identity sequence is reset** past the largest value its column now
holds. This is the step whose absence produces a database that verifies perfectly and then collides
on the first insert, because copying preserves identifiers while the sequences behind them still sit
at 1. It is the most common way a PostgreSQL migration appears to have worked.

On failure the helper drops the databases and roles it created, says so, and states that the source
was not touched. `--keep-on-failure` leaves them for inspection instead.

### What is not covered by tests

The copy itself needs two live database servers and belongs to the rehearsal, not the unit suite.
What is pinned there is everything deciding *what* is copied and what it becomes: that `xmin` is
never written and identity columns always are, that the case-insensitive column list resolves to
real table and column names, the type conversions — with the timestamp case called out, since
stamping UTC rather than converting is the difference between every row surviving and every row
shifting by the migrating machine's offset — and the enrollment token transform. The copy plan is
pinned to the baselines (`BaselineCopyTests`). The two schema stages are tested on SQLite
(`SchemaStagesTests`), and the order of the run with fake stages (`MigrationRunTests`). The
destination side runs against a real server in the opt-in `PostgresOwnershipHarnessTests`. Rows are
written into the baselines as the copier writes them, then upgraded through every later migration.
A `FoldSystemTenant` refusal fails the tool with its message, and the rollback removes both
databases and the roles.

## Who owns the schema

From 0.4.0 one layout holds on every install path: bootstrap, the setup wizard, the recovery
wizard and `modularca-migrate`. It is the layout `modularca-migrate` built for production and
staging. The names:

- **A**: `App.Username` in `db.yaml` (e.g. `modularca_app`).
- **U**: `Audit.Username` (e.g. `modularca_audit`).
- **O**: `<U>_owner` (e.g. `modularca_audit_owner`), a role with no login.
- **R**: `SqlRoot` in `setup-database.yaml`, used by bootstrap only. It must be a PostgreSQL
  superuser; bootstrap checks that first and refuses otherwise. `CREATEDB` and `CREATEROLE` are not
  enough.

The rule:

1. A owns the application database, every table, index, sequence and `__EFMigrationsHistory` in its
   `public` schema, and the `citext` extension.
2. O owns the audit database. O has no login, no password and no member except superusers. U owns
   every table and `__EFMigrationsHistory` in the audit database's `public` schema. U holds CONNECT
   on the database and USAGE and CREATE on `public`, but no CREATE on the database, and is not a
   member of O. So U applies its own migrations, and cannot drop the database, create a schema or
   create an extension.
3. A and U have no SUPERUSER, CREATEDB, CREATEROLE, REPLICATION or BYPASSRLS, and are members of no
   role.
4. The control role applies migrations with exactly the `db.yaml` credentials. No administrative
   credential ever reaches a ModularCA process, and nothing the service account can write is ever
   run as root or as a PostgreSQL superuser.

A fresh install also revokes PUBLIC's rights on both databases. A and U keep what they need, as
owner and by grant. A monitoring or reporting role therefore needs its own
`GRANT CONNECT ON DATABASE`. Production and staging were built before this change and keep PUBLIC's
CONNECT unless an operator revokes it. Where `public` belongs to the superuser and PUBLIC may
create tables in it (PostgreSQL 14, and a database pg_upgraded from 14 to a later release),
bootstrap and `modularca-migrate` give `public` to the database owner and revoke PUBLIC's CREATE.
They decide from the schema's actual owner and ACL, not from the server version; on a database
created by PostgreSQL 15 or later there is nothing to do. PostgreSQL 14 is the oldest
release supported: bootstrap, `modularca-migrate` and the startup check all refuse anything older.

| Operation | Runs as |
|---|---|
| Startup check: presence, migration history, ownership (catalog reads only) | A on the application database, U on the audit database |
| Migrations (control role only) | A and U, each on its own migration connection |
| Bootstrap: roles, `CREATE` and `DROP DATABASE`, grants, adopting a preserved audit database | R |
| Bootstrap: baselines, later migrations, seed data | A and U, through the code path the control role uses |
| Backup (`pg_dump`), restore, factory reset | A and U |
| Repairing an install made before 0.4.0 | the local `postgres` superuser, running the root-owned `/usr/share/modularca/sql/adopt-ownership.sql` |

Bootstrap proves the layout before it writes any configuration. It checks, as A and as U, that
each role owns its schema. That also proves `pg_hba.conf` lets both roles in, which bootstrap now
needs as much as the service does.

### The audit trail is tamper-evident, not tamper-proof

**U owns the audit tables.** Anyone who holds its password can ALTER, DROP or TRUNCATE them, add a
trigger or a rule, and write to their migration history. That includes anyone who controls the
node. U also holds DELETE, which the retention job uses. What U cannot do is drop the audit
database, create a schema or an extension, or become O.

So privileges do not prevent tampering with audit history. The hash chain makes it evident:
each record carries the SHA-256 of the record before it, and verification
(`AuditHashChainService.VerifyAsync`) reports a record that was altered, removed or reordered.
Restarts and retention prunes are themselves chained records, which it counts. The chain is not
keyed, so someone holding U's password could rewrite a chain consistently from an edited record
onward. Against U itself, tampering is evident only when the chain is compared with a copy kept
outside the database, such as an earlier backup of the audit database. Describe the product as
tamper-evident, never as tamper-proof. Production and staging have had this layout since they
moved to PostgreSQL. 0.4.0 brings every other install into line with it.

Preventing tampering is on the roadmap as **separated schema authority**:

- a no-login table owner, distinct from the database owner;
- a migrator that can only `SET ROLE` to that owner, with its credential held outside the node;
- runtime roles with DML only: U gets SELECT, INSERT and DELETE, and only SELECT on its migration
  history;
- a bounded `SECURITY DEFINER` function for retention.

It waits on two things. First, the payload under `/opt/modularca` must become root-owned, with
`ReadWritePaths` narrowed. Second, credentials need a store outside `/opt/modularca`; today
`/etc/modularca` is a symlink into it. The ownership check and the repair already take the target
owner as a parameter, so the conversion will be one repair run.

### Installs made by the wizard or `--bootstrap` before 0.4.0

Before 0.4.0 the wizard and the CLI applied both baselines as SqlRoot. So the superuser owns every
table in both databases, and the app role has no privilege on its own tables. Such an install
cannot read its own application tables. From 0.4.0 the service refuses it at start with exit
status 3. The refusal lists the objects and their owner and prints the repair:

```bash
sudo systemctl stop modularca modularca-signer
sudo -u postgres psql -X -d 'modularca-app' -v kind=app -v target='modularca_app' -f /usr/share/modularca/sql/adopt-ownership.sql
sudo -u postgres psql -X -d 'modularca-audit' -v kind=audit -v target='modularca_audit' -f /usr/share/modularca/sql/adopt-ownership.sql
sudo systemctl start modularca
```

Use the database and role names from `db.yaml`; the refusal prints them. For a server that is not
on port 5432, add `-p <port>`. On a database host without the package, take the script from the
tarball's `share/sql/`. Run it as a superuser and never from a directory the service account can
write.

The script hands each object in `public` to the target role, one `ALTER ... OWNER TO` per object,
in one transaction. It moves only objects that a superuser, a CREATEDB or CREATEROLE role, or the
database owner created. Indexes and identity sequences move with their table, and extension members
stay where they are. Objects owned by any other ordinary role are reported, never moved. It refuses,
and changes nothing, unless all of these hold:

- the database holds this product's frozen baseline in its migration history;
- the target is a plain login role, with no SUPERUSER, CREATEDB, CREATEROLE, REPLICATION or
  BYPASSRLS;
- for `kind=app`, the target already owns the database;
- for `kind=audit`, the target was granted CONNECT on the database and cannot become its owner.

Running it again changes nothing. `REASSIGN OWNED` is avoided on purpose: PostgreSQL refuses it for
`postgres`, and it would also move shared objects such as the audit database itself.

**The `.deb` runs this repair itself** when PostgreSQL is local; `packaging/README-PACKAGING.md`
says exactly when. A tarball install, a remote or managed server, and a failed automatic repair
all get the refusal and the commands above. The other way out is to run the 0.4.0 bootstrap again.
It re-owns a preserved audit database automatically, but it discards the application data.

To see the same report without changing anything, run
`sudo -u modularca /opt/modularca/ModularCA.API --db-ownership check` as the service user, never as
root. It exits 0 when both databases are sound and 3 when not.

A restore still works on a repaired install. `citext` stays owned by the superuser that created it,
because PostgreSQL has no `ALTER EXTENSION ... OWNER`. So the restore creates the extension as A
when it is missing, and leaves the extension's entries out of the dump's table of contents rather
than dropping and recreating it.

## Schema changes after the baselines (0.4.0 on)

The baselines are frozen: `20260919181506_InitialCreate` for the application context and
`20260919181510_InitialAuditSchema` for the audit context, with their designer files. Production
and staging applied them on 2026-09-19. Never regenerate or hand-edit them, nor any migration after
them; `FrozenBaselineTests` pins the baselines and the 0.4.0 migrations by normalised hash. The model snapshots
change only through `dotnet ef migrations add`. Every schema change from 0.4.0 on is a new
migration, with any data transformation written into it.

### Adding a migration

Run from the repository root. `ModularCA.Database` is both the target and the startup project,
through its design-time factories (`ModularCADbContextFactory`, `AuditDbContextFactory`). No
database server is needed.

```bash
dotnet ef migrations add <Name> --project ModularCA.Database --startup-project ModularCA.Database --context ModularCADbContext
dotnet ef migrations add <Name> --project ModularCA.Database --startup-project ModularCA.Database --context AuditDbContext --output-dir Migrations/Audit
```

The audit context needs `--output-dir Migrations/Audit`, or its migration lands beside the
application's in the wrong namespace. To check that the model matches the snapshots, and to list
what each context knows:

```bash
dotnet ef migrations has-pending-model-changes --project ModularCA.Database --startup-project ModularCA.Database --context ModularCADbContext
dotnet ef migrations has-pending-model-changes --project ModularCA.Database --startup-project ModularCA.Database --context AuditDbContext
dotnet ef migrations list --project ModularCA.Database --startup-project ModularCA.Database --context ModularCADbContext --no-connect
```

`SchemaVersionGateTests` asserts the same thing in the unit suite, so a model change without its
migration fails the build's tests.

### Preconditions

A migration that transforms data first states what must hold, with `FailIf` from
`MigrationPreconditions`:

```csharp
migrationBuilder.FailIf(
    "(SELECT count(*) FROM \"SecurityPolicy\") > 1",
    "This instance has more than one SecurityPolicy row. Delete the extra rows before upgrading.");
```

It emits `DO $$ BEGIN IF (<condition>) THEN RAISE EXCEPTION '<message>'; END IF; END $$;`. The
raise rolls back the migration's transaction. Before it applies anything, the control role
rehearses every pending migration in one transaction that it rolls back (see "At startup"). A
refusal in the last pending migration therefore leaves the earlier ones unapplied too.

A message can name values the database computes when the check fails: `{0}`, `{1}` and so on
stand for SQL expressions passed after the message.

```csharp
migrationBuilder.FailIf(
    "EXISTS (SELECT 1 FROM \"TenantHostnames\")",
    "This instance has {0} tenant hostname(s)...",
    "(SELECT count(*) FROM \"TenantHostnames\")");
```

A message with values is raised as `RAISE EXCEPTION USING MESSAGE = concat(...)` rather than as a
format string, because RAISE's own `%` placeholders cannot put a value next to a literal `%` or
next to another value. Quotes are escaped and `%` is always literal, with or without values. Do not use `suppressTransaction: true` in a
migration that has a precondition.

### Rules for migration authors

Every migration runs as the runtime role that owns the database it changes (A or U, see "Who owns
the schema"), on every install, with nothing else in reach. So a migration:

- never names a role and never runs `SET ROLE`;
- contains no `GRANT`, `REVOKE`, `ALTER DEFAULT PRIVILEGES` or `OWNER TO`;
- creates or drops no schema, role or database, and puts everything in `public`;
- adds no extension to the audit context, and none except `citext` to the application context;
- runs entirely inside a transaction. That rules out `suppressTransaction: true`, an index
  created concurrently, and any statement PostgreSQL refuses in a transaction block, such as
  `VACUUM`. It also rules out `ALTER TYPE ... ADD VALUE`, whose new value a later statement of the
  same transaction cannot use. The dry run runs every pending migration in one transaction. It
  will not run a migration it cannot rehearse, and the start refuses it as a defective build.
  `MigrationLintTests` checks every migration's generated commands for all of this.

A migration that breaks one of these rules fails with 42501 on its first real upgrade, on every
install at once. Long statements are fine. A migration runs with a `lock_timeout` of
`Schema.MigrationLockTimeoutSeconds` (30 s) and a `statement_timeout` of
`Schema.MigrationCommandTimeoutSeconds` (3600 s).

### At startup

`SchemaStartup` (ModularCA.API/Startup) checks every database a process uses before it writes to
either. The control, enrollment and validation roles check the application and the audit database.
The signer checks the application database, where its own audit goes. Setup mode and an
ingress-only process are not checked. The check has four phases.

1. **Read.** Each database is read as its own runtime role, on a dedicated connection that gives up
   on a lock after 3 s, so a read never queues behind a migration. The read covers:
   - whether the database exists and has tables;
   - its migration history;
   - from `pg_catalog` only, which objects in `public` the role does not own.
2. **Decide.** Both databases are judged before anything is applied to either.
   - **Exit status 3, for every role**, when the operator must act:
     - a migration is recorded that this build does not know, so the schema is newer than the
       build;
     - there are tables but no migration history;
     - a login or TLS failure, a `pg_hba.conf` refusal, or a missing privilege;
     - an object the runtime role cannot even read (the pre-0.4.0 wizard layout);
     - PostgreSQL older than 14.
   - **Wait**, with backoff from 2 s to 30 s, when:
     - the database cannot be reached;
     - it is locked by a migration in progress;
     - for a role other than control, migrations are pending that only the control role applies.

     The wait keeps extending systemd's start timeout and logs at most once a minute. After
     `Schema.WaitSeconds` (900) the process exits with **status 75**, and systemd retries it.
   - **Ownership.** The control role refuses (status 3) to migrate a database whose runtime role
     does not own every object in it. It refuses before anything is applied to either database, and
     prints the repair. With nothing pending, the same finding is only a warning that the next
     release carrying a migration will refuse.
   - **Missing or empty.** A database that does not exist, or has no tables, is not refused. The
     runtime never creates a database or a schema; bootstrap does.
   - **Model.** Before applying anything, the control role checks that this build's model matches
     its latest migration. If it does not, the build is defective, and the process exits 3 having
     applied nothing.
3. **Dry run, then apply** (control role only). Each database gets its own migration connection as
   its runtime role, with a `lock_timeout` of `Schema.MigrationLockTimeoutSeconds` (30) and a
   `statement_timeout` of `Schema.MigrationCommandTimeoutSeconds` (3600; 0 means no limit).
   - **Dry run.** `SchemaVersionGate.DryRunPendingAsync` opens one transaction and takes the lock
     on `__EFMigrationsHistory` that EF's apply takes. Under that lock it reads the history again
     and runs every pending migration in order. For each it runs the commands EF's migrator
     generates for the real apply, history insert included (`SchemaVersionGate.UpCommands`; the
     same `IMigrationsSqlGenerator` call against the same finalized target model, which
     `MigrationLintTests` pins against `Migrator.GenerateUpSql`). It then rolls back, whatever
     happened, and closes the unpooled connection, so no lock outlives it. PostgreSQL DDL is
     transactional, so a later migration sees what the earlier ones did, as it will for real. The
     application database is rehearsed first, then the audit database. If either refuses, the
     process exits 3 having applied nothing to either database. A migration with a command that
     must run outside a transaction is not run: the dry run reports it, and the start exits 3 as a
     defective build.
   - **Collect mode.** The dry run reports every refusal it can reach, not only the first. Each
     command runs under its own savepoint, released when it succeeds and rolled back to when it
     fails (`SchemaVersionGate.DryRunPendingAsync`, deciding through `DryRunCollector`):
     - a refusal (SQLSTATE P0001, which `FailIf` raises) is recorded with its migration, its check
       label (`MigrationCheckLabels`, pinned to the `// Pn` comments by `MigrationCheckLabelsTests`)
       and its `RAISE` text, and the run continues;
     - another error in a migration that has already refused is taken as its knock-on (a unique
       index the refused duplicates break): the rest of that migration is skipped and the run
       continues with the next;
     - any other error, or a lock timeout, deadlock, lost connection or statement timeout even
       after a refusal, stops the run: the checks after it could not run.

     It passes only when every command of every pending migration ran. The message numbers the
     refusals ("1 of N"), marks every one after the first "also found" (real on the current data,
     but its outcome may change once the earlier ones are fixed), lists the skipped migration
     tails and where it stopped, and says that nothing was applied. A refusal in the application
     database does not stop the audit database's dry run, so the journal lists both. A transient
     error is retried (below) only when no refusal came before it. The real apply is unchanged: it
     runs only after both dry runs pass, and stops at its first error.
   - **Apply.** Only when both dry runs pass. The application database's pending migrations go
     first, then the audit database's. Each migration commits on its own. If one still fails (an
     error the data could not predict, such as a timeout), the message:
     - names the first migration not applied;
     - lists the migrations committed in this run;
     - says whether statements the migration ran outside a transaction stayed applied.

   A lock timeout, a deadlock, a serialization failure, a lost connection or a connection that
   could not be opened, in the dry run or the apply, is retried in the process: back to step 1
   after a backoff from 2 s to 30 s, for up to `Schema.WaitSeconds` from the first such failure,
   and only then does it exit 75. A statement timeout exits 3: raise
   `Schema.MigrationCommandTimeoutSeconds`. Any other failure exits 3. The start timeout is
   extended every 20 s throughout steps 1 to 4.
4. **Verify.** Both databases are read again, and each must now be current.

Both units carry `RestartPreventExitStatus=3`. A refusal therefore leaves the unit failed, with its
reason in the journal, instead of being retried. Status 75 is retried, up to the unit's
`StartLimitBurst` (5 in 300 s). `modularca-signer.service` is ordered after `modularca.service`,
so on a shared host the signer starts once the node has migrated. Enrollment, validation and signer
processes may be started together with control, and they wait for it. To recover from a refusal,
fix the cause and start again, or run the previous release: a dry-run refusal leaves the schema as
the previous release left it. A dump is needed only after a migration failed for real.

### Checking an upgrade before it is installed

`ModularCA.API --upgrade-check [--config-dir <dir>]` runs steps 1 and 2 and the dry run of step 3
as the control role would, then stops. It uses the runtime roles from `db.yaml` and the `Schema`
budgets from `config.yaml`, both read from `--config-dir`, which defaults to the `config/` beside
the binary. It never applies anything: the dry run is rolled back. For each database it prints
the schema (current, the pending list, newer than the build, no history, missing or empty), the
ownership probe and its warnings, and the dry-run result. The last line is a one-line verdict.

| Exit | Verdict line | When |
|---|---|---|
| 0 | `UPGRADE CHECK: PASS (...)` | every pending migration would apply cleanly, or there is nothing to apply (a missing or empty database included) |
| 3 | `UPGRADE CHECK: REFUSED (...)` | anything the start would refuse with 3, a migration that refuses in the dry run, ownership that is not sound even with nothing pending, or a configuration this build cannot use |
| 75 | `UPGRADE CHECK: UNREACHABLE (...)` | a database could not be reached or was locked, or the dry run hit a transient error |

`packaging/install.sh` runs the new build's check on an upgrade, as the service account, against
`/opt/modularca/config`, after it stops the units and before it replaces anything. It runs the build
where it was unpacked if the service account can, and otherwise from a copy in a root-owned
directory beside `/opt/modularca`, which it then removes. A non-zero status starts the stopped
units again on the installed build, and the installer exits with that status, having changed
nothing. `--skip-upgrade-check` skips the check with a warning; the start's own dry run still
applies nothing on a refusal. The `.deb` has no such step. `preinst` runs before the new build is
unpacked, and by `postinst` the old one is gone. So it relies on the start's dry run, and
`postinst` does not run a second rehearsal (`packaging/README-PACKAGING.md`).

The time budgets live in `config.yaml`; these are the defaults:

```yaml
Schema:
  WaitSeconds: 900
  MigrationCommandTimeoutSeconds: 3600
  MigrationLockTimeoutSeconds: 30
```

Take a dump before every upgrade (`pg_dump -Fc` of both databases). It is the recovery path.

### The upgrade test harness

`PostgresUpgradeHarnessTests` in `tests/ModularCA.Tests/Database` is opt-in and skipped unless its
variables are set.

**Fresh baseline.** `MODULARCA_TEST_PG` is a connection string to a server where the user may
create and drop databases. The test creates two throwaway databases and applies the baselines
only. It seeds a 0.3.x shape in SQL written against the baseline schema. Then it migrates one stage
at a time through `SchemaVersionGate.ApplyPendingThroughAsync`, the control role's code stopped at a
named migration. It asserts each stage in SQL at that stage's migration, then migrates to latest
and drops both databases. A later migration that renames a table therefore cannot break an earlier
stage's checks: those checks never run against the renamed schema.

The audit database is seeded at its baseline with hashed records: the instance chain and two
tenant chains, each hashed by the real `AuditHashChainService.ComputeHash`. After the audit database
is migrated, the test seals the retired chains as the control role's start does. It then asserts
that `VerifyAsync` finds no break in any chain and that `CheckRetiredChainAsync` reports every
retired chain `Sealed`. `AuditHashGoldenVectorTests` pins the canonical input itself with
hard-coded hashes. It also pins the persisted strings recorded rows carry: the lock key, the chain
action and target types, the fold migration id, the seal text and its member names, the retired
`AuditActionType` values, the licence keys and the signer audit scope tokens.

```bash
MODULARCA_TEST_PG="Host=localhost;Username=postgres;Password=...;Database=postgres" \
  dotnet test tests/ModularCA.Tests --filter "FullyQualifiedName~PostgresUpgradeHarnessTests"
```

The dry run has its own tests on the same server.

- A 0.3.x database where `InstanceUniqueCaNames` refuses (P1, a label two CAs share). The dry run
  names it with its message, having rehearsed `RetireTenantHostnames` and `FoldSystemTenant`. The
  history still holds only the baseline, `TenantHostnames` and `Tenants.IsSystemTenant` are still
  there, and nothing is renamed. A new connection then takes ACCESS EXCLUSIVE on every table at
  once, and no client session holds a lock. `--upgrade-check` and the control role's start both
  exit 3, and still nothing is applied.
- A `RenameTenantToSpace` refusal raised after that migration's own renames leaves every name as
  it was.
- A clean 0.3.x database passes the dry run unchanged, the audit database has nothing pending,
  `--upgrade-check` exits 0 with the pending count, and the start then migrates it to current.
- The audit dry run on an empty database rehearses the history table and the baseline and leaves
  the database empty.

On SQLite, `SchemaGateMigrationTests` covers the same outcomes without a server, including a
migration outside a transaction that is not rehearsed.

The backup test in `PostgresOwnershipHarnessTests` also needs `pg_dump` and `pg_restore`. It looks
in `MODULARCA_TEST_PG_BIN`, then on PATH, then in the newest `C:\Program Files\PostgreSQL\*\bin`, and
is skipped with that reason when it does not find both.

A later stage that adds a data migration extends the seed with the rows its precondition and
transformation care about, and extends the assertions. For `InstanceUniqueCaNames` (0.4.0 S4) the
test asserts that plain unique indexes on CA `Label` and `Name` exist with no filter, that the
non-unique `IX_CertificateAuthorities_TenantId` backs the foreign key, that the four per-tenant and
instance-only indexes and the three tenant quota columns are gone, and that a space CA cannot take
an instance CA's label nor a CA a deleted CA's name. One further test per precondition seeds an
instance SSH CA labelled like the space's root CA (P1), a second space's root CA labelled the same
(P1), the same with a soft-deleted CA (P1), a
label that differs only in case (P2), a duplicate name (P3), an enabled and a disabled protocol
configuration naming a signing profile that issues from no CA (P4), and the same for certificate
templates (P5), and asserts the message and that nothing of the migration was applied. For `FoldSystemTenant` (0.4.0 S3) the seed
adds a system tenant and an organisation whose CA policies differ, the system signing CA and an SSH
CA with their groups, the system groups, the four `org-system-*` groups (grants, no members), a
Kerberos realm and a custom role on the system tenant, a CA-scoped user grant, a CA-bound profile,
an enrollment token, an executed ceremony whose parameters name the system tenant, and a CA-scoped
service identity. The test asserts that no system tenant and no `IsSystemTenant` column remain, that
every row that named the system tenant now has a null tenant, that the `org-system-*` groups are
gone, that `SecurityPolicy` holds the system tenant's values while the organisation keeps its own,
that the tenant foreign keys are `ON DELETE RESTRICT`, and that the partial unique indexes refuse a
second instance CA with the same label. One further test per precondition (P1 and P3 to P9; P2,
which refused more than one organisation, was dropped) seeds the shape that precondition refuses
and asserts its message and that nothing was applied, and a fresh database migrates without a
`SecurityPolicy` row, which bootstrap then seeds. Another adds a second organisation with its own
policy, root CA, groups, CA-bound profile and open ceremony, and one of each for the first: the
dry run and `--upgrade-check` pass, the control role's start upgrades it, each organisation is a
space with its rows and policy, the instance has the system tenant's policy, and the three
retired audit chains seal and verify. This test runs everything as the
connection's user, so it does not exercise ownership. The rehearsal below does.

For `RenameTenantToSpace` (0.4.0 S6) the seed, added at the stage before it, holds an open ceremony
in every stored parameter shape, written as the legacy fixtures in `CeremonyParametersFixtures`
(PascalCase `TenantId` and `MintedTierTenantId`, camelCase `tenantId`): a controlled-user change, a
CA creation, an SSH CA creation, a CA revocation, and space, instance and per-CA quorum policy
changes, the space ones with operation type `TenantPolicyChange`. It also holds the space's other
`org-acme-*` groups, one with a customised display name, a tenant-wide group whose name does not
follow the slug, and a signer audit row with the old `tenant` scope token. The stage asserts:

- every value in every renamed table is where it was, under the new names;
- no table, column, constraint, constraint definition, index definition, trigger, view or function
  in `public` says tenant;
- each ceremony's parameters equal its 0.4.0 fixture up to key order, and read with the real
  classes with their space ids, an instance policy change with none;
- no `TenantPolicyChange` is left;
- the space's four groups are `space-acme-*`, display names `Space Acme …` unless customised, with
  their members, while the mismatched group keeps its name;
- the signer audit row keeps `tenant`.

At latest, the catalog names exactly what the model names: every table, column, primary, unique,
foreign and check constraint and index, plus the raw `IX_CertificateAuthorities_LabelLower`. An LDAP
mapping that still targets `org-acme-user` then syncs into `space-acme-user`, with a warning. The
audit database is not migrated by S6, and its chains still verify sealed. One further test per
precondition seeds parameters naming a tenant that are not JSON, not an object, or hold both the old
and the new key (P1), and a group whose new name is taken or longer than 200 characters (P2), and
asserts the message and that the tables kept their tenant names.

**Rehearsal on a dump of staging.** Restore staging's dumps into disposable databases with the
ownership staging has, then run the test as the service roles. Restoring as `postgres` with only
`--no-owner` would leave the superuser owning every table, which hides exactly the failure a
migration that alters a table would hit in production. The test migrates the copy in place, so
never point it at a live database.

```bash
psql -h localhost -U postgres -v ON_ERROR_STOP=1 <<'SQL'
CREATE ROLE rehearsal_app LOGIN PASSWORD 'app-secret';
CREATE ROLE rehearsal_audit LOGIN PASSWORD 'audit-secret';
CREATE ROLE rehearsal_audit_owner NOLOGIN;
SQL
createdb -h localhost -U postgres -O rehearsal_app -E UTF8 -T template0 rehearsal_app
createdb -h localhost -U postgres -O rehearsal_audit_owner -E UTF8 -T template0 rehearsal_audit
psql -h localhost -U postgres -d rehearsal_audit -v ON_ERROR_STOP=1 <<'SQL'
GRANT CONNECT ON DATABASE rehearsal_audit TO rehearsal_audit;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO rehearsal_audit;
SQL
pg_restore -h localhost -U postgres -d rehearsal_app --no-owner --no-privileges --role=rehearsal_app staging-app.dump
pg_restore -h localhost -U postgres -d rehearsal_audit --no-owner --no-privileges --role=rehearsal_audit staging-audit.dump
MODULARCA_TEST_PG_REHEARSAL="Host=localhost;Username=rehearsal_app;Password=app-secret;Database=rehearsal_app" \
MODULARCA_TEST_PG_REHEARSAL_AUDIT="Host=localhost;Username=rehearsal_audit;Password=audit-secret;Database=rehearsal_audit" \
  dotnet test tests/ModularCA.Tests --filter "FullyQualifiedName~A_restored_dump_migrates_to_latest"
```

`--role` makes `pg_restore` create every object as that role, so each role owns its tables, as on
staging. `pg_hba.conf` must allow password logins for the two roles from localhost. Drop the two
databases and the three roles afterwards.

It checks that no migration is unknown to the build, and that every pending one applies. Through
`InstanceUniqueCaNames`, the stage before the rename, it also checks that CA, user, membership and
certificate counts are unchanged, that there is one tenant fewer (the system tenant) and four
groups fewer (its `org-system-*` groups), that no group named `org-system-*` remains, that the
`IsSystemTenant` column and the three tenant quota columns are gone, and that the unique `Label` and
`Name` indexes exist. It then migrates to latest, through `RenameTenantToSpace`, and the audit
database too when its variable is set. A staging copy that two CAs share a label or a name on, or
whose enabled protocol configuration or template signs with another CA's profile, fails here with
the `InstanceUniqueCaNames` refusal, and one with a taken `space-<slug>-*` group name fails with the
`RenameTenantToSpace` refusal, which is the point of rehearsing.
