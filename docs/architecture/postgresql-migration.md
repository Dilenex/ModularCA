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
usernames and email addresses, tenant slugs and CA labels as they appear in enrollment URLs,
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
`CREATE EXTENSION IF NOT EXISTS citext` — and bootstrap creates it first anyway, on the privileged
connection that just created the database, so the migration's own copy is a no-op. Leaving it to
the migration alone would work, but only because PostgreSQL 13 marks `citext` trusted and the app
role owns its database; an install should not rest on two facts it never states. This is the one
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
- The server is PostgreSQL 13 or newer — where `citext` became trusted and `DROP DATABASE WITH
  (FORCE)` arrived, which are the two facts the rest of the design rests on.
- `citext` is available in `pg_available_extensions`. Missing contrib is a packaging problem and
  insufficient rights are a permissions problem, and the two failures read nothing alike.
- The administrative role has `CREATEDB` and `CREATEROLE`. Neither is transactional, so neither can
  be tested by trying it and rolling back; the catalogue is the only honest answer.
- Neither target database nor either target role exists, and none of the four names collide with
  each other or with the administrative account.

`--dry-run` stops after all of it. Nothing outside the operator's terminal has changed at that
point, which is what makes the whole preflight readable at a time when acting on it is free.

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
- Row counts per table, source against destination.
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
shifting by the migrating machine's offset — and the enrollment token transform.
