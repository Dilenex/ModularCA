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

**One migration per context.** A clean install applies a single `InitialCreate` for the
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
4. The helper, and a rehearsal of the whole path against a copy of the staging database.
5. A rehearsal against a copy of production before anything touches production.
