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
3. The case-sensitivity decision, applied per column, with tests that fail if a lookup becomes
   case-sensitive where it was not.
4. The helper, and a rehearsal of the whole path against a copy of the staging database.
5. A rehearsal against a copy of production before anything touches production.
