# A restore and a running node never meet

A restore replaces the application database. The deploy guide has always said to stop the node
first; since 0.4.5 the instance enforces it. A restore refuses while a node is serving from the
database, and a node does not start while a restore is running.

Why: on a test bed an orchestrator restarted a pod around a restore. The node started while its
database was being replaced, read a half-way state and wrote over a value the restore had just
stored. Neither process noticed the other. What showed was a spurious "this instance runs from an
earlier or copied state" notice; a node starting in that window could as well have started its
scheduler, or signed a CRL from counters the restore was about to raise.

## The mechanism

PostgreSQL advisory locks in the application database, session-level, under two fixed keys
(`ModularCA.Database.RestoreLock`). No table and no migration: a lock lives in the server's
memory and ends with the connection that took it, so a process that dies releases it.

| Key | Held shared by, for as long as it runs | Taken exclusively by |
|---|---|---|
| `pg_advisory_lock(1296253266, 1)`, the node key | every node process: any of the roles control, enrollment, validation and ingress, with or without the signer in process | a command-line restore; a restore from the console |
| `pg_advisory_lock(1296253266, 2)`, the signer key | a process that is the signer and nothing else (`--role signer`) | a command-line restore |

1296253266 is the ASCII bytes of `MCAR`. Advisory locks are per database, so two instances on one
server never meet. `pg_restore` runs as a child process on connections of its own and is not
affected by them.

Each holder keeps its lock on one **dedicated, unpooled connection** (application name
`ModularCA restore lock`) that no other code is handed. Nothing else in the product takes these
keys: `--upgrade-check` in both forms, `--backup`, `--backup-manifest`, `--db-ownership`,
`--settings`, the claim and token commands and every other one-off command run beside either
kind of holder. A test lists the source files that name the lock.

### Why two keys

The signer service reads its pins from the application database and writes every decision to
`SignerAudit` there, so it must not run through a command-line restore, which also replaces the
keystore files under it: the deploy guide says "the node must be stopped, and on a split install
the signer too". But a restore from the console of a split install goes *through* the running
signer. One key for both would refuse every console restore there. So the signer has a key of its
own, which the command-line restore asks for and the console's restore does not.

## A restore

`BackupRestore.RestoreCoreAsync` takes the lock once the archive has passed its checks and the
databases have answered, and before the confirmation is asked, the pre-restore snapshot is
taken, or anything is changed. It keeps it until the restore ends, however it ends.

- **Command line** (`--restore`): a connection of its own; the node key, then the signer key,
  both exclusive, without waiting. A key that is not granted is asked for again for two seconds,
  which covers a node stopped a moment ago whose session the server has not closed yet, and then
  the restore is refused: exit status **3**, and the last line is one of

      RESTORE: REFUSED (a node is serving from this application database, or another restore is running on it: stop the node, every process of it on every host, or wait for the other restore, then restore again). Nothing was changed.
      RESTORE: REFUSED (the signer service is running on this application database: stop the signer, then restore again). Nothing was changed.

- **Console** (`POST /api/v1/admin/backup/restore`): the restore runs inside a node that holds
  the node key shared. It asks for the same key exclusively *on that same connection*. A session
  never conflicts with itself, so PostgreSQL grants it exactly when no other session holds the
  key: the node does not block itself, and the restore is refused, with HTTP 409 and the reason,
  while another node serves from the same database or another restore runs. When the restore
  ends the exclusive lock is released and the shared one stays. While it runs the node's
  scheduled jobs are held.

- **Two restores at once**: the second cannot have the node key and is refused with 3.

- **The restore's own connection drops**: looked at once more just before the first database is
  replaced; a lock that was lost by then refuses the restore with 3 (`the restore's lock on the
  application database was lost before anything was changed`). After that point the restore goes
  on, and says in its output that the lock was lost and that any node that started meanwhile
  must be checked and restarted.

A database that does not answer when the lock is asked for is `RESTORE: UNREACHABLE`, 75, as it
is everywhere else in the restore.

## A start

The lock is the first thing a start does with the application database
(`SchemaStartup.TakeServingLockAsync`): before the schema check, so before any migration, the
settings, the incarnation comparison and the instance identifier. The signer-only process does
the same with its key before its schema check and before it reads its pins.

| What it finds | What it does |
|---|---|
| The key is free | takes it shared and goes on |
| A restore holds it | logs once that it waits for a restore, asks again every second for up to `Schema.RestoreWaitSeconds` (60), and goes on when the restore ends in that time |
| The restore is still running when the wait is over | exits with status **75**. The last line: `A restore of the application database '<name>' was still running after 60 s (Schema.RestoreWaitSeconds), so this process did not start. Exiting with status 75 so the service manager starts it again; it starts once the restore has finished.` |
| The server does not answer | waits, as the schema check does, for up to `Schema.WaitSeconds`, then exits 75 |
| The database is missing, or refuses the role | goes on without the lock; the schema check, which follows at once, refuses what an operator must fix (status 3) or leaves a missing database to setup recovery. The lock is taken in the background once the database answers |

Status 75 keeps its one meaning: starting the same thing again cures it. `Schema.RestoreWaitSeconds`
is a setting of the host (`config.yaml`, or the signer's `signer.yaml`), read at start; 0 means
do not wait. Setup mode takes no lock: there is no database yet.

## While it runs

Every five seconds the holder checks its connection. This is what makes the lock safe to rely
on, and what it costs when the connection is lost.

- **The connection dropped** (the database restarted, the network blinked). The server released
  the lock with the session. The process logs a warning, and takes the lock again as soon as the
  database answers. `/health/ready` shows `checks.restoreLock.status` = `reconnecting` meanwhile
  and stays healthy on this account: an ordinary database restart does not take a node down.
- **A restore took the key while it was free.** The process is now running beside a restore, and
  what it holds in memory is from before it. It logs an error and **exits with status 75**, node
  and signer alike. It does not wait for a health probe to notice: an install without one would
  go on serving. The packaged units restart on every status but 3 and 4, and a pod's units
  restart always, so it comes back by itself, and that start waits for the restore to finish
  (`Schema.RestoreWaitSeconds`), then exits 75 again until it has.
  - **Where nothing restarts the process** (a node started by hand, or a Windows host with no
    service wrapper that restarts it) it stays stopped until someone starts it. Stopped is the
    safe state here.
  - Between finding the restore and the process ending, `checks.restoreLock.status` is
    `restore_running`, `/health/live` and `/health/ready` answer 503 and the scheduler holds
    every job. `restart_needed` (the restore has finished, the process has not been restarted)
    is the same with the restore over. Both are seen only for a moment in the shipped program;
    they remain for a host that embeds the lock without the exit.

`checks.restoreLock` in `/health/ready`:

    "restoreLock": { "status": "held", "since": "2026-11-13T09:12:04.1Z", "scheduledJobsHeld": false, "detail": null }

`status` is one of `held`, `not_taken` (setup mode, or the database has not answered since the
start), `reconnecting`, `restoring` (a restore started from this node's console is running),
`restore_running` and `restart_needed`. Only the last two are unhealthy.

The signer-only process logs the same events and exits the same way. It has no scheduler and its
health answer does not carry the lock.

## What is not protected

- **Before the node can reach the database.** A node that starts while the database is down, or
  does not exist yet, has no lock until the database answers. It waits for a database that is
  down, so the window is a database that is *missing* or *refuses the role*, where the schema
  check stops the start anyway or setup recovery is about to make the database.
- **Between a dropped connection and the next check**, at most five seconds plus the time the
  database is away. A restore that starts in that gap is not refused. It is noticed while it
  runs (`restore_running`). One that starts *and finishes* inside the gap is not noticed at all.
  A full restore takes longer than the gap on anything but an empty database.
- **A node that is killed without its connection closing**, for instance a host that loses power
  while the database is on another host: the server keeps the session, and the lock, until its
  TCP keepalive gives up. A restore is refused meanwhile, which is the safe side; end the
  session on the server (`pg_terminate_backend`) to go on.
- **A connection pooler in transaction mode** between the product and PostgreSQL gives every
  statement another server session, and a session-level lock means nothing there. The lock's
  connection must reach PostgreSQL directly or through a pooler in session mode.
- **Work already in flight.** The scheduler's hold stops jobs from starting; a job or a request
  that is running when a restore is found is not interrupted.
- **Anything that is not ModularCA.** `pg_restore`, `psql` or a volume snapshot run by hand
  against the database take no lock. The incarnation comparison at the next start is what
  notices those (`rollback-continuity.md`).
- **Bootstrap and reset** (`--bootstrap`, the setup wizard) neither take nor respect the lock.

## The restore's last line, and the incarnation

After the database is restored the restore stores this machine's incarnation in it, so that the
next start is not reported as a rollback. That store is tried four times over seven seconds (1 s,
2 s and 4 s between attempts), each on a new connection. If it still fails the restore is done
all the same, exit status 0, and its last line says so:

    RESTORE: DONE (the audit database was kept; the incarnation was not stored, so the next start shows a roll-back notice). Start the node to apply the restored state.

## Code

`ModularCA.Database/RestoreLock.cs` (the keys, `ServingDatabaseLock`, the command line's
`OwnConnectionRestoreExclusion`), `ModularCA.API/Startup/SchemaStartup.RestoreLock.cs` (the
start), `ModularCA.API/Startup/SignerRole.cs`, `ModularCA.Bootstrap/BackupRestore.cs`
(`TakeExclusionAsync`), `ModularCA.API/HealthChecks/RestoreLockHealthCheck.cs`,
`ModularCA.Core/Services/SchedulerService.cs` (the hold). Tests:
`tests/ModularCA.Tests/Database/PostgresRestoreLockTests.cs` on real connections,
`tests/ModularCA.Tests/Bootstrap/RestoreExclusionTests.cs`, and the restore drills under
`tests/ModularCA.Tests/DisasterRecovery` with the real program.
