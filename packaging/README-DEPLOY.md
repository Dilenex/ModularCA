# ModularCA — Linux x64 distribution

Self-contained `linux-x64` build. No .NET runtime is required on the target.

    sudo ./install.sh

## What is in here

| Path | |
|---|---|
| `ModularCA.API` | The service. Native ELF apphost; the systemd unit runs it directly. |
| `ModularCA.Keystore.Unlocker` | Break-glass keystore CLI. Separate binary on purpose — it exists for when the service will not start, so it must not depend on the service's hosting or configuration. |
| `wwwroot/` | The five built SPAs: admin, user, public, setup, docs. |
| `config/*.example` | Templates. `install.sh` copies them in only on a first install and never over a real config. |
| `deploy/` | systemd units, per-role unit drop-ins (`dropins/`), plus nginx and nftables templates. `install.sh` installs both units in `/etc/systemd/system/` (`modularca-signer.service` is not enabled); the rest are examples to apply by hand from the extracted archive. |
| `share/sql/adopt-ownership.sql` | The one-time schema-ownership repair for installs made before 0.4.0, run as the PostgreSQL superuser. `install.sh` installs it root-owned to `/usr/share/modularca/sql/`, never into `/opt/modularca`. |

## Permissions are set by the installer, not the archive

This archive is **built on Windows**, so it carries no Unix permission bits and no executable
flags. `install.sh` sets them explicitly (the `.deb`'s `postinst` sets the same):

- **Program files belong to root.** `/opt/modularca` itself and everything the build ships into
  it (binaries, libraries, `wwwroot/`) are `root:root`, directories and the three executables
  (`ModularCA.API`, `ModularCA.Keystore.Unlocker`, `modularca-migrate`) `0755`, everything else
  `0644`. No service account can replace a binary, which matters most on a split install, where the
  signer runs the same binaries as the node.
- **The service account owns only the runtime directories**, the four the service writes:
  `config/` (`0700`; configuration, credentials, the web TLS certificate, the data-protection keys
  in `config/dp-keys/`, backup keys), `keystores/` (`0700`; the CA private keys, and the SSH CA
  keys in `ssh-ca.keystore`),
  `logs/` (`0750`) and `backups/` (`0700`; scheduled backups and the audit archive). The unit's
  `ReadWritePaths=` names the same four, and everything else under `/opt/modularca` is read-only
  to the service.
- **A runtime directory is set up once.** The installer creates one that is missing, owned by
  `modularca` with the mode above, and hands over one still owned by root. After that it never
  changes its ownership, its mode or anything in it, on any run; the service writes its secrets
  there owner-only itself. On a split install the signer keeps `keystores/` and `keystore.yaml` across every
  upgrade (see "Two units" below).
- **The signer's own directory, `signer/`, is never the installer's.** On a split install the
  operator creates it for `modularca-signer`; `install.sh` and the `.deb` never create it, copy into
  it, chown or chmod it, and warn when it belongs to anyone else. It is not in the node unit's
  `ReadWritePaths=`.
- `/usr/share/modularca/sql/adopt-ownership.sql` → `root:root 0644`. It is run as the PostgreSQL
  superuser, so it must not live where the service account can rewrite it.

If you point `Backup.OutputPath`, `AuditRetention.ArchivePath` or
`Logging.FilePath` at a directory outside these four, create it owned by `modularca` and add it to
`ReadWritePaths=` in a drop-in (`/etc/systemd/system/modularca.service.d/paths.conf`). `install.sh`
warns about any top-level entry in `/opt/modularca` that `modularca` owns and the build does not
ship, and leaves it as it is. The command-line `--backup` writes its archive to `Backup.OutputPath`
(`backups/` by default), as the console and the scheduler do; a path given on the command line
must also lie inside `/opt/modularca`. A restore writes its pre-restore snapshot to the same
directory:

    sudo -u modularca /opt/modularca/ModularCA.API --backup

Extracting the tarball and running the binary directly, without the installer, gives you a
non-executable apphost and world-readable secrets. Use the installer.

## First install

1. Create the PostgreSQL cluster (14 or later) and a superuser credential for setup. It must be a
   real `SUPERUSER`: bootstrap checks this first and refuses a role that only has `CREATEDB` and
   `CREATEROLE`. It is used only during setup, and `setup-database.yaml` is deleted afterwards.
   Bootstrap creates the app and audit roles and then logs in as them to build the schema, so
   `pg_hba.conf` must allow password logins for both from this host, as the service needs anyway.
   It also revokes PUBLIC's rights on both databases. A monitoring role needs its own
   `GRANT CONNECT ON DATABASE`.
2. Fill in `/opt/modularca/config/setup-database.yaml` from the `.example`.
3. `sudo systemctl enable --now modularca`
4. Complete the setup wizard. It is reachable only while the install is unconfigured and closes
   itself when finished.

The wizard prints a one-time setup token to the service log:

    journalctl -u modularca | grep -i "setup token"

## Upgrading

Re-run `install.sh`. It stops `modularca` and `modularca-signer` if they are running, then runs
the **new** build's `--upgrade-check` (below) as the service account against the installed
`config/`, before it replaces anything. If the check does not pass, it prints the check's report
and "the upgrade would be refused; nothing was changed", starts again the units it stopped, on
the build still installed, and exits with the check's status (3 refused, 75 a database could not
be reached). If it passes, it replaces binaries and `wwwroot`, gives them to root, leaves the
runtime directories (`config/`, `keystores/`, `logs/`, `backups/`) exactly as they are, ownership
and modes included, and starts again the units that were running. Database migrations are applied by the
service when it starts. A fresh install (no `config/db.yaml`) has nothing to check.

If `install.sh` fails partway, it says the install is INCOMPLETE. Before it began replacing files
it starts the stopped units again on the installed build. Once it has begun, it leaves them
stopped, since `/opt/modularca` may hold a partly copied build: restore `/opt/modularca` from your
backup, or fix the cause and run `install.sh` again, then start the units it names yourself (a
re-run finds them stopped and leaves them stopped).

`sudo ./install.sh --skip-upgrade-check` installs without the check, with a warning. Use it only in
an emergency, such as a database you cannot reach from this host during the install. The service
still dry-runs every pending migration when it starts and applies nothing if one refuses, but it
then exits 3 on the new build, and going back means reinstalling the previous tarball.

Take a backup first — the CA private keys are the part you cannot recreate. Dump both databases
too (`pg_dump -Fc`); the dump is how you go back if a migration cannot be completed.

### Checking an upgrade before installing it

    sudo -u modularca <new build>/ModularCA.API --upgrade-check --config-dir /opt/modularca/config

`install.sh` runs exactly this. Run it as the service account, never as root, from a directory
that account can read. The tarball carries no executable bits, so `install.sh` copies the build
into a root-owned directory beside `/opt/modularca` first. `--config-dir` names the installed
configuration; without it the binary reads the `config/` beside itself. The check uses `db.yaml`'s
runtime roles, as the service does, and the `Schema` time budgets in `config.yaml`. For each
database it reports the schema (current, pending migrations, newer than the build, no history,
missing), the ownership probe and its warnings, and a **dry run**: every pending migration, history
inserts included, in one transaction that is then rolled back. The last line is the verdict:

| Exit | Verdict | Meaning |
|---|---|---|
| 0 | `UPGRADE CHECK: PASS` | every pending migration would apply cleanly, or nothing is pending |
| 3 | `UPGRADE CHECK: REFUSED` | a migration refuses (each refusal named, with its message), the schema is newer than the build, ownership is not sound, or the configuration cannot be used |
| 75 | `UPGRADE CHECK: UNREACHABLE` | a database could not be reached, or was locked; try again |

It applies nothing. While its dry run runs, it holds the locks the migrations take, as the upgrade
itself would, so run it with the units stopped, as `install.sh` does, on a large database.

The dry run does not stop at the first refusal. It runs each statement under its own savepoint,
so one run lists every precondition that refuses, in every pending migration, and you can fix them
all before checking again. The report numbers them ("1 of 3") and quotes each message as the
migration raises it. Exit 0 means every statement of every pending migration ran; if the check
had to skip a statement or could not reach one, it exits 3. The other wording:

- **"also found"** marks every refusal after the first. Each is real on the data as it is now, but
  its outcome may change once the earlier ones are fixed. For example, two CAs with the same label
  also share it up to case, so `InstanceUniqueCaNames` P1 and P2 both list them; renaming one CA
  fixes both.
- **"Skipped: the rest of migration X"** follows a refusal whose migration then failed on a later
  statement, typically because that statement needs the refusal fixed, as a unique index needs the
  duplicates gone. Those steps are checked once the refusal is fixed.
- **"Stopped: ... The checks after this point could not run"** is an error that is not a refusal.
  The check cannot go on past it, so migrations after it were not checked; "which may follow from
  the steps skipped above" says it is likely a consequence of a skip. Fix what is listed and check
  again to see the rest.

The service's own dry run at start (below) lists the same, in the journal.

### What the service checks when it starts

Before it serves anything, the service reads both databases as its own roles and decides; see
"At startup" in `docs/architecture/postgresql-migration.md` for the full sequence. What an
operator sees:

| Outcome | Exit status | What happens |
|---|---|---|
| Everything current, or the control role dry-ran and then applied the pending migrations | — | starts |
| Database unreachable, locked by a migration, or (enrollment, validation, signer) waiting for the control role's migrations | — then **75** | waits up to `Schema.WaitSeconds` (900 s), then exits and systemd retries |
| The dry run or a migration failed on a lock timeout, a deadlock or a lost connection | — then **75** | retried in the service with backoff for up to `Schema.WaitSeconds`, then exits and systemd retries |
| A pending migration refuses in the dry run | **3** | nothing applied to either database; the journal lists every refusal of both databases, each with its migration and message |
| Schema newer than this build, tables without history, wrong password, `pg_hba.conf` refusal, TLS failure, tables the runtime role does not own, a migration that failed for good, PostgreSQL older than 14 | **3** | not retried (`RestartPreventExitStatus=3`); the journal says why and prints the fix |

The control role applies nothing it has not rehearsed. Before the first migration it runs every
pending migration of both databases in one transaction per database and rolls it back. One refusal
anywhere stops the start with nothing applied, so a precondition in the fourth migration can no
longer leave the first three applied and the database half-upgraded. The dry run still reports
every refusal it finds, as `--upgrade-check` does; the apply, when it runs, stops at its first
error. PostgreSQL DDL is
transactional, so the rehearsal runs the same statements as the real apply. A migration that would
have to run outside a transaction cannot be rehearsed. The service refuses it as a defective build,
and the migration lint keeps one from being written.

    journalctl -u modularca -n 100

After fixing the cause, `sudo systemctl start modularca`. A failed start also counts against the
unit's start limit, so reset it first with `sudo systemctl reset-failed modularca` if systemd
says the start request was repeated too quickly.

To check schema ownership read-only at any time, as the service user and never as root:

    sudo -u modularca /opt/modularca/ModularCA.API --db-ownership check

It exits 0 when both databases are sound and 3 when not, and prints what it found and the repair.

### Upgrading to 0.4.0

0.4.0 renames tenants to spaces in the schema, and every role reads those tables. A node, ingress
or signer still running an older build queries the old names: it fails as soon as the control role
has migrated, and while it runs it can hold the locks a migration waits for. **Stop every node and
the signer, on every host, before the control role upgrades**, and start the others only once it
has.

#### Checklist

Follow it in order, on staging first and then on production. Nothing in it changes the database
until the control role starts on 0.4.0, and even that applies nothing unless every migration
passes its dry run. `install.sh` runs the same dry run before it replaces anything
(`--upgrade-check`, above), so the SQL in step 2 is an optional preview: it needs only the build
you run now, and can be run before the tarball is even copied to the host. An install already on a
0.4.0 pre-release has passed the checks of the stages it has.

1. **Back up.** Take the usual backup (the keystores and `config/` are what you cannot recreate),
   then dump both databases. The dumps are the only way back: no 0.4.0 migration has a downgrade.

       sudo -u postgres pg_dump -Fc -d '<app database>' -f ~postgres/modularca-app-pre-0.4.0.dump
       sudo -u postgres pg_dump -Fc -d '<audit database>' -f ~postgres/modularca-audit-pre-0.4.0.dump

2. **Optionally, preview with the read-only pre-checks** in `sudo -u postgres psql -X -d '<app database>'`. Each one
   mirrors a migration precondition, named in its label, and passes when it returns no rows; check
   n passes when it prints no notice. The first line makes the session read-only. What each one
   guards is under "What changes" below. On an install already on a 0.4.0 pre-release, a check
   that names `Tenants`, `TenantHostnames` or `IsSystemTenant` fails with "does not exist" once its
   migration has run, and can be skipped.

   ```sql
   SET default_transaction_read_only = on;
   -- a. RetireTenantHostnames: tenant hostnames
   SELECT "Hostname" FROM "TenantHostnames";
   -- b. FoldSystemTenant P1: exactly one system tenant, soft-deleted ones counted, unless there are no tenants
   SELECT (SELECT count(*) FROM "Tenants" WHERE "IsSystemTenant") AS system_tenants
    WHERE (SELECT count(*) FROM "Tenants" WHERE "IsSystemTenant") > 1 OR ((SELECT count(*) FROM "Tenants" WHERE "IsSystemTenant") = 0 AND EXISTS (SELECT 1 FROM "Tenants"));
   -- d. FoldSystemTenant P3: at most one security policy row
   SELECT "Id", "UpdatedAt" FROM "SecurityPolicy" WHERE (SELECT count(*) FROM "SecurityPolicy") > 1;
   -- e. FoldSystemTenant P4: open ceremonies naming the system tenant
   SELECT "Id", "OperationType", "Status" FROM "KeyCeremonies"
    WHERE "Status" IN ('Pending', 'Approved') AND ("TenantId" = (SELECT "Id" FROM "Tenants" WHERE "IsSystemTenant")
       OR strpos(lower("ParametersJson"), (SELECT "Id" FROM "Tenants" WHERE "IsSystemTenant")::text) > 0);
   -- f. FoldSystemTenant P5: capability grants and role assignments held directly across the whole system tenant
   SELECT 'grant' AS kind, "Id" FROM "UserCapabilityGrants"
    WHERE "TenantId" = (SELECT "Id" FROM "Tenants" WHERE "IsSystemTenant") AND "CertificateAuthorityId" IS NULL
   UNION ALL SELECT 'role assignment', "Id" FROM "RoleAssignments"
    WHERE "GroupId" IS NULL AND "TenantId" = (SELECT "Id" FROM "Tenants" WHERE "IsSystemTenant") AND "CertificateAuthorityId" IS NULL;
   -- g. FoldSystemTenant P6: service identities scoped to the whole system tenant
   SELECT "Username" FROM "Users"
    WHERE "ServiceScopeTenantId" = (SELECT "Id" FROM "Tenants" WHERE "IsSystemTenant") AND "ServiceScopeCaId" IS NULL;
   -- h. FoldSystemTenant P7: members and badge sources of the system tenant's tenant-wide groups
   SELECT g."Name", count(DISTINCT m."UserId") AS members, count(DISTINCT s."Id") AS badge_sources
     FROM "CaGroups" g LEFT JOIN "CaGroupMembers" m ON m."GroupId" = g."Id"
     LEFT JOIN "AccessBadgeSources" s ON s."SourceId" = g."Id"
    WHERE g."TenantId" = (SELECT "Id" FROM "Tenants" WHERE "IsSystemTenant") AND NOT g."IsSystemGroup" AND g."CertificateAuthorityId" IS NULL
    GROUP BY g."Id", g."Name" HAVING count(m."Id") + count(s."Id") > 0;
   -- i. FoldSystemTenant P8: groups whose tenant does not exist, or whose tenant differs from their CA's, next to the system tenant
   SELECT g."Name" FROM "CaGroups" g LEFT JOIN "CertificateAuthorities" ca ON ca."Id" = g."CertificateAuthorityId"
    WHERE NOT EXISTS (SELECT 1 FROM "Tenants" t WHERE t."Id" = g."TenantId")
       OR (g."TenantId" <> ca."TenantId" AND (g."TenantId" = (SELECT "Id" FROM "Tenants" WHERE "IsSystemTenant") OR ca."TenantId" = (SELECT "Id" FROM "Tenants" WHERE "IsSystemTenant")));
   -- j. FoldSystemTenant P9: certificate profiles on the system tenant bound to no CA
   SELECT "Name" FROM "CertProfiles"
    WHERE "TenantId" = (SELECT "Id" FROM "Tenants" WHERE "IsSystemTenant") AND "CertificateAuthorityId" IS NULL AND NOT "IsCaProfile";
   -- k. InstanceUniqueCaNames P1, P2, P3: CA labels shared exactly or up to case, or names shared, deleted CAs included
   SELECT 'label' AS clash, ca."Label"::text AS value, string_agg(ca."Name"::text, ', ') AS cas
     FROM "CertificateAuthorities" ca WHERE ca."Label" IS NOT NULL GROUP BY ca."Label"::text HAVING count(*) > 1
   UNION ALL SELECT 'label, any case', lower(ca."Label"), string_agg(ca."Label"::text || ' (' || ca."Name"::text || ')', ', ')
     FROM "CertificateAuthorities" ca WHERE ca."Label" IS NOT NULL GROUP BY lower(ca."Label") HAVING count(*) > 1
   UNION ALL SELECT 'name', min(ca."Name"::text), string_agg(coalesce(ca."Label"::text, '-'), ', ')
     FROM "CertificateAuthorities" ca WHERE ca."Name" IS NOT NULL GROUP BY ca."Name" HAVING count(*) > 1;
   -- l. InstanceUniqueCaNames P4: protocol configurations signing with another CA's profile
   SELECT ca."Label", pc."Protocol", sp."Name" FROM "CaProtocolConfigs" pc
     JOIN "CertificateAuthorities" ca ON ca."Id" = pc."CaId" JOIN "SigningProfiles" sp ON sp."Id" = pc."SigningProfileId"
    WHERE pc."IsEnabled" AND NOT ca."IsDeleted" AND NOT ca."IsSshCa"
      AND (sp."IssuerId" IS NULL OR sp."IssuerId" <> ca."CertificateId");
   -- m. InstanceUniqueCaNames P5: certificate templates signing with another CA's profile
   SELECT ct."Name", ca."Label", sp."Name" FROM "CertificateTemplates" ct
     JOIN "CertificateAuthorities" ca ON ca."Id" = ct."CaId" JOIN "SigningProfiles" sp ON sp."Id" = ct."SigningProfileId"
    WHERE ct."IsEnabled" AND NOT ca."IsDeleted" AND NOT ca."IsSshCa"
      AND (sp."IssuerId" IS NULL OR sp."IssuerId" <> ca."CertificateId");
   -- n. RenameTenantToSpace P1: ceremonies whose stored parameters name a tenant but are not a JSON object
   --    with one tenant key each; a NOTICE lists them, and nothing prints when there are none
   DO $$
   DECLARE
       r record;
       t text;
       n text;
       j jsonb;
       bad text := '';
   BEGIN
       FOR r IN SELECT k."Id", k."Status", k."ParametersJson" FROM "KeyCeremonies" k
                WHERE strpos(lower(k."ParametersJson"), 'tenantid') > 0 ORDER BY k."Id"
       LOOP
           t := r."ParametersJson";
           LOOP
               n := regexp_replace(t, '(^|[^\\])((\\\\)*)\\u0000', '\1\2\\ufffd', 'g');
               EXIT WHEN n = t;
               t := n;
           END LOOP;
           BEGIN
               j := t::jsonb;
           EXCEPTION WHEN data_exception THEN
               j := NULL;
           END;
           IF j IS NULL OR jsonb_typeof(j) <> 'object'
              OR (SELECT count(*) FROM jsonb_object_keys(j) jk WHERE lower(jk) IN ('tenantid', 'spaceid')) > 1
              OR (SELECT count(*) FROM jsonb_object_keys(j) jk WHERE lower(jk) IN ('mintedtiertenantid', 'mintedtierspaceid')) > 1 THEN
               bad := bad || CASE WHEN bad = '' THEN '' ELSE ', ' END || r."Id"::text || ' (' || r."Status" || ')';
           END IF;
       END LOOP;
       IF bad <> '' THEN
           RAISE NOTICE 'Ceremonies whose parameters 0.4.0 cannot rename: %', bad;
       END IF;
   END $$;
   -- o. RenameTenantToSpace P2: org-<slug>-* groups whose space-<slug>-* name is taken or too long; the
   --    system tenant is left out, and so are its tenant-wide groups, which FoldSystemTenant deletes first
   SELECT r."Name", r.new_name FROM (
     SELECT g."Id", g."Name", 'space-' || s."Slug"::text || '-' || x.suffix AS new_name,
            regexp_replace(g."DisplayName", '^(Org|Organisation|Organization) ', 'Space ') AS new_display
       FROM "CaGroups" g
       JOIN "Tenants" s ON s."Id" = g."TenantId" AND NOT s."IsSystemTenant"
       CROSS JOIN (VALUES ('admin'), ('operator'), ('auditor'), ('user')) AS x(suffix)
      WHERE g."CertificateAuthorityId" IS NULL
        AND lower(g."Name"::text) = lower('org-' || s."Slug"::text || '-' || x.suffix)) r
    WHERE length(r.new_name) > 200 OR length(r.new_display) > 300
       OR EXISTS (SELECT 1 FROM "CaGroups" o WHERE lower(o."Name"::text) = lower(r.new_name)
          AND o."Id" NOT IN (SELECT g."Id" FROM "CaGroups" g WHERE g."TenantId" = (SELECT "Id" FROM "Tenants" WHERE "IsSystemTenant") AND NOT g."IsSystemGroup" AND g."CertificateAuthorityId" IS NULL));
   ```

   Then, on every host, look for the configuration keys 0.4.0 renames or retires:

       sudo grep -nE '^\s*(TenantId|AllowMultipleOrganizations)\s*:' /opt/modularca/config/config.yaml
       sudo grep -n 'org-' /opt/modularca/config/config.yaml

   Leave a `TenantId` under `IntegrationApi` or `CertManager` that names an organisation tenant
   as it is until after the upgrade: the build you run now ignores `SpaceId`, so renaming it first
   would leave that API key unscoped. 0.4.0 reads it as `SpaceId`, and the organisation keeps its
   id as a space.

   A `TenantId` that names the **system tenant** is different. 0.4.0 folds the system tenant into
   the instance and deletes it, so its id names nothing and the key would reach no CA: every
   request it makes would fail, with no error at start. `--upgrade-check` refuses while one is
   configured, naming the key. The system tenant's id is what this prints (in the same psql
   session):

   ```sql
   SELECT "Id" FROM "Tenants" WHERE "IsSystemTenant";
   ```

   For such a key, replace `TenantId: <id>` with `SpaceId: instance` in step 3, once the units are
   stopped. From 0.4.0, `SpaceId` takes a space's id (that space's CAs), `instance` (the instance's
   CAs, which the system tenant's CAs become) or nothing (every space and the instance); any other
   value reaches no CA. Do not set both keys: differing values stop the service. Do not make the
   change earlier: the build you run now ignores `SpaceId`, so while it runs that key is unscoped.
   If the upgrade is refused and the previous build is started again, the key stays unscoped until
   the upgrade succeeds; set that section's `Enabled: false` meanwhile if that matters.

   Note the `org-<slug>-*` names in `LdapAuth.GroupToRoleMappings` for step 7. A mapping to an
   `org-system-*` group must be removed or repointed before upgrading (see "The `org-system-*`
   groups are empty" under "What changes").

3. **Stop every unit, on every host**: control, enrollment and validation, ingress, and the signer.

       sudo systemctl stop modularca modularca-signer
       systemctl is-active modularca modularca-signer     # both inactive

   Then, on each host whose `config.yaml` scopes an integration key to the system tenant, replace
   that `TenantId` with `SpaceId: instance` (step 2).

4. **Install on the control host and start the control role alone.** `install.sh` first runs the
   new build's `--upgrade-check`, which dry-runs all four migrations; if any refuse, it lists every
   precondition that refuses and what each found, changes nothing and exits 3. Fix the data with
   the build you run now and run `install.sh` again; if the report says checks could not run, the
   next run may find more. `install.sh` starts nothing when nothing was running; the
   `.deb` upgrade from 0.3.x starts `modularca` itself (see below), which on the control host is
   this step.

       sudo systemctl start modularca
       journalctl -u modularca -n 200 --no-pager

   The journal reports the dry run, then names each migration applied: `RetireTenantHostnames`,
   `FoldSystemTenant`, `InstanceUniqueCaNames` and `RenameTenantToSpace` on a 0.3.x database. A
   refusal stops the service with status 3, and the journal lists every refusal, each with the
   migration, the precondition and what it found. Nothing is applied to either database: the dry run catches a refusal in any of the four
   before the first is applied. Fix it and start again, or run the previous release.
   An install made by the wizard or `--bootstrap` before 0.4.0 is refused for ownership first;
   repair it as below. Expect warnings for a legacy `TenantId` key, a retired
   `AllowMultipleOrganizations` and each LDAP mapping to an `org-*` group.

5. **Start the other units** once the control role is up: the signer, then each enrollment,
   validation and ingress host, upgraded the same way.

       sudo systemctl start modularca-signer

6. **Verify.** `/health/ready` on every process reports ready. As a system admin, check the audit
   chains:

       curl -s -H "Authorization: Bearer <access token>" https://<host>/api/v1/admin/audit/verify/chains

   The instance chain reports `Integrity` `Valid` (or `PartiallyVerifiable` for records written
   before the hash was versioned) and `BreakCount` 0. Each retired chain reports `Sealed` true and
   `TailState` `Sealed`; nothing else is acceptable. Audit retention never deletes a seal, and it
   carries each succession record forward before pruning the instance chain, so `TailMissing` or
   `TailAltered` means the retired chain was tampered with: stop and investigate before going on.
   `Unsealed` means the control role has not sealed the retired chains yet; check its start log.
   Under Spaces, each space is listed, and its groups are named `space-<slug>-*`.

7. **Tidy the configuration**, on every host, then restart that host's units. Rename
   `IntegrationApi.TenantId` and `CertManager.TenantId` to `SpaceId`, delete
   `Features.AllowMultipleOrganizations` and `Ingress.RouteRefreshSeconds`, and change each
   mapping to an organisation's `org-<slug>-*` group to its `space-<slug>-*` name. There is no
   `space-system-*` group, and the slug `system` is reserved, so no space can have one: a mapping
   to an `org-system-*` group was removed or repointed before the upgrade (step 2), and one still
   there maps to nothing. On the control host, saving the
   settings in the console writes `SpaceId` and drops the retired key, and a super's save of the
   LDAP settings rewrites the group mappings. The warnings stop once nothing is left. Then delete
   `config/tenant-tls/`.

#### What changes

- **Installs built by `modularca-migrate`**, which is every install that came from MariaDB 0.3.0,
  and production and staging: nothing to do. The runtime roles already own their schemas, and the
  service confirms it on every start.
- **PostgreSQL installs made by the setup wizard or `--bootstrap` before 0.4.0.** The superuser owns
  their tables, and the service refuses to start (status 3) until ownership is repaired once. The
  `.deb` does the repair itself when PostgreSQL is local: see `README-PACKAGING.md`. For a tarball
  install, or a database on another host, run the commands the refusal prints on the database host,
  with both units stopped. They are also in `docs/architecture/postgresql-migration.md`:

      sudo systemctl stop modularca modularca-signer
      sudo -u postgres psql -X -d '<app database>' -v kind=app -v target='<app role>' -f /usr/share/modularca/sql/adopt-ownership.sql
      sudo -u postgres psql -X -d '<audit database>' -v kind=audit -v target='<audit role>' -f /usr/share/modularca/sql/adopt-ownership.sql
      sudo systemctl start modularca

  Run the file from `/usr/share/modularca/sql`, or from the tarball's `share/sql` on a host
  without the install. Never run it from a copy under `/opt/modularca`, which the service account
  can rewrite.
- **Program files are root's.** Before 0.4.0 the installer and `postinst` gave all of
  `/opt/modularca` to `modularca`; from 0.4.0 they give the program files to root and leave the
  service account only `config/`, `keystores/`, `logs/` and `backups/` (see "Permissions are set by
  the installer"). The packaged unit's `ReadWritePaths=` is narrowed to those four. A tarball
  install keeps an `/etc/systemd/system/modularca.service` that differs from the packaged one, so it
  keeps `ReadWritePaths=/opt/modularca`, which still works; replace it with the packaged copy to
  narrow it. A configured path outside the four needs a drop-in, as described there.
- **The `.deb` upgrade from 0.3.x, once.** The 0.3.x package's `prerm` stops `modularca` and records
  nothing, and dpkg runs it before any script of the new package, so not even the new `preinst`
  can see whether the node was running. On this one upgrade `postinst` therefore starts `modularca`
  whenever it is enabled, even if an operator had stopped it, and restarts `modularca-signer` only
  if it was running. If the node was stopped on purpose, stop it again afterwards
  (`sudo systemctl stop modularca`), or `systemctl disable modularca` before upgrading. From 0.4.0
  on, `prerm` records which units were running and the upgrade starts exactly those.
- **The `.deb` has no installer-side upgrade check.** Its `preinst` runs before the new binary is
  unpacked, and by `postinst` dpkg has already replaced the old one, so a refusal there could not
  keep the installed build. The `.deb` relies on the service's own dry run when it starts, which
  applies nothing on a refusal. `postinst` does not run `--upgrade-check` either: it would hold the
  migrations' locks for a second full rehearsal inside dpkg, moments before the service's own,
  and could change nothing. To check before installing, unpack the package and run the check from
  the unpacked copy. **Stop the `modularca` units first, on this host and on every other host that
  shares the database** (step 3): the dry run takes `ACCESS EXCLUSIVE` locks on tables every unit
  uses, and holds them until it rolls back, so running units stall behind it, or hold locks it
  then waits on. `install.sh` stops its own host's units before its check for the same reason;
  the other hosts are yours to stop.

      sudo systemctl stop modularca modularca-signer      # here and on every host sharing the database
      d=$(sudo mktemp -d /opt/.modularca-deb-check.XXXXXX) && sudo dpkg-deb -x modularca_<version>_amd64.deb "$d"
      sudo chmod -R go+rX "$d" && sudo chmod 0755 "$d/opt/modularca/ModularCA.API"
      sudo -u modularca "$d/opt/modularca/ModularCA.API" --upgrade-check --config-dir /opt/modularca/config
      sudo rm -rf "$d"

  If the check passes, install the package. It starts only the units it found running (on the
  upgrade from 0.3.x, `modularca` whenever it is enabled, above), and you stopped them for the
  check, so afterwards start each unit you stopped by hand that is not running, here and on every
  other host, the node before the signer:

      sudo systemctl start modularca
      sudo systemctl start modularca-signer      # where this host runs it

  If it refuses, start the units again on the installed build, fix what it names, and check again.
- **Tenant hostnames are gone.** 0.4.0 serves only the instance's own names, under its web TLS
  certificate. Its first migration, `RetireTenantHostnames`, drops the `TenantHostnames` table and
  refuses (status 3, nothing applied) while the table has any row (check a); the journal says how
  many. Before upgrading, delete every name under Tenants, Hostnames with the build you run now, or
  serve those names through the instance's public domain or a reverse proxy in front of it. The
  `Ingress.Routes` in `config.yaml` are unaffected; `Ingress.RouteRefreshSeconds` is no longer
  read and can be removed.

  The certificates those names were served under stay on disk, one PKCS#12 file per name under
  `config/tenant-tls/` in the install directory (`/opt/modularca/config/tenant-tls/*.pfx`),
  protected by `Https.CertificatePassword`. Nothing reads them any more, and neither the upgrade
  nor the package removes them. Once the upgrade has succeeded they can be deleted:

      sudo rm -r /opt/modularca/config/tenant-tls

- **The system tenant is folded into the instance.** The `FoldSystemTenant` migration moves the
  system signing CA, SSH CAs, the system groups and those CAs' groups to the instance (no space),
  copies the system tenant's CA policy to the security policy as it is, and deletes the tenant and
  its four tenant-wide `org-system-*` groups. Every organisation tenant becomes a space, however
  many there are, with its CAs, groups, profiles and policy as they were. It changes nothing and
  stops the service (status 3, the journal names the precondition and what it found) unless all of
  these hold (checks b and d to j; there is no check c):
  - **No open ceremony names the system tenant.** Execute or cancel every Pending or Approved
    ceremony on a system CA (the system signing CA, an SSH CA) or on the System tenant's policy,
    and every controlled-user ceremony on those. The migration never rewrites a ceremony.

    0.3.x cancels only a Pending ceremony, and only for its initiator. An **Approved** ceremony
    that can no longer be executed (its target is gone, or executing it fails) therefore keeps
    check e refusing, with no way out in the console. Find those with this read-only query, in a
    `psql` session on the application database (`SET default_transaction_read_only = on;` first,
    as in step 2):

    ```sql
    SELECT "Id", "OperationType", "TargetEntityId", "InitiatedByUsername", "CreatedAt", "CurrentApprovals"
      FROM "KeyCeremonies"
     WHERE "Status" = 'Approved' AND ("TenantId" = (SELECT "Id" FROM "Tenants" WHERE "IsSystemTenant")
        OR strpos(lower("ParametersJson"), (SELECT "Id" FROM "Tenants" WHERE "IsSystemTenant")::text) > 0);
    ```

    Try to execute each one first. For one that cannot be executed, and only then, mark it
    Cancelled by hand. **Take the dumps of step 1 first**, stop every unit (step 3), and change
    one ceremony at a time, by id, in a session that is not read-only:

    ```sql
    BEGIN;
    UPDATE "KeyCeremonies" SET "Status" = 'Cancelled' WHERE "Id" = '<ceremony id>' AND "Status" = 'Approved';
    -- expect UPDATE 1; anything else: ROLLBACK;
    COMMIT;
    ```

    `Cancelled` is the status 0.3.x gives a cancelled ceremony, and nothing else changes. Unlike a
    cancel in the console, this writes no `KeyCeremonyCancelled` audit record: note who did it,
    when and why in your change record.
  - **The `org-system-*` groups are empty.** Move each member of `org-system-admin`,
    `org-system-operator`, `org-system-auditor` and `org-system-user` to the system group that
    fits (`system-admin`, `system-operator`, `system-auditor`) or to a CA's group, and edit any
    access badge that names one of them. Their grants and roles are deleted with them.

    With LDAP login on, check `LdapAuth.GroupToRoleMappings` first (step 2's `grep -n 'org-'`). A
    0.3.x mapping from a directory group to an `org-system-*` group adds its members back at their
    next login, so check h keeps refusing however often the group is emptied. Remove each such
    mapping, or point it at the `system-*` group or CA group the members were moved to, in
    `config.yaml` on every host or in the console's LDAP settings, and only then empty the
    groups. If the `org-system-*` mappings are the only ones, repoint them rather than remove
    them: with no mapping left, 0.3.x matches directory group names to ModularCA group names
    directly, which changes who gets which group at the next login. There is no `space-system-*` group to rename such a mapping to after the upgrade.
  - **Nothing on the system tenant would become instance-wide.** Remove capability grants and
    role assignments given to users directly across the whole System tenant (grants on one of
    its CAs are fine), service identities scoped to the whole System tenant (scope them to a CA),
    and certificate profiles on the System tenant that are bound to no CA.
  - **One security policy row.**
  - **Every group is in an existing tenant, and a CA's group is in its CA's tenant**, wherever the
    system tenant is involved. Correct each group listed.

  After the upgrade, the instance's policy (Settings, Security Policy, Instance CA policy) governs
  the instance CAs only and each space keeps its own; nothing is merged. Pre-releases of 0.4.0
  also refused an instance with more than one organisation tenant. That refusal was dropped: with
  independent scopes and several spaces per instance it guarded nothing, and staging had two
  organisations. At its first start
  the control role seals each per-tenant audit chain and anchors its final hash in the instance
  chain, where every new record now goes; `GET /api/v1/admin/audit/verify/chains` reports them.
  Bookmarks with `?tenant=system` no longer resolve. There is no downgrade: to go back, restore the
  dumps taken before the upgrade.
- **CA labels and names are unique across the instance.** A label is the path of a CA's CRL,
  OCSP, AIA and enrolment URLs. The `InstanceUniqueCaNames` migration refuses (status 3, nothing
  applied) while two CAs, counting soft-deleted ones, share a label, have labels that differ only in
  case, or share a name (check k); the journal lists each, with its space or "instance" and
  whether it is deleted.

  Rename all but one of each under Certificate Authorities (edit the CA's label or name), or with
  `PUT /api/v1/admin/authorities/{id}`. Prefer the SSH CA, or a CA that has issued nothing:
  renaming the label of an X.509 CA changes its CRL, OCSP and AIA URLs, and certificates it already
  issued keep pointing at the old ones. A name is a display name; renaming it changes no
  certificate. A soft-deleted CA still holds its label and name; rename it with SQL
  (`UPDATE "CertificateAuthorities" SET "Label" = '<label>-old', "Name" = '<name> (old)' WHERE "Id" = '<id>';`,
  with the service stopped and a dump taken) only when nothing it issued is still in use.
  The same migration drops the space-level quota columns (maximum CAs, certificates and users)
  whatever they hold; per-CA quotas are unchanged.
- **A protocol must sign with its own CA's signing profile.** 0.3.x let a CA's EST, CMP, SCEP,
  ACME, XCEP or MSAE configuration name any signing profile. From 0.4.0 a configuration whose
  signing profile issues from no CA, from another CA, or from a superseded certificate of the
  same CA makes every request to that CA's endpoints fail, so `InstanceUniqueCaNames` refuses
  (status 3, nothing applied) while any enabled configuration of a live X.509 CA is like that
  (check l); the journal lists each CA label, protocol and profile. For each, open Protocol Config
  for that CA in the 0.3.x console and choose that CA's own signing profile, or disable the
  protocol, then upgrade. The same holds for the certificate templates MSAE enrols against
  (check m): fix each under Certificate Templates (`/admin/templates`), or disable the template.
- **Tenants are now spaces, and each space's groups are renamed.** The `RenameTenantToSpace`
  migration renames the `Tenants` table to `Spaces` and every `TenantId` column to `SpaceId` in
  place; no data is copied. In the same step it renames each space's space-wide groups
  `org-<slug>-admin`, `-operator`, `-auditor` and `-user` to `space-<slug>-*`, the names new
  spaces get, and a display name starting `Org` or `Organisation` to start `Space`. Members,
  grants, roles and badges follow, because they refer to groups by id. It refuses (status 3,
  nothing applied) when a `space-<slug>-*` name is already taken by another group, or would be too
  long (check o); rename that group first. Scripts that call the API or query the database by an `org-*` group
  name must use the new name, and scripts that call the admin API must use the space paths and
  members (see the changelog). The same migration renames the scope keys in stored ceremony
  parameters, so open ceremonies carry over, and refuses parameters it cannot read as one JSON
  object (check n). Every process reads the new names, which is why every unit is stopped before control
  upgrades.

  `LdapAuth.GroupToRoleMappings` in config.yaml names groups, and the migration cannot edit it.
  Until it is updated, a mapping to an `org-<slug>-*` group that no longer exists, whose
  `space-<slug>-*` group does, is read as the new name, at every sync and when the mappings are
  validated, with a warning in the journal naming both. Change the mapping to the new name, in
  config.yaml or in the console's LDAP settings, to silence it. Only that pattern is translated;
  no other group name is guessed.
- **Configuration keys say space.** `IntegrationApi.TenantId` and `CertManager.TenantId` are
  `IntegrationApi.SpaceId` and `CertManager.SpaceId`. The old key is read as the new one, with a
  warning naming the file, so an integration API key scoped to an organisation keeps its scope:
  the organisation is a space with the same id. A key scoped to the system tenant does not, since
  that tenant is deleted: set it to `instance`, which scopes the key to the instance's CAs, where
  the system tenant's CAs go (step 2). `--upgrade-check`, and so `install.sh`, refuses while one is
  configured, naming the key; the `.deb` has no such check, so run it by hand (above). `SpaceId`
  takes a space's id, `instance`, or nothing for every space and the instance; any other value
  reaches no CA. Each 0.4.0 process that serves the integration endpoints warns at every start,
  naming the key, when a configured `SpaceId` names no existing space or is not a value it reads.
  When both keys are set and differ, the process refuses to start (status 3) and names the file
  and both keys; keep the one with the intended value. `Features.AllowMultipleOrganizations` is retired and ignored, with a
  warning while it is present: creating a space always succeeds, and past four spaces the console
  recommends a licence.

The audit role owns the audit tables on every install. The audit trail is tamper-evident through its
hash chain, not tamper-proof: see "The audit trail is tamper-evident, not tamper-proof" in
`docs/architecture/postgresql-migration.md`.

## Backup and recovery

This is the whole procedure for losing the CA host and getting the CA back. It is exercised by a
test that runs the real program: it installs an instance, backs it up, destroys the host and
both databases, restores onto a second host and checks the result
(`tests/ModularCA.Tests/DisasterRecovery`).

### What to keep off the host

Three things, and a restore needs all three. Losing any one of them loses the CA.

| What | Where it is | When it changes |
|---|---|---|
| A backup archive, `modularca-backup-<timestamp>.enc` | `backups/` | Every backup |
| The backup key, `backup.key` (or the backup password you set) | `config/` | Never, unless you reset the instance or change the password |
| The keystore passphrases, `keystore.yaml` | `config/` | Never |

Copy the key and the passphrases off the host once, when you install, and keep them apart from
the archives: an archive with its key and the passphrases is the CA. Copy each new archive off
the host as it is made. Nothing does this for you; `backups/` is on the same disk as everything
else.

An archive holds both databases, the keystores, `config/` and the secrets that protect stored
data. It does not hold its own key, the keystore passphrases, the database credentials
(`db.yaml`) or the web certificate's key (`api-tls.pfx`).

### Taking backups

The node takes one every day at 02:00 UTC and keeps the last ten (`Backup.Schedule`,
`Backup.RetentionCount`). The console's Backup page takes one on demand. From the command line:

    sudo -u modularca /opt/modularca/ModularCA.API --backup

`pg_dump` and `pg_restore` must be on the PATH of the account that runs ModularCA, at the
server's major version or newer. A backup that cannot dump a database stops and writes no
archive; the scheduled job raises a `BackupFailed` alert. One `pg_dump` or `pg_restore` run may
take up to `Backup.DatabaseTimeoutMinutes` (60).

### What a restore brings back, and what it does not

A restored CA is the CA as it was when the archive was taken.

- **Certificates issued after the backup are unknown to it.** They still chain to the CA, but
  they are not in its records: they cannot be revoked or renewed from the console, they are not
  on its CRL, and its OCSP responder answers "revoked" for them, because it answers that for any
  serial it never issued. Reissue them.
- **Revocations made after the backup are forgotten.** Those certificates are valid again as far
  as the CA knows. Revoke them again; the old host's last CRL, if you still have it, lists them.
- **The first start publishes a new CRL**, numbered above every CRL the old host published, so a
  client that has seen a later CRL does not treat the new one as a rollback.
- **The web certificate is new.** Its key is in no archive, so the node issues itself a
  replacement at its first start, with the same names. Clients that trust the root are
  unaffected; anything that pinned the old certificate is not. If the old host's disk may be in
  someone else's hands, revoke the old web certificate from the console.
- **Users, passwords, authenticator secrets and passkeys come back as they were.** Passkeys keep
  working only under the same public name.

How much you lose is set by how often you back up and how quickly the archive leaves the host.

**While the CA is down** nothing is issued or revoked and OCSP does not answer. The last CRL
stays valid only until its next scheduled publication, 30 minutes away at most with the default
schedule: the schedule's overlap setting is stored but not applied yet. After that, clients that
insist on a current CRL fail until the CA is back. A longer CRL interval buys a longer outage at
the price of slower revocation.

### Restoring onto the same host

`--restore` puts back the databases, the keystores and `config/` from an archive; the console's
Backup page does the same for an archive in `backups/`. From the command line, with the service
stopped:

    sudo systemctl stop modularca
    sudo -u modularca /opt/modularca/ModularCA.API --restore /opt/modularca/backups/<archive>.enc
    sudo systemctl start modularca

It asks you to type `RESTORE`. Before it changes anything it writes the live `config/` and
keystores to `backups/pre-restore-<timestamp>.zip`, owner-only. That file holds every secret in
`config/`; delete it once the restored node is running and you no longer need to go back.

A database that cannot be restored stops the restore before a keystore or a config file is
replaced. Each database is restored in one transaction, so one that fails is left as it was.

**The databases are this host's.** A restore writes into the databases this host's own
`config/db.yaml` names, with its credentials and any `MODULARCA__DB__*` overrides in the
service's environment. No archive carries `db.yaml`, and the restore ignores a `DB:` section in
the archived `config.yaml`: archives taken by earlier builds can have one, and it names the host
the backup was taken on, which may still be running. The restored `config.yaml` is written
without it. A host with no `db.yaml` is refused before anything changes.

### Restoring onto a new host

1. **Install the build the archive was taken with**, with `install.sh`, and PostgreSQL with its
   client tools.
2. **Give the host databases.** Either way works:
   - Complete the setup wizard, or run an unattended install, as for a first install. This
     makes a new, empty CA that the restore then replaces. Stop the service afterwards.
   - Or create two login roles and two empty databases yourself, each database owned by its
     role, and write `config/db.yaml` from `config/db.yaml.example`, owned by `modularca`,
     `0600`. Do not start the service.
3. **Put the kit in place**, owned by `modularca`, `0600`: `keystore.yaml` and `backup.key` in
   `config/`, replacing the ones a fresh install made, and the archive in `backups/`.
4. **Restore**, as above. For an archive protected by a password, give `--password` or answer
   the prompt.
5. **Start the service.** At this start it unwraps the stored-data secrets the restore staged in
   `config/restore-pending/`, issues its web certificate and publishes a new CRL.
6. **Check it**, from another machine:
   - `http://<name>:<http port>/ca/<label>` returns the root you already trust.
   - `https://<name>:<port>/` presents a certificate that root signed.
   - `http://<name>:<http port>/crl/<label>` returns a CRL dated today.
   - Sign in. The audit trail's integrity check is `GET /api/v1/admin/audit/verify`, as an
     administrator; it should report no breaks.
7. **Deal with the gap**: reissue what was issued after the backup, revoke again what was
   revoked after it, take a new backup, and delete `backups/pre-restore-*.zip`.

Where the host has a `config.yaml` (after the wizard), the restore compares the archive's schema
with the database's and refuses a difference, which is why step 1 asks for the same build.
Upgrade after the restore, not before.

With compose, step 2 is `docker compose up -d` and the wizard, and the rest is:

    docker compose stop modularca
    docker compose cp keystore.yaml modularca:/opt/modularca/config/keystore.yaml
    docker compose cp backup.key modularca:/opt/modularca/config/backup.key
    docker compose cp <archive>.enc modularca:/opt/modularca/backups/
    docker compose run --rm modularca --restore /opt/modularca/backups/<archive>.enc
    docker compose up -d modularca

The host procedure is what the test runs. The compose commands have not been run yet.

### Rehearse it

A backup you have not restored is a guess. Restore your latest archive onto a spare machine or a
second compose project now and again, with the kit you actually keep, and do step 6. Do not
give the rehearsal the production name: it would answer OCSP and publish CRLs as the CA.

## Firewall and ports

The installer does not touch your firewall. Nothing in the package opens a port, so a fresh
install on a host with a default-deny firewall starts cleanly, listens correctly, and is
unreachable — with no error anywhere, because the packets never reach the socket.

Permit whichever ports you configured:

    sudo ufw allow 80/tcp && sudo ufw allow 443/tcp      # if you set Http.Port 80 / Https.Port 443
    sudo ufw allow 8080/tcp && sudo ufw allow 8443/tcp   # if you kept the defaults

**Do not also apply `deploy/nftables-modularca.conf` unless you kept the unprivileged
defaults.** That file redirects 80 to 8080 and 443 to 8443, for deployments where the ports must
stay unprivileged. Applied while ModularCA listens on 80/443 directly it rewrites every inbound
connection to a port nothing is listening on, and the symptoms are misleading: the service is
active, `ss` shows it bound, the firewall shows the ports allowed, and the application logs
nothing at all. Read the header of that file before installing it.

If the service is running and you cannot reach it, this settles it in one command — run it on the
server while a client tries to connect:

    sudo tcpdump -ni any tcp port 443 -c 20

Nothing at all means the packets are not reaching the machine, so look outside it (hypervisor
firewall, routing, VLAN). A SYN arriving with no SYN-ACK in reply means they reach the machine and
something on it is dropping them — a firewall rule, or the redirect above. A completed handshake
followed by silence means the network is fine and the problem is TLS.

## Things worth knowing before the first production start

**`config/OIDSeed.yaml` is not shipped.** When it is absent the OID catalog falls back to
built-in camelCase defaults. That is a supported configuration and the usage resolution handles
every spelling, but if you have a curated OID catalog, place it at `/opt/modularca/config/OIDSeed.yaml`
*before* running the wizard — the seeded certificate profiles are built from it.

**Audit history survives a reinstall.** The audit database is preserved by default; wiping it is
opt-in (`--wipe-audit` on a CLI bootstrap, or the "Erase existing audit history" checkbox in the
wizard). If you are rehearsing installs on one host, expect audit rows to carry across.

**The initial administrator password must be changed on first login.** When the password was
generated rather than chosen, it is printed once to the service log and the account is flagged
`PasswordChangeOnNextLogon`; the first login returns 403 and directs you through a change.

**Privileged ports** are granted by `AmbientCapabilities=CAP_NET_BIND_SERVICE` in the unit. Do
not also `setcap` the binary — the unit already covers it, and a stale file capability survives
upgrades in ways the unit does not.

## Two units: the signer apart from the node

By default one process holds everything, keys included. The hardened shape runs the keys in a
second unit, `modularca-signer.service`, under its own user: it holds `keystores/`, the keystore
passwords and any PKCS#11 session, and answers the node over gRPC with mutual TLS on loopback.
The node (`modularca.service` with `--role node`) then holds no key and no keystore password;
each side pins the other's public key, and there is no trust-store lookup.

The signer reads its settings from its own directory, `/opt/modularca/signer/`, which belongs to
`modularca-signer` and which the node can neither read nor write. The packaged unit says so:
`--signer-dir /opt/modularca/signer`. From there it reads `signer.yaml` (its settings only),
`db.yaml`, `keystore.yaml` and its identity files, and writes its logs and keystore audit to
`signer/logs/`. It reads nothing under `config/`. The node keeps `config/` to itself, and nothing
the node writes, its console's settings pages included, can change what the signer loads.

Do this after the first install has completed its wizard as a single process, so the keystores
and `config/keystore.yaml` exist.

1. Create the signer's user and its directory, and give it the keys and its files. The node keeps
   everything else, and `config/` stays `modularca`'s alone.

       sudo useradd --system --home /opt/modularca --shell /usr/sbin/nologin modularca-signer
       sudo systemctl stop modularca
       cd /opt/modularca
       sudo chown -R modularca-signer:modularca-signer keystores
       sudo chmod 0700 keystores
       sudo install -d -o modularca-signer -g modularca-signer -m 0700 signer
       sudo install -o modularca-signer -g modularca-signer -m 0600 config/keystore.yaml signer/keystore.yaml
       sudo install -o modularca-signer -g modularca-signer -m 0600 config/db.yaml signer/db.yaml
       sudo rm config/keystore.yaml

   The signer uses only the `App:` section of its `db.yaml`; you may delete `Audit:` from its copy.
   If the database password later changes (`modularca-migrate`, a rotation), update both copies.

2. Write the signer's settings, `signer/signer.yaml`. It has the shape of `config.yaml` and holds
   only what the signer reads; relative paths resolve against `signer/`:

       sudo -u modularca-signer tee signer/signer.yaml >/dev/null <<'EOF'
       Signer:
         Listen: "127.0.0.1:8446"
         ServerCertificate: "signer-server.pfx"
         IdentityCa: "signer-identity-ca.pfx"
       EOF
       sudo chmod 0600 signer/signer.yaml

   An HSM is configured here, not in the node's `config.yaml`: move any `Hsm:` section (and a
   `Schema:` or `Logging:` you changed) from `config.yaml` into `signer.yaml`, and delete it from
   `config.yaml`. The node with a remote signer never reads `Hsm:`, and the PIN then lives only in
   the signer's directory.

3. On the signer, create the identity CA and the signer's server certificate, then issue the
   node its client certificate:

       cd /opt/modularca
       sudo -u modularca-signer ./ModularCA.API --role signer --signer-dir /opt/modularca/signer --init-identity
       sudo -u modularca-signer ./ModularCA.API --role signer --signer-dir /opt/modularca/signer --issue-node-identity /tmp/node-identity

   The first writes `signer/signer-identity-ca.pfx` and `signer/signer-server.pfx`, owner-only. The
   second writes `/tmp/node-identity/signer-client.pfx` and `signer-pin.txt` and prints two things:
   the `PinnedClientSpki` for the signer, and the `Signer:` section for the node. (`--apply`, which
   writes both halves into one `config.yaml`, is the pod's and is refused with `--signer-dir`.)

4. Configure both sides. The signer side, in `signer/signer.yaml` (`sudo -e` keeps its owner and
   mode):

       Signer:
         Listen: "127.0.0.1:8446"
         ServerCertificate: "signer-server.pfx"
         IdentityCa: "signer-identity-ca.pfx"
         PinnedClientSpki: "<printed by --issue-node-identity>"

   The node side, in `config/config.yaml`, after moving the node's certificate into place. This is
   everything the node needs to know about the signer, the address it dials and the server key it
   pins, and it stays in the node's own file:

       sudo install -o modularca -g modularca -m 0600 /tmp/node-identity/signer-client.pfx /opt/modularca/config/
       sudo rm -rf /tmp/node-identity

       Signer:
         Mode: "Remote"
         Endpoint: "https://127.0.0.1:8446"
         ClientCertificate: "config/signer-client.pfx"
         PinnedServerSpki: "<the contents of signer-pin.txt>"

5. Point the node's unit at the node role, then start the node and the signer. The signer's unit
   is already installed, not enabled, with `--signer-dir /opt/modularca/signer` on its `ExecStart=`
   and `ReadWritePaths=` naming `keystores/` and `signer/` only: `install.sh` puts it in
   `/etc/systemd/system/`, the `.deb` in `/lib/systemd/system/` (its source is
   `deploy/modularca-signer.service` in the archive). Do not copy it into `/etc/systemd/system/` on
   a `.deb` install; a copy there overrides the packaged one.

       sudo mkdir -p /etc/systemd/system/modularca.service.d
       printf '[Service]\nExecStart=\nExecStart=/opt/modularca/ModularCA.API --role node\n' \
           | sudo tee /etc/systemd/system/modularca.service.d/role.conf
       sudo systemctl daemon-reload
       sudo systemctl start modularca
       sudo systemctl enable --now modularca-signer

   The signer unit is ordered after the node. At boot and after an upgrade, the node's control role
   applies migrations before it reports ready, and the signer starts after that. A signer started
   on its own waits for those migrations in-process.

   `journalctl -u modularca-signer` shows where the signer read its settings from, the listener
   and the pins it holds; `/health/ready` on the node shows the signer as a step. While the signer
   is down the node answers 503 on every enrollment endpoint with "The signer is unreachable" and
   reconnects on its own.

Backups taken by the node's scheduled job go through the signer and keep working. The
command-line `--backup` and `--restore` read the keystore files directly, so on a split
install run them on the signer host as the signer's user, with `--role signer --signer-dir
/opt/modularca/signer` so they find its `keystore.yaml`. On one host that user can neither
read the node's backup key (`config/backup.key` or `config/backup-password.key`) nor write
`backups/`, so there the scheduled or console backup is the one that works as installed. The
node's client certificate lives one year; reissue it with `--issue-node-identity` and replace the
file and the pin.

### Moving an existing split install onto the signer's directory

A split install made before `--signer-dir` reads `config/config.yaml`, `config/db.yaml`,
`config/keystore.yaml` and `config/signer-*.pfx`, in the directory the node owns. Until it moves,
the signer says so in a warning at every start. The packaged unit already names
`/opt/modularca/signer`: while that directory does not exist the signer reads `config/` as before
(and warns that the directory is missing), so an upgrade does not stop it. To move it:

1. Create the directory and let the signer copy what it reads into it. The signer's account can
   still read the shared files; the copy writes `signer.yaml` with only the signer's sections (its
   half of `Signer:`, `Hsm:`, `Schema:`, the logging levels), `db.yaml` with only the application
   database, `keystore.yaml` and the identity files, all owner-only, and changes nothing in
   `config/`:

       cd /opt/modularca
       sudo install -d -o modularca-signer -g modularca-signer -m 0700 signer
       sudo -u modularca-signer ./ModularCA.API --role signer --signer-dir /opt/modularca/signer --migrate-signer-dir

2. Read `signer/signer.yaml` before the signer does (`sudo cat`). It was copied from a file the
   node could write, so check `Hsm.ModulePath`, `Signer.PinnedClientSpki` and `Signer.Listen`
   against what you set.

3. Point the unit at the directory. A `.deb` install has the flag once upgraded to this build
   (`systemctl cat modularca-signer` shows it). A tarball install keeps the unit it already has,
   since `install.sh` never replaces a unit that differs from the packaged one; give it the flag
   with a drop-in, which is harmless where the flag is already there:

       sudo mkdir -p /etc/systemd/system/modularca-signer.service.d
       printf '[Service]\nExecStart=\nExecStart=/opt/modularca/ModularCA.API --role signer --signer-dir /opt/modularca/signer\nReadWritePaths=-/opt/modularca/signer\n' \
           | sudo tee /etc/systemd/system/modularca-signer.service.d/signer-dir.conf
       sudo systemctl daemon-reload
       sudo systemctl restart modularca-signer

   `journalctl -u modularca-signer` now names `signer/signer.yaml` and no longer warns.

4. Take the signer's files and access away from the node's directory:

       cd /opt/modularca
       sudo rm config/keystore.yaml config/signer-server.pfx config/signer-identity-ca.pfx
       sudo chgrp modularca config config/config.yaml config/db.yaml
       sudo chmod 0700 config
       sudo chmod 0600 config/config.yaml config/db.yaml

   Remove `Hsm:` and the signer's half of `Signer:` (`Listen`, `ServerCertificate`,
   `PinnedClientSpki`, `IdentityCa` and their passwords) from `config/config.yaml`; the node never
   reads them. Restart the node.

To go back, stop the signer, remove `--signer-dir` from its unit (or the drop-in) and restore the
files and the group read of step 1 above as they were.

### Ownership on a split install, and what upgrades keep

| Path | Owner | Mode | |
|---|---|---|---|
| `/opt/modularca` and the program files | `root:root` | `0755` / `0644` | neither account can replace a binary |
| `keystores/` and its files | `modularca-signer` | `0700` / `0600` | the node cannot read them |
| `signer/` and everything in it | `modularca-signer` | `0700` / `0600` | the signer's settings, identity and logs; the node can neither read nor write them |
| `config/`, `logs/`, `backups/` and their files | `modularca` | `0700`, `0750`, `0700`, owner-only | the node's alone, as for a single process |

`install.sh` and the `.deb` keep all of it on every run: they give the program files to root and
never change the ownership, mode or contents of `config/`, `keystores/`, `logs/` or `backups/` once
they exist. They never create, copy into, chown or chmod `signer/`, and warn when it belongs to
anyone but `modularca-signer`. Each says so when it finds `keystores/` owned by `modularca-signer`.
An install upgraded by a 0.4.0 pre-release installer before this was fixed had all of it handed
back to `modularca`: check with `ls -la /opt/modularca/keystores /opt/modularca/signer` and repeat
step 1 if so.

**What the node can still reach on one host.** It cannot read the keys or anything in `signer/`,
cannot write anything the signer reads, and cannot replace the binaries the signer runs. It shares
the application database with the signer, as the same role: it can change the rows the signer
reads there (keystore rows, which the keystore's pin MAC and file signatures guard, ceremonies,
which the signer verifies) and the signer's audit rows. It can make itself unreachable to the
signer or fill the disk the two share. And a signer still on the shared layout (one that warns at
start) reads the node's `config/`, where the node can change `Hsm.ModulePath` (a library the
signer loads), `Signer.PinnedClientSpki` and `Signer.Listen` and so get code run in the signer at
its next start: move it as above.

## Three processes: signer, control, enrollment and validation

The node itself splits into roles, and a process runs any subset: `--role control`,
`--role enrollment,validation`, `--role node` (the three together, the two-unit shape above).
Each role hosts only its own controllers, so an inactive role's paths do not exist on that
process (404, no sign-in prompt), and only its own background work:

| Role | Serves | Runs |
|---|---|---|
| `control` | the console and setup wizard, the admin, auth, user and account API, `/health` | every scheduled job that mutates (CRL publishing, LDAP, renewals, backups, audit retention, TLS renewal) and every startup write (migrations, repairs, policy sync) |
| `enrollment` | ACME, EST, SCEP, CMP, MSAE, token and integration enrollment, the TSA, `/health` | the protocol cleanup jobs, under their own scheduler lease |
| `validation` | CRL, OCSP, AIA and CA certificates on HTTPS and on the plain-HTTP port, `/health` | nothing scheduled; OCSP is signed through the signer |

The layout this is for is three processes: the signer, the control plane, and one process
running enrollment and validation. Why one would do it: the enrollment process parses five
protocols, CMS and Kerberos from the network, and is the one most likely to be reached by an
attacker; on its own it holds no console, no admin API and no key, and a compromise there
cannot reach the ceremonies, the backups or the user database except through the database
permissions it has. The control plane can then sit on the admin network only, be restarted
for maintenance without interrupting issuance or OCSP, and be the one place migrations and
scheduled writes happen. Validation can be scaled on its own for CRL and OCSP load, since it
needs only the database and the signer.

Every node process reads the same `config.yaml` shape, so each host gets its own install with
the same database, the same `JWT.Secret` (a token the console issued must verify on every
host's `/health/ready`), and a `Signer:` section pointing at the signer. Two
node processes cannot share one install directory on one host: they would bind the same
ports. The signer's `Signer.Listen` (in `signer/signer.yaml`) must then be reachable from the enrollment and validation
hosts (not loopback), and each of them needs its own client certificate from
`--issue-node-identity`; the pinning works the same.

1. Complete the first install as a single process and split the signer out as above.

2. On each node host, select the role with a unit drop-in. The examples are in
   `/opt/modularca/deploy/dropins/`; `--role` on the command line wins over `Roles:` in
   `config.yaml`, so the config file can be shared across hosts unchanged.

       # control host
       sudo mkdir -p /etc/systemd/system/modularca.service.d
       sudo cp /opt/modularca/deploy/dropins/role-control.conf /etc/systemd/system/modularca.service.d/role.conf

       # enrollment + validation host
       sudo mkdir -p /etc/systemd/system/modularca.service.d
       printf '[Service]\nExecStart=\nExecStart=/opt/modularca/ModularCA.API --role enrollment,validation\n' \
           | sudo tee /etc/systemd/system/modularca.service.d/role.conf

       sudo systemctl daemon-reload && sudo systemctl restart modularca

   `role-enrollment.conf` and `role-validation.conf` are there for a host that runs one of
   the two alone.

3. Route by path in front of them, or by name with the ingress role (next section): `/admin`, `/user`, `/login`,
   `/setup`, `/docs`, `/public`, `/api/v1/admin`, `/api/v1/auth`, `/api/v1/user`,
   `/api/v1/account`, `/api/v1/me`, `/api/v1/setup`, `/api/v1/version`,
   `/api/v1/public/info`, `/api/v1/public/csp-report` to the control host;
   `/acme`, `/.well-known/est`, `/scep`, `/cmp`, `/msae`, `/tsa`, `/api/v1/acme`,
   `/api/v1/scep`, `/api/v1/cmp`, `/api/v1/msae`, `/api/v1/public/enroll`,
   `/api/v1/public/templates`, `/api/v1/public/tsa`, `/api/v1/integration` to the enrollment
   host; `/ca`, `/crl`, `/ocsp`, `/ssh`, `/api/v1/public/ca`, `/api/v1/public/crl`,
   `/api/v1/public/ocsp`, `/api/v1/public/ssh` to the validation host. The CDP and AIA URLs
   already in issued certificates point at the public domain, so the validation host is the
   one that must answer there on plain HTTP.

`/health` on any process lists the roles it runs; `/health/ready` reports, per role, what it
needs and whether it has it: validation the signer reachable, enrollment the signer unlocked,
control the database. A process without the control role refuses to start an unconfigured
install, because the wizard is the control plane's.

## Compose: one host, one process

`deploy/compose/compose.yaml`, in the source repository, runs ModularCA and a PostgreSQL 16
server on one host, with every role in one process. It is the shortest way to a working CA, and enough for a small install. It
works with Docker Compose and with `podman compose`.

    cd deploy/compose
    cp .env.example .env        # set POSTGRES_PASSWORD in it
    docker compose up -d
    docker compose logs modularca | grep -i "setup token"

Then open `https://<host>:8443`. The certificate is a temporary one made for setup: compare its
fingerprint with the one in the log before going on. The wizard asks for:

- **The token** from the log.
- **The database.** Host `db`, port 5432, superuser `postgres`, the password from `.env`, TLS
  left on "Require". The superuser is used once, to create the two databases and their roles.
- **The public name** clients will use for this host. ACME, passkeys and the web certificate are
  all bound to it, so choose the real one.
- **Whether more than one person will administer the CA.** "Just me" starts key ceremonies off,
  since a lone administrator could never get one approved.
- **Ports.** Keep 8443 and 8080, or change the `ports:` mappings in `compose.yaml` to match.

The wizard stops the process after the database step and again at the end. The `restart:` line
in `compose.yaml` brings it back each time; wait a few seconds and reload the page.

Things to know:

- **The instance is the five named volumes**: `db`, `config`, `keystores`, `logs` and `backups`.
  `docker compose down` keeps them. `docker compose down -v` deletes the CA.
- **Backups land in the `backups` volume**, on the same host as everything else. Copy them off
  it. A restore on another host also needs the backup key or password and the keystore's
  secondary passphrase, both of which live in the `config` volume: keep a copy of those too, or
  the archives cannot be opened.
- **Keep the database and the image's client tools at the same major version.** The image
  carries `pg_dump` 16 to match `postgres:16`. For a newer server, build the image with
  `--build-arg PG_MAJOR=17`.
- **The database connection is encrypted but not verified.** It never leaves the private network
  compose creates. Give PostgreSQL its own certificate if you move it to another host.
- **ACME clients on a private network need one switch turned on.** http-01 validation refuses
  private addresses by default, and a request for one fails with "Refusing to validate challenge
  against private address". The wizard asks when you tick ACME: answer "Yes, on a private
  network". Unattended, set `Acme.AllowPrivateAddressValidation: true` in `bootstrap.yaml`.
  Afterwards, and for any CA created later, open the CA's protocol settings in the console
  (`/admin/authorities/protocols`), choose ACME, and turn on "Allow Private Address Validation
  (HTTP-01)". Leave it off for a CA that validates names on the public internet: with it on,
  whoever can request a certificate can make the server fetch from addresses inside your network.
- **To install unattended**, put a `bootstrap.yaml` and a `setup-database.yaml` in the `config`
  volume before the first start (each has an `.example` under `config/`). The container then
  bootstraps without the wizard and prints the first administrator's password once, in its log.
  Set `HttpsApi.PublicDomain` in `bootstrap.yaml` to the name clients will use. Left out, it is
  the first DNS name under `HttpsApi.SANs` that is not `localhost`, and `localhost` when there
  is none, which only works from the host itself.
- **To upgrade**, change the image tag and `docker compose up -d`. Migrations run when the new
  version starts. Take a backup first; going back means restoring it. To see whether the new
  version would refuse the upgrade before committing to it, run its check, which changes
  nothing: `docker compose run --rm modularca --upgrade-check`.

For the signer in its own container, holding the keys where the node cannot read them, use the
pod below.

## The pod: node and signer as two containers

The container tier is the two-unit shape above with the units as containers from one image,
sharing only the pod's loopback. `deploy/container/modularca-pod.yaml` is a Kubernetes pod
manifest that Podman runs directly:

    podman kube play deploy/container/modularca-pod.yaml
    podman kube play --down deploy/container/modularca-pod.yaml

The same file is a plain Pod on Kubernetes, or the template of a one-replica Deployment: the
signer is a sidecar and scales with the node, not apart from it.

Before the first start, put into the `modularca-config` volume what a headless bootstrap needs:
`bootstrap.yaml` and `setup-database.yaml` (each has an `.example` under `config/`). Nothing
else is ever needed. Name the node in `bootstrap.yaml` with `HttpsApi.PublicDomain`, the
hostname clients will use; bootstrap writes `config.yaml` itself and replaces one that is
already there. If one person will administer the
instance, set `Administration.MultipleAdministrators: false` in `bootstrap.yaml`: key ceremonies
then start off for the instance and the first space, where a lone administrator could never get
one approved. Left out, they start on. Three init containers run every start and find their work
done after the first:

1. **bootstrap** completes the first install as a single process, because bootstrap writes the
   keystore locally and there is nothing to split until it exists. The initial administrator
   password is printed once, into this container's log: `podman logs modularca-bootstrap`.
2. **signer-init** creates the signer's identity CA and server certificate. It refuses to replace
   an existing CA, so it does nothing on later starts.
3. **node-identity** issues the node its client certificate and writes both halves of the channel
   into the one `Signer:` section of the shared `config.yaml` — the node reads its keys from it,
   the signer reads its own. It exits without touching a file that already names a remote signer
   with both pins set.

Then the two containers start: `signer` with `--role signer`, `node` with `--role node`.

The volumes are the security division, not housekeeping. `modularca-config` is shared, and the
signer mounts it read-only. `modularca-keystores` is mounted by the signer alone — **the node
never sees it**, which is the whole point of the split. `modularca-data` is the node's alone. The
signer listens on the pod's loopback, publishes no port, and cannot be reached from outside the
pod at all.

To do the same by hand on a host with the two units, the command the third init container runs
is the one to know: `--role signer --issue-node-identity --apply config/config.yaml` writes what
the earlier steps in this file have you transcribe, and takes a `.pre-signer-*.bak` copy of the
file first.

## The ingress in front of nodes

The ingress role is what makes a split install reachable under its names: one process
terminates TLS for every hostname under the instance's web TLS certificate and forwards each
name listed in `Ingress.Routes` in `config.yaml` to the node that serves it. Plain HTTP on
port 80 is routed by Host as well, so a routed name's CRL and OCSP URLs reach its node without
a redirect. The route table is read at startup; a name with no route is served by the ingress
process's own roles, which is why a single process with every role and no route behaves
exactly as before the role existed.

The layout this is for is the ingress on 443 and 80, each node on a loopback port of its own
with `--role node`, the signer as a separate unit, and a route per name naming its node.

    ingress (--role ingress)         443, 80          Ingress.Routes
    node A (--role node)             127.0.0.1:8443   Https.Port 8443, Http.Port 8080, Signer: Remote
    node B (--role node)             127.0.0.1:8453   Https.Port 8453, Http.Port 8090, Signer: Remote
    signer (--role signer)           127.0.0.1:8446   one client certificate per node

Every node is its own install directory (two node processes cannot share one: they would
bind the same ports), each with the same database, the same `JWT.Secret`, and a `Signer:`
section naming the signer with its own client certificate from `--issue-node-identity`. The
ingress is one more install directory on the same or another host; it needs the database
(the startup schema check and the listener's trust anchors read it) and the web TLS
certificate, whose names must cover every routed name, but no keystore, no keystore password
and no signer client certificate.

1. Complete the first install as a single process and split the signer out as above.

2. Install each node in its own directory with its own ports, `--role node` in the unit
   drop-in, and `Signer.Mode: Remote`. The node trusts forwarded headers from loopback by
   default; an ingress on another host must be listed in `Http.TrustedProxyCidrs` on the
   node, or the node records the ingress as the client.

3. Tell the ingress where each name goes, in its `config.yaml`:

         Ingress:
           Routes:
             - Host: "ca-a.example"
               Upstream: "https://127.0.0.1:8443"
               PlainHttpUpstream: "http://127.0.0.1:8080"
             - Host: "ca-b.example"
               Upstream: "https://127.0.0.1:8453"
               PlainHttpUpstream: "http://127.0.0.1:8090"
           DangerousAcceptAnyUpstreamCertificate: true   # loopback upstreams only; refused otherwise

   A change to the routes takes effect when the ingress restarts.

   Upstream TLS: a node reached by address presents a certificate for its public name, so
   the ingress cannot validate it as a browser would. Pin it (`PinnedSpki` on the route: the
   SHA-256 of the node's web TLS certificate SubjectPublicKeyInfo, hex, which changes when
   that certificate is reissued), or name the CA that issued every node's web TLS certificate
   in `Ingress.UpstreamCaCertificatePath`, or, for loopback upstreams only, accept any
   certificate with `DangerousAcceptAnyUpstreamCertificate`. A non-loopback `https://`
   upstream under that flag stops the ingress at startup. A plain `http://` upstream on
   loopback needs none of this.

4. Point the ingress unit at the role and start it:

       sudo mkdir -p /etc/systemd/system/modularca.service.d
       sudo cp /opt/modularca/deploy/dropins/role-ingress.conf /etc/systemd/system/modularca.service.d/role.conf
       sudo systemctl daemon-reload && sudo systemctl restart modularca

   The startup log lists every route (`[INGRESS] 2 route(s): ...`). `/health/ready` on the
   ingress carries an `ingress` entry: the number of routes, and per upstream what the active
   probe (`/health/live` every `HealthCheckIntervalSeconds`) last found. A node that stops answering is marked down
   and every request for its hostname is answered 503 with a body naming the host until it
   is back; the other hostnames are unaffected.

What the ingress does not do: it terminates TLS, so a client certificate presented to it is
not forwarded. The mTLS sign-in name and the EST client-certificate name are answered by
the process that hosts control and enrollment, so those names must stay on that process (no
upstream for them, and the ingress running in the same process as control), or that
process must be reached directly. `X-Forwarded-For`, `-Proto` and `-Host` are added on the
way to a node; `Authorization: Negotiate` and `WWW-Authenticate` pass through untouched.

## Break-glass

    cd /opt/modularca
    sudo -u modularca ./ModularCA.Keystore.Unlocker \
        --keystore keystores/ca-certs.keystore --print

It verifies the keystore's file signature and each entry's signature against the pinned signing
CA, then prints the entries as PEM. `--insecure-no-verify` skips the database-backed checks for
the case where the database is what you have lost; it is also required before the tool will
write decrypted keys to disk.

The SSH CA keys are in a third file, `keystores/ssh-ca.keystore`, which exists only on an install
that has an SSH CA. The tool opens it the same way, with one difference: it asks for no main
passphrase. The signer generated that passphrase, and it is kept only in the application database
(the file's `Keystores` row), wrapped under the secondary passphrase the file shares with
`ca-certs.keystore`. Without the application database this file cannot be opened, by this tool or
any other, so a backup that holds the SSH keystore is only as good as the database dump beside it.

`ssh-ca.keystore` and its `Keystores` row exist together. A restore keeps them together: an archive
without an SSH keystore moves the live file aside as `ssh-ca.keystore.bak.<timestamp>`, and a reset
deletes it. If the signer ever reports the file without its row (a database restored by other
means than `--restore`), it stays locked and says so; move the file aside and start it again.

### A locked account no one can unlock

With `LockoutMinutes` at 0, enough wrong passwords lock an account until an administrator unlocks
it. If that account is the only system-super, or every administrator who could unlock it is
locked too, unlock it on the host:

    sudo -u modularca /opt/modularca/ModularCA.API --unlock-user <username>

It connects with the application credentials in `config/db.yaml`, clears the lock, any temporary
lockout and the failed-login count, rotates the account's security stamp, and exits. It does not
re-enable a disabled account, or change its password or MFA. It runs only on the host, as the
service user, never over HTTP, so it grants nothing that reading `db.yaml` does not already give.
Each use is logged to `logs/modularca-bootstrap-<date>.log` and written to the audit trail, with the
audit credentials in `db.yaml`, as `UserUnlockedOnHost` by `host:break-glass`. If the audit
database cannot be reached the account is still unlocked, and the command prints a warning that
no audit record was written: record that use by hand.
