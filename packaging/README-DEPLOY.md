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
| `deploy/` | systemd units, per-role unit drop-ins (`dropins/`), plus nginx and nftables templates. |
| `share/sql/adopt-ownership.sql` | The one-time schema-ownership repair for installs made before 0.4.0, run as the PostgreSQL superuser. `install.sh` installs it root-owned to `/usr/share/modularca/sql/`, never into `/opt/modularca`. |

## Permissions are set by the installer, not the archive

This archive is **built on Windows**, so it carries no Unix permission bits and no executable
flags. `install.sh` sets them explicitly:

- `ModularCA.API` and `ModularCA.Keystore.Unlocker` → `0755`
- `config/` and `keystores/` → `0700`, files `0600` — they hold database credentials, the
  secondary keystore passphrase, and the CA private keys
- everything under `/opt/modularca` owned by the `modularca` service account
- `/usr/share/modularca/sql/adopt-ownership.sql` → `root:root 0644`. It is run as the PostgreSQL
  superuser, so it must not live where the service account can rewrite it.

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

Re-run `install.sh`. It stops `modularca` and `modularca-signer` if they are running, replaces
binaries and `wwwroot`, leaves `config/` and `keystores/` alone, and starts again the units that
were running. Database migrations are applied by the service when it starts.

Take a backup first — the CA private keys are the part you cannot recreate. Dump both databases
too (`pg_dump -Fc`); the dump is how you go back if a migration cannot be completed.

### What the service checks when it starts

Before it serves anything, the service reads both databases as its own roles and decides; see
"At startup" in `docs/architecture/postgresql-migration.md` for the full sequence. What an
operator sees:

| Outcome | Exit status | What happens |
|---|---|---|
| Everything current, or the control role applied the pending migrations | — | starts |
| Database unreachable, locked by a migration, or (enrollment, validation, signer) waiting for the control role's migrations | — then **75** | waits up to `Schema.WaitSeconds` (900 s), then exits and systemd retries |
| A migration failed on a lock timeout, a deadlock or a lost connection | — then **75** | retried in the service with backoff for up to `Schema.WaitSeconds`, then exits and systemd retries |
| Schema newer than this build, tables without history, wrong password, `pg_hba.conf` refusal, TLS failure, tables the runtime role does not own, a migration that failed for good, PostgreSQL older than 14 | **3** | not retried (`RestartPreventExitStatus=3`); the journal says why and prints the fix |

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

Follow it in order, on staging first and then on production. Every check runs with the build you
run now and changes nothing. An install already on a 0.4.0 pre-release has passed the checks of the
stages it has; each migration refuses anyway, changing nothing, if a check was missed.

1. **Back up.** Take the usual backup (the keystores and `config/` are what you cannot recreate),
   then dump both databases. The dumps are the only way back: no 0.4.0 migration has a downgrade.

       sudo -u postgres pg_dump -Fc -d '<app database>' -f ~postgres/modularca-app-pre-0.4.0.dump
       sudo -u postgres pg_dump -Fc -d '<audit database>' -f ~postgres/modularca-audit-pre-0.4.0.dump

2. **Run the read-only pre-checks** in `sudo -u postgres psql -X -d '<app database>'`. Each one
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
   -- c. FoldSystemTenant P2: at most one organisation tenant that is not soft-deleted
   SELECT "Name" FROM "Tenants" WHERE NOT "IsSystemTenant" AND NOT "IsDeleted"
      AND (SELECT count(*) FROM "Tenants" WHERE NOT "IsSystemTenant" AND NOT "IsDeleted") > 1;
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
   -- k. InstanceUniqueCaNames P1, P2, P3: CA labels (ignoring case) or names shared, deleted CAs included
   SELECT 'label' AS clash, lower(ca."Label") AS value, string_agg(ca."Name"::text, ', ') AS cas
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

   Leave a `TenantId` under `IntegrationApi` or `CertManager` as it is until after the upgrade:
   the build you run now ignores `SpaceId`, so renaming it first would leave that API key
   unscoped. 0.4.0 reads it as `SpaceId`. Note the `org-<slug>-*` names in
   `LdapAuth.GroupToRoleMappings` for step 7.

3. **Stop every unit, on every host**: control, enrollment and validation, ingress, and the signer.

       sudo systemctl stop modularca modularca-signer
       systemctl is-active modularca modularca-signer     # both inactive

4. **Install on the control host and start the control role alone.** `install.sh` starts nothing
   when nothing was running; the `.deb` upgrade from 0.3.x starts `modularca` itself (see below),
   which on the control host is this step.

       sudo systemctl start modularca
       journalctl -u modularca -n 200 --no-pager

   The journal names each migration applied: `RetireTenantHostnames`, `FoldSystemTenant`,
   `InstanceUniqueCaNames` and `RenameTenantToSpace` on a 0.3.x database. A refusal stops the
   service with status 3 and names the precondition and what it found, with nothing of that
   migration applied: fix it and start again, or restore the dumps and run the previous release.
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
   `TailState` `Sealed` (or `Pruned`). Under Spaces, each space is listed, and its groups are named
   `space-<slug>-*`.

7. **Tidy the configuration**, on every host, then restart that host's units. Rename
   `IntegrationApi.TenantId` and `CertManager.TenantId` to `SpaceId`, delete
   `Features.AllowMultipleOrganizations` and `Ingress.RouteRefreshSeconds`, and change each
   `org-<slug>-*` group mapping to its `space-<slug>-*` name. On the control host, saving the
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
- **The `.deb` upgrade from 0.3.x, once.** The 0.3.x package's `prerm` stops `modularca` and records
  nothing, and dpkg runs it before any script of the new package, so not even the new `preinst`
  can see whether the node was running. On this one upgrade `postinst` therefore starts `modularca`
  whenever it is enabled, even if an operator had stopped it, and restarts `modularca-signer` only
  if it was running. If the node was stopped on purpose, stop it again afterwards
  (`sudo systemctl stop modularca`), or `systemctl disable modularca` before upgrading. From 0.4.0
  on, `prerm` records which units were running and the upgrade starts exactly those.
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
  its four tenant-wide `org-system-*` groups. It changes nothing and stops the service (status 3,
  the journal names the precondition and what it found) unless all of these hold (checks b to j):
  - **No open ceremony names the system tenant.** Execute or cancel every Pending or Approved
    ceremony on a system CA (the system signing CA, an SSH CA) or on the System tenant's policy,
    and every controlled-user ceremony on those. The migration never rewrites a ceremony.
  - **The `org-system-*` groups are empty.** Move each member of `org-system-admin`,
    `org-system-operator`, `org-system-auditor` and `org-system-user` to the system group that
    fits (`system-admin`, `system-operator`, `system-auditor`) or to a CA's group, and edit any
    access badge that names one of them. Their grants and roles are deleted with them.
  - **Nothing on the system tenant would become instance-wide.** Remove capability grants and
    role assignments given to users directly across the whole System tenant (grants on one of
    its CAs are fine), service identities scoped to the whole System tenant (scope them to a CA),
    and certificate profiles on the System tenant that are bound to no CA.
  - **One organisation.** An instance with more than one organisation tenant is refused,
    whatever `Features.AllowMultipleOrganizations` says. A soft-deleted tenant does not count; a
    disabled one does.
  - **One security policy row.**
  - **Every group is in an existing tenant, and a CA's group is in its CA's tenant**, wherever the
    system tenant is involved. Correct each group listed.

  After the upgrade, the instance's policy (Settings, Security Policy, Instance CA policy) governs
  the instance CAs only and the space keeps its own; nothing is merged. At its first start
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
  warning naming the file, so an integration API key keeps its scope. When both are set and
  differ, the process refuses to start (status 3) and names the file and both keys; keep the one
  with the intended value. `Features.AllowMultipleOrganizations` is retired and ignored, with a
  warning while it is present: creating a space always succeeds, and past four spaces the console
  recommends a licence.

The audit role owns the audit tables on every install. The audit trail is tamper-evident through its
hash chain, not tamper-proof: see "The audit trail is tamper-evident, not tamper-proof" in
`docs/architecture/postgresql-migration.md`.

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

Do this after the first install has completed its wizard as a single process, so the keystores
and `config/keystore.yaml` exist.

1. Create the signer's user and give it the keys. The node keeps everything else.

       sudo useradd --system --home /opt/modularca --shell /usr/sbin/nologin modularca-signer
       sudo systemctl stop modularca
       sudo chown -R modularca-signer:modularca-signer /opt/modularca/keystores
       sudo chown modularca-signer:modularca-signer /opt/modularca/config/keystore.yaml
       sudo chmod 0700 /opt/modularca/keystores
       sudo chmod 0640 /opt/modularca/config/config.yaml /opt/modularca/config/db.yaml
       sudo chgrp modularca-signer /opt/modularca/config /opt/modularca/config/config.yaml /opt/modularca/config/db.yaml
       sudo chmod 0750 /opt/modularca/config

   Both units read `config/config.yaml` and `config/db.yaml`; only the signer reads
   `keystore.yaml`. The node no longer needs `keystore.yaml` or `keystores/` at all, and on two
   hosts they are simply not copied to the node.

2. On the signer, create the identity CA and the signer's server certificate, then issue the
   node its client certificate:

       cd /opt/modularca
       sudo -u modularca-signer ./ModularCA.API --role signer --init-identity
       sudo -u modularca-signer ./ModularCA.API --role signer --issue-node-identity /tmp/node-identity

   The first writes `config/signer-identity-ca.pfx` and `config/signer-server.pfx`
   (owner-only). The second writes `/tmp/node-identity/signer-client.pfx` and
   `signer-pin.txt` and prints two things: the `PinnedClientSpki` for the signer, and the
   `Signer:` section for the node.

3. Configure both sides in `config/config.yaml`. The signer side:

       Signer:
         Listen: "127.0.0.1:8446"
         ServerCertificate: "config/signer-server.pfx"
         PinnedClientSpki: "<printed by --issue-node-identity>"

   The node side, after moving `/tmp/node-identity/signer-client.pfx` to
   `/opt/modularca/config/` (owned by `modularca`, mode 0600):

       Signer:
         Mode: "Remote"
         Endpoint: "https://127.0.0.1:8446"
         ClientCertificate: "config/signer-client.pfx"
         PinnedServerSpki: "<the contents of signer-pin.txt>"

   On one host both sections live in the same file; each process reads the keys for its role.

4. Point the node's unit at the node role, then start the node and the signer:

       sudo mkdir -p /etc/systemd/system/modularca.service.d
       printf '[Service]\nExecStart=\nExecStart=/opt/modularca/ModularCA.API --role node\n' \
           | sudo tee /etc/systemd/system/modularca.service.d/role.conf
       sudo cp /opt/modularca/deploy/modularca-signer.service /etc/systemd/system/
       sudo systemctl daemon-reload
       sudo systemctl start modularca
       sudo systemctl enable --now modularca-signer

   The signer unit is ordered after the node. At boot and after an upgrade, the node's control role
   applies migrations before it reports ready, and the signer starts after that. A signer started
   on its own waits for those migrations in-process.

   `journalctl -u modularca-signer` shows the listener and the pins it holds; `/health/ready`
   on the node shows the signer as a step. While the signer is down the node answers 503 on
   every enrollment endpoint with "The signer is unreachable" and reconnects on its own.

Backups taken by the node's scheduled job go through the signer and keep working. The
command-line `--backup` and `--restore` read the keystore files directly, so on a split
install run them on the signer host as the signer's user. The node's client certificate lives
one year; reissue it with `--issue-node-identity` and replace the file and the pin.

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
ports. The signer's `Signer.Listen` must then be reachable from the enrollment and validation
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

## The pod: node and signer as two containers

The container tier is the two-unit shape above with the units as containers from one image,
sharing only the pod's loopback. `deploy/container/modularca-pod.yaml` is a Kubernetes pod
manifest that Podman runs directly:

    podman kube play deploy/container/modularca-pod.yaml
    podman kube play --down deploy/container/modularca-pod.yaml

The same file is a plain Pod on Kubernetes, or the template of a one-replica Deployment: the
signer is a sidecar and scales with the node, not apart from it.

Before the first start, put into the `modularca-config` volume what a headless bootstrap needs —
`bootstrap.yaml`, `setup-database.yaml`, and a `config.yaml` naming the node (each has an
`.example` under `config/`). Nothing else is ever needed. Three init containers run every start
and find their work done after the first:

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
