-- ModularCA: hand the objects an administrator created in one ModularCA database to its runtime role.
-- Run as a PostgreSQL superuser, connected to that database, with every ModularCA unit stopped:
--   sudo -u postgres psql -X -d '<db>' -v kind=app|audit -v target=<db.yaml role> -f /usr/share/modularca/sql/adopt-ownership.sql
-- Idempotent. Refuses a database that is not a ModularCA database of that kind.
\set ON_ERROR_STOP on
SET lock_timeout = '10s';
SET modularca.kind = :'kind';
SET modularca.target = :'target';
BEGIN;
DO $adopt$
DECLARE
  k text := current_setting('modularca.kind');
  tgt text := current_setting('modularca.target');
  base text := CASE k WHEN 'app' THEN '20260919181506_InitialCreate' WHEN 'audit' THEN '20260919181510_InitialAuditSchema' END;
  t pg_roles%ROWTYPE; dbo oid; ok boolean; r record; n int := 0;
BEGIN
  IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN RAISE EXCEPTION 'run as a PostgreSQL superuser'; END IF;
  IF base IS NULL THEN RAISE EXCEPTION 'kind must be app or audit'; END IF;
  SELECT * INTO t FROM pg_roles WHERE rolname = tgt;
  IF NOT FOUND OR NOT t.rolcanlogin OR t.rolsuper OR t.rolcreatedb OR t.rolcreaterole OR t.rolreplication OR t.rolbypassrls THEN
    RAISE EXCEPTION 'refused: % is not a plain login role', tgt; END IF;
  IF to_regclass('public."__EFMigrationsHistory"') IS NULL THEN RAISE EXCEPTION 'refused: % has no migration history', current_database(); END IF;
  EXECUTE 'SELECT EXISTS (SELECT 1 FROM public."__EFMigrationsHistory" WHERE "MigrationId" = $1)' INTO ok USING base;
  IF NOT ok THEN RAISE EXCEPTION 'refused: % is not a ModularCA % database', current_database(), k; END IF;
  SELECT datdba INTO dbo FROM pg_database WHERE datname = current_database();
  IF k = 'app' AND dbo <> t.oid THEN RAISE EXCEPTION 'refused: % does not own %', tgt, current_database(); END IF;
  IF k = 'audit' AND pg_has_role(t.oid, dbo, 'MEMBER') THEN RAISE EXCEPTION 'refused: % could drop the audit database', tgt; END IF;
  IF k = 'audit' AND NOT EXISTS (SELECT 1 FROM pg_database d, aclexplode(d.datacl) a
      WHERE d.datname = current_database() AND a.grantee = t.oid AND a.privilege_type = 'CONNECT') THEN
    RAISE EXCEPTION 'refused: % was never granted CONNECT here', tgt; END IF;
  FOR r IN SELECT c.oid::regclass AS obj, c.relkind FROM pg_class c JOIN pg_roles w ON w.oid = c.relowner
     WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r','p','v','m','f','S') AND c.relowner <> t.oid
       AND (w.rolsuper OR w.rolcreatedb OR w.rolcreaterole OR w.oid = dbo)
       AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid
                         AND (d.deptype = 'e' OR (c.relkind = 'S' AND d.deptype IN ('a','i'))))
  LOOP
    EXECUTE format('ALTER %s %s OWNER TO %I', CASE r.relkind WHEN 'S' THEN 'SEQUENCE' WHEN 'v' THEN 'VIEW'
      WHEN 'm' THEN 'MATERIALIZED VIEW' WHEN 'f' THEN 'FOREIGN TABLE' ELSE 'TABLE' END, r.obj, tgt);
    n := n + 1;
  END LOOP;
  RAISE NOTICE 'modularca: % object(s) in % now owned by %', n, current_database(), tgt;
  FOR r IN SELECT c.oid::regclass AS obj, pg_get_userbyid(c.relowner) AS owner FROM pg_class c
     WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r','p','v','m','f','S')
       AND NOT pg_has_role(t.oid, c.relowner, 'USAGE')
       AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype IN ('e','a','i'))
  LOOP RAISE WARNING 'not adopted (owned by ordinary role %): %', r.owner, r.obj; END LOOP;
END $adopt$;
COMMIT;
