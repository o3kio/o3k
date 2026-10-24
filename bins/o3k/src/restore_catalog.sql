-- PP.6 D10 catalog descriptor (PostgreSQL 16).
--
-- This query is deliberately independent of pg_restore's TOC.  It returns one
-- deterministic JSON document for comparison between a migration-created
-- clean database and the disposable database populated from an archive.  No
-- values from an artifact are interpolated into this SQL.
--
-- Callers must execute it with a role which can inspect pg_catalog, and hash
-- the canonical JSON bytes (RFC 8785) rather than relying on object counts.
SET search_path = pg_catalog;

WITH
tables AS (
  SELECT c.oid, n.nspname AS schema, c.relname AS name,
    c.relkind::text AS relkind, c.relpersistence::text AS persistence,
    c.relreplident::text AS replica_identity,c.relrowsecurity,c.relforcerowsecurity,c.reloptions::text[] AS options,
    pg_get_userbyid(c.relowner) AS owner,
    c.relacl::text[] AS acl,
    COALESCE((SELECT jsonb_agg(jsonb_build_object(
      'name',a.attname,'ordinal',a.attnum,'type',format_type(a.atttypid,a.atttypmod),
      'collation',CASE WHEN a.attcollation=0 THEN NULL ELSE format('%s.%s',nc.nspname,cc.collname) END,
      'not_null',a.attnotnull,'default',pg_get_expr(ad.adbin,ad.adrelid),
      'generated',a.attgenerated::text,'identity',a.attidentity::text,
      'storage',a.attstorage::text,'compression',a.attcompression::text,'statistics',a.attstattarget,
      'acl',a.attacl::text[],'options',a.attoptions::text[])
      ORDER BY a.attnum)
      FROM pg_attribute a LEFT JOIN pg_attrdef ad ON ad.adrelid=a.attrelid AND ad.adnum=a.attnum
      LEFT JOIN pg_collation cc ON cc.oid=a.attcollation LEFT JOIN pg_namespace nc ON nc.oid=cc.collnamespace
      WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped),'[]'::jsonb) AS columns
  FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE c.relkind IN ('r','p') AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
),
indexes AS (
 SELECT i.indexrelid AS oid,n.nspname AS schema,i_rel.relname AS name,
   pg_get_userbyid(i_rel.relowner) AS owner,pg_get_indexdef(i.indexrelid) AS definition,
   i.indisunique,i.indisprimary,i.indisvalid,i.indisready,i.indislive,i.indisreplident,
   i_rel.reloptions::text[] AS options,pg_get_expr(i.indpred,i.indrelid) AS predicate,
   t.relname AS table_name
 FROM pg_index i JOIN pg_class i_rel ON i_rel.oid=i.indexrelid
 JOIN pg_class t ON t.oid=i.indrelid JOIN pg_namespace n ON n.oid=i_rel.relnamespace
 WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
),
constraints AS (
 SELECT con.oid,n.nspname AS schema,con.conname AS name,t.relname AS table_name,
   con.contype::text AS type,con.convalidated,con.condeferrable,con.condeferred,
   pg_get_constraintdef(con.oid,true) AS definition
 FROM pg_constraint con JOIN pg_class t ON t.oid=con.conrelid
 JOIN pg_namespace n ON n.oid=t.relnamespace
 WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
),
functions AS (
 SELECT p.oid,n.nspname AS schema,p.proname AS name,
   pg_get_function_identity_arguments(p.oid) AS identity_arguments,
   CASE WHEN p.prokind IN ('f','p','w') THEN pg_get_functiondef(p.oid) END AS definition, l.lanname AS language,
   p.prokind::text AS kind,p.provolatile::text AS volatility,p.prosecdef AS security_definer,
   p.proleakproof,p.proconfig,pg_get_userbyid(p.proowner) AS owner,
   p.proacl::text[] AS acl
 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang
 WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
),
aggregates AS (
 SELECT n.nspname AS schema,p.proname AS name,
   pg_get_function_identity_arguments(p.oid) AS identity_arguments,
   pg_get_userbyid(p.proowner) AS owner
 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE p.prokind='a' AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
),
types AS (
 SELECT n.nspname AS schema,t.typname AS name,t.typtype::text AS kind,
   format_type(t.typbasetype,t.typtypmod) AS base_type,
   t.typnotnull,pg_get_userbyid(t.typowner) AS owner,
   t.typacl::text[] AS acl, t.typdefault AS default_expression
 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace
 LEFT JOIN pg_type dbase ON dbase.oid=t.typbasetype
 WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
   AND t.typtype IN ('d','e','c')
),
event_triggers AS (
 SELECT e.evtname AS name,e.evtevent AS event,e.evtenabled::text AS enabled,
   pg_get_userbyid(e.evtowner) AS owner, e.evttags::text[] AS tags
 FROM pg_event_trigger e
),
foreign_objects AS (
 SELECT 'foreign_server' AS kind,s.srvname AS name,s.srvtype,s.srvversion,
   s.srvoptions::text[] AS options,pg_get_userbyid(s.srvowner) AS owner
 FROM pg_foreign_server s
 UNION ALL
 SELECT 'foreign_data_wrapper',w.fdwname,NULL::text,NULL::text,w.fdwoptions::text[],pg_get_userbyid(w.fdwowner)
 FROM pg_foreign_data_wrapper w
),
foreign_user_mappings AS (
 SELECT s.srvname AS server,CASE WHEN u.umuser=0 THEN 'PUBLIC' ELSE r.rolname END AS role_name,
   u.umoptions::text[] AS options
 FROM pg_user_mappings u JOIN pg_foreign_server s ON s.oid=u.srvid
 LEFT JOIN pg_roles r ON r.oid=u.umuser
),
unexpected_relations AS (
 SELECT n.nspname AS schema,c.relname AS name,c.relkind::text AS kind,
   pg_get_userbyid(c.relowner) AS owner
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
   AND c.relkind NOT IN ('r','p','v','m','S','i','I','t')
),
database_acl AS (
 SELECT d.datname,pg_get_userbyid(d.datdba) AS owner,d.datacl::text[] AS acl
 FROM pg_database d WHERE d.datname=current_database()
),
database_settings AS (
 SELECT d.datname,r.rolname,s.setconfig::text[] AS settings
 FROM pg_db_role_setting s LEFT JOIN pg_database d ON d.oid=s.setdatabase
 LEFT JOIN pg_roles r ON r.oid=s.setrole
 WHERE s.setdatabase=0 OR d.datname=current_database()
),
rules AS (
 SELECT n.nspname AS schema,c.relname AS table_name,r.rulename AS name,
   pg_get_ruledef(r.oid,true) AS definition
 FROM pg_rewrite r JOIN pg_class c ON c.oid=r.ev_class JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE r.rulename <> '_RETURN' AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
),
default_acls AS (
 SELECT n.nspname AS schema,d.defaclobjtype::text AS object_type,
   pg_get_userbyid(d.defaclrole) AS role,d.defaclacl::text[] AS acl
 FROM pg_default_acl d LEFT JOIN pg_namespace n ON n.oid=d.defaclnamespace
),
triggers AS (
 SELECT tg.oid,n.nspname AS schema,t.relname AS table_name,tg.tgname AS name,
   pg_get_triggerdef(tg.oid,true) AS definition,tg.tgenabled::text AS enabled,
   tg.tgisinternal AS internal
 FROM pg_trigger tg JOIN pg_class t ON t.oid=tg.tgrelid JOIN pg_namespace n ON n.oid=t.relnamespace
 WHERE NOT tg.tgisinternal AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
),
views AS (
 SELECT c.oid,n.nspname AS schema,c.relname AS name,c.relkind::text AS relkind,
   pg_get_userbyid(c.relowner) AS owner,pg_get_viewdef(c.oid,true) AS definition,c.relacl::text[] AS acl,c.reloptions::text[] AS options
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE c.relkind IN ('v','m') AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
),
sequences AS (
 SELECT c.oid,n.nspname AS schema,c.relname AS name,pg_get_userbyid(c.relowner) AS owner,
   format_type(s.seqtypid,NULL) AS type,
   s.seqstart,s.seqincrement,s.seqmin,s.seqmax,s.seqcache,s.seqcycle,c.relacl::text[] AS acl,
   COALESCE((SELECT jsonb_agg(jsonb_build_object('schema',tn.nspname,'table',t.relname,
      'column',a.attname,'dependency',d.deptype::text) ORDER BY tn.nspname,t.relname,a.attname)
      FROM pg_depend d JOIN pg_class t ON t.oid=d.refobjid
      JOIN pg_namespace tn ON tn.oid=t.relnamespace
      JOIN pg_attribute a ON a.attrelid=t.oid AND a.attnum=d.refobjsubid
      WHERE d.classid='pg_class'::regclass AND d.objid=c.oid
        AND d.refclassid='pg_class'::regclass AND d.deptype IN ('a','i')),'[]'::jsonb) AS owned_by
 FROM pg_sequence s JOIN pg_class c ON c.oid=s.seqrelid JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
),
policies AS (
 SELECT p.polrelid,c.relname AS table_name,n.nspname AS schema,p.polname AS name,
   p.polcmd::text AS command,p.polpermissive,COALESCE((SELECT array_agg(CASE WHEN x.oid=0 THEN 'PUBLIC' ELSE r.rolname END ORDER BY x.oid=0,r.rolname)
      FROM unnest(p.polroles) x(oid) LEFT JOIN pg_roles r ON r.oid=x.oid),'{}') AS roles,
   pg_get_expr(p.polqual,p.polrelid) AS using_expression,
   pg_get_expr(p.polwithcheck,p.polrelid) AS check_expression
 FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
),
schemas AS (
 SELECT n.oid,n.nspname AS name,pg_get_userbyid(n.nspowner) AS owner,n.nspacl::text[] AS acl
 FROM pg_namespace n WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
),
extensions AS (
 SELECT e.extname AS name,e.extversion,e.extrelocatable,n.nspname AS schema
 FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace
),
roles AS (
 SELECT r.rolname,r.rolsuper,r.rolinherit,r.rolcreaterole,r.rolcreatedb,r.rolcanlogin,
   r.rolreplication,r.rolbypassrls,r.rolconnlimit,r.rolvaliduntil,r.rolconfig::text[] AS config
 FROM pg_roles r
),
memberships AS (
 SELECT parent.rolname AS role_name,member.rolname AS member_name,grantor.rolname AS grantor,m.admin_option,m.inherit_option,m.set_option
 FROM pg_auth_members m JOIN pg_roles parent ON parent.oid=m.roleid JOIN pg_roles member ON member.oid=m.member
 JOIN pg_roles grantor ON grantor.oid=m.grantor

),
migrations AS (
 SELECT version::text AS version,encode(checksum,'hex') AS checksum,success
 FROM public._sqlx_migrations ORDER BY version
)
SELECT jsonb_build_object(
 'postgres_major',substring(current_setting('server_version') from '^[0-9]+'),
 'tables',COALESCE((SELECT jsonb_agg(to_jsonb(t) - 'oid' ORDER BY schema,name) FROM tables t),'[]'::jsonb),
 'indexes',COALESCE((SELECT jsonb_agg(to_jsonb(i) - 'oid' ORDER BY schema,name) FROM indexes i),'[]'::jsonb),
 'constraints',COALESCE((SELECT jsonb_agg(to_jsonb(c) - 'oid' ORDER BY schema,table_name,name) FROM constraints c),'[]'::jsonb),
 'functions',COALESCE((SELECT jsonb_agg(to_jsonb(f) - 'oid' ORDER BY schema,name,identity_arguments) FROM functions f),'[]'::jsonb),
 'aggregates',COALESCE((SELECT jsonb_agg(to_jsonb(a) ORDER BY schema,name,identity_arguments) FROM aggregates a),'[]'::jsonb),
 'types',COALESCE((SELECT jsonb_agg(to_jsonb(t) ORDER BY schema,name) FROM types t),'[]'::jsonb),
 'triggers',COALESCE((SELECT jsonb_agg(to_jsonb(t) - 'oid' ORDER BY schema,table_name,name) FROM triggers t),'[]'::jsonb),
 'views',COALESCE((SELECT jsonb_agg(to_jsonb(v) - 'oid' ORDER BY schema,name) FROM views v),'[]'::jsonb),
 'sequences',COALESCE((SELECT jsonb_agg(to_jsonb(s) - 'oid' ORDER BY schema,name) FROM sequences s),'[]'::jsonb),
 'rls_policies',COALESCE((SELECT jsonb_agg(to_jsonb(p) - 'polrelid' ORDER BY schema,table_name,name) FROM policies p),'[]'::jsonb),
 'schemas',COALESCE((SELECT jsonb_agg(to_jsonb(s) - 'oid' ORDER BY name) FROM schemas s),'[]'::jsonb),
 'extensions',COALESCE((SELECT jsonb_agg(to_jsonb(e) ORDER BY name) FROM extensions e),'[]'::jsonb),
 'event_triggers',COALESCE((SELECT jsonb_agg(to_jsonb(e) ORDER BY name) FROM event_triggers e),'[]'::jsonb),
 'foreign_objects',COALESCE((SELECT jsonb_agg(to_jsonb(f) ORDER BY kind,name) FROM foreign_objects f),'[]'::jsonb),
 'foreign_user_mappings',COALESCE((SELECT jsonb_agg(to_jsonb(u) ORDER BY server,role_name) FROM foreign_user_mappings u),'[]'::jsonb),
 'unexpected_relations',COALESCE((SELECT jsonb_agg(to_jsonb(r) ORDER BY schema,name,kind) FROM unexpected_relations r),'[]'::jsonb),
 'database_settings',COALESCE((SELECT jsonb_agg(to_jsonb(s) ORDER BY datname,rolname) FROM database_settings s),'[]'::jsonb),
 'database_acl',COALESCE((SELECT jsonb_agg(to_jsonb(d) ORDER BY datname) FROM database_acl d),'[]'::jsonb),
 'rules',COALESCE((SELECT jsonb_agg(to_jsonb(r) ORDER BY schema,table_name,name) FROM rules r),'[]'::jsonb),
 'default_acls',COALESCE((SELECT jsonb_agg(to_jsonb(a) ORDER BY schema,object_type,role) FROM default_acls a),'[]'::jsonb),
 'roles',COALESCE((SELECT jsonb_agg(to_jsonb(r) ORDER BY rolname) FROM roles r),'[]'::jsonb),
 'memberships',COALESCE((SELECT jsonb_agg(to_jsonb(m) ORDER BY role_name,member_name,grantor) FROM memberships m),'[]'::jsonb),
 'migrations',COALESCE((SELECT jsonb_agg(to_jsonb(m) ORDER BY version) FROM migrations m),'[]'::jsonb)
) AS catalog;
