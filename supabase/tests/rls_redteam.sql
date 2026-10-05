-- BridgeGuard Pro v32 REDTEAM regression tests (pgTAP).
-- These tests are intentionally structural: they do not require real user rows.
-- Run with: supabase test db (when Supabase CLI/test harness is configured).

BEGIN;

SELECT plan(16);

-- Every exposed application table must have RLS enabled.
SELECT ok(c.relrowsecurity, 'RLS enabled on ' || c.relname)
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
  AND c.relname IN (
    'profiles','devices','conversations','conversation_members',
    'messages','security_events','ai_consents','calls','call_signals','rate_limits'
  )
ORDER BY c.relname;

-- Client-facing tables must not expose broad PUBLIC privileges.
SELECT is(
  has_table_privilege('public', 'public.devices', 'INSERT'),
  false,
  'PUBLIC cannot insert devices'
);
SELECT is(
  has_table_privilege('public', 'public.calls', 'UPDATE'),
  false,
  'PUBLIC cannot update calls'
);

-- Controlled mutation RPCs are callable only by authenticated users.
SELECT is(
  has_function_privilege('public', 'public.register_device(text,text,text)', 'EXECUTE'),
  false,
  'PUBLIC cannot execute register_device'
);
SELECT is(
  has_function_privilege('anon', 'public.register_device(text,text,text)', 'EXECUTE'),
  false,
  'anon cannot execute register_device'
);
SELECT is(
  has_function_privilege('authenticated', 'public.register_device(text,text,text)', 'EXECUTE'),
  true,
  'authenticated can execute register_device'
);

-- Internal trigger helpers must not be Data API callable.
SELECT is(
  has_function_privilege('authenticated', 'public.handle_new_user()', 'EXECUTE'),
  false,
  'authenticated cannot execute handle_new_user'
);
SELECT is(
  has_function_privilege('authenticated', 'public.audit_device_insert()', 'EXECUTE'),
  false,
  'authenticated cannot execute audit_device_insert'
);
SELECT is(
  has_function_privilege('authenticated', 'public.write_security_event(uuid,text,jsonb)', 'EXECUTE'),
  false,
  'authenticated cannot execute internal event writer'
);

-- High-risk direct table writes are revoked.
SELECT is(
  has_table_privilege('authenticated', 'public.devices', 'INSERT'),
  false,
  'authenticated cannot directly insert devices'
);
SELECT is(
  has_table_privilege('authenticated', 'public.calls', 'INSERT'),
  false,
  'authenticated cannot directly insert calls'
);
SELECT is(
  has_table_privilege('authenticated', 'public.calls', 'UPDATE'),
  false,
  'authenticated cannot directly update calls'
);

-- RLS policies exist for the main authorization boundaries.
SELECT ok(
  EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename='messages' AND policyname='messages: members read'),
  'messages member-read policy exists'
);
SELECT ok(
  EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename='messages' AND policyname='messages: members send from own active device'),
  'messages sender/device binding policy exists'
);
SELECT ok(
  EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename='call_signals' AND policyname='signals: call members send'),
  'call signal membership policy exists'
);
SELECT ok(
  EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename='profiles' AND policyname='profiles: self update'),
  'profile self-update policy exists'
);

SELECT * FROM finish();
ROLLBACK;
