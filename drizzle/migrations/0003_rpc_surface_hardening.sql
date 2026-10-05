-- REDTEAM hardening pass 3: close callable helper information leaks.
-- Supabase/Postgres functions are executable by default unless explicitly revoked.
-- Keep only the minimum client-callable helpers exposed to authenticated users.

CREATE OR REPLACE FUNCTION public.is_member(_conv uuid, _uid uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.conversation_members
    WHERE conversation_id = _conv
      AND user_id = _uid
  )
$$;

CREATE OR REPLACE FUNCTION public.shares_conversation(_a uuid, _b uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.conversation_members m1
    JOIN public.conversation_members m2
      ON m1.conversation_id = m2.conversation_id
    WHERE m1.user_id = auth.uid()
      AND m2.user_id = CASE
        WHEN _a = auth.uid() THEN _b
        WHEN _b = auth.uid() THEN _a
        ELSE NULL
      END
  )
$$;

REVOKE EXECUTE ON FUNCTION public.is_member(uuid, uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.is_member(uuid, uuid) TO authenticated;

REVOKE EXECUTE ON FUNCTION public.shares_conversation(uuid, uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.shares_conversation(uuid, uuid) TO authenticated;

-- Trigger-only security-definer functions must not be callable from the Data API.
REVOKE EXECUTE ON FUNCTION public.handle_new_user() FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.audit_device_insert() FROM PUBLIC, anon, authenticated;

-- Internal event writer remains trigger/RPC-internal only.
REVOKE EXECUTE ON FUNCTION public.write_security_event(uuid, text, jsonb) FROM PUBLIC, anon, authenticated;

-- Avoid direct table writes where all mutations have a controlled RPC.
REVOKE INSERT ON public.devices FROM authenticated;
REVOKE INSERT ON public.calls FROM authenticated;
REVOKE UPDATE ON public.calls FROM authenticated;
