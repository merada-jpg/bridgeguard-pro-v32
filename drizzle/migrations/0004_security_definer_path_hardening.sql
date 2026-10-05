-- REDTEAM hardening pass 4: pin SECURITY DEFINER helper search_path to empty.
-- These helpers are reachable from RLS policies, so keep their execution context
-- deterministic and schema-qualified.

CREATE OR REPLACE FUNCTION public.is_member(_conv uuid, _uid uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
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
SET search_path = ''
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
