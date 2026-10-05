-- BridgeGuard Pro v32: REDTEAM hardening pass 3.
-- Call semantics are explicitly 1:1 until a dedicated multi-party protocol exists.
-- Prevent cross-participant signaling abuse and concurrent-call races.

CREATE UNIQUE INDEX IF NOT EXISTS calls_one_active_per_conversation
  ON public.calls(conversation_id)
  WHERE status IN ('ringing','active');

CREATE OR REPLACE FUNCTION public.start_call(
  _conversation uuid,
  _route text DEFAULT 'unknown'
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  uid uuid := auth.uid();
  cid uuid;
  member_count int;
BEGIN
  IF uid IS NULL THEN
    RAISE EXCEPTION 'not authenticated';
  END IF;

  IF _route NOT IN ('p2p', 'relay', 'unknown') THEN
    RAISE EXCEPTION 'invalid call route';
  END IF;

  SELECT count(*) INTO member_count
  FROM public.conversation_members
  WHERE conversation_id = _conversation;

  IF member_count <> 2 OR NOT public.is_member(_conversation, uid) THEN
    RAISE EXCEPTION 'call requires exactly two conversation members';
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.calls
    WHERE conversation_id = _conversation
      AND status IN ('ringing','active')
  ) THEN
    RAISE EXCEPTION 'active call already exists';
  END IF;

  IF NOT public.check_rate_limit('start_call', 20, 3600) THEN
    RAISE EXCEPTION 'rate limited';
  END IF;

  INSERT INTO public.calls(conversation_id, initiator_id, status, route)
  VALUES (_conversation, uid, 'ringing', _route)
  RETURNING id INTO cid;

  RETURN cid;
EXCEPTION
  WHEN unique_violation THEN
    RAISE EXCEPTION 'active call already exists';
END
$$;

REVOKE ALL ON FUNCTION public.start_call(uuid, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.start_call(uuid, text) TO authenticated;

CREATE OR REPLACE FUNCTION public.update_call_status(
  _call uuid,
  _status public.call_status
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  uid uuid := auth.uid();
  current_status public.call_status;
  conversation uuid;
BEGIN
  IF uid IS NULL THEN
    RAISE EXCEPTION 'not authenticated';
  END IF;

  SELECT c.status, c.conversation_id
    INTO current_status, conversation
  FROM public.calls c
  WHERE c.id = _call
    AND public.is_member(c.conversation_id, uid);

  IF current_status IS NULL THEN
    RAISE EXCEPTION 'not allowed';
  END IF;

  IF current_status = 'ringing' AND _status NOT IN ('active','ended','missed','failed') THEN
    RAISE EXCEPTION 'invalid call transition';
  ELSIF current_status = 'active' AND _status NOT IN ('ended','failed') THEN
    RAISE EXCEPTION 'invalid call transition';
  ELSIF current_status IN ('ended','missed','failed') THEN
    RAISE EXCEPTION 'call already finalized';
  END IF;

  UPDATE public.calls
  SET status = _status,
      ended_at = CASE
        WHEN _status IN ('ended','missed','failed') THEN COALESCE(ended_at, now())
        ELSE ended_at
      END
  WHERE id = _call
    AND public.is_member(conversation, uid);
END
$$;

REVOKE ALL ON FUNCTION public.update_call_status(uuid, public.call_status) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.update_call_status(uuid, public.call_status) TO authenticated;

DROP POLICY IF EXISTS "signals: call members send" ON public.call_signals;
CREATE POLICY "signals: call members send" ON public.call_signals
FOR INSERT TO authenticated
WITH CHECK (
  sender_id = auth.uid()
  AND kind IN ('offer','answer','candidate','hangup')
  AND jsonb_typeof(payload) = 'object'
  AND octet_length(payload::text) <= 16000
  AND EXISTS (
    SELECT 1
    FROM public.calls c
    WHERE c.id = call_id
      AND c.status IN ('ringing','active')
      AND public.is_member(c.conversation_id, auth.uid())
      AND (SELECT count(*) FROM public.conversation_members cm WHERE cm.conversation_id = c.conversation_id) = 2
  )
);

REVOKE UPDATE ON public.call_signals FROM authenticated;
REVOKE DELETE ON public.call_signals FROM authenticated;
