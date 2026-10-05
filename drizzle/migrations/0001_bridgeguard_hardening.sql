-- BridgeGuard Pro v32 hardening pass.
-- Do not allow arbitrary member updates to call ownership, routing or timestamps.

REVOKE UPDATE ON public.calls FROM authenticated;

CREATE OR REPLACE FUNCTION public.update_call_status(_call uuid, _status public.call_status)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  uid uuid := auth.uid();
  current_status public.call_status;
BEGIN
  IF uid IS NULL THEN RAISE EXCEPTION 'not authenticated'; END IF;

  SELECT status INTO current_status
  FROM public.calls
  WHERE id = _call
    AND public.is_member(conversation_id, uid);

  IF current_status IS NULL THEN RAISE EXCEPTION 'not allowed'; END IF;

  IF _status NOT IN ('active','ended','missed','failed') THEN
    RAISE EXCEPTION 'invalid call transition';
  END IF;

  IF current_status = 'ended' THEN
    RAISE EXCEPTION 'call already ended';
  END IF;

  UPDATE public.calls
  SET status = _status,
      ended_at = CASE WHEN _status IN ('ended','missed','failed') THEN now() ELSE ended_at END
  WHERE id = _call;
END
$$;

REVOKE ALL ON FUNCTION public.update_call_status(uuid, public.call_status) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.update_call_status(uuid, public.call_status) TO authenticated;
