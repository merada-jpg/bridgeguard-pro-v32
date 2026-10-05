-- BridgeGuard Pro v32: REDTEAM hardening pass 2.
-- Goals:
-- 1) remove client-side mass assignment paths for device/call creation;
-- 2) bind message sender epochs to the registered device key;
-- 3) make call state transitions monotonic;
-- 4) narrow profile update privileges;
-- 5) add server-side rate limits to high-cost object creation.

-- PROFILES: clients may only edit user-controlled profile fields.
REVOKE UPDATE ON public.profiles FROM authenticated;
GRANT UPDATE (handle, display_name) ON public.profiles TO authenticated;

-- DEVICES: registration must go through an authorization/rate-limit RPC.
REVOKE INSERT ON public.devices FROM authenticated;

CREATE OR REPLACE FUNCTION public.register_device(
  _name text,
  _public_key text,
  _fingerprint text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  uid uuid := auth.uid();
  new_id uuid;
  new_version int;
BEGIN
  IF uid IS NULL THEN
    RAISE EXCEPTION 'not authenticated';
  END IF;

  IF char_length(trim(_name)) NOT BETWEEN 1 AND 60
     OR char_length(_public_key) NOT BETWEEN 40 AND 400
     OR char_length(_fingerprint) NOT BETWEEN 16 AND 128 THEN
    RAISE EXCEPTION 'invalid device';
  END IF;

  IF NOT check_rate_limit('register_device', 10, 3600) THEN
    RAISE EXCEPTION 'rate limited';
  END IF;

  INSERT INTO public.devices(user_id, name, public_identity_key, fingerprint)
  VALUES (uid, trim(_name), _public_key, upper(_fingerprint))
  RETURNING id, key_version INTO new_id, new_version;

  RETURN jsonb_build_object('id', new_id, 'key_version', new_version);
END
$$;

REVOKE ALL ON FUNCTION public.register_device(text, text, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.register_device(text, text, text) TO authenticated;

-- MESSAGES: bind the sender's encrypted epoch to the server-registered device.
-- This prevents a malicious client from presenting a different sender public key
-- inside the envelope while claiming to send from another registered device.
DROP POLICY IF EXISTS "messages: members send from own active device" ON public.messages;
CREATE POLICY "messages: members send from own active device" ON public.messages
FOR INSERT TO authenticated
WITH CHECK (
  sender_id = auth.uid()
  AND public.is_member(conversation_id, auth.uid())
  AND jsonb_typeof(envelopes) = 'object'
  AND jsonb_typeof(envelopes->'r') = 'object'
  AND (envelopes->>'spk') IS NOT NULL
  AND (envelopes->>'sv') ~ '^[0-9]+$'
  AND EXISTS (
    SELECT 1
    FROM public.devices d
    WHERE d.id = sender_device_id
      AND d.user_id = auth.uid()
      AND d.revoked_at IS NULL
      AND d.public_identity_key = envelopes->>'spk'
      AND d.key_version = (envelopes->>'sv')::int
  )
  AND octet_length(envelopes::text) <= 200000
);

-- CALLS: creation is now server-controlled.
REVOKE INSERT ON public.calls FROM authenticated;

CREATE OR REPLACE FUNCTION public.start_call(
  _conversation uuid,
  _route text DEFAULT 'unknown'
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  uid uuid := auth.uid();
  cid uuid;
BEGIN
  IF uid IS NULL THEN
    RAISE EXCEPTION 'not authenticated';
  END IF;

  IF _route NOT IN ('p2p', 'relay', 'unknown') THEN
    RAISE EXCEPTION 'invalid call route';
  END IF;

  IF NOT public.is_member(_conversation, uid) THEN
    RAISE EXCEPTION 'not allowed';
  END IF;

  IF NOT public.check_rate_limit('start_call', 20, 3600) THEN
    RAISE EXCEPTION 'rate limited';
  END IF;

  INSERT INTO public.calls(conversation_id, initiator_id, status, route)
  VALUES (_conversation, uid, 'ringing', _route)
  RETURNING id INTO cid;

  RETURN cid;
END
$$;

REVOKE ALL ON FUNCTION public.start_call(uuid, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.start_call(uuid, text) TO authenticated;

-- CALLS: only legal forward transitions.
CREATE OR REPLACE FUNCTION public.update_call_status(
  _call uuid,
  _status public.call_status
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  uid uuid := auth.uid();
  current_status public.call_status;
BEGIN
  IF uid IS NULL THEN
    RAISE EXCEPTION 'not authenticated';
  END IF;

  SELECT c.status INTO current_status
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
  WHERE id = _call;
END
$$;

REVOKE ALL ON FUNCTION public.update_call_status(uuid, public.call_status) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.update_call_status(uuid, public.call_status) TO authenticated;

-- Keep the direct table UPDATE denial explicit after migrations that may recreate grants.
REVOKE UPDATE ON public.calls FROM authenticated;
