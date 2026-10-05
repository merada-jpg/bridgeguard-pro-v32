-- Bridge Pro v32 core schema. Principle: least privilege, RLS on every table,
-- no plaintext message column, no private keys server-side.

CREATE TYPE public.device_verification AS ENUM ('unverified', 'verified');
CREATE TYPE public.call_status AS ENUM ('ringing', 'active', 'ended', 'missed', 'failed');

-- PROFILES -----------------------------------------------------------------
CREATE TABLE public.profiles (
  id uuid PRIMARY KEY,
  handle text UNIQUE NOT NULL CHECK (handle ~ '^[a-z0-9_]{3,24}$'),
  display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 60),
  created_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, UPDATE ON public.profiles TO authenticated;
GRANT ALL ON public.profiles TO service_role;
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

-- DEVICES (public keys only) ----------------------------------------------
CREATE TABLE public.devices (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 60),
  public_identity_key text NOT NULL CHECK (char_length(public_identity_key) BETWEEN 40 AND 400),
  fingerprint text NOT NULL CHECK (char_length(fingerprint) BETWEEN 16 AND 128),
  verification public.device_verification NOT NULL DEFAULT 'unverified',
  key_version int NOT NULL DEFAULT 1,
  key_rotated_at timestamptz,
  revoked_at timestamptz,
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX devices_user_idx ON public.devices(user_id);
GRANT SELECT, INSERT ON public.devices TO authenticated;
GRANT ALL ON public.devices TO service_role;
ALTER TABLE public.devices ENABLE ROW LEVEL SECURITY;

-- CONVERSATIONS -------------------------------------------------------------
CREATE TABLE public.conversations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  title text NOT NULL CHECK (char_length(title) BETWEEN 1 AND 80),
  created_by uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT ON public.conversations TO authenticated;
GRANT ALL ON public.conversations TO service_role;
ALTER TABLE public.conversations ENABLE ROW LEVEL SECURITY;

CREATE TABLE public.conversation_members (
  conversation_id uuid NOT NULL REFERENCES public.conversations(id) ON DELETE CASCADE,
  user_id uuid NOT NULL,
  role text NOT NULL DEFAULT 'member' CHECK (role IN ('owner','member')),
  joined_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (conversation_id, user_id)
);
CREATE INDEX cm_user_idx ON public.conversation_members(user_id);
GRANT SELECT, DELETE ON public.conversation_members TO authenticated;
GRANT ALL ON public.conversation_members TO service_role;
ALTER TABLE public.conversation_members ENABLE ROW LEVEL SECURITY;

-- MESSAGES: ciphertext only -----------------------------------------------
CREATE TABLE public.messages (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  conversation_id uuid NOT NULL REFERENCES public.conversations(id) ON DELETE CASCADE,
  sender_id uuid NOT NULL,
  sender_device_id uuid NOT NULL REFERENCES public.devices(id),
  alg text NOT NULL CHECK (alg IN ('ECDH-P256+HKDF-SHA256+AES-256-GCM')),
  ciphertext text NOT NULL CHECK (char_length(ciphertext) BETWEEN 1 AND 20000),
  iv text NOT NULL CHECK (char_length(iv) BETWEEN 8 AND 64),
  envelopes jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX messages_conv_idx ON public.messages(conversation_id, created_at);
GRANT SELECT, INSERT ON public.messages TO authenticated;
GRANT ALL ON public.messages TO service_role;
ALTER TABLE public.messages ENABLE ROW LEVEL SECURITY;

-- SECURITY EVENTS (append-only, written via function/triggers) -------------
CREATE TABLE public.security_events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id uuid NOT NULL,
  event_type text NOT NULL,
  detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX se_user_idx ON public.security_events(user_id, created_at DESC);
GRANT SELECT ON public.security_events TO authenticated;
GRANT ALL ON public.security_events TO service_role;
ALTER TABLE public.security_events ENABLE ROW LEVEL SECURITY;

-- AI CONSENTS (per conversation, opt-in) ----------------------------------
CREATE TABLE public.ai_consents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  conversation_id uuid NOT NULL REFERENCES public.conversations(id) ON DELETE CASCADE,
  granted_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);
CREATE UNIQUE INDEX ai_consent_active ON public.ai_consents(user_id, conversation_id) WHERE revoked_at IS NULL;
GRANT SELECT ON public.ai_consents TO authenticated;
GRANT ALL ON public.ai_consents TO service_role;
ALTER TABLE public.ai_consents ENABLE ROW LEVEL SECURITY;

-- CALLS + SIGNALING --------------------------------------------------------
CREATE TABLE public.calls (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  conversation_id uuid NOT NULL REFERENCES public.conversations(id) ON DELETE CASCADE,
  initiator_id uuid NOT NULL,
  status public.call_status NOT NULL DEFAULT 'ringing',
  route text CHECK (route IN ('p2p','relay','unknown')),
  started_at timestamptz NOT NULL DEFAULT now(),
  ended_at timestamptz
);
GRANT SELECT, INSERT, UPDATE ON public.calls TO authenticated;
GRANT ALL ON public.calls TO service_role;
ALTER TABLE public.calls ENABLE ROW LEVEL SECURITY;

CREATE TABLE public.call_signals (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  call_id uuid NOT NULL REFERENCES public.calls(id) ON DELETE CASCADE,
  sender_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('offer','answer','candidate','hangup')),
  payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT ON public.call_signals TO authenticated;
GRANT ALL ON public.call_signals TO service_role;
ALTER TABLE public.call_signals ENABLE ROW LEVEL SECURITY;

-- RATE LIMITS (no client access at all) -----------------------------------
CREATE TABLE public.rate_limits (
  user_id uuid NOT NULL,
  bucket text NOT NULL,
  window_start timestamptz NOT NULL,
  count int NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, bucket, window_start)
);
GRANT ALL ON public.rate_limits TO service_role;
ALTER TABLE public.rate_limits ENABLE ROW LEVEL SECURITY;

-- HELPERS ------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.is_member(_conv uuid, _uid uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM conversation_members WHERE conversation_id = _conv AND user_id = _uid)
$$;

CREATE OR REPLACE FUNCTION public.shares_conversation(_a uuid, _b uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (
    SELECT 1 FROM conversation_members m1
    JOIN conversation_members m2 ON m1.conversation_id = m2.conversation_id
    WHERE m1.user_id = _a AND m2.user_id = _b)
$$;

CREATE OR REPLACE FUNCTION public.write_security_event(_uid uuid, _type text, _detail jsonb)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  INSERT INTO security_events(user_id, event_type, detail) VALUES (_uid, _type, coalesce(_detail,'{}'::jsonb));
$$;
REVOKE ALL ON FUNCTION public.write_security_event(uuid, text, jsonb) FROM PUBLIC, anon, authenticated;

-- Fixed-window rate limiter. Returns true when allowed.
CREATE OR REPLACE FUNCTION public.check_rate_limit(_bucket text, _max int, _window_seconds int)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE uid uuid := auth.uid(); ws timestamptz; c int;
BEGIN
  IF uid IS NULL THEN RETURN false; END IF;
  IF _bucket !~ '^[a-z_]{2,32}$' OR _max < 1 OR _max > 1000 OR _window_seconds < 1 OR _window_seconds > 86400 THEN
    RAISE EXCEPTION 'invalid rate limit parameters';
  END IF;
  ws := to_timestamp(floor(extract(epoch FROM now()) / _window_seconds) * _window_seconds);
  INSERT INTO rate_limits(user_id, bucket, window_start, count) VALUES (uid, _bucket, ws, 1)
  ON CONFLICT (user_id, bucket, window_start) DO UPDATE SET count = rate_limits.count + 1
  RETURNING count INTO c;
  DELETE FROM rate_limits WHERE user_id = uid AND window_start < now() - interval '1 day';
  RETURN c <= _max;
END $$;
REVOKE ALL ON FUNCTION public.check_rate_limit(text,int,int) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.check_rate_limit(text,int,int) TO authenticated;

-- Client-callable logger with an allowlist of event types.
CREATE OR REPLACE FUNCTION public.log_security_event(_type text, _detail jsonb DEFAULT '{}'::jsonb)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF auth.uid() IS NULL THEN RAISE EXCEPTION 'not authenticated'; END IF;
  IF _type NOT IN ('sign_in','sign_out','sign_out_all','session_expired','data_export','fingerprint_viewed') THEN
    RAISE EXCEPTION 'event type not allowed';
  END IF;
  IF octet_length(_detail::text) > 1000 THEN RAISE EXCEPTION 'detail too large'; END IF;
  IF NOT check_rate_limit('sec_log', 60, 60) THEN RAISE EXCEPTION 'rate limited'; END IF;
  PERFORM write_security_event(auth.uid(), _type, _detail);
END $$;
REVOKE ALL ON FUNCTION public.log_security_event(text,jsonb) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.log_security_event(text,jsonb) TO authenticated;

-- Profile auto-create on signup
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE base text;
BEGIN
  base := lower(regexp_replace(split_part(coalesce(NEW.email,'user'),'@',1), '[^a-z0-9_]', '', 'g'));
  IF char_length(base) < 3 THEN base := 'user'; END IF;
  base := left(base, 16) || '_' || substr(replace(NEW.id::text,'-',''),1,6);
  INSERT INTO profiles(id, handle, display_name)
  VALUES (NEW.id, base, left(coalesce(NEW.raw_user_meta_data->>'display_name', split_part(NEW.email,'@',1), 'مستخدم'), 60));
  PERFORM write_security_event(NEW.id, 'account_created', '{}'::jsonb);
  RETURN NEW;
END $$;
CREATE TRIGGER on_auth_user_created AFTER INSERT ON auth.users FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- RPCs for privileged-but-authorized mutations ----------------------------
CREATE OR REPLACE FUNCTION public.create_conversation(_title text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE cid uuid; uid uuid := auth.uid();
BEGIN
  IF uid IS NULL THEN RAISE EXCEPTION 'not authenticated'; END IF;
  IF char_length(trim(_title)) NOT BETWEEN 1 AND 80 THEN RAISE EXCEPTION 'invalid title'; END IF;
  IF NOT check_rate_limit('create_conv', 20, 3600) THEN RAISE EXCEPTION 'rate limited'; END IF;
  INSERT INTO conversations(title, created_by) VALUES (trim(_title), uid) RETURNING id INTO cid;
  INSERT INTO conversation_members(conversation_id, user_id, role) VALUES (cid, uid, 'owner');
  RETURN cid;
END $$;
REVOKE ALL ON FUNCTION public.create_conversation(text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.create_conversation(text) TO authenticated;

CREATE OR REPLACE FUNCTION public.add_member_by_handle(_conv uuid, _handle text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE target uuid; uid uuid := auth.uid();
BEGIN
  IF uid IS NULL THEN RAISE EXCEPTION 'not authenticated'; END IF;
  IF NOT EXISTS (SELECT 1 FROM conversation_members WHERE conversation_id=_conv AND user_id=uid AND role='owner') THEN
    RAISE EXCEPTION 'not allowed';
  END IF;
  IF NOT check_rate_limit('add_member', 30, 3600) THEN RAISE EXCEPTION 'rate limited'; END IF;
  SELECT id INTO target FROM profiles WHERE handle = lower(trim(_handle));
  -- Same generic error for "not found" to limit handle enumeration.
  IF target IS NULL THEN RAISE EXCEPTION 'could not add member'; END IF;
  INSERT INTO conversation_members(conversation_id, user_id) VALUES (_conv, target) ON CONFLICT DO NOTHING;
END $$;
REVOKE ALL ON FUNCTION public.add_member_by_handle(uuid,text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.add_member_by_handle(uuid,text) TO authenticated;

CREATE OR REPLACE FUNCTION public.revoke_device(_device uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  UPDATE devices SET revoked_at = now() WHERE id = _device AND user_id = auth.uid() AND revoked_at IS NULL;
  IF NOT FOUND THEN RAISE EXCEPTION 'not allowed'; END IF;
  PERFORM write_security_event(auth.uid(), 'device_revoked', jsonb_build_object('device_id', _device));
END $$;
REVOKE ALL ON FUNCTION public.revoke_device(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.revoke_device(uuid) TO authenticated;

CREATE OR REPLACE FUNCTION public.rotate_device_key(_device uuid, _public_key text, _fingerprint text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF char_length(_public_key) NOT BETWEEN 40 AND 400 OR char_length(_fingerprint) NOT BETWEEN 16 AND 128 THEN
    RAISE EXCEPTION 'invalid key';
  END IF;
  IF NOT check_rate_limit('rotate_key', 10, 3600) THEN RAISE EXCEPTION 'rate limited'; END IF;
  UPDATE devices SET public_identity_key=_public_key, fingerprint=_fingerprint,
    key_version = key_version + 1, key_rotated_at = now(), verification = 'unverified'
  WHERE id=_device AND user_id=auth.uid() AND revoked_at IS NULL;
  IF NOT FOUND THEN RAISE EXCEPTION 'not allowed'; END IF;
  PERFORM write_security_event(auth.uid(), 'key_rotated', jsonb_build_object('device_id', _device));
END $$;
REVOKE ALL ON FUNCTION public.rotate_device_key(uuid,text,text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.rotate_device_key(uuid,text,text) TO authenticated;

-- Marks a device as verified by its OWNER after comparing fingerprints out-of-band.
CREATE OR REPLACE FUNCTION public.mark_device_verified(_device uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  UPDATE devices SET verification='verified' WHERE id=_device AND user_id=auth.uid() AND revoked_at IS NULL;
  IF NOT FOUND THEN RAISE EXCEPTION 'not allowed'; END IF;
  PERFORM write_security_event(auth.uid(), 'device_verified', jsonb_build_object('device_id', _device));
END $$;
REVOKE ALL ON FUNCTION public.mark_device_verified(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.mark_device_verified(uuid) TO authenticated;

CREATE OR REPLACE FUNCTION public.set_ai_consent(_conv uuid, _granted boolean)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT is_member(_conv, auth.uid()) THEN RAISE EXCEPTION 'not allowed'; END IF;
  IF _granted THEN
    INSERT INTO ai_consents(user_id, conversation_id) VALUES (auth.uid(), _conv) ON CONFLICT DO NOTHING;
    PERFORM write_security_event(auth.uid(), 'ai_consent_granted', jsonb_build_object('conversation_id', _conv));
  ELSE
    UPDATE ai_consents SET revoked_at = now() WHERE user_id=auth.uid() AND conversation_id=_conv AND revoked_at IS NULL;
    PERFORM write_security_event(auth.uid(), 'ai_consent_revoked', jsonb_build_object('conversation_id', _conv));
  END IF;
END $$;
REVOKE ALL ON FUNCTION public.set_ai_consent(uuid,boolean) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.set_ai_consent(uuid,boolean) TO authenticated;

-- Device insert audit
CREATE OR REPLACE FUNCTION public.audit_device_insert()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  PERFORM write_security_event(NEW.user_id, 'device_registered', jsonb_build_object('device_id', NEW.id, 'name', NEW.name));
  RETURN NEW;
END $$;
CREATE TRIGGER devices_audit AFTER INSERT ON public.devices FOR EACH ROW EXECUTE FUNCTION public.audit_device_insert();

-- POLICIES -----------------------------------------------------------------
CREATE POLICY "profiles: self or co-member read" ON public.profiles FOR SELECT TO authenticated
  USING (id = auth.uid() OR public.shares_conversation(auth.uid(), id));
CREATE POLICY "profiles: self update" ON public.profiles FOR UPDATE TO authenticated
  USING (id = auth.uid()) WITH CHECK (id = auth.uid());

CREATE POLICY "devices: self or co-member read" ON public.devices FOR SELECT TO authenticated
  USING (user_id = auth.uid() OR public.shares_conversation(auth.uid(), user_id));
CREATE POLICY "devices: self insert unverified" ON public.devices FOR INSERT TO authenticated
  WITH CHECK (user_id = auth.uid() AND verification = 'unverified' AND revoked_at IS NULL AND key_version = 1);

CREATE POLICY "conversations: members read" ON public.conversations FOR SELECT TO authenticated
  USING (public.is_member(id, auth.uid()));

CREATE POLICY "members: co-members read" ON public.conversation_members FOR SELECT TO authenticated
  USING (public.is_member(conversation_id, auth.uid()));
CREATE POLICY "members: leave self" ON public.conversation_members FOR DELETE TO authenticated
  USING (user_id = auth.uid());

CREATE POLICY "messages: members read" ON public.messages FOR SELECT TO authenticated
  USING (public.is_member(conversation_id, auth.uid()));
CREATE POLICY "messages: members send from own active device" ON public.messages FOR INSERT TO authenticated
  WITH CHECK (
    sender_id = auth.uid()
    AND public.is_member(conversation_id, auth.uid())
    AND EXISTS (SELECT 1 FROM public.devices d WHERE d.id = sender_device_id AND d.user_id = auth.uid() AND d.revoked_at IS NULL)
  );

CREATE POLICY "security_events: own read" ON public.security_events FOR SELECT TO authenticated
  USING (user_id = auth.uid());

CREATE POLICY "ai_consents: own read" ON public.ai_consents FOR SELECT TO authenticated
  USING (user_id = auth.uid());

CREATE POLICY "calls: members read" ON public.calls FOR SELECT TO authenticated
  USING (public.is_member(conversation_id, auth.uid()));
CREATE POLICY "calls: members start" ON public.calls FOR INSERT TO authenticated
  WITH CHECK (initiator_id = auth.uid() AND status = 'ringing' AND public.is_member(conversation_id, auth.uid()));
CREATE POLICY "calls: members update" ON public.calls FOR UPDATE TO authenticated
  USING (public.is_member(conversation_id, auth.uid()))
  WITH CHECK (public.is_member(conversation_id, auth.uid()));

CREATE POLICY "signals: call members read" ON public.call_signals FOR SELECT TO authenticated
  USING (EXISTS (SELECT 1 FROM public.calls c WHERE c.id = call_id AND public.is_member(c.conversation_id, auth.uid())));
CREATE POLICY "signals: call members send" ON public.call_signals FOR INSERT TO authenticated
  WITH CHECK (sender_id = auth.uid() AND octet_length(payload::text) < 16000
    AND EXISTS (SELECT 1 FROM public.calls c WHERE c.id = call_id AND c.status IN ('ringing','active') AND public.is_member(c.conversation_id, auth.uid())));

-- rate_limits: no policies => no client access.

ALTER PUBLICATION supabase_realtime ADD TABLE public.messages;
ALTER PUBLICATION supabase_realtime ADD TABLE public.call_signals;
ALTER PUBLICATION supabase_realtime ADD TABLE public.calls;