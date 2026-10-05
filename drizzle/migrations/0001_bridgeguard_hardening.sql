-- BridgeGuard Pro v32 hardening pass.
-- Tighten call mutation authorization so members cannot rewrite initiator/conversation/start time.

DROP POLICY IF EXISTS "calls: members update" ON public.calls;

CREATE POLICY "calls: participants update status only" ON public.calls
FOR UPDATE TO authenticated
USING (
  public.is_member(conversation_id, auth.uid())
  AND (
    initiator_id = auth.uid()
    OR status IN ('ringing','active')
  )
)
WITH CHECK (
  public.is_member(conversation_id, auth.uid())
  AND initiator_id = (SELECT c.initiator_id FROM public.calls c WHERE c.id = calls.id)
  AND conversation_id = (SELECT c.conversation_id FROM public.calls c WHERE c.id = calls.id)
  AND started_at = (SELECT c.started_at FROM public.calls c WHERE c.id = calls.id)
);

-- A caller can end its own call; a participant can transition ringing/active
-- to a terminal state without changing ownership or conversation identity.
