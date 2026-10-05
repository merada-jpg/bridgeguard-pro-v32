import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { z } from "zod";

/** Export the caller's own data (RLS-scoped; messages stay as ciphertext). */
export const exportMyData = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { supabase, userId } = context;
    const { data: allowed } = await supabase.rpc("check_rate_limit", { _bucket: "export", _max: 3, _window_seconds: 3600 });
    if (!allowed) return { ok: false as const, error: "محاولات كثيرة. حاول لاحقًا." };
    const [profile, devices, events, consents, sent] = await Promise.all([
      supabase.from("profiles").select("*").eq("id", userId).maybeSingle(),
      supabase.from("devices").select("id,name,fingerprint,verification,key_version,key_rotated_at,revoked_at,created_at,last_seen_at").eq("user_id", userId),
      supabase.from("security_events").select("event_type,detail,created_at").eq("user_id", userId).order("created_at", { ascending: false }).limit(500),
      supabase.from("ai_consents").select("conversation_id,granted_at,revoked_at").eq("user_id", userId),
      supabase.from("messages").select("id,conversation_id,alg,ciphertext,iv,created_at").eq("sender_id", userId).limit(5000),
    ]);
    await supabase.rpc("log_security_event", { _type: "data_export", _detail: {} });
    return {
      ok: true as const,
      data: {
        exported_at: new Date().toISOString(),
        note: "الرسائل مُصدّرة كنص مشفّر؛ لا يملك الخادم مفاتيح فكّها.",
        profile: profile.data,
        devices: devices.data,
        security_events: events.data,
        ai_consents: consents.data,
        sent_messages_ciphertext: sent.data,
      },
    };
  });

/** Permanently delete the caller's account. Requires typed confirmation. */
export const deleteMyAccount = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => z.object({ confirm: z.literal("احذف حسابي") }).parse(d))
  .handler(async ({ context }) => {
    const { userId } = context;
    // Privileged client loaded only after the caller is authenticated, and it
    // only ever targets the caller's own userId (never client-supplied ids).
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    await supabaseAdmin.from("messages").delete().eq("sender_id", userId);
    await supabaseAdmin.from("ai_consents").delete().eq("user_id", userId);
    await supabaseAdmin.from("conversation_members").delete().eq("user_id", userId);
    await supabaseAdmin.from("devices").delete().eq("user_id", userId);
    await supabaseAdmin.from("security_events").delete().eq("user_id", userId);
    await supabaseAdmin.from("rate_limits").delete().eq("user_id", userId);
    await supabaseAdmin.from("profiles").delete().eq("id", userId);
    const { error } = await supabaseAdmin.auth.admin.deleteUser(userId);
    if (error) return { ok: false as const, error: "تعذّر حذف الحساب. حاول لاحقًا." };
    return { ok: true as const };
  });

/** ICE servers. TURN credentials stay server-side env; only returned to signed-in users. */
export const getIceServers = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .handler(async () => {
    const servers: Array<{ urls: string | string[]; username?: string; credential?: string }> = [
      { urls: "stun:stun.l.google.com:19302" },
    ];
    const url = process.env["TURN_URL"];
    if (url) servers.push({ urls: url, username: process.env["TURN_USERNAME"], credential: process.env["TURN_CREDENTIAL"] });
    return { servers, turnConfigured: Boolean(url) };
  });