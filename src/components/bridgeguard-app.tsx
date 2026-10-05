import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  Bot,
  Check,
  ChevronLeft,
  Copy,
  Fingerprint,
  KeyRound,
  LockKeyhole,
  MessageSquare,
  Phone,
  Plus,
  RefreshCw,
  Send,
  ShieldCheck,
  ShieldAlert,
  Trash2,
  UserPlus,
  Video,
  Wifi,
  type LucideIcon,
} from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { safeError } from "@/lib/validation";
import { ensureDevice, getLocalDevice, rotateLocalKey } from "@/lib/device";
import { encryptMessage, decryptMessage, type EnvelopeSet } from "@/lib/crypto";
import { askAssistant } from "@/lib/ai.functions";
import { exportMyData, deleteMyAccount, getIceServers } from "@/lib/account.functions";

type Section = "home" | "messages" | "calls" | "security" | "privacy" | "ai";
type User = { id: string; email: string | null };
type Profile = { id: string; display_name: string; handle: string };
type Conversation = { id: string; title: string; created_by: string; created_at: string };
type Device = {
  id: string;
  name: string;
  fingerprint: string;
  verification: "unverified" | "verified";
  key_version: number;
  revoked_at: string | null;
  last_seen_at: string;
  public_identity_key: string;
};
type Message = {
  id: string;
  conversation_id: string;
  sender_id: string;
  sender_device_id: string;
  alg: string;
  ciphertext: string;
  iv: string;
  envelopes: EnvelopeSet;
  created_at: string;
  text?: string;
};

const demoMessages = [
  { from: "النظام", text: "وضع التجربة المحلية فعال. لا تُرسل أي بيانات إلى الخادم.", time: "الآن" },
  { from: "BridgeGuard", text: "المبدأ: لا ندّعي ما لم نستطع إثباته.", time: "الآن" },
];

function Button({ children, className = "", ...props }: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      {...props}
      className={[
        "inline-flex min-h-10 items-center justify-center gap-2 rounded-xl px-4 py-2 text-sm font-semibold transition",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary disabled:cursor-not-allowed disabled:opacity-50",
        className,
      ].join(" ")}
    >
      {children}
    </button>
  );
}

function Card({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return <section className={`surface p-5 ${className}`}>{children}</section>;
}

function Badge({ children, tone = "neutral" }: { children: React.ReactNode; tone?: "ok" | "warn" | "neutral" }) {
  const classes = tone === "ok"
    ? "bg-success/15 text-success"
    : tone === "warn"
      ? "bg-warning/15 text-warning"
      : "bg-muted text-muted-foreground";
  return <span className={`inline-flex items-center gap-1 rounded-full px-2.5 py-1 text-xs font-semibold ${classes}`}>{children}</span>;
}

function AuthScreen({ onGuest }: { onGuest: () => void }) {
  const [mode, setMode] = useState<"login" | "signup">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      if (mode === "signup") {
        const { error: err } = await supabase.auth.signUp({
          email: email.trim(),
          password,
          options: { data: { display_name: name.trim() || undefined } },
        });
        if (err) throw err;
        setError("تم إنشاء الحساب. إذا كان تأكيد البريد مفعّلًا، افتح رسالة التأكيد ثم سجّل الدخول.");
        setMode("login");
      } else {
        const { error: err } = await supabase.auth.signInWithPassword({ email: email.trim(), password });
        if (err) throw err;
      }
    } catch (e) {
      setError(safeError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="min-h-screen px-4 py-8 md:px-8">
      <div className="mx-auto grid min-h-[calc(100vh-4rem)] max-w-6xl items-center gap-8 lg:grid-cols-[1.05fr_.95fr]">
        <div className="animate-rise">
          <Badge tone="ok"><ShieldCheck className="size-3.5" /> BridgeGuard Pro v32</Badge>
          <h1 className="mt-5 max-w-3xl text-4xl font-black leading-tight md:text-6xl">
            اتصالات آمنة قابلة للإثبات، <span className="text-signal">لا مجرد ادعاءات.</span>
          </h1>
          <p className="mt-5 max-w-2xl text-base leading-8 text-muted-foreground md:text-lg">
            منصة عربية للرسائل والمكالمات ومركز أمان واضح: مفاتيح الجهاز تبقى محليًا، والرسائل المخزنة على الخادم نص مشفّر فقط.
          </p>
          <div className="mt-8 grid gap-3 sm:grid-cols-3">
            {([
              ["هوية الجهاز", "لا مفاتيح خاصة على الخادم", LockKeyhole],
              ["WebCrypto", "ECDH + HKDF + AES-GCM", KeyRound],
              ["RLS", "تفويض على مستوى البيانات", ShieldCheck],
            ] as Array<[string, string, LucideIcon]>).map(([title, desc, Icon]) => (
              <Card key={String(title)} className="p-4">
                <Icon className="size-5 text-primary" />
                <div className="mt-3 font-bold">{String(title)}</div>
                <div className="mt-1 text-xs leading-5 text-muted-foreground">{String(desc)}</div>
              </Card>
            ))}
          </div>
          <div className="mt-5 rounded-2xl border border-warning/30 bg-warning/10 p-4 text-sm leading-6 text-warning">
            هذه النسخة نموذج أمني متقدم وليست تدقيقًا تشفيريًا مستقلًا. لا تستخدمها لادعاءات "E2EE موثّق" أو "تشفير عسكري".
          </div>
        </div>

        <Card className="mx-auto w-full max-w-md animate-rise p-6">
          <div className="mb-6 flex gap-2 rounded-xl bg-muted p-1">
            <button onClick={() => setMode("login")} className={`flex-1 rounded-lg px-3 py-2 text-sm ${mode === "login" ? "bg-card font-bold" : "text-muted-foreground"}`}>دخول</button>
            <button onClick={() => setMode("signup")} className={`flex-1 rounded-lg px-3 py-2 text-sm ${mode === "signup" ? "bg-card font-bold" : "text-muted-foreground"}`}>حساب جديد</button>
          </div>
          <form onSubmit={submit} className="space-y-4">
            {mode === "signup" && (
              <label className="block text-sm">
                الاسم
                <input value={name} onChange={(e) => setName(e.target.value)} className="mt-1.5 w-full rounded-xl border bg-background px-3 py-3" maxLength={60} />
              </label>
            )}
            <label className="block text-sm">
              البريد الإلكتروني
              <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} className="mt-1.5 w-full rounded-xl border bg-background px-3 py-3" autoComplete="email" />
            </label>
            <label className="block text-sm">
              كلمة المرور
              <input type="password" required value={password} onChange={(e) => setPassword(e.target.value)} className="mt-1.5 w-full rounded-xl border bg-background px-3 py-3" minLength={10} autoComplete={mode === "login" ? "current-password" : "new-password"} />
            </label>
            {error && <div className="rounded-xl bg-warning/10 p-3 text-sm leading-6 text-warning">{error}</div>}
            <Button type="submit" disabled={busy} className="w-full bg-primary text-primary-foreground hover:opacity-90">
              {busy ? <RefreshCw className="size-4 animate-spin" /> : null}
              {mode === "login" ? "دخول آمن" : "إنشاء الحساب"}
            </Button>
          </form>
          <div className="my-5 flex items-center gap-3 text-xs text-muted-foreground"><span className="h-px flex-1 bg-border" /> أو <span className="h-px flex-1 bg-border" /></div>
          <Button onClick={onGuest} className="w-full border bg-background hover:bg-muted">تجربة محلية كضيف</Button>
          <p className="mt-3 text-center text-xs leading-5 text-muted-foreground">وضع الضيف لا ينشئ هوية خادم ولا يحفظ رسائل حقيقية.</p>
        </Card>
      </div>
    </main>
  );
}

function Sidebar({ section, setSection, profile, onSignOut }: { section: Section; setSection: (s: Section) => void; profile?: Profile | null; onSignOut: () => void }) {
  const items: [Section, string, typeof Activity][] = [
    ["home", "نظرة عامة", Activity],
    ["messages", "الرسائل", MessageSquare],
    ["calls", "المكالمات", Video],
    ["security", "مركز الأمان", ShieldCheck],
    ["privacy", "الخصوصية", Fingerprint],
    ["ai", "المساعد الذكي", Bot],
  ];
  return (
    <aside className="border-b bg-sidebar p-3 md:min-h-screen md:w-64 md:border-b-0 md:border-e">
      <div className="flex items-center justify-between gap-3 px-2 py-2 md:block">
        <div>
          <div className="font-display text-lg font-black">BridgeGuard</div>
          <div className="text-xs text-muted-foreground">Pro v32</div>
        </div>
        <div className="text-end md:mt-5">
          <div className="text-sm font-bold">{profile?.display_name ?? "ضيف"}</div>
          {profile?.handle && <div className="text-xs text-muted-foreground">@{profile.handle}</div>}
        </div>
      </div>
      <nav className="mt-3 flex gap-1 overflow-x-auto md:block md:space-y-1">
        {items.map(([id, label, Icon]) => (
          <button key={id} onClick={() => setSection(id)} className={`flex shrink-0 items-center gap-3 rounded-xl px-3 py-3 text-sm ${section === id ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:bg-muted hover:text-foreground"} md:w-full`}>
            <Icon className="size-4" /> {label}
          </button>
        ))}
      </nav>
      <div className="mt-3 md:absolute md:bottom-4 md:w-[calc(16rem-1.5rem)]">
        <Button onClick={onSignOut} className="w-full border bg-background hover:bg-muted">تسجيل الخروج</Button>
      </div>
    </aside>
  );
}

function Overview({ profile, device, guest, onSection }: { profile?: Profile | null; device?: Device | null; guest: boolean; onSection: (s: Section) => void }) {
  const checks = [
    ["هوية الجهاز", Boolean(device), "مفتاح خاص محلي"],
    ["تشفير الرسائل", true, "WebCrypto"],
    ["تفويض RLS", !guest, guest ? "وضع محلي" : "Supabase"],
    ["ذكاء اصطناعي", false, "موافقة مطلوبة"],
  ];
  return (
    <div className="space-y-6">
      <div className="surface overflow-hidden p-6 md:p-8">
        <div className="flex flex-col justify-between gap-6 md:flex-row md:items-end">
          <div>
            <Badge tone="ok"><Wifi className="size-3.5" /> {guest ? "جلسة محلية" : "جلسة مصادق عليها"}</Badge>
            <h2 className="mt-3 text-3xl font-black">مرحبًا {profile?.display_name ?? "بك"} 👋</h2>
            <p className="mt-2 max-w-2xl leading-7 text-muted-foreground">لوحة واحدة لمراقبة الهوية، الرسائل، المكالمات، الخصوصية، والموافقة الصريحة على الذكاء الاصطناعي.</p>
          </div>
          <Button onClick={() => onSection("security")} className="bg-primary text-primary-foreground">افتح مركز الأمان <ChevronLeft className="size-4" /></Button>
        </div>
      </div>
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {checks.map(([label, ok, detail]) => (
          <Card key={String(label)}>
            <div className="flex items-start justify-between gap-3">
              <div><div className="font-bold">{String(label)}</div><div className="mt-1 text-xs text-muted-foreground">{String(detail)}</div></div>
              {ok ? <Badge tone="ok"><Check className="size-3" /> جاهز</Badge> : <Badge tone="warn"><ShieldAlert className="size-3" /> يحتاج موافقة</Badge>}
            </div>
          </Card>
        ))}
      </div>
      <Card>
        <div className="flex items-center gap-3"><LockKeyhole className="size-5 text-primary" /><h3 className="font-bold">حدود الأمان الحالية</h3></div>
        <ul className="mt-4 grid gap-3 text-sm leading-6 text-muted-foreground md:grid-cols-2">
          <li>• لا توجد مفاتيح خاصة في قاعدة البيانات.</li>
          <li>• الرسائل تُحفظ ciphertext فقط.</li>
          <li>• لا يوجد ادعاء Forward Secrecy في هذه النسخة.</li>
          <li>• المكالمات تستخدم signaling ويمكن أن تحتاج TURN.</li>
        </ul>
      </Card>
    </div>
  );
}

function Messages({ user, device, guest }: { user: User | undefined; device: Device | null; guest: boolean }) {
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [selected, setSelected] = useState<Conversation | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [text, setText] = useState("");
  const [newTitle, setNewTitle] = useState("");
  const [memberHandle, setMemberHandle] = useState("");
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState("");

  async function loadConversations() {
    if (!user || guest) return;
    const { data, error } = await supabase.from("conversations").select("id,title,created_by,created_at").order("created_at", { ascending: false });
    if (error) return setStatus(safeError(error));
    setConversations(data ?? []);
    if (!selected && data?.[0]) setSelected(data[0]);
  }

  async function loadMessages(conv: Conversation) {
    if (!user || guest) return;
    const { data, error } = await supabase.from("messages").select("*").eq("conversation_id", conv.id).order("created_at", { ascending: true }).limit(200);
    if (error) return setStatus(safeError(error));
    const rows = (data ?? []).map((row) => ({ ...row, envelopes: row.envelopes as unknown as EnvelopeSet })) as Message[];
    const senderIds = [...new Set(rows.map((m) => m.sender_device_id))];
    const { data: devices } = senderIds.length ? await supabase.from("devices").select("id,public_identity_key").in("id", senderIds) : { data: [] as { id: string; public_identity_key: string }[] };
    const keys = new Map((devices ?? []).map((d) => [d.id, d.public_identity_key]));
    const out: Message[] = [];
    for (const row of rows) {
      try {
        const key = keys.get(row.sender_device_id);
        if (!key || !device || !row.envelopes) throw new Error("no-key");
        const localDevice = await getLocalDevice(user.id);
        if (!localDevice) throw new Error("لا يوجد مفتاح محلي");
        out.push({
          ...row,
          text: await decryptMessage(
            { ...row, senderDeviceId: row.sender_device_id },
            {
              deviceId: device.id,
              keyVersion: localDevice.keyVersion,
              privateKey: localDevice.privateKey,
              keyHistory: localDevice.keyHistory,
            },
            key,
          ),
        });
      } catch {
        out.push({ ...row, text: row.sender_id === user.id ? "رسالة مرسلة مشفّرة (تعذر فكها بهذا الإصدار من المفتاح)." : "رسالة مشفّرة غير قابلة للفك على هذا الجهاز." });
      }
    }
    setMessages(out);
  }

  useEffect(() => { void loadConversations(); }, [user?.id, guest]);
  useEffect(() => { if (selected) void loadMessages(selected); }, [selected?.id, device?.id]);

  async function createConversation() {
    if (!newTitle.trim()) return;
    const { data, error } = await supabase.rpc("create_conversation", { _title: newTitle.trim() });
    if (error) return setStatus(safeError(error));
    setNewTitle("");
    await loadConversations();
    const found = conversations.find((c) => c.id === data);
    if (found) setSelected(found);
  }

  async function addMember() {
    if (!selected || !memberHandle.trim()) return;
    const { error } = await supabase.rpc("add_member_by_handle", { _conv: selected.id, _handle: memberHandle.trim() });
    setStatus(error ? safeError(error) : "تمت إضافة العضو.");
    setMemberHandle("");
  }

  async function send() {
    if (!selected || !user || !device || !text.trim()) return;
    setBusy(true);
    setStatus("");
    try {
      const { data: members, error: memberError } = await supabase.from("conversation_members").select("user_id").eq("conversation_id", selected.id);
      if (memberError) throw memberError;
      const ids = [...new Set((members ?? []).map((m) => m.user_id))];
      const { data: ds, error: deviceError } = await supabase.from("devices").select("id,user_id,key_version,public_identity_key").in("user_id", ids).is("revoked_at", null);
      if (deviceError) throw deviceError;
      const recipients = (ds ?? []).map((d) => ({ deviceId: d.id, keyVersion: d.key_version, publicKeyB64: d.public_identity_key }));
      const localDevice = await getLocalDevice(user.id);
      if (!localDevice) throw new Error("لا يوجد مفتاح محلي");
      const payload = await encryptMessage(
        text.trim(),
        { deviceId: device.id, keyVersion: device.key_version, privateKey: localDevice.privateKey, publicKeyB64: localDevice.publicKeyB64 },
        recipients,
      );
      const { error } = await supabase.from("messages").insert({ conversation_id: selected.id, sender_id: user.id, sender_device_id: device.id, alg: "ECDH-P256+HKDF-SHA256+AES-256-GCM", ciphertext: payload.ciphertext, iv: payload.iv, envelopes: payload.envelopes });
      if (error) throw error;
      setText("");
      await loadMessages(selected);
    } catch (e) {
      setStatus(safeError(e));
    } finally {
      setBusy(false);
    }
  }

  if (guest) {
    return <Card><div className="flex items-center gap-3"><MessageSquare className="text-primary" /><h2 className="text-xl font-bold">الرسائل — وضع الضيف</h2></div><p className="mt-3 text-sm leading-7 text-muted-foreground">هذه جلسة عرض محلية. سجّل الدخول لتفعيل المحادثات المشفرة وتخزين ciphertext على الخادم.</p><div className="mt-5 space-y-3">{demoMessages.map((m) => <div key={m.text} className="rounded-2xl bg-muted p-4"><div className="text-xs text-muted-foreground">{m.from} · {m.time}</div><div className="mt-1">{m.text}</div></div>)}</div></Card>;
  }

  return (
    <div className="grid gap-4 lg:grid-cols-[300px_1fr]">
      <Card className="p-3">
        <div className="flex gap-2">
          <input value={newTitle} onChange={(e) => setNewTitle(e.target.value)} placeholder="عنوان محادثة جديدة" className="min-w-0 flex-1 rounded-xl border bg-background px-3 py-2 text-sm" />
          <Button onClick={createConversation} className="bg-primary px-3 text-primary-foreground"><Plus className="size-4" /></Button>
        </div>
        <div className="mt-3 space-y-1">{conversations.map((c) => <button key={c.id} onClick={() => setSelected(c)} className={`w-full rounded-xl p-3 text-start ${selected?.id === c.id ? "bg-primary/15" : "hover:bg-muted"}`}><div className="font-semibold">{c.title}</div><div className="text-xs text-muted-foreground">{new Date(c.created_at).toLocaleString("ar-DZ")}</div></button>)}</div>
        {!conversations.length && <p className="p-4 text-sm text-muted-foreground">لا توجد محادثات بعد.</p>}
      </Card>
      <Card className="flex min-h-[520px] flex-col p-0">
        <div className="border-b p-4">
          <div className="flex items-center justify-between gap-3"><div><h2 className="font-bold">{selected?.title ?? "اختر محادثة"}</h2><div className="text-xs text-muted-foreground">تخزين ciphertext فقط</div></div>{selected && <Badge tone="ok"><LockKeyhole className="size-3" /> تشفير محلي</Badge>}</div>
          {selected?.created_by === user?.id && <div className="mt-3 flex gap-2"><input value={memberHandle} onChange={(e) => setMemberHandle(e.target.value)} placeholder="handle العضو" className="min-w-0 flex-1 rounded-xl border bg-background px-3 py-2 text-sm" /><Button onClick={addMember} className="border bg-background"><UserPlus className="size-4" /> إضافة</Button></div>}
        </div>
        <div className="flex-1 space-y-3 overflow-auto p-4">
          {messages.map((m) => <div key={m.id} className={`max-w-[85%] rounded-2xl p-3 ${m.sender_id === user?.id ? "ms-auto bg-primary text-primary-foreground" : "bg-muted"}`}><div className="text-sm leading-6">{m.text}</div><div className="mt-1 text-[10px] opacity-70">{new Date(m.created_at).toLocaleTimeString("ar-DZ", { hour: "2-digit", minute: "2-digit" })}</div></div>)}
          {!messages.length && <div className="grid h-full place-items-center text-sm text-muted-foreground">لا توجد رسائل.</div>}
        </div>
        <div className="border-t p-3">
          {status && <div className="mb-2 text-xs text-warning">{status}</div>}
          <div className="flex gap-2"><input value={text} onChange={(e) => setText(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); void send(); } }} placeholder="اكتب رسالة…" className="min-w-0 flex-1 rounded-xl border bg-background px-3 py-3" maxLength={4000} /><Button onClick={send} disabled={busy || !selected} className="bg-primary text-primary-foreground"><Send className="size-4" /> إرسال</Button></div>
        </div>
      </Card>
    </div>
  );
}

function Security({ user, device }: { user: User | undefined; device: Device | null }) {
  const [devices, setDevices] = useState<Device[]>([]);
  const [status, setStatus] = useState("");
  const [turn, setTurn] = useState<boolean | null>(null);

  async function load() {
    if (!user) return;
    const { data, error } = await supabase.from("devices").select("id,name,fingerprint,verification,key_version,revoked_at,last_seen_at,public_identity_key").eq("user_id", user.id).order("created_at", { ascending: false });
    if (!error) setDevices(data ?? []);
    else setStatus(safeError(error));
    const ice = await getIceServers();
    setTurn(ice.turnConfigured);
  }
  useEffect(() => { void load(); }, [user?.id]);

  async function revoke(id: string) {
    const { error } = await supabase.rpc("revoke_device", { _device: id });
    setStatus(error ? safeError(error) : "تم إلغاء الجهاز.");
    await load();
  }

  async function rotate() {
    if (!user || !device) return;
    try { await rotateLocalKey(user.id); setStatus("تم تدوير مفتاح الجهاز المحلي. أعِد التحقق من البصمة عند الحاجة."); await load(); }
    catch (e) { setStatus(safeError(e)); }
  }

  return <div className="space-y-4">
    <Card>
      <div className="flex flex-wrap items-center justify-between gap-3"><div><h2 className="text-xl font-bold">مركز الأمان</h2><p className="mt-1 text-sm text-muted-foreground">حالة الجلسة والهوية والمفاتيح ومسار الاتصال.</p></div><Badge tone="warn"><ShieldAlert className="size-3.5" /> غير مدقّق تشفيريًا</Badge></div>
      <div className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-2xl bg-muted p-4"><div className="text-xs text-muted-foreground">الجهاز الحالي</div><div className="mt-1 font-bold">{device?.name ?? "غير مسجل"}</div></div>
        <div className="rounded-2xl bg-muted p-4"><div className="text-xs text-muted-foreground">إصدار المفتاح</div><div className="mt-1 font-bold">{device?.key_version ?? "—"}</div></div>
        <div className="rounded-2xl bg-muted p-4"><div className="text-xs text-muted-foreground">TURN</div><div className="mt-1 font-bold">{turn === null ? "…" : turn ? "مهيأ" : "غير مهيأ"}</div></div>
        <div className="rounded-2xl bg-muted p-4"><div className="text-xs text-muted-foreground">Forward Secrecy</div><div className="mt-1 font-bold text-warning">غير متوفر</div></div>
      </div>
    </Card>
    <Card>
      <div className="flex items-center justify-between gap-3"><h3 className="font-bold">أجهزة الحساب</h3><Button onClick={() => void rotate()} disabled={!device} className="border bg-background"><RefreshCw className="size-4" /> تدوير المفتاح</Button></div>
      <div className="mt-4 space-y-3">{devices.map((d) => <div key={d.id} className="rounded-2xl border p-4"><div className="flex flex-wrap items-start justify-between gap-3"><div><div className="font-semibold">{d.name}</div><div className="mt-1 text-xs text-muted-foreground">الإصدار {d.key_version} · {d.revoked_at ? "ملغى" : "نشط"}</div></div><Badge tone={d.verification === "verified" ? "ok" : "warn"}>{d.verification === "verified" ? "موثّق" : "غير موثّق"}</Badge></div><button onClick={() => navigator.clipboard?.writeText(d.fingerprint)} className="mt-3 flex items-center gap-2 break-all text-start font-mono text-xs text-primary"><Copy className="size-3.5 shrink-0" />{d.fingerprint}</button>{!d.revoked_at && d.id !== device?.id && <Button onClick={() => void revoke(d.id)} className="mt-3 border bg-background text-destructive"><Trash2 className="size-4" /> إلغاء الجهاز</Button>}</div>)}</div>
      {status && <div className="mt-3 text-sm text-warning">{status}</div>}
    </Card>
  </div>;
}

function Calls() {
  return <div className="grid gap-4 md:grid-cols-2">
    <Card><Phone className="size-6 text-primary" /><h2 className="mt-4 text-xl font-bold">المكالمات الآمنة</h2><p className="mt-2 text-sm leading-7 text-muted-foreground">WebRTC مع signaling على الخادم وTURN عند الحاجة. لا نقول "بدون خادم" لأن signaling وrelay قد يكونان ضروريين.</p><div className="mt-5 rounded-2xl bg-warning/10 p-4 text-sm leading-6 text-warning">واجهة المكالمات جاهزة كمرحلة المنتج، أما مسار WebRTC الكامل فيحتاج ربط واجهة الاتصال بإشارات call_signals واختبارًا فعليًا عبر شبكات مختلفة.</div></Card>
    <Card><Video className="size-6 text-primary" /><h3 className="mt-4 font-bold">حالة المسار</h3><div className="mt-4 space-y-2 text-sm"><div className="flex justify-between rounded-xl bg-muted p-3"><span>Signaling</span><Badge tone="ok">Backend موجود</Badge></div><div className="flex justify-between rounded-xl bg-muted p-3"><span>STUN</span><Badge tone="ok">متاح</Badge></div><div className="flex justify-between rounded-xl bg-muted p-3"><span>TURN</span><Badge tone="warn">حسب البيئة</Badge></div></div></Card>
  </div>;
}

function Privacy({ user: _user }: { user: User | undefined }) {
  const [status, setStatus] = useState("");
  const [confirm, setConfirm] = useState("");
  async function exportData() {
    const r = await exportMyData();
    if (r.ok) {
      const blob = new Blob([JSON.stringify(r.data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a"); a.href = url; a.download = "bridgeguard-export.json"; a.click(); URL.revokeObjectURL(url);
      setStatus("تم تجهيز نسخة البيانات.");
    } else setStatus(r.error);
  }
  async function deleteAccount() {
    const r = await deleteMyAccount({ data: { confirm: "احذف حسابي" } });
    setStatus(r.ok ? "تم طلب حذف الحساب. سجّل الخروج الآن." : r.error);
  }
  return <div className="space-y-4">
    <Card><h2 className="text-xl font-bold">مركز الخصوصية</h2><p className="mt-2 text-sm leading-7 text-muted-foreground">البيانات المصدّرة تتضمن الرسائل كنص مشفّر. لا يستطيع الخادم فك محتواها بهذا التصميم.</p><Button onClick={() => void exportData()} className="mt-5 bg-primary text-primary-foreground">تصدير بياناتي</Button></Card>
    <Card className="border-destructive/30"><h3 className="font-bold text-destructive">حذف الحساب</h3><p className="mt-2 text-sm leading-6 text-muted-foreground">هذا الإجراء نهائي. اكتب العبارة المطلوبة ثم نفّذ الحذف.</p><input value={confirm} onChange={(e) => setConfirm(e.target.value)} placeholder="احذف حسابي" className="mt-4 w-full rounded-xl border bg-background px-3 py-3" /><Button disabled={confirm !== "احذف حسابي"} onClick={() => void deleteAccount()} className="mt-3 bg-destructive text-destructive-foreground">حذف الحساب نهائيًا</Button></Card>
    {status && <div className="rounded-xl bg-muted p-3 text-sm">{status}</div>}
  </div>;
}

function AI({ user }: { user?: User }) {
  const [prompt, setPrompt] = useState("");
  const [answer, setAnswer] = useState("");
  const [consent, setConsent] = useState(false);
  const [busy, setBusy] = useState(false);
  async function run() {
    if (!consent || !prompt.trim()) return;
    setBusy(true); setAnswer("");
    const r = await askAssistant({ data: { prompt: prompt.trim() } });
    setAnswer(r.ok ? r.text : r.error);
    setBusy(false);
  }
  return <Card>
    <div className="flex items-start gap-3"><Bot className="mt-1 size-6 text-primary" /><div><h2 className="text-xl font-bold">المساعد الذكي</h2><p className="mt-1 text-sm leading-6 text-muted-foreground">المساعد لا يحصل على رسائل المحادثات تلقائيًا. مشاركة سياق المحادثة يجب أن تكون اختيارية ومصرّحًا بها.</p></div></div>
    <label className="mt-5 flex gap-3 rounded-2xl bg-warning/10 p-4 text-sm leading-6"><input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} className="mt-1 size-4" /> أوافق على إرسال النص الذي أكتبه هنا إلى مزود الذكاء الاصطناعي لمعالجة الطلب.</label>
    <textarea value={prompt} onChange={(e) => setPrompt(e.target.value)} placeholder="اكتب طلبك…" className="mt-4 min-h-32 w-full rounded-2xl border bg-background p-4" maxLength={2000} />
    <Button onClick={() => void run()} disabled={!consent || busy} className="mt-3 bg-primary text-primary-foreground"><Bot className="size-4" /> {busy ? "جارٍ المعالجة…" : "إرسال للمساعد"}</Button>
    {answer && <div className="mt-5 rounded-2xl bg-muted p-4 whitespace-pre-wrap text-sm leading-7">{answer}</div>}
    {!user && <div className="mt-3 text-xs text-warning">يتطلب المساعد جلسة مصادق عليها.</div>}
  </Card>;
}

export default function BridgeGuardApp() {
  const [user, setUser] = useState<User | null>(null);
  const [profile, setProfile] = useState<Profile | null>(null);
  const [device, setDevice] = useState<Device | null>(null);
  const [guest, setGuest] = useState(false);
  const [section, setSection] = useState<Section>("home");
  const [booting, setBooting] = useState(true);

  async function hydrate(nextUser: User | null) {
    setUser(nextUser);
    if (!nextUser) { setProfile(null); setDevice(null); return; }
    const [{ data: p }, local] = await Promise.all([
      supabase.from("profiles").select("id,display_name,handle").eq("id", nextUser.id).maybeSingle(),
      getLocalDevice(nextUser.id).catch(() => undefined),
    ]);
    setProfile(p);
    try {
      const d = await ensureDevice(nextUser.id);
      setDevice(d as unknown as Device);
    } catch {
      if (local) setDevice(local as unknown as Device);
    }
  }

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => hydrate(data.session?.user ? { id: data.session.user.id, email: data.session.user.email ?? null } : null)).finally(() => setBooting(false));
    const { data: listener } = supabase.auth.onAuthStateChange((_event, session) => {
      void hydrate(session?.user ? { id: session.user.id, email: session.user.email ?? null } : null);
    });
    return () => listener.subscription.unsubscribe();
  }, []);

  async function signOut() {
    await supabase.auth.signOut({ scope: "global" });
    setGuest(false);
  }

  const title = useMemo(() => ({ home: "نظرة عامة", messages: "الرسائل", calls: "المكالمات", security: "مركز الأمان", privacy: "الخصوصية", ai: "المساعد الذكي" }[section]), [section]);

  if (booting) return <div className="grid min-h-screen place-items-center"><RefreshCw className="size-7 animate-spin text-primary" /></div>;
  if (!user && !guest) return <AuthScreen onGuest={() => setGuest(true)} />;

  return (
    <div dir="rtl" className="min-h-screen md:flex">
      <Sidebar section={section} setSection={setSection} profile={profile} onSignOut={() => void signOut()} />
      <main className="min-w-0 flex-1 p-4 md:p-8">
        <div className="mx-auto max-w-7xl">
          <header className="mb-6 flex items-center justify-between gap-4">
            <div><div className="text-xs text-muted-foreground">BridgeGuard Pro v32</div><h1 className="text-2xl font-black">{title}</h1></div>
            <Badge tone="ok"><LockKeyhole className="size-3.5" /> {guest ? "محلي" : "محمي"}</Badge>
          </header>
          {section === "home" && <Overview profile={profile} device={device} guest={guest} onSection={setSection} />}
          {section === "messages" && <Messages user={user ?? undefined} device={device} guest={guest} />}
          {section === "calls" && <Calls />}
          {section === "security" && <Security user={user ?? undefined} device={device} />}
          {section === "privacy" && <Privacy user={user ?? undefined} />}
          {section === "ai" && <AI user={user ?? undefined} />}
        </div>
      </main>
    </div>
  );
}
