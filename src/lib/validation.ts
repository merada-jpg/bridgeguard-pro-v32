import { z } from "zod";

export const emailSchema = z.string().trim().email("بريد إلكتروني غير صالح").max(254);
export const passwordSchema = z
  .string()
  .min(10, "كلمة المرور يجب ألا تقل عن 10 أحرف")
  .max(128, "كلمة المرور طويلة جدًا");
export const displayNameSchema = z.string().trim().min(1, "الاسم مطلوب").max(60, "الاسم طويل جدًا");
export const handleSchema = z
  .string()
  .trim()
  .toLowerCase()
  .regex(/^[a-z0-9_]{3,24}$/, "المعرّف: 3–24 حرفًا لاتينيًا صغيرًا أو أرقامًا أو _");
export const conversationTitleSchema = z.string().trim().min(1, "العنوان مطلوب").max(80, "العنوان طويل جدًا");
export const messageSchema = z.string().trim().min(1).max(4000, "الرسالة طويلة جدًا (4000 حرف كحد أقصى)");
export const uuidSchema = z.string().uuid();

export const aiRequestSchema = z.object({
  prompt: z.string().trim().min(1).max(2000),
  conversationId: uuidSchema.optional(),
  // Plaintext context the user explicitly chose to share (decrypted on their device).
  context: z.array(z.string().max(4000)).max(30).optional(),
});

/** Map backend errors to safe, generic user-facing text (never leak internals). */
export function safeError(e: unknown): string {
  const msg = e && typeof e === "object" && "message" in e ? String((e as { message: unknown }).message) : "";
  if (/rate limited/i.test(msg)) return "محاولات كثيرة. حاول مرة أخرى بعد قليل.";
  if (/Invalid login credentials/i.test(msg)) return "البريد أو كلمة المرور غير صحيحة.";
  if (/Email not confirmed/i.test(msg)) return "يرجى تأكيد بريدك الإلكتروني أولًا.";
  if (/already registered/i.test(msg)) return "تعذّر إنشاء الحساب. جرّب تسجيل الدخول.";
  if (/pwned|weak|compromised/i.test(msg)) return "كلمة المرور ضعيفة أو ظهرت في تسريبات معروفة.";
  if (/not allowed|permission|denied|violates row-level/i.test(msg)) return "غير مسموح بهذا الإجراء.";
  return "حدث خطأ غير متوقع. حاول مرة أخرى.";
}