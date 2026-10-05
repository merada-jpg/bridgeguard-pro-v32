import { describe, expect, it } from "vitest";
import { aiRequestSchema, handleSchema, passwordSchema, safeError } from "@/lib/validation";

describe("security validation", () => {
  it("rejects weak passwords", () => {
    expect(passwordSchema.safeParse("short").success).toBe(false);
  });

  it("accepts only constrained handles", () => {
    expect(handleSchema.safeParse("bridge_user_01").success).toBe(true);
    expect(handleSchema.safeParse("Bad Handle").success).toBe(false);
  });

  it("bounds AI input", () => {
    expect(aiRequestSchema.safeParse({ prompt: "اختبار" }).success).toBe(true);
    expect(aiRequestSchema.safeParse({ prompt: "" }).success).toBe(false);
  });

  it("returns generic errors instead of backend details", () => {
    expect(safeError(new Error("permission denied by RLS policy"))).toBe("غير مسموح بهذا الإجراء.");
    expect(safeError(new Error("database password=secret"))).toBe("حدث خطأ غير متوقع. حاول مرة أخرى.");
  });
});
