"use server";

import { refresh } from "next/cache";
import QRCode from "qrcode";
import { mutate, num, text, type ActionState } from "@/lib/actions";
import { callIam } from "@/lib/iam-api";

type Enrollment = { methodId: number; secretBase32: string; otpauthUri: string };

/** 등록 화면 상태: 시작 전 → 코드 확인 → 완료 */
export type MfaState =
  | { step: "start"; error?: string }
  | { step: "confirm"; methodId: number; secret: string; otpauthUri: string; qrSvg: string; error?: string }
  | { step: "done" };

/** 버튼마다 intent 로 단계를 나눈다 */
export async function mfaAction(previous: MfaState, formData: FormData): Promise<MfaState> {
  if (formData.get("intent") === "start") {
    const result = await callIam<Enrollment>("/api/v1/me/mfa/totp", { method: "POST" }, "/mfa");
    if (!result.ok) return { step: "start", error: result.message };
    const { methodId, secretBase32, otpauthUri } = result.data;
    // QR 은 서버에서 만들어 비밀값이 외부 QR 서비스로 나가지 않게 한다
    const qrSvg = await QRCode.toString(otpauthUri, { type: "svg", margin: 0, errorCorrectionLevel: "M", color: { dark: "#131a19", light: "#ffffff" } });
    return { step: "confirm", methodId, secret: secretBase32, otpauthUri, qrSvg };
  }

  if (previous.step !== "confirm") return { step: "start" };
  const code = String(formData.get("code") ?? "").trim();
  if (!/^\d{6}$/.test(code)) return { ...previous, error: "6자리 숫자를 입력하세요" };

  const result = await callIam(
    `/api/v1/me/mfa/totp/${previous.methodId}/confirm`,
    { method: "POST", body: JSON.stringify({ code }) },
    "/mfa",
  );
  if (!result.ok) return { ...previous, error: result.message };
  refresh();
  return { step: "done" };
}

export async function removeMfaMethod(_: ActionState, form: FormData): Promise<ActionState> {
  return mutate(`/api/v1/me/mfa/${num(form, "methodId")}`, "DELETE", undefined, "삭제했습니다", "/mfa");
}

export async function removePasskey(_: ActionState, form: FormData): Promise<ActionState> {
  const id = encodeURIComponent(text(form, "credentialId") ?? "");
  return mutate(`/api/v1/me/passkeys/${id}`, "DELETE", undefined, "삭제했습니다", "/mfa");
}
