import { verifyWebhook } from "@/lib/iam";
import { deliveries, endSessions, findBySubject } from "@/lib/store";

export const runtime = "nodejs"; // node:crypto 로 HMAC 을 계산한다 (Edge 런타임 아님)

export async function POST(request: Request) {
  // 서명은 받은 바이트 그대로 계산한다. request.json() 으로 읽고 다시 직렬화하면 서명이 맞지 않는다
  const raw = Buffer.from(await request.arrayBuffer());
  const h = request.headers;
  if (!verifyWebhook(raw, h.get("X-Didrakon-Timestamp"), h.get("X-Didrakon-Signature"))) {
    return Response.json({ error: "invalid signature" }, { status: 401 });
  }
  const delivery = h.get("X-Didrakon-Delivery") ?? "";
  if (deliveries.has(delivery)) return Response.json({ duplicate: true });

  const event = JSON.parse(raw.toString("utf8"));
  if (event.type === "user.status_changed" && event.data?.status === "RETIRED") {
    const user = findBySubject(event.data.subjectId);
    if (user) user.active = false; // 계정 끄기 (실제 시스템은 권한도 모두 회수)
    endSessions((u) => u.sub === String(event.data.subjectId));
  }
  deliveries.add(delivery);
  return Response.json({ ok: true });
}
