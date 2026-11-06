import type { NextRequest } from "next/server";
import { findBySubject, getSession } from "@/lib/store";

export function GET(request: NextRequest) {
  const u = getSession(request)?.user;
  if (!u || !findBySubject(u.sub)?.active) return Response.json({ error: "unauthorized" }, { status: 401 });
  const { sub, name, empNo, roles, localUserId, sid } = u;
  return Response.json({ sub, name, empNo, roles, localUserId, sid });
}
