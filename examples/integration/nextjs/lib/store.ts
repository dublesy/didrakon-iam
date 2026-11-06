// 서버 세션과 로컬 사용자 저장소. 예제라 메모리에 둔다.
// - 인스턴스가 여럿이거나 재시작하면 사라진다. 운영은 Redis·DB 에 둔다
// - Next.js 는 경로마다 모듈을 따로 읽을 수 있어 globalThis 에 하나만 둔다
import crypto from "node:crypto";
import type { NextRequest, NextResponse } from "next/server";

export type LocalUser = { id: number; empNo: string | null; name: string; iamSubjectId: string | null; active: boolean };
export type SessionUser = {
  sub: string;
  sid: string | null; // back-channel 로그아웃이 이 값으로 세션을 찾는다
  name: string | null;
  empNo: string | null;
  roles: string[];
  localUserId: number;
  idToken: string;
};
export type Session = {
  id: string;
  login?: { state: string; nonce: string; verifier: string }; // /login → /callback 사이에만
  user?: SessionUser;
};

type Store = { sessions: Map<string, Session>; users: LocalUser[]; deliveries: Set<string> };
const g = globalThis as unknown as { sampleStore?: Store };
const db: Store = (g.sampleStore ??= {
  sessions: new Map(),
  // 이미 있던 계정: 첫 로그인 때 사번으로 연결된다
  users: [{ id: 1, empNo: "D-001", name: "기존 사용자", iamSubjectId: null, active: true }],
  // 처리한 웹훅 전달 ID. 운영은 DB 테이블(delivery_id 를 기본 키로)에 둔다
  deliveries: new Set(),
});
export const deliveries = db.deliveries;

// ---- 세션: httpOnly 쿠키에는 무작위 세션 ID 만 둔다
export const SESSION_COOKIE = "sample_nextjs_sid"; // localhost 는 포트가 달라도 쿠키를 함께 쓰므로 겹치지 않는 이름

export function getSession(request: NextRequest): Session | undefined {
  const id = request.cookies.get(SESSION_COOKIE)?.value;
  return id ? db.sessions.get(id) : undefined;
}

/** 새 세션을 만들고 쿠키를 붙인다. 로그인 전후에 새로 만들어 세션 고정을 막는다 */
export function startSession(response: NextResponse, data: Omit<Session, "id">): Session {
  const session = { id: crypto.randomBytes(32).toString("base64url"), ...data };
  db.sessions.set(session.id, session);
  response.cookies.set(SESSION_COOKIE, session.id, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.APP_BASE_URL?.startsWith("https://") ?? false,
    path: "/",
  });
  return session;
}

export function deleteSession(id: string) {
  db.sessions.delete(id);
}

/** 조건에 맞는 세션을 모두 지우고 지운 수를 돌려준다 */
export function endSessions(match: (user: SessionUser) => boolean): number {
  let count = 0;
  for (const [id, s] of db.sessions) {
    if (s.user && match(s.user)) {
      db.sessions.delete(id);
      count++;
    }
  }
  return count;
}

// ---- 로컬 사용자. 실제 시스템은 users 테이블에 iam_subject_id 컬럼을 둔다

/** IAM sub 로 찾고, 없으면 사번으로 찾아 연결하고, 그래도 없으면 만든다(JIT) */
export function linkAccount(claims: { sub: string; emp_no?: unknown; name?: unknown }): LocalUser {
  const sub = String(claims.sub);
  const empNo = typeof claims.emp_no === "string" ? claims.emp_no : null;
  let user = db.users.find((u) => u.iamSubjectId === sub);
  if (!user && empNo) {
    user = db.users.find((u) => u.iamSubjectId === null && u.empNo === empNo);
    if (user) user.iamSubjectId = sub;
  }
  if (!user) {
    user = { id: db.users.length + 1, empNo, name: String(claims.name ?? ""), iamSubjectId: sub, active: true };
    db.users.push(user);
  }
  return user;
}

export const findBySubject = (sub: string | number) => db.users.find((u) => u.iamSubjectId === String(sub));
