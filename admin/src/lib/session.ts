import "server-only";
import { cookies } from "next/headers";
import { connection } from "next/server";
import { config } from "./config";
import { seal, unseal } from "./crypto";
import { SESSION_COOKIE } from "./session-cookie";

/** 로그인 세션. 토큰은 암호화한 httpOnly 쿠키에만 있고 브라우저 스크립트는 읽을 수 없다 */
export type Session = {
  accessToken: string;
  idToken?: string;
  /** 액세스 토큰 만료 시각 (epoch ms) */
  expiresAt: number;
};

/** 로그인 진행 중에만 쓰는 값 (state·PKCE verifier·돌아갈 경로) */
export type PendingLogin = { state: string; verifier: string; next: string };

const LOGIN_COOKIE = "iam_admin_login";

/** 액세스 토큰 만료 30초 전부터 다시 로그인 대상으로 본다 */
const EXPIRY_MARGIN_MS = 30_000;

const baseCookie = {
  httpOnly: true,
  sameSite: "lax" as const,
  secure: process.env.NODE_ENV === "production",
  path: "/",
};

/**
 * 세션은 요청마다 다르고 만료 판단에 지금 시각(Date.now)을 쓰므로 요청 시점에만 읽는다.
 * cacheComponents·partialPrefetching 에서는 쿠키를 읽은 뒤에도 미리 렌더링이 이어져 Date.now 가 막히므로 connection() 으로 끊는다
 */
export async function readSession(): Promise<Session | null> {
  await connection();
  const value = (await cookies()).get(SESSION_COOKIE)?.value;
  return value ? unseal<Session>(value) : null;
}

export const isExpired = (session: Session) => Date.now() >= session.expiresAt - EXPIRY_MARGIN_MS;

/** Route Handler·Server Action 에서만 호출한다 (서버 컴포넌트는 쿠키를 쓸 수 없다) */
export async function writeSession(session: Session) {
  // IdP 로그인 세션(8시간)보다 오래 두지 않는다
  (await cookies()).set(SESSION_COOKIE, seal(session), { ...baseCookie, maxAge: 8 * 60 * 60 });
}

export async function clearSession() {
  (await cookies()).delete(SESSION_COOKIE);
}

export async function writePendingLogin(pending: PendingLogin) {
  (await cookies()).set(LOGIN_COOKIE, seal(pending), { ...baseCookie, maxAge: 10 * 60 });
}

/** 한 번 읽으면 지운다 (state 재사용 방지) */
export async function takePendingLogin(): Promise<PendingLogin | null> {
  const jar = await cookies();
  const value = jar.get(LOGIN_COOKIE)?.value;
  jar.delete(LOGIN_COOKIE);
  return value ? unseal<PendingLogin>(value) : null;
}

/**
 * 오픈 리다이렉트를 막기 위해 이 콘솔 안의 경로만 허용한다.
 * 문자열 앞부분만 보면 탭·줄바꿈("/\t/evil.example")처럼 URL 해석기가 지우는 글자로 빠져나가므로,
 * 실제로 주소를 해석해 출처가 이 콘솔인지 보고 경로 부분만 돌려준다.
 * 해석한 경로가 "//" 로 시작하면 거부한다. "/.//evil.example" 은 경로가 "//evil.example" 이 되는데, 이것을 다시 주소로 쓰면 다른 사이트로 읽힌다
 */
export function safeNext(next: string | null | undefined): string {
  if (!next || !next.startsWith("/")) return "/";
  try {
    const base = new URL(config.appUrl);
    const url = new URL(next, base);
    if (url.origin !== base.origin || url.pathname.startsWith("//")) return "/";
    return `${url.pathname}${url.search}${url.hash}`;
  } catch {
    return "/";
  }
}
