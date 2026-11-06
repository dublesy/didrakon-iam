import "server-only";

/** 서버에서만 읽는 설정. 값은 .env.local (예시: .env.example) */
export const config = {
  /** IAM(IdP) 주소. 토큰 iss 와 같아야 한다 */
  issuer: process.env.IAM_ISSUER ?? "http://localhost:8080",
  /** IAM 에 등록된 관리 콘솔 클라이언트 (PKCE public client) */
  clientId: process.env.IAM_CLIENT_ID ?? "iam-admin",
  /** 이 콘솔의 주소. redirect_uri·로그아웃 후 주소를 만든다 */
  appUrl: process.env.APP_URL ?? "http://localhost:3000",
};

export const redirectUri = () => `${config.appUrl}/callback`;
export const postLogoutRedirectUri = () => `${config.appUrl}/`;

/** 세션 쿠키 암호화 키 (Base64, 32바이트). 없으면 요청을 처리하지 않는다 */
export function sessionKey(): Buffer {
  const raw = process.env.SESSION_SECRET ?? "";
  const key = Buffer.from(raw, "base64");
  if (key.length !== 32) {
    throw new Error("SESSION_SECRET 은 Base64 로 인코딩한 32바이트 키여야 합니다 (openssl rand -base64 32)");
  }
  return key;
}
