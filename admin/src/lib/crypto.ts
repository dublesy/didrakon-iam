import "server-only";
import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { sessionKey } from "./config";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;
const TAG_LENGTH = 16;

/** 값을 JSON 으로 만들어 AES-GCM 으로 암호화한다. 쿠키에 그대로 넣을 수 있는 base64url 문자열 */
export function seal(value: unknown): string {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, sessionKey(), iv);
  const body = Buffer.concat([cipher.update(JSON.stringify(value), "utf8"), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), body]).toString("base64url");
}

/** 위조·손상·키 변경이면 null */
export function unseal<T>(sealed: string): T | null {
  try {
    const data = Buffer.from(sealed, "base64url");
    const decipher = createDecipheriv(ALGORITHM, sessionKey(), data.subarray(0, IV_LENGTH));
    decipher.setAuthTag(data.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH));
    const plain = Buffer.concat([decipher.update(data.subarray(IV_LENGTH + TAG_LENGTH)), decipher.final()]);
    return JSON.parse(plain.toString("utf8")) as T;
  } catch {
    return null;
  }
}

export const randomToken = (bytes = 32) => randomBytes(bytes).toString("base64url");

/** PKCE S256 challenge */
export const codeChallenge = (verifier: string) => createHash("sha256").update(verifier).digest("base64url");
