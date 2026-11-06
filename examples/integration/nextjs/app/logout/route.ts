import { NextResponse, type NextRequest } from "next/server";
import * as client from "openid-client";
import { oidcConfig, settings } from "@/lib/iam";
import { deleteSession, getSession, SESSION_COOKIE } from "@/lib/store";

export async function GET(request: NextRequest) {
  const session = getSession(request);
  if (session) deleteSession(session.id);
  const idToken = session?.user?.idToken;
  const target = idToken
    ? client.buildEndSessionUrl(await oidcConfig(), { id_token_hint: idToken, post_logout_redirect_uri: `${settings.baseUrl}/` })
    : new URL("/", settings.baseUrl);
  const response = NextResponse.redirect(target, 302);
  response.cookies.delete(SESSION_COOKIE);
  return response;
}
