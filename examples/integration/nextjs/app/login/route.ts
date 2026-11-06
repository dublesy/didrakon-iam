import { NextResponse, type NextRequest } from "next/server";
import * as client from "openid-client";
import { oidcConfig, settings } from "@/lib/iam";
import { deleteSession, getSession, startSession } from "@/lib/store";

export async function GET(request: NextRequest) {
  const config = await oidcConfig();
  const login = {
    state: client.randomState(),
    nonce: client.randomNonce(),
    verifier: client.randomPKCECodeVerifier(),
  };
  const url = client.buildAuthorizationUrl(config, {
    redirect_uri: `${settings.baseUrl}/callback`,
    scope: "openid profile",
    state: login.state,
    nonce: login.nonce,
    code_challenge: await client.calculatePKCECodeChallenge(login.verifier),
    code_challenge_method: "S256",
  });
  const response = NextResponse.redirect(url, 302);
  const old = getSession(request);
  if (old) deleteSession(old.id);
  startSession(response, { login }); // state·nonce·verifier 는 서버 세션에 둔다
  return response;
}
