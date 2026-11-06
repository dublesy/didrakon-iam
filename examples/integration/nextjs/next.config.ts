import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // 이 폴더만으로 빌드한다 (저장소의 다른 lockfile 을 작업 공간 루트로 잡지 않게)
  turbopack: { root: __dirname },
  outputFileTracingRoot: __dirname,
  agentRules: false, // next dev 가 AGENTS.md 를 만들지 않게
};

export default nextConfig;
