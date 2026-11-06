import type { Metadata } from "next";
import localFont from "next/font/local";
import "./globals.css";

/** 한글 UI 글꼴. 자체 호스팅 (OFL) */
const pretendard = localFont({
  src: "../../node_modules/pretendard/dist/web/variable/woff2/PretendardVariable.woff2",
  variable: "--font-pretendard",
  weight: "45 920",
  display: "swap",
});

export const metadata: Metadata = {
  title: "DIDRAKON IAM",
  description: "사람과 시스템의 계정·권한 관리",
};

/** 모든 화면 공통: 글꼴·색 토큰만. 관리 화면의 메뉴·상단 검색은 (console)/layout.tsx 에 있다 */
export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="ko" className={`${pretendard.variable} h-full`}>
      <body className="min-h-full">{children}</body>
    </html>
  );
}
