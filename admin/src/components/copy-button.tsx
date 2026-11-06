"use client";

import { useState } from "react";
import { buttonClass } from "@/components/ui";

/** 값 하나를 클립보드로 복사한다. 복사하면 잠깐 "복사함"으로 바뀐다 */
export function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      aria-label={`${label} 복사`}
      className={buttonClass.row}
      onClick={async () => {
        await navigator.clipboard.writeText(value);
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }}
    >
      <span aria-live="polite">{copied ? "복사함" : "복사"}</span>
    </button>
  );
}
