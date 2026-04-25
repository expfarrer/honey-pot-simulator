import { RiskLevel } from "@prisma/client";
import clsx from "clsx";

const LABELS: Record<RiskLevel, string> = {
  LOW: "LOW",
  MEDIUM: "MEDIUM",
  HIGH: "HIGH",
  CRITICAL: "CRITICAL",
};

const CLASSES: Record<RiskLevel, string> = {
  LOW: "risk-low",
  MEDIUM: "risk-medium",
  HIGH: "risk-high",
  CRITICAL: "risk-critical",
};

export function RiskBadge({ level }: { level: RiskLevel }) {
  return (
    <span
      className={clsx(
        "inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-semibold border",
        CLASSES[level]
      )}
    >
      {LABELS[level]}
    </span>
  );
}
