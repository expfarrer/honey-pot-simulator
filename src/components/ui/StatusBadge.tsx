import { HoneypotStatus } from "@prisma/client";
import clsx from "clsx";

const DOT_CLASSES: Record<HoneypotStatus, string> = {
  RUNNING: "bg-[#00ff88] shadow-[0_0_6px_#00ff88]",
  PAUSED: "bg-[#ffa502]",
  STOPPED: "bg-[#718096]",
  ERROR: "bg-[#ff4757] shadow-[0_0_6px_#ff4757]",
};

const TEXT_CLASSES: Record<HoneypotStatus, string> = {
  RUNNING: "text-[#00ff88]",
  PAUSED: "text-[#ffa502]",
  STOPPED: "text-[#718096]",
  ERROR: "text-[#ff4757]",
};

export function StatusBadge({ status }: { status: HoneypotStatus }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span
        className={clsx("inline-block w-2 h-2 rounded-full", DOT_CLASSES[status])}
      />
      <span className={clsx("text-xs font-mono font-semibold", TEXT_CLASSES[status])}>
        {status}
      </span>
    </span>
  );
}
