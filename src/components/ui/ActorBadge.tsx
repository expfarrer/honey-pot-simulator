import { ActorType } from "@prisma/client";
import clsx from "clsx";

const CLASSES: Record<ActorType, string> = {
  BOT: "text-[#718096] bg-[rgba(113,128,150,0.08)] border-[rgba(113,128,150,0.2)]",
  HUMAN: "text-[#3d9eff] bg-[rgba(61,158,255,0.08)] border-[rgba(61,158,255,0.2)]",
  ADVANCED: "text-[#a55eea] bg-[rgba(165,94,234,0.08)] border-[rgba(165,94,234,0.2)]",
};

export function ActorBadge({ type }: { type: ActorType }) {
  return (
    <span
      className={clsx(
        "inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-semibold border",
        CLASSES[type]
      )}
    >
      {type}
    </span>
  );
}
