"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { HoneypotStatus } from "@prisma/client";

interface Props {
  honeypotId: string;
  currentStatus: HoneypotStatus;
}

type Action = "start" | "pause" | "stop" | "restart";

const ACTION_LABELS: Record<Action, string> = {
  start: "Start",
  pause: "Pause",
  stop: "Stop",
  restart: "Restart",
};

const ACTION_COLORS: Record<Action, string> = {
  start: "text-[#00ff88] border-[rgba(0,255,136,0.3)] hover:bg-[rgba(0,255,136,0.08)]",
  pause: "text-[#ffa502] border-[rgba(255,165,2,0.3)] hover:bg-[rgba(255,165,2,0.08)]",
  stop: "text-[#ff4757] border-[rgba(255,71,87,0.3)] hover:bg-[rgba(255,71,87,0.08)]",
  restart: "text-[#3d9eff] border-[rgba(61,158,255,0.3)] hover:bg-[rgba(61,158,255,0.08)]",
};

function availableActions(status: HoneypotStatus): Action[] {
  switch (status) {
    case "RUNNING": return ["pause", "stop", "restart"];
    case "PAUSED": return ["start", "stop"];
    case "STOPPED": return ["start"];
    case "ERROR": return ["start", "restart"];
    default: return [];
  }
}

export function HoneypotControls({ honeypotId, currentStatus }: Props) {
  const router = useRouter();
  const [loading, setLoading] = useState<Action | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleAction(action: Action) {
    setLoading(action);
    setError(null);
    try {
      const res = await fetch(`/api/honeypots/${honeypotId}/${action}`, {
        method: "POST",
      });
      if (!res.ok) {
        const data = await res.json();
        setError(data.error ?? "Action failed");
      } else {
        router.refresh();
      }
    } catch {
      setError("Network error");
    } finally {
      setLoading(null);
    }
  }

  const actions = availableActions(currentStatus);

  return (
    <div className="flex items-center gap-2">
      {actions.map((action) => (
        <button
          key={action}
          onClick={() => handleAction(action)}
          disabled={loading !== null}
          className={`px-3 py-1.5 rounded border text-xs font-mono font-semibold transition disabled:opacity-50 disabled:cursor-not-allowed ${ACTION_COLORS[action]}`}
        >
          {loading === action ? "..." : ACTION_LABELS[action]}
        </button>
      ))}
      {error && (
        <span className="text-xs text-[#ff4757] font-mono">{error}</span>
      )}
    </div>
  );
}
