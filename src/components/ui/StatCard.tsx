interface StatCardProps {
  label: string;
  value: string | number;
  sub?: string;
  accent?: "green" | "red" | "yellow" | "blue" | "purple" | "default";
}

const ACCENT_COLORS = {
  green: "text-[#00ff88]",
  red: "text-[#ff4757]",
  yellow: "text-[#ffa502]",
  blue: "text-[#3d9eff]",
  purple: "text-[#a55eea]",
  default: "text-gray-100",
};

export function StatCard({ label, value, sub, accent = "default" }: StatCardProps) {
  return (
    <div className="bg-[#0f1117] border border-[#1e2535] rounded-lg p-5">
      <div className="text-xs text-gray-500 uppercase tracking-widest mb-2">{label}</div>
      <div className={`text-3xl font-mono font-bold ${ACCENT_COLORS[accent]}`}>
        {value}
      </div>
      {sub && <div className="text-xs text-gray-600 mt-1">{sub}</div>}
    </div>
  );
}
