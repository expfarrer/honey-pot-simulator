"use client";

import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { format } from "date-fns";

interface DataPoint {
  time: string;
  count: number;
}

interface Props {
  data: DataPoint[];
}

function CustomTooltip({ active, payload, label }: {
  active?: boolean;
  payload?: { value: number }[];
  label?: string;
}) {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-[#161b27] border border-[#1e2535] rounded px-3 py-2 text-xs font-mono">
      <div className="text-gray-400">{label && format(new Date(label), "HH:mm")}</div>
      <div className="text-[#00ff88] font-bold">{payload[0].value} connections</div>
    </div>
  );
}

export function ConnectionChart({ data }: Props) {
  const formatted = data.map((d) => ({
    ...d,
    label: format(new Date(d.time), "HH:mm"),
  }));

  return (
    <ResponsiveContainer width="100%" height={200}>
      <AreaChart data={formatted} margin={{ top: 5, right: 5, bottom: 0, left: -20 }}>
        <defs>
          <linearGradient id="connectionGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#00ff88" stopOpacity={0.15} />
            <stop offset="95%" stopColor="#00ff88" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="#1e2535" vertical={false} />
        <XAxis
          dataKey="label"
          tick={{ fill: "#4a5568", fontSize: 10, fontFamily: "monospace" }}
          axisLine={false}
          tickLine={false}
          interval={9}
        />
        <YAxis
          tick={{ fill: "#4a5568", fontSize: 10, fontFamily: "monospace" }}
          axisLine={false}
          tickLine={false}
          allowDecimals={false}
        />
        <Tooltip content={<CustomTooltip />} />
        <Area
          type="monotone"
          dataKey="count"
          stroke="#00ff88"
          strokeWidth={1.5}
          fill="url(#connectionGradient)"
          dot={false}
          activeDot={{ r: 3, fill: "#00ff88", stroke: "#00ff88" }}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}
