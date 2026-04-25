import { prisma } from "@/lib/db";
import { StatCard } from "@/components/ui/StatCard";
import { RiskBadge } from "@/components/ui/RiskBadge";
import { ActorBadge } from "@/components/ui/ActorBadge";
import { SectionHeader } from "@/components/ui/SectionHeader";
import { ConnectionChart } from "@/components/charts/ConnectionChart";
import { subHours, startOfMinute, subMinutes, format } from "date-fns";
import Link from "next/link";

export const dynamic = "force-dynamic";
export const revalidate = 0;

async function getDashboardData() {
  const since24h = subHours(new Date(), 24);

  const [
    activeHoneypots,
    totalConnections,
    uniqueIpGroups,
    riskBreakdown,
    topUsernames,
    topCommands,
    recentSessions,
    timeSeriesRaw,
  ] = await Promise.all([
    prisma.honeypot.count({ where: { status: "RUNNING" } }),
    prisma.session.count({ where: { startedAt: { gte: since24h } } }),
    prisma.session.groupBy({
      by: ["sourceIp"],
      where: { startedAt: { gte: since24h } },
      _count: true,
    }),
    prisma.session.groupBy({
      by: ["riskLevel"],
      where: { startedAt: { gte: since24h } },
      _count: true,
    }),
    prisma.event.groupBy({
      by: ["username"],
      where: { username: { not: null }, createdAt: { gte: since24h } },
      _count: true,
      orderBy: { _count: { username: "desc" } },
      take: 8,
    }),
    prisma.event.groupBy({
      by: ["command"],
      where: { command: { not: null }, eventType: "COMMAND", createdAt: { gte: since24h } },
      _count: true,
      orderBy: { _count: { command: "desc" } },
      take: 8,
    }),
    prisma.session.findMany({
      where: { startedAt: { gte: since24h } },
      orderBy: { startedAt: "desc" },
      take: 15,
      include: {
        honeypot: { select: { name: true } },
        _count: { select: { events: true } },
      },
    }),
    prisma.session.findMany({
      where: { startedAt: { gte: subMinutes(new Date(), 60) } },
      select: { startedAt: true },
      orderBy: { startedAt: "asc" },
    }),
  ]);

  const buckets = new Map<string, number>();
  for (let i = 59; i >= 0; i--) {
    const bucket = startOfMinute(subMinutes(new Date(), i));
    buckets.set(bucket.toISOString(), 0);
  }
  for (const { startedAt } of timeSeriesRaw) {
    const key = startOfMinute(startedAt).toISOString();
    if (buckets.has(key)) {
      buckets.set(key, (buckets.get(key) ?? 0) + 1);
    }
  }
  const timeSeries = Array.from(buckets.entries()).map(([time, count]) => ({ time, count }));

  const riskMap = Object.fromEntries(riskBreakdown.map((r) => [r.riskLevel, r._count]));

  return {
    activeHoneypots,
    totalConnections,
    uniqueIps: uniqueIpGroups.length,
    riskMap,
    topUsernames,
    topCommands,
    recentSessions,
    timeSeries,
  };
}

export default async function AdminDashboard() {
  const {
    activeHoneypots,
    totalConnections,
    uniqueIps,
    riskMap,
    topUsernames,
    topCommands,
    recentSessions,
    timeSeries,
  } = await getDashboardData();

  return (
    <div>
      <SectionHeader
        title="Dashboard"
        description="Threat activity overview — last 24 hours"
      />

      {/* Stat row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <StatCard label="Active Honeypots" value={activeHoneypots} accent="green" />
        <StatCard label="Connections (24h)" value={totalConnections} accent="blue" />
        <StatCard label="Unique Source IPs" value={uniqueIps} accent="yellow" />
        <StatCard
          label="Critical Sessions"
          value={riskMap["CRITICAL"] ?? 0}
          accent="red"
          sub={`${riskMap["HIGH"] ?? 0} HIGH  ${riskMap["MEDIUM"] ?? 0} MEDIUM`}
        />
      </div>

      {/* Risk breakdown */}
      <div className="grid grid-cols-4 gap-3 mb-8">
        {(["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const).map((level) => (
          <div key={level} className="bg-[#0f1117] border border-[#1e2535] rounded-lg p-4">
            <RiskBadge level={level} />
            <div className="text-2xl font-mono font-bold text-gray-100 mt-2">
              {riskMap[level] ?? 0}
            </div>
          </div>
        ))}
      </div>

      {/* Chart */}
      <div className="bg-[#0f1117] border border-[#1e2535] rounded-lg p-6 mb-8">
        <div className="text-xs text-gray-500 uppercase tracking-widest mb-4">
          Connections / Minute — Last 60 Minutes
        </div>
        <ConnectionChart data={timeSeries} />
      </div>

      {/* Bottom grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Top usernames */}
        <div className="bg-[#0f1117] border border-[#1e2535] rounded-lg p-5">
          <div className="text-xs text-gray-500 uppercase tracking-widest mb-4">
            Top Usernames (24h)
          </div>
          <div className="space-y-2">
            {topUsernames.length === 0 && (
              <div className="text-xs text-gray-600">No data</div>
            )}
            {topUsernames.map((u) => (
              <div key={u.username} className="flex items-center justify-between">
                <span className="font-mono text-xs text-gray-300 truncate max-w-[160px]">
                  {u.username}
                </span>
                <span className="font-mono text-xs text-[#3d9eff] ml-2 shrink-0">
                  {u._count}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Top commands */}
        <div className="bg-[#0f1117] border border-[#1e2535] rounded-lg p-5">
          <div className="text-xs text-gray-500 uppercase tracking-widest mb-4">
            Top Commands (24h)
          </div>
          <div className="space-y-2">
            {topCommands.length === 0 && (
              <div className="text-xs text-gray-600">No data</div>
            )}
            {topCommands.map((c) => (
              <div key={c.command} className="flex items-center justify-between">
                <span className="font-mono text-xs text-[#ffa502] truncate max-w-[180px]">
                  {c.command}
                </span>
                <span className="font-mono text-xs text-gray-500 ml-2 shrink-0">
                  {c._count}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Risk by actor */}
        <div className="bg-[#0f1117] border border-[#1e2535] rounded-lg p-5">
          <div className="text-xs text-gray-500 uppercase tracking-widest mb-4">
            Recent Sessions
          </div>
          <div className="space-y-2">
            {recentSessions.slice(0, 5).map((s) => (
              <div key={s.id} className="flex items-center justify-between gap-2">
                <span className="font-mono text-xs text-gray-400 truncate">
                  {s.sourceIp}
                </span>
                <div className="flex items-center gap-1.5 shrink-0">
                  <ActorBadge type={s.actorType} />
                  <RiskBadge level={s.riskLevel} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent sessions table */}
      <div className="mt-8 bg-[#0f1117] border border-[#1e2535] rounded-lg overflow-hidden">
        <div className="px-6 py-4 border-b border-[#1e2535]">
          <span className="text-xs text-gray-500 uppercase tracking-widest">
            Recent Sessions
          </span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs font-mono">
            <thead>
              <tr className="border-b border-[#1e2535] text-gray-500">
                <th className="text-left px-6 py-3 font-normal tracking-widest uppercase">Source IP</th>
                <th className="text-left px-4 py-3 font-normal tracking-widest uppercase">Honeypot</th>
                <th className="text-left px-4 py-3 font-normal tracking-widest uppercase">Started</th>
                <th className="text-left px-4 py-3 font-normal tracking-widest uppercase">Events</th>
                <th className="text-left px-4 py-3 font-normal tracking-widest uppercase">Actor</th>
                <th className="text-left px-4 py-3 font-normal tracking-widest uppercase">Risk</th>
              </tr>
            </thead>
            <tbody>
              {recentSessions.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-6 py-8 text-center text-gray-600">
                    No sessions recorded yet
                  </td>
                </tr>
              )}
              {recentSessions.map((s) => (
                <tr key={s.id} className="border-b border-[#1e2535] table-row-hover">
                  <td className="px-6 py-3 text-gray-300">{s.sourceIp}</td>
                  <td className="px-4 py-3 text-gray-500">{s.honeypot.name}</td>
                  <td className="px-4 py-3 text-gray-500">
                    {format(new Date(s.startedAt), "MMM dd HH:mm:ss")}
                  </td>
                  <td className="px-4 py-3 text-gray-400">{s._count.events}</td>
                  <td className="px-4 py-3">
                    <ActorBadge type={s.actorType} />
                  </td>
                  <td className="px-4 py-3">
                    <RiskBadge level={s.riskLevel} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
