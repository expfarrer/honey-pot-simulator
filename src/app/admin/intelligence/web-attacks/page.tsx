import { prisma } from "@/lib/db";
import { SectionHeader } from "@/components/ui/SectionHeader";
import { StatCard } from "@/components/ui/StatCard";
import { RiskBadge } from "@/components/ui/RiskBadge";
import { ActorBadge } from "@/components/ui/ActorBadge";
import { format } from "date-fns";
import Link from "next/link";

export const dynamic = "force-dynamic";
export const revalidate = 0;

const PAYLOAD_COLORS: Record<string, string> = {
  SQLI:          "text-[#ff4757]",
  XSS:           "text-[#ffa502]",
  LFI:           "text-[#a55eea]",
  CMD_INJECTION: "text-[#ff4757] font-bold",
  NONE:          "text-gray-500",
};

const CHAIN_COLORS: Record<string, string> = {
  AUTH_BRUTE_FORCE: "text-[#ff4757]",
  WEB_EXPLOIT:      "text-[#ff4757]",
  SCAN:             "text-[#ffa502]",
};

async function getData() {
  const [
    httpRequestCount,
    httpLoginCount,
    httpPayloadCount,
    topHttpPayloads,
    httpActors,
    recentHttpChains,
    recentLoginEvents,
  ] = await Promise.all([
    prisma.event.count({ where: { eventType: "HTTP_REQUEST" } }),
    prisma.event.count({ where: { eventType: "HTTP_LOGIN_ATTEMPT" } }),
    prisma.event.count({ where: { eventType: "HTTP_PAYLOAD_ATTEMPT" } }),

    prisma.commandPattern.findMany({
      where: { patternType: "HTTP_PAYLOAD" },
      orderBy: { count: "desc" },
      take: 20,
    }),

    prisma.actorProfile.findMany({
      where: { httpRequestCount: { gt: 0 } },
      orderBy: { httpPayloadCount: "desc" },
      take: 30,
    }),

    prisma.attackChain.findMany({
      where: {
        chainType: { in: ["AUTH_BRUTE_FORCE", "WEB_EXPLOIT", "SCAN"] },
      },
      orderBy: { createdAt: "desc" },
      take: 20,
      include: { session: { select: { sourceIp: true, id: true } } },
    }),

    prisma.event.findMany({
      where: { eventType: "HTTP_LOGIN_ATTEMPT" },
      orderBy: { createdAt: "desc" },
      take: 200,
      select: { username: true, createdAt: true, rawJson: true },
    }),
  ]);

  // Aggregate endpoints from recent HTTP events
  const endpointEvents = await prisma.event.findMany({
    where: { eventType: { in: ["HTTP_REQUEST", "HTTP_LOGIN_ATTEMPT", "HTTP_PAYLOAD_ATTEMPT"] } },
    orderBy: { createdAt: "desc" },
    take: 1000,
    select: { rawJson: true, eventType: true },
  });

  const endpointMap = new Map<string, number>();
  for (const ev of endpointEvents) {
    const raw = ev.rawJson as Record<string, unknown>;
    const ep = (raw.endpoint as string) ?? "";
    if (ep) endpointMap.set(ep, (endpointMap.get(ep) ?? 0) + 1);
  }
  const topEndpoints = [...endpointMap.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);

  // Top credential targets from login attempts
  const credMap = new Map<string, number>();
  for (const ev of recentLoginEvents) {
    if (ev.username) {
      credMap.set(ev.username, (credMap.get(ev.username) ?? 0) + 1);
    }
  }
  const topCredTargets = [...credMap.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);

  return {
    httpRequestCount,
    httpLoginCount,
    httpPayloadCount,
    topHttpPayloads,
    httpActors,
    recentHttpChains,
    topEndpoints,
    topCredTargets,
  };
}

export default async function WebAttacksPage() {
  const {
    httpRequestCount,
    httpLoginCount,
    httpPayloadCount,
    topHttpPayloads,
    httpActors,
    recentHttpChains,
    topEndpoints,
    topCredTargets,
  } = await getData();

  const bruteForceCount = recentHttpChains.filter((c) => c.chainType === "AUTH_BRUTE_FORCE").length;

  return (
    <div>
      <SectionHeader
        title="Web Attacks"
        description="HTTP trap telemetry — credential harvesting, payload injection, and scan patterns"
        actions={
          <Link
            href="/admin/intelligence"
            className="px-4 py-2 text-xs font-mono border border-[#1e2535] rounded text-gray-400 hover:text-gray-200 hover:border-gray-500 transition"
          >
            ← All Intelligence
          </Link>
        }
      />

      {/* Overview stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <StatCard label="HTTP Requests"    value={httpRequestCount}  accent="blue" />
        <StatCard label="Login Attempts"   value={httpLoginCount}    accent="yellow" />
        <StatCard label="Payload Attempts" value={httpPayloadCount}  accent="red" />
        <StatCard label="Brute Force IPs"  value={bruteForceCount}   accent="purple" />
      </div>

      {/* Top endpoints + Top credential targets */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">

        <div className="bg-[#0f1117] border border-[#1e2535] rounded-lg overflow-hidden">
          <div className="px-5 py-4 border-b border-[#1e2535]">
            <span className="text-xs text-gray-500 uppercase tracking-widest">Most Targeted Endpoints</span>
          </div>
          <div className="divide-y divide-[#1e2535]">
            {topEndpoints.length === 0 && (
              <div className="px-5 py-8 text-center text-xs text-gray-600 font-mono">No endpoint data yet</div>
            )}
            {topEndpoints.map(([ep, count]) => (
              <div key={ep} className="px-5 py-3 flex items-center justify-between">
                <span className="font-mono text-xs text-[#3d9eff] truncate max-w-[260px]">{ep}</span>
                <span className="font-mono text-xs text-gray-400 shrink-0">{count}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-[#0f1117] border border-[#1e2535] rounded-lg overflow-hidden">
          <div className="px-5 py-4 border-b border-[#1e2535]">
            <span className="text-xs text-gray-500 uppercase tracking-widest">Top Credential Targets</span>
          </div>
          <div className="divide-y divide-[#1e2535]">
            {topCredTargets.length === 0 && (
              <div className="px-5 py-8 text-center text-xs text-gray-600 font-mono">No login attempts yet</div>
            )}
            {topCredTargets.map(([username, count]) => (
              <div key={username} className="px-5 py-3 flex items-center justify-between">
                <span className="font-mono text-xs text-gray-200">{username}</span>
                <span className="font-mono text-xs text-[#ffa502] shrink-0">{count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Top HTTP payloads */}
      <div className="bg-[#0f1117] border border-[#1e2535] rounded-lg overflow-hidden mb-8">
        <div className="px-5 py-4 border-b border-[#1e2535]">
          <span className="text-xs text-gray-500 uppercase tracking-widest">Top HTTP Payloads</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs font-mono">
            <thead>
              <tr className="border-b border-[#1e2535] text-gray-600">
                <th className="text-left px-5 py-2 font-normal uppercase tracking-widest">Payload (normalized)</th>
                <th className="text-left px-3 py-2 font-normal uppercase tracking-widest">Category</th>
                <th className="text-right px-3 py-2 font-normal uppercase tracking-widest">Count</th>
                <th className="text-right px-3 py-2 font-normal uppercase tracking-widest">IPs</th>
                <th className="text-left px-3 py-2 font-normal uppercase tracking-widest">Risk</th>
                <th className="text-left px-3 py-2 font-normal uppercase tracking-widest">Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {topHttpPayloads.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-5 py-8 text-center text-gray-600">No payload patterns yet</td>
                </tr>
              )}
              {topHttpPayloads.map((p) => (
                <tr key={p.id} className="border-b border-[#1e2535] table-row-hover">
                  <td className="px-5 py-2">
                    <span className={`truncate max-w-[280px] block ${PAYLOAD_COLORS[p.category] ?? "text-gray-300"}`}>
                      {p.normalizedCommand}
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    <span className={PAYLOAD_COLORS[p.category] ?? "text-gray-500"}>{p.category}</span>
                  </td>
                  <td className="px-3 py-2 text-right text-[#3d9eff]">{p.count}</td>
                  <td className="px-3 py-2 text-right text-gray-400">
                    {p.uniqueIps >= 100 ? "100+" : p.uniqueIps}
                  </td>
                  <td className="px-3 py-2">
                    <RiskBadge level={p.riskLevel} />
                  </td>
                  <td className="px-3 py-2 text-gray-600">
                    {format(new Date(p.lastSeen), "MMM dd HH:mm")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* HTTP actor profiles */}
      <div className="bg-[#0f1117] border border-[#1e2535] rounded-lg overflow-hidden mb-8">
        <div className="px-5 py-4 border-b border-[#1e2535]">
          <span className="text-xs text-gray-500 uppercase tracking-widest">Web Attacker Profiles</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs font-mono">
            <thead>
              <tr className="border-b border-[#1e2535] text-gray-600">
                <th className="text-left px-5 py-2 font-normal uppercase tracking-widest">Source IP</th>
                <th className="text-left px-3 py-2 font-normal uppercase tracking-widest">Actor</th>
                <th className="text-right px-3 py-2 font-normal uppercase tracking-widest">HTTP Reqs</th>
                <th className="text-right px-3 py-2 font-normal uppercase tracking-widest">Payloads</th>
                <th className="text-right px-3 py-2 font-normal uppercase tracking-widest">Risk</th>
                <th className="text-left px-3 py-2 font-normal uppercase tracking-widest">Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {httpActors.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-5 py-8 text-center text-gray-600">No web attacker profiles yet</td>
                </tr>
              )}
              {httpActors.map((a) => (
                <tr key={a.id} className="border-b border-[#1e2535] table-row-hover">
                  <td className="px-5 py-3 text-gray-300">{a.sourceIp}</td>
                  <td className="px-3 py-3">
                    <ActorBadge type={a.actorType} />
                  </td>
                  <td className="px-3 py-3 text-right text-[#3d9eff]">{a.httpRequestCount}</td>
                  <td className="px-3 py-3 text-right">
                    <span className={a.httpPayloadCount > 0 ? "text-[#ff4757]" : "text-gray-600"}>
                      {a.httpPayloadCount}
                    </span>
                  </td>
                  <td className="px-3 py-3 text-right">
                    <span className={a.riskScore >= 60 ? "text-[#ff4757]" : a.riskScore >= 30 ? "text-[#ffa502]" : "text-gray-500"}>
                      {a.riskScore}
                    </span>
                  </td>
                  <td className="px-3 py-3 text-gray-600">
                    {format(new Date(a.lastSeen), "MMM dd HH:mm")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* HTTP attack chains */}
      <div className="bg-[#0f1117] border border-[#1e2535] rounded-lg overflow-hidden">
        <div className="px-5 py-4 border-b border-[#1e2535]">
          <span className="text-xs text-gray-500 uppercase tracking-widest">HTTP Attack Chains</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs font-mono">
            <thead>
              <tr className="border-b border-[#1e2535] text-gray-600">
                <th className="text-left px-5 py-2 font-normal uppercase tracking-widest">Chain Type</th>
                <th className="text-left px-3 py-2 font-normal uppercase tracking-widest">Severity</th>
                <th className="text-right px-3 py-2 font-normal uppercase tracking-widest">Confidence</th>
                <th className="text-left px-3 py-2 font-normal uppercase tracking-widest">Source IP</th>
                <th className="text-left px-3 py-2 font-normal uppercase tracking-widest">Detected</th>
              </tr>
            </thead>
            <tbody>
              {recentHttpChains.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-5 py-8 text-center text-gray-600">No HTTP attack chains detected yet</td>
                </tr>
              )}
              {recentHttpChains.map((c) => (
                <tr key={c.id} className="border-b border-[#1e2535] table-row-hover">
                  <td className="px-5 py-3">
                    <span className={CHAIN_COLORS[c.chainType] ?? "text-gray-300"}>
                      {c.chainType.replace(/_/g, " ")}
                    </span>
                  </td>
                  <td className="px-3 py-3">
                    <RiskBadge level={c.severity} />
                  </td>
                  <td className="px-3 py-3 text-right text-gray-400">{c.confidence}%</td>
                  <td className="px-3 py-3 text-gray-300">{c.session.sourceIp}</td>
                  <td className="px-3 py-3 text-gray-600">
                    {format(new Date(c.createdAt), "MMM dd HH:mm:ss")}
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
