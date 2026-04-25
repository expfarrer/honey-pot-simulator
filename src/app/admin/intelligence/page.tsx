import { prisma } from "@/lib/db";
import { SectionHeader } from "@/components/ui/SectionHeader";
import { StatCard } from "@/components/ui/StatCard";
import { RiskBadge } from "@/components/ui/RiskBadge";
import { ActorBadge } from "@/components/ui/ActorBadge";
import { format } from "date-fns";
import Link from "next/link";

export const dynamic = "force-dynamic";
export const revalidate = 0;

const CATEGORY_COLORS: Record<string, string> = {
  fingerprint:    "text-[#3d9eff]",
  recon:          "text-[#ffa502]",
  payload:        "text-[#ff4757]",
  persistence:    "text-[#a55eea]",
  anti_forensics: "text-[#ff4757] font-bold",
  unknown:        "text-gray-500",
};

const CHAIN_COLORS: Record<string, string> = {
  FINGERPRINT:       "text-[#3d9eff]",
  PAYLOAD_EXECUTION: "text-[#ff4757]",
  PERSISTENCE:       "text-[#a55eea]",
  ANTI_FORENSICS:    "text-[#ff4757]",
  IOT_BOT:           "text-[#ffa502]",
};

async function getData() {
  const [
    commandPatternCount,
    credentialPatternCount,
    actorCount,
    chainCount,
    topCommands,
    topCredentials,
    actors,
    recentChains,
  ] = await Promise.all([
    prisma.commandPattern.count(),
    prisma.credentialPattern.count(),
    prisma.actorProfile.count(),
    prisma.attackChain.count(),

    prisma.commandPattern.findMany({
      orderBy: { count: "desc" },
      take: 20,
    }),

    prisma.credentialPattern.findMany({
      orderBy: { count: "desc" },
      take: 20,
    }),

    prisma.actorProfile.findMany({
      orderBy: { riskScore: "desc" },
      take: 30,
    }),

    prisma.attackChain.findMany({
      orderBy: { createdAt: "desc" },
      take: 20,
      include: {
        session: { select: { sourceIp: true, id: true } },
      },
    }),
  ]);

  return {
    commandPatternCount,
    credentialPatternCount,
    actorCount,
    chainCount,
    topCommands,
    topCredentials,
    actors,
    recentChains,
  };
}

export default async function IntelligencePage() {
  const {
    commandPatternCount,
    credentialPatternCount,
    actorCount,
    chainCount,
    topCommands,
    topCredentials,
    actors,
    recentChains,
  } = await getData();

  return (
    <div>
      <SectionHeader
        title="Threat Intelligence"
        description="Aggregated attacker patterns, actor profiles, and detected attack chains"
        actions={
          <Link
            href="/admin/intelligence/interesting-sessions"
            className="px-4 py-2 text-xs font-mono border border-[#1e2535] rounded text-gray-400 hover:text-gray-200 hover:border-gray-500 transition"
          >
            Interesting Sessions →
          </Link>
        }
      />

      {/* Overview cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <StatCard label="Command Patterns" value={commandPatternCount} accent="blue" />
        <StatCard label="Credential Combos" value={credentialPatternCount} accent="yellow" />
        <StatCard label="Known Actors"      value={actorCount}           accent="purple" />
        <StatCard label="Attack Chains"     value={chainCount}           accent="red" />
      </div>

      {/* Command patterns + Credential combos */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">

        {/* Command patterns table */}
        <div className="bg-[#0f1117] border border-[#1e2535] rounded-lg overflow-hidden">
          <div className="px-5 py-4 border-b border-[#1e2535]">
            <span className="text-xs text-gray-500 uppercase tracking-widest">Top Command Patterns</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs font-mono">
              <thead>
                <tr className="border-b border-[#1e2535] text-gray-600">
                  <th className="text-left px-5 py-2 font-normal uppercase tracking-widest">Command</th>
                  <th className="text-left px-3 py-2 font-normal uppercase tracking-widest">Cat</th>
                  <th className="text-right px-3 py-2 font-normal uppercase tracking-widest">Count</th>
                  <th className="text-right px-3 py-2 font-normal uppercase tracking-widest">IPs</th>
                  <th className="text-left px-3 py-2 font-normal uppercase tracking-widest">Risk</th>
                  <th className="text-left px-3 py-2 font-normal uppercase tracking-widest">Last</th>
                </tr>
              </thead>
              <tbody>
                {topCommands.length === 0 && (
                  <tr>
                    <td colSpan={6} className="px-5 py-6 text-center text-gray-600">No patterns yet</td>
                  </tr>
                )}
                {topCommands.map((p) => (
                  <tr key={p.id} className="border-b border-[#1e2535] table-row-hover">
                    <td className="px-5 py-2">
                      <span className={`truncate max-w-[220px] block ${CATEGORY_COLORS[p.category] ?? "text-gray-300"}`}>
                        {p.normalizedCommand}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-gray-500">{p.category}</td>
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

        {/* Credential combos table */}
        <div className="bg-[#0f1117] border border-[#1e2535] rounded-lg overflow-hidden">
          <div className="px-5 py-4 border-b border-[#1e2535]">
            <span className="text-xs text-gray-500 uppercase tracking-widest">Top Credential Combos</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs font-mono">
              <thead>
                <tr className="border-b border-[#1e2535] text-gray-600">
                  <th className="text-left px-5 py-2 font-normal uppercase tracking-widest">Username</th>
                  <th className="text-left px-3 py-2 font-normal uppercase tracking-widest">Password Hash</th>
                  <th className="text-right px-3 py-2 font-normal uppercase tracking-widest">Count</th>
                  <th className="text-right px-3 py-2 font-normal uppercase tracking-widest">IPs</th>
                  <th className="text-left px-3 py-2 font-normal uppercase tracking-widest">First</th>
                  <th className="text-left px-3 py-2 font-normal uppercase tracking-widest">Last</th>
                </tr>
              </thead>
              <tbody>
                {topCredentials.length === 0 && (
                  <tr>
                    <td colSpan={6} className="px-5 py-6 text-center text-gray-600">No credential data yet</td>
                  </tr>
                )}
                {topCredentials.map((c) => (
                  <tr key={c.id} className="border-b border-[#1e2535] table-row-hover">
                    <td className="px-5 py-2 text-gray-200">{c.username}</td>
                    <td className="px-3 py-2 text-gray-600">
                      {c.passwordHash.slice(0, 8)}…
                    </td>
                    <td className="px-3 py-2 text-right text-[#ffa502]">{c.count}</td>
                    <td className="px-3 py-2 text-right text-gray-400">
                      {c.uniqueIps >= 100 ? "100+" : c.uniqueIps}
                    </td>
                    <td className="px-3 py-2 text-gray-600">
                      {format(new Date(c.firstSeen), "MMM dd")}
                    </td>
                    <td className="px-3 py-2 text-gray-600">
                      {format(new Date(c.lastSeen), "MMM dd HH:mm")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Actor profiles */}
      <div className="bg-[#0f1117] border border-[#1e2535] rounded-lg overflow-hidden mb-8">
        <div className="px-5 py-4 border-b border-[#1e2535]">
          <span className="text-xs text-gray-500 uppercase tracking-widest">Actor Profiles</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs font-mono">
            <thead>
              <tr className="border-b border-[#1e2535] text-gray-600">
                <th className="text-left px-5 py-2 font-normal uppercase tracking-widest">Source IP</th>
                <th className="text-left px-3 py-2 font-normal uppercase tracking-widest">Actor</th>
                <th className="text-right px-3 py-2 font-normal uppercase tracking-widest">Risk Score</th>
                <th className="text-right px-3 py-2 font-normal uppercase tracking-widest">Sessions</th>
                <th className="text-right px-3 py-2 font-normal uppercase tracking-widest">Events</th>
                <th className="text-left px-3 py-2 font-normal uppercase tracking-widest">First Seen</th>
                <th className="text-left px-3 py-2 font-normal uppercase tracking-widest">Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {actors.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-5 py-8 text-center text-gray-600">No actor profiles yet</td>
                </tr>
              )}
              {actors.map((a) => (
                <tr key={a.id} className="border-b border-[#1e2535] table-row-hover">
                  <td className="px-5 py-3 text-gray-300">{a.sourceIp}</td>
                  <td className="px-3 py-3">
                    <ActorBadge type={a.actorType} />
                  </td>
                  <td className="px-3 py-3 text-right">
                    <span className={a.riskScore >= 60 ? "text-[#ff4757]" : a.riskScore >= 30 ? "text-[#ffa502]" : "text-gray-500"}>
                      {a.riskScore}
                    </span>
                  </td>
                  <td className="px-3 py-3 text-right text-gray-400">{a.totalSessions}</td>
                  <td className="px-3 py-3 text-right text-gray-400">{a.totalEvents}</td>
                  <td className="px-3 py-3 text-gray-600">{format(new Date(a.firstSeen), "MMM dd HH:mm")}</td>
                  <td className="px-3 py-3 text-gray-600">{format(new Date(a.lastSeen), "MMM dd HH:mm")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Attack chains */}
      <div className="bg-[#0f1117] border border-[#1e2535] rounded-lg overflow-hidden">
        <div className="px-5 py-4 border-b border-[#1e2535]">
          <span className="text-xs text-gray-500 uppercase tracking-widest">Attack Chains</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs font-mono">
            <thead>
              <tr className="border-b border-[#1e2535] text-gray-600">
                <th className="text-left px-5 py-2 font-normal uppercase tracking-widest">Chain Type</th>
                <th className="text-left px-3 py-2 font-normal uppercase tracking-widest">Severity</th>
                <th className="text-right px-3 py-2 font-normal uppercase tracking-widest">Confidence</th>
                <th className="text-left px-3 py-2 font-normal uppercase tracking-widest">Source IP</th>
                <th className="text-left px-3 py-2 font-normal uppercase tracking-widest">Session</th>
                <th className="text-left px-3 py-2 font-normal uppercase tracking-widest">Detected</th>
              </tr>
            </thead>
            <tbody>
              {recentChains.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-5 py-8 text-center text-gray-600">No attack chains detected yet</td>
                </tr>
              )}
              {recentChains.map((c) => (
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
                  <td className="px-3 py-3">
                    <Link
                      href={`/admin/honeypots`}
                      className="text-[#3d9eff] hover:underline font-mono"
                    >
                      {c.session.id.slice(0, 8)}…
                    </Link>
                  </td>
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
