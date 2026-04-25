import { prisma } from "@/lib/db";
import { SectionHeader } from "@/components/ui/SectionHeader";
import { RiskBadge } from "@/components/ui/RiskBadge";
import { ActorBadge } from "@/components/ui/ActorBadge";
import { classifyCommand } from "@/lib/intelligence/classifier";
import { format } from "date-fns";
import Link from "next/link";

export const dynamic = "force-dynamic";
export const revalidate = 0;

// Simple Levenshtein edit distance
function editDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] =
        a[i - 1] === b[j - 1]
          ? dp[i - 1][j - 1]
          : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

const KNOWN_COMMANDS = [
  "ls", "cd", "cat", "grep", "find", "pwd", "whoami", "uname", "id", "echo",
  "clear", "exit", "ifconfig", "netstat", "ps", "top", "wget", "curl", "chmod",
];

function hasTypoCommand(commands: string[]): boolean {
  for (const cmd of commands) {
    const first = cmd.split(" ")[0].toLowerCase();
    if (KNOWN_COMMANDS.includes(first)) continue;
    if (first.length < 2 || first.length > 12) continue;
    for (const known of KNOWN_COMMANDS) {
      if (editDistance(first, known) === 1) return true;
    }
  }
  return false;
}

function hasCategory(commands: string[], target: string): boolean {
  return commands.some((c) => classifyCommand(c) === target);
}

interface InterestingReason {
  label: string;
  color: string;
}

function getReasons(params: {
  commands: string[];
  riskLevel: string;
  durationSeconds: number;
}): InterestingReason[] {
  const reasons: InterestingReason[] = [];
  const { commands, riskLevel, durationSeconds } = params;

  if (riskLevel === "HIGH" || riskLevel === "CRITICAL") {
    reasons.push({ label: riskLevel, color: "text-[#ff4757]" });
  }
  if (commands.length > 5) {
    reasons.push({ label: `${commands.length} commands`, color: "text-[#ffa502]" });
  }
  if (hasTypoCommand(commands)) {
    reasons.push({ label: "typo detected", color: "text-[#3d9eff]" });
  }
  if (hasCategory(commands, "payload")) {
    reasons.push({ label: "payload", color: "text-[#ff4757]" });
  }
  if (hasCategory(commands, "anti_forensics")) {
    reasons.push({ label: "anti-forensics", color: "text-[#a55eea]" });
  }
  if (durationSeconds > 30) {
    reasons.push({ label: `${Math.round(durationSeconds)}s session`, color: "text-[#00ff88]" });
  }
  return reasons;
}

async function getInterestingSessions() {
  // Fetch high-signal candidates from DB
  const candidates = await prisma.session.findMany({
    where: {
      OR: [
        { riskLevel: { in: ["HIGH", "CRITICAL"] } },
        { attackChains: { some: {} } },
        { endedAt: { not: null } },
      ],
    },
    orderBy: { startedAt: "desc" },
    take: 200,
    include: {
      honeypot: { select: { name: true, id: true } },
      attackChains: { select: { chainType: true, severity: true } },
      events: {
        where: { eventType: "COMMAND" },
        select: { command: true, createdAt: true },
        orderBy: { createdAt: "asc" },
      },
      _count: { select: { events: { where: { eventType: "COMMAND" } } } },
    },
  });

  // Apply application-side interesting filters
  return candidates
    .map((s) => {
      const commands = s.events.map((e) => e.command!).filter(Boolean);
      const durationSeconds =
        s.endedAt ? (s.endedAt.getTime() - s.startedAt.getTime()) / 1000 : 0;

      const reasons = getReasons({
        commands,
        riskLevel: s.riskLevel,
        durationSeconds,
      });

      return { session: s, commands, durationSeconds, reasons };
    })
    .filter((item) => item.reasons.length > 0)
    .sort((a, b) => b.reasons.length - a.reasons.length);
}

export default async function InterestingSessionsPage() {
  const sessions = await getInterestingSessions();

  return (
    <div>
      <SectionHeader
        title="Interesting Sessions"
        description="High-signal sessions filtered for human operators, payload attempts, and anomalies"
        actions={
          <Link
            href="/admin/intelligence"
            className="px-4 py-2 text-xs font-mono border border-[#1e2535] rounded text-gray-400 hover:text-gray-200 hover:border-gray-500 transition"
          >
            ← Intelligence
          </Link>
        }
      />

      <div className="mb-4 text-xs text-gray-600 font-mono">
        {sessions.length} session{sessions.length !== 1 ? "s" : ""} flagged
      </div>

      <div className="bg-[#0f1117] border border-[#1e2535] rounded-lg overflow-hidden">
        <table className="w-full text-xs font-mono">
          <thead>
            <tr className="border-b border-[#1e2535] text-gray-600">
              <th className="text-left px-5 py-3 font-normal uppercase tracking-widest">Source IP</th>
              <th className="text-left px-3 py-3 font-normal uppercase tracking-widest">Honeypot</th>
              <th className="text-left px-3 py-3 font-normal uppercase tracking-widest">Actor</th>
              <th className="text-right px-3 py-3 font-normal uppercase tracking-widest">Cmds</th>
              <th className="text-left px-3 py-3 font-normal uppercase tracking-widest">Risk</th>
              <th className="text-left px-3 py-3 font-normal uppercase tracking-widest">Chains</th>
              <th className="text-left px-3 py-3 font-normal uppercase tracking-widest">Reasons</th>
              <th className="text-left px-3 py-3 font-normal uppercase tracking-widest">Started</th>
            </tr>
          </thead>
          <tbody>
            {sessions.length === 0 && (
              <tr>
                <td colSpan={8} className="px-5 py-12 text-center text-gray-600">
                  No interesting sessions detected yet. Ingest more data to see results.
                </td>
              </tr>
            )}
            {sessions.map(({ session: s, commands, reasons }) => (
              <tr key={s.id} className="border-b border-[#1e2535] table-row-hover">
                <td className="px-5 py-3 text-gray-200">{s.sourceIp}</td>
                <td className="px-3 py-3 text-gray-500">{s.honeypot.name}</td>
                <td className="px-3 py-3">
                  <ActorBadge type={s.actorType} />
                </td>
                <td className="px-3 py-3 text-right text-gray-400">{commands.length}</td>
                <td className="px-3 py-3">
                  <RiskBadge level={s.riskLevel} />
                </td>
                <td className="px-3 py-3">
                  {s.attackChains.length === 0 ? (
                    <span className="text-gray-700">—</span>
                  ) : (
                    <div className="flex flex-wrap gap-1">
                      {s.attackChains.map((c) => (
                        <span
                          key={c.chainType}
                          className="text-[10px] px-1.5 py-0.5 rounded bg-[rgba(165,94,234,0.08)] border border-[rgba(165,94,234,0.2)] text-[#a55eea]"
                        >
                          {c.chainType.replace(/_/g, " ")}
                        </span>
                      ))}
                    </div>
                  )}
                </td>
                <td className="px-3 py-3">
                  <div className="flex flex-wrap gap-1">
                    {reasons.map((r) => (
                      <span key={r.label} className={`text-[10px] ${r.color}`}>
                        {r.label}
                      </span>
                    ))}
                  </div>
                </td>
                <td className="px-3 py-3 text-gray-600">
                  {format(new Date(s.startedAt), "MMM dd HH:mm:ss")}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Session detail expandable preview */}
      {sessions.length > 0 && (
        <div className="mt-8 space-y-4">
          <div className="text-xs text-gray-500 uppercase tracking-widest mb-4">
            Command Preview — Top Sessions
          </div>
          {sessions.slice(0, 5).map(({ session: s, commands }) => (
            <div
              key={s.id}
              className="bg-[#0f1117] border border-[#1e2535] rounded-lg overflow-hidden"
            >
              <div className="px-5 py-3 border-b border-[#1e2535] flex items-center gap-4">
                <span className="text-gray-300 font-mono text-xs">{s.sourceIp}</span>
                <ActorBadge type={s.actorType} />
                <RiskBadge level={s.riskLevel} />
                <span className="text-gray-600 text-xs ml-auto">
                  {format(new Date(s.startedAt), "MMM dd HH:mm:ss")}
                </span>
              </div>
              <div className="p-5 space-y-1 bg-[#080b11]">
                {commands.length === 0 && (
                  <div className="text-xs text-gray-600">No commands</div>
                )}
                {commands.map((cmd, i) => {
                  const cat = classifyCommand(cmd);
                  const catColors: Record<string, string> = {
                    fingerprint: "text-[#3d9eff]",
                    recon: "text-[#ffa502]",
                    payload: "text-[#ff4757]",
                    persistence: "text-[#a55eea]",
                    anti_forensics: "text-[#ff4757] font-bold",
                    unknown: "text-gray-500",
                  };
                  return (
                    <div key={i} className="flex items-start gap-3">
                      <span className="text-gray-600 w-5 shrink-0">{i + 1}</span>
                      <span className={`font-mono text-xs ${catColors[cat]}`}>{cmd}</span>
                      <span className="text-gray-700 text-[10px] ml-auto shrink-0">{cat}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
