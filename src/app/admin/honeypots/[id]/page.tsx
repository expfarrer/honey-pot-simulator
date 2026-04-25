import { prisma } from "@/lib/db";
import { notFound } from "next/navigation";
import { SectionHeader } from "@/components/ui/SectionHeader";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { RiskBadge } from "@/components/ui/RiskBadge";
import { ActorBadge } from "@/components/ui/ActorBadge";
import { HoneypotControls } from "@/components/HoneypotControls";
import { classifyCommand } from "@/lib/intelligence/classifier";
import { format } from "date-fns";
import Link from "next/link";

export const dynamic = "force-dynamic";

const CATEGORY_COLORS: Record<string, string> = {
  fingerprint: "text-[#3d9eff]",
  recon: "text-[#ffa502]",
  payload: "text-[#ff4757]",
  persistence: "text-[#a55eea]",
  anti_forensics: "text-[#ff4757] font-bold",
  unknown: "text-gray-500",
};

export default async function HoneypotDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;

  const honeypot = await prisma.honeypot.findUnique({
    where: { id },
    include: {
      sessions: {
        orderBy: { startedAt: "desc" },
        take: 30,
        include: {
          events: {
            orderBy: { createdAt: "asc" },
          },
        },
      },
      _count: { select: { sessions: true } },
    },
  });

  if (!honeypot) notFound();

  const config = honeypot.configJson as Record<string, unknown>;

  // Build command breakdown
  const commandMap = new Map<string, number>();
  for (const session of honeypot.sessions) {
    for (const event of session.events) {
      if (event.command) {
        commandMap.set(event.command, (commandMap.get(event.command) ?? 0) + 1);
      }
    }
  }
  const topCommands = [...commandMap.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);

  // Credential attempts
  const credMap = new Map<string, number>();
  for (const session of honeypot.sessions) {
    for (const event of session.events) {
      if (event.username) {
        const key = event.username;
        credMap.set(key, (credMap.get(key) ?? 0) + 1);
      }
    }
  }
  const topCreds = [...credMap.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);

  return (
    <div>
      <div className="mb-2">
        <Link
          href="/admin/honeypots"
          className="text-xs text-gray-500 hover:text-gray-300 font-mono transition"
        >
          Honeypots /
        </Link>
        <span className="text-xs text-gray-300 font-mono ml-1">{honeypot.name}</span>
      </div>

      <SectionHeader
        title={honeypot.name}
        description={`${honeypot.type} honeypot on port :${honeypot.publicPort}`}
        actions={
          <div className="flex items-center gap-4">
            <StatusBadge status={honeypot.status} />
            <HoneypotControls
              honeypotId={honeypot.id}
              currentStatus={honeypot.status}
            />
          </div>
        }
      />

      {/* Config panel */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        <div className="bg-[#0f1117] border border-[#1e2535] rounded-lg p-5">
          <div className="text-xs text-gray-500 uppercase tracking-widest mb-4">Configuration</div>
          <dl className="space-y-3 text-xs font-mono">
            {Object.entries(config).map(([k, v]) => (
              <div key={k} className="flex justify-between gap-4">
                <dt className="text-gray-500">{k}</dt>
                <dd className="text-gray-300 text-right truncate max-w-[160px]">
                  {String(v)}
                </dd>
              </div>
            ))}
            <div className="flex justify-between gap-4">
              <dt className="text-gray-500">publicPort</dt>
              <dd className="text-[#3d9eff]">:{honeypot.publicPort}</dd>
            </div>
            <div className="flex justify-between gap-4">
              <dt className="text-gray-500">dockerService</dt>
              <dd className="text-gray-300">{honeypot.dockerService ?? "—"}</dd>
            </div>
          </dl>
        </div>

        <div className="bg-[#0f1117] border border-[#1e2535] rounded-lg p-5">
          <div className="text-xs text-gray-500 uppercase tracking-widest mb-4">Top Commands</div>
          <div className="space-y-2">
            {topCommands.length === 0 && (
              <div className="text-xs text-gray-600">No commands recorded</div>
            )}
            {topCommands.map(([cmd, count]) => {
              const cat = classifyCommand(cmd);
              return (
                <div key={cmd} className="flex items-center justify-between gap-2">
                  <span className={`font-mono text-xs truncate max-w-[180px] ${CATEGORY_COLORS[cat]}`}>
                    {cmd}
                  </span>
                  <span className="text-xs text-gray-500 shrink-0">{count}</span>
                </div>
              );
            })}
          </div>
        </div>

        <div className="bg-[#0f1117] border border-[#1e2535] rounded-lg p-5">
          <div className="text-xs text-gray-500 uppercase tracking-widest mb-4">Credential Attempts</div>
          <div className="space-y-2">
            {topCreds.length === 0 && (
              <div className="text-xs text-gray-600">No credentials recorded</div>
            )}
            {topCreds.map(([username, count]) => (
              <div key={username} className="flex items-center justify-between gap-2">
                <span className="font-mono text-xs text-gray-300 truncate">{username}</span>
                <span className="text-xs text-[#3d9eff] shrink-0">{count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Sessions list with event timeline */}
      <div className="bg-[#0f1117] border border-[#1e2535] rounded-lg overflow-hidden">
        <div className="px-6 py-4 border-b border-[#1e2535] flex items-center justify-between">
          <span className="text-xs text-gray-500 uppercase tracking-widest">
            Sessions ({honeypot._count.sessions})
          </span>
        </div>

        <div className="divide-y divide-[#1e2535]">
          {honeypot.sessions.length === 0 && (
            <div className="px-6 py-12 text-center text-xs text-gray-600 font-mono">
              No sessions yet
            </div>
          )}
          {honeypot.sessions.map((session) => (
            <details key={session.id} className="group">
              <summary className="px-6 py-4 flex items-center gap-4 cursor-pointer list-none hover:bg-[#161b27] transition">
                <span className="text-gray-400 font-mono text-xs w-4 group-open:text-[#00ff88]">
                  ▶
                </span>
                <span className="font-mono text-xs text-gray-200 w-32 shrink-0">
                  {session.sourceIp}
                </span>
                <span className="font-mono text-xs text-gray-500">
                  {format(new Date(session.startedAt), "MMM dd HH:mm:ss")}
                </span>
                <span className="font-mono text-xs text-gray-600 ml-auto mr-4">
                  {session.events.length} events
                </span>
                <ActorBadge type={session.actorType} />
                <RiskBadge level={session.riskLevel} />
              </summary>

              {/* Event timeline */}
              <div className="px-6 pb-4 pl-16 space-y-1 bg-[#080b11]">
                {session.events.map((ev) => {
                  const isHttp = ev.eventType.startsWith("HTTP_");
                  const cat = ev.command && !isHttp ? classifyCommand(ev.command) : null;
                  const raw = ev.rawJson as Record<string, unknown>;
                  const payloadCat = raw?.payloadCategory as string | undefined;
                  const httpEndpoint = raw?.endpoint as string | undefined;

                  return (
                    <div key={ev.id} className="flex items-start gap-3 py-1">
                      <span className="font-mono text-xs text-gray-600 w-20 shrink-0">
                        {format(new Date(ev.createdAt), "HH:mm:ss")}
                      </span>
                      <span className={`font-mono text-xs w-28 shrink-0 ${isHttp ? "text-[#3d9eff]" : "text-gray-500"}`}>
                        {ev.eventType}
                      </span>
                      {isHttp ? (
                        <span className="font-mono text-xs text-gray-400 truncate max-w-[300px]">
                          {ev.username && <span className="text-gray-300">{ev.username}</span>}
                          {ev.username && " @ "}
                          <span className={payloadCat && payloadCat !== "NONE" ? "text-[#ff4757]" : "text-gray-500"}>
                            {httpEndpoint ?? ev.command ?? ""}
                          </span>
                          {payloadCat && payloadCat !== "NONE" && (
                            <span className="ml-2 text-[#ffa502]">[{payloadCat}]</span>
                          )}
                        </span>
                      ) : (
                        <>
                          {ev.command && (
                            <span className={`font-mono text-xs ${cat ? CATEGORY_COLORS[cat] : "text-gray-300"}`}>
                              {ev.command}
                            </span>
                          )}
                          {ev.username && !ev.command && (
                            <span className="font-mono text-xs text-gray-400">
                              user: {ev.username}
                            </span>
                          )}
                        </>
                      )}
                    </div>
                  );
                })}
                {session.events.length === 0 && (
                  <div className="text-xs text-gray-600 py-2">No events</div>
                )}
              </div>
            </details>
          ))}
        </div>
      </div>
    </div>
  );
}
