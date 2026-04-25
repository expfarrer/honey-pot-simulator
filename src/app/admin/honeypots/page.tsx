import { prisma } from "@/lib/db";
import { SectionHeader } from "@/components/ui/SectionHeader";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { HoneypotControls } from "@/components/HoneypotControls";
import { subHours, format } from "date-fns";
import Link from "next/link";

export const dynamic = "force-dynamic";
export const revalidate = 0;

async function getHoneypots() {
  const since24h = subHours(new Date(), 24);

  return prisma.honeypot.findMany({
    orderBy: { createdAt: "desc" },
    include: {
      _count: { select: { sessions: true } },
      sessions: {
        orderBy: { startedAt: "desc" },
        take: 1,
        select: { startedAt: true },
      },
      // count events via sessions — done separately
    },
  });
}


export default async function HoneypotsPage() {
  const honeypots = await getHoneypots();

  return (
    <div>
      <SectionHeader
        title="Honeypots"
        description="Manage and monitor deployed honeypot instances"
        actions={
          <Link
            href="/admin/honeypots/new"
            className="px-4 py-2 bg-[#00ff88] text-[#0a0d14] text-xs font-mono font-bold rounded hover:bg-[#00e67a] transition"
          >
            + New Honeypot
          </Link>
        }
      />

      <div className="bg-[#0f1117] border border-[#1e2535] rounded-lg overflow-hidden">
        <table className="w-full text-xs font-mono">
          <thead>
            <tr className="border-b border-[#1e2535] text-gray-500">
              <th className="text-left px-6 py-3 font-normal tracking-widest uppercase">Name</th>
              <th className="text-left px-4 py-3 font-normal tracking-widest uppercase">Type</th>
              <th className="text-left px-4 py-3 font-normal tracking-widest uppercase">Status</th>
              <th className="text-left px-4 py-3 font-normal tracking-widest uppercase">Port</th>
              <th className="text-left px-4 py-3 font-normal tracking-widest uppercase">Sessions</th>
              <th className="text-left px-4 py-3 font-normal tracking-widest uppercase">Last Activity</th>
              <th className="text-left px-4 py-3 font-normal tracking-widest uppercase">Controls</th>
            </tr>
          </thead>
          <tbody>
            {honeypots.length === 0 && (
              <tr>
                <td colSpan={7} className="px-6 py-12 text-center text-gray-600">
                  No honeypots configured. Create one to get started.
                </td>
              </tr>
            )}
            {honeypots.map((hp) => {
              const lastActivity = hp.sessions[0]?.startedAt;
              return (
                <tr key={hp.id} className="border-b border-[#1e2535] table-row-hover">
                  <td className="px-6 py-4">
                    <Link
                      href={`/admin/honeypots/${hp.id}`}
                      className="text-gray-200 hover:text-[#00ff88] transition font-semibold"
                    >
                      {hp.name}
                    </Link>
                  </td>
                  <td className="px-4 py-4 text-gray-500">{hp.type}</td>
                  <td className="px-4 py-4">
                    <StatusBadge status={hp.status} />
                  </td>
                  <td className="px-4 py-4 text-[#3d9eff]">:{hp.publicPort}</td>
                  <td className="px-4 py-4 text-gray-400">{hp._count.sessions}</td>
                  <td className="px-4 py-4 text-gray-500">
                    {lastActivity
                      ? format(new Date(lastActivity), "MMM dd HH:mm:ss")
                      : "—"}
                  </td>
                  <td className="px-4 py-4">
                    <HoneypotControls
                      honeypotId={hp.id}
                      currentStatus={hp.status}
                    />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
