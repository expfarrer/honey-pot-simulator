import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { validateAdminSecret } from "@/lib/auth";
import { subHours, startOfMinute, subMinutes } from "date-fns";

export async function GET(req: NextRequest) {
  if (!validateAdminSecret(req)) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const since24h = subHours(new Date(), 24);

  const [
    activeHoneypots,
    totalConnections,
    uniqueIps,
    riskBreakdown,
    topUsernames,
    topPasswords,
    topCommands,
    recentSessions,
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
      where: {
        username: { not: null },
        createdAt: { gte: since24h },
      },
      _count: true,
      orderBy: { _count: { username: "desc" } },
      take: 10,
    }),

    prisma.event.groupBy({
      by: ["password"],
      where: {
        password: { not: null },
        createdAt: { gte: since24h },
      },
      _count: true,
      orderBy: { _count: { password: "desc" } },
      take: 10,
    }),

    prisma.event.groupBy({
      by: ["command"],
      where: {
        command: { not: null },
        eventType: "COMMAND",
        createdAt: { gte: since24h },
      },
      _count: true,
      orderBy: { _count: { command: "desc" } },
      take: 10,
    }),

    prisma.session.findMany({
      where: { startedAt: { gte: since24h } },
      orderBy: { startedAt: "desc" },
      take: 20,
      include: {
        honeypot: { select: { name: true } },
        _count: { select: { events: true } },
      },
    }),
  ]);

  // Build time series: connections per minute for last 60 minutes
  const since60m = subMinutes(new Date(), 60);
  const timeSeries = await prisma.session.findMany({
    where: { startedAt: { gte: since60m } },
    select: { startedAt: true },
    orderBy: { startedAt: "asc" },
  });

  const buckets = new Map<string, number>();
  for (let i = 59; i >= 0; i--) {
    const bucket = startOfMinute(subMinutes(new Date(), i));
    buckets.set(bucket.toISOString(), 0);
  }

  for (const { startedAt } of timeSeries) {
    const key = startOfMinute(startedAt).toISOString();
    if (buckets.has(key)) {
      buckets.set(key, (buckets.get(key) ?? 0) + 1);
    }
  }

  const connectionTimeSeries = Array.from(buckets.entries()).map(
    ([time, count]) => ({ time, count })
  );

  return NextResponse.json({
    activeHoneypots,
    totalConnections,
    uniqueIps: uniqueIps.length,
    riskBreakdown: Object.fromEntries(
      riskBreakdown.map((r) => [r.riskLevel, r._count])
    ),
    topUsernames: topUsernames.map((u) => ({
      username: u.username,
      count: u._count,
    })),
    topPasswords: topPasswords.map((p) => ({
      passwordHash: p.password,
      count: p._count,
    })),
    topCommands: topCommands.map((c) => ({
      command: c.command,
      count: c._count,
    })),
    recentSessions,
    connectionTimeSeries,
  });
}
