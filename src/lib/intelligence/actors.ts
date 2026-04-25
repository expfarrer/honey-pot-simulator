import { prisma } from "@/lib/db";
import type { Prisma, ActorType, RiskLevel } from "@prisma/client";

const RISK_SCORES: Record<RiskLevel, number> = {
  LOW: 10,
  MEDIUM: 30,
  HIGH: 60,
  CRITICAL: 100,
};

function deriveActorType(params: {
  totalSessions: number;
  commands: string[];
  topCommands: { command: string; count: number }[];
  httpRequestCount: number;
  httpPayloadCount: number;
}): ActorType {
  const { totalSessions, commands, httpRequestCount, httpPayloadCount } = params;

  const hasAdvancedIndicator = commands.some(
    (c) =>
      c.includes("/dev/tcp") ||
      c.includes("/dev/udp") ||
      c.includes("base64") ||
      c.includes("eval") ||
      c.match(/HISTFILE|HISTSIZE=0|unset.*HIST/) !== null ||
      c.includes("shred")
  );
  if (hasAdvancedIndicator) return "ADVANCED";

  if (httpPayloadCount >= 3) return "ADVANCED";

  if (totalSessions >= 2 && commands.length > 5) return "HUMAN";
  if (totalSessions >= 1 && commands.length > 3) return "HUMAN";

  if (httpRequestCount > 20 || totalSessions === 0) return "BOT";

  return "BOT";
}

function mergeTopList(
  existing: { command: string; count: number }[],
  newItems: string[],
  cap = 20
): { command: string; count: number }[] {
  const map = new Map(existing.map((e) => [e.command, e.count]));
  for (const item of newItems) {
    map.set(item, (map.get(item) ?? 0) + 1);
  }
  return [...map.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, cap)
    .map(([command, count]) => ({ command, count }));
}

export async function updateActorProfile(params: {
  sourceIp: string;
  actorType: ActorType;
  riskLevel: RiskLevel;
  commands: string[];
  usernames: string[];
  eventCount: number;
  isNewSession: boolean;
  httpRequest?: boolean;
  httpPayload?: boolean;
}): Promise<void> {
  const {
    sourceIp,
    riskLevel,
    commands,
    usernames,
    eventCount,
    isNewSession,
    httpRequest = false,
    httpPayload = false,
  } = params;
  const riskScore = RISK_SCORES[riskLevel];

  const existing = await prisma.actorProfile.findUnique({ where: { sourceIp } });

  if (existing) {
    const newTopCommands = mergeTopList(
      existing.topCommandsJson as { command: string; count: number }[],
      commands
    );
    const newTopUsernames = mergeTopList(
      existing.topUsernamesJson as { command: string; count: number }[],
      usernames
    );

    const allCommands = [
      ...((existing.topCommandsJson as { command: string; count: number }[]).map(
        (e) => e.command
      )),
      ...commands,
    ];

    const newHttpRequestCount = existing.httpRequestCount + (httpRequest ? 1 : 0);
    const newHttpPayloadCount = existing.httpPayloadCount + (httpPayload ? 1 : 0);

    const derivedType = deriveActorType({
      totalSessions: existing.totalSessions + (isNewSession ? 1 : 0),
      commands: allCommands,
      topCommands: newTopCommands,
      httpRequestCount: newHttpRequestCount,
      httpPayloadCount: newHttpPayloadCount,
    });

    await prisma.actorProfile.update({
      where: { id: existing.id },
      data: {
        actorType: derivedType,
        riskScore: Math.max(existing.riskScore, riskScore),
        totalSessions: isNewSession ? { increment: 1 } : undefined,
        totalEvents: { increment: eventCount },
        httpRequestCount: httpRequest ? { increment: 1 } : undefined,
        httpPayloadCount: httpPayload ? { increment: 1 } : undefined,
        lastSeen: new Date(),
        topCommandsJson: newTopCommands as Prisma.InputJsonValue,
        topUsernamesJson: newTopUsernames as Prisma.InputJsonValue,
      },
    });
  } else {
    const topCommands = mergeTopList([], commands);
    const topUsernames = mergeTopList([], usernames);
    const derivedType = deriveActorType({
      totalSessions: isNewSession ? 1 : 0,
      commands,
      topCommands,
      httpRequestCount: httpRequest ? 1 : 0,
      httpPayloadCount: httpPayload ? 1 : 0,
    });

    await prisma.actorProfile.create({
      data: {
        sourceIp,
        actorType: derivedType,
        riskScore,
        totalSessions: isNewSession ? 1 : 0,
        totalEvents: eventCount,
        httpRequestCount: httpRequest ? 1 : 0,
        httpPayloadCount: httpPayload ? 1 : 0,
        firstSeen: new Date(),
        lastSeen: new Date(),
        topCommandsJson: topCommands as Prisma.InputJsonValue,
        topUsernamesJson: topUsernames as Prisma.InputJsonValue,
      },
    });
  }
}
