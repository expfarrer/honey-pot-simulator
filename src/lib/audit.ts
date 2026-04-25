import { prisma } from "./db";
import type { Prisma } from "@prisma/client";

export async function writeAuditLog(
  action: string,
  details: Record<string, unknown>,
  honeypotId?: string,
  actorIp?: string
): Promise<void> {
  await prisma.auditLog.create({
    data: {
      action,
      details: details as Prisma.InputJsonValue,
      honeypotId: honeypotId ?? null,
      actorIp: actorIp ?? null,
    },
  });
}
