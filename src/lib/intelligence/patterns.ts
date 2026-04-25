import { prisma } from "@/lib/db";
import { classifyCommand } from "./classifier";
import { normalizeCommand, normalizeHttpPayload } from "./normalize";
import type { Prisma, RiskLevel } from "@prisma/client";

const IP_CAP = 100;

function categoryToRiskLevel(category: string): RiskLevel {
  switch (category) {
    case "anti_forensics": return "CRITICAL";
    case "payload":        return "HIGH";
    case "persistence":    return "HIGH";
    case "CMD_INJECTION":  return "CRITICAL";
    case "SQLI":           return "HIGH";
    case "XSS":            return "HIGH";
    case "LFI":            return "HIGH";
    case "recon":          return "MEDIUM";
    case "fingerprint":    return "MEDIUM";
    default:               return "LOW";
  }
}

function addIp(seenIps: string[], ip: string): { updated: string[]; isNew: boolean } {
  if (seenIps.includes(ip)) return { updated: seenIps, isNew: false };
  if (seenIps.length >= IP_CAP) return { updated: seenIps, isNew: false };
  return { updated: [...seenIps, ip], isNew: true };
}

export async function updateCommandPattern(params: {
  command: string;
  sourceIp: string;
}): Promise<void> {
  const { command, sourceIp } = params;
  const normalized = normalizeCommand(command).slice(0, 500);
  const category = classifyCommand(command);
  const riskLevel = categoryToRiskLevel(category);

  const existing = await prisma.commandPattern.findUnique({
    where: { normalizedCommand: normalized },
  });

  if (existing) {
    const { updated, isNew } = addIp(existing.seenIpsJson as string[], sourceIp);
    await prisma.commandPattern.update({
      where: { id: existing.id },
      data: {
        count: { increment: 1 },
        ...(isNew ? { uniqueIps: { increment: 1 } } : {}),
        seenIpsJson: updated as Prisma.InputJsonValue,
        lastSeen: new Date(),
      },
    });
  } else {
    await prisma.commandPattern.create({
      data: {
        command: command.slice(0, 500),
        normalizedCommand: normalized,
        category,
        patternType: "COMMAND",
        riskLevel,
        count: 1,
        uniqueIps: 1,
        seenIpsJson: [sourceIp] as Prisma.InputJsonValue,
        firstSeen: new Date(),
        lastSeen: new Date(),
      },
    });
  }
}

export async function updateCredentialPattern(params: {
  username: string;
  passwordHash: string;
  sourceIp: string;
}): Promise<void> {
  const { username, passwordHash, sourceIp } = params;
  const key = `${username}:${passwordHash}`;

  const existing = await prisma.credentialPattern.findUnique({
    where: { usernamePasswordKey: key },
  });

  if (existing) {
    const { updated, isNew } = addIp(existing.seenIpsJson as string[], sourceIp);
    await prisma.credentialPattern.update({
      where: { id: existing.id },
      data: {
        count: { increment: 1 },
        ...(isNew ? { uniqueIps: { increment: 1 } } : {}),
        seenIpsJson: updated as Prisma.InputJsonValue,
        lastSeen: new Date(),
      },
    });
  } else {
    await prisma.credentialPattern.create({
      data: {
        username,
        passwordHash,
        usernamePasswordKey: key,
        count: 1,
        uniqueIps: 1,
        seenIpsJson: [sourceIp] as Prisma.InputJsonValue,
        firstSeen: new Date(),
        lastSeen: new Date(),
      },
    });
  }
}

export async function updateHttpPattern(params: {
  payload: string;
  payloadCategory: string;
  sourceIp: string;
}): Promise<void> {
  const { payload, payloadCategory, sourceIp } = params;
  const normalized = normalizeHttpPayload(payload);
  const riskLevel = categoryToRiskLevel(payloadCategory);

  const existing = await prisma.commandPattern.findUnique({
    where: { normalizedCommand: normalized },
  });

  if (existing) {
    const { updated, isNew } = addIp(existing.seenIpsJson as string[], sourceIp);
    await prisma.commandPattern.update({
      where: { id: existing.id },
      data: {
        count: { increment: 1 },
        ...(isNew ? { uniqueIps: { increment: 1 } } : {}),
        seenIpsJson: updated as Prisma.InputJsonValue,
        lastSeen: new Date(),
      },
    });
  } else {
    await prisma.commandPattern.create({
      data: {
        command: payload.slice(0, 500),
        normalizedCommand: normalized,
        category: payloadCategory,
        patternType: "HTTP_PAYLOAD",
        riskLevel,
        count: 1,
        uniqueIps: 1,
        seenIpsJson: [sourceIp] as Prisma.InputJsonValue,
        firstSeen: new Date(),
        lastSeen: new Date(),
      },
    });
  }
}
