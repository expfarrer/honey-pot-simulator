import { prisma } from "@/lib/db";
import type { Prisma, ChainType, RiskLevel } from "@prisma/client";

interface ChainStep {
  order: number;
  command: string;
  category: string;
}

interface DetectedChain {
  chainType: ChainType;
  severity: RiskLevel;
  steps: ChainStep[];
  confidence: number;
}

const DOWNLOAD_RE = /\b(wget|curl|tftp|fetch)\b/;
const CHMOD_RE = /\bchmod\b/;
const EXECUTE_RE = /^\.\//;
const IOT_SHELL_RE = /^(enable|system|shell)\b/;
const FINGERPRINT_RE = /^(uname|whoami|id|hostname|ifconfig|ip\s|cat\s+\/etc\/(os-release|issue|passwd))/;
const PERSISTENCE_RE = /\.ssh\/authorized_keys|crontab|chattr|\/etc\/rc\.local|systemctl\s+enable|useradd|adduser/;
const ANTI_FORENSICS_RE = /HISTFILE|HISTSIZE=0|HISTFILESIZE=0|unset\s+HIST|history\s+-c|rm\s+.*bash_history|shred|>\s*\/var\/log/;

function detectFingerprintChain(
  commands: string[],
  hasLoginSuccess: boolean
): DetectedChain | null {
  const steps: ChainStep[] = [];
  commands.forEach((cmd, i) => {
    if (FINGERPRINT_RE.test(cmd.toLowerCase())) {
      steps.push({ order: i, command: cmd, category: "fingerprint" });
    }
  });
  if (steps.length < 2) return null;
  return {
    chainType: "FINGERPRINT",
    severity: hasLoginSuccess ? "MEDIUM" : "LOW",
    steps,
    confidence: hasLoginSuccess ? 65 : 45,
  };
}

function detectPayloadChain(commands: string[]): DetectedChain | null {
  const steps: ChainStep[] = [];
  let hasDownload = false;
  let hasChmod = false;
  let hasExecute = false;

  commands.forEach((cmd, i) => {
    if (DOWNLOAD_RE.test(cmd)) {
      hasDownload = true;
      steps.push({ order: i, command: cmd, category: "download" });
    } else if (CHMOD_RE.test(cmd.toLowerCase())) {
      hasChmod = true;
      steps.push({ order: i, command: cmd, category: "chmod" });
    } else if (EXECUTE_RE.test(cmd.trim())) {
      hasExecute = true;
      steps.push({ order: i, command: cmd, category: "execute" });
    }
  });

  if (!hasDownload) return null;

  let confidence = 50;
  let severity: RiskLevel = "HIGH";
  if (hasChmod) confidence = 75;
  if (hasChmod && hasExecute) {
    confidence = 95;
    severity = "CRITICAL";
  }

  return { chainType: "PAYLOAD_EXECUTION", severity, steps, confidence };
}

function detectPersistenceChain(commands: string[]): DetectedChain | null {
  const steps: ChainStep[] = [];
  commands.forEach((cmd, i) => {
    if (PERSISTENCE_RE.test(cmd.toLowerCase())) {
      steps.push({ order: i, command: cmd, category: "persistence" });
    }
  });
  if (steps.length === 0) return null;
  return {
    chainType: "PERSISTENCE",
    severity: "HIGH",
    steps,
    confidence: steps.length >= 2 ? 90 : 70,
  };
}

function detectAntiForensicsChain(commands: string[]): DetectedChain | null {
  const steps: ChainStep[] = [];
  commands.forEach((cmd, i) => {
    if (ANTI_FORENSICS_RE.test(cmd)) {
      steps.push({ order: i, command: cmd, category: "anti_forensics" });
    }
  });
  if (steps.length === 0) return null;
  return {
    chainType: "ANTI_FORENSICS",
    severity: steps.length >= 2 ? "CRITICAL" : "HIGH",
    steps,
    confidence: 85,
  };
}

function detectIotBotChain(commands: string[]): DetectedChain | null {
  const steps: ChainStep[] = [];
  let hasIotCmd = false;
  let hasDownload = false;

  commands.forEach((cmd, i) => {
    if (IOT_SHELL_RE.test(cmd.trim().toLowerCase())) {
      hasIotCmd = true;
      steps.push({ order: i, command: cmd, category: "iot_shell" });
    } else if (DOWNLOAD_RE.test(cmd)) {
      hasDownload = true;
      steps.push({ order: i, command: cmd, category: "download" });
    }
  });

  if (!hasDownload) return null;
  return {
    chainType: "IOT_BOT",
    severity: hasIotCmd ? "HIGH" : "MEDIUM",
    steps,
    confidence: hasIotCmd ? 80 : 55,
  };
}

export async function detectAttackChains(params: {
  sessionId: string;
  honeypotId: string;
  commands: string[];
  hasLoginSuccess: boolean;
}): Promise<void> {
  const { sessionId, honeypotId, commands, hasLoginSuccess } = params;
  if (commands.length === 0) return;

  const detectors = [
    detectFingerprintChain(commands, hasLoginSuccess),
    detectPayloadChain(commands),
    detectPersistenceChain(commands),
    detectAntiForensicsChain(commands),
    detectIotBotChain(commands),
  ];

  for (const chain of detectors) {
    if (!chain) continue;
    await prisma.attackChain.upsert({
      where: { sessionId_chainType: { sessionId, chainType: chain.chainType } },
      update: {
        severity: chain.severity,
        stepsJson: chain.steps as unknown as Prisma.InputJsonValue,
        confidence: chain.confidence,
      },
      create: {
        sessionId,
        honeypotId,
        chainType: chain.chainType,
        severity: chain.severity,
        stepsJson: chain.steps as unknown as Prisma.InputJsonValue,
        confidence: chain.confidence,
      },
    });
  }
}

export async function detectHttpChains(params: {
  sessionId: string;
  honeypotId: string;
}): Promise<void> {
  const { sessionId, honeypotId } = params;

  const events = await prisma.event.findMany({
    where: { sessionId },
    orderBy: { createdAt: "asc" },
  });

  if (events.length === 0) return;

  const loginAttempts = events.filter((e) => e.eventType === "HTTP_LOGIN_ATTEMPT");
  const payloadAttempts = events.filter((e) => e.eventType === "HTTP_PAYLOAD_ATTEMPT");
  const httpRequests = events.filter(
    (e) => e.eventType === "HTTP_REQUEST" || e.eventType === "HTTP_LOGIN_ATTEMPT" || e.eventType === "HTTP_PAYLOAD_ATTEMPT"
  );

  const chains: DetectedChain[] = [];

  // AUTH_BRUTE_FORCE: 5+ login attempts in the same session
  if (loginAttempts.length >= 5) {
    chains.push({
      chainType: "AUTH_BRUTE_FORCE",
      severity: loginAttempts.length >= 20 ? "CRITICAL" : "HIGH",
      steps: loginAttempts.slice(0, 20).map((e, i) => ({
        order: i,
        command: e.username ?? "unknown",
        category: "login_attempt",
      })),
      confidence: Math.min(95, 60 + loginAttempts.length * 2),
    });
  }

  // WEB_EXPLOIT: any payload attempts detected
  if (payloadAttempts.length >= 1) {
    const categories = payloadAttempts
      .map((e) => (e.rawJson as Record<string, unknown>).payloadCategory as string)
      .filter(Boolean);
    const uniqueCats = [...new Set(categories)];
    chains.push({
      chainType: "WEB_EXPLOIT",
      severity: payloadAttempts.length >= 3 || uniqueCats.length >= 2 ? "CRITICAL" : "HIGH",
      steps: payloadAttempts.slice(0, 20).map((e, i) => ({
        order: i,
        command: (e.command ?? "").slice(0, 120),
        category: ((e.rawJson as Record<string, unknown>).payloadCategory as string) ?? "unknown",
      })),
      confidence: Math.min(95, 70 + payloadAttempts.length * 5),
    });
  }

  // SCAN: 10+ distinct endpoints visited in the same session
  const endpoints = new Set(
    httpRequests.map((e) => {
      const raw = e.rawJson as Record<string, unknown>;
      return (raw.endpoint as string) ?? e.command ?? "";
    })
  );
  if (endpoints.size >= 10) {
    chains.push({
      chainType: "SCAN",
      severity: "MEDIUM",
      steps: [...endpoints].slice(0, 20).map((ep, i) => ({
        order: i,
        command: ep,
        category: "scan",
      })),
      confidence: Math.min(90, 50 + endpoints.size * 2),
    });
  }

  for (const chain of chains) {
    await prisma.attackChain.upsert({
      where: { sessionId_chainType: { sessionId, chainType: chain.chainType } },
      update: {
        severity: chain.severity,
        stepsJson: chain.steps as unknown as Prisma.InputJsonValue,
        confidence: chain.confidence,
      },
      create: {
        sessionId,
        honeypotId,
        chainType: chain.chainType,
        severity: chain.severity,
        stepsJson: chain.steps as unknown as Prisma.InputJsonValue,
        confidence: chain.confidence,
      },
    });
  }
}
