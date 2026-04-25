import { RiskLevel, ActorType } from "@prisma/client";
import { classifyCommand, CommandCategory } from "./classifier";

interface ScoringInput {
  commands: string[];
  loginAttempts: number;
  loginSuccess: boolean;
  sessionDurationSeconds: number;
}

interface ScoringResult {
  riskLevel: RiskLevel;
  actorType: ActorType;
  commandCategories: CommandCategory[];
  score: number;
}

const CATEGORY_WEIGHTS: Record<CommandCategory, number> = {
  fingerprint: 10,
  recon: 15,
  payload: 50,
  persistence: 40,
  anti_forensics: 60,
  unknown: 5,
};

export function scoreSession(input: ScoringInput): ScoringResult {
  const commandCategories = input.commands.map(classifyCommand);
  const hasPayload = commandCategories.includes("payload");
  const hasPersistence = commandCategories.includes("persistence");
  const hasAntiForensics = commandCategories.includes("anti_forensics");
  const hasFingerprint = commandCategories.includes("fingerprint");

  let score = 0;
  for (const cat of commandCategories) {
    score += CATEGORY_WEIGHTS[cat];
  }

  if (input.loginAttempts > 5) score += 20;
  if (input.loginSuccess) score += 15;

  const riskLevel = deriveRiskLevel({
    score,
    hasPayload,
    hasPersistence,
    hasAntiForensics,
    hasFingerprint,
    loginSuccess: input.loginSuccess,
    commandCount: input.commands.length,
  });

  const actorType = deriveActorType({
    commandCount: input.commands.length,
    sessionDurationSeconds: input.sessionDurationSeconds,
    hasPayload,
    hasAntiForensics,
    hasPersistence,
    commands: input.commands,
  });

  return { riskLevel, actorType, commandCategories, score };
}

function deriveRiskLevel(params: {
  score: number;
  hasPayload: boolean;
  hasPersistence: boolean;
  hasAntiForensics: boolean;
  hasFingerprint: boolean;
  loginSuccess: boolean;
  commandCount: number;
}): RiskLevel {
  // Multi-step attack chain
  if (
    params.hasPayload &&
    (params.hasPersistence || params.hasAntiForensics)
  ) {
    return RiskLevel.CRITICAL;
  }

  if (params.hasPayload || params.hasAntiForensics) {
    return RiskLevel.HIGH;
  }

  if (
    params.loginSuccess &&
    (params.hasFingerprint || params.commandCount > 3)
  ) {
    return RiskLevel.MEDIUM;
  }

  return RiskLevel.LOW;
}

function deriveActorType(params: {
  commandCount: number;
  sessionDurationSeconds: number;
  hasPayload: boolean;
  hasAntiForensics: boolean;
  hasPersistence: boolean;
  commands: string[];
}): ActorType {
  // Obfuscation or /dev/tcp usage or multi-step — ADVANCED
  if (
    params.hasAntiForensics ||
    params.commands.some(
      (c) => c.includes("/dev/tcp") || c.includes("base64") || c.includes("eval")
    ) ||
    (params.hasPayload && params.hasPersistence)
  ) {
    return ActorType.ADVANCED;
  }

  // Multiple commands, slow session — likely HUMAN
  if (
    params.commandCount > 3 &&
    params.sessionDurationSeconds > 10
  ) {
    return ActorType.HUMAN;
  }

  // Single command or fast disconnect — BOT
  return ActorType.BOT;
}
