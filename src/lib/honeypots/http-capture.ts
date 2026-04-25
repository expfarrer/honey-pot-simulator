import { prisma } from "@/lib/db";
import type { EventType, RiskLevel, Prisma } from "@prisma/client";
import { updateHttpPattern, updateCredentialPattern } from "@/lib/intelligence/patterns";
import { updateActorProfile } from "@/lib/intelligence/actors";
import { detectHttpChains } from "@/lib/intelligence/chains";

let cachedHoneypotId: string | null = null;

async function getHttpHoneypotId(): Promise<string> {
  if (cachedHoneypotId) return cachedHoneypotId;

  const existing = await prisma.honeypot.findFirst({ where: { type: "HTTP" } });
  if (existing) {
    cachedHoneypotId = existing.id;
    return existing.id;
  }

  const created = await prisma.honeypot.create({
    data: {
      name: "HTTP Trap",
      type: "HTTP",
      status: "RUNNING",
      publicPort: 8080,
      configJson: {
        paths: ["/trap/login", "/trap/admin", "/trap/wp-admin", "/trap/api/auth", "/trap/upload"],
      },
    },
  });
  cachedHoneypotId = created.id;
  return created.id;
}

export interface HttpCaptureParams {
  sourceIp: string;
  endpoint: string;
  method: string;
  eventType: EventType;
  username?: string;
  passwordHash?: string;
  payload?: string;
  payloadCategory?: string;
  userAgent?: string;
}

export async function captureHttpRequest(params: HttpCaptureParams): Promise<void> {
  const {
    sourceIp,
    endpoint,
    method,
    eventType,
    username,
    passwordHash,
    payload,
    payloadCategory,
    userAgent,
  } = params;

  const honeypotId = await getHttpHoneypotId();

  // Group HTTP requests from the same IP into hourly sessions
  const hourBucket = Math.floor(Date.now() / 3_600_000);
  const sessionRef = `http:${honeypotId}:${sourceIp}:${hourBucket}`;

  const hasPayload = !!(payload && payloadCategory && payloadCategory !== "NONE");
  const sessionRisk: RiskLevel = hasPayload ? "HIGH" : eventType === "HTTP_LOGIN_ATTEMPT" ? "MEDIUM" : "LOW";

  const session = await prisma.session.upsert({
    where: { sessionRef },
    update: {
      endedAt: new Date(),
      riskLevel: sessionRisk,
    },
    create: {
      honeypotId,
      sourceIp,
      startedAt: new Date(),
      endedAt: new Date(),
      riskLevel: sessionRisk,
      actorType: "UNKNOWN",
      sessionRef,
    },
  });

  await prisma.event.create({
    data: {
      sessionId: session.id,
      eventType,
      command: hasPayload ? (payload ?? endpoint).slice(0, 500) : endpoint,
      username: username ?? null,
      password: passwordHash ?? null,
      rawJson: {
        endpoint,
        method,
        userAgent: userAgent ?? null,
        payloadCategory: payloadCategory ?? null,
      } as Prisma.InputJsonValue,
      createdAt: new Date(),
    },
  });

  const tasks: Promise<void>[] = [];

  if (hasPayload) {
    tasks.push(updateHttpPattern({ payload: payload!, payloadCategory: payloadCategory!, sourceIp }));
  }

  if (username && passwordHash) {
    tasks.push(updateCredentialPattern({ username, passwordHash, sourceIp }));
  }

  tasks.push(
    updateActorProfile({
      sourceIp,
      actorType: "UNKNOWN",
      riskLevel: sessionRisk,
      commands: [],
      usernames: username ? [username] : [],
      eventCount: 1,
      isNewSession: false,
      httpRequest: true,
      httpPayload: hasPayload,
    })
  );

  tasks.push(detectHttpChains({ sessionId: session.id, honeypotId }));

  const results = await Promise.allSettled(tasks);
  for (const r of results) {
    if (r.status === "rejected") {
      console.error("[http-capture] intelligence task failed:", r.reason);
    }
  }
}
