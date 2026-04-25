import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/db";
import { validateIngestSecret } from "@/lib/auth";
import { scoreSession } from "@/lib/intelligence/scorer";
import { updateCommandPattern, updateCredentialPattern } from "@/lib/intelligence/patterns";
import { updateActorProfile } from "@/lib/intelligence/actors";
import { detectAttackChains } from "@/lib/intelligence/chains";
import { EventType } from "@prisma/client";

const CowrieEventSchema = z
  .object({
    eventid: z.string(),
    timestamp: z.string(),
    session: z.string(),
    src_ip: z.string(),
    src_port: z.number().optional(),
    username: z.string().optional(),
    password: z.string().optional(),
    input: z.string().optional(),
    message: z.string().optional(),
    sensor: z.string().optional(),
  })
  .passthrough();

const IngestBodySchema = z.object({
  honeypotId: z.string(),
  events: z.array(CowrieEventSchema),
});

function mapCowrieEventType(eventid: string): EventType {
  if (eventid.includes("cowrie.session.connect")) return EventType.CONNECTION;
  if (eventid.includes("cowrie.login.success")) return EventType.LOGIN_SUCCESS;
  if (eventid.includes("cowrie.login.failed")) return EventType.LOGIN_FAILED;
  if (eventid.includes("cowrie.command.input")) return EventType.COMMAND;
  if (eventid.includes("cowrie.session.file_upload")) return EventType.FILE_UPLOAD;
  if (eventid.includes("cowrie.session.file_download")) return EventType.FILE_DOWNLOAD;
  if (eventid.includes("cowrie.session.closed")) return EventType.DISCONNECT;
  if (eventid.includes("cowrie.direct-tcpip")) return EventType.PORT_FORWARD;
  return EventType.CONNECTION;
}

async function runIntelligence(params: {
  sessionId: string;
  honeypotId: string;
  sourceIp: string;
  commands: string[];
  usernames: string[];
  passwordHashes: Map<string, string>;
  actorType: import("@prisma/client").ActorType;
  riskLevel: import("@prisma/client").RiskLevel;
  eventCount: number;
  isNewSession: boolean;
  hasLoginSuccess: boolean;
}): Promise<void> {
  const {
    sessionId,
    honeypotId,
    sourceIp,
    commands,
    usernames,
    passwordHashes,
    actorType,
    riskLevel,
    eventCount,
    isNewSession,
    hasLoginSuccess,
  } = params;

  const tasks: Promise<void>[] = [];

  for (const cmd of commands) {
    tasks.push(updateCommandPattern({ command: cmd, sourceIp }));
  }

  for (const username of usernames) {
    const hash = passwordHashes.get(username);
    if (hash) {
      tasks.push(updateCredentialPattern({ username, passwordHash: hash, sourceIp }));
    }
  }

  tasks.push(
    updateActorProfile({
      sourceIp,
      actorType,
      riskLevel,
      commands,
      usernames,
      eventCount,
      isNewSession,
    })
  );

  tasks.push(
    detectAttackChains({ sessionId, honeypotId, commands, hasLoginSuccess })
  );

  const results = await Promise.allSettled(tasks);
  for (const r of results) {
    if (r.status === "rejected") {
      console.error("[intelligence] task failed:", r.reason);
    }
  }
}

export async function POST(req: NextRequest) {
  if (!validateIngestSecret(req)) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await req.json().catch(() => null);
  const parsed = IngestBodySchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ error: parsed.error.flatten() }, { status: 400 });
  }

  const { honeypotId, events } = parsed.data;

  const honeypot = await prisma.honeypot.findUnique({ where: { id: honeypotId } });
  if (!honeypot) {
    return NextResponse.json({ error: "Honeypot not found" }, { status: 404 });
  }

  const sessionMap = new Map<string, typeof events>();
  for (const event of events) {
    if (!sessionMap.has(event.session)) sessionMap.set(event.session, []);
    sessionMap.get(event.session)!.push(event);
  }

  let insertedSessions = 0;
  let insertedEvents = 0;

  for (const [sessionRef, sessionEvents] of sessionMap.entries()) {
    sessionEvents.sort(
      (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    );

    const connectEvent = sessionEvents.find((e) => e.eventid.includes("session.connect"));
    const disconnectEvent = sessionEvents.find((e) => e.eventid.includes("session.closed"));

    const sourceIp = connectEvent?.src_ip ?? sessionEvents[0].src_ip;
    const startedAt = connectEvent
      ? new Date(connectEvent.timestamp)
      : new Date(sessionEvents[0].timestamp);
    const endedAt = disconnectEvent ? new Date(disconnectEvent.timestamp) : undefined;

    const commands = sessionEvents
      .filter((e) => e.eventid.includes("command.input") && e.input)
      .map((e) => e.input!);

    const loginAttempts = sessionEvents.filter(
      (e) => e.eventid.includes("login.failed") || e.eventid.includes("login.success")
    ).length;

    const hasLoginSuccess = sessionEvents.some((e) => e.eventid.includes("login.success"));
    const durationSeconds = endedAt ? (endedAt.getTime() - startedAt.getTime()) / 1000 : 0;

    const { riskLevel, actorType } = scoreSession({
      commands,
      loginAttempts,
      loginSuccess: hasLoginSuccess,
      sessionDurationSeconds: durationSeconds,
    });

    // Upsert session
    const existingSession = await prisma.session.findUnique({ where: { sessionRef } });
    const session = await prisma.session.upsert({
      where: { sessionRef },
      update: { endedAt: endedAt ?? undefined, riskLevel, actorType },
      create: {
        honeypotId,
        sourceIp,
        sourcePort: connectEvent?.src_port ?? null,
        startedAt,
        endedAt: endedAt ?? null,
        riskLevel,
        actorType,
        sessionRef,
      },
    });
    const isNewSession = !existingSession;
    insertedSessions++;

    // Build password hash map (username → hash)
    const { createHash } = await import("crypto");
    const passwordHashes = new Map<string, string>();
    const usernames: string[] = [];

    for (const ev of sessionEvents) {
      const eventType = mapCowrieEventType(ev.eventid);

      let hashedPassword: string | null = null;
      if (ev.password) {
        hashedPassword = createHash("sha256").update(ev.password).digest("hex");
        if (ev.username) {
          passwordHashes.set(ev.username, hashedPassword);
          if (!usernames.includes(ev.username)) usernames.push(ev.username);
        }
      } else if (ev.username && !usernames.includes(ev.username)) {
        usernames.push(ev.username);
      }

      await prisma.event.create({
        data: {
          sessionId: session.id,
          eventType,
          command: ev.input ?? null,
          username: ev.username ?? null,
          password: hashedPassword,
          rawJson: ev as object,
          createdAt: new Date(ev.timestamp),
        },
      });
      insertedEvents++;
    }

    // Run intelligence processing — failures must not break ingestion
    try {
      await runIntelligence({
        sessionId: session.id,
        honeypotId,
        sourceIp,
        commands,
        usernames,
        passwordHashes,
        actorType,
        riskLevel,
        eventCount: sessionEvents.length,
        isNewSession,
        hasLoginSuccess,
      });
    } catch (err) {
      console.error("[ingest] intelligence processing failed for session", sessionRef, err);
    }
  }

  return NextResponse.json({ ok: true, insertedSessions, insertedEvents });
}
