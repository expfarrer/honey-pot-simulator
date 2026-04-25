import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/db";
import { validateIngestSecret } from "@/lib/auth";
import { scoreSession } from "@/lib/intelligence/scorer";
import { EventType, RiskLevel, ActorType } from "@prisma/client";

// Cowrie JSON log event shapes
const CowrieEventSchema = z.object({
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
}).passthrough();

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

  // Verify honeypot exists
  const honeypot = await prisma.honeypot.findUnique({ where: { id: honeypotId } });
  if (!honeypot) {
    return NextResponse.json({ error: "Honeypot not found" }, { status: 404 });
  }

  // Group events by cowrie session ID
  const sessionMap = new Map<string, typeof events>();
  for (const event of events) {
    const sid = event.session;
    if (!sessionMap.has(sid)) sessionMap.set(sid, []);
    sessionMap.get(sid)!.push(event);
  }

  let insertedSessions = 0;
  let insertedEvents = 0;

  for (const [sessionRef, sessionEvents] of sessionMap.entries()) {
    // Sort by timestamp
    sessionEvents.sort(
      (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    );

    const connectEvent = sessionEvents.find((e) =>
      e.eventid.includes("session.connect")
    );
    const disconnectEvent = sessionEvents.find((e) =>
      e.eventid.includes("session.closed")
    );

    const sourceIp = connectEvent?.src_ip ?? sessionEvents[0].src_ip;
    const startedAt = connectEvent
      ? new Date(connectEvent.timestamp)
      : new Date(sessionEvents[0].timestamp);
    const endedAt = disconnectEvent
      ? new Date(disconnectEvent.timestamp)
      : undefined;

    const commands = sessionEvents
      .filter((e) => e.eventid.includes("command.input") && e.input)
      .map((e) => e.input!);

    const loginAttempts = sessionEvents.filter(
      (e) =>
        e.eventid.includes("login.failed") || e.eventid.includes("login.success")
    ).length;

    const loginSuccess = sessionEvents.some((e) =>
      e.eventid.includes("login.success")
    );

    const durationSeconds = endedAt
      ? (endedAt.getTime() - startedAt.getTime()) / 1000
      : 0;

    const { riskLevel, actorType } = scoreSession({
      commands,
      loginAttempts,
      loginSuccess,
      sessionDurationSeconds: durationSeconds,
    });

    // Upsert session by sessionRef
    const session = await prisma.session.upsert({
      where: { sessionRef: sessionRef },
      update: {
        endedAt: endedAt ?? undefined,
        riskLevel,
        actorType,
      },
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

    insertedSessions++;

    // Insert events (skip duplicates by checking existing)
    for (const ev of sessionEvents) {
      const eventType = mapCowrieEventType(ev.eventid);

      // Do not store plaintext passwords — hash them
      let hashedPassword: string | null = null;
      if (ev.password) {
        const { createHash } = await import("crypto");
        hashedPassword = createHash("sha256").update(ev.password).digest("hex");
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
  }

  return NextResponse.json({
    ok: true,
    insertedSessions,
    insertedEvents,
  });
}
