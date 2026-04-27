#!/usr/bin/env node
/**
 * cowrie-forward — tails cowrie/logs/cowrie.json and posts session batches
 * to the SetTrap ingest endpoint.
 *
 * Usage:
 *   node scripts/cowrie-forward.mjs <honeypotId>
 *
 * The honeypotId is printed when you run npm run seed:intelligence.
 * It can also be found in the admin dashboard URL for the SSH honeypot.
 */

import { createReadStream, statSync, existsSync } from "fs";
import { createInterface } from "readline";

const HONEYPOT_ID = process.argv[2];
if (!HONEYPOT_ID) {
  console.error("Usage: node scripts/cowrie-forward.mjs <honeypotId>");
  process.exit(1);
}

const INGEST_URL = process.env.INGEST_URL ?? "http://localhost:3000/api/ingest/cowrie";
const INGEST_SECRET = process.env.INGEST_SECRET ?? "change-me-ingest-secret";
const LOG_FILE = "./cowrie/logs/cowrie.json";
const POLL_MS = 2000;
const FLUSH_MS = 4000; // wait this long after last event before sending a session batch

let fileOffset = 0;
const pendingSessions = new Map(); // sessionId → { events[], flushTimer }

async function postBatch(events) {
  if (events.length === 0) return;
  try {
    const res = await fetch(INGEST_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-ingest-secret": INGEST_SECRET,
      },
      body: JSON.stringify({ honeypotId: HONEYPOT_ID, events }),
    });
    const body = await res.json().catch(() => ({}));
    if (res.ok) {
      console.log(`[ingest] ok — sessions:${body.insertedSessions ?? "?"} events:${body.insertedEvents ?? "?"}`);
    } else {
      console.error(`[ingest] ${res.status}`, body);
    }
  } catch (err) {
    console.error("[ingest] request failed:", err.message);
  }
}

function scheduleFlush(sessionId) {
  const entry = pendingSessions.get(sessionId);
  if (!entry) return;
  if (entry.flushTimer) clearTimeout(entry.flushTimer);
  entry.flushTimer = setTimeout(async () => {
    const e = entry.events;
    pendingSessions.delete(sessionId);
    await postBatch(e);
  }, FLUSH_MS);
}

function ingestLine(line) {
  const trimmed = line.trim();
  if (!trimmed) return;
  let event;
  try {
    event = JSON.parse(trimmed);
  } catch {
    return; // not JSON
  }
  if (!event.session || !event.eventid) return;

  const sid = event.session;
  if (!pendingSessions.has(sid)) {
    pendingSessions.set(sid, { events: [], flushTimer: null });
  }
  pendingSessions.get(sid).events.push(event);

  // Flush immediately on disconnect
  if (event.eventid.includes("session.closed")) {
    scheduleFlush(sid);
  } else {
    scheduleFlush(sid);
  }
}

async function readNewLines() {
  if (!existsSync(LOG_FILE)) return;
  const { size } = statSync(LOG_FILE);
  if (size <= fileOffset) return;

  await new Promise((resolve) => {
    const stream = createReadStream(LOG_FILE, {
      start: fileOffset,
      end: size - 1,
      encoding: "utf8",
    });
    const rl = createInterface({ input: stream });
    rl.on("line", ingestLine);
    rl.on("close", resolve);
  });

  fileOffset = size;
}

// Skip lines already in the file at startup (replay from now on only)
async function init() {
  if (existsSync(LOG_FILE)) {
    fileOffset = statSync(LOG_FILE).size;
    console.log(`[forward] starting — skipping ${fileOffset} existing bytes in ${LOG_FILE}`);
  } else {
    console.log(`[forward] ${LOG_FILE} not found yet — will watch for it`);
  }
}

console.log(`[forward] honeypotId=${HONEYPOT_ID}`);
console.log(`[forward] ingest=${INGEST_URL}`);
console.log(`[forward] polling every ${POLL_MS}ms, flush after ${FLUSH_MS}ms idle`);

await init();
setInterval(readNewLines, POLL_MS);
