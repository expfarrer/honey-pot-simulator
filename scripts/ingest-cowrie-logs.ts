#!/usr/bin/env tsx
/**
 * Polling-based Cowrie log ingestion script.
 * Use this when Cowrie's HTTP output plugin is unavailable.
 * Run on the same host as cowrie logs:
 *   HONEYPOT_ID=xxx APP_URL=http://localhost:3000 npx tsx scripts/ingest-cowrie-logs.ts /path/to/cowrie.json
 */

import * as fs from "fs";
import * as readline from "readline";

const LOG_FILE = process.argv[2];
const HONEYPOT_ID = process.env.HONEYPOT_ID;
const APP_URL = process.env.APP_URL ?? "http://localhost:3000";
const INGEST_SECRET = process.env.INGEST_SECRET ?? "";
const POLL_MS = 5000;

if (!LOG_FILE || !HONEYPOT_ID) {
  console.error("Usage: HONEYPOT_ID=xxx tsx scripts/ingest-cowrie-logs.ts <log-file>");
  process.exit(1);
}

let lastSize = 0;

async function readNewLines(): Promise<string[]> {
  const stat = fs.statSync(LOG_FILE);
  if (stat.size <= lastSize) return [];

  const stream = fs.createReadStream(LOG_FILE, {
    start: lastSize,
    end: stat.size - 1,
    encoding: "utf8",
  });

  const lines: string[] = [];
  const rl = readline.createInterface({ input: stream });
  for await (const line of rl) {
    const trimmed = line.trim();
    if (trimmed) lines.push(trimmed);
  }

  lastSize = stat.size;
  return lines;
}

async function ingest(lines: string[]) {
  const events = lines.flatMap((line) => {
    try { return [JSON.parse(line)]; }
    catch { return []; }
  });

  if (events.length === 0) return;

  const res = await fetch(`${APP_URL}/api/ingest/cowrie`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(INGEST_SECRET ? { "x-ingest-secret": INGEST_SECRET } : {}),
    },
    body: JSON.stringify({ honeypotId: HONEYPOT_ID, events }),
  });

  if (!res.ok) {
    console.error("Ingest failed:", res.status, await res.text());
  } else {
    const data = await res.json();
    console.log(`Ingested ${data.insertedEvents} events in ${data.insertedSessions} sessions`);
  }
}

async function poll() {
  try {
    const lines = await readNewLines();
    if (lines.length > 0) await ingest(lines);
  } catch (err) {
    console.error("Poll error:", err);
  }
}

console.log(`Watching ${LOG_FILE} for honeypot ${HONEYPOT_ID}`);
setInterval(poll, POLL_MS);
poll();
