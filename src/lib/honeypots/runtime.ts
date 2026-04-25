import { execFile } from "child_process";
import { promisify } from "util";
import { prisma } from "../db";
import { writeAuditLog } from "../audit";
import { HoneypotStatus } from "@prisma/client";

const execFileAsync = promisify(execFile);

// Strict service allowlist — no user input ever reaches the shell
const ALLOWED_SERVICES = ["cowrie", "http-honeypot", "iot-honeypot"] as const;
type AllowedService = (typeof ALLOWED_SERVICES)[number];

function isAllowedService(name: string): name is AllowedService {
  return (ALLOWED_SERVICES as readonly string[]).includes(name);
}

async function runCompose(args: string[]): Promise<string> {
  const { stdout, stderr } = await execFileAsync("docker", [
    "compose",
    "-f",
    "/app/docker-compose.yml",
    ...args,
  ]);
  return stdout + stderr;
}

async function updateStatus(id: string, status: HoneypotStatus) {
  await prisma.honeypot.update({ where: { id }, data: { status } });
}

export async function startHoneypot(id: string): Promise<void> {
  const hp = await prisma.honeypot.findUniqueOrThrow({ where: { id } });

  if (!hp.dockerService || !isAllowedService(hp.dockerService)) {
    throw new Error(`No allowed Docker service configured for honeypot ${id}`);
  }

  await runCompose(["up", "-d", "--no-recreate", hp.dockerService]);
  await updateStatus(id, HoneypotStatus.RUNNING);
  await writeAuditLog("HONEYPOT_START", { honeypotId: id, service: hp.dockerService }, id);
}

export async function stopHoneypot(id: string): Promise<void> {
  const hp = await prisma.honeypot.findUniqueOrThrow({ where: { id } });

  if (!hp.dockerService || !isAllowedService(hp.dockerService)) {
    throw new Error(`No allowed Docker service configured for honeypot ${id}`);
  }

  await runCompose(["stop", hp.dockerService]);
  await updateStatus(id, HoneypotStatus.STOPPED);
  await writeAuditLog("HONEYPOT_STOP", { honeypotId: id, service: hp.dockerService }, id);
}

export async function pauseHoneypot(id: string): Promise<void> {
  const hp = await prisma.honeypot.findUniqueOrThrow({ where: { id } });

  if (!hp.dockerService || !isAllowedService(hp.dockerService)) {
    throw new Error(`No allowed Docker service configured for honeypot ${id}`);
  }

  await runCompose(["pause", hp.dockerService]);
  await updateStatus(id, HoneypotStatus.PAUSED);
  await writeAuditLog("HONEYPOT_PAUSE", { honeypotId: id, service: hp.dockerService }, id);
}

export async function restartHoneypot(id: string): Promise<void> {
  const hp = await prisma.honeypot.findUniqueOrThrow({ where: { id } });

  if (!hp.dockerService || !isAllowedService(hp.dockerService)) {
    throw new Error(`No allowed Docker service configured for honeypot ${id}`);
  }

  await runCompose(["restart", hp.dockerService]);
  await updateStatus(id, HoneypotStatus.RUNNING);
  await writeAuditLog("HONEYPOT_RESTART", { honeypotId: id, service: hp.dockerService }, id);
}
