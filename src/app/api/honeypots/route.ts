import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/db";
import { validateAdminSecret } from "@/lib/auth";
import { HoneypotType, Prisma } from "@prisma/client";

const CreateSchema = z.object({
  name: z.string().min(1).max(100),
  type: z.nativeEnum(HoneypotType).default(HoneypotType.SSH),
  publicPort: z.number().int().min(1).max(65535),
  dockerService: z.string().optional(),
  configJson: z.record(z.unknown()).optional(),
});

export async function GET(req: NextRequest) {
  if (!validateAdminSecret(req)) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const honeypots = await prisma.honeypot.findMany({
    orderBy: { createdAt: "desc" },
    include: {
      _count: { select: { sessions: true } },
      sessions: {
        orderBy: { startedAt: "desc" },
        take: 1,
        select: { startedAt: true },
      },
    },
  });

  return NextResponse.json(honeypots);
}

export async function POST(req: NextRequest) {
  if (!validateAdminSecret(req)) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await req.json().catch(() => null);
  const parsed = CreateSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ error: parsed.error.flatten() }, { status: 400 });
  }

  const { name, type, publicPort, dockerService, configJson } = parsed.data;

  const existing = await prisma.honeypot.findUnique({ where: { publicPort } });
  if (existing) {
    return NextResponse.json({ error: "Port already in use" }, { status: 409 });
  }

  const honeypot = await prisma.honeypot.create({
    data: {
      name,
      type,
      publicPort,
      dockerService: dockerService ?? null,
      configJson: (configJson ?? {}) as Prisma.InputJsonValue,
    },
  });

  return NextResponse.json(honeypot, { status: 201 });
}
