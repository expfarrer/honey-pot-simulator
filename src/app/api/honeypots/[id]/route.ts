import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/db";
import { validateAdminSecret } from "@/lib/auth";
import { HoneypotStatus, Prisma } from "@prisma/client";

const PatchSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  publicPort: z.number().int().min(1).max(65535).optional(),
  configJson: z.record(z.unknown()).optional(),
  status: z.nativeEnum(HoneypotStatus).optional(),
});

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  if (!validateAdminSecret(req)) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id } = await params;

  const honeypot = await prisma.honeypot.findUnique({
    where: { id },
    include: {
      sessions: {
        orderBy: { startedAt: "desc" },
        take: 50,
        include: {
          _count: { select: { events: true } },
        },
      },
      _count: { select: { sessions: true } },
    },
  });

  if (!honeypot) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  return NextResponse.json(honeypot);
}

export async function PATCH(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  if (!validateAdminSecret(req)) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id } = await params;

  const body = await req.json().catch(() => null);
  const parsed = PatchSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ error: parsed.error.flatten() }, { status: 400 });
  }

  const { configJson, ...rest } = parsed.data;
  const honeypot = await prisma.honeypot.update({
    where: { id },
    data: {
      ...rest,
      ...(configJson !== undefined
        ? { configJson: configJson as Prisma.InputJsonValue }
        : {}),
    },
  });

  return NextResponse.json(honeypot);
}
