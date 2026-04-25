import { NextRequest, NextResponse } from "next/server";
import { createHash } from "crypto";
import { captureHttpRequest } from "@/lib/honeypots/http-capture";
import { detectPayloadCategory } from "@/lib/intelligence/payloads";
import { checkRateLimit } from "@/lib/rate-limit";

function getSourceIp(req: NextRequest): string {
  return (
    req.headers.get("x-forwarded-for")?.split(",")[0].trim() ??
    req.headers.get("x-real-ip") ??
    "unknown"
  );
}

function randomDelay(): Promise<void> {
  const ms = 300 + Math.floor(Math.random() * 700);
  return new Promise((r) => setTimeout(r, ms));
}

export async function GET(req: NextRequest) {
  const sourceIp = getSourceIp(req);
  const userAgent = req.headers.get("user-agent") ?? undefined;

  await captureHttpRequest({
    sourceIp,
    endpoint: "/trap/api/auth",
    method: "GET",
    eventType: "HTTP_REQUEST",
    userAgent,
  }).catch(console.error);

  const nonce = createHash("sha256")
    .update(`${sourceIp}:${Date.now()}`)
    .digest("hex")
    .slice(0, 32);

  return NextResponse.json({
    realm: "api.corpnet.internal",
    algorithm: "sha256",
    nonce,
    expires: Math.floor(Date.now() / 1000) + 300,
    required: ["username", "password"],
  });
}

export async function POST(req: NextRequest) {
  const sourceIp = getSourceIp(req);
  const { allowed } = checkRateLimit(sourceIp);
  if (!allowed) {
    return NextResponse.json({ error: "Too Many Requests" }, { status: 429 });
  }

  const userAgent = req.headers.get("user-agent") ?? undefined;

  let username = "";
  let password = "";
  let token = "";
  let rawBody = "";

  try {
    const body = await req.json();
    username = String(body.username ?? body.user ?? "");
    password = String(body.password ?? body.secret ?? body.key ?? "");
    token = String(body.token ?? body.api_key ?? body.apiKey ?? "");
    rawBody = JSON.stringify(body).slice(0, 500);
  } catch {
    try {
      rawBody = await req.text();
      rawBody = rawBody.slice(0, 500);
    } catch {
      // ignore
    }
  }

  const credential = password || token;
  const passwordHash = credential
    ? createHash("sha256").update(credential).digest("hex")
    : "";

  const payloadToCheck = rawBody || username;
  const payloadCategory = detectPayloadCategory(payloadToCheck);
  const hasPayload = payloadCategory !== "NONE";

  await captureHttpRequest({
    sourceIp,
    endpoint: "/trap/api/auth",
    method: "POST",
    eventType: hasPayload ? "HTTP_PAYLOAD_ATTEMPT" : "HTTP_LOGIN_ATTEMPT",
    username: username || undefined,
    passwordHash: passwordHash || undefined,
    payload: hasPayload ? payloadToCheck : undefined,
    payloadCategory: hasPayload ? payloadCategory : undefined,
    userAgent,
  }).catch(console.error);

  await randomDelay();

  return NextResponse.json(
    {
      error: "Unauthorized",
      message: "Invalid credentials or expired nonce.",
      code: 401,
    },
    { status: 401 }
  );
}
