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
  const ms = 500 + Math.floor(Math.random() * 1000);
  return new Promise((r) => setTimeout(r, ms));
}

export async function POST(req: NextRequest) {
  const sourceIp = getSourceIp(req);
  const { allowed } = checkRateLimit(sourceIp);
  if (!allowed) {
    return NextResponse.json({ error: "Too Many Requests" }, { status: 429 });
  }

  const endpoint = req.nextUrl.searchParams.get("endpoint") ?? "login";
  const userAgent = req.headers.get("user-agent") ?? undefined;

  let username = "";
  let password = "";

  const contentType = req.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    const body = await req.json().catch(() => ({}));
    username = String(body.username ?? body.email ?? "");
    password = String(body.password ?? body.secret ?? "");
  } else {
    const form = await req.formData().catch(() => new FormData());
    username = String(form.get("username") ?? form.get("email") ?? form.get("log") ?? "");
    password = String(form.get("password") ?? form.get("pwd") ?? "");
  }

  const passwordHash = password ? createHash("sha256").update(password).digest("hex") : "";

  // Check for injection payloads in username/password fields
  const usernameCategory = detectPayloadCategory(username);
  const passwordCategory = detectPayloadCategory(password);
  const hasPayload = usernameCategory !== "NONE" || passwordCategory !== "NONE";
  const payloadCategory = usernameCategory !== "NONE" ? usernameCategory : passwordCategory;

  await captureHttpRequest({
    sourceIp,
    endpoint: `/trap/${endpoint}`,
    method: "POST",
    eventType: hasPayload ? "HTTP_PAYLOAD_ATTEMPT" : "HTTP_LOGIN_ATTEMPT",
    username: username || undefined,
    passwordHash: passwordHash || undefined,
    payload: hasPayload ? `${username}:${password}`.slice(0, 500) : undefined,
    payloadCategory: hasPayload ? payloadCategory : undefined,
    userAgent,
  });

  await randomDelay();

  // Redirect back to trap page with error flag
  const redirectUrl = new URL(`/trap/${endpoint}?error=1`, req.url);
  return NextResponse.redirect(redirectUrl, 302);
}
