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

const UPLOAD_PAGE = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>File Upload</title>
<style>
  body { margin: 0; background: #f5f5f5; font-family: system-ui, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
  .card { background: #fff; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); padding: 40px; width: 420px; }
  h2 { margin: 0 0 8px; color: #333; font-size: 20px; }
  p { color: #666; font-size: 14px; margin: 0 0 28px; }
  label { display: block; font-size: 13px; color: #333; margin-bottom: 6px; }
  input[type=file] { width: 100%; padding: 10px; border: 2px dashed #ccc; border-radius: 4px; background: #fafafa; cursor: pointer; box-sizing: border-box; margin-bottom: 20px; }
  textarea { width: 100%; padding: 10px 12px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; resize: vertical; box-sizing: border-box; margin-bottom: 20px; min-height: 80px; }
  button { width: 100%; padding: 11px; background: #0066cc; color: #fff; border: none; border-radius: 4px; font-size: 14px; font-weight: 500; cursor: pointer; }
  button:hover { background: #0052a3; }
</style>
</head>
<body>
<div class="card">
  <h2>Upload Document</h2>
  <p>Upload files to the secure document management system.</p>
  <form method="POST" enctype="multipart/form-data">
    <label>Select file</label>
    <input type="file" name="file" accept="*/*" />
    <label>Description (optional)</label>
    <textarea name="description" placeholder="File description..."></textarea>
    <button type="submit">Upload</button>
  </form>
</div>
</body>
</html>`;

export async function GET(req: NextRequest) {
  const sourceIp = getSourceIp(req);
  const userAgent = req.headers.get("user-agent") ?? undefined;

  await captureHttpRequest({
    sourceIp,
    endpoint: "/trap/upload",
    method: "GET",
    eventType: "HTTP_REQUEST",
    userAgent,
  }).catch(console.error);

  return new NextResponse(UPLOAD_PAGE, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

export async function POST(req: NextRequest) {
  const sourceIp = getSourceIp(req);
  const { allowed } = checkRateLimit(sourceIp);
  if (!allowed) {
    return NextResponse.json({ error: "Too Many Requests" }, { status: 429 });
  }

  const userAgent = req.headers.get("user-agent") ?? undefined;

  let fileName = "";
  let description = "";
  let fileContent = "";

  try {
    const form = await req.formData();
    const file = form.get("file");
    description = String(form.get("description") ?? "");

    if (file && typeof file !== "string") {
      fileName = file.name;
      const text = await file.text().catch(() => "");
      fileContent = text.slice(0, 1000);
    }
  } catch {
    // ignore parse errors
  }

  const payload = [fileName, description, fileContent].filter(Boolean).join(" | ").slice(0, 500);
  const payloadCategory = payload ? detectPayloadCategory(payload) : "NONE";
  const hasPayload = payloadCategory !== "NONE";

  await captureHttpRequest({
    sourceIp,
    endpoint: "/trap/upload",
    method: "POST",
    eventType: hasPayload ? "HTTP_PAYLOAD_ATTEMPT" : "HTTP_REQUEST",
    payload: hasPayload ? payload : undefined,
    payloadCategory: hasPayload ? payloadCategory : undefined,
    userAgent,
  }).catch(console.error);

  // Fake file hash to look convincing
  const fakeHash = createHash("sha256").update(fileName + Date.now()).digest("hex");

  return NextResponse.json({
    success: true,
    message: "File uploaded successfully.",
    fileId: fakeHash.slice(0, 16),
    status: "processing",
  });
}
