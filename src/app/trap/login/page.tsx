import { headers } from "next/headers";
import { captureHttpRequest } from "@/lib/honeypots/http-capture";

export const dynamic = "force-dynamic";

async function logVisit(sourceIp: string, userAgent: string) {
  await captureHttpRequest({
    sourceIp,
    endpoint: "/trap/login",
    method: "GET",
    eventType: "HTTP_REQUEST",
    userAgent,
  }).catch(() => {});
}

export default async function TrapLoginPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  const hdrs = await headers();
  const sourceIp =
    hdrs.get("x-forwarded-for")?.split(",")[0].trim() ??
    hdrs.get("x-real-ip") ??
    "unknown";
  const userAgent = hdrs.get("user-agent") ?? "";
  const { error } = await searchParams;

  await logVisit(sourceIp, userAgent);

  return (
    <div
      style={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: "#f0f2f5",
      }}
    >
      <div
        style={{
          background: "#fff",
          borderRadius: 8,
          boxShadow: "0 2px 12px rgba(0,0,0,0.12)",
          padding: "40px 48px",
          width: 360,
        }}
      >
        <div style={{ textAlign: "center", marginBottom: 32 }}>
          <div
            style={{
              width: 48,
              height: 48,
              background: "#1a73e8",
              borderRadius: 10,
              margin: "0 auto 16px",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <span style={{ color: "#fff", fontWeight: 700, fontSize: 20 }}>C</span>
          </div>
          <h1 style={{ margin: 0, fontSize: 22, fontWeight: 600, color: "#202124" }}>
            Sign in
          </h1>
          <p style={{ margin: "8px 0 0", fontSize: 14, color: "#5f6368" }}>
            CorpNet Employee Portal
          </p>
        </div>

        {error && (
          <div
            style={{
              background: "#fce8e6",
              border: "1px solid #f28b82",
              borderRadius: 4,
              padding: "10px 14px",
              marginBottom: 20,
              fontSize: 13,
              color: "#c5221f",
            }}
          >
            Invalid username or password. Please try again.
          </div>
        )}

        <form method="POST" action="/api/trap/login?endpoint=login">
          <div style={{ marginBottom: 18 }}>
            <label style={{ display: "block", fontSize: 13, color: "#202124", marginBottom: 6 }}>
              Email address
            </label>
            <input
              type="text"
              name="email"
              autoComplete="username"
              placeholder="user@corpnet.internal"
              style={{
                width: "100%",
                padding: "10px 12px",
                border: "1px solid #dadce0",
                borderRadius: 4,
                fontSize: 14,
                outline: "none",
                boxSizing: "border-box",
              }}
            />
          </div>
          <div style={{ marginBottom: 24 }}>
            <label style={{ display: "block", fontSize: 13, color: "#202124", marginBottom: 6 }}>
              Password
            </label>
            <input
              type="password"
              name="password"
              autoComplete="current-password"
              style={{
                width: "100%",
                padding: "10px 12px",
                border: "1px solid #dadce0",
                borderRadius: 4,
                fontSize: 14,
                outline: "none",
                boxSizing: "border-box",
              }}
            />
          </div>
          <button
            type="submit"
            style={{
              width: "100%",
              padding: "11px",
              background: "#1a73e8",
              color: "#fff",
              border: "none",
              borderRadius: 4,
              fontSize: 14,
              fontWeight: 500,
              cursor: "pointer",
            }}
          >
            Sign in
          </button>
        </form>

        <div style={{ marginTop: 20, textAlign: "center" }}>
          <a
            href="#"
            style={{ fontSize: 13, color: "#1a73e8", textDecoration: "none" }}
          >
            Forgot password?
          </a>
        </div>
      </div>
    </div>
  );
}
