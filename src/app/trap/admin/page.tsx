import { headers } from "next/headers";
import { captureHttpRequest } from "@/lib/honeypots/http-capture";

export const dynamic = "force-dynamic";

async function logVisit(sourceIp: string, userAgent: string) {
  await captureHttpRequest({
    sourceIp,
    endpoint: "/trap/admin",
    method: "GET",
    eventType: "HTTP_REQUEST",
    userAgent,
  }).catch(() => {});
}

export default async function TrapAdminPage({
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
    <div style={{ minHeight: "100vh", background: "#1e1e2e", color: "#cdd6f4", fontFamily: "system-ui, sans-serif" }}>
      {/* Header */}
      <div style={{ background: "#181825", borderBottom: "1px solid #313244", padding: "0 24px", height: 56, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <span style={{ fontWeight: 700, fontSize: 16, color: "#cba6f7" }}>AdminPanel v3.1</span>
        <span style={{ fontSize: 13, color: "#6c7086" }}>Not authenticated</span>
      </div>

      {/* Login gate */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", minHeight: "calc(100vh - 56px)" }}>
        <div style={{ background: "#181825", border: "1px solid #313244", borderRadius: 8, padding: "40px 48px", width: 380 }}>
          <h2 style={{ margin: "0 0 8px", fontSize: 20, fontWeight: 600 }}>Administrator Login</h2>
          <p style={{ margin: "0 0 28px", fontSize: 13, color: "#6c7086" }}>Authentication required to access this panel.</p>

          {error && (
            <div style={{ background: "#45243a", border: "1px solid #f38ba8", borderRadius: 4, padding: "10px 14px", marginBottom: 20, fontSize: 13, color: "#f38ba8" }}>
              Access denied. Invalid credentials.
            </div>
          )}

          <form method="POST" action="/api/trap/login?endpoint=admin">
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: "block", fontSize: 12, color: "#a6adc8", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.05em" }}>Username</label>
              <input
                type="text"
                name="username"
                autoComplete="username"
                placeholder="admin"
                style={{ width: "100%", padding: "10px 12px", background: "#1e1e2e", border: "1px solid #45475a", borderRadius: 4, color: "#cdd6f4", fontSize: 14, outline: "none", boxSizing: "border-box" }}
              />
            </div>
            <div style={{ marginBottom: 24 }}>
              <label style={{ display: "block", fontSize: 12, color: "#a6adc8", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.05em" }}>Password</label>
              <input
                type="password"
                name="password"
                autoComplete="current-password"
                style={{ width: "100%", padding: "10px 12px", background: "#1e1e2e", border: "1px solid #45475a", borderRadius: 4, color: "#cdd6f4", fontSize: 14, outline: "none", boxSizing: "border-box" }}
              />
            </div>
            <button
              type="submit"
              style={{ width: "100%", padding: 11, background: "#cba6f7", color: "#1e1e2e", border: "none", borderRadius: 4, fontSize: 14, fontWeight: 600, cursor: "pointer" }}
            >
              Login
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
