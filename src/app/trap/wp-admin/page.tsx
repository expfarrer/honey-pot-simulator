import { headers } from "next/headers";
import { captureHttpRequest } from "@/lib/honeypots/http-capture";

export const dynamic = "force-dynamic";

async function logVisit(sourceIp: string, userAgent: string) {
  await captureHttpRequest({
    sourceIp,
    endpoint: "/trap/wp-admin",
    method: "GET",
    eventType: "HTTP_REQUEST",
    userAgent,
  }).catch(() => {});
}

export default async function TrapWpAdminPage({
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
    <div style={{ minHeight: "100vh", background: "#f1f1f1", fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" }}>
      {/* WP-style header bar */}
      <div style={{ background: "#1d2327", height: 32, display: "flex", alignItems: "center", padding: "0 16px" }}>
        <span style={{ color: "#a7aaad", fontSize: 13 }}>WordPress</span>
      </div>

      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", minHeight: "calc(100vh - 32px)" }}>
        <div style={{ width: 320 }}>
          {/* WP logo area */}
          <div style={{ textAlign: "center", marginBottom: 24 }}>
            <div style={{ width: 84, height: 84, background: "#1d2327", borderRadius: "50%", margin: "0 auto", display: "flex", alignItems: "center", justifyContent: "center" }}>
              <span style={{ color: "#fff", fontWeight: 900, fontSize: 32 }}>W</span>
            </div>
          </div>

          <div style={{ background: "#fff", border: "1px solid #c3c4c7", borderRadius: 4, padding: "26px 24px", boxShadow: "0 1px 3px rgba(0,0,0,0.04)" }}>
            {error && (
              <div style={{ background: "#fcf0f1", border: "1px solid #d63638", borderRadius: 2, padding: "10px 12px", marginBottom: 20, fontSize: 13, color: "#d63638" }}>
                <strong>Error:</strong> The username or password you entered is incorrect.
              </div>
            )}

            <form method="POST" action="/api/trap/login?endpoint=wp-admin">
              <div style={{ marginBottom: 18 }}>
                <label style={{ display: "block", fontSize: 14, fontWeight: 600, color: "#3c434a", marginBottom: 5 }}>Username or Email Address</label>
                <input
                  type="text"
                  name="log"
                  autoComplete="username"
                  style={{ width: "100%", padding: "6px 10px", border: "1px solid #8c8f94", borderRadius: 4, fontSize: 14, color: "#3c434a", outline: "none", boxSizing: "border-box", height: 40 }}
                />
              </div>
              <div style={{ marginBottom: 6 }}>
                <label style={{ display: "block", fontSize: 14, fontWeight: 600, color: "#3c434a", marginBottom: 5 }}>Password</label>
                <input
                  type="password"
                  name="pwd"
                  autoComplete="current-password"
                  style={{ width: "100%", padding: "6px 10px", border: "1px solid #8c8f94", borderRadius: 4, fontSize: 14, color: "#3c434a", outline: "none", boxSizing: "border-box", height: 40 }}
                />
              </div>
              <div style={{ marginBottom: 20, display: "flex", alignItems: "center", gap: 8 }}>
                <input type="checkbox" id="rememberme" name="rememberme" style={{ cursor: "pointer" }} />
                <label htmlFor="rememberme" style={{ fontSize: 13, color: "#3c434a", cursor: "pointer" }}>Remember Me</label>
              </div>
              <button
                type="submit"
                name="wp-submit"
                style={{ width: "100%", padding: "8px 12px", background: "#135e96", color: "#fff", border: "none", borderRadius: 3, fontSize: 14, fontWeight: 600, cursor: "pointer", height: 36 }}
              >
                Log In
              </button>
              <input type="hidden" name="redirect_to" value="/wp-admin/" />
            </form>
          </div>

          <div style={{ marginTop: 16, textAlign: "center" }}>
            <a href="#" style={{ fontSize: 13, color: "#135e96", textDecoration: "none" }}>Lost your password?</a>
          </div>
          <div style={{ marginTop: 8, textAlign: "center" }}>
            <a href="#" style={{ fontSize: 13, color: "#135e96", textDecoration: "none" }}>← Back to site</a>
          </div>
        </div>
      </div>
    </div>
  );
}
