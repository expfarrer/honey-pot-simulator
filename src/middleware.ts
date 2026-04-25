import { NextRequest, NextResponse } from "next/server";

export function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;

  // Protect all /admin/* routes (UI)
  if (pathname.startsWith("/admin")) {
    const cookie = req.cookies.get("admin_secret")?.value;
    const secret = process.env.ADMIN_SECRET;

    if (!secret || cookie !== secret) {
      const loginUrl = new URL("/login", req.url);
      loginUrl.searchParams.set("redirect", pathname);
      return NextResponse.redirect(loginUrl);
    }
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/admin/:path*"],
};
