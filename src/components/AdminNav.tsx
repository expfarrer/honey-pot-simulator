"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import clsx from "clsx";

const NAV_ITEMS = [
  { href: "/admin", label: "DASHBOARD" },
  { href: "/admin/honeypots", label: "HONEYPOTS" },
];

export function AdminNav() {
  const pathname = usePathname();

  return (
    <header className="border-b border-[#1e2535] bg-[#0a0d14] sticky top-0 z-50">
      <div className="max-w-screen-2xl mx-auto px-6 py-0 flex items-center gap-8 h-14">
        <Link href="/admin" className="flex items-center gap-3 shrink-0">
          <span className="font-mono text-sm font-bold text-[#00ff88] tracking-widest">
            SETTRAP
          </span>
          <span className="text-[#1e2535]">|</span>
          <span className="font-mono text-xs text-gray-500 tracking-widest">
            COMMAND
          </span>
        </Link>

        <nav className="flex items-center gap-1">
          {NAV_ITEMS.map((item) => {
            const active =
              item.href === "/admin"
                ? pathname === "/admin"
                : pathname.startsWith(item.href);
            return (
              <Link
                key={item.href}
                href={item.href}
                className={clsx(
                  "px-4 py-4 text-xs font-mono tracking-widest border-b-2 transition",
                  active
                    ? "border-[#00ff88] text-[#00ff88]"
                    : "border-transparent text-gray-500 hover:text-gray-300"
                )}
              >
                {item.label}
              </Link>
            );
          })}
        </nav>

        <div className="ml-auto flex items-center gap-3">
          <span className="inline-flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-[#00ff88] shadow-[0_0_6px_#00ff88] animate-pulse" />
            <span className="text-xs text-gray-500 font-mono">LIVE</span>
          </span>
        </div>
      </div>
    </header>
  );
}
