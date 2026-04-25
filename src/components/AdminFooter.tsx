import { APP_VERSION, APP_VERSION_LABEL } from "@/lib/version";

export function AdminFooter() {
  return (
    <footer className="border-t border-[#1e2535] mt-12">
      <div className="max-w-screen-2xl mx-auto px-6 py-4 flex items-center justify-between">
        <span className="font-mono text-xs text-gray-600">
          SetTrap Command v{APP_VERSION} — {APP_VERSION_LABEL}
        </span>
        <span className="font-mono text-xs text-gray-700">
          Defensive monitoring only. All sessions logged.
        </span>
      </div>
    </footer>
  );
}
