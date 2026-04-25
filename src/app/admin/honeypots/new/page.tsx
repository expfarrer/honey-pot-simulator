"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { SectionHeader } from "@/components/ui/SectionHeader";

export default function NewHoneypotPage() {
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setLoading(true);
    setError(null);

    const form = new FormData(e.currentTarget);
    const body = {
      name: form.get("name") as string,
      type: form.get("type") as string,
      publicPort: parseInt(form.get("publicPort") as string, 10),
      dockerService: form.get("dockerService") as string || undefined,
      configJson: {
        hostname: form.get("hostname") as string || "ubuntu-server",
        version: form.get("version") as string || "OpenSSH_8.9p1",
      },
    };

    const res = await fetch("/api/honeypots", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    if (res.ok) {
      router.push("/admin/honeypots");
      router.refresh();
    } else {
      const data = await res.json();
      setError(data.error ? JSON.stringify(data.error) : "Failed to create honeypot");
      setLoading(false);
    }
  }

  return (
    <div className="max-w-2xl">
      <SectionHeader
        title="New Honeypot"
        description="Configure a new honeypot instance"
      />

      <form
        onSubmit={handleSubmit}
        className="bg-[#0f1117] border border-[#1e2535] rounded-lg p-8 space-y-6"
      >
        <div className="grid grid-cols-2 gap-6">
          <div>
            <label className="block text-xs text-gray-400 uppercase tracking-widest mb-2">
              Name *
            </label>
            <input
              name="name"
              required
              className="w-full bg-[#161b27] border border-[#1e2535] rounded px-4 py-2.5 text-sm font-mono text-gray-200 focus:outline-none focus:border-[#00ff88] transition"
              placeholder="SSH Honeypot Alpha"
            />
          </div>

          <div>
            <label className="block text-xs text-gray-400 uppercase tracking-widest mb-2">
              Type *
            </label>
            <select
              name="type"
              className="w-full bg-[#161b27] border border-[#1e2535] rounded px-4 py-2.5 text-sm font-mono text-gray-200 focus:outline-none focus:border-[#00ff88] transition"
            >
              <option value="SSH">SSH</option>
              <option value="HTTP">HTTP</option>
              <option value="WORDPRESS">WordPress</option>
              <option value="REDIS">Redis</option>
              <option value="MONGODB">MongoDB</option>
              <option value="IOT">IoT/Router</option>
            </select>
          </div>

          <div>
            <label className="block text-xs text-gray-400 uppercase tracking-widest mb-2">
              Public Port *
            </label>
            <input
              name="publicPort"
              type="number"
              required
              min={1}
              max={65535}
              defaultValue={2222}
              className="w-full bg-[#161b27] border border-[#1e2535] rounded px-4 py-2.5 text-sm font-mono text-gray-200 focus:outline-none focus:border-[#00ff88] transition"
            />
          </div>

          <div>
            <label className="block text-xs text-gray-400 uppercase tracking-widest mb-2">
              Docker Service
            </label>
            <input
              name="dockerService"
              className="w-full bg-[#161b27] border border-[#1e2535] rounded px-4 py-2.5 text-sm font-mono text-gray-200 focus:outline-none focus:border-[#00ff88] transition"
              placeholder="cowrie"
            />
          </div>

          <div>
            <label className="block text-xs text-gray-400 uppercase tracking-widest mb-2">
              Fake Hostname
            </label>
            <input
              name="hostname"
              className="w-full bg-[#161b27] border border-[#1e2535] rounded px-4 py-2.5 text-sm font-mono text-gray-200 focus:outline-none focus:border-[#00ff88] transition"
              placeholder="ubuntu-server"
            />
          </div>

          <div>
            <label className="block text-xs text-gray-400 uppercase tracking-widest mb-2">
              SSH Version Banner
            </label>
            <input
              name="version"
              className="w-full bg-[#161b27] border border-[#1e2535] rounded px-4 py-2.5 text-sm font-mono text-gray-200 focus:outline-none focus:border-[#00ff88] transition"
              placeholder="OpenSSH_8.9p1"
            />
          </div>
        </div>

        {error && (
          <div className="text-xs text-[#ff4757] bg-[rgba(255,71,87,0.08)] border border-[rgba(255,71,87,0.2)] rounded px-4 py-3 font-mono">
            {error}
          </div>
        )}

        <div className="flex items-center gap-4 pt-2">
          <button
            type="submit"
            disabled={loading}
            className="px-6 py-2.5 bg-[#00ff88] text-[#0a0d14] text-xs font-mono font-bold rounded hover:bg-[#00e67a] transition disabled:opacity-50"
          >
            {loading ? "Creating..." : "Create Honeypot"}
          </button>
          <button
            type="button"
            onClick={() => router.back()}
            className="px-6 py-2.5 text-gray-400 text-xs font-mono border border-[#1e2535] rounded hover:border-gray-500 transition"
          >
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}
