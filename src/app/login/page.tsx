"use client";

import { useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense } from "react";

function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const redirect = searchParams.get("redirect") ?? "/admin";
  const [secret, setSecret] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");

    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ secret }),
    });

    if (res.ok) {
      router.push(redirect);
    } else {
      setError("Invalid credentials");
    }
    setLoading(false);
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#0a0d14]">
      <div className="w-full max-w-sm">
        <div className="mb-8 text-center">
          <div className="text-2xl font-mono font-bold text-[#00ff88] tracking-widest mb-1">
            SETTRAP
          </div>
          <div className="text-xs text-gray-500 tracking-[0.3em] uppercase">
            Command Platform
          </div>
        </div>

        <form onSubmit={handleSubmit} className="bg-[#0f1117] border border-[#1e2535] rounded-lg p-8">
          <div className="mb-6">
            <label className="block text-xs text-gray-400 uppercase tracking-widest mb-2">
              Admin Secret
            </label>
            <input
              type="password"
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              className="w-full bg-[#161b27] border border-[#1e2535] rounded px-4 py-3 text-sm font-mono text-gray-200 focus:outline-none focus:border-[#00ff88] focus:ring-1 focus:ring-[#00ff88] transition"
              placeholder="Enter admin secret"
              autoFocus
              required
            />
          </div>

          {error && (
            <div className="mb-4 text-xs text-[#ff4757] bg-[rgba(255,71,87,0.08)] border border-[rgba(255,71,87,0.2)] rounded px-3 py-2">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-[#00ff88] text-[#0a0d14] font-mono font-bold text-sm py-3 rounded hover:bg-[#00e67a] transition disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? "AUTHENTICATING..." : "ACCESS PLATFORM"}
          </button>
        </form>

        <p className="mt-4 text-center text-xs text-gray-600">
          Authorized access only. All sessions are logged.
        </p>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense>
      <LoginForm />
    </Suspense>
  );
}
