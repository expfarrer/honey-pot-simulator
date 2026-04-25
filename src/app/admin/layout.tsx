import { AdminNav } from "@/components/AdminNav";

export default function AdminLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-[#0a0d14]">
      <AdminNav />
      <main className="max-w-screen-2xl mx-auto px-6 py-8">{children}</main>
    </div>
  );
}
