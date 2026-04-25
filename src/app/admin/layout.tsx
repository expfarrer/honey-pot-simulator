import { AdminNav } from "@/components/AdminNav";
import { AdminFooter } from "@/components/AdminFooter";

export default function AdminLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-[#0a0d14] flex flex-col">
      <AdminNav />
      <main className="flex-1 max-w-screen-2xl w-full mx-auto px-6 py-8">{children}</main>
      <AdminFooter />
    </div>
  );
}
