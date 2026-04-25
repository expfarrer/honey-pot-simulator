import { NextRequest } from "next/server";

export function validateAdminSecret(req: NextRequest): boolean {
  const header = req.headers.get("x-admin-secret");
  const cookie = req.cookies.get("admin_secret")?.value;
  const secret = process.env.ADMIN_SECRET;
  if (!secret) return false;
  return header === secret || cookie === secret;
}

export function validateIngestSecret(req: NextRequest): boolean {
  const header = req.headers.get("x-ingest-secret");
  const secret = process.env.INGEST_SECRET;
  if (!secret || secret === "") return true; // allow unauthenticated if not set
  return header === secret;
}
