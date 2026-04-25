function required(name: string): string {
  const val = process.env[name];
  if (!val) throw new Error(`Missing required environment variable: ${name}`);
  return val;
}

function optional(name: string, fallback: string): string {
  return process.env[name] ?? fallback;
}

export const env = {
  DATABASE_URL: required("DATABASE_URL"),
  ADMIN_SECRET: required("ADMIN_SECRET"),
  INGEST_SECRET: optional("INGEST_SECRET", ""),
  NODE_ENV: optional("NODE_ENV", "development"),
} as const;
