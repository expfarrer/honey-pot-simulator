export type PayloadCategory = "SQLI" | "XSS" | "LFI" | "CMD_INJECTION" | "NONE";

const SQLI_RE =
  /('|--|union\s+select|select\s+.+from|insert\s+into|drop\s+table|or\s+1\s*=\s*1|and\s+1\s*=\s*1|1'\s*=\s*'1|sleep\s*\(|benchmark\s*\(|waitfor\s+delay)/i;

const XSS_RE =
  /(<script[\s>]|javascript\s*:|onerror\s*=|onload\s*=|alert\s*\(|document\.(cookie|write)|eval\s*\(|<img[^>]+src\s*=\s*['"]?\s*javascript)/i;

const LFI_RE =
  /(\.\.(\/|\\)){1,}|\/etc\/passwd|\/etc\/shadow|\/proc\/self|\/windows\/system32|\.\.%2[fF]|%2e%2e/i;

const CMD_RE =
  /([;|&`]\s*(cat|ls|wget|curl|chmod|bash|sh|nc|id|whoami|uname)\b|\/bin\/(sh|bash|dash)|cmd\.exe|powershell|ncat\b|\bnc\s+-[le])/i;

export function detectPayloadCategory(input: string): PayloadCategory {
  if (CMD_RE.test(input)) return "CMD_INJECTION";
  if (LFI_RE.test(input)) return "LFI";
  if (SQLI_RE.test(input)) return "SQLI";
  if (XSS_RE.test(input)) return "XSS";
  return "NONE";
}
