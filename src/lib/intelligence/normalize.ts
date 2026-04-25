const IP_RE = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g;
const URL_RE = /https?:\/\/[^\s]+/g;
const TMP_RE = /\/tmp\/[^\s;|&]+/g;
const HEX_TOKEN_RE = /\b[0-9a-f]{16,}\b/gi;
const B64_TOKEN_RE = /[A-Za-z0-9+/]{24,}={0,2}/g;
const WHITESPACE_RE = /\s+/g;

export function normalizeCommand(command: string): string {
  let s = command.trim();
  s = s.replace(URL_RE, "<url>");
  s = s.replace(IP_RE, "<ip>");
  s = s.replace(TMP_RE, "/tmp/<tmp>");
  s = s.replace(HEX_TOKEN_RE, "<token>");
  s = s.replace(B64_TOKEN_RE, "<token>");
  s = s.replace(WHITESPACE_RE, " ");
  return s.toLowerCase();
}

const NUM_RE = /\b\d+\b/g;
const LONG_STR_RE = /[^\s&=]{40,}/g;
const ENCODED_RE = /%[0-9a-f]{2}/gi;
const QUOTE_STR_RE = /(['"])[^'"]{20,}\1/g;

export function normalizeHttpPayload(input: string): string {
  let s = input.trim();
  s = s.replace(URL_RE, "<url>");
  s = s.replace(IP_RE, "<ip>");
  s = s.replace(QUOTE_STR_RE, "<str>");
  s = s.replace(HEX_TOKEN_RE, "<token>");
  s = s.replace(B64_TOKEN_RE, "<token>");
  s = s.replace(ENCODED_RE, (m) => m.toLowerCase());
  s = s.replace(LONG_STR_RE, "<payload>");
  s = s.replace(NUM_RE, "<num>");
  s = s.replace(WHITESPACE_RE, " ");
  return s.toLowerCase().slice(0, 500);
}
