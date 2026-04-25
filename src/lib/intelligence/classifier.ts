export type CommandCategory =
  | "fingerprint"
  | "recon"
  | "payload"
  | "persistence"
  | "anti_forensics"
  | "unknown";

const FINGERPRINT_PATTERNS = [
  /^uname(\s|$)/,
  /^whoami(\s|$)/,
  /^id(\s|$)/,
  /^hostname(\s|$)/,
  /^ifconfig(\s|$)/,
  /^ip\s+(addr|route|link)/,
  /^cat\s+\/etc\/(os-release|issue|passwd|shadow)/,
  /^uptime(\s|$)/,
  /^ps(\s|$)/,
  /^top(\s|$)/,
  /^netstat(\s|$)/,
  /^ss(\s|$)/,
];

const RECON_PATTERNS = [
  /^ls(\s|$)/,
  /^cd(\s|$)/,
  /^cat\s+/,
  /^find\s+/,
  /^grep\s+/,
  /^locate\s+/,
  /^which\s+/,
  /^whereis\s+/,
  /^env(\s|$)/,
  /^printenv(\s|$)/,
  /^df(\s|$)/,
  /^du(\s|$)/,
];

const PAYLOAD_PATTERNS = [
  /\bwget\b/,
  /\bcurl\b/,
  /\btftp\b/,
  /\/dev\/tcp\//,
  /\/dev\/udp\//,
  /\bpython[23]?\s+-c\b/,
  /\bperl\s+-e\b/,
  /\bbash\s+-i\b/,
  /\bnc\b.*-e/,
  /\bncat\b/,
  /base64\s+--decode/,
  /\bchmod\s+[+]?x\b.*&&/,
];

const PERSISTENCE_PATTERNS = [
  /\bchmod\b/,
  /\bchattr\b/,
  /\.ssh\/authorized_keys/,
  /crontab\s+-e/,
  /\/etc\/cron/,
  /\/etc\/rc\.local/,
  /systemctl\s+enable/,
  /\badduser\b/,
  /\buseradd\b/,
  /\bpasswd\b/,
];

const ANTI_FORENSICS_PATTERNS = [
  /HISTFILE/,
  /unset\s+HISTORY/,
  /HISTSIZE=0/,
  /HISTFILESIZE=0/,
  /history\s+-c/,
  /rm\s+.*bash_history/,
  /shred\s+/,
  />\s*\/var\/log/,
];

export function classifyCommand(command: string): CommandCategory {
  const normalized = command.trim().toLowerCase();

  if (ANTI_FORENSICS_PATTERNS.some((p) => p.test(command))) return "anti_forensics";
  if (PAYLOAD_PATTERNS.some((p) => p.test(command))) return "payload";
  if (PERSISTENCE_PATTERNS.some((p) => p.test(normalized))) return "persistence";
  if (FINGERPRINT_PATTERNS.some((p) => p.test(normalized))) return "fingerprint";
  if (RECON_PATTERNS.some((p) => p.test(normalized))) return "recon";

  return "unknown";
}

export function classifyMultipleCommands(
  commands: string[]
): Map<string, CommandCategory> {
  const result = new Map<string, CommandCategory>();
  for (const cmd of commands) {
    result.set(cmd, classifyCommand(cmd));
  }
  return result;
}
