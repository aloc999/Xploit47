/**
 * Deterministic attack-step scoring for Xploit47.
 * No randomness — same input always yields the same score and breakdown.
 */

export interface ScoreBreakdown {
  /** Sum of components, clamped to [0, 1] */
  total: number;
  base: number;
  specificity: number;
  actionability: number;
  phaseValue: number;
  coherence: number;
  progress: number;
  depthPenalty: number;
  /** Human-readable reasons that contributed */
  reasons: string[];
}

export type KillChainPhase =
  | "recon"
  | "enumeration"
  | "vulnerability_analysis"
  | "exploitation"
  | "privilege_escalation"
  | "post_exploitation"
  | "reporting"
  | "unknown";

const PHASE_RANK: Record<KillChainPhase, number> = {
  recon: 1,
  enumeration: 2,
  vulnerability_analysis: 3,
  exploitation: 4,
  privilege_escalation: 5,
  post_exploitation: 6,
  reporting: 7,
  unknown: 0,
};

export function classifyPhase(text: string): KillChainPhase {
  const t = text.toLowerCase();

  if (/\b(report|document|writeup|summary|findings)\b/.test(t)) return "reporting";
  if (
    /\b(privesc|privilege\s*escalat|linpeas|winpeas|sudo\s+-l|getsystem|uac\s*bypass|kernel\s*exploit)\b/.test(
      t
    )
  ) {
    return "privilege_escalation";
  }
  if (
    /\b(post[- ]?exploit|lateral|pivot|persist|exfil|bloodhound|mimikatz|dump\s+creds|hashdump)\b/.test(
      t
    )
  ) {
    return "post_exploitation";
  }
  if (
    /\b(exploit|metasploit|msfconsole|payload|reverse\s*shell|get\s+shell|pwn|rce|cve-\d{4}-\d+)\b/.test(
      t
    )
  ) {
    return "exploitation";
  }
  if (
    /\b(vuln|cve|searchsploit|nuclei|nessus|cvss|misconfig|weak\s+cred)\b/.test(t)
  ) {
    return "vulnerability_analysis";
  }
  if (
    /\b(enum|enumerat|smb|ldap|kerberos|ftp|snmp|rpc|share|user\s*list|dirb|gobuster|ffuf|nikto|whatweb)\b/.test(
      t
    )
  ) {
    return "enumeration";
  }
  if (
    /\b(recon|nmap|masscan|ping|traceroute|osint|whois|subdomain|amass|theharvester|port\s*scan)\b/.test(
      t
    )
  ) {
    return "recon";
  }

  return "unknown";
}

function round4(n: number): number {
  return Math.round(n * 10000) / 10000;
}

function clamp01(n: number): number {
  return Math.min(1, Math.max(0, n));
}

/** Extract concrete indicators that make a step measurable / specific */
function scoreSpecificity(text: string, reasons: string[]): number {
  let score = 0;
  const t = text;

  // IPv4
  if (/\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/.test(t)) {
    score += 0.08;
    reasons.push("contains IPv4 target");
  }
  // IPv6 (loose)
  if (/\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b/i.test(t)) {
    score += 0.06;
    reasons.push("contains IPv6 target");
  }
  // Hostname / FQDN
  if (/\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\b/i.test(t) &&
      !/\b(?:nmap|enum4linux|metasploit|searchsploit)\b/i.test(t.match(/\b[a-z0-9.-]+\.[a-z]{2,}\b/i)?.[0] || "")) {
    // only if looks like domain
    if (/\b[a-z0-9-]+\.(?:local|lan|htb|thm|com|net|org|io|gov)\b/i.test(t)) {
      score += 0.06;
      reasons.push("contains hostname/domain");
    }
  }
  // Port
  if (/\bports?\s*[:=]?\s*\d{1,5}\b|\b-p\s*[\d,-]+|\b(?:port\s+)?(?:22|80|443|445|3389|8080|8443)\b/i.test(t)) {
    score += 0.07;
    reasons.push("names a port or port range");
  }
  // CVE
  if (/\bCVE-\d{4}-\d{4,7}\b/i.test(t)) {
    score += 0.1;
    reasons.push("references a CVE");
  }
  // File/path
  if (/\/[\w./-]+|\b[A-Za-z]:\\[\w\\.-]+|\b(?:user|root|flag)\.txt\b/i.test(t)) {
    score += 0.04;
    reasons.push("references a path or flag file");
  }
  // Protocol
  if (/\b(?:smb|ssh|http|https|ldap|rdp|ftp|smtp|dns|nfs|winrm|mssql|mysql|postgres)\b/i.test(t)) {
    score += 0.05;
    reasons.push("names a protocol/service");
  }

  return Math.min(score, 0.3);
}

function scoreActionability(text: string, reasons: string[]): number {
  let score = 0;
  const t = text.toLowerCase();

  const tools = [
    "nmap", "masscan", "rustscan", "enum4linux", "smbclient", "smbmap",
    "crackmapexec", "netexec", "impacket", "bloodhound", "ldapsearch",
    "gobuster", "ffuf", "feroxbuster", "dirb", "nikto", "nuclei",
    "sqlmap", "burp", "wfuzz", "hydra", "john", "hashcat",
    "metasploit", "msfconsole", "searchsploit", "exploitdb",
    "linpeas", "winpeas", "pspy", "gtfobins", "lolbas",
    "responder", "ntlmrelayx", "mimikatz", "rubeus", "certipy",
    "chisel", "ligolo", "socat", "nc", "ncat", "curl", "wget",
  ];

  for (const tool of tools) {
    if (new RegExp(`\\b${tool}\\b`, "i").test(text)) {
      score += 0.12;
      reasons.push(`names tool: ${tool}`);
      break;
    }
  }

  // Concrete command flags / shell shape
  if (/\s-\w{1,3}\b|--\w+|\/[\w-]{2,}/.test(text) || /`[^`]+`/.test(text)) {
    score += 0.06;
    reasons.push("includes command-like flags");
  }

  // Strong action verbs
  if (
    /\b(scan|enumerat|exploit|bruteforce|brute-force|dump|relay|pivot|escalate|inject|fuzz|crack|spray|exfiltrat)\w*\b/i.test(
      t
    )
  ) {
    score += 0.06;
    reasons.push("uses concrete action verb");
  }

  // Outcome-oriented language
  if (/\b(obtain|get|gain|capture|retrieve)\b.{0,20}\b(shell|foothold|creds|hash|ticket|flag)\b/i.test(t)) {
    score += 0.04;
    reasons.push("states a clear objective outcome");
  }

  return Math.min(score, 0.25);
}

function scorePhaseValue(phase: KillChainPhase, reasons: string[]): number {
  // Later kill-chain phases are higher value when correctly identified
  const map: Record<KillChainPhase, number> = {
    recon: 0.08,
    enumeration: 0.1,
    vulnerability_analysis: 0.12,
    exploitation: 0.16,
    privilege_escalation: 0.16,
    post_exploitation: 0.14,
    reporting: 0.06,
    unknown: 0.04,
  };
  const v = map[phase];
  if (phase !== "unknown") reasons.push(`phase: ${phase}`);
  return v;
}

function scoreCoherence(
  parentText: string | undefined,
  childText: string,
  parentPhase: KillChainPhase | undefined,
  childPhase: KillChainPhase,
  reasons: string[]
): number {
  if (!parentText) return 0;

  let score = 0;
  const parentTerms = new Set(
    parentText
      .toLowerCase()
      .split(/\W+/)
      .filter((t) => t.length > 2 && !STOPWORDS.has(t))
  );
  const childTerms = childText
    .toLowerCase()
    .split(/\W+/)
    .filter((t) => t.length > 2 && !STOPWORDS.has(t));

  if (parentTerms.size > 0 && childTerms.length > 0) {
    const overlap = childTerms.filter((t) => parentTerms.has(t)).length;
    const ratio = overlap / Math.max(childTerms.length, 1);
    const termScore = Math.min(ratio * 0.2, 0.12);
    if (termScore > 0.02) {
      score += termScore;
      reasons.push(`shares context with previous step (${overlap} terms)`);
    }
  }

  // Shared IP / CVE / port across steps
  const parentIps = parentText.match(
    /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g
  );
  const childIps = childText.match(
    /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g
  );
  if (parentIps && childIps && parentIps.some((ip) => childIps.includes(ip))) {
    score += 0.05;
    reasons.push("continues on same IP target");
  }

  // Kill-chain progression (child phase >= parent phase, or +1)
  if (parentPhase && parentPhase !== "unknown" && childPhase !== "unknown") {
    const delta = PHASE_RANK[childPhase] - PHASE_RANK[parentPhase];
    if (delta === 0 || delta === 1) {
      score += 0.05;
      reasons.push("follows logical kill-chain progression");
    } else if (delta > 1) {
      score += 0.02;
      reasons.push("advances kill-chain (possible skip)");
    } else if (delta < 0) {
      // regression — slight penalty applied elsewhere via lower score
      reasons.push("phase regresses vs previous step");
    }
  }

  return Math.min(score, 0.2);
}

function scoreProgress(
  stepNumber: number,
  totalSteps: number,
  reasons: string[]
): number {
  if (totalSteps < 1 || stepNumber < 1) return 0;
  // Mild bonus for staying within planned bounds
  if (stepNumber <= totalSteps) {
    const ratio = stepNumber / totalSteps;
    const v = round4(0.03 + ratio * 0.02);
    reasons.push(`progress ${stepNumber}/${totalSteps}`);
    return Math.min(v, 0.05);
  }
  reasons.push("exceeded planned total steps");
  return 0.01;
}

const STOPWORDS = new Set([
  "the", "and", "for", "with", "from", "this", "that", "into", "onto",
  "step", "attack", "on", "to", "of", "a", "an", "in", "at", "or", "as",
  "is", "are", "be", "by", "use", "using", "run", "running", "check",
]);

export interface ScoreInput {
  attackStep: string;
  attackStepNumber: number;
  totalAttackSteps: number;
  parentAttackStep?: string;
  parentPhase?: KillChainPhase;
  /** Optional explicit phase override */
  phase?: KillChainPhase;
}

/**
 * Fully deterministic score in [0, 1] with explainable breakdown.
 */
export function scoreAttackStep(input: ScoreInput): {
  score: number;
  breakdown: ScoreBreakdown;
  phase: KillChainPhase;
} {
  const reasons: string[] = [];
  const phase = input.phase ?? classifyPhase(input.attackStep);

  const base = 0.12;
  reasons.push("base score");

  const specificity = scoreSpecificity(input.attackStep, reasons);
  const actionability = scoreActionability(input.attackStep, reasons);
  const phaseValue = scorePhaseValue(phase, reasons);
  const coherence = scoreCoherence(
    input.parentAttackStep,
    input.attackStep,
    input.parentPhase,
    phase,
    reasons
  );
  const progress = scoreProgress(
    input.attackStepNumber,
    input.totalAttackSteps,
    reasons
  );

  // Depth penalty: very deep chains without new specificity get slight dampening
  const depth = Math.max(0, input.attackStepNumber - 1);
  const depthPenalty = Math.min(depth * 0.015, 0.12);
  if (depthPenalty > 0) reasons.push(`depth penalty for step ${input.attackStepNumber}`);

  const raw =
    base + specificity + actionability + phaseValue + coherence + progress - depthPenalty;
  const total = round4(clamp01(raw));

  const breakdown: ScoreBreakdown = {
    total,
    base: round4(base),
    specificity: round4(specificity),
    actionability: round4(actionability),
    phaseValue: round4(phaseValue),
    coherence: round4(coherence),
    progress: round4(progress),
    depthPenalty: round4(depthPenalty),
    reasons,
  };

  return { score: total, breakdown, phase };
}

/**
 * Path score = length-weighted average with slight preference for rising scores.
 */
export function scorePath(scores: number[]): number {
  if (scores.length === 0) return 0;
  const avg = scores.reduce((a, b) => a + b, 0) / scores.length;
  let rises = 0;
  for (let i = 1; i < scores.length; i++) {
    if (scores[i] >= scores[i - 1]) rises++;
  }
  const trend =
    scores.length > 1 ? (rises / (scores.length - 1)) * 0.05 : 0;
  return round4(clamp01(avg + trend));
}

/** Critical if high impact phase + solid specificity/actionability */
export function isCriticalStep(
  phase: KillChainPhase,
  breakdown: ScoreBreakdown
): boolean {
  const highImpact: KillChainPhase[] = [
    "exploitation",
    "privilege_escalation",
    "post_exploitation",
  ];
  if (highImpact.includes(phase) && breakdown.total >= 0.55) return true;
  if (breakdown.specificity >= 0.15 && breakdown.actionability >= 0.12 && breakdown.total >= 0.65) {
    return true;
  }
  if (breakdown.reasons.some((r) => r.includes("CVE")) && phase === "exploitation") {
    return true;
  }
  return false;
}
