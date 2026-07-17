/**
 * Deterministic tool / asset inference for attack steps.
 */

import { KillChainPhase, classifyPhase } from "./scoring.js";

export interface Recommendation {
  recommendedTool: string;
  confidence: number; // 0..1
  alternatives: string[];
  rationale: string;
}

export function extractAsset(text: string, explicit?: string): string | undefined {
  if (explicit && explicit.trim()) return explicit.trim();

  const ipv4 = text.match(
    /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/
  );
  if (ipv4) return ipv4[0];

  const htb = text.match(/\b[a-z0-9-]+\.(?:htb|thm|local|lan)\b/i);
  if (htb) return htb[0];

  const fqdn = text.match(
    /\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\b/i
  );
  if (fqdn && !/^(nmap|gobuster|metasploit|searchsploit)\b/i.test(fqdn[0])) {
    return fqdn[0];
  }

  return undefined;
}

/** Ordered rule list: first match wins (most specific first). */
const TOOL_RULES: Array<{
  pattern: RegExp;
  tool: string;
  alternatives: string[];
  rationale: string;
  confidence: number;
}> = [
  {
    pattern: /\b(linpeas|linux\s*priv|lin\s*enum)\b/i,
    tool: "linpeas",
    alternatives: ["linenum", "pspy", "gtfobins"],
    rationale: "Linux privilege-escalation enumeration",
    confidence: 0.95,
  },
  {
    pattern: /\b(winpeas|windows\s*priv|win\s*enum)\b/i,
    tool: "winPEAS",
    alternatives: ["Seatbelt", "PowerUp", "winPEAS"],
    rationale: "Windows privilege-escalation enumeration",
    confidence: 0.95,
  },
  {
    pattern: /\b(bloodhound|sharpHound|ad\s*graph)\b/i,
    tool: "BloodHound",
    alternatives: ["bloodhound-python", "RustHound"],
    rationale: "Active Directory attack-path mapping",
    confidence: 0.95,
  },
  {
    pattern: /\b(mimikatz|lsass|sekurlsa)\b/i,
    tool: "mimikatz",
    alternatives: ["pypykatz", "nanodump"],
    rationale: "Credential dumping / LSASS",
    confidence: 0.9,
  },
  {
    pattern: /\b(kerberoast|asreproast|rubeus)\b/i,
    tool: "Rubeus",
    alternatives: ["impacket-GetUserSPNs", "certipy"],
    rationale: "Kerberos attack tooling",
    confidence: 0.9,
  },
  {
    pattern: /\b(sqlmap|sql\s*inject|sqli)\b/i,
    tool: "sqlmap",
    alternatives: ["manual SQLi", "ghauri"],
    rationale: "SQL injection testing",
    confidence: 0.92,
  },
  {
    pattern:
      /\b(searchsploit|exploit-?db|public\s+exploits?|search\s+public\b.{0,40}\bexploits?|lookup\s+cve|search\s+.{0,30}\bCVE-\d{4}-\d+)\b/i,
    tool: "searchsploit",
    alternatives: ["ExploitDB web", "Metasploit search"],
    rationale: "Public exploit lookup",
    confidence: 0.95,
  },
  {
    pattern: /\b(metasploit|msfconsole|msfvenom|eternalblue|ms17-010)\b/i,
    tool: "metasploit",
    alternatives: ["manual PoC", "nuclei"],
    rationale: "Exploitation framework",
    confidence: 0.9,
  },
  {
    pattern: /\b(nuclei|template\s*scan)\b/i,
    tool: "nuclei",
    alternatives: ["nmap scripts", "nikto"],
    rationale: "Template-based vulnerability scanning",
    confidence: 0.9,
  },
  {
    pattern: /\b(gobuster|feroxbuster|dirb|dirbuster|ffuf|fuzz\s*dir|content\s*discover)\b/i,
    tool: "gobuster",
    alternatives: ["ffuf", "feroxbuster", "dirsearch"],
    rationale: "Web content / directory discovery",
    confidence: 0.9,
  },
  {
    pattern: /\b(nikto|whatweb|wappalyzer|httpx|web\s*fingerprint)\b/i,
    tool: "httpx",
    alternatives: ["whatweb", "nikto", "wafw00f"],
    rationale: "Web service fingerprinting",
    confidence: 0.85,
  },
  {
    // Prefer enum tools only when not clearly in exploit/search context
    pattern: /\b(enum4linux|smbmap|smbclient|port\s*445|cifs|enumerat\w*\s+smb|smb\s+enum)\b/i,
    tool: "enum4linux-ng",
    alternatives: ["smbmap", "smbclient", "crackmapexec", "netexec"],
    rationale: "SMB enumeration",
    confidence: 0.92,
  },
  {
    pattern: /\bsmb\b/i,
    tool: "enum4linux-ng",
    alternatives: ["smbmap", "smbclient", "searchsploit"],
    rationale: "SMB-related activity",
    confidence: 0.7,
  },
  {
    pattern: /\b(ldap|ldapsearch|active\s*directory|domain\s*controller)\b/i,
    tool: "ldapsearch",
    alternatives: ["BloodHound", "netexec ldap", "impacket"],
    rationale: "LDAP / AD enumeration",
    confidence: 0.88,
  },
  {
    pattern: /\b(hydra|medusa|patator|password\s*spray|brute\s*force|bruteforce)\b/i,
    tool: "hydra",
    alternatives: ["netexec", "crackmapexec", "medusa"],
    rationale: "Credential brute-force / spray",
    confidence: 0.88,
  },
  {
    pattern: /\b(hashcat|john|crack\s*hash|ntlm\s*hash)\b/i,
    tool: "hashcat",
    alternatives: ["john", "online cracker (lab only)"],
    rationale: "Password hash cracking",
    confidence: 0.9,
  },
  {
    pattern: /\b(nmap|port\s*scan|masscan|rustscan|service\s*scan|full\s*scan)\b/i,
    tool: "nmap",
    alternatives: ["rustscan", "masscan"],
    rationale: "Network / port scanning",
    confidence: 0.95,
  },
  {
    pattern: /\b(ssh|port\s*22)\b/i,
    tool: "ssh",
    alternatives: ["hydra", "nmap ssh scripts"],
    rationale: "SSH access / enumeration",
    confidence: 0.75,
  },
  {
    pattern: /\b(burp|intercept|proxy\s*http)\b/i,
    tool: "Burp Suite",
    alternatives: ["ZAP", "caido"],
    rationale: "HTTP interception / manual testing",
    confidence: 0.85,
  },
  {
    pattern: /\b(chisel|ligolo|socat|pivot|tunnel)\b/i,
    tool: "chisel",
    alternatives: ["ligolo-ng", "ssh -R/-L", "socat"],
    rationale: "Pivoting / tunneling",
    confidence: 0.85,
  },
  {
    pattern: /\b(wireshark|tcpdump|packet\s*captur)\b/i,
    tool: "tcpdump",
    alternatives: ["wireshark", "tshark"],
    rationale: "Packet capture / traffic analysis",
    confidence: 0.85,
  },
];

const PHASE_DEFAULTS: Record<
  KillChainPhase,
  { tool: string; alternatives: string[]; rationale: string }
> = {
  recon: {
    tool: "nmap",
    alternatives: ["rustscan", "masscan"],
    rationale: "Default recon: map open ports/services",
  },
  enumeration: {
    tool: "enum4linux-ng",
    alternatives: ["gobuster", "ldapsearch", "snmpwalk"],
    rationale: "Default enum: service-specific discovery",
  },
  vulnerability_analysis: {
    tool: "searchsploit",
    alternatives: ["nuclei", "nmap NSE"],
    rationale: "Default vuln analysis: known issue lookup",
  },
  exploitation: {
    tool: "metasploit",
    alternatives: ["manual PoC", "nuclei"],
    rationale: "Default exploitation framework",
  },
  privilege_escalation: {
    tool: "linpeas / winPEAS",
    alternatives: ["pspy", "Seatbelt", "GTFOBins"],
    rationale: "Default privesc enumeration suite",
  },
  post_exploitation: {
    tool: "BloodHound / mimikatz",
    alternatives: ["impacket", "netexec"],
    rationale: "Default post-ex / lateral movement",
  },
  reporting: {
    tool: "manual documentation",
    alternatives: ["Obsidian", "SysReptor", "Dradis"],
    rationale: "Document findings and evidence",
  },
  unknown: {
    tool: "manual investigation",
    alternatives: ["nmap", "notes"],
    rationale: "Insufficient signal to recommend a specific tool",
  },
};

export function recommendTool(
  attackStep: string,
  explicitTool?: string,
  phase?: KillChainPhase
): Recommendation {
  if (explicitTool && explicitTool.trim()) {
    return {
      recommendedTool: explicitTool.trim(),
      confidence: 1,
      alternatives: [],
      rationale: "tool provided by caller",
    };
  }

  for (const rule of TOOL_RULES) {
    if (rule.pattern.test(attackStep)) {
      return {
        recommendedTool: rule.tool,
        confidence: rule.confidence,
        alternatives: rule.alternatives,
        rationale: rule.rationale,
      };
    }
  }

  const p = phase ?? classifyPhase(attackStep);
  const def = PHASE_DEFAULTS[p];
  return {
    recommendedTool: def.tool,
    alternatives: def.alternatives,
    rationale: def.rationale,
    confidence: p === "unknown" ? 0.35 : 0.55,
  };
}

/** Lightweight next-step hints from current phase (planning only). */
export function nextStepHints(phase: KillChainPhase, asset?: string): string[] {
  const target = asset || "target";
  switch (phase) {
    case "recon":
      return [
        `Enumerate discovered services on ${target}`,
        `Identify versions via nmap -sV / banner grabs`,
        `Map attack surface (web, SMB, SSH, etc.)`,
      ];
    case "enumeration":
      return [
        `Deep-enum high-value services on ${target}`,
        `Search for public CVEs matching versions`,
        `Collect creds/shares/users for later use`,
      ];
    case "vulnerability_analysis":
      return [
        `Validate exploit applicability (version, config)`,
        `Prefer low-noise authenticated checks when possible`,
        `Prepare exploit path with rollback/safety notes`,
      ];
    case "exploitation":
      return [
        `Confirm foothold / shell stability`,
        `Run local recon as the new user`,
        `Begin privilege-escalation enumeration`,
      ];
    case "privilege_escalation":
      return [
        `Review sudo/SUID/service misconfigs`,
        `Check kernel / driver CVEs carefully`,
        `Capture proof (root/SYSTEM) and evidence`,
      ];
    case "post_exploitation":
      return [
        `Map lateral movement options`,
        `Document sensitive data access`,
        `Prepare clean reporting evidence`,
      ];
    case "reporting":
      return [
        `Finalize severity ratings and impact`,
        `Attach reproduction steps and evidence`,
        `Recommend remediations`,
      ];
    default:
      return [
        `Clarify objective for ${target}`,
        `Start with scoped recon if not done`,
        `Keep notes for the attack chain`,
      ];
  }
}
