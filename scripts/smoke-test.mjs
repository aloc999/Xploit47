#!/usr/bin/env node
/**
 * Xploit47 accuracy + integration smoke tests
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { Reasoner } from "../dist/reasoner.js";
import {
  scoreAttackStep,
  classifyPhase,
  scorePath,
} from "../dist/scoring.js";
import { recommendTool, extractAsset } from "../dist/recommend.js";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");

let failed = 0;
function assert(cond, msg) {
  if (!cond) {
    console.error("FAIL:", msg);
    failed++;
  } else {
    console.log("PASS:", msg);
  }
}

// --- Deterministic scoring ---
const s1 = scoreAttackStep({
  attackStep: "nmap -p- 10.10.10.10",
  attackStepNumber: 1,
  totalAttackSteps: 5,
});
const s1b = scoreAttackStep({
  attackStep: "nmap -p- 10.10.10.10",
  attackStepNumber: 1,
  totalAttackSteps: 5,
});
assert(s1.score === s1b.score, "scoring is deterministic");
assert(s1.score >= 0 && s1.score <= 1, "score in [0,1]");
assert(s1.phase === "recon", "nmap classified as recon");
assert(s1.breakdown.reasons.length > 0, "score has reasons");
assert(s1.breakdown.specificity > 0, "nmap+IP has specificity");

const vague = scoreAttackStep({
  attackStep: "do stuff",
  attackStepNumber: 1,
  totalAttackSteps: 5,
});
assert(
  s1.score > vague.score,
  "specific step scores higher than vague step"
);

const exploit = scoreAttackStep({
  attackStep: "Exploit SMB with EternalBlue CVE-2017-0144 on 10.10.10.10",
  attackStepNumber: 4,
  totalAttackSteps: 6,
  parentAttackStep: "Search public SMB exploits CVE-2017-0144 on 10.10.10.10",
  parentPhase: "vulnerability_analysis",
});
assert(exploit.phase === "exploitation", "CVE exploit phase");
assert(exploit.breakdown.coherence > 0, "parent coherence > 0");
assert(classifyPhase("Run linpeas for privilege escalation") === "privilege_escalation", "privesc phase");

// --- Recommend / extract ---
assert(extractAsset("scan 10.10.10.10 now") === "10.10.10.10", "extract IPv4");
assert(recommendTool("Enumerate SMB on port 445").recommendedTool.includes("enum"), "SMB tool");
assert(recommendTool("nmap -sV target").recommendedTool === "nmap", "nmap tool");
assert(recommendTool("x", "custom-tool").recommendedTool === "custom-tool", "explicit tool wins");
assert(recommendTool("x", "custom-tool").confidence === 1, "explicit tool confidence 1");

// --- Path score ---
assert(scorePath([0.5, 0.6, 0.7]) > scorePath([0.7, 0.6, 0.5]), "rising path scores higher");
assert(scorePath([]) === 0, "empty path score 0");

// --- Reasoner chain accuracy ---
const reasoner = new Reasoner();

const beam1 = await reasoner.processAttackStep({
  attackStep: "nmap -p- 10.10.10.10",
  attackStepNumber: 1,
  totalAttackSteps: 4,
  nextAttackStepNeeded: true,
  strategyType: "beam_search",
});
assert(beam1.strategyUsed === "beam_search", "beam strategy");
assert(beam1.attackStep === "nmap -p- 10.10.10.10", "beam preserves attackStep");
assert(beam1.asset === "10.10.10.10", "auto asset extraction");
assert(beam1.recommendedTool === "nmap", "auto tool nmap");
assert(beam1.phase === "recon", "beam phase recon");
assert(beam1.path.length === 1, "first path length 1");
assert(beam1.scoreBreakdown.total === beam1.score, "breakdown total matches score (beam)");

const beam2 = await reasoner.processAttackStep({
  attackStep: "Enumerate SMB on port 445 on 10.10.10.10",
  attackStepNumber: 2,
  totalAttackSteps: 4,
  nextAttackStepNeeded: true,
  strategyType: "beam_search",
});
assert(beam2.parentId === beam1.nodeId, "auto parent link step2→step1");
assert(beam2.path.length === 2, "path length 2 after step2");
assert(beam2.path[0].nodeId === beam1.nodeId, "path starts at step1");
assert(beam2.scoreBreakdown.coherence > 0, "chain coherence scored");

const mcts = await reasoner.processAttackStep({
  attackStep: "Search public SMB exploits CVE-2017-0144 on 10.10.10.10",
  attackStepNumber: 3,
  totalAttackSteps: 4,
  nextAttackStepNeeded: true,
  strategyType: "mcts",
});
assert(mcts.strategyUsed === "mcts", "mcts strategy");
assert(
  mcts.attackStep.includes("CVE-2017-0144"),
  "mcts returns real attackStep"
);
assert(!/Simulated attack step/i.test(mcts.attackStep), "mcts not simulated string");
assert(mcts.parentId === beam2.nodeId, "mcts auto parent link");
assert(mcts.path.length === 3, "path length 3 across strategies");
assert(mcts.recommendedTool === "searchsploit", "CVE search tool");

// MCTS deterministic for same step in fresh reasoner
const r2 = new Reasoner();
const m1 = await r2.processAttackStep({
  attackStep: "nmap -sC -sV 10.10.10.10",
  attackStepNumber: 1,
  totalAttackSteps: 3,
  nextAttackStepNeeded: true,
  strategyType: "mcts",
});
const r3 = new Reasoner();
const m2 = await r3.processAttackStep({
  attackStep: "nmap -sC -sV 10.10.10.10",
  attackStepNumber: 1,
  totalAttackSteps: 3,
  nextAttackStepNeeded: true,
  strategyType: "mcts",
});
assert(m1.score === m2.score, "mcts score deterministic across runs");
assert(m1.phase === m2.phase, "mcts phase deterministic");

const stats = await reasoner.getStats();
assert(stats.userNodes === 3, "stats userNodes=3 (no sim pollution)");
assert(stats.totalNodes === 3, "stats totalNodes excludes simulations");
assert(typeof stats.bestPathScore === "number", "bestPathScore present");

// --- MCP integration ---
const transport = new StdioClientTransport({
  command: "node",
  args: [join(root, "dist/index.js")],
  cwd: root,
});
const client = new Client({ name: "xploit47-smoke", version: "1.0.0" });
await client.connect(transport);

const tools = await client.listTools();
assert(tools.tools?.length === 1, "one tool registered");
assert(tools.tools[0].name === "xploit47", "tool name is xploit47");

const call = await client.callTool({
  name: "xploit47",
  arguments: {
    attackStep: "Exploit SMB EternalBlue CVE-2017-0144 on 10.10.10.10",
    attackStepNumber: 1,
    totalAttackSteps: 3,
    nextAttackStepNeeded: true,
    strategyType: "beam_search",
  },
});
const text = call.content?.[0]?.text || "";
const parsed = JSON.parse(text);
assert(parsed.success === true, "success true");
assert(parsed.server === "Xploit47", "response server name");
assert(parsed.phase === "exploitation", "MCP phase exploitation");
assert(parsed.asset === "10.10.10.10", "MCP auto asset");
assert(parsed.recommendedTool === "metasploit", "MCP auto tool metasploit");
assert(parsed.scoreBreakdown?.reasons?.length > 0, "MCP score reasons");
assert(Array.isArray(parsed.nextStepHints) && parsed.nextStepHints.length > 0, "nextStepHints");
assert(Array.isArray(parsed.path), "path array");
assert(parsed.critical === true, "high-impact exploit marked critical");

const bad = await client.callTool({
  name: "xploit47",
  arguments: {
    attackStep: "",
    attackStepNumber: 1,
    totalAttackSteps: 1,
    nextAttackStepNeeded: false,
  },
});
assert(bad.isError === true, "empty attackStep is error");

await client.close();

if (failed > 0) {
  console.error(`\n${failed} test(s) failed`);
  process.exit(1);
}
console.log("\nAll accuracy smoke tests passed.");
