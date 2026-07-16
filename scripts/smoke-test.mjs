#!/usr/bin/env node
/**
 * Xploit47 smoke tests — reasoner + full MCP client handshake
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { Reasoner } from "../dist/reasoner.js";
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

// --- Unit: reasoner ---
const reasoner = new Reasoner();

const beam = await reasoner.processAttackStep({
  attackStep: "nmap -p- 10.10.10.10",
  attackStepNumber: 1,
  totalAttackSteps: 3,
  nextAttackStepNeeded: true,
  strategyType: "beam_search",
});
assert(beam.strategyUsed === "beam_search", "beam strategy");
assert(typeof beam.score === "number" && beam.score >= 0 && beam.score <= 1, "beam score range");
assert(beam.attackStep === "nmap -p- 10.10.10.10", "beam preserves attackStep");
assert(!!beam.nodeId, "beam nodeId");

const mcts = await reasoner.processAttackStep({
  attackStep: "Enumerate SMB on port 445",
  attackStepNumber: 2,
  totalAttackSteps: 3,
  nextAttackStepNeeded: true,
  strategyType: "mcts",
});
assert(mcts.strategyUsed === "mcts", "mcts strategy");
assert(
  mcts.attackStep === "Enumerate SMB on port 445",
  "mcts returns real attackStep (not simulated text)"
);
assert(!/Simulated attack step/i.test(mcts.attackStep), "mcts not simulated string");
assert(typeof mcts.score === "number" && mcts.score >= 0 && mcts.score <= 1, "mcts score range");

const stats = await reasoner.getStats();
assert(stats.totalNodes >= 2, "stats has nodes");

// --- Integration: MCP stdio ---
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
    attackStep: "Search public SMB exploits CVE-2017-0144",
    attackStepNumber: 3,
    totalAttackSteps: 4,
    nextAttackStepNeeded: true,
    strategyType: "beam_search",
    asset: "10.10.10.10",
    recommendedTool: "searchsploit",
    critical: true,
  },
});
const text = call.content?.[0]?.text || "";
const parsed = JSON.parse(text);
assert(parsed.server === "Xploit47", "response server name");
assert(parsed.attackStep.includes("SMB"), "call returns attackStep");
assert(parsed.recommendedTool === "searchsploit", "recommendedTool echoed");
assert(parsed.critical === true, "critical flag");
assert(parsed.strategyUsed === "beam_search", "strategy in response");

// validation error path
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
console.log("\nAll smoke tests passed.");
