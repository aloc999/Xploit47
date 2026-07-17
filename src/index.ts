#!/usr/bin/env node
/**
 * Xploit47 — Penetration testing reasoning MCP server
 *
 * Systematic attack-path planning using Beam Search and Monte Carlo Tree Search.
 * Designed for authorized CTF/HTB work and professional pentest workflows.
 */

import { pathToFileURL } from "node:url";
import { spawn } from "node:child_process";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import chalk from "chalk";
import { Reasoner } from "./reasoner.js";
import { ReasoningStrategy } from "./types.js";

const SERVER_NAME = "Xploit47";
const SERVER_VERSION = "1.2.0";
const TOOL_NAME = "xploit47";
const EXEC_TOOL_NAME = "xploit47_exec";

class AttackStepLogger {
  private attackSteps: any[] = [];

  formatAttackStep(data: {
    attackStepNumber: number;
    totalAttackSteps: number;
    attackStep: string;
    asset?: string;
    recommendedTool?: string;
    critical?: boolean;
    score?: number;
    phase?: string;
  }): string {
    const {
      attackStepNumber,
      totalAttackSteps,
      attackStep,
      asset,
      recommendedTool,
      critical,
      score,
      phase,
    } = data;
    const prefix = critical
      ? chalk.red("🔥 Critical Path")
      : chalk.blue("🛡️  Attack Step");
    const header = `${prefix} ${attackStepNumber}/${totalAttackSteps}`;
    const assetLine = `Target Asset: ${asset || "N/A"}`;
    const toolLine = `Recommended Tool: ${recommendedTool || "N/A"}`;
    const metaLine = `Score: ${score != null ? score.toFixed(4) : "N/A"} | Phase: ${phase || "N/A"}`;
    const strip = (s: string) => s.replace(/\u001b\[[0-9;]*m/g, "");
    const width = Math.max(
      strip(header).length,
      attackStep.length,
      assetLine.length,
      toolLine.length,
      metaLine.length,
      40
    );
    const pad = (s: string) => {
      const visible = strip(s).length;
      return s + " ".repeat(Math.max(0, width - visible));
    };
    const border = "─".repeat(width + 2);
    return (
      `\n┌${border}┐\n` +
      `│ ${pad(header)} │\n` +
      `├${border}┤\n` +
      `│ ${pad(attackStep)} │\n` +
      `│ ${pad(assetLine)} │\n` +
      `│ ${pad(toolLine)} │\n` +
      `│ ${pad(metaLine)} │\n` +
      `└${border}┘`
    );
  }

  log(input: any): void {
    this.attackSteps.push(input);
    console.error(this.formatAttackStep(input));
  }

  count(): number {
    return this.attackSteps.length;
  }
}

function processInput(input: any) {
  if (input == null || typeof input !== "object") {
    throw new Error("arguments must be an object");
  }

  const result = {
    attackStep: String(input.attackStep ?? "").trim(),
    attackStepNumber: Number(input.attackStepNumber),
    totalAttackSteps: Number(input.totalAttackSteps),
    nextAttackStepNeeded: Boolean(input.nextAttackStepNeeded),
    strategyType: input.strategyType as ReasoningStrategy | undefined,
    asset:
      input.asset != null && input.asset !== ""
        ? String(input.asset).trim()
        : undefined,
    recommendedTool:
      input.recommendedTool != null && input.recommendedTool !== ""
        ? String(input.recommendedTool).trim()
        : undefined,
    critical:
      input.critical === undefined ? undefined : Boolean(input.critical),
    parentId:
      input.parentId != null && input.parentId !== ""
        ? String(input.parentId).trim()
        : undefined,
  };

  if (!result.attackStep) {
    throw new Error("attackStep must be provided");
  }
  if (!Number.isFinite(result.attackStepNumber) || result.attackStepNumber < 1) {
    throw new Error("attackStepNumber must be an integer >= 1");
  }
  if (
    !Number.isFinite(result.totalAttackSteps) ||
    result.totalAttackSteps < 1
  ) {
    throw new Error("totalAttackSteps must be an integer >= 1");
  }
  if (
    result.strategyType !== undefined &&
    !Object.values(ReasoningStrategy).includes(result.strategyType)
  ) {
    throw new Error(
      `strategyType must be one of: ${Object.values(ReasoningStrategy).join(", ")}`
    );
  }

  result.attackStepNumber = Math.floor(result.attackStepNumber);
  result.totalAttackSteps = Math.floor(result.totalAttackSteps);

  return result;
}

function errorResult(message: string) {
  return {
    content: [
      { type: "text", text: JSON.stringify({ error: message, success: false }) },
    ],
    isError: true,
  };
}

const MAX_STREAM_BYTES = 5 * 1024 * 1024;

function truncate(s: string, max = 200000): string {
  if (s.length <= max) return s;
  return s.slice(0, max) + `\n...[truncated ${s.length - max} chars]`;
}

async function handleExec(args: any) {
  const command = String(args?.command ?? "").trim();
  const authorized = args?.authorized === true;
  const timeout =
    Number.isFinite(Number(args?.timeout)) && Number(args.timeout) > 0
      ? Math.min(Number(args.timeout), 1800)
      : 120;
  const cwd = args?.cwd ? String(args.cwd) : undefined;
  const extraEnv =
    args?.env && typeof args.env === "object" ? args.env : {};

  if (!command) {
    return errorResult("command must be provided");
  }
  if (!authorized) {
    return errorResult(
      "authorized must be true — confirm written authorization for this target"
    );
  }

  const startedAt = Date.now();
  try {
    const { stdout, stderr, code, truncated } = await new Promise<{
      stdout: string;
      stderr: string;
      code: number | null;
      truncated: boolean;
    }>((resolve, reject) => {
      const child = spawn(command, {
        shell: true,
        cwd,
        env: { ...process.env, ...extraEnv },
        timeout: timeout * 1000,
      });

      let stdout = "";
      let stderr = "";
      let truncated = false;
      let stdoutBytes = 0;
      let stderrBytes = 0;

      child.stdout?.on("data", (d: Buffer) => {
        stdoutBytes += d.length;
        if (stdoutBytes <= MAX_STREAM_BYTES) stdout += d.toString();
        else truncated = true;
      });
      child.stderr?.on("data", (d: Buffer) => {
        stderrBytes += d.length;
        if (stderrBytes <= MAX_STREAM_BYTES) stderr += d.toString();
        else truncated = true;
      });
      child.on("error", reject);
      child.on("close", (code) =>
        resolve({ stdout, stderr, code, truncated })
      );
    });

    const durationMs = Date.now() - startedAt;
    const payload = {
      server: SERVER_NAME,
      version: SERVER_VERSION,
      tool: EXEC_TOOL_NAME,
      command,
      authorized: true,
      exitCode: code,
      success: code === 0,
      durationMs,
      truncated,
      stdout: truncate(stdout),
      stderr: truncate(stderr),
    };

    return {
      content: [{ type: "text", text: JSON.stringify(payload, null, 2) }],
      isError: code !== 0,
    };
  } catch (error) {
    return errorResult(
      error instanceof Error ? error.message : String(error)
    );
  }
}

function createServer() {
  const server = new Server(
    {
      name: SERVER_NAME,
      version: SERVER_VERSION,
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  const reasoner = new Reasoner();
  const logger = new AttackStepLogger();

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: TOOL_NAME,
        description:
          "Xploit47 accurate pentest reasoning engine. Scores and chains attack steps with deterministic Beam Search or MCTS. Returns explainable score breakdown, kill-chain phase, auto tool recommendation, asset extraction, critical-path flag, full path, and next-step hints. For authorized CTF/HTB and professional pentest planning only.",
        inputSchema: {
          type: "object",
          properties: {
            attackStep: {
              type: "string",
              description:
                "Current attack step or action in the penetration test",
            },
            attackStepNumber: {
              type: "integer",
              description: "Current step number in the attack chain",
              minimum: 1,
            },
            totalAttackSteps: {
              type: "integer",
              description: "Total expected steps in the attack chain",
              minimum: 1,
            },
            nextAttackStepNeeded: {
              type: "boolean",
              description: "Whether another attack step is needed",
            },
            strategyType: {
              type: "string",
              enum: Object.values(ReasoningStrategy),
              description:
                "Attack strategy: beam_search (methodical) or mcts (exploratory)",
            },
            asset: {
              type: "string",
              description:
                "Target asset (optional; auto-extracted from step when omitted)",
            },
            recommendedTool: {
              type: "string",
              description:
                "Tool for this step (optional; auto-recommended when omitted)",
            },
            critical: {
              type: "boolean",
              description:
                "Force critical-path flag (optional; auto-detected when omitted)",
            },
            parentId: {
              type: "string",
              description:
                "Parent node id for explicit chaining (optional; auto-links sequential steps)",
            },
          },
          required: [
            "attackStep",
            "attackStepNumber",
            "totalAttackSteps",
            "nextAttackStepNeeded",
          ],
        },
      },
      {
        name: EXEC_TOOL_NAME,
        description:
          "Execute a shell command on the local machine to run pentest tools (nmap, enum4linux, searchsploit, metasploit, smbclient, gobuster, ffuf, curl, etc.) recommended by the xploit47 reasoning tool. Returns combined stdout/stderr, exit code, and duration. AUTHORIZED TESTING ONLY — you must have written permission or be on a CTF/HTB lab. Set authorized=true to confirm. Prefer running the exact command the xploit47 tool recommended.",
        inputSchema: {
          type: "object",
          properties: {
            command: {
              type: "string",
              description: "Shell command to execute (runs via /bin/sh -c)",
            },
            authorized: {
              type: "boolean",
              description:
                "Must be true. Confirms you have authorization to run this command against the target.",
            },
            timeout: {
              type: "integer",
              description: "Max execution time in seconds (default 120, max 1800)",
              minimum: 1,
              maximum: 1800,
            },
            cwd: {
              type: "string",
              description: "Working directory (optional)",
            },
            env: {
              type: "object",
              description: "Additional environment variables (optional)",
              additionalProperties: { type: "string" },
            },
          },
          required: ["command", "authorized"],
        },
      },
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const toolName = request.params.name;

    if (toolName === EXEC_TOOL_NAME) {
      return handleExec(request.params.arguments);
    }

    if (toolName !== TOOL_NAME) {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({ error: "Unknown tool", success: false }),
          },
        ],
        isError: true,
      };
    }

    try {
      const step = processInput(request.params.arguments);

      if (step.attackStepNumber > step.totalAttackSteps) {
        step.totalAttackSteps = step.attackStepNumber;
      }

      const response = await reasoner.processAttackStep({
        attackStep: step.attackStep,
        attackStepNumber: step.attackStepNumber,
        totalAttackSteps: step.totalAttackSteps,
        nextAttackStepNeeded: step.nextAttackStepNeeded,
        strategyType: step.strategyType,
        asset: step.asset,
        recommendedTool: step.recommendedTool,
        critical: step.critical,
        parentId: step.parentId,
      });

      logger.log({
        ...step,
        asset: response.asset ?? step.asset,
        recommendedTool: response.recommendedTool,
        critical: response.critical,
        score: response.score,
        phase: response.phase,
      });

      const stats = await reasoner.getStats();

      const result = {
        server: SERVER_NAME,
        version: SERVER_VERSION,
        success: true,
        attackStepNumber: step.attackStepNumber,
        totalAttackSteps: step.totalAttackSteps,
        nextAttackStepNeeded: step.nextAttackStepNeeded,
        attackStep: step.attackStep,
        asset: response.asset,
        recommendedTool: response.recommendedTool,
        toolConfidence: response.toolConfidence,
        toolAlternatives: response.toolAlternatives,
        toolRationale: response.toolRationale,
        critical: response.critical,
        phase: response.phase,
        nodeId: response.nodeId,
        parentId: response.parentId,
        score: response.score,
        scoreBreakdown: response.scoreBreakdown,
        strategyUsed: response.strategyUsed,
        path: response.path,
        pathScore: response.pathScore,
        nextStepHints: response.nextStepHints,
        attackStepCount: logger.count(),
        stats: {
          totalNodes: stats.totalNodes,
          userNodes: stats.userNodes,
          averageScore: stats.averageScore,
          maxDepth: stats.maxDepth,
          branchingFactor: stats.branchingFactor,
          bestPathScore: stats.bestPathScore,
          strategyMetrics: stats.strategyMetrics,
        },
      };

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              error: error instanceof Error ? error.message : String(error),
              success: false,
            }),
          },
        ],
        isError: true,
      };
    }
  });

  return server;
}

/** Smithery-compatible default export */
export default function ({ config }: { config?: any } = {}) {
  return createServer();
}

async function runServer() {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(
    chalk.green(
      `Xploit47 MCP Server v${SERVER_VERSION} running on stdio (accurate Beam Search + MCTS)`
    )
  );
}

const isDirectRun =
  !!process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isDirectRun) {
  runServer().catch((error) => {
    console.error("Fatal error running Xploit47 server:", error);
    process.exit(1);
  });
}
