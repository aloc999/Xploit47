#!/usr/bin/env node
/**
 * Xploit47 — Penetration testing reasoning MCP server
 *
 * Systematic attack-path planning using Beam Search and Monte Carlo Tree Search.
 * Designed for authorized CTF/HTB work and professional pentest workflows.
 */

import { pathToFileURL } from "node:url";
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
const SERVER_VERSION = "1.0.0";
const TOOL_NAME = "xploit47";

/** Simple step logger (mirrors original index.js UX) */
class AttackStepLogger {
  private attackSteps: any[] = [];

  formatAttackStep(data: {
    attackStepNumber: number;
    totalAttackSteps: number;
    attackStep: string;
    asset?: string;
    recommendedTool?: string;
    critical?: boolean;
  }): string {
    const {
      attackStepNumber,
      totalAttackSteps,
      attackStep,
      asset,
      recommendedTool,
      critical,
    } = data;
    const prefix = critical
      ? chalk.red("🔥 Critical Path")
      : chalk.blue("🛡️  Attack Step");
    const header = `${prefix} ${attackStepNumber}/${totalAttackSteps}`;
    const assetLine = `Target Asset: ${asset || "N/A"}`;
    const toolLine = `Recommended Tool: ${recommendedTool || "N/A"}`;
    // Visible width ignores ANSI codes for border sizing
    const strip = (s: string) => s.replace(/\u001b\[[0-9;]*m/g, "");
    const width = Math.max(
      strip(header).length,
      attackStep.length,
      assetLine.length,
      toolLine.length,
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
    asset: input.asset != null && input.asset !== "" ? String(input.asset) : undefined,
    recommendedTool:
      input.recommendedTool != null && input.recommendedTool !== ""
        ? String(input.recommendedTool)
        : undefined,
    critical: Boolean(input.critical),
  };

  if (!result.attackStep) {
    throw new Error("attackStep must be provided");
  }
  if (!Number.isFinite(result.attackStepNumber) || result.attackStepNumber < 1) {
    throw new Error("attackStepNumber must be an integer >= 1");
  }
  if (!Number.isFinite(result.totalAttackSteps) || result.totalAttackSteps < 1) {
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

  // Coerce to integers for clean stats
  result.attackStepNumber = Math.floor(result.attackStepNumber);
  result.totalAttackSteps = Math.floor(result.totalAttackSteps);

  return result;
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
          "Xploit47 advanced pentest reasoning engine. Breaks down attack paths step by step using Beam Search or Monte Carlo Tree Search (MCTS). Scores steps, tracks attack chains, and returns strategy metrics. Use for CTF/HTB planning and authorized pentest workflows.",
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
                "Attack strategy to use: beam_search (methodical) or mcts (exploratory)",
            },
            asset: {
              type: "string",
              description: "Target asset for this step (optional)",
            },
            recommendedTool: {
              type: "string",
              description: "Recommended tool for this step (optional)",
            },
            critical: {
              type: "boolean",
              description: "Whether this step is on the critical path",
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
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    if (request.params.name !== TOOL_NAME) {
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

      logger.log(step);

      const response = await reasoner.processAttackStep({
        attackStep: step.attackStep,
        attackStepNumber: step.attackStepNumber,
        totalAttackSteps: step.totalAttackSteps,
        nextAttackStepNeeded: step.nextAttackStepNeeded,
        strategyType: step.strategyType,
      });

      const stats = await reasoner.getStats();

      const result = {
        server: SERVER_NAME,
        attackStepNumber: step.attackStepNumber,
        totalAttackSteps: step.totalAttackSteps,
        nextAttackStepNeeded: step.nextAttackStepNeeded,
        attackStep: step.attackStep,
        asset: step.asset,
        recommendedTool: step.recommendedTool,
        critical: step.critical || false,
        nodeId: response.nodeId,
        score: response.score,
        strategyUsed: response.strategyUsed,
        attackStepCount: logger.count(),
        stats: {
          totalNodes: stats.totalNodes,
          averageScore: stats.averageScore,
          maxDepth: stats.maxDepth,
          branchingFactor: stats.branchingFactor,
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
      `Xploit47 MCP Server v${SERVER_VERSION} running on stdio (Beam Search + MCTS)`
    )
  );
}

// Run when executed directly (stdio MCP mode)
const isDirectRun =
  !!process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isDirectRun) {
  runServer().catch((error) => {
    console.error("Fatal error running Xploit47 server:", error);
    process.exit(1);
  });
}
