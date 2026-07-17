import { v4 as uuidv4 } from "uuid";
import {
  AttackNode,
  ReasoningRequest,
  ReasoningResponse,
  CONFIG,
} from "../types.js";
import { BaseStrategy } from "./base.js";
import { StateManager } from "../state.js";
import { extractAsset } from "../recommend.js";
import { isCriticalStep, scoreAttackStep } from "../scoring.js";
import { recommendTool } from "../recommend.js";

interface MCTSNode extends AttackNode {
  visits: number;
  totalSimScore: number;
  ucb1Score?: number;
}

export class MCTSStrategy extends BaseStrategy {
  private readonly explorationConstant = Math.sqrt(2);
  private readonly simulationDepth = 3;

  constructor(stateManager: StateManager) {
    super(stateManager);
  }

  public async processAttackStep(
    request: ReasoningRequest
  ): Promise<ReasoningResponse> {
    const parent = await this.resolveParent(request);

    const rootNode: MCTSNode = {
      id: uuidv4(),
      attackStep: request.attackStep,
      depth: request.attackStepNumber - 1,
      visits: 0,
      totalSimScore: 0,
      score: 0,
      isComplete: !request.nextAttackStepNeeded,
      isSimulation: false,
      parent,
      parentId: parent?.id,
      attackStepNumber: request.attackStepNumber,
      totalAttackSteps: request.totalAttackSteps,
      children: [],
    };

    const evaluated = this.evaluateAttackStep(rootNode, parent, request);
    rootNode.score = evaluated.score;
    rootNode.scoreBreakdown = evaluated.breakdown;
    rootNode.phase = evaluated.phase;
    rootNode.asset = extractAsset(request.attackStep, request.asset);
    const rec = recommendTool(
      request.attackStep,
      request.recommendedTool,
      evaluated.phase
    );
    rootNode.recommendedTool = rec.recommendedTool;
    rootNode.critical =
      request.critical === true
        ? true
        : isCriticalStep(evaluated.phase, evaluated.breakdown);

    // Store root only in strategy local map + state (user node)
    await this.saveNode(rootNode);
    if (parent) {
      if (!parent.children) parent.children = [];
      if (!parent.children.some((c) => c.id === rootNode.id)) {
        parent.children.push(rootNode);
      }
      await this.saveNode(parent);
    }

    // MCTS iterations refine score; simulation nodes stay local (not in global stats)
    for (let i = 0; i < CONFIG.mctsIterations; i++) {
      const selected = this.select(rootNode);
      const expanded = this.expand(selected, request);
      const simScore = this.simulate(expanded, request);
      this.backpropagate(expanded, simScore);
    }

    // Blend base evaluation with MCTS visit-weighted value (deterministic weights)
    const mctsValue =
      rootNode.visits > 0 ? rootNode.totalSimScore / rootNode.visits : evaluated.score;
    // 70% content score + 30% MCTS tree value — still in [0,1]
    const blended = Math.round((evaluated.score * 0.7 + mctsValue * 0.3) * 10000) / 10000;
    rootNode.score = Math.min(1, Math.max(0, blended));
    if (rootNode.scoreBreakdown) {
      rootNode.scoreBreakdown = {
        ...rootNode.scoreBreakdown,
        total: rootNode.score,
        reasons: [
          ...rootNode.scoreBreakdown.reasons,
          `mcts blend: content=${evaluated.score.toFixed(4)} tree=${mctsValue.toFixed(4)}`,
        ],
      };
    }

    await this.saveNode(rootNode);

    const path = await this.getPathFrom(rootNode);
    return this.buildResponse(rootNode, request, "mcts", path);
  }

  private select(node: MCTSNode): MCTSNode {
    let current = node;
    while (Array.isArray(current.children) && current.children.length > 0) {
      const mctsChildren = current.children.filter(
        (c): c is MCTSNode => typeof (c as MCTSNode).visits === "number"
      );
      if (mctsChildren.length === 0) break;
      const next = this.selectBestUCB1(current, mctsChildren);
      if (!next) break;
      current = next;
    }
    return current;
  }

  private expand(node: MCTSNode, request: ReasoningRequest): MCTSNode {
    // Phase-aware simulated child (local only — isSimulation, not saved to StateManager)
    const parentPhase = node.phase;
    const simStep = this.syntheticStep(node, request);

    const newNode: MCTSNode = {
      id: uuidv4(),
      attackStep: simStep,
      depth: (node.depth || 0) + 1,
      visits: 0,
      totalSimScore: 0,
      score: 0,
      isComplete: false,
      isSimulation: true,
      parent: node,
      parentId: node.id,
    };

    const { score, breakdown, phase } = scoreAttackStep({
      attackStep: simStep,
      attackStepNumber: (node.attackStepNumber ?? node.depth + 1) + 1,
      totalAttackSteps: request.totalAttackSteps,
      parentAttackStep: node.attackStep,
      parentPhase,
    });
    newNode.score = score;
    newNode.scoreBreakdown = breakdown;
    newNode.phase = phase;

    // Keep sims only in local parent.children for tree walk — do NOT pollute global store
    this.nodes.set(newNode.id, newNode);
    if (!node.children) node.children = [];
    node.children.push(newNode);

    return newNode;
  }

  /** Deterministic synthetic next step from parent (no Math.random) */
  private syntheticStep(node: MCTSNode, request: ReasoningRequest): string {
    const asset = node.asset || extractAsset(request.attackStep) || "target";
    const phase = node.phase || "unknown";
    const templates: Record<string, string[]> = {
      recon: [
        `Enumerate services on ${asset}`,
        `Banner-grab and version-scan open ports on ${asset}`,
      ],
      enumeration: [
        `Deep-enumerate high-value service on ${asset}`,
        `Collect users/shares/versions from ${asset}`,
      ],
      vulnerability_analysis: [
        `Map findings on ${asset} to public CVEs`,
        `Validate exploit preconditions for ${asset}`,
      ],
      exploitation: [
        `Attempt foothold on ${asset} via validated vector`,
        `Stabilize shell and confirm access on ${asset}`,
      ],
      privilege_escalation: [
        `Run local privesc checks on ${asset}`,
        `Review sudo/SUID/service misconfigs on ${asset}`,
      ],
      post_exploitation: [
        `Map lateral movement from ${asset}`,
        `Document sensitive access from ${asset}`,
      ],
      reporting: [
        `Document evidence and impact for ${asset}`,
        `Finalize remediation notes for ${asset}`,
      ],
      unknown: [
        `Clarify next objective on ${asset}`,
        `Continue structured enumeration on ${asset}`,
      ],
    };
    const list = templates[phase] || templates.unknown;
    // Deterministic pick from depth + step number
    const idx =
      Math.abs((node.depth + 1) * 31 + (node.attackStepNumber || 1) * 17) %
      list.length;
    return list[idx];
  }

  private simulate(node: MCTSNode, request: ReasoningRequest): number {
    let current = node;
    let totalScore = current.score || 0;
    let count = 1;

    for (let depth = 0; depth < this.simulationDepth; depth++) {
      const simStep = this.syntheticStep(current, request);
      const { score, phase } = scoreAttackStep({
        attackStep: simStep,
        attackStepNumber:
          (current.attackStepNumber ?? current.depth + 1) + 1,
        totalAttackSteps: request.totalAttackSteps,
        parentAttackStep: current.attackStep,
        parentPhase: current.phase,
      });
      totalScore += score;
      count++;
      // advance virtual node (not stored)
      current = {
        ...current,
        id: `sim-virtual-${depth}`,
        attackStep: simStep,
        depth: (current.depth || 0) + 1,
        score,
        phase,
        attackStepNumber: (current.attackStepNumber ?? 0) + 1,
        visits: 0,
        totalSimScore: 0,
        isSimulation: true,
      };
    }

    return Math.round((totalScore / count) * 10000) / 10000;
  }

  private backpropagate(node: MCTSNode, score: number): void {
    let current: MCTSNode | undefined = node;
    while (current) {
      current.visits = (current.visits || 0) + 1;
      current.totalSimScore = (current.totalSimScore || 0) + score;
      // Only overwrite score on simulation nodes; user nodes keep content score
      // until final blend (UCB uses totalSimScore/visits, not score).
      if (current.isSimulation) {
        current.score =
          Math.round((current.totalSimScore / current.visits) * 10000) / 10000;
      }
      current = current.parent as MCTSNode | undefined;
    }
  }

  private selectBestUCB1(
    parent: MCTSNode,
    children: MCTSNode[]
  ): MCTSNode | undefined {
    if (children.length === 0) return undefined;
    const totalVisits = Math.max(parent.visits || 1, 1);

    for (const child of children) {
      if (child.visits === 0) {
        // Prioritize unvisited — UCB infinite
        child.ucb1Score = Number.POSITIVE_INFINITY;
        continue;
      }
      const exploitation = child.totalSimScore / child.visits;
      const exploration = Math.sqrt(Math.log(totalVisits) / child.visits);
      child.ucb1Score = exploitation + this.explorationConstant * exploration;
    }

    // Deterministic tie-break by id
    return children.reduce((best, cur) => {
      const b = best.ucb1Score ?? -Infinity;
      const c = cur.ucb1Score ?? -Infinity;
      if (c > b) return cur;
      if (c === b && cur.id < best.id) return cur;
      return best;
    });
  }

  public async getBestPath(): Promise<AttackNode[]> {
    const nodes = Array.from(this.nodes.values()).filter((n) => !n.isSimulation);
    if (nodes.length === 0) return [];

    const complete = nodes.filter((n) => n.isComplete);
    const pool = complete.length > 0 ? complete : nodes;
    const best = pool.sort((a, b) => (b.score ?? 0) - (a.score ?? 0))[0];
    return this.getPathFrom(best);
  }

  public async clear(): Promise<void> {
    await super.clear();
  }
}
