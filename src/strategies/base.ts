import {
  AttackNode,
  ReasoningRequest,
  ReasoningResponse,
} from "../types.js";
import { StateManager } from "../state.js";
import {
  classifyPhase,
  isCriticalStep,
  scoreAttackStep,
  scorePath,
  type KillChainPhase,
  type ScoreBreakdown,
} from "../scoring.js";
import {
  extractAsset,
  nextStepHints,
  recommendTool,
} from "../recommend.js";

export interface StrategyMetrics {
  name: string;
  nodesExplored: number;
  averageScore: number;
  maxDepth: number;
  active?: boolean;
  [key: string]: number | string | boolean | undefined;
}

export abstract class BaseStrategy {
  protected stateManager: StateManager;
  protected nodes: Map<string, AttackNode> = new Map();

  constructor(stateManager: StateManager) {
    this.stateManager = stateManager;
    this.nodes = new Map();
  }

  abstract processAttackStep(
    request: ReasoningRequest
  ): Promise<ReasoningResponse>;

  protected async getNode(id: string): Promise<AttackNode | undefined> {
    return this.nodes.get(id) ?? this.stateManager.getNode(id);
  }

  protected async saveNode(node: AttackNode): Promise<void> {
    this.nodes.set(node.id, node);
    await this.stateManager.saveNode(node);
  }

  /**
   * Deterministic evaluation using shared scoring module.
   * Replaces heuristic length/random scoring.
   */
  protected evaluateAttackStep(
    node: AttackNode,
    parent?: AttackNode,
    request?: ReasoningRequest
  ): { score: number; breakdown: ScoreBreakdown; phase: KillChainPhase } {
    const result = scoreAttackStep({
      attackStep: node.attackStep,
      attackStepNumber:
        request?.attackStepNumber ?? (node.depth || 0) + 1,
      totalAttackSteps:
        request?.totalAttackSteps ?? Math.max((node.depth || 0) + 1, 1),
      parentAttackStep: parent?.attackStep,
      parentPhase: parent?.phase,
    });
    return result;
  }

  protected buildResponse(
    node: AttackNode,
    request: ReasoningRequest,
    strategyUsed: string,
    path: AttackNode[]
  ): ReasoningResponse {
    const phase = node.phase ?? classifyPhase(node.attackStep);
    const asset = node.asset ?? extractAsset(request.attackStep, request.asset);
    const rec = recommendTool(
      request.attackStep,
      request.recommendedTool ?? node.recommendedTool,
      phase
    );
    const breakdown =
      node.scoreBreakdown ??
      scoreAttackStep({
        attackStep: node.attackStep,
        attackStepNumber: request.attackStepNumber,
        totalAttackSteps: request.totalAttackSteps,
      }).breakdown;

    const critical =
      request.critical === true
        ? true
        : node.critical ?? isCriticalStep(phase, breakdown);

    const pathScores = path.map((n) => n.score ?? 0);
    const userPath = path.filter((n) => !n.isSimulation);

    return {
      nodeId: node.id,
      attackStep: node.attackStep,
      score: node.score ?? breakdown.total,
      strategyUsed,
      nextAttackStepNeeded: request.nextAttackStepNeeded,
      phase,
      asset,
      recommendedTool: rec.recommendedTool,
      toolConfidence: rec.confidence,
      toolAlternatives: rec.alternatives,
      toolRationale: rec.rationale,
      critical,
      scoreBreakdown: breakdown,
      parentId: node.parentId ?? node.parent?.id,
      path: userPath.map((n) => ({
        nodeId: n.id,
        attackStep: n.attackStep,
        score: n.score ?? 0,
        phase: n.phase,
      })),
      pathScore: scorePath(pathScores.length ? pathScores : [node.score ?? 0]),
      nextStepHints: nextStepHints(phase, asset),
    };
  }

  protected async resolveParent(
    request: ReasoningRequest
  ): Promise<AttackNode | undefined> {
    if (!request.parentId) return undefined;
    return this.getNode(request.parentId);
  }

  protected async getPathFrom(node: AttackNode): Promise<AttackNode[]> {
    const path: AttackNode[] = [];
    let current: AttackNode | undefined = node;
    const seen = new Set<string>();

    while (current && !seen.has(current.id)) {
      seen.add(current.id);
      path.unshift(current);
      if (current.parentId) {
        current = await this.getNode(current.parentId);
      } else if (current.parent) {
        current = current.parent;
      } else {
        break;
      }
    }
    return path;
  }

  public async getBestPath(): Promise<AttackNode[]> {
    const nodes = (await this.stateManager.getAllNodes()).filter(
      (n) => !n.isSimulation
    );
    if (nodes.length === 0) return [];

    const completed = nodes
      .filter((n) => n.isComplete)
      .sort((a, b) => (b.score ?? 0) - (a.score ?? 0));

    const target =
      completed[0] ??
      [...nodes].sort((a, b) => (b.score ?? 0) - (a.score ?? 0))[0];

    return this.getPathFrom(target);
  }

  public async getMetrics(): Promise<StrategyMetrics> {
    const nodes = (await this.stateManager.getAllNodes()).filter(
      (n) => !n.isSimulation
    );

    return {
      name: this.constructor.name,
      nodesExplored: nodes.length,
      averageScore:
        nodes.length > 0
          ? nodes.reduce((sum, n) => sum + (n.score ?? 0), 0) / nodes.length
          : 0,
      maxDepth: nodes.length > 0 ? Math.max(...nodes.map((n) => n.depth)) : 0,
    };
  }

  public async clear(): Promise<void> {
    this.nodes.clear();
  }
}
